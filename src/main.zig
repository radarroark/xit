//! you're looking at radar's hopeless attempt to implement
//! git in zig. one day, it will be the fastest git in the world,
//! with extra features for rewriting history like in BFG.
//! right now, though, it just makes a couple dirs and prints
//! messages out...which already makes it more usable than git.
//!
//! "C'mon Alex! You always dreamt about going on a big adventure!
//!  Let this be our first!" -- Lunar: Silver Star Story

const std = @import("std");
const process = std.process;
const hash = @import("./hash.zig");
const compress = @import("./compress.zig");

/// takes the args passed to this program and puts them
/// in an arraylist. do we need to do this? i don't know,
/// but i'd rather have it in an arraylist so it's easier
/// to look at. so yeah, i do need it. fight me.
fn appendArgs(out: *std.ArrayList([]const u8)) !void {
    var arg_it = process.args();
    _ = arg_it.skip();

    while (true) {
        const s = arg_it.next();
        if (s == null) {
            break;
        }
        try out.append(s.?);
    }
}

const CommandKind = enum {
    invalid,
    usage,
    init,
    commit,
};

const Command = union(CommandKind) {
    invalid: struct {
        name: []const u8,
    },
    usage,
    init: struct {
        dir: []const u8,
    },
    commit,
};

/// returns the data from the process args in a nicer format.
/// i'm trying not to handle errors here. but maybe i will
/// need to eventually. we'll see.
fn parseArgs(args: *std.ArrayList([]const u8)) Command {
    if (args.items.len >= 1) {
        if (std.mem.eql(u8, args.items[0], "init")) {
            return Command{ .init = .{ .dir = if (args.items.len > 1) args.items[1] else "." } };
        } else if (std.mem.eql(u8, args.items[0], "commit")) {
            return Command{ .commit = {} };
        } else {
            return Command{ .invalid = .{ .name = args.items[0] } };
        }
    }

    return Command{ .usage = {} };
}

/// this is meant to be the main entry point if you wanted to use zit
/// as a library. there will definitely be more specialized functions
/// you can call as well, but if you just want to pass the CLI args and
/// have it behave just like the standalone git client than this is
/// where it's at, homie.
pub fn zitMain(args: *std.ArrayList([]const u8), allocator: std.mem.Allocator) !void {
    const cmd = parseArgs(args);

    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    switch (cmd) {
        Command.invalid => {
            try stderr.print("\"{s}\" is not a valid command\n", .{cmd.invalid.name});
            return;
        },
        Command.usage => {
            try stdout.print(
                \\usage: zit
                \\
                \\start a working area:
                \\   init
                \\
            , .{});
        },
        Command.init => {
            // get the root dir. no path was given to the init command, this
            // should just be the current working directory (cwd). if a path was
            // given, it should either append it to the cwd or, if it is absolute,
            // it should just use that path alone. IT'S MAGIC!
            var root_dir = try std.fs.cwd().makeOpenPath(cmd.init.dir, .{});
            defer root_dir.close();

            // make the .git dir. right now we're throwing an error if it already
            // exists. in git it says "Reinitialized existing Git repository" so
            // we'll need to do that eventually.
            root_dir.makeDir(".git") catch |err| {
                switch (err) {
                    error.PathAlreadyExists => {
                        try stderr.print("{s} is already a repository\n", .{cmd.init.dir});
                        return;
                    },
                    else => return err,
                }
            };

            // make a few dirs inside of .git
            var git_dir = try root_dir.openDir(".git", .{});
            defer git_dir.close();
            try git_dir.makeDir("objects");
            try git_dir.makeDir("refs");
        },
        Command.commit => {
            // get the cwd path
            var cwd_path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
            const cwd_path = try std.fs.cwd().realpath(".", &cwd_path_buffer);
            var cwd = try std.fs.openDirAbsolute(cwd_path, .{});
            defer cwd.close();

            // get an iterator for the files in the cwd
            var root_dir = try cwd.makeOpenPathIterable(".", .{});
            defer root_dir.close();
            var iter = root_dir.iterate();

            // iterate over each file (not recursive...to do that, use walk instead of iterate)
            while (try iter.next()) |entry| {
                // skip things
                if (std.mem.eql(u8, entry.name, ".git")) {
                    continue;
                }
                // if it's a file...
                if (entry.kind == std.fs.File.Kind.File) {
                    // get absolute path of the file
                    var path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
                    const in_path = try cwd.realpath(entry.name, &path_buffer);
                    var in = try std.fs.openFileAbsolute(in_path, .{ .mode = std.fs.File.OpenMode.read_only });
                    defer in.close();

                    // calc the sha1 of its contents
                    var sha1_hex_buffer = [_]u8{0} ** hash.SHA1_HEX_LEN;
                    const sha1_hex = try hash.sha1(in, &sha1_hex_buffer);

                    std.debug.print("{}: '{s}' {s}\n", .{ entry.kind, in_path, sha1_hex });

                    // compress the file
                    var out_compressed = try cwd.createFile("out_compressed", .{ .read = true });
                    defer out_compressed.close();
                    try compress.compress(in, out_compressed, allocator);

                    // decompress it so we know it works
                    var out_decompressed = try cwd.createFile("out_decompressed", .{});
                    defer out_decompressed.close();
                    try compress.decompress(out_compressed, out_decompressed, allocator);
                }
            }
        },
    }
}

/// this is the main "main". it's even mainier than zitMain.
/// this is the real deal. there is no main more main than this.
/// at least, not that i know of. i guess internally zig probably
/// has an earlier entrypoint which is even mainier than this.
/// i wonder where it all actually begins. when you first turn your
/// computer on, where does the big bang happen? it's a beautiful
/// thing to think about.
pub fn main() !void {
    const allocator = std.heap.page_allocator;
    var args = std.ArrayList([]const u8).init(allocator);
    defer args.deinit();

    try appendArgs(&args);
    try zitMain(&args, allocator);
}
