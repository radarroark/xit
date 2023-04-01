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
const object = @import("./object.zig");
const cmd = @import("./command.zig");
const idx = @import("./index.zig");
const stat = @import("./status.zig");

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

/// this is meant to be the main entry point if you wanted to use zit
/// as a library. there will definitely be more specialized functions
/// you can call as well, but if you just want to pass the CLI args and
/// have it behave just like the standalone git client than this is
/// where it's at, homie.
pub fn zitMain(allocator: std.mem.Allocator, args: *std.ArrayList([]const u8)) !void {
    var command = try cmd.Command.init(allocator, args);
    defer command.deinit();

    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    // get the cwd path
    var cwd_path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
    const cwd_path = try std.fs.cwd().realpath(".", &cwd_path_buffer);
    var cwd = try std.fs.openDirAbsolute(cwd_path, .{});
    defer cwd.close();

    switch (command.data) {
        cmd.CommandData.invalid => {
            try stderr.print("\"{s}\" is not a valid command\n", .{command.data.invalid.name});
            return;
        },
        cmd.CommandData.usage => {
            try stdout.print(
                \\usage: zit
                \\
                \\start a working area:
                \\   init
                \\
            , .{});
        },
        cmd.CommandData.init => {
            // get the root dir. no path was given to the init command, this
            // should just be the current working directory (cwd). if a path was
            // given, it should either append it to the cwd or, if it is absolute,
            // it should just use that path alone. IT'S MAGIC!
            var root_dir = try std.fs.cwd().makeOpenPath(command.data.init.dir, .{});
            defer root_dir.close();

            // make the .git dir. right now we're throwing an error if it already
            // exists. in git it says "Reinitialized existing Git repository" so
            // we'll need to do that eventually.
            root_dir.makeDir(".git") catch |err| {
                switch (err) {
                    error.PathAlreadyExists => {
                        try stderr.print("{s} is already a repository\n", .{command.data.init.dir});
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
        cmd.CommandData.add => {
            try idx.writeIndex(allocator, cwd, command.data.add.paths);
        },
        cmd.CommandData.commit => {
            try object.writeCommit(allocator, cwd, command.data);
        },
        cmd.CommandData.status => {
            var git_dir = try cwd.openDir(".git", .{});
            defer git_dir.close();
            var status = try stat.Status.init(allocator, cwd, git_dir);
            defer status.deinit();
            for (status.entries.items) |entry| {
                try stdout.print("{s}\n", .{entry});
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
    try zitMain(allocator, &args);
}
