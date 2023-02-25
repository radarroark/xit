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
const index = @import("./index.zig");

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

/// returns the data from the process args in a nicer format.
/// right now it just parses the args into a sorted map. i was
/// thinking of using an existing arg parser lib but i decided
/// i should roll my own and let it evolve along with my needs.
/// i'm actually pretty happy with this already...it's stupid
/// but it works, and unlike those libs i understand every line.
fn parseArgs(args: *std.ArrayList([]const u8), allocator: std.mem.Allocator, arena: *std.heap.ArenaAllocator) !cmd.Command {
    if (args.items.len >= 1) {
        // put args into data structures for easy access
        var pos_args = std.ArrayList([]const u8).init(allocator);
        defer pos_args.deinit();
        var map_args = std.StringArrayHashMap(?[]const u8).init(allocator);
        defer map_args.deinit();
        for (args.items[1..]) |arg| {
            if (arg.len == 0) {
                continue;
            } else if (arg.len > 1 and arg[0] == '-') {
                try map_args.put(arg, null);
            } else {
                const keys = map_args.keys();
                if (keys.len > 0) {
                    const last_key = keys[keys.len - 1];
                    const last_val = map_args.get(last_key);
                    // if there isn't a spot for this arg in the map,
                    // it is a positional arg
                    if (last_val == null or last_val.? != null) {
                        try pos_args.append(arg);
                    }
                    // otherwise put it in the map
                    else if (last_val.? == null) {
                        try map_args.put(last_key, arg);
                    }
                } else {
                    try pos_args.append(arg);
                }
            }
        }
        // branch on the first arg
        if (std.mem.eql(u8, args.items[0], "init")) {
            return cmd.Command{ .init = .{ .dir = if (args.items.len > 1) args.items[1] else "." } };
        } else if (std.mem.eql(u8, args.items[0], "add")) {
            if (pos_args.items.len == 0) {
                return cmd.CommandError.AddPathsMissing;
            }
            var paths = try std.ArrayList([]const u8).initCapacity(arena.allocator(), pos_args.capacity);
            paths.appendSliceAssumeCapacity(pos_args.items);
            return cmd.Command{ .add = .{ .paths = paths } };
        } else if (std.mem.eql(u8, args.items[0], "commit")) {
            // if a message is included, it must have a non-null value
            const message_maybe = map_args.get("-m");
            const message = if (message_maybe == null) null else (message_maybe.? orelse return cmd.CommandError.CommitMessageMissing);
            return cmd.Command{ .commit = .{ .message = message } };
        } else {
            return cmd.Command{ .invalid = .{ .name = args.items[0] } };
        }
    }

    return cmd.Command{ .usage = {} };
}

test "parseArgs" {
    const allocator = std.testing.allocator;
    var args = std.ArrayList([]const u8).init(allocator);
    defer args.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    args.clearAndFree();
    try args.append("add");
    try std.testing.expect(cmd.CommandError.AddPathsMissing == parseArgs(&args, allocator, &arena));

    args.clearAndFree();
    try args.append("add");
    try args.append("file.txt");
    const add_cmd = try parseArgs(&args, allocator, &arena);
    try std.testing.expect(add_cmd == .add);
    defer add_cmd.add.paths.deinit();

    args.clearAndFree();
    try args.append("commit");
    try args.append("-m");
    try std.testing.expect(cmd.CommandError.CommitMessageMissing == parseArgs(&args, allocator, &arena));

    args.clearAndFree();
    try args.append("commit");
    const commit_cmd_without_msg = try parseArgs(&args, allocator, &arena);
    try std.testing.expect(commit_cmd_without_msg == .commit);
    try std.testing.expect(null == commit_cmd_without_msg.commit.message);

    args.clearAndFree();
    try args.append("commit");
    try args.append("-m");
    try args.append("let there be light");
    const commit_cmd_with_msg = try parseArgs(&args, allocator, &arena);
    try std.testing.expect(commit_cmd_with_msg == .commit);
    try std.testing.expect(null != commit_cmd_with_msg.commit.message);
    try std.testing.expect(std.mem.eql(u8, "let there be light", commit_cmd_with_msg.commit.message.?));
}

/// this is meant to be the main entry point if you wanted to use zit
/// as a library. there will definitely be more specialized functions
/// you can call as well, but if you just want to pass the CLI args and
/// have it behave just like the standalone git client than this is
/// where it's at, homie.
pub fn zitMain(args: *std.ArrayList([]const u8), allocator: std.mem.Allocator) !void {
    // make arena for any allocations that need to be made by parseArgs
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const command = try parseArgs(args, allocator, &arena);

    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    // get the cwd path
    var cwd_path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
    const cwd_path = try std.fs.cwd().realpath(".", &cwd_path_buffer);
    var cwd = try std.fs.openDirAbsolute(cwd_path, .{});
    defer cwd.close();

    switch (command) {
        cmd.Command.invalid => {
            try stderr.print("\"{s}\" is not a valid command\n", .{command.invalid.name});
            return;
        },
        cmd.Command.usage => {
            try stdout.print(
                \\usage: zit
                \\
                \\start a working area:
                \\   init
                \\
            , .{});
        },
        cmd.Command.init => {
            // get the root dir. no path was given to the init command, this
            // should just be the current working directory (cwd). if a path was
            // given, it should either append it to the cwd or, if it is absolute,
            // it should just use that path alone. IT'S MAGIC!
            var root_dir = try std.fs.cwd().makeOpenPath(command.init.dir, .{});
            defer root_dir.close();

            // make the .git dir. right now we're throwing an error if it already
            // exists. in git it says "Reinitialized existing Git repository" so
            // we'll need to do that eventually.
            root_dir.makeDir(".git") catch |err| {
                switch (err) {
                    error.PathAlreadyExists => {
                        try stderr.print("{s} is already a repository\n", .{command.init.dir});
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
        cmd.Command.add => {
            try index.writeIndex(cwd, command.add.paths, allocator);
        },
        cmd.Command.commit => {
            // write commit object
            var sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
            try object.writeObject(cwd, ".", allocator, null, &sha1_bytes_buffer);
            var sha1_hex_buffer = [_]u8{0} ** hash.SHA1_HEX_LEN;
            const sha1_hex = try std.fmt.bufPrint(&sha1_hex_buffer, "{}", .{std.fmt.fmtSliceHexLower(&sha1_bytes_buffer)});
            try object.writeCommit(cwd, allocator, command, sha1_hex);
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
