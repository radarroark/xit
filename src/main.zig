//! you're looking at radar's hopeless attempt to implement
//! the successor to git. behold the three rules of xit:
//!
//! 1. keep the codebase small and stupid.
//! 2. prefer simple 80% solutions over complex 100% solutions.
//! 3. never take yourself too seriously. be a dork, and you'll
//! attract dorks. together, we'll make a glorious pack of strays.
//!
//! "C'mon Alex! You always dreamt about going on a big adventure!
//!  Let this be our first!" -- Lunar: Silver Star Story

const std = @import("std");
const cmd = @import("./command.zig");
const rp = @import("./repo.zig");
const ui = @import("./ui.zig");

const USAGE =
    \\
    \\start a working area:
    \\   init
    \\
;

/// this is meant to be the main entry point if you wanted to use xit
/// as a CLI tool. to use xit programmatically, build a Repo struct
/// and call methods on it directly. to use xit subconsciously, just
/// think about it really often and eventually you'll dream about it.
pub fn xitMain(
    comptime repo_kind: rp.RepoKind,
    allocator: std.mem.Allocator,
    args: []const []const u8,
    cwd: std.fs.Dir,
    writers: anytype,
) !void {
    var command = try cmd.Command.init(allocator, args);
    defer command.deinit();

    switch (command) {
        .invalid => |invalid| {
            try writers.err.print("\"{s}\" is not a valid command\n", .{invalid.name});
            try writers.out.print(USAGE, .{});
        },
        .help => |sub_cmd_kind_maybe| {
            if (sub_cmd_kind_maybe) |sub_cmd_kind| {
                // TODO: print usage for each sub command
                switch (sub_cmd_kind) {
                    else => try writers.out.print(USAGE, .{}),
                }
            } else {
                try writers.out.print(USAGE, .{});
            }
        },
        .tui => |sub_cmd_kind_maybe| {
            var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = cwd });
            defer repo.deinit();
            try ui.start(repo_kind, &repo, allocator, sub_cmd_kind_maybe);
        },
        .cli => |sub_cmd_maybe| {
            if (sub_cmd_maybe) |sub_cmd| {
                var repo = try rp.Repo(repo_kind).initWithCommand(allocator, .{ .cwd = cwd }, sub_cmd, writers);
                defer repo.deinit();
            } else {
                try writers.out.print(USAGE, .{});
            }
        },
    }
}

/// this is the main "main". it's even mainier than xitMain.
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

    var arg_it = try std.process.argsWithAllocator(allocator);
    defer arg_it.deinit();
    _ = arg_it.skip();
    while (arg_it.next()) |arg| {
        try args.append(arg);
    }

    try xitMain(
        .xit,
        allocator,
        args.items,
        std.fs.cwd(),
        .{ .out = std.io.getStdOut().writer(), .err = std.io.getStdErr().writer() },
    );
}
