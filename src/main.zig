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
const hash = @import("./hash.zig");

/// this is meant to be the main entry point if you wanted to use xit
/// as a CLI tool. to use xit programmatically, build a Repo struct
/// and call methods on it directly. to use xit subconsciously, just
/// think about it really often and eventually you'll dream about it.
pub fn run(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    allocator: std.mem.Allocator,
    args: []const []const u8,
    cwd: std.fs.Dir,
    writers: rp.Writers,
) !void {
    var cmd_args = try cmd.CommandArgs.init(allocator, args);
    defer cmd_args.deinit();

    switch (try cmd.CommandDispatch(repo_kind, repo_opts.hash).init(&cmd_args)) {
        .invalid => |invalid| switch (invalid) {
            .command => |command| {
                try writers.err.print("\"{s}\" is not a valid command\n\n", .{command});
                try cmd.printHelp(null, writers);
            },
            .argument => |argument| {
                try writers.err.print("\"{s}\" is not a valid argument\n\n", .{argument.value});
                try cmd.printHelp(argument.command, writers);
            },
        },
        .help => |cmd_kind_maybe| try cmd.printHelp(cmd_kind_maybe, writers),
        .tui => |cmd_kind_maybe| if (.none == repo_opts.hash) {
            // if no hash was specified, use AnyRepo to detect the hash being used
            var any_repo = try rp.AnyRepo(repo_kind, repo_opts).open(allocator, .{ .cwd = cwd });
            defer any_repo.deinit();
            switch (any_repo) {
                .none => return error.HashKindNotFound,
                .sha1 => |*repo| try ui.start(repo_kind, repo_opts.withHash(.sha1), repo, allocator, cmd_kind_maybe),
                .sha256 => |*repo| try ui.start(repo_kind, repo_opts.withHash(.sha256), repo, allocator, cmd_kind_maybe),
            }
        } else {
            var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = cwd });
            defer repo.deinit();
            try ui.start(repo_kind, repo_opts, &repo, allocator, cmd_kind_maybe);
        },
        .cli => |cli_cmd| switch (cli_cmd) {
            .init => |init_cmd| {
                const new_repo_opts = comptime if (.none == repo_opts.hash)
                    // if no hash was specified, just use the default hash
                    repo_opts.withHash((rp.RepoOpts(repo_kind){}).hash)
                else
                    repo_opts;
                var repo = try rp.Repo(repo_kind, new_repo_opts).init(allocator, .{ .cwd = cwd }, init_cmd.dir);
                defer repo.deinit();

                // add default user config
                try repo.addConfig(allocator, .{ .name = "user.name", .value = "fixme" });
                try repo.addConfig(allocator, .{ .name = "user.email", .value = "fix@me" });

                try writers.out.print(
                    \\congrats, you just created a new repo! aren't you special.
                    \\try setting your name and email. if you're too lazy, the
                    \\default ones will be used, and you'll be like one of those
                    \\low-effort people who make slides with times new roman font.
                    \\
                    \\    xit config add user.name foo
                    \\    xit config add user.email foo@bar
                    \\
                , .{});
            },
            else => if (.none == repo_opts.hash) {
                // if no hash was specified, use AnyRepo to detect the hash being used
                var any_repo = try rp.AnyRepo(repo_kind, repo_opts).open(allocator, .{ .cwd = cwd });
                defer any_repo.deinit();
                switch (any_repo) {
                    .none => return error.HashKindNotFound,
                    .sha1 => |*repo| {
                        const cmd_maybe = try cmd.Command(repo_kind, .sha1).init(&cmd_args);
                        try repo.runCommand(allocator, cmd_maybe orelse return error.InvalidCommand, writers);
                    },
                    .sha256 => |*repo| {
                        const cmd_maybe = try cmd.Command(repo_kind, .sha256).init(&cmd_args);
                        try repo.runCommand(allocator, cmd_maybe orelse return error.InvalidCommand, writers);
                    },
                }
            } else {
                var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = cwd });
                defer repo.deinit();
                try repo.runCommand(allocator, cli_cmd, writers);
            },
        },
    }
}

/// this is the main "main". it's even mainier than "run".
/// this is the real deal. there is no main more main than this.
/// at least, not that i know of. i guess internally zig probably
/// has an earlier entrypoint which is even mainier than this.
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

    const writers = rp.Writers{ .out = std.io.getStdOut().writer().any(), .err = std.io.getStdErr().writer().any() };
    try run(.xit, .{}, allocator, args.items, std.fs.cwd(), writers);
}
