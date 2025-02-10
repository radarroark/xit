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

const USAGE =
    \\
    \\usage: xit <command> [<args>]
    \\
    \\init          Create an empty xit repository
    \\              (in the current dir)
    \\                  xit init
    \\              (in a new dir)
    \\                  xit init myproject
    \\
    \\add           Add file contents to the index
    \\                  xit add myfile.txt
    \\
    \\unadd         Remove file contents from the index,
    \\              but not from the working tree
    \\                  xit unadd myfile.txt
    \\
    \\rm            Remove file contents from the index
    \\              and from the working tree
    \\                  xit rm myfile.txt
    \\
    \\reset         Add or remove file to/from the index
    \\              to match what's in the latest commit
    \\                  xit reset myfile.txt
    \\
    \\commit        Record changes to the repository
    \\                  xit commit -m "my commit message"
    \\
    \\status        Show the working tree status
    \\              (display in TUI)
    \\                  xit status
    \\              (display in CLI)
    \\                  xit status --cli
    \\
    \\diff          Show changes between commits, commit and working tree, etc
    \\              (display in TUI)
    \\                  xit diff
    \\              (display diff of workspace content in the CLI)
    \\                  xit diff --cli
    \\              (display diff of staged content in the CLI)
    \\                  xit diff --staged
    \\
    \\branch        Add, remove, and list branches
    \\              (add branch)
    \\                  xit branch add mybranch
    \\              (remove branch)
    \\                  xit branch rm mybranch
    \\              (list branches)
    \\                  xit branch list
    \\
    \\switch        Switch working tree to a branch or commit id
    \\              (switch to branch)
    \\                  xit switch mybranch
    \\              (switch to commit id)
    \\                  xit switch :a1b2c3...
    \\
    \\restore       Restore working tree files
    \\                  xit restore myfile.txt
    \\
    \\log           Show commit logs
    \\              (display in TUI)
    \\                  xit log
    \\              (display in CLI)
    \\                  xit log --cli
    \\
    \\merge         Join two or more development histories together
    \\              (merge branch)
    \\                  xit merge mybranch
    \\              (merge commit id)
    \\                  xit merge a1b2c3...
    \\
    \\cherry-pick   Apply the changes introduced by an existing commit
    \\                  xit cherry-pick a1b2c3...
    \\
    \\config        Add, remove, and list config options
    \\              (add config)
    \\                  xit config add core.editor vim
    \\              (remove config)
    \\                  xit config rm core.editor
    \\              (list configs)
    \\                  xit config list
    \\
    \\remote        Add, remove, and list remotes
    \\              (add remote)
    \\                  xit remote add origin https://github.com/...
    \\              (remove remote)
    \\                  xit remote rm origin
    \\              (list remotes)
    \\                  xit remote list
    \\
;

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
                try writers.err.print("\"{s}\" is not a valid command\n", .{command});
                try writers.out.print(USAGE, .{});
            },
            .argument => |argument| {
                try writers.err.print("\"{s}\" is not a valid argument\n", .{argument.value});
                try writers.out.print(USAGE, .{});
            },
        },
        .help => |cmd_kind_maybe| if (cmd_kind_maybe) |cmd_kind| switch (cmd_kind) {
            // TODO: print usage for each sub command
            else => try writers.out.print(USAGE, .{}),
        } else {
            try writers.out.print(USAGE, .{});
        },
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
