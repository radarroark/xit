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
    \\switch        Switch branches
    \\                  xit switch mybranch
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
    \\                  xit merge mybranch
    \\
    \\cherry-pick   Apply the changes introduced by an existing commit
    \\              (must be the entire oid for now)
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
    if (repo_opts.hash == .none) {
        // if the hash is set to none, it means we should try to auto-detect
        // the hash kind that is being used by the repo. this will be useful
        // in the future when we need to support multiple hash algorithms.

        // if we are initing a new repo, just use the default hash kind
        {
            const sub_cmd_kind_maybe = blk: {
                var sub_cmd_args = try cmd.SubCommandArgs.init(allocator, args);
                defer sub_cmd_args.deinit();
                break :blk sub_cmd_args.sub_command_kind;
            };

            if (sub_cmd_kind_maybe) |sub_cmd_kind| {
                if (sub_cmd_kind == .init) {
                    const default_hash = (rp.RepoOpts(repo_kind){}).hash;
                    try run(repo_kind, repo_opts.withHash(default_hash), allocator, args, cwd, writers);
                    return;
                }
            }
        }

        // find the existing hash kind from the repo and include it in the repo opts
        const hash_kind = blk: {
            var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = cwd });
            defer repo.deinit();
            break :blk try repo.hashKind();
        };
        switch (hash_kind) {
            .none => return error.HashKindNotFound,
            .sha1 => try run(repo_kind, repo_opts.withHash(.sha1), allocator, args, cwd, writers),
        }
    } else {
        var sub_cmd_args = try cmd.SubCommandArgs.init(allocator, args);
        defer sub_cmd_args.deinit();

        const command = try cmd.Command(repo_opts.hash).init(&sub_cmd_args);
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
                var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = cwd });
                defer repo.deinit();
                try ui.start(repo_kind, repo_opts, &repo, allocator, sub_cmd_kind_maybe);
            },
            .cli => |sub_cmd_maybe| {
                if (sub_cmd_maybe) |sub_cmd| {
                    var repo = try rp.Repo(repo_kind, repo_opts).initWithCommand(allocator, .{ .cwd = cwd }, sub_cmd, writers);
                    defer repo.deinit();
                    try repo.runCommand(allocator, sub_cmd, writers);
                } else {
                    try writers.out.print(USAGE, .{});
                }
            },
        }
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
