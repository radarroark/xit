//! the command parsed from CLI args.

const std = @import("std");
const rp = @import("./repo.zig");
const df = @import("./diff.zig");
const mrg = @import("./merge.zig");
const idx = @import("./index.zig");
const obj = @import("./object.zig");
const cfg = @import("./config.zig");
const bch = @import("./branch.zig");
const ref = @import("./ref.zig");
const hash = @import("./hash.zig");

pub const SubCommandKind = enum {
    init,
    add,
    unadd,
    rm,
    reset,
    commit,
    status,
    diff,
    branch,
    switch_head,
    restore,
    log,
    merge,
    config,
    remote,
    fetch,
    pull,
};

pub const SubCommandArgs = struct {
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    sub_command_kind: ?SubCommandKind,
    positional_args: std.ArrayList([]const u8),
    map_args: std.StringArrayHashMap(?[]const u8),

    pub fn init(allocator: std.mem.Allocator, args: []const []const u8) !SubCommandArgs {
        const arena = try allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        errdefer {
            arena.deinit();
            allocator.destroy(arena);
        }

        var positional_args = std.ArrayList([]const u8).init(arena.allocator());
        var map_args = std.StringArrayHashMap(?[]const u8).init(arena.allocator());

        for (args) |arg| {
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
                        try positional_args.append(arg);
                    }
                    // otherwise put it in the map
                    else if (last_val.? == null) {
                        try map_args.put(last_key, arg);
                    }
                } else {
                    try positional_args.append(arg);
                }
            }
        }

        if (positional_args.items.len == 0) {
            return .{
                .allocator = allocator,
                .arena = arena,
                .sub_command_kind = null,
                .positional_args = positional_args,
                .map_args = map_args,
            };
        } else {
            const sub_command = positional_args.items[0];

            const sub_command_kind: ?SubCommandKind =
                if (std.mem.eql(u8, sub_command, "init"))
                .init
            else if (std.mem.eql(u8, sub_command, "add"))
                .add
            else if (std.mem.eql(u8, sub_command, "unadd"))
                .unadd
            else if (std.mem.eql(u8, sub_command, "rm"))
                .rm
            else if (std.mem.eql(u8, sub_command, "reset"))
                .reset
            else if (std.mem.eql(u8, sub_command, "commit"))
                .commit
            else if (std.mem.eql(u8, sub_command, "status"))
                .status
            else if (std.mem.eql(u8, sub_command, "diff"))
                .diff
            else if (std.mem.eql(u8, sub_command, "branch"))
                .branch
            else if (std.mem.eql(u8, sub_command, "switch"))
                .switch_head
            else if (std.mem.eql(u8, sub_command, "restore"))
                .restore
            else if (std.mem.eql(u8, sub_command, "log"))
                .log
            else if (std.mem.eql(u8, sub_command, "merge"))
                .merge
            else if (std.mem.eql(u8, sub_command, "cherry-pick"))
                .merge
            else if (std.mem.eql(u8, sub_command, "config"))
                .config
            else if (std.mem.eql(u8, sub_command, "remote"))
                .remote
            else if (std.mem.eql(u8, sub_command, "fetch"))
                .fetch
            else if (std.mem.eql(u8, sub_command, "pull"))
                .pull
            else
                null;

            return .{
                .allocator = allocator,
                .arena = arena,
                .sub_command_kind = sub_command_kind,
                .positional_args = positional_args,
                .map_args = map_args,
            };
        }
    }

    pub fn deinit(self: *SubCommandArgs) void {
        self.arena.deinit();
        self.allocator.destroy(self.arena);
    }
};

pub fn SubCommand(comptime repo_kind: rp.RepoKind, comptime hash_kind: hash.HashKind) type {
    return union(SubCommandKind) {
        init: struct {
            dir: []const u8,
        },
        add: struct {
            paths: []const []const u8,
        },
        unadd: struct {
            paths: []const []const u8,
            opts: idx.IndexUnaddOptions,
        },
        rm: struct {
            paths: []const []const u8,
            opts: idx.IndexRemoveOptions,
        },
        reset: struct {
            path: []const u8,
        },
        commit: obj.CommitMetadata(hash_kind),
        status,
        diff: struct {
            diff_opts: df.BasicDiffOptions(hash_kind),
        },
        branch: bch.BranchCommand,
        switch_head: struct {
            target: []const u8,
        },
        restore: struct {
            path: []const u8,
        },
        log,
        merge: mrg.MergeInput(repo_kind, hash_kind),
        config: cfg.ConfigCommand,
        remote: cfg.ConfigCommand,
        fetch: struct {
            remote_name: []const u8,
        },
        pull: struct {
            remote_name: []const u8,
            remote_ref_name: []const u8,
        },
    };
}

pub fn Command(comptime repo_kind: rp.RepoKind, comptime hash_kind: hash.HashKind) type {
    return union(enum) {
        invalid: struct {
            name: []const u8,
        },
        help: ?SubCommandKind,
        tui: ?SubCommandKind,
        cli: ?SubCommand(repo_kind, hash_kind),

        pub fn init(sub_cmd_args: *const SubCommandArgs) !Command(repo_kind, hash_kind) {
            if (sub_cmd_args.sub_command_kind) |sub_command_kind| {
                const extra_args = sub_cmd_args.positional_args.items[1..];
                const show_help = sub_cmd_args.map_args.contains("--help");

                switch (sub_command_kind) {
                    .init => {
                        if (extra_args.len == 0) {
                            return .{ .cli = .{ .init = .{ .dir = "." } } };
                        } else if (extra_args.len == 1) {
                            return .{ .cli = .{ .init = .{ .dir = extra_args[0] } } };
                        } else {
                            return .{ .help = .init };
                        }
                    },
                    .add => {
                        if (extra_args.len == 0 or show_help) {
                            return .{ .help = .add };
                        } else {
                            return .{ .cli = .{ .add = .{ .paths = extra_args } } };
                        }
                    },
                    .unadd => {
                        if (extra_args.len == 0 or show_help) {
                            return .{ .help = .unadd };
                        } else {
                            return .{ .cli = .{ .unadd = .{
                                .paths = extra_args,
                                .opts = .{
                                    .force = sub_cmd_args.map_args.contains("-f"),
                                },
                            } } };
                        }
                    },
                    .rm => {
                        if (extra_args.len == 0 or show_help) {
                            return .{ .help = .rm };
                        } else {
                            return .{ .cli = .{ .rm = .{
                                .paths = extra_args,
                                .opts = .{
                                    .force = sub_cmd_args.map_args.contains("-f"),
                                    .remove_from_workspace = true,
                                },
                            } } };
                        }
                    },
                    .reset => {
                        if (extra_args.len != 1 or show_help) {
                            return .{ .help = .reset };
                        } else {
                            return .{ .cli = .{ .reset = .{ .path = extra_args[0] } } };
                        }
                    },
                    .commit => {
                        // if a message is included, it must have a non-null value
                        const message = if (sub_cmd_args.map_args.get("-m")) |msg| (msg orelse return error.CommitMessageNotFound) else "";
                        return .{ .cli = .{ .commit = .{ .message = message } } };
                    },
                    .status => {
                        if (extra_args.len > 0 or show_help) {
                            return .{ .help = .status };
                        } else if (sub_cmd_args.map_args.contains("--cli")) {
                            return .{ .cli = .status };
                        } else {
                            return .{ .tui = .status };
                        }
                    },
                    .diff => {
                        if (extra_args.len > 0 or show_help) {
                            return .{ .help = .diff };
                        } else if (sub_cmd_args.map_args.contains("--cli")) {
                            const diff_opts: df.BasicDiffOptions(hash_kind) = if (sub_cmd_args.map_args.contains("--staged"))
                                .index
                            else
                                (if (sub_cmd_args.map_args.contains("--base"))
                                    .{ .workspace = .{ .conflict_diff_kind = .base } }
                                else if (sub_cmd_args.map_args.contains("--ours"))
                                    .{ .workspace = .{ .conflict_diff_kind = .target } }
                                else if (sub_cmd_args.map_args.contains("--theirs"))
                                    .{ .workspace = .{ .conflict_diff_kind = .source } }
                                else
                                    .{ .workspace = .{ .conflict_diff_kind = .target } });
                            return .{ .cli = .{ .diff = .{ .diff_opts = diff_opts } } };
                        } else {
                            return .{ .tui = .diff };
                        }
                    },
                    .branch => {
                        if (extra_args.len == 0 or show_help) {
                            return .{ .help = .branch };
                        } else {
                            const cmd_name = extra_args[0];

                            var cmd: bch.BranchCommand = undefined;
                            if (std.mem.eql(u8, "list", cmd_name)) {
                                cmd = .list;
                            } else if (std.mem.eql(u8, "add", cmd_name)) {
                                if (extra_args.len != 2) {
                                    return error.WrongNumberOfBranchArgs;
                                }
                                cmd = .{ .add = .{ .name = extra_args[1] } };
                            } else if (std.mem.eql(u8, "rm", cmd_name)) {
                                if (extra_args.len != 2) {
                                    return error.WrongNumberOfBranchArgs;
                                }
                                cmd = .{ .remove = .{ .name = extra_args[1] } };
                            } else {
                                return error.InvalidBranchCommand;
                            }

                            return .{ .cli = .{ .branch = cmd } };
                        }
                    },
                    .switch_head => {
                        if (extra_args.len != 1 or show_help) {
                            return .{ .help = .switch_head };
                        } else {
                            return .{ .cli = .{ .switch_head = .{ .target = extra_args[0] } } };
                        }
                    },
                    .restore => {
                        if (extra_args.len != 1 or show_help) {
                            return .{ .help = .restore };
                        } else {
                            return .{ .cli = .{ .restore = .{ .path = extra_args[0] } } };
                        }
                    },
                    .log => {
                        if (extra_args.len != 0 or show_help) {
                            return .{ .help = .log };
                        } else if (sub_cmd_args.map_args.contains("--cli")) {
                            return .{ .cli = .log };
                        } else {
                            return .{ .tui = .log };
                        }
                    },
                    .merge => {
                        if (show_help) {
                            return .{ .help = .merge };
                        } else {
                            const sub_command = sub_cmd_args.positional_args.items[0];
                            const merge_kind: mrg.MergeKind = if (std.mem.eql(u8, "merge", sub_command))
                                .full
                            else if (std.mem.eql(u8, "cherry-pick", sub_command))
                                .pick
                            else
                                return error.InvalidMergeKind;

                            const merge_action: mrg.MergeAction(repo_kind, hash_kind) =
                                if (sub_cmd_args.map_args.contains("--continue"))
                                .cont
                            else blk: {
                                var source = std.ArrayList(ref.RefOrOid(hash_kind)).init(sub_cmd_args.arena.allocator());
                                for (extra_args) |arg| {
                                    try source.append(ref.RefOrOid(hash_kind).initFromUser(arg));
                                }
                                break :blk .{ .new = .{ .source = try source.toOwnedSlice() } };
                            };

                            return .{
                                .cli = .{
                                    .merge = .{
                                        .kind = merge_kind,
                                        .action = merge_action,
                                    },
                                },
                            };
                        }
                    },
                    .config => {
                        if (extra_args.len == 0 or show_help) {
                            return .{ .help = .config };
                        } else {
                            const cmd_name = extra_args[0];

                            var cmd: cfg.ConfigCommand = undefined;
                            if (std.mem.eql(u8, "list", cmd_name)) {
                                cmd = .list;
                            } else if (std.mem.eql(u8, "add", cmd_name)) {
                                if (extra_args.len != 3) {
                                    return error.WrongNumberOfConfigArgs;
                                }
                                cmd = .{ .add = .{
                                    .name = extra_args[1],
                                    .value = extra_args[2],
                                } };
                            } else if (std.mem.eql(u8, "rm", cmd_name)) {
                                if (extra_args.len != 2) {
                                    return error.WrongNumberOfConfigArgs;
                                }
                                cmd = .{ .remove = .{
                                    .name = extra_args[1],
                                } };
                            } else {
                                return error.InvalidConfigCommand;
                            }

                            return .{ .cli = .{ .config = cmd } };
                        }
                    },
                    .remote => {
                        if (extra_args.len == 0 or show_help) {
                            return .{ .help = .remote };
                        } else {
                            const cmd_name = extra_args[0];

                            var cmd: cfg.ConfigCommand = undefined;
                            if (std.mem.eql(u8, "list", cmd_name)) {
                                cmd = .list;
                            } else if (std.mem.eql(u8, "add", cmd_name)) {
                                if (extra_args.len != 3) {
                                    return error.WrongNumberOfRemoteArgs;
                                }
                                cmd = .{ .add = .{
                                    .name = extra_args[1],
                                    .value = extra_args[2],
                                } };
                            } else if (std.mem.eql(u8, "rm", cmd_name)) {
                                if (extra_args.len != 2) {
                                    return error.WrongNumberofRemoteArgs;
                                }
                                cmd = .{ .remove = .{
                                    .name = extra_args[1],
                                } };
                            } else {
                                return error.InvalidRemoteCommand;
                            }

                            return .{ .cli = .{ .remote = cmd } };
                        }
                    },
                    .fetch => {
                        if (extra_args.len != 1 or show_help) {
                            return .{ .help = .fetch };
                        } else {
                            return .{ .cli = .{ .fetch = .{
                                .remote_name = extra_args[0],
                            } } };
                        }
                    },
                    .pull => {
                        if (extra_args.len != 2 or show_help) {
                            return .{ .help = .pull };
                        } else {
                            return .{ .cli = .{ .pull = .{
                                .remote_name = extra_args[0],
                                .remote_ref_name = extra_args[1],
                            } } };
                        }
                    },
                }
            } else if (sub_cmd_args.positional_args.items.len > 0) {
                return .{ .invalid = .{ .name = sub_cmd_args.positional_args.items[0] } };
            } else {
                if (sub_cmd_args.map_args.count() == 0) {
                    return .{ .tui = null };
                } else {
                    return .{ .cli = null };
                }
            }
        }
    };
}

test "command" {
    const repo_kind = rp.RepoKind.git;
    const hash_kind = hash.HashKind.sha1;
    const allocator = std.testing.allocator;

    var args = std.ArrayList([]const u8).init(allocator);
    defer args.deinit();

    {
        var sub_cmd_args = try SubCommandArgs.init(allocator, &.{ "add", "--cli" });
        defer sub_cmd_args.deinit();
        const command = try Command(repo_kind, hash_kind).init(&sub_cmd_args);
        try std.testing.expect(command == .help);
    }

    {
        var sub_cmd_args = try SubCommandArgs.init(allocator, &.{ "add", "file.txt" });
        defer sub_cmd_args.deinit();
        const command = try Command(repo_kind, hash_kind).init(&sub_cmd_args);
        try std.testing.expect(command == .cli and command.cli.? == .add);
    }

    {
        var sub_cmd_args = try SubCommandArgs.init(allocator, &.{ "commit", "-m" });
        defer sub_cmd_args.deinit();
        const command_or_err = Command(repo_kind, hash_kind).init(&sub_cmd_args);
        if (command_or_err) |_| {
            return error.ExpectedError;
        } else |err| {
            try std.testing.expect(error.CommitMessageNotFound == err);
        }
    }

    {
        var sub_cmd_args = try SubCommandArgs.init(allocator, &.{ "commit", "-m", "let there be light" });
        defer sub_cmd_args.deinit();
        const command = try Command(repo_kind, hash_kind).init(&sub_cmd_args);
        try std.testing.expect(command == .cli and command.cli.? == .commit);
        try std.testing.expect(std.mem.eql(u8, "let there be light", command.cli.?.commit.message));
    }
}
