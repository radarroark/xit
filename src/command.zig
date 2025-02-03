//! the command parsed from CLI args.

const std = @import("std");
const rp = @import("./repo.zig");
const df = @import("./diff.zig");
const mrg = @import("./merge.zig");
const idx = @import("./index.zig");
const obj = @import("./object.zig");
const cfg = @import("./config.zig");
const bch = @import("./branch.zig");
const rf = @import("./ref.zig");
const hash = @import("./hash.zig");
const res = @import("./restore.zig");

pub const CommandKind = enum {
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

pub const CommandArgs = struct {
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    command_kind: ?CommandKind,
    command_name: ?[]const u8,
    positional_args: []const []const u8,
    map_args: std.StringArrayHashMap(?[]const u8),
    unused_args: std.StringArrayHashMap(void),

    pub fn init(allocator: std.mem.Allocator, args: []const []const u8) !CommandArgs {
        const arena = try allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        errdefer {
            arena.deinit();
            allocator.destroy(arena);
        }

        var positional_args = std.ArrayList([]const u8).init(arena.allocator());
        var map_args = std.StringArrayHashMap(?[]const u8).init(arena.allocator());
        var unused_args = std.StringArrayHashMap(void).init(arena.allocator());

        for (args) |arg| {
            if (arg.len == 0) {
                continue;
            } else if (arg.len > 1 and arg[0] == '-') {
                try map_args.put(arg, null);
                try unused_args.put(arg, {});
            } else {
                const keys = map_args.keys();
                if (keys.len > 0) {
                    const last_key = keys[keys.len - 1];
                    const last_val_maybe = map_args.get(last_key);
                    if (last_val_maybe) |last_val| {
                        // if the last key doesn't have a value yet, add it
                        if (last_val == null) {
                            try map_args.put(last_key, arg);
                        }
                        // otherwise, it's a positional arg
                        else {
                            try positional_args.append(arg);
                        }
                    } else {
                        try positional_args.append(arg);
                    }
                } else {
                    try positional_args.append(arg);
                }
            }
        }

        const args_slice = try positional_args.toOwnedSlice();
        if (args_slice.len == 0) {
            return .{
                .allocator = allocator,
                .arena = arena,
                .command_kind = null,
                .command_name = null,
                .positional_args = args_slice,
                .map_args = map_args,
                .unused_args = unused_args,
            };
        } else {
            const command_name = args_slice[0];
            const extra_args = args_slice[1..];

            const command_kind: ?CommandKind =
                if (std.mem.eql(u8, command_name, "init"))
                .init
            else if (std.mem.eql(u8, command_name, "add"))
                .add
            else if (std.mem.eql(u8, command_name, "unadd"))
                .unadd
            else if (std.mem.eql(u8, command_name, "rm"))
                .rm
            else if (std.mem.eql(u8, command_name, "reset"))
                .reset
            else if (std.mem.eql(u8, command_name, "commit"))
                .commit
            else if (std.mem.eql(u8, command_name, "status"))
                .status
            else if (std.mem.eql(u8, command_name, "diff"))
                .diff
            else if (std.mem.eql(u8, command_name, "branch"))
                .branch
            else if (std.mem.eql(u8, command_name, "switch"))
                .switch_head
            else if (std.mem.eql(u8, command_name, "restore"))
                .restore
            else if (std.mem.eql(u8, command_name, "log"))
                .log
            else if (std.mem.eql(u8, command_name, "merge"))
                .merge
            else if (std.mem.eql(u8, command_name, "cherry-pick"))
                .merge
            else if (std.mem.eql(u8, command_name, "config"))
                .config
            else if (std.mem.eql(u8, command_name, "remote"))
                .remote
            else if (std.mem.eql(u8, command_name, "fetch"))
                .fetch
            else if (std.mem.eql(u8, command_name, "pull"))
                .pull
            else
                null;

            return .{
                .allocator = allocator,
                .arena = arena,
                .command_kind = command_kind,
                .command_name = command_name,
                .positional_args = extra_args,
                .map_args = map_args,
                .unused_args = unused_args,
            };
        }
    }

    pub fn deinit(self: *CommandArgs) void {
        self.arena.deinit();
        self.allocator.destroy(self.arena);
    }

    pub fn contains(self: *CommandArgs, arg: []const u8) bool {
        _ = self.unused_args.orderedRemove(arg);
        return self.map_args.contains(arg);
    }

    pub fn get(self: *CommandArgs, arg: []const u8) ??[]const u8 {
        _ = self.unused_args.orderedRemove(arg);
        return self.map_args.get(arg);
    }
};

/// parses the args into a format that can be directly used by a repo.
/// if any additional allocation needs to be done, the arena inside the cmd args will be used.
pub fn Command(comptime repo_kind: rp.RepoKind, comptime hash_kind: hash.HashKind) type {
    return union(CommandKind) {
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
        switch_head: res.SwitchInput(hash_kind),
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

        pub fn init(cmd_args: *CommandArgs) !?Command(repo_kind, hash_kind) {
            const command_kind = cmd_args.command_kind orelse return null;
            switch (command_kind) {
                .init => {
                    if (cmd_args.positional_args.len == 0) {
                        return .{ .init = .{ .dir = "." } };
                    } else if (cmd_args.positional_args.len == 1) {
                        return .{ .init = .{ .dir = cmd_args.positional_args[0] } };
                    } else {
                        return null;
                    }
                },
                .add => {
                    if (cmd_args.positional_args.len == 0) return null;

                    return .{ .add = .{ .paths = cmd_args.positional_args } };
                },
                .unadd => {
                    if (cmd_args.positional_args.len == 0) return null;

                    return .{ .unadd = .{
                        .paths = cmd_args.positional_args,
                        .opts = .{
                            .force = cmd_args.contains("-f"),
                        },
                    } };
                },
                .rm => {
                    if (cmd_args.positional_args.len == 0) return null;

                    return .{ .rm = .{
                        .paths = cmd_args.positional_args,
                        .opts = .{
                            .force = cmd_args.contains("-f"),
                            .remove_from_workspace = true,
                        },
                    } };
                },
                .reset => {
                    if (cmd_args.positional_args.len != 1) return null;

                    return .{ .reset = .{ .path = cmd_args.positional_args[0] } };
                },
                .commit => {
                    // if a message is included, it must have a non-null value
                    const message = if (cmd_args.get("-m")) |msg| (msg orelse return error.CommitMessageNotFound) else "";
                    return .{ .commit = .{ .message = message } };
                },
                .status => return .status,
                .diff => {
                    const diff_opts: df.BasicDiffOptions(hash_kind) = if (cmd_args.contains("--staged"))
                        .index
                    else
                        (if (cmd_args.contains("--base"))
                            .{ .workspace = .{ .conflict_diff_kind = .base } }
                        else if (cmd_args.contains("--ours"))
                            .{ .workspace = .{ .conflict_diff_kind = .target } }
                        else if (cmd_args.contains("--theirs"))
                            .{ .workspace = .{ .conflict_diff_kind = .source } }
                        else
                            .{ .workspace = .{ .conflict_diff_kind = .target } });
                    return .{ .diff = .{ .diff_opts = diff_opts } };
                },
                .branch => {
                    if (cmd_args.positional_args.len == 0) return null;

                    const cmd_name = cmd_args.positional_args[0];

                    var cmd: bch.BranchCommand = undefined;
                    if (std.mem.eql(u8, "list", cmd_name)) {
                        cmd = .list;
                    } else if (std.mem.eql(u8, "add", cmd_name)) {
                        if (cmd_args.positional_args.len != 2) {
                            return null;
                        }
                        cmd = .{ .add = .{ .name = cmd_args.positional_args[1] } };
                    } else if (std.mem.eql(u8, "rm", cmd_name)) {
                        if (cmd_args.positional_args.len != 2) {
                            return null;
                        }
                        cmd = .{ .remove = .{ .name = cmd_args.positional_args[1] } };
                    } else {
                        try cmd_args.unused_args.put(cmd_name, {});
                        return null;
                    }

                    return .{ .branch = cmd };
                },
                .switch_head => {
                    if (cmd_args.positional_args.len != 1) return null;
                    const target = cmd_args.positional_args[0];

                    return .{ .switch_head = .{ .head = .{ .replace = rf.RefOrOid(hash_kind).initFromUser(target) orelse return null } } };
                },
                .restore => {
                    if (cmd_args.positional_args.len != 1) return null;

                    return .{ .restore = .{ .path = cmd_args.positional_args[0] } };
                },
                .log => {
                    if (cmd_args.positional_args.len != 0) return null;

                    return .log;
                },
                .merge => {
                    if (cmd_args.positional_args.len == 0) return null;

                    const command_name = cmd_args.command_name orelse return error.InvalidMergeKind;
                    const merge_kind: mrg.MergeKind = if (std.mem.eql(u8, "merge", command_name))
                        .full
                    else if (std.mem.eql(u8, "cherry-pick", command_name))
                        .pick
                    else
                        return error.InvalidMergeKind;

                    const merge_action: mrg.MergeAction(repo_kind, hash_kind) =
                        if (cmd_args.contains("--continue"))
                        .cont
                    else blk: {
                        var source = std.ArrayList(rf.RefOrOid(hash_kind)).init(cmd_args.arena.allocator());
                        for (cmd_args.positional_args) |arg| {
                            try source.append(rf.RefOrOid(hash_kind).initFromUser(arg) orelse return null);
                        }
                        break :blk .{ .new = .{ .source = try source.toOwnedSlice() } };
                    };

                    return .{
                        .merge = .{
                            .kind = merge_kind,
                            .action = merge_action,
                        },
                    };
                },
                .config => {
                    if (cmd_args.positional_args.len == 0) return null;

                    const cmd_name = cmd_args.positional_args[0];

                    var cmd: cfg.ConfigCommand = undefined;
                    if (std.mem.eql(u8, "list", cmd_name)) {
                        cmd = .list;
                    } else if (std.mem.eql(u8, "add", cmd_name)) {
                        if (cmd_args.positional_args.len != 3) {
                            return null;
                        }
                        cmd = .{ .add = .{
                            .name = cmd_args.positional_args[1],
                            .value = cmd_args.positional_args[2],
                        } };
                    } else if (std.mem.eql(u8, "rm", cmd_name)) {
                        if (cmd_args.positional_args.len != 2) {
                            return null;
                        }
                        cmd = .{ .remove = .{
                            .name = cmd_args.positional_args[1],
                        } };
                    } else {
                        try cmd_args.unused_args.put(cmd_name, {});
                        return null;
                    }

                    return .{ .config = cmd };
                },
                .remote => {
                    if (cmd_args.positional_args.len == 0) return null;

                    const cmd_name = cmd_args.positional_args[0];

                    var cmd: cfg.ConfigCommand = undefined;
                    if (std.mem.eql(u8, "list", cmd_name)) {
                        cmd = .list;
                    } else if (std.mem.eql(u8, "add", cmd_name)) {
                        if (cmd_args.positional_args.len != 3) {
                            return null;
                        }
                        cmd = .{ .add = .{
                            .name = cmd_args.positional_args[1],
                            .value = cmd_args.positional_args[2],
                        } };
                    } else if (std.mem.eql(u8, "rm", cmd_name)) {
                        if (cmd_args.positional_args.len != 2) {
                            return null;
                        }
                        cmd = .{ .remove = .{
                            .name = cmd_args.positional_args[1],
                        } };
                    } else {
                        try cmd_args.unused_args.put(cmd_name, {});
                        return null;
                    }

                    return .{ .remote = cmd };
                },
                .fetch => {
                    if (cmd_args.positional_args.len != 1) return null;

                    return .{ .fetch = .{
                        .remote_name = cmd_args.positional_args[0],
                    } };
                },
                .pull => {
                    if (cmd_args.positional_args.len != 2) return null;

                    return .{ .pull = .{
                        .remote_name = cmd_args.positional_args[0],
                        .remote_ref_name = cmd_args.positional_args[1],
                    } };
                },
            }
        }
    };
}

/// parses the given args into a command if valid, and determines how it should be run
/// (via the TUI or CLI).
pub fn CommandDispatch(comptime repo_kind: rp.RepoKind, comptime hash_kind: hash.HashKind) type {
    return union(enum) {
        invalid: union(enum) {
            command: []const u8,
            argument: struct {
                command: ?CommandKind,
                value: []const u8,
            },
        },
        help: ?CommandKind,
        tui: ?CommandKind,
        cli: Command(repo_kind, hash_kind),

        pub fn init(cmd_args: *CommandArgs) !CommandDispatch(repo_kind, hash_kind) {
            const dispatch = try initIgnoreUnused(cmd_args);
            if (cmd_args.unused_args.count() > 0) {
                return .{
                    .invalid = .{
                        .argument = .{
                            .command = switch (dispatch) {
                                .invalid => return dispatch, // if there was already an error, return it instead
                                .help, .tui => |cmd_kind_maybe| cmd_kind_maybe,
                                .cli => |command| command,
                            },
                            .value = cmd_args.unused_args.keys()[0],
                        },
                    },
                };
            }
            return dispatch;
        }

        pub fn initIgnoreUnused(cmd_args: *CommandArgs) !CommandDispatch(repo_kind, hash_kind) {
            const show_help = cmd_args.contains("--help");
            const force_cli = cmd_args.contains("--cli");

            if (cmd_args.command_kind) |command_kind| {
                if (show_help) {
                    return .{ .help = command_kind };
                } else if (cmd_args.positional_args.len == 0 and !force_cli and switch (command_kind) {
                    .status, .diff, .log => true,
                    else => false,
                }) {
                    return .{ .tui = command_kind };
                } else if (try Command(repo_kind, hash_kind).init(cmd_args)) |cmd| {
                    return .{ .cli = cmd };
                } else {
                    return .{ .help = command_kind };
                }
            } else if (cmd_args.command_name) |command_name| {
                return .{ .invalid = .{ .command = command_name } };
            } else if (show_help) {
                return .{ .help = null };
            } else if (!force_cli) {
                return .{ .tui = null };
            } else {
                return .{ .help = null };
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
        var cmd_args = try CommandArgs.init(allocator, &.{ "add", "--cli" });
        defer cmd_args.deinit();
        const command = try CommandDispatch(repo_kind, hash_kind).init(&cmd_args);
        try std.testing.expectEqualStrings("help", @tagName(command));
    }

    {
        var cmd_args = try CommandArgs.init(allocator, &.{ "add", "file.txt" });
        defer cmd_args.deinit();
        const command = try CommandDispatch(repo_kind, hash_kind).init(&cmd_args);
        try std.testing.expectEqualStrings("cli", @tagName(command));
        try std.testing.expectEqualStrings("add", @tagName(command.cli));
    }

    {
        var cmd_args = try CommandArgs.init(allocator, &.{ "commit", "-m" });
        defer cmd_args.deinit();
        const command_or_err = CommandDispatch(repo_kind, hash_kind).init(&cmd_args);
        try std.testing.expectError(error.CommitMessageNotFound, command_or_err);
    }

    {
        var cmd_args = try CommandArgs.init(allocator, &.{ "commit", "-m", "let there be light" });
        defer cmd_args.deinit();
        const command = try CommandDispatch(repo_kind, hash_kind).init(&cmd_args);
        try std.testing.expectEqualStrings("cli", @tagName(command));
        try std.testing.expectEqualStrings("let there be light", command.cli.commit.message.?);
    }

    {
        var cmd_args = try CommandArgs.init(allocator, &.{ "stats", "--clii" });
        defer cmd_args.deinit();
        const command = try CommandDispatch(repo_kind, hash_kind).init(&cmd_args);
        try std.testing.expectEqualStrings("invalid", @tagName(command));
        try std.testing.expectEqualStrings("command", @tagName(command.invalid));
        try std.testing.expectEqualStrings("stats", command.invalid.command);
    }

    {
        var cmd_args = try CommandArgs.init(allocator, &.{ "status", "--clii" });
        defer cmd_args.deinit();
        const command = try CommandDispatch(repo_kind, hash_kind).init(&cmd_args);
        try std.testing.expectEqualStrings("invalid", @tagName(command));
        try std.testing.expectEqualStrings("argument", @tagName(command.invalid));
        try std.testing.expectEqualStrings("status", @tagName(command.invalid.argument.command.?));
        try std.testing.expectEqualStrings("--clii", command.invalid.argument.value);
    }
}
