//! the command parsed from CLI args.

const std = @import("std");
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
    cherry_pick,
    config,
    remote,
    fetch,
    pull,
};

pub const SubCommandArgs = struct {
    sub_command_kind: ?SubCommandKind,
    positional_args: std.ArrayList([]const u8),
    map_args: std.StringArrayHashMap(?[]const u8),

    pub fn init(allocator: std.mem.Allocator, args: []const []const u8) !SubCommandArgs {
        var positional_args = std.ArrayList([]const u8).init(allocator);
        errdefer positional_args.deinit();
        var map_args = std.StringArrayHashMap(?[]const u8).init(allocator);
        errdefer map_args.deinit();

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
                .cherry_pick
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
                .sub_command_kind = sub_command_kind,
                .positional_args = positional_args,
                .map_args = map_args,
            };
        }
    }

    pub fn deinit(self: *SubCommandArgs) void {
        self.positional_args.deinit();
        self.map_args.deinit();
    }
};

pub fn SubCommand(comptime hash_kind: hash.HashKind) type {
    return union(SubCommandKind) {
        init: struct {
            dir: []const u8,
        },
        add: struct {
            paths: std.ArrayList([]const u8),
        },
        unadd: struct {
            paths: std.ArrayList([]const u8),
            opts: idx.IndexUnaddOptions,
        },
        rm: struct {
            paths: std.ArrayList([]const u8),
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
        merge: mrg.MergeInput(hash_kind),
        cherry_pick: mrg.MergeInput(hash_kind),
        config: cfg.ConfigCommand,
        remote: cfg.ConfigCommand,
        fetch: struct {
            remote_name: []const u8,
        },
        pull: struct {
            remote_name: []const u8,
            remote_ref_name: []const u8,
        },

        pub fn deinit(self: *SubCommand(hash_kind)) void {
            switch (self.*) {
                .add => |*add| {
                    add.paths.deinit();
                },
                .unadd => |*unadd| {
                    unadd.paths.deinit();
                },
                .rm => |*rm| {
                    rm.paths.deinit();
                },
                else => {},
            }
        }
    };
}

pub fn Command(comptime hash_kind: hash.HashKind) type {
    return union(enum) {
        invalid: struct {
            name: []const u8,
        },
        help: ?SubCommandKind,
        tui: ?SubCommandKind,
        cli: ?SubCommand(hash_kind),

        pub fn init(allocator: std.mem.Allocator, sub_cmd_args: *const SubCommandArgs) !Command(hash_kind) {
            if (sub_cmd_args.sub_command_kind) |sub_command_kind| {
                const extra_args = sub_cmd_args.positional_args.items[1..];

                if (extra_args.len == 0 and sub_cmd_args.map_args.count() == 0) {
                    return switch (sub_command_kind) {
                        .status, .diff, .log => .{ .tui = sub_command_kind },
                        else => .{ .help = sub_command_kind },
                    };
                }

                switch (sub_command_kind) {
                    .init => {
                        if (sub_cmd_args.map_args.contains("help")) {
                            return .{ .help = .init };
                        } else {
                            return .{ .cli = .{ .init = .{ .dir = if (extra_args.len > 0) extra_args[0] else "." } } };
                        }
                    },
                    .add => {
                        if (extra_args.len == 0) {
                            return error.AddPathsNotFound;
                        }
                        var paths = try std.ArrayList([]const u8).initCapacity(allocator, extra_args.len);
                        errdefer paths.deinit();
                        paths.appendSliceAssumeCapacity(extra_args);
                        return .{ .cli = .{ .add = .{ .paths = paths } } };
                    },
                    .unadd => {
                        if (extra_args.len == 0) {
                            return error.UnaddPathsNotFound;
                        }
                        var paths = try std.ArrayList([]const u8).initCapacity(allocator, extra_args.len);
                        errdefer paths.deinit();
                        paths.appendSliceAssumeCapacity(extra_args);
                        return .{ .cli = .{ .unadd = .{
                            .paths = paths,
                            .opts = .{
                                .force = sub_cmd_args.map_args.contains("-f"),
                            },
                        } } };
                    },
                    .rm => {
                        if (extra_args.len == 0) {
                            return error.RmPathsNotFound;
                        }
                        var paths = try std.ArrayList([]const u8).initCapacity(allocator, extra_args.len);
                        errdefer paths.deinit();
                        paths.appendSliceAssumeCapacity(extra_args);
                        return .{ .cli = .{ .rm = .{
                            .paths = paths,
                            .opts = .{
                                .force = sub_cmd_args.map_args.contains("-f"),
                                .remove_from_workspace = true,
                            },
                        } } };
                    },
                    .reset => {
                        if (extra_args.len == 0) {
                            return error.ResetPathNotFound;
                        } else if (extra_args.len > 1) {
                            return error.TooManyArgs;
                        }
                        return .{ .cli = .{ .reset = .{ .path = extra_args[0] } } };
                    },
                    .commit => {
                        // if a message is included, it must have a non-null value
                        const message = if (sub_cmd_args.map_args.get("-m")) |msg| (msg orelse return error.CommitMessageNotFound) else "";
                        return .{ .cli = .{ .commit = .{ .message = message } } };
                    },
                    .status => {
                        if (sub_cmd_args.map_args.contains("help")) {
                            return .{ .help = .status };
                        } else if (sub_cmd_args.map_args.contains("cli")) {
                            return .{ .cli = .status };
                        } else {
                            return .{ .cli = .{ .status = {} } };
                        }
                    },
                    .diff => {
                        if (sub_cmd_args.map_args.contains("help")) {
                            return .{ .help = .diff };
                        } else {
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
                        }
                    },
                    .branch => {
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
                    },
                    .switch_head => {
                        if (extra_args.len == 0) {
                            return error.SwitchTargetNotFound;
                        }
                        return .{ .cli = .{ .switch_head = .{ .target = extra_args[0] } } };
                    },
                    .restore => {
                        if (extra_args.len == 0) {
                            return error.RestorePathNotFound;
                        } else if (extra_args.len > 1) {
                            return error.TooManyArgs;
                        }
                        return .{ .cli = .{ .restore = .{ .path = extra_args[0] } } };
                    },
                    .log => {
                        if (sub_cmd_args.map_args.contains("help")) {
                            return .{ .help = .log };
                        } else {
                            return .{ .cli = .log };
                        }
                    },
                    .merge => {
                        var merge_input_maybe: ?mrg.MergeInput(hash_kind) = switch (extra_args.len) {
                            0 => null,
                            1 => .{ .new = ref.RefOrOid(hash_kind).initFromUser(extra_args[0]) },
                            2 => .{ .new = .{ .ref = .{ .kind = .{ .remote = extra_args[0] }, .name = extra_args[1] } } },
                            else => return error.TooManyArgs,
                        };
                        if (sub_cmd_args.map_args.contains("--continue")) {
                            if (merge_input_maybe != null) {
                                return error.ConflictingMergeArgs;
                            }
                            merge_input_maybe = .cont;
                        }
                        if (merge_input_maybe) |merge_input| {
                            return .{ .cli = .{ .merge = merge_input } };
                        } else {
                            return error.InsufficientMergeArgs;
                        }
                    },
                    .cherry_pick => {
                        var merge_input_maybe: ?mrg.MergeInput(hash_kind) = switch (extra_args.len) {
                            0 => null,
                            1 => .{ .new = ref.RefOrOid(hash_kind).initFromUser(extra_args[0]) },
                            else => return error.TooManyArgs,
                        };
                        if (sub_cmd_args.map_args.contains("--continue")) {
                            if (merge_input_maybe != null) {
                                return error.ConflictingCherryPickArgs;
                            }
                            merge_input_maybe = .cont;
                        }
                        if (merge_input_maybe) |merge_input| {
                            return .{ .cli = .{ .cherry_pick = merge_input } };
                        } else {
                            return error.InsufficientCherryPickArgs;
                        }
                    },
                    .config => {
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
                    },
                    .remote => {
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
                    },
                    .fetch => {
                        if (extra_args.len == 1) {
                            return .{ .cli = .{ .fetch = .{
                                .remote_name = extra_args[0],
                            } } };
                        } else {
                            return error.WrongNumberOfFetchArgs;
                        }
                    },
                    .pull => {
                        if (extra_args.len == 2) {
                            return .{ .cli = .{ .pull = .{
                                .remote_name = extra_args[0],
                                .remote_ref_name = extra_args[1],
                            } } };
                        } else {
                            return error.WrongNumberOfPullArgs;
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

        pub fn deinit(self: *Command(hash_kind)) void {
            switch (self.*) {
                .cli => |*cli| {
                    if (cli.*) |*sub_command| {
                        sub_command.deinit();
                    }
                },
                else => {},
            }
        }
    };
}

test "command" {
    const hash_kind = hash.HashKind.sha1;
    const allocator = std.testing.allocator;

    var args = std.ArrayList([]const u8).init(allocator);
    defer args.deinit();

    {
        var sub_cmd_args = try SubCommandArgs.init(allocator, &.{ "add", "--cli" });
        defer sub_cmd_args.deinit();
        var command_or_err = Command(hash_kind).init(allocator, &sub_cmd_args);
        if (command_or_err) |*command| {
            defer command.deinit();
            return error.ExpectedError;
        } else |err| {
            try std.testing.expect(error.AddPathsNotFound == err);
        }
    }

    {
        var sub_cmd_args = try SubCommandArgs.init(allocator, &.{ "add", "file.txt" });
        defer sub_cmd_args.deinit();
        var command = try Command(hash_kind).init(allocator, &sub_cmd_args);
        defer command.deinit();
        try std.testing.expect(command == .cli and command.cli.? == .add);
    }

    {
        var sub_cmd_args = try SubCommandArgs.init(allocator, &.{ "commit", "-m" });
        defer sub_cmd_args.deinit();
        var command_or_err = Command(hash_kind).init(allocator, &sub_cmd_args);
        if (command_or_err) |*command| {
            defer command.deinit();
            return error.ExpectedError;
        } else |err| {
            try std.testing.expect(error.CommitMessageNotFound == err);
        }
    }

    {
        var sub_cmd_args = try SubCommandArgs.init(allocator, &.{ "commit", "-m", "let there be light" });
        defer sub_cmd_args.deinit();
        var command = try Command(hash_kind).init(allocator, &sub_cmd_args);
        defer command.deinit();
        try std.testing.expect(command == .cli and command.cli.? == .commit);
        try std.testing.expect(std.mem.eql(u8, "let there be light", command.cli.?.commit.message));
    }
}
