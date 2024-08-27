//! the command parsed from CLI args.

const std = @import("std");
const df = @import("./diff.zig");
const mrg = @import("./merge.zig");
const idx = @import("./index.zig");
const obj = @import("./object.zig");
const cfg = @import("./config.zig");

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
    remote,
};

pub const SubCommand = union(SubCommandKind) {
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
    commit: obj.CommitMetadata,
    status,
    diff: struct {
        diff_opts: df.BasicDiffOptions,
    },
    branch: struct {
        name: ?[]const u8,
    },
    switch_head: struct {
        target: []const u8,
    },
    restore: struct {
        path: []const u8,
    },
    log,
    merge: mrg.MergeInput,
    cherry_pick: mrg.MergeInput,
    remote: cfg.RemoteCommand,

    pub fn deinit(self: *SubCommand) void {
        switch (self.*) {
            .add => {
                self.add.paths.deinit();
            },
            .unadd => {
                self.unadd.paths.deinit();
            },
            .rm => {
                self.rm.paths.deinit();
            },
            else => {},
        }
    }
};

pub const Command = union(enum) {
    invalid: struct {
        name: []const u8,
    },
    tui: ?SubCommandKind,
    cli: ?SubCommand,

    /// parses the process args into a much nicer format. this
    /// is way dumber than all those fancy command line parsing
    /// libraries out there. let's keep it that way.
    pub fn init(allocator: std.mem.Allocator, args: []const []const u8) !Command {
        // put args into data structures for easy access
        var positional_args = std.ArrayList([]const u8).init(allocator);
        defer positional_args.deinit();
        var map_args = std.StringArrayHashMap(?[]const u8).init(allocator);
        defer map_args.deinit();
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
            if (map_args.count() == 0) {
                return .{ .tui = null };
            } else {
                return .{ .cli = null };
            }
        }

        const sub_command = positional_args.items[0];
        const extra_args = positional_args.items[1..];

        if (extra_args.len == 0 and map_args.count() == 0) {
            if (std.mem.eql(u8, sub_command, "add")) {
                return .{ .tui = .add };
            } else if (std.mem.eql(u8, sub_command, "unadd")) {
                return .{ .tui = .unadd };
            } else if (std.mem.eql(u8, sub_command, "rm")) {
                return .{ .tui = .rm };
            } else if (std.mem.eql(u8, sub_command, "reset")) {
                return .{ .tui = .reset };
            } else if (std.mem.eql(u8, sub_command, "commit")) {
                return .{ .tui = .commit };
            } else if (std.mem.eql(u8, sub_command, "status")) {
                return .{ .tui = .status };
            } else if (std.mem.eql(u8, sub_command, "diff")) {
                return .{ .tui = .diff };
            } else if (std.mem.eql(u8, sub_command, "branch")) {
                return .{ .tui = .branch };
            } else if (std.mem.eql(u8, sub_command, "switch")) {
                return .{ .tui = .switch_head };
            } else if (std.mem.eql(u8, sub_command, "restore")) {
                return .{ .tui = .restore };
            } else if (std.mem.eql(u8, sub_command, "log")) {
                return .{ .tui = .log };
            } else if (std.mem.eql(u8, sub_command, "merge")) {
                return .{ .tui = .merge };
            } else if (std.mem.eql(u8, sub_command, "cherry-pick")) {
                return .{ .tui = .cherry_pick };
            } else if (std.mem.eql(u8, sub_command, "remote")) {
                return .{ .tui = .remote };
            }
        }

        if (std.mem.eql(u8, sub_command, "init")) {
            return .{ .cli = .{ .init = .{ .dir = if (extra_args.len > 0) extra_args[0] else "." } } };
        } else if (std.mem.eql(u8, sub_command, "add")) {
            if (extra_args.len == 0) {
                return error.AddPathsNotFound;
            }
            var paths = try std.ArrayList([]const u8).initCapacity(allocator, extra_args.len);
            errdefer paths.deinit();
            paths.appendSliceAssumeCapacity(extra_args);
            return .{ .cli = .{ .add = .{ .paths = paths } } };
        } else if (std.mem.eql(u8, sub_command, "unadd")) {
            if (extra_args.len == 0) {
                return error.UnaddPathsNotFound;
            }
            var paths = try std.ArrayList([]const u8).initCapacity(allocator, extra_args.len);
            errdefer paths.deinit();
            paths.appendSliceAssumeCapacity(extra_args);
            return .{ .cli = .{ .unadd = .{
                .paths = paths,
                .opts = .{
                    .force = map_args.contains("-f"),
                },
            } } };
        } else if (std.mem.eql(u8, sub_command, "rm")) {
            if (extra_args.len == 0) {
                return error.RmPathsNotFound;
            }
            var paths = try std.ArrayList([]const u8).initCapacity(allocator, extra_args.len);
            errdefer paths.deinit();
            paths.appendSliceAssumeCapacity(extra_args);
            return .{ .cli = .{ .rm = .{
                .paths = paths,
                .opts = .{
                    .force = map_args.contains("-f"),
                    .remove_from_workspace = true,
                },
            } } };
        } else if (std.mem.eql(u8, sub_command, "reset")) {
            if (extra_args.len == 0) {
                return error.ResetPathNotFound;
            } else if (extra_args.len > 1) {
                return error.TooManyArgs;
            }
            return .{ .cli = .{ .reset = .{ .path = extra_args[0] } } };
        } else if (std.mem.eql(u8, sub_command, "commit")) {
            // if a message is included, it must have a non-null value
            const message = if (map_args.get("-m")) |msg| (msg orelse return error.CommitMessageNotFound) else "";
            return .{ .cli = .{ .commit = .{ .message = message } } };
        } else if (std.mem.eql(u8, sub_command, "status")) {
            return .{ .cli = .{ .status = {} } };
        } else if (std.mem.eql(u8, sub_command, "diff")) {
            const diff_opts: df.BasicDiffOptions = if (map_args.contains("--staged"))
                .index
            else
                (if (map_args.contains("--base"))
                    .{ .workspace = .{ .conflict_diff_kind = .common } }
                else if (map_args.contains("--ours"))
                    .{ .workspace = .{ .conflict_diff_kind = .current } }
                else if (map_args.contains("--theirs"))
                    .{ .workspace = .{ .conflict_diff_kind = .source } }
                else
                    .{ .workspace = .{ .conflict_diff_kind = .current } });
            return .{ .cli = .{ .diff = .{ .diff_opts = diff_opts } } };
        } else if (std.mem.eql(u8, sub_command, "branch")) {
            return .{ .cli = .{ .branch = .{ .name = if (extra_args.len == 0) null else extra_args[0] } } };
        } else if (std.mem.eql(u8, sub_command, "switch")) {
            if (extra_args.len == 0) {
                return error.SwitchTargetNotFound;
            }
            return .{ .cli = .{ .switch_head = .{ .target = extra_args[0] } } };
        } else if (std.mem.eql(u8, sub_command, "restore")) {
            if (extra_args.len == 0) {
                return error.RestorePathNotFound;
            } else if (extra_args.len > 1) {
                return error.TooManyArgs;
            }
            return .{ .cli = .{ .restore = .{ .path = extra_args[0] } } };
        } else if (std.mem.eql(u8, sub_command, "log")) {
            return .{ .cli = .log };
        } else if (std.mem.eql(u8, sub_command, "merge")) {
            var merge_input_maybe: ?mrg.MergeInput = null;
            if (extra_args.len > 0) {
                merge_input_maybe = .{ .new = .{ .source_name = extra_args[0] } };
            }
            if (map_args.contains("--continue")) {
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
        } else if (std.mem.eql(u8, sub_command, "cherry-pick")) {
            var merge_input_maybe: ?mrg.MergeInput = null;
            if (extra_args.len > 0) {
                merge_input_maybe = .{ .new = .{ .source_name = extra_args[0] } };
            }
            if (map_args.contains("--continue")) {
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
        } else if (std.mem.eql(u8, sub_command, "remote")) {
            if (extra_args.len < 1) {
                return error.InsufficientRemoteArgs;
            }
            const cmd_name = extra_args[0];

            var remote_cmd: cfg.RemoteCommand = undefined;
            if (std.mem.eql(u8, "list", cmd_name)) {
                remote_cmd = .list;
            } else if (std.mem.eql(u8, "add", cmd_name)) {
                if (extra_args.len < 3) {
                    return error.InsufficientRemoteArgs;
                }
                remote_cmd = .{ .add = .{
                    .name = extra_args[1],
                    .url = extra_args[2],
                } };
            } else if (std.mem.eql(u8, "remove", cmd_name)) {
                if (extra_args.len < 2) {
                    return error.InsufficientRemoteArgs;
                }
                remote_cmd = .{ .remove = .{
                    .name = extra_args[1],
                } };
            } else {
                return error.InvalidRemoteCommand;
            }
            return .{ .cli = .{ .remote = remote_cmd } };
        }

        return .{ .invalid = .{ .name = sub_command } };
    }

    pub fn deinit(self: *Command) void {
        switch (self.*) {
            .cli => {
                if (self.cli) |*sub_command| {
                    sub_command.deinit();
                }
            },
            else => {},
        }
    }
};

test "command" {
    const allocator = std.testing.allocator;
    var args = std.ArrayList([]const u8).init(allocator);
    defer args.deinit();

    {
        var command_or_err = Command.init(allocator, &.{ "add", "--cli" });
        if (command_or_err) |*command| {
            defer command.deinit();
            return error.ExpectedError;
        } else |err| {
            try std.testing.expect(error.AddPathsNotFound == err);
        }
    }

    {
        var command = try Command.init(allocator, &.{ "add", "file.txt" });
        defer command.deinit();
        try std.testing.expect(command == .cli and command.cli.? == .add);
    }

    {
        var command_or_err = Command.init(allocator, &.{ "commit", "-m" });
        if (command_or_err) |*command| {
            defer command.deinit();
            return error.ExpectedError;
        } else |err| {
            try std.testing.expect(error.CommitMessageNotFound == err);
        }
    }

    {
        var command = try Command.init(allocator, &.{"commit"});
        defer command.deinit();
        try std.testing.expect(command == .tui and command.tui.? == .commit);
    }

    {
        var command = try Command.init(allocator, &.{ "commit", "-m", "let there be light" });
        defer command.deinit();
        try std.testing.expect(command == .cli and command.cli.? == .commit);
        try std.testing.expect(std.mem.eql(u8, "let there be light", command.cli.?.commit.message));
    }
}
