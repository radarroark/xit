//! the command parsed from CLI args.

const std = @import("std");
const df = @import("./diff.zig");

pub const CommandKind = enum {
    invalid,
    usage,
    init,
    add,
    commit,
    status,
    diff,
    branch,
    switch_head,
    restore,
    log,
    merge,
};

pub const CommandData = union(CommandKind) {
    invalid: struct {
        name: []const u8,
    },
    usage,
    init: struct {
        dir: []const u8,
    },
    add: struct {
        paths: std.ArrayList([]const u8),
    },
    commit: struct {
        message: ?[]const u8,
    },
    status,
    diff: struct {
        diff_kind: df.DiffKind,
        conflict_diff_kind_maybe: ?df.ConflictDiffKind,
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
    merge: struct {
        source: []const u8,
    },
};

/// returns the data from the process args in a nicer format.
/// right now it just parses the args into a sorted map. i was
/// thinking of using an existing arg parser lib but i decided
/// i should roll my own and let it evolve along with my needs.
/// i'm actually pretty happy with this already...it's stupid
/// but it works, and unlike those libs i understand every line.
pub fn parseArgs(allocator: std.mem.Allocator, args: *std.ArrayList([]const u8)) !CommandData {
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
            return CommandData{ .init = .{ .dir = if (args.items.len > 1) args.items[1] else "." } };
        } else if (std.mem.eql(u8, args.items[0], "add")) {
            if (pos_args.items.len == 0) {
                return error.AddPathsMissing;
            }
            var paths = try std.ArrayList([]const u8).initCapacity(allocator, pos_args.capacity);
            errdefer paths.deinit(); // pointless for now but for future sake
            paths.appendSliceAssumeCapacity(pos_args.items);
            return CommandData{ .add = .{ .paths = paths } };
        } else if (std.mem.eql(u8, args.items[0], "commit")) {
            // if a message is included, it must have a non-null value
            const message_maybe = map_args.get("-m");
            const message = if (message_maybe == null) null else (message_maybe.? orelse return error.CommitMessageMissing);
            return CommandData{ .commit = .{ .message = message } };
        } else if (std.mem.eql(u8, args.items[0], "status")) {
            return CommandData{ .status = {} };
        } else if (std.mem.eql(u8, args.items[0], "diff")) {
            return CommandData{ .diff = .{
                .diff_kind = if (map_args.contains("--staged")) .index else .workspace,
                .conflict_diff_kind_maybe = if (map_args.contains("--base")) .common else if (map_args.contains("--ours")) .current else if (map_args.contains("--theirs")) .source else null,
            } };
        } else if (std.mem.eql(u8, args.items[0], "branch")) {
            return CommandData{ .branch = .{ .name = if (pos_args.items.len == 0) null else pos_args.items[0] } };
        } else if (std.mem.eql(u8, args.items[0], "switch")) {
            if (pos_args.items.len == 0) {
                return error.SwitchTargetMissing;
            }
            return CommandData{ .switch_head = .{ .target = pos_args.items[0] } };
        } else if (std.mem.eql(u8, args.items[0], "restore")) {
            if (pos_args.items.len == 0) {
                return error.RestorePathMissing;
            }
            return CommandData{ .restore = .{ .path = pos_args.items[0] } };
        } else if (std.mem.eql(u8, args.items[0], "log")) {
            return CommandData{ .log = {} };
        } else if (std.mem.eql(u8, args.items[0], "merge")) {
            if (pos_args.items.len == 0) {
                return error.MergeSourceMissing;
            }
            return CommandData{ .merge = .{ .source = pos_args.items[0] } };
        } else {
            return CommandData{ .invalid = .{ .name = args.items[0] } };
        }
    }

    return CommandData{ .usage = {} };
}

pub const Command = struct {
    data: CommandData,

    pub fn init(allocator: std.mem.Allocator, args: *std.ArrayList([]const u8)) !Command {
        return .{
            .data = try parseArgs(allocator, args),
        };
    }

    pub fn deinit(self: *Command) void {
        switch (self.data) {
            .add => {
                self.data.add.paths.deinit();
            },
            else => {},
        }
    }
};

test "command" {
    const allocator = std.testing.allocator;
    var args = std.ArrayList([]const u8).init(allocator);
    defer args.deinit();

    args.clearAndFree();
    try args.append("add");
    try std.testing.expect(error.AddPathsMissing == Command.init(allocator, &args));

    args.clearAndFree();
    try args.append("add");
    try args.append("file.txt");
    {
        var command = try Command.init(allocator, &args);
        defer command.deinit();
        try std.testing.expect(command.data == .add);
    }

    args.clearAndFree();
    try args.append("commit");
    try args.append("-m");
    try std.testing.expect(error.CommitMessageMissing == Command.init(allocator, &args));

    args.clearAndFree();
    try args.append("commit");
    {
        var command = try Command.init(allocator, &args);
        defer command.deinit();
        try std.testing.expect(command.data == .commit);
        try std.testing.expect(null == command.data.commit.message);
    }

    args.clearAndFree();
    try args.append("commit");
    try args.append("-m");
    try args.append("let there be light");
    {
        var command = try Command.init(allocator, &args);
        defer command.deinit();
        try std.testing.expect(command.data == .commit);
        try std.testing.expect(null != command.data.commit.message);
        try std.testing.expect(std.mem.eql(u8, "let there be light", command.data.commit.message.?));
    }
}
