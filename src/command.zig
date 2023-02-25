const std = @import("std");

pub const CommandKind = enum {
    invalid,
    usage,
    init,
    add,
    commit,
};

pub const Command = union(CommandKind) {
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
};

pub const CommandError = error{
    AddPathsMissing,
    CommitMessageMissing,
};
