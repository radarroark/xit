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
const tag = @import("./tag.zig");

pub const CommandKind = enum {
    init,
    add,
    unadd,
    untrack,
    rm,
    commit,
    tag,
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

const Help = struct {
    name: []const u8,
    descrip: []const u8,
    example: []const u8,
};

fn commandHelp(command_kind: CommandKind) Help {
    return switch (command_kind) {
        .init => .{
            .name = "init",
            .descrip =
            \\create an empty xit repository
            ,
            .example =
            \\(in the current dir)
            \\    xit init
            \\(in a new dir)
            \\    xit init myproject
            ,
        },
        .add => .{
            .name = "add",
            .descrip =
            \\add file contents to the index
            ,
            .example =
            \\xit add myfile.txt
            ,
        },
        .unadd => .{
            .name = "unadd",
            .descrip =
            \\remove any changes to a file
            \\that were added to the index
            ,
            .example =
            \\xit unadd myfile.txt
            ,
        },
        .untrack => .{
            .name = "untrack",
            .descrip =
            \\no longer track file in the index,
            \\but leave it in the working tree
            ,
            .example =
            \\xit untrack myfile.txt
            ,
        },
        .rm => .{
            .name = "rm",
            .descrip =
            \\no longer track file in the index,
            \\and remove it from the working tree
            ,
            .example =
            \\xit rm myfile.txt
            ,
        },
        .commit => .{
            .name = "commit",
            .descrip =
            \\record changes to the repository
            ,
            .example =
            \\xit commit -m "my commit message"
            ,
        },
        .tag => .{
            .name = "tag",
            .descrip =
            \\add, remove, and list tags
            ,
            .example =
            \\(add tag)
            \\    xit tag add mytag
            \\(remove tag)
            \\    xit tag rm mytag
            \\(list tag)
            \\    xit tag list
            ,
        },
        .status => .{
            .name = "status",
            .descrip =
            \\show the working tree status
            ,
            .example =
            \\(display in TUI)
            \\    xit status
            \\(display in CLI)
            \\    xit status --cli
            ,
        },
        .diff => .{
            .name = "diff",
            .descrip =
            \\show changes between commits, commit and working tree, etc
            ,
            .example =
            \\(display in TUI)
            \\    xit diff
            \\(display diff of workspace content in the CLI)
            \\    xit diff --cli
            \\(display diff of staged content in the CLI)
            \\    xit diff --staged
            ,
        },
        .branch => .{
            .name = "branch",
            .descrip =
            \\add, remove, and list branches
            ,
            .example =
            \\(add branch)
            \\    xit branch add mybranch
            \\(remove branch)
            \\    xit branch rm mybranch
            \\(list branches)
            \\    xit branch list
            ,
        },
        .switch_head => .{
            .name = "switch",
            .descrip =
            \\switch working tree to a branch or commit id
            ,
            .example =
            \\(switch to branch)
            \\    xit switch mybranch
            \\(switch to commit id)
            \\    xit switch a1b2c3...
            ,
        },
        .restore => .{
            .name = "restore",
            .descrip =
            \\restore working tree files
            ,
            .example =
            \\xit restore myfile.txt
            ,
        },
        .log => .{
            .name = "log",
            .descrip =
            \\show commit logs
            ,
            .example =
            \\(display in TUI)
            \\    xit log
            \\(display in CLI)
            \\    xit log --cli
            ,
        },
        .merge => .{
            .name = "merge",
            .descrip =
            \\join two or more development histories together
            ,
            .example =
            \\(merge branch)
            \\    xit merge mybranch
            \\(merge commit id)
            \\    xit merge a1b2c3...
            ,
        },
        .cherry_pick => .{
            .name = "cherry-pick",
            .descrip =
            \\apply the changes introduced by an existing commit
            ,
            .example =
            \\xit cherry-pick a1b2c3...
            ,
        },
        .config => .{
            .name = "config",
            .descrip =
            \\add, remove, and list config options
            ,
            .example =
            \\(add config)
            \\    xit config add core.editor vim
            \\(remove config)
            \\    xit config rm core.editor
            \\(list configs)
            \\    xit config list
            ,
        },
        .remote => .{
            .name = "remote",
            .descrip =
            \\add, remove, and list remotes
            ,
            .example =
            \\(add remote)
            \\    xit remote add origin https://github.com/...
            \\(remove remote)
            \\    xit remote rm origin
            \\(list remotes)
            \\    xit remote list
            ,
        },
        .fetch => .{
            .name = "fetch",
            .descrip =
            \\download objects and refs from another repo
            ,
            .example =
            \\xit fetch
            ,
        },
        .pull => .{
            .name = "pull",
            .descrip =
            \\fetch and merge from another repo
            ,
            .example =
            \\xit pull
            ,
        },
    };
}

pub fn printHelp(cmd_kind_maybe: ?CommandKind, writer: std.io.AnyWriter) !void {
    const print_indent = 15;
    if (cmd_kind_maybe) |cmd_kind| {
        const help = commandHelp(cmd_kind);
        // name and description
        try writer.print("{s}", .{help.name});
        for (0..print_indent - help.name.len) |_| try writer.print(" ", .{});
        var split_iter = std.mem.splitScalar(u8, help.descrip, '\n');
        try writer.print("{s}\n", .{split_iter.first()});
        while (split_iter.next()) |line| {
            for (0..print_indent) |_| try writer.print(" ", .{});
            try writer.print("{s}\n", .{line});
        }
        try writer.print("\n", .{});
        // example
        split_iter = std.mem.splitScalar(u8, help.example, '\n');
        while (split_iter.next()) |line| {
            for (0..print_indent) |_| try writer.print(" ", .{});
            try writer.print("{s}\n", .{line});
        }
    } else {
        try writer.print("help: xit <command> [<args>]\n\n", .{});
        inline for (@typeInfo(CommandKind).Enum.fields) |field| {
            const help = commandHelp(@enumFromInt(field.value));
            // name and description
            try writer.print("{s}", .{help.name});
            for (0..print_indent - help.name.len) |_| try writer.print(" ", .{});
            var split_iter = std.mem.splitScalar(u8, help.descrip, '\n');
            try writer.print("{s}\n", .{split_iter.first()});
            while (split_iter.next()) |line| {
                for (0..print_indent) |_| try writer.print(" ", .{});
                try writer.print("{s}\n", .{line});
            }
        }
    }
}

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
            else if (std.mem.eql(u8, command_name, "untrack"))
                .untrack
            else if (std.mem.eql(u8, command_name, "rm"))
                .rm
            else if (std.mem.eql(u8, command_name, "commit"))
                .commit
            else if (std.mem.eql(u8, command_name, "tag"))
                .tag
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
                .cherry_pick
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
        },
        untrack: struct {
            paths: []const []const u8,
            opts: idx.IndexUntrackOptions,
        },
        rm: struct {
            paths: []const []const u8,
            opts: idx.IndexRemoveOptions,
        },
        commit: obj.CommitMetadata(hash_kind),
        tag: tag.TagCommand,
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
        cherry_pick: mrg.MergeInput(repo_kind, hash_kind),
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
                    } };
                },
                .untrack => {
                    if (cmd_args.positional_args.len == 0) return null;

                    return .{ .untrack = .{
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
                .commit => {
                    // if a message is included, it must have a non-null value
                    const message_maybe = if (cmd_args.get("-m")) |msg| (msg orelse return error.TagMessageNotFound) else null;
                    return .{ .commit = .{
                        .message = message_maybe,
                        .allow_empty = cmd_args.contains("--allow-empty"),
                    } };
                },
                .tag => {
                    if (cmd_args.positional_args.len == 0) return null;

                    const cmd_name = cmd_args.positional_args[0];

                    var cmd: tag.TagCommand = undefined;
                    if (std.mem.eql(u8, "list", cmd_name)) {
                        cmd = .list;
                    } else if (std.mem.eql(u8, "add", cmd_name)) {
                        if (cmd_args.positional_args.len != 2) {
                            return null;
                        }
                        // if a message is included, it must have a non-null value
                        const message_maybe = if (cmd_args.get("-m")) |msg| (msg orelse return error.TagMessageNotFound) else null;
                        cmd = .{ .add = .{
                            .name = cmd_args.positional_args[1],
                            .message = message_maybe,
                        } };
                    } else if (std.mem.eql(u8, "rm", cmd_name)) {
                        if (cmd_args.positional_args.len != 2) {
                            return null;
                        }
                        cmd = .{ .remove = .{ .name = cmd_args.positional_args[1] } };
                    } else {
                        try cmd_args.unused_args.put(cmd_name, {});
                        return null;
                    }

                    return .{ .tag = cmd };
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

                    const merge_action: mrg.MergeAction(repo_kind, hash_kind) =
                        if (cmd_args.contains("--continue"))
                        .cont
                    else blk: {
                        var source = std.ArrayList(rf.RefOrOid(hash_kind)).init(cmd_args.arena.allocator());
                        for (cmd_args.positional_args) |arg| {
                            try source.append(rf.RefOrOid(hash_kind).initFromUser(arg) orelse return error.InvalidRefOrOid);
                        }
                        break :blk .{ .new = .{ .source = try source.toOwnedSlice() } };
                    };

                    return .{
                        .merge = .{
                            .kind = .full,
                            .action = merge_action,
                        },
                    };
                },
                .cherry_pick => {
                    if (cmd_args.positional_args.len == 0) return null;

                    const merge_action: mrg.MergeAction(repo_kind, hash_kind) =
                        if (cmd_args.contains("--continue"))
                        .cont
                    else blk: {
                        var source = std.ArrayList(rf.RefOrOid(hash_kind)).init(cmd_args.arena.allocator());
                        for (cmd_args.positional_args) |arg| {
                            try source.append(rf.RefOrOid(hash_kind).initFromUser(arg) orelse return error.InvalidRefOrOid);
                        }
                        break :blk .{ .new = .{ .source = try source.toOwnedSlice() } };
                    };

                    return .{
                        .merge = .{
                            .kind = .pick,
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
                        if (cmd_args.positional_args.len < 3) {
                            return null;
                        }
                        cmd = .{ .add = .{
                            .name = cmd_args.positional_args[1],
                            .value = if (cmd_args.positional_args.len == 3)
                                cmd_args.positional_args[2]
                            else
                                try std.mem.join(cmd_args.arena.allocator(), " ", cmd_args.positional_args[2..]),
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

    // arg requires value
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

    // extra config add args are joined
    {
        var cmd_args = try CommandArgs.init(allocator, &.{ "config", "add", "user.name", "radar", "roark" });
        defer cmd_args.deinit();
        const command = try CommandDispatch(repo_kind, hash_kind).init(&cmd_args);
        try std.testing.expectEqualStrings("cli", @tagName(command));
        try std.testing.expectEqualStrings("radar roark", command.cli.config.add.value);
    }

    // invalid command and arg
    {
        var cmd_args = try CommandArgs.init(allocator, &.{ "stats", "--clii" });
        defer cmd_args.deinit();
        const command = try CommandDispatch(repo_kind, hash_kind).init(&cmd_args);
        try std.testing.expectEqualStrings("invalid", @tagName(command));
        try std.testing.expectEqualStrings("command", @tagName(command.invalid));
        try std.testing.expectEqualStrings("stats", command.invalid.command);
    }

    // invalid arg
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
