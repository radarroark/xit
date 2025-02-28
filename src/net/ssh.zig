const std = @import("std");
const rp = @import("../repo.zig");
const cfg = @import("../config.zig");
const net_wire = @import("./wire.zig");

pub const Opts = struct {
    command: ?[]const u8 = null,
};

pub const SshState = struct {
    process: ?*std.process.Child,
    allocator: *std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    command: ?[]const u8,

    pub fn init(
        comptime repo_kind: rp.RepoKind,
        comptime repo_opts: rp.RepoOpts(repo_kind),
        state: rp.Repo(repo_kind, repo_opts).State(.read_only),
        allocator: std.mem.Allocator,
        opts: Opts,
    ) !SshState {
        const allocator_ptr = try allocator.create(std.mem.Allocator);
        errdefer allocator.destroy(allocator_ptr);
        allocator_ptr.* = allocator;

        const arena_ptr = try allocator.create(std.heap.ArenaAllocator);
        errdefer allocator.destroy(arena_ptr);
        arena_ptr.* = std.heap.ArenaAllocator.init(allocator);

        const command = if (opts.command) |cmd|
            try arena_ptr.allocator().dupe(u8, cmd)
        else blk: {
            const env_var_maybe = std.process.getEnvVarOwned(allocator, "XIT_SSH_COMMAND") catch |err| switch (err) {
                error.EnvironmentVariableNotFound => null,
                else => |e| return e,
            };
            if (env_var_maybe) |env_var| {
                defer allocator.free(env_var);
                break :blk try arena_ptr.allocator().dupe(u8, env_var);
            }

            var config = try cfg.Config(repo_kind, repo_opts).init(state, allocator);
            defer config.deinit();
            const core_section = config.sections.get("core") orelse break :blk null;
            const ssh_cmd = core_section.get("sshcommand") orelse break :blk null;
            if (ssh_cmd.len > 0) {
                break :blk try arena_ptr.allocator().dupe(u8, ssh_cmd);
            }

            break :blk null;
        };

        return .{
            .process = null,
            .allocator = allocator_ptr,
            .arena = arena_ptr,
            .command = command,
        };
    }

    pub fn deinit(self: *SshState) void {
        self.arena.deinit();
        self.allocator.destroy(self.arena);
        self.allocator.destroy(self.allocator);
    }

    pub fn close(self: *SshState) !void {
        if (self.process) |process| {
            _ = try process.kill();
            self.allocator.destroy(process);
            self.process = null;
        }
    }
};

pub const SshStream = struct {
    wire_state: *SshState,

    pub fn initMaybe(
        wire_state: *SshState,
        sshpath: []const u8,
        wire_action: net_wire.WireAction,
    ) !?SshStream {
        switch (wire_action) {
            .list_upload_pack, .list_receive_pack => {
                try spawnSsh(wire_state, wire_action, sshpath, wire_state.command);
                return .{ .wire_state = wire_state };
            },
            .upload_pack, .receive_pack => return null,
        }
    }

    pub fn deinit(_: *SshStream) void {}

    pub fn read(
        self: *SshStream,
        buffer: [*]u8,
        buf_size: usize,
    ) !usize {
        const process = self.wire_state.process orelse return error.ProcessNotFound;
        const stdout = process.stdout orelse return error.StdoutNotFound;
        return try stdout.read(buffer[0..buf_size]);
    }

    pub fn write(
        self: *SshStream,
        buffer: [*]const u8,
        len: usize,
    ) !void {
        const process = self.wire_state.process orelse return error.ProcessNotFound;
        const stdin = process.stdin orelse return error.StdinNotFound;
        try stdin.writeAll(buffer[0..len]);
    }
};

pub fn parseUri(str: []const u8) !std.Uri {
    return if (std.mem.startsWith(u8, str, "ssh://"))
        try std.Uri.parse(str)
    else blk: {
        const colon_idx = std.mem.indexOfScalar(u8, str, ':') orelse return error.InvalidSshUrl;
        const user_and_host = str[0..colon_idx];
        const path = str[colon_idx + 1 ..];

        const at_idx = std.mem.indexOfScalar(u8, user_and_host, '@') orelse return error.InvalidSshUrl;
        const user = user_and_host[0..at_idx];
        const host = user_and_host[at_idx + 1 ..];

        break :blk std.Uri{
            .scheme = "ssh://",
            .user = .{ .percent_encoded = user },
            .host = .{ .percent_encoded = host },
            .path = .{ .percent_encoded = path },
        };
    };
}

fn spawnSsh(
    wire_state: *SshState,
    wire_action: net_wire.WireAction,
    url: []const u8,
    command_maybe: ?[]const u8,
) !void {
    var args = std.ArrayList([]const u8).init(wire_state.arena.allocator());

    const command = if (command_maybe) |cmd| cmd else "ssh";

    // TODO: fix paths that have spaces
    var arg_iter = try std.process.ArgIteratorGeneral(.{ .single_quotes = true }).init(wire_state.allocator.*, command);
    defer arg_iter.deinit();
    while (arg_iter.next()) |arg| {
        try args.append(arg);
    }

    const uri = try parseUri(url);

    if (uri.port) |port| {
        try args.append("-p");
        try args.append(try std.fmt.allocPrint(wire_state.arena.allocator(), "{}", .{port}));
    }

    if (uri.user) |user| {
        const user_str = switch (user) {
            .raw => |s| s,
            .percent_encoded => |s| s,
        };
        if (uri.host) |host| {
            const host_str = switch (host) {
                .raw => |s| s,
                .percent_encoded => |s| s,
            };
            try args.append(try std.fmt.allocPrint(wire_state.arena.allocator(), "{s}@{s}", .{ user_str, host_str }));
        }
    } else {
        if (uri.host) |host| {
            const host_str = switch (host) {
                .raw => |s| s,
                .percent_encoded => |s| s,
            };
            try args.append(try wire_state.arena.allocator().dupe(u8, host_str));
        }
    }

    const sub_command = switch (wire_action) {
        .list_upload_pack => "git-upload-pack",
        .list_receive_pack => "git-receive-pack",
        else => return error.InvalidAction,
    };
    try args.append(try wire_state.arena.allocator().dupe(u8, sub_command));

    const path_str = switch (uri.path) {
        .raw => |s| s,
        .percent_encoded => |s| s,
    };
    try args.append(try wire_state.arena.allocator().dupe(u8, path_str));

    const ssh_cmdline = try args.toOwnedSlice();

    const process = try wire_state.allocator.create(std.process.Child);
    process.* = std.process.Child.init(ssh_cmdline, wire_state.allocator.*);
    process.stdin_behavior = .Pipe;
    process.stdout_behavior = .Pipe;
    process.stderr_behavior = .Ignore;
    wire_state.process = process;

    try process.spawn();
}
