const std = @import("std");
const net_socket = @import("./socket.zig");
const net_wire = @import("./wire.zig");
const net_pkt = @import("./pkt.zig");

pub const RawState = struct {
    pub fn init() RawState {
        return .{};
    }

    pub fn deinit(_: *RawState) void {}

    pub fn close(_: *RawState) !void {}
};

pub const RawStream = struct {
    wire_state: *RawState,
    io: net_socket.SocketStream,
    cmd: []const u8,
    url: []u8,
    sent_command: bool,
    allocator: std.mem.Allocator,

    pub fn initMaybe(
        allocator: std.mem.Allocator,
        wire_state: *RawState,
        url: []const u8,
        wire_action: net_wire.WireAction,
    ) !?RawStream {
        return switch (wire_action) {
            .list_upload_pack => try listUpload(allocator, wire_state, url),
            .list_receive_pack => try listReceive(allocator, wire_state, url),
            .upload_pack => null,
            .receive_pack => null,
        };
    }

    fn init(
        allocator: std.mem.Allocator,
        wire_state: *RawState,
        url: []const u8,
        cmd: []const u8,
    ) !RawStream {
        const url_dupe = try allocator.dupe(u8, url);
        errdefer allocator.free(url_dupe);

        const uri = try std.Uri.parse(url_dupe);

        const host = uri.host orelse return error.InvalidUri;
        const port = uri.port orelse return error.InvalidUri;

        const host_str = switch (host) {
            .raw => |s| s,
            .percent_encoded => |s| s,
        };

        return .{
            .wire_state = wire_state,
            .io = try net_socket.SocketStream.init(allocator, host_str, port),
            .cmd = cmd,
            .url = url_dupe,
            .sent_command = false,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *RawStream, allocator: std.mem.Allocator) void {
        self.io.close() catch {};
        self.io.deinit(allocator);
        allocator.free(self.url);
    }

    pub fn read(
        self: *RawStream,
        buffer: [*c]u8,
        buf_size: usize,
    ) !usize {
        if (!self.sent_command) {
            try sendCommand(self);
        }

        return try self.io.read(buffer, buf_size);
    }

    pub fn write(
        self: *RawStream,
        buffer: [*c]const u8,
        len: usize,
    ) !void {
        if (!self.sent_command) {
            try sendCommand(self);
        }

        try self.io.writeAll(buffer, len);
    }
};

fn sendCommand(stream: *RawStream) !void {
    var buffer = std.ArrayList(u8).init(stream.allocator);
    defer buffer.deinit();

    const uri = try std.Uri.parse(stream.url);
    const path = switch (uri.path) {
        .raw => |s| s,
        .percent_encoded => |s| s,
    };
    const host = uri.host orelse return error.InvalidUri;
    const host_str = switch (host) {
        .raw => |s| s,
        .percent_encoded => |s| s,
    };
    try buffer.writer().print("0000{s} {s}\x00host={s}\x00", .{ stream.cmd, path, host_str });

    var command_size_buf = [_]u8{'0'} ** 4;
    try net_pkt.commandSize(&command_size_buf, buffer.items.len);
    @memcpy(buffer.items[0..command_size_buf.len], &command_size_buf);

    try stream.io.writeAll(buffer.items.ptr, buffer.items.len);

    stream.sent_command = true;
}

fn listUpload(
    allocator: std.mem.Allocator,
    wire_state: *RawState,
    url: []const u8,
) !RawStream {
    var stream = try RawStream.init(allocator, wire_state, url, "git-upload-pack");
    errdefer stream.deinit(allocator);

    try stream.io.connect(allocator);

    return stream;
}

fn listReceive(
    allocator: std.mem.Allocator,
    wire_state: *RawState,
    url: []const u8,
) !RawStream {
    var stream = try RawStream.init(allocator, wire_state, url, "git-receive-pack");
    errdefer stream.deinit(allocator);

    try stream.io.connect(allocator);

    return stream;
}
