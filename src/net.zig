const std = @import("std");
const network = @import("network");

const TIMEOUT_MICRO_SECS: u32 = 2_000_000;

pub fn fetch(allocator: std.mem.Allocator, host: []const u8, port: u16, repo: []const u8) !void {
    try network.init();
    defer network.deinit();

    var sock = try network.connectToHost(allocator, host, port, .tcp);
    defer sock.close();
    try sock.setTimeouts(TIMEOUT_MICRO_SECS, TIMEOUT_MICRO_SECS);

    const writer = sock.writer();

    // send command
    {
        var command_buf = [_]u8{0} ** 256;
        const command = try std.fmt.bufPrint(&command_buf, "0000git-upload-pack {s}\x00host={s}\x00", .{ repo, host });

        var command_size_buf = [_]u8{0} ** 4;
        const command_size = try std.fmt.bufPrint(&command_size_buf, "{x}", .{command.len});

        @memcpy(command[command_size_buf.len - command_size.len .. command_size_buf.len], command_size);

        try writer.writeAll(command);
    }
}
