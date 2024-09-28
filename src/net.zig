const std = @import("std");
const network = @import("network");

const TIMEOUT_MICRO_SECS: u32 = 2_000_000;

pub fn fetch(allocator: std.mem.Allocator, host: []const u8, port: u16) !void {
    try network.init();
    defer network.deinit();

    var sock = try network.connectToHost(allocator, host, port, .tcp);
    defer sock.close();
    try sock.setTimeouts(TIMEOUT_MICRO_SECS, TIMEOUT_MICRO_SECS);
}
