const std = @import("std");

pub const Diff = struct {
    result: std.ArrayList([]const u8),

    pub fn init(allocator: std.mem.Allocator, a: []const []const u8, b: []const []const u8) !Diff {
        const max = a.len + b.len;
        var v = try std.ArrayList(isize).initCapacity(allocator, 2 * max + 1);
        defer v.deinit();
        var result = std.ArrayList([]const u8).init(allocator);
        errdefer result.deinit();
        return Diff{
            .result = result,
        };
    }

    pub fn deinit(self: *Diff) void {
        self.result.deinit();
    }
};
