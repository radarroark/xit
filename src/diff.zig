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

test "diff" {
    const allocator = std.testing.allocator;
    const lines1 = [_][]const u8{ "A", "B", "C", "A", "B", "B", "A" };
    const lines2 = [_][]const u8{ "C", "B", "A", "B", "A", "C" };
    const expected_diff = [_][]const u8{};
    var actual_diff = try Diff.init(allocator, &lines1, &lines2);
    defer actual_diff.deinit();
    try std.testing.expectEqual(expected_diff.len, actual_diff.result.items.len);
    for (expected_diff, actual_diff.result.items) |expected, actual| {
        try std.testing.expectEqualStrings(expected, actual);
    }
}
