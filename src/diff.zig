const std = @import("std");

fn absIndex(i: isize, len: usize) usize {
    return if (i < 0) len - std.math.absCast(i) else @intCast(i);
}

pub const Diff = struct {
    result: std.ArrayList(Line),

    pub const Line = struct {
        op: enum {
            eql,
            ins,
            del,
        },
        text: []const u8,
    };

    pub fn init(allocator: std.mem.Allocator, a: []const []const u8, b: []const []const u8) !Diff {
        var trace = std.ArrayList(std.ArrayList(isize)).init(allocator);
        defer {
            for (trace.items) |*arr| {
                arr.deinit();
            }
            trace.deinit();
        }

        {
            const max = a.len + b.len;
            var v = try std.ArrayList(isize).initCapacity(allocator, 2 * max + 1);
            defer v.deinit();
            v.expandToCapacity();
            for (v.items) |*item| {
                item.* = 0;
            }
            blk: for (0..max) |d| {
                try trace.append(try v.clone());
                for (0..d + 1) |i| {
                    const dd: isize = @intCast(d);
                    const ii: isize = @intCast(i);
                    const kk: isize = -dd + ii * 2;
                    var xx: isize = undefined;
                    if (kk == -dd or (kk != dd and v.items[absIndex(kk - 1, v.items.len)] < v.items[absIndex(kk + 1, v.items.len)])) {
                        xx = v.items[absIndex(kk + 1, v.items.len)];
                    } else {
                        xx = v.items[absIndex(kk - 1, v.items.len)] + 1;
                    }
                    var yy = xx - kk;
                    while (xx < a.len and yy < b.len and std.mem.eql(u8, a[absIndex(xx, a.len)], b[absIndex(yy, b.len)])) {
                        xx += 1;
                        yy += 1;
                    }
                    v.items[absIndex(kk, v.items.len)] = xx;
                    if (xx >= a.len and yy >= b.len) {
                        break :blk;
                    }
                }
            }
        }

        var backtrack = std.ArrayList([4]isize).init(allocator);
        defer backtrack.deinit();
        {
            var xx: isize = @intCast(a.len);
            var yy: isize = @intCast(b.len);
            for (0..trace.items.len) |i| {
                const d = trace.items.len - i - 1;
                const v = trace.items[d];
                const dd: isize = @intCast(d);
                const kk = xx - yy;

                var prev_kk: isize = undefined;
                if (kk == -dd or (kk != dd and v.items[absIndex(kk - 1, v.items.len)] < v.items[absIndex(kk + 1, v.items.len)])) {
                    prev_kk = kk + 1;
                } else {
                    prev_kk = kk - 1;
                }
                const prev_xx = v.items[absIndex(prev_kk, v.items.len)];
                const prev_yy = prev_xx - prev_kk;

                while (xx > prev_xx and yy > prev_yy) {
                    try backtrack.append(.{ xx - 1, yy - 1, xx, yy });
                    xx -= 1;
                    yy -= 1;
                }

                if (dd > 0) {
                    try backtrack.append(.{ prev_xx, prev_yy, xx, yy });
                }

                xx = prev_xx;
                yy = prev_yy;
            }
        }

        var result = try std.ArrayList(Line).initCapacity(allocator, backtrack.items.len);
        errdefer result.deinit();
        result.expandToCapacity();
        for (backtrack.items, 0..) |edit, i| {
            const ii = backtrack.items.len - i - 1;

            const prev_xx = edit[0];
            const prev_yy = edit[1];
            const xx = edit[2];
            const yy = edit[3];

            if (xx == prev_xx) {
                result.items[ii] = .{ .op = .ins, .text = b[absIndex(prev_yy, b.len)] };
            } else if (yy == prev_yy) {
                result.items[ii] = .{ .op = .del, .text = a[absIndex(prev_xx, a.len)] };
            } else {
                result.items[ii] = .{ .op = .eql, .text = a[absIndex(prev_xx, a.len)] };
            }
        }

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
    const expected_diff = [_]Diff.Line{
        .{ .op = .del, .text = "A" },
        .{ .op = .del, .text = "B" },
        .{ .op = .eql, .text = "C" },
        .{ .op = .ins, .text = "B" },
        .{ .op = .eql, .text = "A" },
        .{ .op = .eql, .text = "B" },
        .{ .op = .del, .text = "B" },
        .{ .op = .eql, .text = "A" },
        .{ .op = .ins, .text = "C" },
    };
    var actual_diff = try Diff.init(allocator, &lines1, &lines2);
    defer actual_diff.deinit();
    try std.testing.expectEqual(expected_diff.len, actual_diff.result.items.len);
    for (expected_diff, actual_diff.result.items) |expected, actual| {
        try std.testing.expectEqual(expected, actual);
    }
}
