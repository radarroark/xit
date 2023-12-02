const std = @import("std");
const rp = @import("./repo.zig");
const st = @import("./status.zig");
const hash = @import("./hash.zig");
const io = @import("./io.zig");
const idx = @import("./index.zig");
const obj = @import("./object.zig");

fn absIndex(i: isize, len: usize) usize {
    return if (i < 0) len - std.math.absCast(i) else @intCast(i);
}

pub const MyersDiff = struct {
    result: std.ArrayList(Line),

    pub const Line = struct {
        op: enum {
            eql,
            ins,
            del,
        },
        text: []const u8,
    };

    pub fn init(allocator: std.mem.Allocator, a: []const []const u8, b: []const []const u8) !MyersDiff {
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

        return MyersDiff{
            .result = result,
        };
    }

    pub fn deinit(self: *MyersDiff) void {
        self.result.deinit();
    }
};

pub const DiffKind = enum {
    workspace,
    index,
};

pub fn DiffList(comptime repo_kind: rp.RepoKind) type {
    return struct {
        diffs: std.ArrayList(Diff),
        status: st.Status(repo_kind),

        pub const Target = struct {
            path: []const u8,
            oid: [hash.SHA1_BYTES_LEN]u8,
            oid_hex: [hash.SHA1_HEX_LEN]u8,
            mode: ?io.Mode,

            pub fn initFromIndex(entry: idx.Index(repo_kind).Entry) Target {
                return .{
                    .path = entry.path,
                    .oid = entry.oid,
                    .oid_hex = std.fmt.bytesToHex(&entry.oid, .lower),
                    .mode = entry.mode,
                };
            }

            pub fn initFromWorkspace(core: *rp.Repo(repo_kind).Core, path: []const u8, mode: io.Mode) !Target {
                var target = Target{
                    .path = path,
                    .oid = [_]u8{0} ** hash.SHA1_BYTES_LEN,
                    .oid_hex = [_]u8{0} ** hash.SHA1_HEX_LEN,
                    .mode = mode,
                };
                var file = try core.repo_dir.openFile(path, .{ .mode = std.fs.File.OpenMode.read_only });
                defer file.close();
                try hash.sha1_file(file, null, &target.oid);
                target.oid_hex = std.fmt.bytesToHex(&target.oid, .lower);
                return target;
            }

            pub fn initFromNothing(path: []const u8) Target {
                return .{
                    .path = path,
                    .oid = [_]u8{0} ** hash.SHA1_BYTES_LEN,
                    .oid_hex = [_]u8{0} ** hash.SHA1_HEX_LEN,
                    .mode = null,
                };
            }

            pub fn initFromHead(path: []const u8, entry: obj.TreeEntry) Target {
                return .{
                    .path = path,
                    .oid = entry.oid,
                    .oid_hex = std.fmt.bytesToHex(&entry.oid, .lower),
                    .mode = entry.mode,
                };
            }
        };

        pub const Diff = struct {
            path: []const u8,
            lines: std.ArrayList([]const u8),
            arena: std.heap.ArenaAllocator,

            pub fn init(allocator: std.mem.Allocator, a: Target, b: Target) !Diff {
                var arena = std.heap.ArenaAllocator.init(allocator);
                errdefer arena.deinit();

                var lines = std.ArrayList([]const u8).init(arena.allocator());

                try lines.append(try std.fmt.allocPrint(arena.allocator(), "diff --git a/{s} b/{s}", .{ a.path, b.path }));

                if (a.mode) |a_mode| {
                    if (b.mode) |b_mode| {
                        if (a_mode.unix_permission != b_mode.unix_permission) {
                            try lines.append(try std.fmt.allocPrint(arena.allocator(), "old mode {s}", .{a_mode.to_str()}));
                            try lines.append(try std.fmt.allocPrint(arena.allocator(), "new mode {s}", .{b_mode.to_str()}));
                        }
                    } else {
                        try lines.append(try std.fmt.allocPrint(arena.allocator(), "deleted file mode {s}", .{a_mode.to_str()}));
                    }
                } else {
                    if (b.mode) |b_mode| {
                        try lines.append(try std.fmt.allocPrint(arena.allocator(), "new file mode {s}", .{b_mode.to_str()}));
                    }
                }

                if (!std.mem.eql(u8, &a.oid, &b.oid)) {
                    if (a.mode) |a_mode| {
                        if (b.mode) |b_mode| {
                            if (a_mode.unix_permission != b_mode.unix_permission) {
                                try lines.append(try std.fmt.allocPrint(arena.allocator(), "index {s}..{s} {s}", .{
                                    a.oid_hex[0..7],
                                    b.oid_hex[0..7],
                                    a_mode.to_str(),
                                }));
                            } else {
                                try lines.append(try std.fmt.allocPrint(arena.allocator(), "index {s}..{s}", .{
                                    a.oid_hex[0..7],
                                    b.oid_hex[0..7],
                                }));
                            }
                        } else {
                            try lines.append(try std.fmt.allocPrint(arena.allocator(), "index {s}..{s}", .{
                                a.oid_hex[0..7],
                                b.oid_hex[0..7],
                            }));
                        }
                    }

                    try lines.append(try std.fmt.allocPrint(arena.allocator(), "--- a/{s}", .{a.path}));

                    if (b.mode != null) {
                        try lines.append(try std.fmt.allocPrint(arena.allocator(), "+++ b/{s}", .{b.path}));
                    } else {
                        try lines.append("+++ /dev/null");
                    }
                }

                return .{
                    .path = a.path,
                    .lines = lines,
                    .arena = arena,
                };
            }

            pub fn deinit(self: *Diff) void {
                self.arena.deinit();
            }
        };

        pub fn init(allocator: std.mem.Allocator, core: *rp.Repo(repo_kind).Core, diff_kind: DiffKind) !DiffList(repo_kind) {
            var status = try st.Status(repo_kind).init(allocator, core);
            errdefer status.deinit();

            var diffs = std.ArrayList(Diff).init(allocator);
            errdefer diffs.deinit();

            switch (diff_kind) {
                .workspace => {
                    for (status.workspace_modified.items) |entry| {
                        try diffs.append(try Diff.init(
                            allocator,
                            Target.initFromIndex(status.index.entries.get(entry.path) orelse return error.EntryNotFound),
                            try Target.initFromWorkspace(core, entry.path, io.getMode(entry.meta)),
                        ));
                    }

                    for (status.workspace_deleted.items) |path| {
                        try diffs.append(try Diff.init(
                            allocator,
                            Target.initFromIndex(status.index.entries.get(path) orelse return error.EntryNotFound),
                            Target.initFromNothing(path),
                        ));
                    }
                },
                .index => {
                    for (status.index_added.items) |path| {
                        try diffs.append(try Diff.init(
                            allocator,
                            Target.initFromNothing(path),
                            Target.initFromIndex(status.index.entries.get(path) orelse return error.EntryNotFound),
                        ));
                    }

                    for (status.index_modified.items) |path| {
                        try diffs.append(try Diff.init(
                            allocator,
                            Target.initFromHead(path, status.head_tree.entries.get(path) orelse return error.EntryNotFound),
                            Target.initFromIndex(status.index.entries.get(path) orelse return error.EntryNotFound),
                        ));
                    }

                    for (status.index_deleted.items) |path| {
                        try diffs.append(try Diff.init(
                            allocator,
                            Target.initFromHead(path, status.head_tree.entries.get(path) orelse return error.EntryNotFound),
                            Target.initFromNothing(path),
                        ));
                    }
                },
            }

            return .{
                .diffs = diffs,
                .status = status,
            };
        }

        pub fn deinit(self: *DiffList(repo_kind)) void {
            for (self.diffs.items) |*diff| {
                diff.deinit();
            }
            self.diffs.deinit();
            self.status.deinit();
        }
    };
}

test "myers diff" {
    const allocator = std.testing.allocator;
    const lines1 = [_][]const u8{ "A", "B", "C", "A", "B", "B", "A" };
    const lines2 = [_][]const u8{ "C", "B", "A", "B", "A", "C" };
    const expected_diff = [_]MyersDiff.Line{
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
    var actual_diff = try MyersDiff.init(allocator, &lines1, &lines2);
    defer actual_diff.deinit();
    try std.testing.expectEqual(expected_diff.len, actual_diff.result.items.len);
    for (expected_diff, actual_diff.result.items) |expected, actual| {
        try std.testing.expectEqual(expected, actual);
    }
}
