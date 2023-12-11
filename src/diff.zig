const std = @import("std");
const rp = @import("./repo.zig");
const st = @import("./status.zig");
const hash = @import("./hash.zig");
const io = @import("./io.zig");
const idx = @import("./index.zig");
const obj = @import("./object.zig");
const chk = @import("./checkout.zig");

fn absIndex(i: isize, len: usize) usize {
    return if (i < 0) len - @abs(i) else @intCast(i);
}

pub const MyersDiff = struct {
    edits: std.ArrayList(Edit),

    pub const Line = struct {
        num: usize,
        text: []const u8,
    };

    pub const Edit = union(enum) {
        eql: struct {
            old_line: Line,
            new_line: Line,
        },
        ins: struct {
            new_line: Line,
        },
        del: struct {
            old_line: Line,
        },
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
            blk: for (0..max + 1) |d| {
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

        var edits = try std.ArrayList(Edit).initCapacity(allocator, backtrack.items.len);
        errdefer edits.deinit();
        edits.expandToCapacity();
        for (backtrack.items, 0..) |edit, i| {
            const ii = backtrack.items.len - i - 1;

            const prev_xx = edit[0];
            const prev_yy = edit[1];
            const xx = edit[2];
            const yy = edit[3];

            if (xx == prev_xx) {
                const new_idx = absIndex(prev_yy, b.len);
                edits.items[ii] = .{
                    .ins = .{
                        .new_line = .{ .num = new_idx + 1, .text = b[new_idx] },
                    },
                };
            } else if (yy == prev_yy) {
                const old_idx = absIndex(prev_xx, a.len);
                edits.items[ii] = .{
                    .del = .{
                        .old_line = .{ .num = old_idx + 1, .text = a[old_idx] },
                    },
                };
            } else {
                const old_idx = absIndex(prev_xx, a.len);
                const new_idx = absIndex(prev_yy, b.len);
                edits.items[ii] = .{
                    .eql = .{
                        .old_line = .{ .num = old_idx + 1, .text = a[old_idx] },
                        .new_line = .{ .num = new_idx + 1, .text = b[new_idx] },
                    },
                };
            }
        }

        return MyersDiff{
            .edits = edits,
        };
    }

    pub fn deinit(self: *MyersDiff) void {
        self.edits.deinit();
    }
};

test "myers diff" {
    const allocator = std.testing.allocator;
    {
        const lines1 = [_][]const u8{ "A", "B", "C", "A", "B", "B", "A" };
        const lines2 = [_][]const u8{ "C", "B", "A", "B", "A", "C" };
        const expected_diff = [_]MyersDiff.Edit{
            .{ .del = .{ .old_line = .{ .num = 1, .text = "A" } } },
            .{ .del = .{ .old_line = .{ .num = 2, .text = "B" } } },
            .{ .eql = .{ .old_line = .{ .num = 3, .text = "C" }, .new_line = .{ .num = 1, .text = "C" } } },
            .{ .ins = .{ .new_line = .{ .num = 2, .text = "B" } } },
            .{ .eql = .{ .old_line = .{ .num = 4, .text = "A" }, .new_line = .{ .num = 3, .text = "A" } } },
            .{ .eql = .{ .old_line = .{ .num = 5, .text = "B" }, .new_line = .{ .num = 4, .text = "B" } } },
            .{ .del = .{ .old_line = .{ .num = 6, .text = "B" } } },
            .{ .eql = .{ .old_line = .{ .num = 7, .text = "A" }, .new_line = .{ .num = 5, .text = "A" } } },
            .{ .ins = .{ .new_line = .{ .num = 6, .text = "C" } } },
        };
        var actual_diff = try MyersDiff.init(allocator, &lines1, &lines2);
        defer actual_diff.deinit();
        try std.testing.expectEqual(expected_diff.len, actual_diff.edits.items.len);
        for (expected_diff, actual_diff.edits.items) |expected, actual| {
            try std.testing.expectEqualDeep(expected, actual);
        }
    }
    {
        const lines1 = [_][]const u8{"hello, world!"};
        const lines2 = [_][]const u8{"goodbye, world!"};
        const expected_diff = [_]MyersDiff.Edit{
            .{ .del = .{ .old_line = .{ .num = 1, .text = "hello, world!" } } },
            .{ .ins = .{ .new_line = .{ .num = 1, .text = "goodbye, world!" } } },
        };
        var actual_diff = try MyersDiff.init(allocator, &lines1, &lines2);
        defer actual_diff.deinit();
        try std.testing.expectEqual(expected_diff.len, actual_diff.edits.items.len);
        for (expected_diff, actual_diff.edits.items) |expected, actual| {
            try std.testing.expectEqualDeep(expected, actual);
        }
    }
}

pub const DiffKind = enum {
    workspace,
    index,
};

pub fn DiffList(comptime repo_kind: rp.RepoKind) type {
    return struct {
        diffs: std.ArrayList(Diff),
        status: st.Status(repo_kind),

        pub const Target = struct {
            allocator: std.mem.Allocator,
            path: []const u8,
            oid: [hash.SHA1_BYTES_LEN]u8,
            oid_hex: [hash.SHA1_HEX_LEN]u8,
            mode: ?io.Mode,
            // TODO: don't read it all into memory
            buffer: []u8,
            lines: std.ArrayList([]const u8),

            pub fn initFromIndex(allocator: std.mem.Allocator, core: *rp.Repo(repo_kind).Core, entry: idx.Index(repo_kind).Entry) !Target {
                const oid_hex = std.fmt.bytesToHex(&entry.oid, .lower);
                var target = Target{
                    .allocator = allocator,
                    .path = entry.path,
                    .oid = entry.oid,
                    .oid_hex = oid_hex,
                    .mode = entry.mode,
                    .buffer = try allocator.alloc(u8, 1024),
                    .lines = undefined,
                };
                const buf = try chk.objectToBuffer(repo_kind, core, allocator, oid_hex, target.buffer);

                var lines = std.ArrayList([]const u8).init(allocator);
                errdefer lines.deinit();
                var iter = std.mem.splitScalar(u8, buf, '\n');
                while (iter.next()) |line| {
                    try lines.append(line);
                }
                target.lines = lines;

                return target;
            }

            pub fn initFromWorkspace(allocator: std.mem.Allocator, core: *rp.Repo(repo_kind).Core, path: []const u8, mode: io.Mode) !Target {
                var target = Target{
                    .allocator = allocator,
                    .path = path,
                    .oid = undefined,
                    .oid_hex = undefined,
                    .mode = mode,
                    .buffer = try allocator.alloc(u8, 1024),
                    .lines = undefined,
                };

                var file = try core.repo_dir.openFile(path, .{ .mode = std.fs.File.OpenMode.read_only });
                defer file.close();
                const size = try file.reader().read(target.buffer);
                const buf = target.buffer[0..size];

                var lines = std.ArrayList([]const u8).init(allocator);
                errdefer lines.deinit();
                var iter = std.mem.splitScalar(u8, buf, '\n');
                while (iter.next()) |line| {
                    try lines.append(line);
                }
                target.lines = lines;

                const file_size = (try file.metadata()).size();
                const header = try std.fmt.allocPrint(allocator, "blob {}\x00", .{file_size});
                defer allocator.free(header);
                try hash.sha1_file(file, header, &target.oid);
                target.oid_hex = std.fmt.bytesToHex(&target.oid, .lower);

                return target;
            }

            pub fn initFromNothing(allocator: std.mem.Allocator, path: []const u8) !Target {
                return .{
                    .allocator = allocator,
                    .path = path,
                    .oid = [_]u8{0} ** hash.SHA1_BYTES_LEN,
                    .oid_hex = [_]u8{0} ** hash.SHA1_HEX_LEN,
                    .mode = null,
                    .buffer = try allocator.alloc(u8, 0),
                    .lines = std.ArrayList([]const u8).init(allocator),
                };
            }

            pub fn initFromHead(allocator: std.mem.Allocator, core: *rp.Repo(repo_kind).Core, path: []const u8, entry: obj.TreeEntry) !Target {
                const oid_hex = std.fmt.bytesToHex(&entry.oid, .lower);
                var target = Target{
                    .allocator = allocator,
                    .path = path,
                    .oid = entry.oid,
                    .oid_hex = oid_hex,
                    .mode = entry.mode,
                    .buffer = try allocator.alloc(u8, 1024),
                    .lines = undefined,
                };
                const buf = try chk.objectToBuffer(repo_kind, core, allocator, oid_hex, target.buffer);

                var lines = std.ArrayList([]const u8).init(allocator);
                errdefer lines.deinit();
                var iter = std.mem.splitScalar(u8, buf, '\n');
                while (iter.next()) |line| {
                    try lines.append(line);
                }
                target.lines = lines;

                return target;
            }

            pub fn deinit(self: *Target) void {
                self.allocator.free(self.buffer);
                self.lines.deinit();
            }
        };

        pub const Diff = struct {
            path: []const u8,
            header_lines: std.ArrayList([]const u8),
            hunks: std.ArrayList(Hunk),
            arena: std.heap.ArenaAllocator,
            target_a: Target,
            target_b: Target,

            pub const Hunk = struct {
                edits: std.ArrayList(MyersDiff.Edit),

                pub const Offsets = struct {
                    del_start: usize,
                    del_count: usize,
                    ins_start: usize,
                    ins_count: usize,
                };

                pub fn offsets(self: Hunk) Offsets {
                    var o = Offsets{
                        .del_start = 0,
                        .del_count = 0,
                        .ins_start = 0,
                        .ins_count = 0,
                    };
                    for (self.edits.items) |edit| {
                        switch (edit) {
                            .eql => {
                                if (o.ins_start == 0) o.ins_start = edit.eql.new_line.num;
                                o.ins_count += 1;
                                if (o.del_start == 0) o.del_start = edit.eql.old_line.num;
                                o.del_count += 1;
                            },
                            .ins => {
                                if (o.ins_start == 0) o.ins_start = edit.ins.new_line.num;
                                o.ins_count += 1;
                            },
                            .del => {
                                if (o.del_start == 0) o.del_start = edit.del.old_line.num;
                                o.del_count += 1;
                            },
                        }
                    }
                    return o;
                }
            };

            pub fn init(allocator: std.mem.Allocator, a: Target, b: Target) !Diff {
                var arena = std.heap.ArenaAllocator.init(allocator);
                errdefer arena.deinit();

                var header_lines = std.ArrayList([]const u8).init(arena.allocator());

                try header_lines.append(try std.fmt.allocPrint(arena.allocator(), "diff --git a/{s} b/{s}", .{ a.path, b.path }));

                var mode_maybe: ?io.Mode = null;

                if (a.mode) |a_mode| {
                    if (b.mode) |b_mode| {
                        if (a_mode.unix_permission != b_mode.unix_permission) {
                            try header_lines.append(try std.fmt.allocPrint(arena.allocator(), "old mode {s}", .{a_mode.to_str()}));
                            try header_lines.append(try std.fmt.allocPrint(arena.allocator(), "new mode {s}", .{b_mode.to_str()}));
                        } else {
                            mode_maybe = a_mode;
                        }
                    } else {
                        try header_lines.append(try std.fmt.allocPrint(arena.allocator(), "deleted file mode {s}", .{a_mode.to_str()}));
                    }
                } else {
                    if (b.mode) |b_mode| {
                        try header_lines.append(try std.fmt.allocPrint(arena.allocator(), "new file mode {s}", .{b_mode.to_str()}));
                    }
                }

                var hunks = std.ArrayList(Hunk).init(arena.allocator());

                if (!std.mem.eql(u8, &a.oid, &b.oid)) {
                    if (mode_maybe) |mode| {
                        try header_lines.append(try std.fmt.allocPrint(arena.allocator(), "index {s}..{s} {s}", .{
                            a.oid_hex[0..7],
                            b.oid_hex[0..7],
                            mode.to_str(),
                        }));
                    } else {
                        try header_lines.append(try std.fmt.allocPrint(arena.allocator(), "index {s}..{s}", .{
                            a.oid_hex[0..7],
                            b.oid_hex[0..7],
                        }));
                    }

                    try header_lines.append(try std.fmt.allocPrint(arena.allocator(), "--- a/{s}", .{a.path}));

                    if (b.mode != null) {
                        try header_lines.append(try std.fmt.allocPrint(arena.allocator(), "+++ b/{s}", .{b.path}));
                    } else {
                        try header_lines.append("+++ /dev/null");
                    }

                    var diff = try MyersDiff.init(allocator, a.lines.items, b.lines.items);
                    defer diff.deinit();
                    const max_margin: usize = 3;
                    const DiffState = struct {
                        found_edit: bool,
                        margin: usize,
                        begin_idx: usize,
                        end_idx: usize,
                    };
                    var diff_state = DiffState{
                        .found_edit = false,
                        .margin = 0,
                        .begin_idx = 0,
                        .end_idx = 0,
                    };

                    for (diff.edits.items, 0..) |edit, i| {
                        diff_state.end_idx = i;

                        if (edit == .eql) {
                            diff_state.margin += 1;
                            if (diff_state.found_edit) {
                                // if the end margin isn't the max,
                                // keep adding to the hunk
                                if (diff_state.margin < max_margin) {
                                    if (i < diff.edits.items.len - 1) continue;
                                }
                            }
                            // if the begin margin is over the max,
                            // remove the first line (which is
                            // guaranteed to be an .eql edit)
                            else if (diff_state.margin > max_margin) {
                                diff_state.begin_idx += 1;
                                diff_state.margin -= 1;
                                if (i < diff.edits.items.len - 1) continue;
                            }
                        } else {
                            diff_state.found_edit = true;
                            diff_state.margin = 0;
                            if (i < diff.edits.items.len - 1) continue;
                        }

                        // if the diff state contains an actual edit
                        // (that is, one line whose op is not .eql)
                        if (diff_state.found_edit) {
                            var hunk = Hunk{
                                .edits = std.ArrayList(MyersDiff.Edit).init(arena.allocator()),
                            };
                            for (diff_state.begin_idx..diff_state.end_idx + 1) |edit_idx| {
                                try hunk.edits.append(diff.edits.items[edit_idx]);
                            }
                            try hunks.append(hunk);
                            diff_state.found_edit = false;
                            diff_state.margin = 0;
                            diff_state.end_idx += 1;
                            diff_state.begin_idx = diff_state.end_idx;
                        }
                    }
                }

                return .{
                    .path = a.path,
                    .header_lines = header_lines,
                    .hunks = hunks,
                    .arena = arena,
                    .target_a = a,
                    .target_b = b,
                };
            }

            pub fn deinit(self: *Diff) void {
                self.arena.deinit();
                self.target_a.deinit();
                self.target_b.deinit();
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
                        var a = try Target.initFromIndex(allocator, core, status.index.entries.get(entry.path) orelse return error.EntryNotFound);
                        errdefer a.deinit();
                        var b = try Target.initFromWorkspace(allocator, core, entry.path, io.getMode(entry.meta));
                        errdefer b.deinit();
                        try diffs.append(try Diff.init(allocator, a, b));
                    }

                    for (status.workspace_deleted.items) |path| {
                        var a = try Target.initFromIndex(allocator, core, status.index.entries.get(path) orelse return error.EntryNotFound);
                        errdefer a.deinit();
                        var b = try Target.initFromNothing(allocator, path);
                        errdefer b.deinit();
                        try diffs.append(try Diff.init(allocator, a, b));
                    }
                },
                .index => {
                    for (status.index_added.items) |path| {
                        var a = try Target.initFromNothing(allocator, path);
                        errdefer a.deinit();
                        var b = try Target.initFromIndex(allocator, core, status.index.entries.get(path) orelse return error.EntryNotFound);
                        errdefer b.deinit();
                        try diffs.append(try Diff.init(allocator, a, b));
                    }

                    for (status.index_modified.items) |path| {
                        var a = try Target.initFromHead(allocator, core, path, status.head_tree.entries.get(path) orelse return error.EntryNotFound);
                        errdefer a.deinit();
                        var b = try Target.initFromIndex(allocator, core, status.index.entries.get(path) orelse return error.EntryNotFound);
                        errdefer b.deinit();
                        try diffs.append(try Diff.init(allocator, a, b));
                    }

                    for (status.index_deleted.items) |path| {
                        var a = try Target.initFromHead(allocator, core, path, status.head_tree.entries.get(path) orelse return error.EntryNotFound);
                        errdefer a.deinit();
                        var b = try Target.initFromNothing(allocator, path);
                        errdefer b.deinit();
                        try diffs.append(try Diff.init(allocator, a, b));
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
