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
    edits: std.ArrayList(Edit), // TODO: turn into iterator

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

pub fn Target(comptime repo_kind: rp.RepoKind) type {
    return struct {
        allocator: std.mem.Allocator,
        path: []const u8,
        oid: [hash.SHA1_BYTES_LEN]u8,
        oid_hex: [hash.SHA1_HEX_LEN]u8,
        mode: ?io.Mode,
        // TODO: don't read it all into memory
        buffer: []u8,
        lines: std.ArrayList([]const u8),

        pub fn initFromIndex(allocator: std.mem.Allocator, core: *rp.Repo(repo_kind).Core, entry: idx.Index(repo_kind).Entry) !Target(repo_kind) {
            const oid_hex = std.fmt.bytesToHex(&entry.oid, .lower);
            var target = Target(repo_kind){
                .allocator = allocator,
                .path = entry.path,
                .oid = entry.oid,
                .oid_hex = oid_hex,
                .mode = entry.mode,
                .buffer = try allocator.alloc(u8, 1024),
                .lines = undefined,
            };
            const buf = try chk.objectToBuffer(repo_kind, core, oid_hex, target.buffer);

            var lines = std.ArrayList([]const u8).init(allocator);
            errdefer lines.deinit();
            var iter = std.mem.splitScalar(u8, buf, '\n');
            while (iter.next()) |line| {
                try lines.append(line);
            }
            target.lines = lines;

            return target;
        }

        pub fn initFromWorkspace(allocator: std.mem.Allocator, core: *rp.Repo(repo_kind).Core, path: []const u8, mode: io.Mode) !Target(repo_kind) {
            var target = Target(repo_kind){
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

        pub fn initFromNothing(allocator: std.mem.Allocator, path: []const u8) !Target(repo_kind) {
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

        pub fn initFromHead(allocator: std.mem.Allocator, core: *rp.Repo(repo_kind).Core, path: []const u8, entry: obj.TreeEntry) !Target(repo_kind) {
            const oid_hex = std.fmt.bytesToHex(&entry.oid, .lower);
            var target = Target(repo_kind){
                .allocator = allocator,
                .path = path,
                .oid = entry.oid,
                .oid_hex = oid_hex,
                .mode = entry.mode,
                .buffer = try allocator.alloc(u8, 1024),
                .lines = undefined,
            };
            const buf = try chk.objectToBuffer(repo_kind, core, oid_hex, target.buffer);

            var lines = std.ArrayList([]const u8).init(allocator);
            errdefer lines.deinit();
            var iter = std.mem.splitScalar(u8, buf, '\n');
            while (iter.next()) |line| {
                try lines.append(line);
            }
            target.lines = lines;

            return target;
        }

        pub fn deinit(self: *Target(repo_kind)) void {
            self.allocator.free(self.buffer);
            self.lines.deinit();
        }
    };
}

pub fn Diff(comptime repo_kind: rp.RepoKind) type {
    return struct {
        path: []const u8,
        header_lines: std.ArrayList([]const u8),
        myers_diff: ?MyersDiff,
        hunks: std.ArrayList(Hunk), // TODO: turn into iterator
        arena: std.heap.ArenaAllocator,
        target_a: Target(repo_kind),
        target_b: Target(repo_kind),

        pub const Hunk = struct {
            edits: []MyersDiff.Edit,

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
                for (self.edits) |edit| {
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

        pub fn init(allocator: std.mem.Allocator, a: Target(repo_kind), b: Target(repo_kind)) !Diff(repo_kind) {
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

            var diff = Diff(repo_kind){
                .path = a.path,
                .header_lines = header_lines,
                .myers_diff = null,
                .hunks = std.ArrayList(Hunk).init(arena.allocator()),
                .arena = arena,
                .target_a = a,
                .target_b = b,
            };

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

                var myers_diff = try MyersDiff.init(allocator, a.lines.items, b.lines.items);
                errdefer myers_diff.deinit();
                const max_margin: usize = 3;
                var found_edit = false;
                var margin: usize = 0;
                var begin_idx: usize = 0;
                var end_idx: usize = 0;

                for (myers_diff.edits.items, 0..) |edit, i| {
                    end_idx = i;

                    if (edit == .eql) {
                        margin += 1;
                        if (found_edit) {
                            // if the end margin isn't the max,
                            // keep adding to the hunk
                            if (margin < max_margin) {
                                if (i < myers_diff.edits.items.len - 1) continue;
                            }
                        }
                        // if the begin margin is over the max,
                        // remove the first line (which is
                        // guaranteed to be an eql edit)
                        else if (margin > max_margin) {
                            begin_idx += 1;
                            margin -= 1;
                            if (i < myers_diff.edits.items.len - 1) continue;
                        }
                    } else {
                        found_edit = true;
                        margin = 0;
                        if (i < myers_diff.edits.items.len - 1) continue;
                    }

                    // if the diff state contains an actual edit
                    // (that is, non-eql line)
                    if (found_edit) {
                        const hunk = Hunk{
                            .edits = myers_diff.edits.items[begin_idx .. end_idx + 1],
                        };
                        try diff.hunks.append(hunk);
                        found_edit = false;
                        margin = 0;
                        end_idx += 1;
                        begin_idx = end_idx;
                    }
                }

                diff.myers_diff = myers_diff;
            }

            return diff;
        }

        pub fn deinit(self: *Diff(repo_kind)) void {
            self.arena.deinit();
            if (self.myers_diff) |*myers_diff| {
                myers_diff.deinit();
            }
            self.target_a.deinit();
            self.target_b.deinit();
        }
    };
}

pub const DiffKind = enum {
    workspace,
    index,
};

pub fn DiffIterator(comptime repo_kind: rp.RepoKind) type {
    return struct {
        allocator: std.mem.Allocator,
        core: *rp.Repo(repo_kind).Core,
        diff_kind: DiffKind,
        status: st.Status(repo_kind),
        diff: Diff(repo_kind),
        next_index: usize,

        pub fn init(allocator: std.mem.Allocator, core: *rp.Repo(repo_kind).Core, diff_kind: DiffKind) !DiffIterator(repo_kind) {
            var status = try st.Status(repo_kind).init(allocator, core);
            errdefer status.deinit();
            return .{
                .allocator = allocator,
                .core = core,
                .diff_kind = diff_kind,
                .status = status,
                .diff = undefined,
                .next_index = 0,
            };
        }

        pub fn next(self: *DiffIterator(repo_kind)) !?*Diff(repo_kind) {
            var next_index = self.next_index;
            switch (self.diff_kind) {
                .workspace => {
                    if (next_index < self.status.workspace_modified.items.len) {
                        const entry = self.status.workspace_modified.items[next_index];
                        var a = try Target(repo_kind).initFromIndex(self.allocator, self.core, self.status.index.entries.get(entry.path) orelse return error.EntryNotFound);
                        errdefer a.deinit();
                        var b = try Target(repo_kind).initFromWorkspace(self.allocator, self.core, entry.path, io.getMode(entry.meta));
                        errdefer b.deinit();
                        self.diff = try Diff(repo_kind).init(self.allocator, a, b);
                        self.next_index += 1;
                        return &self.diff;
                    } else {
                        next_index -= self.status.workspace_modified.items.len;
                    }

                    if (next_index < self.status.workspace_deleted.items.len) {
                        const path = self.status.workspace_deleted.items[next_index];
                        var a = try Target(repo_kind).initFromIndex(self.allocator, self.core, self.status.index.entries.get(path) orelse return error.EntryNotFound);
                        errdefer a.deinit();
                        var b = try Target(repo_kind).initFromNothing(self.allocator, path);
                        errdefer b.deinit();
                        self.diff = try Diff(repo_kind).init(self.allocator, a, b);
                        self.next_index += 1;
                        return &self.diff;
                    }
                },
                .index => {
                    if (next_index < self.status.index_added.items.len) {
                        const path = self.status.index_added.items[next_index];
                        var a = try Target(repo_kind).initFromNothing(self.allocator, path);
                        errdefer a.deinit();
                        var b = try Target(repo_kind).initFromIndex(self.allocator, self.core, self.status.index.entries.get(path) orelse return error.EntryNotFound);
                        errdefer b.deinit();
                        self.diff = try Diff(repo_kind).init(self.allocator, a, b);
                        self.next_index += 1;
                        return &self.diff;
                    } else {
                        next_index -= self.status.index_added.items.len;
                    }

                    if (next_index < self.status.index_modified.items.len) {
                        const path = self.status.index_modified.items[next_index];
                        var a = try Target(repo_kind).initFromHead(self.allocator, self.core, path, self.status.head_tree.entries.get(path) orelse return error.EntryNotFound);
                        errdefer a.deinit();
                        var b = try Target(repo_kind).initFromIndex(self.allocator, self.core, self.status.index.entries.get(path) orelse return error.EntryNotFound);
                        errdefer b.deinit();
                        self.diff = try Diff(repo_kind).init(self.allocator, a, b);
                        self.next_index += 1;
                        return &self.diff;
                    } else {
                        next_index -= self.status.index_modified.items.len;
                    }

                    if (next_index < self.status.index_deleted.items.len) {
                        const path = self.status.index_deleted.items[next_index];
                        var a = try Target(repo_kind).initFromHead(self.allocator, self.core, path, self.status.head_tree.entries.get(path) orelse return error.EntryNotFound);
                        errdefer a.deinit();
                        var b = try Target(repo_kind).initFromNothing(self.allocator, path);
                        errdefer b.deinit();
                        self.diff = try Diff(repo_kind).init(self.allocator, a, b);
                        self.next_index += 1;
                        return &self.diff;
                    }
                },
            }

            return null;
        }

        pub fn deinit(self: *DiffIterator(repo_kind)) void {
            self.status.deinit();
        }
    };
}
