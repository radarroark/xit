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

pub fn LineIterator(comptime repo_kind: rp.RepoKind) type {
    return struct {
        allocator: std.mem.Allocator,
        path: []const u8,
        oid: [hash.SHA1_BYTES_LEN]u8,
        oid_hex: [hash.SHA1_HEX_LEN]u8,
        mode: ?io.Mode,
        buffer: []u8, // TODO: don't read it all into memory
        split_iter: std.mem.SplitIterator(u8, .scalar),

        pub fn initFromIndex(allocator: std.mem.Allocator, core_cursor: rp.Repo(repo_kind).CoreCursor, entry: idx.Index(repo_kind).Entry) !LineIterator(repo_kind) {
            const oid_hex = std.fmt.bytesToHex(&entry.oid, .lower);
            const buffer = try allocator.alloc(u8, 1024);
            errdefer allocator.free(buffer);
            const buf = try chk.objectToBuffer(repo_kind, core_cursor, oid_hex, buffer);

            return LineIterator(repo_kind){
                .allocator = allocator,
                .path = entry.path,
                .oid = entry.oid,
                .oid_hex = oid_hex,
                .mode = entry.mode,
                .buffer = buffer,
                .split_iter = std.mem.splitScalar(u8, buf, '\n'),
            };
        }

        pub fn initFromWorkspace(allocator: std.mem.Allocator, core_cursor: rp.Repo(repo_kind).CoreCursor, path: []const u8, mode: io.Mode) !LineIterator(repo_kind) {
            const buffer = try allocator.alloc(u8, 1024);
            errdefer allocator.free(buffer);

            var file = try core_cursor.core.repo_dir.openFile(path, .{ .mode = .read_only });
            defer file.close();
            const size = try file.reader().read(buffer);
            const buf = buffer[0..size];

            var line_iter = LineIterator(repo_kind){
                .allocator = allocator,
                .path = path,
                .oid = undefined,
                .oid_hex = undefined,
                .mode = mode,
                .buffer = buffer,
                .split_iter = std.mem.splitScalar(u8, buf, '\n'),
            };

            const file_size = (try file.metadata()).size();
            const header = try std.fmt.allocPrint(allocator, "blob {}\x00", .{file_size});
            defer allocator.free(header);
            try hash.sha1Reader(file.reader(), header, &line_iter.oid);
            line_iter.oid_hex = std.fmt.bytesToHex(&line_iter.oid, .lower);

            return line_iter;
        }

        pub fn initFromNothing(allocator: std.mem.Allocator, path: []const u8) !LineIterator(repo_kind) {
            const buffer = try allocator.alloc(u8, 0);
            errdefer allocator.free(buffer);
            return .{
                .allocator = allocator,
                .path = path,
                .oid = [_]u8{0} ** hash.SHA1_BYTES_LEN,
                .oid_hex = [_]u8{0} ** hash.SHA1_HEX_LEN,
                .mode = null,
                .buffer = buffer,
                .split_iter = std.mem.splitScalar(u8, buffer, '\n'),
            };
        }

        pub fn initFromHead(allocator: std.mem.Allocator, core_cursor: rp.Repo(repo_kind).CoreCursor, path: []const u8, entry: obj.TreeEntry) !LineIterator(repo_kind) {
            const oid_hex = std.fmt.bytesToHex(&entry.oid, .lower);
            const buffer = try allocator.alloc(u8, 1024);
            errdefer allocator.free(buffer);
            const buf = try chk.objectToBuffer(repo_kind, core_cursor, oid_hex, buffer);

            return LineIterator(repo_kind){
                .allocator = allocator,
                .path = path,
                .oid = entry.oid,
                .oid_hex = oid_hex,
                .mode = entry.mode,
                .buffer = buffer,
                .split_iter = std.mem.splitScalar(u8, buf, '\n'),
            };
        }

        pub fn next(self: *LineIterator(repo_kind)) ?[]const u8 {
            return self.split_iter.next();
        }

        pub fn deinit(self: *LineIterator(repo_kind)) void {
            self.allocator.free(self.buffer);
        }
    };
}

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

pub fn HunkIterator(comptime repo_kind: rp.RepoKind) type {
    return struct {
        path: []const u8,
        header_lines: std.ArrayList([]const u8),
        myers_diff_maybe: ?MyersDiff,
        arena: std.heap.ArenaAllocator,
        line_iter_a: LineIterator(repo_kind),
        line_iter_b: LineIterator(repo_kind),
        next_edit_index: usize,
        found_edit: bool,
        margin: usize,
        begin_index: usize,
        end_index: usize,

        pub fn init(allocator: std.mem.Allocator, a: *LineIterator(repo_kind), b: *LineIterator(repo_kind)) !HunkIterator(repo_kind) {
            var arena = std.heap.ArenaAllocator.init(allocator);
            errdefer arena.deinit();

            var header_lines = std.ArrayList([]const u8).init(arena.allocator());

            try header_lines.append(try std.fmt.allocPrint(arena.allocator(), "diff --git a/{s} b/{s}", .{ a.path, b.path }));

            var mode_maybe: ?io.Mode = null;

            if (a.mode) |a_mode| {
                if (b.mode) |b_mode| {
                    if (a_mode.unix_permission != b_mode.unix_permission) {
                        try header_lines.append(try std.fmt.allocPrint(arena.allocator(), "old mode {s}", .{a_mode.toStr()}));
                        try header_lines.append(try std.fmt.allocPrint(arena.allocator(), "new mode {s}", .{b_mode.toStr()}));
                    } else {
                        mode_maybe = a_mode;
                    }
                } else {
                    try header_lines.append(try std.fmt.allocPrint(arena.allocator(), "deleted file mode {s}", .{a_mode.toStr()}));
                }
            } else {
                if (b.mode) |b_mode| {
                    try header_lines.append(try std.fmt.allocPrint(arena.allocator(), "new file mode {s}", .{b_mode.toStr()}));
                }
            }

            var myers_diff_maybe: ?MyersDiff = null;

            if (!std.mem.eql(u8, &a.oid, &b.oid)) {
                if (mode_maybe) |mode| {
                    try header_lines.append(try std.fmt.allocPrint(arena.allocator(), "index {s}..{s} {s}", .{
                        a.oid_hex[0..7],
                        b.oid_hex[0..7],
                        mode.toStr(),
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

                var lines_a = std.ArrayList([]const u8).init(arena.allocator());
                while (a.next()) |line| {
                    try lines_a.append(line);
                }

                var lines_b = std.ArrayList([]const u8).init(arena.allocator());
                while (b.next()) |line| {
                    try lines_b.append(line);
                }

                myers_diff_maybe = try MyersDiff.init(allocator, lines_a.items, lines_b.items);
            }

            return HunkIterator(repo_kind){
                .path = a.path,
                .header_lines = header_lines,
                .myers_diff_maybe = myers_diff_maybe,
                .arena = arena,
                .line_iter_a = a.*,
                .line_iter_b = b.*,
                .next_edit_index = 0,
                .found_edit = false,
                .margin = 0,
                .begin_index = 0,
                .end_index = 0,
            };
        }

        pub fn next(self: *HunkIterator(repo_kind)) ?Hunk {
            const max_margin: usize = 3;
            const edit_index = self.next_edit_index;

            if (self.myers_diff_maybe) |myers_diff| {
                if (edit_index < myers_diff.edits.items.len) {
                    const edit = myers_diff.edits.items[edit_index];
                    self.end_index = edit_index;

                    if (edit == .eql) {
                        self.margin += 1;
                        if (self.found_edit) {
                            // if the end margin isn't the max,
                            // keep adding to the hunk
                            if (self.margin < max_margin) {
                                self.next_edit_index += 1;
                                if (edit_index < myers_diff.edits.items.len - 1) {
                                    return self.next();
                                }
                            }
                        }
                        // if the begin margin is over the max,
                        // remove the first line (which is
                        // guaranteed to be an eql edit)
                        else if (self.margin > max_margin) {
                            self.begin_index += 1;
                            self.margin -= 1;
                            self.next_edit_index += 1;
                            if (edit_index < myers_diff.edits.items.len - 1) {
                                return self.next();
                            }
                        }
                    } else {
                        self.found_edit = true;
                        self.margin = 0;
                        self.next_edit_index += 1;
                        if (edit_index < myers_diff.edits.items.len - 1) {
                            return self.next();
                        }
                    }

                    // if the diff state contains an actual edit
                    // (that is, non-eql line)
                    if (self.found_edit) {
                        const hunk = Hunk{
                            .edits = myers_diff.edits.items[self.begin_index .. self.end_index + 1],
                        };
                        self.found_edit = false;
                        self.margin = 0;
                        self.end_index += 1;
                        self.begin_index = self.end_index;
                        self.next_edit_index += 1;
                        return hunk;
                    } else {
                        self.next_edit_index += 1;
                        return self.next();
                    }
                }
            }

            return null;
        }

        pub fn deinit(self: *HunkIterator(repo_kind)) void {
            self.arena.deinit();
            if (self.myers_diff_maybe) |*myers_diff| {
                myers_diff.deinit();
            }
            self.line_iter_a.deinit();
            self.line_iter_b.deinit();
        }
    };
}

pub const DiffKind = enum {
    workspace,
    index,
};

pub const ConflictDiffKind = enum {
    common, // base
    current, // ours
    source, // theirs
};

pub fn DiffIterator(comptime repo_kind: rp.RepoKind) type {
    return struct {
        allocator: std.mem.Allocator,
        core: *rp.Repo(repo_kind).Core,
        diff_kind: DiffKind,
        conflict_diff_kind_maybe: ?ConflictDiffKind,
        status: st.Status(repo_kind),
        hunk_iter: HunkIterator(repo_kind),
        next_index: usize,

        pub fn init(
            allocator: std.mem.Allocator,
            core: *rp.Repo(repo_kind).Core,
            diff_kind: DiffKind,
            conflict_diff_kind_maybe: ?ConflictDiffKind,
            status: st.Status(repo_kind),
        ) !DiffIterator(repo_kind) {
            return .{
                .allocator = allocator,
                .core = core,
                .diff_kind = diff_kind,
                .conflict_diff_kind_maybe = conflict_diff_kind_maybe,
                .status = status,
                .hunk_iter = undefined,
                .next_index = 0,
            };
        }

        pub fn next(self: *DiffIterator(repo_kind)) !?*HunkIterator(repo_kind) {
            // TODO: instead of latest cursor, store the tx id so we always use the
            // same transaction even if the db is written to while calling next
            var cursor = try self.core.latestCursor();
            const core_cursor = switch (repo_kind) {
                .git => .{ .core = self.core },
                .xit => .{ .core = self.core, .cursor = &cursor },
            };
            var next_index = self.next_index;
            switch (self.diff_kind) {
                .workspace => {
                    if (self.conflict_diff_kind_maybe) |conflict_diff_kind| {
                        if (next_index < self.status.conflicts.count()) {
                            const path = self.status.conflicts.keys()[next_index];
                            const meta = try io.getMetadata(self.core.repo_dir, path);
                            const stage: usize = switch (conflict_diff_kind) {
                                .common => 1,
                                .current => 2,
                                .source => 3,
                            };
                            const index_entries_for_path = self.status.index.entries.get(path) orelse return error.EntryNotFound;
                            // if there is an entry for the stage we are diffing
                            if (index_entries_for_path[stage]) |index_entry| {
                                var a = try LineIterator(repo_kind).initFromIndex(self.allocator, core_cursor, index_entry);
                                errdefer a.deinit();
                                var b = switch (meta.kind()) {
                                    .file => try LineIterator(repo_kind).initFromWorkspace(self.allocator, core_cursor, path, io.getMode(meta)),
                                    // in file/dir conflicts, `path` may be a directory which can't be diffed, so just make it nothing
                                    else => try LineIterator(repo_kind).initFromNothing(self.allocator, path),
                                };
                                errdefer b.deinit();
                                self.hunk_iter = try HunkIterator(repo_kind).init(self.allocator, &a, &b);
                                self.next_index += 1;
                                return &self.hunk_iter;
                            }
                            // there is no entry, so just skip it and call this method recursively
                            else {
                                self.next_index += 1;
                                return try self.next();
                            }
                        } else {
                            next_index -= self.status.conflicts.count();
                        }
                    }

                    if (next_index < self.status.workspace_modified.items.len) {
                        const entry = self.status.workspace_modified.items[next_index];
                        const index_entries_for_path = self.status.index.entries.get(entry.path) orelse return error.EntryNotFound;
                        var a = try LineIterator(repo_kind).initFromIndex(self.allocator, core_cursor, index_entries_for_path[0] orelse return error.NullEntry);
                        errdefer a.deinit();
                        var b = try LineIterator(repo_kind).initFromWorkspace(self.allocator, core_cursor, entry.path, io.getMode(entry.meta));
                        errdefer b.deinit();
                        self.hunk_iter = try HunkIterator(repo_kind).init(self.allocator, &a, &b);
                        self.next_index += 1;
                        return &self.hunk_iter;
                    } else {
                        next_index -= self.status.workspace_modified.items.len;
                    }

                    if (next_index < self.status.workspace_deleted.items.len) {
                        const path = self.status.workspace_deleted.items[next_index];
                        const index_entries_for_path = self.status.index.entries.get(path) orelse return error.EntryNotFound;
                        var a = try LineIterator(repo_kind).initFromIndex(self.allocator, core_cursor, index_entries_for_path[0] orelse return error.NullEntry);
                        errdefer a.deinit();
                        var b = try LineIterator(repo_kind).initFromNothing(self.allocator, path);
                        errdefer b.deinit();
                        self.hunk_iter = try HunkIterator(repo_kind).init(self.allocator, &a, &b);
                        self.next_index += 1;
                        return &self.hunk_iter;
                    }
                },
                .index => {
                    if (next_index < self.status.index_added.items.len) {
                        const path = self.status.index_added.items[next_index];
                        var a = try LineIterator(repo_kind).initFromNothing(self.allocator, path);
                        errdefer a.deinit();
                        const index_entries_for_path = self.status.index.entries.get(path) orelse return error.EntryNotFound;
                        var b = try LineIterator(repo_kind).initFromIndex(self.allocator, core_cursor, index_entries_for_path[0] orelse return error.NullEntry);
                        errdefer b.deinit();
                        self.hunk_iter = try HunkIterator(repo_kind).init(self.allocator, &a, &b);
                        self.next_index += 1;
                        return &self.hunk_iter;
                    } else {
                        next_index -= self.status.index_added.items.len;
                    }

                    if (next_index < self.status.index_modified.items.len) {
                        const path = self.status.index_modified.items[next_index];
                        var a = try LineIterator(repo_kind).initFromHead(self.allocator, core_cursor, path, self.status.head_tree.entries.get(path) orelse return error.EntryNotFound);
                        errdefer a.deinit();
                        const index_entries_for_path = self.status.index.entries.get(path) orelse return error.EntryNotFound;
                        var b = try LineIterator(repo_kind).initFromIndex(self.allocator, core_cursor, index_entries_for_path[0] orelse return error.NullEntry);
                        errdefer b.deinit();
                        self.hunk_iter = try HunkIterator(repo_kind).init(self.allocator, &a, &b);
                        self.next_index += 1;
                        return &self.hunk_iter;
                    } else {
                        next_index -= self.status.index_modified.items.len;
                    }

                    if (next_index < self.status.index_deleted.items.len) {
                        const path = self.status.index_deleted.items[next_index];
                        var a = try LineIterator(repo_kind).initFromHead(self.allocator, core_cursor, path, self.status.head_tree.entries.get(path) orelse return error.EntryNotFound);
                        errdefer a.deinit();
                        var b = try LineIterator(repo_kind).initFromNothing(self.allocator, path);
                        errdefer b.deinit();
                        self.hunk_iter = try HunkIterator(repo_kind).init(self.allocator, &a, &b);
                        self.next_index += 1;
                        return &self.hunk_iter;
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
