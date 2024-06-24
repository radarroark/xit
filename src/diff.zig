const std = @import("std");
const rp = @import("./repo.zig");
const st = @import("./status.zig");
const hash = @import("./hash.zig");
const io = @import("./io.zig");
const idx = @import("./index.zig");
const obj = @import("./object.zig");
const chk = @import("./checkout.zig");

const MAX_READ_BYTES = 1024; // FIXME: this is arbitrary...

pub fn LineIterator(comptime repo_kind: rp.RepoKind) type {
    return struct {
        allocator: std.mem.Allocator,
        path: []const u8,
        oid: [hash.SHA1_BYTES_LEN]u8,
        oid_hex: [hash.SHA1_HEX_LEN]u8,
        mode: ?io.Mode,
        next_line: usize,
        source: union(enum) {
            object: struct {
                object_reader: obj.ObjectReader(repo_kind),
                eof: bool,
            },
            workspace: struct {
                file: std.fs.File,
                eof: bool,
            },
            buffer: struct {
                iter: std.mem.SplitIterator(u8, .scalar),
            },
            nothing,
        },

        pub fn initFromIndex(core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator, entry: idx.Index(repo_kind).Entry) !LineIterator(repo_kind) {
            const oid_hex = std.fmt.bytesToHex(&entry.oid, .lower);
            var object_reader = try obj.ObjectReader(repo_kind).init(core_cursor, oid_hex, true);
            errdefer object_reader.deinit();
            return LineIterator(repo_kind){
                .allocator = allocator,
                .path = entry.path,
                .oid = entry.oid,
                .oid_hex = oid_hex,
                .mode = entry.mode,
                .next_line = 0,
                .source = .{
                    .object = .{
                        .object_reader = object_reader,
                        .eof = false,
                    },
                },
            };
        }

        pub fn initFromWorkspace(core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator, path: []const u8, mode: io.Mode) !LineIterator(repo_kind) {
            var file = try core_cursor.core.repo_dir.openFile(path, .{ .mode = .read_only });
            errdefer file.close();

            const file_size = (try file.metadata()).size();
            const header = try std.fmt.allocPrint(allocator, "blob {}\x00", .{file_size});
            defer allocator.free(header);
            var oid = [_]u8{0} ** hash.SHA1_BYTES_LEN;
            try hash.sha1Reader(file.reader(), header, &oid);
            try file.seekTo(0);

            return LineIterator(repo_kind){
                .allocator = allocator,
                .path = path,
                .oid = oid,
                .oid_hex = std.fmt.bytesToHex(&oid, .lower),
                .mode = mode,
                .next_line = 0,
                .source = .{
                    .workspace = .{
                        .file = file,
                        .eof = false,
                    },
                },
            };
        }

        pub fn initFromNothing(allocator: std.mem.Allocator, path: []const u8) !LineIterator(repo_kind) {
            return .{
                .allocator = allocator,
                .path = path,
                .oid = [_]u8{0} ** hash.SHA1_BYTES_LEN,
                .oid_hex = [_]u8{0} ** hash.SHA1_HEX_LEN,
                .mode = null,
                .next_line = 0,
                .source = .nothing,
            };
        }

        pub fn initFromHead(core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator, path: []const u8, entry: obj.TreeEntry) !LineIterator(repo_kind) {
            const oid_hex = std.fmt.bytesToHex(&entry.oid, .lower);
            var object_reader = try obj.ObjectReader(repo_kind).init(core_cursor, oid_hex, true);
            errdefer object_reader.deinit();
            return LineIterator(repo_kind){
                .allocator = allocator,
                .path = path,
                .oid = entry.oid,
                .oid_hex = oid_hex,
                .mode = entry.mode,
                .next_line = 0,
                .source = .{
                    .object = .{
                        .object_reader = object_reader,
                        .eof = false,
                    },
                },
            };
        }

        pub fn initFromOid(core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator, oid: [hash.SHA1_BYTES_LEN]u8) !LineIterator(repo_kind) {
            const oid_hex = std.fmt.bytesToHex(&oid, .lower);
            var object_reader = try obj.ObjectReader(repo_kind).init(core_cursor, oid_hex, true);
            errdefer object_reader.deinit();
            return LineIterator(repo_kind){
                .allocator = allocator,
                .path = "",
                .oid = oid,
                .oid_hex = oid_hex,
                .mode = null,
                .next_line = 0,
                .source = .{
                    .object = .{
                        .object_reader = object_reader,
                        .eof = false,
                    },
                },
            };
        }

        pub fn initFromBuffer(allocator: std.mem.Allocator, buffer: []const u8) !LineIterator(repo_kind) {
            return .{
                .allocator = allocator,
                .path = "",
                .oid = [_]u8{0} ** hash.SHA1_BYTES_LEN,
                .oid_hex = [_]u8{0} ** hash.SHA1_HEX_LEN,
                .mode = null,
                .next_line = 0,
                .source = .{
                    .buffer = .{
                        .iter = std.mem.splitScalar(u8, buffer, '\n'),
                    },
                },
            };
        }

        pub fn next(self: *LineIterator(repo_kind)) !?[]const u8 {
            switch (self.source) {
                .object => {
                    if (self.source.object.eof) {
                        return null;
                    }
                    var line_arr = std.ArrayList(u8).init(self.allocator);
                    errdefer line_arr.deinit();
                    var buffer = [_]u8{0} ** 1;
                    while (true) {
                        const size = try self.source.object.object_reader.reader().read(&buffer);
                        if (size == 0) {
                            self.source.object.eof = true;
                            break;
                        } else if (buffer[0] == '\n') {
                            break;
                        } else {
                            if (line_arr.items.len == MAX_READ_BYTES) {
                                return error.StreamTooLong;
                            }
                            try line_arr.append(buffer[0]);
                        }
                    }
                    self.next_line += 1;
                    return try line_arr.toOwnedSlice();
                },
                .workspace => {
                    if (self.source.workspace.eof) {
                        return null;
                    }
                    var line_arr = std.ArrayList(u8).init(self.allocator);
                    errdefer line_arr.deinit();
                    self.source.workspace.file.reader().streamUntilDelimiter(line_arr.writer(), '\n', MAX_READ_BYTES) catch |err| switch (err) {
                        error.EndOfStream => self.source.workspace.eof = true,
                        else => return err,
                    };
                    self.next_line += 1;
                    return try line_arr.toOwnedSlice();
                },
                .nothing => return null,
                .buffer => {
                    if (self.source.buffer.iter.next()) |line| {
                        const line_copy = try self.allocator.alloc(u8, line.len);
                        errdefer self.allocator.free(line_copy);
                        @memcpy(line_copy, line);
                        self.next_line += 1;
                        return line_copy;
                    } else {
                        return null;
                    }
                },
            }
        }

        pub fn get(self: *LineIterator(repo_kind), index: usize) !?[]const u8 {
            // TODO: cache result so we don't have to scan the file every time

            // if we don't happen to be on the correct line, restart from the beginning
            if (self.next_line != index) {
                try self.reset();
            }

            while (try self.next()) |line| {
                if (self.next_line == index + 1) {
                    errdefer self.allocator.free(line);
                    return line;
                } else {
                    defer self.allocator.free(line);
                }
            }
            return null;
        }

        pub fn reset(self: *LineIterator(repo_kind)) !void {
            self.next_line = 0;
            switch (self.source) {
                .object => {
                    self.source.object.eof = false;
                    try self.source.object.object_reader.reset();
                },
                .workspace => {
                    self.source.workspace.eof = false;
                    try self.source.workspace.file.seekTo(0);
                },
                .nothing => {},
                .buffer => self.source.buffer.iter.reset(),
            }
        }

        pub fn count(self: *LineIterator(repo_kind)) !usize {
            try self.reset();
            var n: usize = 0;
            while (try self.next()) |line| {
                defer self.allocator.free(line);
                n += 1;
            }
            return n;
        }

        pub fn deinit(self: *LineIterator(repo_kind)) void {
            switch (self.source) {
                .object => {},
                .workspace => self.source.workspace.file.close(),
                .nothing => {},
                .buffer => {},
            }
        }
    };
}

pub fn MyersDiffIterator(comptime repo_kind: rp.RepoKind) type {
    return struct {
        allocator: std.mem.Allocator,
        backtrack: std.ArrayList([4]isize),
        line_iter_a: *LineIterator(repo_kind),
        line_iter_b: *LineIterator(repo_kind),
        line_count_a: usize,
        line_count_b: usize,
        next_index: usize,

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

            pub fn deinit(self: Edit, allocator: std.mem.Allocator) void {
                switch (self) {
                    .eql => {
                        allocator.free(self.eql.old_line.text);
                        allocator.free(self.eql.new_line.text);
                    },
                    .ins => allocator.free(self.ins.new_line.text),
                    .del => allocator.free(self.del.old_line.text),
                }
            }
        };

        pub fn init(allocator: std.mem.Allocator, line_iter_a: *LineIterator(repo_kind), line_iter_b: *LineIterator(repo_kind)) !MyersDiffIterator(repo_kind) {
            var trace = std.ArrayList(std.ArrayList(isize)).init(allocator);
            defer {
                for (trace.items) |*arr| {
                    arr.deinit();
                }
                trace.deinit();
            }

            const line_count_a = try line_iter_a.count();
            const line_count_b = try line_iter_b.count();

            {
                const max = line_count_a + line_count_b;
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
                        while (true) {
                            if (xx < line_count_a and yy < line_count_b) {
                                const line_a = (try line_iter_a.get(absIndex(xx, line_count_a))) orelse return error.ExpectedLine;
                                defer allocator.free(line_a);
                                const line_b = (try line_iter_b.get(absIndex(yy, line_count_b))) orelse return error.ExpectedLine;
                                defer allocator.free(line_b);
                                if (std.mem.eql(u8, line_a, line_b)) {
                                    xx += 1;
                                    yy += 1;
                                    continue;
                                }
                            }
                            break;
                        }
                        v.items[absIndex(kk, v.items.len)] = xx;
                        if (xx >= line_count_a and yy >= line_count_b) {
                            break :blk;
                        }
                    }
                }
            }

            var backtrack = std.ArrayList([4]isize).init(allocator);
            errdefer backtrack.deinit();
            {
                var xx: isize = @intCast(line_count_a);
                var yy: isize = @intCast(line_count_b);
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

            return MyersDiffIterator(repo_kind){
                .allocator = allocator,
                .backtrack = backtrack,
                .line_iter_a = line_iter_a,
                .line_iter_b = line_iter_b,
                .line_count_a = line_count_a,
                .line_count_b = line_count_b,
                .next_index = 0,
            };
        }

        pub fn next(self: *MyersDiffIterator(repo_kind)) !?Edit {
            if (self.next_index == self.backtrack.items.len) {
                return null;
            }

            const i = self.next_index;
            const backtrack_index = self.backtrack.items.len - i - 1;
            self.next_index += 1;

            const edit = self.backtrack.items[backtrack_index];
            const prev_xx = edit[0];
            const prev_yy = edit[1];
            const xx = edit[2];
            const yy = edit[3];

            if (xx == prev_xx) {
                const new_idx = absIndex(prev_yy, self.line_count_b);
                const line_b = (try self.line_iter_b.get(new_idx)) orelse return error.ExpectedLine;
                errdefer self.allocator.free(line_b);
                return .{
                    .ins = .{
                        .new_line = .{ .num = new_idx + 1, .text = line_b },
                    },
                };
            } else if (yy == prev_yy) {
                const old_idx = absIndex(prev_xx, self.line_count_a);
                const line_a = (try self.line_iter_a.get(old_idx)) orelse return error.ExpectedLine;
                errdefer self.allocator.free(line_a);
                return .{
                    .del = .{
                        .old_line = .{ .num = old_idx + 1, .text = line_a },
                    },
                };
            } else {
                const old_idx = absIndex(prev_xx, self.line_count_a);
                const new_idx = absIndex(prev_yy, self.line_count_b);
                const line_a = (try self.line_iter_a.get(old_idx)) orelse return error.ExpectedLine;
                errdefer self.allocator.free(line_a);
                const line_b = (try self.line_iter_b.get(new_idx)) orelse return error.ExpectedLine;
                errdefer self.allocator.free(line_b);
                return .{
                    .eql = .{
                        .old_line = .{ .num = old_idx + 1, .text = line_a },
                        .new_line = .{ .num = new_idx + 1, .text = line_b },
                    },
                };
            }
        }

        pub fn get(self: *MyersDiffIterator(repo_kind), old_line: usize) !?usize {
            // TODO: cache result so we don't have to scan the file every time
            try self.reset();
            while (try self.next()) |edit| {
                defer edit.deinit(self.allocator);
                if (.eql == edit) {
                    if (edit.eql.old_line.num < old_line) {
                        continue;
                    } else if (edit.eql.old_line.num == old_line) {
                        return edit.eql.new_line.num;
                    } else {
                        break;
                    }
                }
            }
            return null;
        }

        pub fn contains(self: *MyersDiffIterator(repo_kind), old_line: usize) !bool {
            if (try self.get(old_line)) |_| {
                return true;
            } else {
                return false;
            }
        }

        pub fn reset(self: *MyersDiffIterator(repo_kind)) !void {
            try self.line_iter_a.reset();
            try self.line_iter_b.reset();
            self.next_index = 0;
        }

        pub fn deinit(self: *MyersDiffIterator(repo_kind)) void {
            self.backtrack.deinit();
        }

        fn absIndex(i: isize, len: usize) usize {
            return if (i < 0) len - @abs(i) else @intCast(i);
        }
    };
}

test "myers diff" {
    const repo_kind = rp.RepoKind.xit;
    const allocator = std.testing.allocator;
    {
        const lines1 = "A\nB\nC\nA\nB\nB\nA";
        const lines2 = "C\nB\nA\nB\nA\nC";
        var line_iter1 = try LineIterator(repo_kind).initFromBuffer(allocator, lines1);
        defer line_iter1.deinit();
        var line_iter2 = try LineIterator(repo_kind).initFromBuffer(allocator, lines2);
        defer line_iter2.deinit();
        const expected_diff = [_]MyersDiffIterator(repo_kind).Edit{
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
        var myers_diff_iter = try MyersDiffIterator(repo_kind).init(allocator, &line_iter1, &line_iter2);
        defer myers_diff_iter.deinit();
        var actual_diff = std.ArrayList(MyersDiffIterator(repo_kind).Edit).init(allocator);
        defer {
            for (actual_diff.items) |edit| {
                edit.deinit(allocator);
            }
            actual_diff.deinit();
        }
        while (try myers_diff_iter.next()) |edit| {
            try actual_diff.append(edit);
        }
        try std.testing.expectEqual(expected_diff.len, actual_diff.items.len);
        for (expected_diff, actual_diff.items) |expected, actual| {
            try std.testing.expectEqualDeep(expected, actual);
        }
    }
    {
        const lines1 = "hello, world!";
        const lines2 = "goodbye, world!";
        var line_iter1 = try LineIterator(repo_kind).initFromBuffer(allocator, lines1);
        defer line_iter1.deinit();
        var line_iter2 = try LineIterator(repo_kind).initFromBuffer(allocator, lines2);
        defer line_iter2.deinit();
        const expected_diff = [_]MyersDiffIterator(repo_kind).Edit{
            .{ .del = .{ .old_line = .{ .num = 1, .text = "hello, world!" } } },
            .{ .ins = .{ .new_line = .{ .num = 1, .text = "goodbye, world!" } } },
        };
        var myers_diff_iter = try MyersDiffIterator(repo_kind).init(allocator, &line_iter1, &line_iter2);
        defer myers_diff_iter.deinit();
        var actual_diff = std.ArrayList(MyersDiffIterator(repo_kind).Edit).init(allocator);
        defer {
            for (actual_diff.items) |edit| {
                edit.deinit(allocator);
            }
            actual_diff.deinit();
        }
        while (try myers_diff_iter.next()) |edit| {
            try actual_diff.append(edit);
        }
        try std.testing.expectEqual(expected_diff.len, actual_diff.items.len);
        for (expected_diff, actual_diff.items) |expected, actual| {
            try std.testing.expectEqualDeep(expected, actual);
        }
    }
}

pub fn Diff3Iterator(comptime repo_kind: rp.RepoKind) type {
    return struct {
        line_count_o: usize,
        line_count_a: usize,
        line_count_b: usize,
        line_o: usize,
        line_a: usize,
        line_b: usize,
        myers_diff_iter_a: MyersDiffIterator(repo_kind),
        myers_diff_iter_b: MyersDiffIterator(repo_kind),
        finished: bool,

        pub const Range = struct {
            begin: usize,
            end: usize,
        };

        pub const Chunk = union(enum) {
            clean: Range,
            conflict: struct {
                o_range: ?Range,
                a_range: ?Range,
                b_range: ?Range,
            },
        };

        pub fn init(
            allocator: std.mem.Allocator,
            line_iter_o: *LineIterator(repo_kind),
            line_iter_a: *LineIterator(repo_kind),
            line_iter_b: *LineIterator(repo_kind),
        ) !Diff3Iterator(repo_kind) {
            var myers_diff_iter_a = try MyersDiffIterator(repo_kind).init(allocator, line_iter_o, line_iter_a);
            errdefer myers_diff_iter_a.deinit();
            var myers_diff_iter_b = try MyersDiffIterator(repo_kind).init(allocator, line_iter_o, line_iter_b);
            errdefer myers_diff_iter_b.deinit();
            return .{
                .line_count_o = try line_iter_o.count(),
                .line_count_a = try line_iter_a.count(),
                .line_count_b = try line_iter_b.count(),
                .line_o = 0,
                .line_a = 0,
                .line_b = 0,
                .myers_diff_iter_a = myers_diff_iter_a,
                .myers_diff_iter_b = myers_diff_iter_b,
                .finished = false,
            };
        }

        pub fn next(self: *Diff3Iterator(repo_kind)) !?Chunk {
            if (self.finished) {
                return null;
            }

            // find next mismatch
            var i: usize = 1;
            while (self.inBounds(i) and
                try self.isMatch(&self.myers_diff_iter_a, self.line_a, i) and
                try self.isMatch(&self.myers_diff_iter_b, self.line_b, i))
            {
                i += 1;
            }

            if (self.inBounds(i)) {
                if (i == 1) {
                    // find next match
                    var o = self.line_o + 1;
                    while (o <= self.line_count_o and (!(try self.myers_diff_iter_a.contains(o)) or !(try self.myers_diff_iter_b.contains(o)))) {
                        o += 1;
                    }
                    if (try self.myers_diff_iter_a.get(o)) |a| {
                        if (try self.myers_diff_iter_b.get(o)) |b| {
                            // return mismatching chunk
                            const line_o = self.line_o;
                            const line_a = self.line_a;
                            const line_b = self.line_b;
                            self.line_o = o - 1;
                            self.line_a = a - 1;
                            self.line_b = b - 1;
                            return chunk(
                                lineRange(line_o, self.line_o),
                                lineRange(line_a, self.line_a),
                                lineRange(line_b, self.line_b),
                                false,
                            );
                        }
                    }
                } else {
                    // return matching chunk
                    const line_o = self.line_o;
                    const line_a = self.line_a;
                    const line_b = self.line_b;
                    self.line_o += i - 1;
                    self.line_a += i - 1;
                    self.line_b += i - 1;
                    return chunk(
                        lineRange(line_o, self.line_o),
                        lineRange(line_a, self.line_a),
                        lineRange(line_b, self.line_b),
                        true,
                    );
                }
            }

            // return final chunk
            self.finished = true;
            return chunk(
                lineRange(self.line_o, self.line_count_o),
                lineRange(self.line_a, self.line_count_a),
                lineRange(self.line_b, self.line_count_b),
                i > 1,
            );
        }

        pub fn reset(self: *Diff3Iterator(repo_kind)) !void {
            self.line_o = 0;
            self.line_a = 0;
            self.line_b = 0;
            try self.myers_diff_iter_a.reset();
            try self.myers_diff_iter_b.reset();
            self.finished = false;
        }

        pub fn deinit(self: *Diff3Iterator(repo_kind)) void {
            self.myers_diff_iter_a.deinit();
            self.myers_diff_iter_b.deinit();
        }

        fn inBounds(self: Diff3Iterator(repo_kind), i: usize) bool {
            return self.line_o + i <= self.line_count_o or
                self.line_a + i <= self.line_count_a or
                self.line_b + i <= self.line_count_b;
        }

        fn isMatch(self: Diff3Iterator(repo_kind), myers_diff_iter: *MyersDiffIterator(repo_kind), offset: usize, i: usize) !bool {
            if (try myers_diff_iter.get(self.line_o + i)) |line_num| {
                return line_num == offset + i;
            } else {
                return false;
            }
        }

        fn lineRange(begin: usize, end: usize) ?Range {
            if (end > begin) {
                return .{ .begin = begin, .end = end };
            } else {
                return null;
            }
        }

        fn chunk(o_range_maybe: ?Range, a_range_maybe: ?Range, b_range_maybe: ?Range, match: bool) ?Chunk {
            if (match) {
                return .{
                    .clean = o_range_maybe orelse return null,
                };
            } else {
                return .{
                    .conflict = .{
                        .o_range = o_range_maybe,
                        .a_range = a_range_maybe,
                        .b_range = b_range_maybe,
                    },
                };
            }
        }
    };
}

test "diff3" {
    const repo_kind = rp.RepoKind.xit;
    const allocator = std.testing.allocator;

    const orig_lines =
        \\celery
        \\garlic
        \\onions
        \\salmon
        \\tomatoes
        \\wine
    ;
    const alice_lines =
        \\celery
        \\salmon
        \\tomatoes
        \\garlic
        \\onions
        \\wine
        \\beer
    ;
    const bob_lines =
        \\celery
        \\salmon
        \\garlic
        \\onions
        \\tomatoes
        \\wine
        \\beer
    ;

    var orig_iter = try LineIterator(repo_kind).initFromBuffer(allocator, orig_lines);
    defer orig_iter.deinit();
    var alice_iter = try LineIterator(repo_kind).initFromBuffer(allocator, alice_lines);
    defer alice_iter.deinit();
    var bob_iter = try LineIterator(repo_kind).initFromBuffer(allocator, bob_lines);
    defer bob_iter.deinit();
    var diff3_iter = try Diff3Iterator(repo_kind).init(allocator, &orig_iter, &alice_iter, &bob_iter);
    defer diff3_iter.deinit();

    var chunk = (try diff3_iter.next()) orelse return error.ExpectedChunk;
    try std.testing.expect(.clean == chunk);

    chunk = (try diff3_iter.next()) orelse return error.ExpectedChunk;
    try std.testing.expect(.conflict == chunk);

    chunk = (try diff3_iter.next()) orelse return error.ExpectedChunk;
    try std.testing.expect(.clean == chunk);

    chunk = (try diff3_iter.next()) orelse return error.ExpectedChunk;
    try std.testing.expect(.conflict == chunk);

    chunk = (try diff3_iter.next()) orelse return error.ExpectedChunk;
    try std.testing.expect(.clean == chunk);

    // this is a conflict even though a and b are both "beer",
    // because the original does not contain it.
    // it is only marked as clean if all three are matches.
    // when outputting the conflict lines this should be
    // auto-resolved since we can compare a and b at that point.
    chunk = (try diff3_iter.next()) orelse return error.ExpectedChunk;
    try std.testing.expect(.conflict == chunk);

    try std.testing.expect(null == try diff3_iter.next());
}

pub fn Hunk(comptime repo_kind: rp.RepoKind) type {
    return struct {
        edits: std.ArrayList(MyersDiffIterator(repo_kind).Edit),
        allocator: std.mem.Allocator,

        pub fn deinit(self: *Hunk(repo_kind)) void {
            for (self.edits.items) |edit| {
                edit.deinit(self.allocator);
            }
            self.edits.deinit();
        }

        pub const Offsets = struct {
            del_start: usize,
            del_count: usize,
            ins_start: usize,
            ins_count: usize,
        };

        pub fn offsets(self: Hunk(repo_kind)) Offsets {
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
}

pub fn HunkIterator(comptime repo_kind: rp.RepoKind) type {
    return struct {
        path: []const u8,
        header_lines: std.ArrayList([]const u8),
        myers_diff_maybe: ?MyersDiffIterator(repo_kind),
        allocator: std.mem.Allocator,
        arena: std.heap.ArenaAllocator,
        line_iter_a: LineIterator(repo_kind),
        line_iter_b: LineIterator(repo_kind),
        found_edit: bool,
        margin: usize,
        next_hunk: Hunk(repo_kind),

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

            var myers_diff_maybe: ?MyersDiffIterator(repo_kind) = null;

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

                myers_diff_maybe = try MyersDiffIterator(repo_kind).init(allocator, a, b);
            }

            return HunkIterator(repo_kind){
                .path = a.path,
                .header_lines = header_lines,
                .myers_diff_maybe = myers_diff_maybe,
                .allocator = allocator,
                .arena = arena,
                .line_iter_a = a.*,
                .line_iter_b = b.*,
                .found_edit = false,
                .margin = 0,
                .next_hunk = Hunk(repo_kind){
                    .edits = std.ArrayList(MyersDiffIterator(repo_kind).Edit).init(allocator),
                    .allocator = allocator,
                },
            };
        }

        pub fn next(self: *HunkIterator(repo_kind)) !?Hunk(repo_kind) {
            const max_margin: usize = 3;

            if (self.myers_diff_maybe) |*myers_diff| {
                while (true) {
                    if (try myers_diff.next()) |edit| {
                        errdefer edit.deinit(self.allocator);
                        try self.next_hunk.edits.append(edit);

                        if (edit == .eql) {
                            self.margin += 1;
                            if (self.found_edit) {
                                // if the end margin isn't the max,
                                // keep adding to the hunk
                                if (self.margin < max_margin) {
                                    continue;
                                }
                            }
                            // if the begin margin is over the max,
                            // remove the first line (which is
                            // guaranteed to be an eql edit)
                            else if (self.margin > max_margin) {
                                const removed_edit = self.next_hunk.edits.orderedRemove(0);
                                removed_edit.deinit(self.allocator);
                                self.margin -= 1;
                                continue;
                            }
                        } else {
                            self.found_edit = true;
                            self.margin = 0;
                            continue;
                        }

                        // if the diff state contains an actual edit
                        // (that is, non-eql line)
                        if (self.found_edit) {
                            const hunk = self.next_hunk;
                            self.next_hunk = Hunk(repo_kind){
                                .edits = std.ArrayList(MyersDiffIterator(repo_kind).Edit).init(self.allocator),
                                .allocator = self.allocator,
                            };
                            self.found_edit = false;
                            self.margin = 0;
                            return hunk;
                        } else {
                            continue;
                        }
                    } else {
                        // nullify the myers diff iterator so next() returns null afterwards
                        myers_diff.deinit();
                        self.myers_diff_maybe = null;
                        // return last hunk
                        const hunk = self.next_hunk;
                        self.next_hunk = Hunk(repo_kind){
                            .edits = std.ArrayList(MyersDiffIterator(repo_kind).Edit).init(self.allocator),
                            .allocator = self.allocator,
                        };
                        self.found_edit = false;
                        self.margin = 0;
                        return hunk;
                    }
                }
            } else {
                return null;
            }
        }

        pub fn deinit(self: *HunkIterator(repo_kind)) void {
            self.arena.deinit();
            if (self.myers_diff_maybe) |*myers_diff| {
                myers_diff.deinit();
            }
            self.line_iter_a.deinit();
            self.line_iter_b.deinit();
            self.next_hunk.deinit();
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

pub fn FileIterator(comptime repo_kind: rp.RepoKind) type {
    return struct {
        allocator: std.mem.Allocator,
        core: *rp.Repo(repo_kind).Core,
        diff_kind: DiffKind,
        conflict_diff_kind: ConflictDiffKind,
        status: st.Status(repo_kind),
        next_index: usize,

        pub fn init(
            allocator: std.mem.Allocator,
            core: *rp.Repo(repo_kind).Core,
            diff_kind: DiffKind,
            conflict_diff_kind: ConflictDiffKind,
            status: st.Status(repo_kind),
        ) !FileIterator(repo_kind) {
            return .{
                .allocator = allocator,
                .core = core,
                .diff_kind = diff_kind,
                .conflict_diff_kind = conflict_diff_kind,
                .status = status,
                .next_index = 0,
            };
        }

        pub fn next(self: *FileIterator(repo_kind)) !?HunkIterator(repo_kind) {
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
                    if (next_index < self.status.conflicts.count()) {
                        const path = self.status.conflicts.keys()[next_index];
                        const meta = try io.getMetadata(self.core.repo_dir, path);
                        const stage: usize = switch (self.conflict_diff_kind) {
                            .common => 1,
                            .current => 2,
                            .source => 3,
                        };
                        const index_entries_for_path = self.status.index.entries.get(path) orelse return error.EntryNotFound;
                        // if there is an entry for the stage we are diffing
                        if (index_entries_for_path[stage]) |index_entry| {
                            var a = try LineIterator(repo_kind).initFromIndex(core_cursor, self.allocator, index_entry);
                            errdefer a.deinit();
                            var b = switch (meta.kind()) {
                                .file => try LineIterator(repo_kind).initFromWorkspace(core_cursor, self.allocator, path, io.getMode(meta)),
                                // in file/dir conflicts, `path` may be a directory which can't be diffed, so just make it nothing
                                else => try LineIterator(repo_kind).initFromNothing(self.allocator, path),
                            };
                            errdefer b.deinit();
                            self.next_index += 1;
                            return try HunkIterator(repo_kind).init(self.allocator, &a, &b);
                        }
                        // there is no entry, so just skip it and call this method recursively
                        else {
                            self.next_index += 1;
                            return try self.next();
                        }
                    } else {
                        next_index -= self.status.conflicts.count();
                    }

                    if (next_index < self.status.workspace_modified.items.len) {
                        const entry = self.status.workspace_modified.items[next_index];
                        const index_entries_for_path = self.status.index.entries.get(entry.path) orelse return error.EntryNotFound;
                        var a = try LineIterator(repo_kind).initFromIndex(core_cursor, self.allocator, index_entries_for_path[0] orelse return error.NullEntry);
                        errdefer a.deinit();
                        var b = try LineIterator(repo_kind).initFromWorkspace(core_cursor, self.allocator, entry.path, io.getMode(entry.meta));
                        errdefer b.deinit();
                        self.next_index += 1;
                        return try HunkIterator(repo_kind).init(self.allocator, &a, &b);
                    } else {
                        next_index -= self.status.workspace_modified.items.len;
                    }

                    if (next_index < self.status.workspace_deleted.items.len) {
                        const path = self.status.workspace_deleted.items[next_index];
                        const index_entries_for_path = self.status.index.entries.get(path) orelse return error.EntryNotFound;
                        var a = try LineIterator(repo_kind).initFromIndex(core_cursor, self.allocator, index_entries_for_path[0] orelse return error.NullEntry);
                        errdefer a.deinit();
                        var b = try LineIterator(repo_kind).initFromNothing(self.allocator, path);
                        errdefer b.deinit();
                        self.next_index += 1;
                        return try HunkIterator(repo_kind).init(self.allocator, &a, &b);
                    }
                },
                .index => {
                    if (next_index < self.status.index_added.items.len) {
                        const path = self.status.index_added.items[next_index];
                        var a = try LineIterator(repo_kind).initFromNothing(self.allocator, path);
                        errdefer a.deinit();
                        const index_entries_for_path = self.status.index.entries.get(path) orelse return error.EntryNotFound;
                        var b = try LineIterator(repo_kind).initFromIndex(core_cursor, self.allocator, index_entries_for_path[0] orelse return error.NullEntry);
                        errdefer b.deinit();
                        self.next_index += 1;
                        return try HunkIterator(repo_kind).init(self.allocator, &a, &b);
                    } else {
                        next_index -= self.status.index_added.items.len;
                    }

                    if (next_index < self.status.index_modified.items.len) {
                        const path = self.status.index_modified.items[next_index];
                        var a = try LineIterator(repo_kind).initFromHead(core_cursor, self.allocator, path, self.status.head_tree.entries.get(path) orelse return error.EntryNotFound);
                        errdefer a.deinit();
                        const index_entries_for_path = self.status.index.entries.get(path) orelse return error.EntryNotFound;
                        var b = try LineIterator(repo_kind).initFromIndex(core_cursor, self.allocator, index_entries_for_path[0] orelse return error.NullEntry);
                        errdefer b.deinit();
                        self.next_index += 1;
                        return try HunkIterator(repo_kind).init(self.allocator, &a, &b);
                    } else {
                        next_index -= self.status.index_modified.items.len;
                    }

                    if (next_index < self.status.index_deleted.items.len) {
                        const path = self.status.index_deleted.items[next_index];
                        var a = try LineIterator(repo_kind).initFromHead(core_cursor, self.allocator, path, self.status.head_tree.entries.get(path) orelse return error.EntryNotFound);
                        errdefer a.deinit();
                        var b = try LineIterator(repo_kind).initFromNothing(self.allocator, path);
                        errdefer b.deinit();
                        self.next_index += 1;
                        return try HunkIterator(repo_kind).init(self.allocator, &a, &b);
                    }
                },
            }

            return null;
        }

        pub fn deinit(self: *FileIterator(repo_kind)) void {
            self.status.deinit();
        }
    };
}
