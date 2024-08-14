const std = @import("std");
const xitdb = @import("xitdb");
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
        line_offsets: []usize,
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
            var object_reader = try obj.ObjectReader(repo_kind).init(allocator, core_cursor, oid_hex, true);
            errdefer object_reader.deinit();
            var iter = LineIterator(repo_kind){
                .allocator = allocator,
                .path = entry.path,
                .oid = entry.oid,
                .oid_hex = oid_hex,
                .mode = entry.mode,
                .line_offsets = undefined,
                .source = .{
                    .object = .{
                        .object_reader = object_reader,
                        .eof = false,
                    },
                },
            };
            try iter.initLineOffsets();
            return iter;
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

            var iter = LineIterator(repo_kind){
                .allocator = allocator,
                .path = path,
                .oid = oid,
                .oid_hex = std.fmt.bytesToHex(&oid, .lower),
                .mode = mode,
                .line_offsets = undefined,
                .source = .{
                    .workspace = .{
                        .file = file,
                        .eof = false,
                    },
                },
            };
            try iter.initLineOffsets();
            return iter;
        }

        pub fn initFromNothing(allocator: std.mem.Allocator, path: []const u8) !LineIterator(repo_kind) {
            var iter = LineIterator(repo_kind){
                .allocator = allocator,
                .path = path,
                .oid = [_]u8{0} ** hash.SHA1_BYTES_LEN,
                .oid_hex = [_]u8{0} ** hash.SHA1_HEX_LEN,
                .mode = null,
                .line_offsets = undefined,
                .source = .nothing,
            };
            try iter.initLineOffsets();
            return iter;
        }

        pub fn initFromHead(core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator, path: []const u8, entry: obj.TreeEntry) !LineIterator(repo_kind) {
            const oid_hex = std.fmt.bytesToHex(&entry.oid, .lower);
            var object_reader = try obj.ObjectReader(repo_kind).init(allocator, core_cursor, oid_hex, true);
            errdefer object_reader.deinit();
            var iter = LineIterator(repo_kind){
                .allocator = allocator,
                .path = path,
                .oid = entry.oid,
                .oid_hex = oid_hex,
                .mode = entry.mode,
                .line_offsets = undefined,
                .source = .{
                    .object = .{
                        .object_reader = object_reader,
                        .eof = false,
                    },
                },
            };
            try iter.initLineOffsets();
            return iter;
        }

        pub fn initFromOid(core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator, path: []const u8, oid: [hash.SHA1_BYTES_LEN]u8, mode_maybe: ?io.Mode) !LineIterator(repo_kind) {
            const oid_hex = std.fmt.bytesToHex(&oid, .lower);
            var object_reader = try obj.ObjectReader(repo_kind).init(allocator, core_cursor, oid_hex, true);
            errdefer object_reader.deinit();
            var iter = LineIterator(repo_kind){
                .allocator = allocator,
                .path = path,
                .oid = oid,
                .oid_hex = oid_hex,
                .mode = mode_maybe,
                .line_offsets = undefined,
                .source = .{
                    .object = .{
                        .object_reader = object_reader,
                        .eof = false,
                    },
                },
            };
            try iter.initLineOffsets();
            return iter;
        }

        pub fn initFromBuffer(allocator: std.mem.Allocator, buffer: []const u8) !LineIterator(repo_kind) {
            var iter = LineIterator(repo_kind){
                .allocator = allocator,
                .path = "",
                .oid = [_]u8{0} ** hash.SHA1_BYTES_LEN,
                .oid_hex = [_]u8{0} ** hash.SHA1_HEX_LEN,
                .mode = null,
                .line_offsets = undefined,
                .source = .{
                    .buffer = .{
                        .iter = std.mem.splitScalar(u8, buffer, '\n'),
                    },
                },
            };
            try iter.initLineOffsets();
            return iter;
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
                        const size = try self.source.object.object_reader.reader.read(&buffer);
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
                    return try line_arr.toOwnedSlice();
                },
                .nothing => return null,
                .buffer => {
                    if (self.source.buffer.iter.next()) |line| {
                        const line_copy = try self.allocator.alloc(u8, line.len);
                        errdefer self.allocator.free(line_copy);
                        @memcpy(line_copy, line);
                        return line_copy;
                    } else {
                        return null;
                    }
                },
            }
        }

        pub fn get(self: *LineIterator(repo_kind), index: usize) ![]const u8 {
            try self.seekTo(self.line_offsets[index]);
            return try self.next() orelse return error.ExpectedLine;
        }

        pub fn reset(self: *LineIterator(repo_kind)) !void {
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

        pub fn count(self: *LineIterator(repo_kind)) usize {
            return self.line_offsets.len;
        }

        pub fn deinit(self: *LineIterator(repo_kind)) void {
            switch (self.source) {
                .object => self.source.object.object_reader.deinit(),
                .workspace => self.source.workspace.file.close(),
                .nothing => {},
                .buffer => {},
            }
            self.allocator.free(self.line_offsets);
        }

        fn seekTo(self: *LineIterator(repo_kind), position: u64) !void {
            try self.reset();
            switch (self.source) {
                .object => try self.source.object.object_reader.seekTo(position),
                .workspace => try self.source.workspace.file.seekTo(position),
                .nothing => {},
                .buffer => {
                    var line_count: usize = 0;
                    while (self.line_offsets[line_count] < position) {
                        if (try self.next()) |line| {
                            self.allocator.free(line);
                            line_count += 1;
                        }
                    }
                },
            }
        }

        fn initLineOffsets(self: *LineIterator(repo_kind)) !void {
            var offsets = std.ArrayList(usize).init(self.allocator);
            errdefer offsets.deinit();
            var last_pos: usize = 0;
            while (try self.next()) |line| {
                defer self.allocator.free(line);
                try offsets.append(last_pos);
                last_pos += line.len + 1;
            }
            self.line_offsets = try offsets.toOwnedSlice();
        }
    };
}

pub fn MyersDiffIterator(comptime repo_kind: rp.RepoKind) type {
    return struct {
        allocator: std.mem.Allocator,
        points: std.ArrayList([2]Point),
        line_iter_a: *LineIterator(repo_kind),
        line_iter_b: *LineIterator(repo_kind),
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

        const Point = struct {
            x: usize,
            y: usize,
        };

        const Box = struct {
            left: usize,
            top: usize,
            right: usize,
            bottom: usize,

            fn width(self: Box) usize {
                return self.right - self.left;
            }

            fn height(self: Box) usize {
                return self.bottom - self.top;
            }

            fn size(self: Box) usize {
                return self.width() + self.height();
            }

            fn delta(self: Box) isize {
                const w: isize = @intCast(self.width());
                const h: isize = @intCast(self.height());
                return w - h;
            }

            fn absIndex(i: isize, len: usize) usize {
                return if (i < 0) len - @abs(i) else @intCast(i);
            }

            fn forward(self: Box, vf: []isize, vb: []isize, d: usize, line_iter_a: *LineIterator(repo_kind), line_iter_b: *LineIterator(repo_kind)) !?[2]Point {
                const line_count_a = line_iter_a.count();
                const line_count_b = line_iter_b.count();

                const dd: isize = @intCast(d);
                for (0..d + 1) |i| {
                    const ii: isize = @intCast(i);
                    const kk: isize = dd - ii * 2;
                    const cc: isize = kk - self.delta();

                    var px: isize = undefined;
                    var xx: isize = undefined;
                    if (kk == -dd or (kk != dd and vf[absIndex(kk - 1, vf.len)] < vf[absIndex(kk + 1, vf.len)])) {
                        px = vf[absIndex(kk + 1, vf.len)];
                        xx = px;
                    } else {
                        px = vf[absIndex(kk - 1, vf.len)];
                        xx = px + 1;
                    }

                    const left: isize = @intCast(self.left);
                    const right: isize = @intCast(self.right);
                    const top: isize = @intCast(self.top);
                    const bottom: isize = @intCast(self.bottom);

                    var yy = top + (xx - left) - kk;
                    const py = if (d == 0 or xx != px) yy else yy - 1;

                    while (true) {
                        if (xx < right and yy < bottom) {
                            const line_a = try line_iter_a.get(absIndex(xx, line_count_a));
                            defer line_iter_a.allocator.free(line_a);
                            const line_b = try line_iter_b.get(absIndex(yy, line_count_b));
                            defer line_iter_b.allocator.free(line_b);
                            if (std.mem.eql(u8, line_a, line_b)) {
                                xx += 1;
                                yy += 1;
                                continue;
                            }
                        }
                        break;
                    }

                    vf[absIndex(kk, vf.len)] = xx;

                    if (@abs(self.delta()) % 2 != 0 and -(dd - 1) <= cc and cc <= (dd - 1) and yy >= vb[absIndex(cc, vb.len)]) {
                        return [2]Point{
                            .{ .x = @intCast(px), .y = @intCast(py) },
                            .{ .x = @intCast(xx), .y = @intCast(yy) },
                        };
                    }
                }

                return null;
            }

            fn backward(self: Box, vf: []isize, vb: []isize, d: usize, line_iter_a: *LineIterator(repo_kind), line_iter_b: *LineIterator(repo_kind)) !?[2]Point {
                const line_count_a = line_iter_a.count();
                const line_count_b = line_iter_b.count();

                const dd: isize = @intCast(d);
                for (0..d + 1) |i| {
                    const ii: isize = @intCast(i);
                    const cc: isize = dd - ii * 2;
                    const kk: isize = cc + self.delta();

                    var py: isize = undefined;
                    var yy: isize = undefined;
                    if (cc == -dd or (cc != dd and vb[absIndex(cc - 1, vb.len)] > vb[absIndex(cc + 1, vb.len)])) {
                        py = vb[absIndex(cc + 1, vb.len)];
                        yy = py;
                    } else {
                        py = vb[absIndex(cc - 1, vb.len)];
                        yy = py - 1;
                    }

                    const left: isize = @intCast(self.left);
                    const top: isize = @intCast(self.top);

                    var xx = left + (yy - top) + kk;
                    const px = if (d == 0 or yy != py) xx else xx + 1;

                    while (true) {
                        if (xx > left and yy > top) {
                            const line_a = try line_iter_a.get(absIndex(xx - 1, line_count_a));
                            defer line_iter_a.allocator.free(line_a);
                            const line_b = try line_iter_b.get(absIndex(yy - 1, line_count_b));
                            defer line_iter_b.allocator.free(line_b);
                            if (std.mem.eql(u8, line_a, line_b)) {
                                xx -= 1;
                                yy -= 1;
                                continue;
                            }
                        }
                        break;
                    }

                    vb[absIndex(cc, vb.len)] = yy;

                    if (@abs(self.delta()) % 2 == 0 and -dd <= kk and kk <= dd and xx <= vf[absIndex(kk, vf.len)]) {
                        return [2]Point{
                            .{ .x = @intCast(xx), .y = @intCast(yy) },
                            .{ .x = @intCast(px), .y = @intCast(py) },
                        };
                    }
                }

                return null;
            }

            fn midpoint(self: Box, allocator: std.mem.Allocator, line_iter_a: *LineIterator(repo_kind), line_iter_b: *LineIterator(repo_kind)) !?[2]Point {
                if (self.size() == 0) {
                    return null;
                }

                const box_size: f64 = @floatFromInt(self.size());
                const max: usize = @intFromFloat(std.math.ceil(box_size / 2));

                var vf = try std.ArrayList(isize).initCapacity(allocator, 2 * max + 1);
                defer vf.deinit();
                vf.expandToCapacity();
                for (vf.items) |*item| {
                    item.* = 0;
                }
                vf.items[1] = @intCast(self.left);

                var vb = try std.ArrayList(isize).initCapacity(allocator, 2 * max + 1);
                defer vb.deinit();
                vb.expandToCapacity();
                for (vb.items) |*item| {
                    item.* = 0;
                }
                vb.items[1] = @intCast(self.bottom);

                for (0..max + 1) |d| {
                    if (try self.forward(vf.items, vb.items, d, line_iter_a, line_iter_b)) |snake| {
                        return snake;
                    }
                    if (try self.backward(vf.items, vb.items, d, line_iter_a, line_iter_b)) |snake| {
                        return snake;
                    }
                }

                return null;
            }

            fn findPath(self: Box, allocator: std.mem.Allocator, line_iter_a: *LineIterator(repo_kind), line_iter_b: *LineIterator(repo_kind)) !?std.DoublyLinkedList(Point) {
                if (try self.midpoint(allocator, line_iter_a, line_iter_b)) |snake| {
                    const start, const finish = snake;

                    const head_box = Box{ .left = self.left, .top = self.top, .right = start.x, .bottom = start.y };
                    const tail_box = Box{ .left = finish.x, .top = finish.y, .right = self.right, .bottom = self.bottom };

                    const head_maybe = try head_box.findPath(allocator, line_iter_a, line_iter_b);
                    const tail_maybe = try tail_box.findPath(allocator, line_iter_a, line_iter_b);

                    var head_list = std.DoublyLinkedList(Point){};
                    if (head_maybe) |head| {
                        head_list = head;
                    } else {
                        var node = try allocator.create(std.DoublyLinkedList(Point).Node);
                        node.data = start;
                        head_list.append(node);
                    }

                    var tail_list = std.DoublyLinkedList(Point){};
                    if (tail_maybe) |tail| {
                        tail_list = tail;
                    } else {
                        var node = try allocator.create(std.DoublyLinkedList(Point).Node);
                        node.data = finish;
                        tail_list.append(node);
                    }

                    head_list.concatByMoving(&tail_list);

                    return head_list;
                } else {
                    return null;
                }
            }
        };

        fn walkDiagonal(p1: Point, p2: Point, line_iter_a: *LineIterator(repo_kind), line_iter_b: *LineIterator(repo_kind), out: *std.ArrayList([2]Point)) !Point {
            var p = p1;
            while (true) {
                if (p.x < p2.x and p.y < p2.y) {
                    const line_a = try line_iter_a.get(p.x);
                    defer line_iter_a.allocator.free(line_a);
                    const line_b = try line_iter_b.get(p.y);
                    defer line_iter_b.allocator.free(line_b);
                    if (std.mem.eql(u8, line_a, line_b)) {
                        try out.append([2]Point{ p, .{ .x = p.x + 1, .y = p.y + 1 } });
                        p.x += 1;
                        p.y += 1;
                        continue;
                    }
                }
                break;
            }
            return p;
        }

        pub fn init(allocator: std.mem.Allocator, line_iter_a: *LineIterator(repo_kind), line_iter_b: *LineIterator(repo_kind)) !MyersDiffIterator(repo_kind) {
            var points = std.ArrayList([2]Point).init(allocator);
            errdefer points.deinit();

            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();

            const box = Box{ .left = 0, .top = 0, .right = line_iter_a.count(), .bottom = line_iter_b.count() };
            if (try box.findPath(arena.allocator(), line_iter_a, line_iter_b)) |path| {
                var node = path.first orelse return error.ExpectedFirstNode;
                while (true) {
                    const next_node = node.next orelse break;
                    const next_p = next_node.data;

                    var p = try walkDiagonal(node.data, next_p, line_iter_a, line_iter_b, &points);
                    if (next_p.x - p.x < next_p.y - p.y) {
                        try points.append([2]Point{ p, .{ .x = p.x, .y = p.y + 1 } });
                        p.y += 1;
                    } else if (next_p.x - p.x > next_p.y - p.y) {
                        try points.append([2]Point{ p, .{ .x = p.x + 1, .y = p.y } });
                        p.x += 1;
                    }
                    _ = try walkDiagonal(p, next_p, line_iter_a, line_iter_b, &points);

                    node = next_node;
                }
            }

            return MyersDiffIterator(repo_kind){
                .allocator = allocator,
                .points = points,
                .line_iter_a = line_iter_a,
                .line_iter_b = line_iter_b,
                .next_index = 0,
            };
        }

        pub fn next(self: *MyersDiffIterator(repo_kind)) !?Edit {
            if (self.next_index == self.points.items.len) {
                return null;
            }

            const p1, const p2 = self.points.items[self.next_index];
            self.next_index += 1;

            if (p1.x == p2.x) {
                const new_idx = p1.y;
                const line_b = try self.line_iter_b.get(new_idx);
                errdefer self.allocator.free(line_b);
                return .{
                    .ins = .{
                        .new_line = .{ .num = new_idx + 1, .text = line_b },
                    },
                };
            } else if (p1.y == p2.y) {
                const old_idx = p1.x;
                const line_a = try self.line_iter_a.get(old_idx);
                errdefer self.allocator.free(line_a);
                return .{
                    .del = .{
                        .old_line = .{ .num = old_idx + 1, .text = line_a },
                    },
                };
            } else {
                const old_idx = p1.x;
                const new_idx = p1.y;
                const line_a = try self.line_iter_a.get(old_idx);
                errdefer self.allocator.free(line_a);
                const line_b = try self.line_iter_b.get(new_idx);
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
            self.points.deinit();
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
            .{ .del = .{ .old_line = .{ .num = 4, .text = "A" } } },
            .{ .eql = .{ .old_line = .{ .num = 5, .text = "B" }, .new_line = .{ .num = 2, .text = "B" } } },
            .{ .ins = .{ .new_line = .{ .num = 3, .text = "A" } } },
            .{ .eql = .{ .old_line = .{ .num = 6, .text = "B" }, .new_line = .{ .num = 4, .text = "B" } } },
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
                .line_count_o = line_iter_o.count(),
                .line_count_a = line_iter_a.count(),
                .line_count_b = line_iter_b.count(),
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
        header_lines: std.ArrayList([]const u8),
        myers_diff: MyersDiffIterator(repo_kind),
        eof: bool,
        allocator: std.mem.Allocator,
        arena: std.heap.ArenaAllocator,
        line_iter_a: *LineIterator(repo_kind),
        line_iter_b: *LineIterator(repo_kind),
        found_edit: bool,
        margin: usize,
        next_hunk: Hunk(repo_kind),

        pub fn init(allocator: std.mem.Allocator, line_iter_a: *LineIterator(repo_kind), line_iter_b: *LineIterator(repo_kind)) !HunkIterator(repo_kind) {
            var arena = std.heap.ArenaAllocator.init(allocator);
            errdefer arena.deinit();

            var header_lines = std.ArrayList([]const u8).init(arena.allocator());

            try header_lines.append(try std.fmt.allocPrint(arena.allocator(), "diff --git a/{s} b/{s}", .{ line_iter_a.path, line_iter_b.path }));

            var mode_maybe: ?io.Mode = null;

            if (line_iter_a.mode) |a_mode| {
                if (line_iter_b.mode) |b_mode| {
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
                if (line_iter_b.mode) |b_mode| {
                    try header_lines.append(try std.fmt.allocPrint(arena.allocator(), "new file mode {s}", .{b_mode.toStr()}));
                }
            }

            if (!std.mem.eql(u8, &line_iter_a.oid, &line_iter_b.oid)) {
                if (mode_maybe) |mode| {
                    try header_lines.append(try std.fmt.allocPrint(arena.allocator(), "index {s}..{s} {s}", .{
                        line_iter_a.oid_hex[0..7],
                        line_iter_b.oid_hex[0..7],
                        mode.toStr(),
                    }));
                } else {
                    try header_lines.append(try std.fmt.allocPrint(arena.allocator(), "index {s}..{s}", .{
                        line_iter_a.oid_hex[0..7],
                        line_iter_b.oid_hex[0..7],
                    }));
                }

                try header_lines.append(try std.fmt.allocPrint(arena.allocator(), "--- a/{s}", .{line_iter_a.path}));

                if (line_iter_b.mode != null) {
                    try header_lines.append(try std.fmt.allocPrint(arena.allocator(), "+++ b/{s}", .{line_iter_b.path}));
                } else {
                    try header_lines.append("+++ /dev/null");
                }
            }

            var myers_diff = try MyersDiffIterator(repo_kind).init(allocator, line_iter_a, line_iter_b);
            errdefer myers_diff.deinit();

            return HunkIterator(repo_kind){
                .header_lines = header_lines,
                .myers_diff = myers_diff,
                .eof = false,
                .allocator = allocator,
                .arena = arena,
                .line_iter_a = line_iter_a,
                .line_iter_b = line_iter_b,
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

            if (!self.eof) {
                while (true) {
                    if (try self.myers_diff.next()) |edit| {
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
                        // set eof so next() returns null afterwards
                        self.eof = true;
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
            self.myers_diff.deinit();
            self.arena.deinit();
            self.next_hunk.deinit();
        }

        pub fn reset(self: *HunkIterator(repo_kind)) !void {
            try self.myers_diff.reset();
            self.eof = false;
            try self.line_iter_a.reset();
            try self.line_iter_b.reset();
            self.found_edit = false;
            self.margin = 0;
            self.next_hunk.deinit();
            self.next_hunk = Hunk(repo_kind){
                .edits = std.ArrayList(MyersDiffIterator(repo_kind).Edit).init(self.allocator),
                .allocator = self.allocator,
            };
        }
    };
}

pub const ConflictDiffKind = enum {
    common, // base
    current, // ours
    source, // theirs
};

pub const DiffKind = enum {
    workspace,
    index,
    tree,
};

pub const BasicDiffOptions = union(DiffKind) {
    workspace: struct {
        conflict_diff_kind: ConflictDiffKind,
    },
    index,
    tree: struct {
        old: ?[hash.SHA1_HEX_LEN]u8,
        new: ?[hash.SHA1_HEX_LEN]u8,
    },
};

pub fn DiffOptions(comptime repo_kind: rp.RepoKind) type {
    return union(DiffKind) {
        workspace: struct {
            conflict_diff_kind: ConflictDiffKind,
            status: *st.Status(repo_kind),
        },
        index: struct {
            status: *st.Status(repo_kind),
        },
        tree: struct {
            tree_diff: *obj.TreeDiff(repo_kind),
        },
    };
}

pub fn LineIteratorPair(comptime repo_kind: rp.RepoKind) type {
    return struct {
        path: []const u8,
        a: LineIterator(repo_kind),
        b: LineIterator(repo_kind),

        pub fn deinit(self: *LineIteratorPair(repo_kind)) void {
            self.a.deinit();
            self.b.deinit();
        }
    };
}

pub fn FileIterator(comptime repo_kind: rp.RepoKind) type {
    return struct {
        allocator: std.mem.Allocator,
        core: *rp.Repo(repo_kind).Core,
        cursor: switch (repo_kind) {
            .git => void,
            .xit => xitdb.Cursor(.file),
        },
        diff_opts: DiffOptions(repo_kind),
        next_index: usize,

        pub fn init(
            allocator: std.mem.Allocator,
            core: *rp.Repo(repo_kind).Core,
            diff_opts: DiffOptions(repo_kind),
        ) !FileIterator(repo_kind) {
            return .{
                .allocator = allocator,
                .core = core,
                .cursor = try core.latestCursor(),
                .diff_opts = diff_opts,
                .next_index = 0,
            };
        }

        pub fn next(self: *FileIterator(repo_kind)) !?LineIteratorPair(repo_kind) {
            const core_cursor = switch (repo_kind) {
                .git => .{ .core = self.core },
                .xit => .{ .core = self.core, .cursor = &self.cursor },
            };
            var next_index = self.next_index;
            switch (self.diff_opts) {
                .workspace => {
                    if (next_index < self.diff_opts.workspace.status.conflicts.count()) {
                        const path = self.diff_opts.workspace.status.conflicts.keys()[next_index];
                        const meta = try io.getMetadata(self.core.repo_dir, path);
                        const stage: usize = switch (self.diff_opts.workspace.conflict_diff_kind) {
                            .common => 1,
                            .current => 2,
                            .source => 3,
                        };
                        const index_entries_for_path = self.diff_opts.workspace.status.index.entries.get(path) orelse return error.EntryNotFound;
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
                            return .{ .path = path, .a = a, .b = b };
                        }
                        // there is no entry, so just skip it and call this method recursively
                        else {
                            self.next_index += 1;
                            return try self.next();
                        }
                    } else {
                        next_index -= self.diff_opts.workspace.status.conflicts.count();
                    }

                    if (next_index < self.diff_opts.workspace.status.workspace_modified.items.len) {
                        const entry = self.diff_opts.workspace.status.workspace_modified.items[next_index];
                        const index_entries_for_path = self.diff_opts.workspace.status.index.entries.get(entry.path) orelse return error.EntryNotFound;
                        var a = try LineIterator(repo_kind).initFromIndex(core_cursor, self.allocator, index_entries_for_path[0] orelse return error.NullEntry);
                        errdefer a.deinit();
                        var b = try LineIterator(repo_kind).initFromWorkspace(core_cursor, self.allocator, entry.path, io.getMode(entry.meta));
                        errdefer b.deinit();
                        self.next_index += 1;
                        return .{ .path = entry.path, .a = a, .b = b };
                    } else {
                        next_index -= self.diff_opts.workspace.status.workspace_modified.items.len;
                    }

                    if (next_index < self.diff_opts.workspace.status.workspace_deleted.items.len) {
                        const path = self.diff_opts.workspace.status.workspace_deleted.items[next_index];
                        const index_entries_for_path = self.diff_opts.workspace.status.index.entries.get(path) orelse return error.EntryNotFound;
                        var a = try LineIterator(repo_kind).initFromIndex(core_cursor, self.allocator, index_entries_for_path[0] orelse return error.NullEntry);
                        errdefer a.deinit();
                        var b = try LineIterator(repo_kind).initFromNothing(self.allocator, path);
                        errdefer b.deinit();
                        self.next_index += 1;
                        return .{ .path = path, .a = a, .b = b };
                    }
                },
                .index => {
                    if (next_index < self.diff_opts.index.status.index_added.items.len) {
                        const path = self.diff_opts.index.status.index_added.items[next_index];
                        var a = try LineIterator(repo_kind).initFromNothing(self.allocator, path);
                        errdefer a.deinit();
                        const index_entries_for_path = self.diff_opts.index.status.index.entries.get(path) orelse return error.EntryNotFound;
                        var b = try LineIterator(repo_kind).initFromIndex(core_cursor, self.allocator, index_entries_for_path[0] orelse return error.NullEntry);
                        errdefer b.deinit();
                        self.next_index += 1;
                        return .{ .path = path, .a = a, .b = b };
                    } else {
                        next_index -= self.diff_opts.index.status.index_added.items.len;
                    }

                    if (next_index < self.diff_opts.index.status.index_modified.items.len) {
                        const path = self.diff_opts.index.status.index_modified.items[next_index];
                        var a = try LineIterator(repo_kind).initFromHead(core_cursor, self.allocator, path, self.diff_opts.index.status.head_tree.entries.get(path) orelse return error.EntryNotFound);
                        errdefer a.deinit();
                        const index_entries_for_path = self.diff_opts.index.status.index.entries.get(path) orelse return error.EntryNotFound;
                        var b = try LineIterator(repo_kind).initFromIndex(core_cursor, self.allocator, index_entries_for_path[0] orelse return error.NullEntry);
                        errdefer b.deinit();
                        self.next_index += 1;
                        return .{ .path = path, .a = a, .b = b };
                    } else {
                        next_index -= self.diff_opts.index.status.index_modified.items.len;
                    }

                    if (next_index < self.diff_opts.index.status.index_deleted.items.len) {
                        const path = self.diff_opts.index.status.index_deleted.items[next_index];
                        var a = try LineIterator(repo_kind).initFromHead(core_cursor, self.allocator, path, self.diff_opts.index.status.head_tree.entries.get(path) orelse return error.EntryNotFound);
                        errdefer a.deinit();
                        var b = try LineIterator(repo_kind).initFromNothing(self.allocator, path);
                        errdefer b.deinit();
                        self.next_index += 1;
                        return .{ .path = path, .a = a, .b = b };
                    }
                },
                .tree => {
                    if (next_index < self.diff_opts.tree.tree_diff.changes.count()) {
                        const path = self.diff_opts.tree.tree_diff.changes.keys()[next_index];
                        const change = self.diff_opts.tree.tree_diff.changes.values()[next_index];
                        var a = if (change.old) |old|
                            try LineIterator(repo_kind).initFromOid(core_cursor, self.allocator, path, old.oid, old.mode)
                        else
                            try LineIterator(repo_kind).initFromNothing(self.allocator, path);
                        errdefer a.deinit();
                        var b = if (change.new) |new|
                            try LineIterator(repo_kind).initFromOid(core_cursor, self.allocator, path, new.oid, new.mode)
                        else
                            try LineIterator(repo_kind).initFromNothing(self.allocator, path);
                        errdefer b.deinit();
                        self.next_index += 1;
                        return .{ .path = path, .a = a, .b = b };
                    }
                },
            }

            return null;
        }
    };
}
