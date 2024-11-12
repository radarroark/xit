const std = @import("std");
const hash = @import("./hash.zig");
const obj = @import("./object.zig");
const idx = @import("./index.zig");
const ref = @import("./ref.zig");
const cht = @import("./checkout.zig");
const io = @import("./io.zig");
const rp = @import("./repo.zig");
const df = @import("./diff.zig");

const MAX_READ_BYTES = 1024; // FIXME: this is arbitrary...

fn getDescendent(comptime repo_kind: rp.RepoKind, allocator: std.mem.Allocator, state: rp.Repo(repo_kind).State(.read_only), oid1: *const [hash.SHA1_HEX_LEN]u8, oid2: *const [hash.SHA1_HEX_LEN]u8) ![hash.SHA1_HEX_LEN]u8 {
    if (std.mem.eql(u8, oid1, oid2)) {
        return oid1.*;
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const ParentKind = enum {
        one,
        two,
    };
    const Parent = struct {
        oid: [hash.SHA1_HEX_LEN]u8,
        kind: ParentKind,
    };
    var queue = std.DoublyLinkedList(Parent){};

    {
        const object = try obj.Object(repo_kind, .full).init(arena.allocator(), state, oid1);
        for (object.content.commit.parents.items) |parent_oid| {
            var node = try arena.allocator().create(std.DoublyLinkedList(Parent).Node);
            node.data = .{ .oid = parent_oid, .kind = .one };
            queue.append(node);
        }
    }

    {
        const object = try obj.Object(repo_kind, .full).init(arena.allocator(), state, oid2);
        for (object.content.commit.parents.items) |parent_oid| {
            var node = try arena.allocator().create(std.DoublyLinkedList(Parent).Node);
            node.data = .{ .oid = parent_oid, .kind = .two };
            queue.append(node);
        }
    }

    while (queue.popFirst()) |node| {
        switch (node.data.kind) {
            .one => {
                if (std.mem.eql(u8, oid2, &node.data.oid)) {
                    return oid1.*;
                } else if (std.mem.eql(u8, oid1, &node.data.oid)) {
                    continue; // this oid was already added to the queue
                }
            },
            .two => {
                if (std.mem.eql(u8, oid1, &node.data.oid)) {
                    return oid2.*;
                } else if (std.mem.eql(u8, oid2, &node.data.oid)) {
                    continue; // this oid was already added to the queue
                }
            },
        }

        // TODO: instead of appending to the end, append it in descending order of timestamp
        // so we prioritize more recent commits and avoid wasteful traversal deep in the history.
        const object = try obj.Object(repo_kind, .full).init(arena.allocator(), state, &node.data.oid);
        for (object.content.commit.parents.items) |parent_oid| {
            var new_node = try arena.allocator().create(std.DoublyLinkedList(Parent).Node);
            new_node.data = .{ .oid = parent_oid, .kind = node.data.kind };
            queue.append(new_node);
        }
    }

    return error.DescendentNotFound;
}

pub fn commonAncestor(comptime repo_kind: rp.RepoKind, allocator: std.mem.Allocator, state: rp.Repo(repo_kind).State(.read_only), oid1: *const [hash.SHA1_HEX_LEN]u8, oid2: *const [hash.SHA1_HEX_LEN]u8) ![hash.SHA1_HEX_LEN]u8 {
    if (std.mem.eql(u8, oid1, oid2)) {
        return oid1.*;
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const Parent = struct {
        oid: [hash.SHA1_HEX_LEN]u8,
        kind: enum {
            one,
            two,
            stale,
        },
    };
    var queue = std.DoublyLinkedList(Parent){};

    {
        var node = try arena.allocator().create(std.DoublyLinkedList(Parent).Node);
        node.data = .{ .oid = oid1.*, .kind = .one };
        queue.append(node);
    }

    {
        var node = try arena.allocator().create(std.DoublyLinkedList(Parent).Node);
        node.data = .{ .oid = oid2.*, .kind = .two };
        queue.append(node);
    }

    var parents_of_1 = std.StringHashMap(void).init(arena.allocator());
    var parents_of_2 = std.StringHashMap(void).init(arena.allocator());
    var parents_of_both = std.StringArrayHashMap(void).init(arena.allocator());
    var stale_oids = std.StringHashMap(void).init(arena.allocator());

    while (queue.popFirst()) |node| {
        switch (node.data.kind) {
            .one => {
                if (parents_of_2.contains(&node.data.oid)) {
                    try parents_of_both.put(&node.data.oid, {});
                } else if (parents_of_1.contains(&node.data.oid)) {
                    continue; // this oid was already added to the queue
                } else {
                    try parents_of_1.put(&node.data.oid, {});
                }
            },
            .two => {
                if (parents_of_1.contains(&node.data.oid)) {
                    try parents_of_both.put(&node.data.oid, {});
                } else if (parents_of_2.contains(&node.data.oid)) {
                    continue; // this oid was already added to the queue
                } else {
                    try parents_of_2.put(&node.data.oid, {});
                }
            },
            .stale => {
                try stale_oids.put(&node.data.oid, {});
            },
        }

        const is_base_ancestor = parents_of_both.contains(&node.data.oid);

        // TODO: instead of appending to the end, append it in descending order of timestamp
        // so we prioritize more recent commits and avoid wasteful traversal deep in the history.
        const object = try obj.Object(repo_kind, .full).init(arena.allocator(), state, &node.data.oid);
        for (object.content.commit.parents.items) |parent_oid| {
            const is_stale = is_base_ancestor or stale_oids.contains(&parent_oid);
            var new_node = try arena.allocator().create(std.DoublyLinkedList(Parent).Node);
            new_node.data = .{ .oid = parent_oid, .kind = if (is_stale) .stale else node.data.kind };
            queue.append(new_node);
        }

        // stop if queue only has stale nodes
        var queue_is_stale = true;
        var next_node_maybe = queue.first;
        while (next_node_maybe) |next_node| {
            if (!stale_oids.contains(&next_node.data.oid)) {
                queue_is_stale = false;
                break;
            }
            next_node_maybe = next_node.next;
        }
        if (queue_is_stale) {
            break;
        }
    }

    const base_ancestor_count = parents_of_both.count();
    if (base_ancestor_count > 1) {
        var oid = parents_of_both.keys()[0][0..hash.SHA1_HEX_LEN].*;
        for (parents_of_both.keys()[1..]) |next_oid| {
            oid = try getDescendent(repo_kind, allocator, state, oid[0..hash.SHA1_HEX_LEN], next_oid[0..hash.SHA1_HEX_LEN]);
        }
        return oid;
    } else if (base_ancestor_count == 1) {
        return parents_of_both.keys()[0][0..hash.SHA1_HEX_LEN].*;
    } else {
        return error.NoCommonAncestor;
    }
}

pub const RenamedEntry = struct {
    path: []const u8,
    tree_entry: obj.TreeEntry,
};
pub const MergeConflict = struct {
    base: ?obj.TreeEntry,
    target: ?obj.TreeEntry,
    source: ?obj.TreeEntry,
    renamed: ?RenamedEntry,
};

fn writeBlobWithDiff3(
    comptime repo_kind: rp.RepoKind,
    state: rp.Repo(repo_kind).State(.read_write),
    allocator: std.mem.Allocator,
    base_file_oid_maybe: ?*const [hash.SHA1_BYTES_LEN]u8,
    target_file_oid: *const [hash.SHA1_BYTES_LEN]u8,
    source_file_oid: *const [hash.SHA1_BYTES_LEN]u8,
    base_oid: *const [hash.SHA1_HEX_LEN]u8,
    target_name: []const u8,
    source_name: []const u8,
    has_conflict: *bool,
) ![hash.SHA1_BYTES_LEN]u8 {
    var base_iter = if (base_file_oid_maybe) |base_file_oid|
        try df.LineIterator(repo_kind).initFromOid(state.readOnly(), allocator, "", base_file_oid, null)
    else
        try df.LineIterator(repo_kind).initFromNothing(allocator, "");
    defer base_iter.deinit();

    var target_iter = try df.LineIterator(repo_kind).initFromOid(state.readOnly(), allocator, "", target_file_oid, null);
    defer target_iter.deinit();

    var source_iter = try df.LineIterator(repo_kind).initFromOid(state.readOnly(), allocator, "", source_file_oid, null);
    defer source_iter.deinit();

    // if any file is binary, just return the source oid because there is no point in trying to merge them
    if (base_iter.source == .binary or target_iter.source == .binary or source_iter.source == .binary) {
        has_conflict.* = true;
        return source_file_oid.*;
    }

    var diff3_iter = try df.Diff3Iterator(repo_kind).init(allocator, &base_iter, &target_iter, &source_iter);
    defer diff3_iter.deinit();

    var line_buffer = std.ArrayList([]const u8).init(allocator);
    defer {
        for (line_buffer.items) |buffer| {
            allocator.free(buffer);
        }
        line_buffer.deinit();
    }

    const LineRange = struct {
        allocator: std.mem.Allocator,
        lines: std.ArrayList([]const u8),

        fn init(alctr: std.mem.Allocator, iter: *df.LineIterator(repo_kind), range_maybe: ?df.Diff3Iterator(repo_kind).Range) !@This() {
            var lines = std.ArrayList([]const u8).init(alctr);
            errdefer {
                for (lines.items) |line| {
                    alctr.free(line);
                }
                lines.deinit();
            }
            if (range_maybe) |range| {
                for (range.begin..range.end) |line_num| {
                    const line = try iter.get(line_num);
                    errdefer alctr.free(line);
                    try lines.append(line);
                }
            }
            return .{
                .allocator = alctr,
                .lines = lines,
            };
        }

        fn deinit(self: *@This()) void {
            for (self.lines.items) |line| {
                self.allocator.free(line);
            }
            self.lines.deinit();
        }

        fn eql(self: @This(), other: @This()) bool {
            if (self.lines.items.len != other.lines.items.len) {
                return false;
            }
            for (self.lines.items, other.lines.items) |our_line, their_line| {
                if (!std.mem.eql(u8, our_line, their_line)) {
                    return false;
                }
            }
            return true;
        }
    };

    const Stream = struct {
        allocator: std.mem.Allocator,
        target_marker: []u8,
        base_marker: []u8,
        separate_marker: []u8,
        source_marker: []u8,
        base_iter: *df.LineIterator(repo_kind),
        target_iter: *df.LineIterator(repo_kind),
        source_iter: *df.LineIterator(repo_kind),
        diff3_iter: *df.Diff3Iterator(repo_kind),
        line_buffer: *std.ArrayList([]const u8),
        current_line: ?[]const u8,
        has_conflict: bool,

        const Parent = @This();

        pub const Reader = struct {
            parent: *Parent,

            pub fn read(self: @This(), buf: []u8) !usize {
                var size: usize = 0;
                while (size < buf.len) {
                    const read_size = try self.readStep(buf[size..]);
                    if (read_size == 0) {
                        break;
                    }
                    size += read_size;
                }
                return size;
            }

            fn readStep(self: @This(), buf: []u8) !usize {
                if (self.parent.current_line) |current_line| {
                    const size = @min(buf.len, current_line.len);
                    var line_finished = current_line.len == 0;
                    if (size > 0) {
                        // copy as much from the current line as we can
                        @memcpy(buf[0..size], current_line[0..size]);
                        const new_current_line = current_line[size..];
                        line_finished = new_current_line.len == 0;
                        self.parent.current_line = new_current_line;
                    }
                    // if we have copied the entire line
                    if (line_finished) {
                        // if there is room for the newline character
                        if (buf.len > size) {
                            // remove the line from the line buffer
                            const line = self.parent.line_buffer.orderedRemove(0);
                            self.parent.allocator.free(line);
                            if (self.parent.line_buffer.items.len > 0) {
                                self.parent.current_line = self.parent.line_buffer.items[0];
                            } else {
                                self.parent.current_line = null;
                            }
                            // if we aren't at the very last line, add a newline character
                            if (self.parent.current_line != null or !self.parent.diff3_iter.finished) {
                                buf[size] = '\n';
                                return size + 1;
                            }
                        }
                    }
                    return size;
                }

                if (try self.parent.diff3_iter.next()) |chunk| {
                    switch (chunk) {
                        .clean => |clean| {
                            for (clean.begin..clean.end) |line_num| {
                                const base_line = try self.parent.base_iter.get(line_num);
                                {
                                    errdefer self.parent.allocator.free(base_line);
                                    try self.parent.line_buffer.append(base_line);
                                }
                                self.parent.current_line = self.parent.line_buffer.items[0];
                            }
                        },
                        .conflict => |conflict| {
                            var base_lines = try LineRange.init(self.parent.allocator, self.parent.base_iter, conflict.o_range);
                            defer base_lines.deinit();
                            var target_lines = try LineRange.init(self.parent.allocator, self.parent.target_iter, conflict.a_range);
                            defer target_lines.deinit();
                            var source_lines = try LineRange.init(self.parent.allocator, self.parent.source_iter, conflict.b_range);
                            defer source_lines.deinit();

                            // if base == target or target == source, return source to autoresolve conflict
                            if (base_lines.eql(target_lines) or target_lines.eql(source_lines)) {
                                if (source_lines.lines.items.len > 0) {
                                    try self.parent.line_buffer.appendSlice(source_lines.lines.items);
                                    self.parent.current_line = self.parent.line_buffer.items[0];
                                    source_lines.lines.clearAndFree();
                                }
                                return self.readStep(buf);
                            }
                            // if base == source, return target to autoresolve conflict
                            else if (base_lines.eql(source_lines)) {
                                if (target_lines.lines.items.len > 0) {
                                    try self.parent.line_buffer.appendSlice(target_lines.lines.items);
                                    self.parent.current_line = self.parent.line_buffer.items[0];
                                    target_lines.lines.clearAndFree();
                                }
                                return self.readStep(buf);
                            }

                            // return conflict

                            const target_marker = try self.parent.allocator.dupe(u8, self.parent.target_marker);
                            {
                                errdefer self.parent.allocator.free(target_marker);
                                try self.parent.line_buffer.append(target_marker);
                            }
                            try self.parent.line_buffer.appendSlice(target_lines.lines.items);
                            target_lines.lines.clearAndFree();

                            const base_marker = try self.parent.allocator.dupe(u8, self.parent.base_marker);
                            {
                                errdefer self.parent.allocator.free(base_marker);
                                try self.parent.line_buffer.append(base_marker);
                            }
                            try self.parent.line_buffer.appendSlice(base_lines.lines.items);
                            base_lines.lines.clearAndFree();

                            const separate_marker = try self.parent.allocator.dupe(u8, self.parent.separate_marker);
                            {
                                errdefer self.parent.allocator.free(separate_marker);
                                try self.parent.line_buffer.append(separate_marker);
                            }

                            try self.parent.line_buffer.appendSlice(source_lines.lines.items);
                            source_lines.lines.clearAndFree();
                            const source_marker = try self.parent.allocator.dupe(u8, self.parent.source_marker);
                            {
                                errdefer self.parent.allocator.free(source_marker);
                                try self.parent.line_buffer.append(source_marker);
                            }

                            self.parent.current_line = self.parent.line_buffer.items[0];
                            self.parent.has_conflict = true;
                        },
                    }
                    return self.readStep(buf);
                } else {
                    return 0;
                }
            }
        };

        pub fn seekTo(self: *@This(), offset: usize) !void {
            if (offset == 0) {
                try self.base_iter.reset();
                try self.target_iter.reset();
                try self.source_iter.reset();
                try self.diff3_iter.reset();
            } else {
                return error.InvalidOffset;
            }
        }

        pub fn reader(self: *@This()) Reader {
            return Reader{
                .parent = self,
            };
        }

        pub fn count(self: *@This()) !usize {
            var n: usize = 0;
            var read_buffer = [_]u8{0} ** MAX_READ_BYTES;
            try self.seekTo(0);
            while (true) {
                const size = try self.reader().read(&read_buffer);
                if (size == 0) {
                    break;
                }
                n += size;
            }
            try self.seekTo(0);
            return n;
        }
    };

    const target_marker = try std.fmt.allocPrint(allocator, "<<<<<<< {s}", .{target_name});
    defer allocator.free(target_marker);
    const base_marker = try std.fmt.allocPrint(allocator, "||||||| original ({s})", .{base_oid});
    defer allocator.free(base_marker);
    const separate_marker = try std.fmt.allocPrint(allocator, "=======", .{});
    defer allocator.free(separate_marker);
    const source_marker = try std.fmt.allocPrint(allocator, ">>>>>>> {s}", .{source_name});
    defer allocator.free(source_marker);
    var stream = Stream{
        .allocator = allocator,
        .target_marker = target_marker,
        .base_marker = base_marker,
        .separate_marker = separate_marker,
        .source_marker = source_marker,
        .base_iter = &base_iter,
        .target_iter = &target_iter,
        .source_iter = &source_iter,
        .diff3_iter = &diff3_iter,
        .line_buffer = &line_buffer,
        .current_line = null,
        .has_conflict = false,
    };

    var oid = [_]u8{0} ** hash.SHA1_BYTES_LEN;
    try obj.writeObject(repo_kind, state, &stream, .{ .kind = .blob, .size = try stream.count() }, &oid);
    has_conflict.* = stream.has_conflict;
    return oid;
}

fn writeBlobWithPatches(
    state: rp.Repo(.xit).State(.read_write),
    allocator: std.mem.Allocator,
    source_file_oid: *const [hash.SHA1_BYTES_LEN]u8,
    base_oid: *const [hash.SHA1_HEX_LEN]u8,
    target_oid: *const [hash.SHA1_HEX_LEN]u8,
    source_oid: *const [hash.SHA1_HEX_LEN]u8,
    target_name: []const u8,
    source_name: []const u8,
    has_conflict: *bool,
    path: []const u8,
) ![hash.SHA1_BYTES_LEN]u8 {
    const commit_id_to_path_to_patch_id_cursor_maybe = try state.extra.moment.getCursor(hash.hashBuffer("commit-id->path->patch-id"));

    var patch_ids = std.ArrayList(hash.Hash).init(allocator);
    defer patch_ids.deinit();

    var iter = try obj.ObjectIterator(.xit, .full).init(allocator, state.readOnly(), &.{source_oid.*}, .{ .recursive = false });
    defer iter.deinit();

    const path_hash = hash.hashBuffer(path);

    while (try iter.next()) |object| {
        defer object.deinit();

        if (std.mem.eql(u8, base_oid, &object.oid)) {
            break;
        }

        if (commit_id_to_path_to_patch_id_cursor_maybe) |commit_id_to_path_to_patch_id_cursor| {
            const commit_id_to_path_to_patch_id = try rp.Repo(.xit).DB.HashMap(.read_only).init(commit_id_to_path_to_patch_id_cursor);
            if (try commit_id_to_path_to_patch_id.getCursor(try hash.hexToHash(&object.oid))) |path_to_patch_id_cursor| {
                const path_to_patch_id = try rp.Repo(.xit).DB.HashMap(.read_only).init(path_to_patch_id_cursor);
                if (try path_to_patch_id.getCursor(path_hash)) |patch_id_cursor| {
                    const patch_id_bytes = try patch_id_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
                    defer allocator.free(patch_id_bytes);
                    const patch_id = hash.bytesToHash(patch_id_bytes[0..hash.SHA1_BYTES_LEN]);
                    try patch_ids.append(patch_id);
                }
            }
        }
    }

    // if there are no patches, it is most likely because the file was determined to be binary,
    // so just return the source oid because there is no point in trying to merge them
    if (patch_ids.items.len == 0) {
        has_conflict.* = true;
        return source_file_oid.*;
    }

    // get branch map
    const branch_name_hash = hash.hashBuffer(target_name);
    const branches_cursor = (try state.extra.moment.getCursor(hash.hashBuffer("branches"))) orelse return error.KeyNotFound;
    const branches = try rp.Repo(.xit).DB.HashMap(.read_only).init(branches_cursor);
    const branch_cursor = (try branches.getCursor(branch_name_hash)) orelse return error.KeyNotFound;

    // put branch in temp location
    const merge_in_progress_cursor = try state.extra.moment.putCursor(hash.hashBuffer("merge-in-progress"));
    const merge_in_progress = try rp.Repo(.xit).DB.HashMap(.read_write).init(merge_in_progress_cursor);
    var merge_branch_cursor = try merge_in_progress.putCursor(hash.hashBuffer("branch"));
    try merge_branch_cursor.writeIfEmpty(.{ .slot = branch_cursor.slot() });
    const merge_branch = try rp.Repo(.xit).DB.HashMap(.read_write).init(merge_branch_cursor);

    const patch = @import("./patch.zig");

    for (0..patch_ids.items.len) |i| {
        const patch_id = patch_ids.items[patch_ids.items.len - i - 1];
        try patch.applyPatch(state.readOnly().extra.moment, &merge_branch, allocator, path_hash, patch_id);
    }

    const merge_path_to_live_parent_to_children_cursor = (try merge_branch.getCursor(hash.hashBuffer("path->live-parent->children"))) orelse return error.KeyNotFound;
    const merge_path_to_live_parent_to_children = try rp.Repo(.xit).DB.HashMap(.read_only).init(merge_path_to_live_parent_to_children_cursor);
    const merge_live_parent_to_children_cursor = (try merge_path_to_live_parent_to_children.getCursor(path_hash)) orelse return error.KeyNotFound;
    const merge_live_parent_to_children = try rp.Repo(.xit).DB.HashMap(.read_only).init(merge_live_parent_to_children_cursor);

    const commit_id_to_path_to_live_parent_to_children_cursor = (try state.extra.moment.getCursor(hash.hashBuffer("commit-id->path->live-parent->children"))) orelse return error.KeyNotFound;
    const commit_id_to_path_to_live_parent_to_children = try rp.Repo(.xit).DB.HashMap(.read_only).init(commit_id_to_path_to_live_parent_to_children_cursor);

    const base_path_to_live_parent_to_children_cursor = (try commit_id_to_path_to_live_parent_to_children.getCursor(try hash.hexToHash(base_oid))) orelse return error.KeyNotFound;
    const base_path_to_live_parent_to_children = try rp.Repo(.xit).DB.HashMap(.read_only).init(base_path_to_live_parent_to_children_cursor);
    const base_live_parent_to_children_cursor = (try base_path_to_live_parent_to_children.getCursor(path_hash)) orelse return error.KeyNotFound;
    const base_live_parent_to_children = try rp.Repo(.xit).DB.HashMap(.read_only).init(base_live_parent_to_children_cursor);

    const target_path_to_live_parent_to_children_cursor = (try commit_id_to_path_to_live_parent_to_children.getCursor(try hash.hexToHash(target_oid))) orelse return error.KeyNotFound;
    const target_path_to_live_parent_to_children = try rp.Repo(.xit).DB.HashMap(.read_only).init(target_path_to_live_parent_to_children_cursor);
    const target_live_parent_to_children_cursor = (try target_path_to_live_parent_to_children.getCursor(path_hash)) orelse return error.KeyNotFound;
    const target_live_parent_to_children = try rp.Repo(.xit).DB.HashMap(.read_only).init(target_live_parent_to_children_cursor);

    const source_path_to_live_parent_to_children_cursor = (try commit_id_to_path_to_live_parent_to_children.getCursor(try hash.hexToHash(source_oid))) orelse return error.KeyNotFound;
    const source_path_to_live_parent_to_children = try rp.Repo(.xit).DB.HashMap(.read_only).init(source_path_to_live_parent_to_children_cursor);
    const source_live_parent_to_children_cursor = (try source_path_to_live_parent_to_children.getCursor(path_hash)) orelse return error.KeyNotFound;
    const source_live_parent_to_children = try rp.Repo(.xit).DB.HashMap(.read_only).init(source_live_parent_to_children_cursor);

    const patch_id_to_change_content_list_cursor = (try state.extra.moment.getCursor(hash.hashBuffer("patch-id->change-content-list"))) orelse return error.KeyNotFound;
    const patch_id_to_change_content_list = try rp.Repo(.xit).DB.HashMap(.read_only).init(patch_id_to_change_content_list_cursor);

    var line_buffer = std.ArrayList([]const u8).init(allocator);
    defer {
        for (line_buffer.items) |buffer| {
            allocator.free(buffer);
        }
        line_buffer.deinit();
    }

    const LineRange = struct {
        allocator: std.mem.Allocator,
        lines: std.ArrayList([]const u8),

        fn init(alctr: std.mem.Allocator, patch_id_to_change_content_list_ptr: *const rp.Repo(.xit).DB.HashMap(.read_only), node_ids: []patch.NodeId) !@This() {
            var lines = std.ArrayList([]const u8).init(alctr);
            errdefer {
                for (lines.items) |line| {
                    alctr.free(line);
                }
                lines.deinit();
            }
            for (node_ids) |node_id| {
                const change_content_list_cursor = (try patch_id_to_change_content_list_ptr.getCursor(node_id.patch_id)) orelse return error.KeyNotFound;
                const change_content_list = try rp.Repo(.xit).DB.ArrayList(.read_only).init(change_content_list_cursor);
                const change_content_cursor = (try change_content_list.getCursor(node_id.node)) orelse return error.KeyNotFound;
                const change_content = try change_content_cursor.readBytesAlloc(alctr, MAX_READ_BYTES);
                {
                    errdefer alctr.free(change_content);
                    try lines.append(change_content);
                }
            }
            return .{
                .allocator = alctr,
                .lines = lines,
            };
        }

        fn deinit(self: *@This()) void {
            for (self.lines.items) |line| {
                self.allocator.free(line);
            }
            self.lines.deinit();
        }

        fn eql(self: @This(), other: @This()) bool {
            if (self.lines.items.len != other.lines.items.len) {
                return false;
            }
            for (self.lines.items, other.lines.items) |our_line, their_line| {
                if (!std.mem.eql(u8, our_line, their_line)) {
                    return false;
                }
            }
            return true;
        }
    };

    const Stream = struct {
        allocator: std.mem.Allocator,
        target_marker: []u8,
        base_marker: []u8,
        separate_marker: []u8,
        source_marker: []u8,
        merge_live_parent_to_children: *const rp.Repo(.xit).DB.HashMap(.read_only),
        base_live_parent_to_children: *const rp.Repo(.xit).DB.HashMap(.read_only),
        target_live_parent_to_children: *const rp.Repo(.xit).DB.HashMap(.read_only),
        source_live_parent_to_children: *const rp.Repo(.xit).DB.HashMap(.read_only),
        patch_id_to_change_content_list: *const rp.Repo(.xit).DB.HashMap(.read_only),
        line_buffer: *std.ArrayList([]const u8),
        current_line: ?[]const u8,
        current_node_id_hash: ?hash.Hash,
        has_conflict: bool,

        const Parent = @This();

        pub const Reader = struct {
            parent: *Parent,

            pub fn read(self: @This(), buf: []u8) !usize {
                var size: usize = 0;
                while (size < buf.len) {
                    const read_size = try self.readStep(buf[size..]);
                    if (read_size == 0) {
                        break;
                    }
                    size += read_size;
                }
                return size;
            }

            fn readStep(self: @This(), buf: []u8) !usize {
                if (self.parent.current_line) |current_line| {
                    const size = @min(buf.len, current_line.len);
                    var line_finished = current_line.len == 0;
                    if (size > 0) {
                        // copy as much from the current line as we can
                        @memcpy(buf[0..size], current_line[0..size]);
                        const new_current_line = current_line[size..];
                        line_finished = new_current_line.len == 0;
                        self.parent.current_line = new_current_line;
                    }
                    // if we have copied the entire line
                    if (line_finished) {
                        // if there is room for the newline character
                        if (buf.len > size) {
                            // remove the line from the line buffer
                            const line = self.parent.line_buffer.orderedRemove(0);
                            self.parent.allocator.free(line);
                            if (self.parent.line_buffer.items.len > 0) {
                                self.parent.current_line = self.parent.line_buffer.items[0];
                            } else {
                                self.parent.current_line = null;
                            }
                            // if we aren't at the very last line, add a newline character
                            if (self.parent.current_line != null or self.parent.current_node_id_hash != null) {
                                buf[size] = '\n';
                                return size + 1;
                            }
                        }
                    }
                    return size;
                }

                if (self.parent.current_node_id_hash) |current_node_id_hash| {
                    const children_cursor = (try self.parent.merge_live_parent_to_children.getCursor(current_node_id_hash)) orelse return error.KeyNotFound;
                    var children_iter = try children_cursor.iterator();
                    defer children_iter.deinit();

                    const first_child_cursor = (try children_iter.next()) orelse return error.ExpectedChild;
                    const first_kv_pair = try first_child_cursor.readKeyValuePair();
                    var first_child_bytes = [_]u8{0} ** patch.NODE_ID_SIZE;
                    const first_child_slice = try first_kv_pair.key_cursor.readBytes(&first_child_bytes);
                    const first_node_id: patch.NodeId = blk: {
                        var stream = std.io.fixedBufferStream(first_child_slice);
                        var node_id_reader = stream.reader();
                        break :blk @bitCast(try node_id_reader.readInt(patch.NodeIdInt, .big));
                    };
                    const first_node_id_hash = hash.hashBuffer(first_child_slice);

                    if (try children_iter.next()) |second_child_cursor| {
                        if (try children_iter.next() != null) return error.MoreThanTwoChildrenFound;

                        const second_kv_pair = try second_child_cursor.readKeyValuePair();
                        var second_child_bytes = [_]u8{0} ** patch.NODE_ID_SIZE;
                        const second_child_slice = try second_kv_pair.key_cursor.readBytes(&second_child_bytes);
                        const second_node_id: patch.NodeId = blk: {
                            var stream = std.io.fixedBufferStream(second_child_slice);
                            var node_id_reader = stream.reader();
                            break :blk @bitCast(try node_id_reader.readInt(patch.NodeIdInt, .big));
                        };
                        const second_node_id_hash = hash.hashBuffer(second_child_slice);

                        const target_node_id, const target_node_id_hash, const source_node_id, const source_node_id_hash =
                            if (try self.parent.target_live_parent_to_children.getCursor(first_node_id_hash) != null)
                            .{ first_node_id, first_node_id_hash, second_node_id, second_node_id_hash }
                        else
                            .{ second_node_id, second_node_id_hash, first_node_id, first_node_id_hash };

                        var target_node_ids = std.ArrayList(patch.NodeId).init(self.parent.allocator);
                        defer target_node_ids.deinit();

                        var join_node_id_hash_maybe: ?hash.Hash = null;

                        // find the target node ids that aren't in source
                        var next_node_id = target_node_id;
                        var next_node_id_hash = target_node_id_hash;
                        while (try self.parent.target_live_parent_to_children.getCursor(next_node_id_hash)) |next_children_cursor| {
                            if (null == try self.parent.source_live_parent_to_children.getCursor(next_node_id_hash)) {
                                try target_node_ids.append(next_node_id);
                            } else {
                                join_node_id_hash_maybe = next_node_id_hash;
                                break;
                            }
                            var next_children_iter = try next_children_cursor.iterator();
                            defer next_children_iter.deinit();
                            if (try next_children_iter.next()) |next_child_cursor| {
                                if (try next_children_iter.next() != null) return error.ExpectedOneChild;
                                const next_kv_pair = try next_child_cursor.readKeyValuePair();
                                var next_child_bytes = [_]u8{0} ** patch.NODE_ID_SIZE;
                                const next_child_slice = try next_kv_pair.key_cursor.readBytes(&next_child_bytes);
                                next_node_id = blk: {
                                    var stream = std.io.fixedBufferStream(next_child_slice);
                                    var node_id_reader = stream.reader();
                                    break :blk @bitCast(try node_id_reader.readInt(patch.NodeIdInt, .big));
                                };
                                next_node_id_hash = hash.hashBuffer(next_child_slice);
                            } else {
                                break;
                            }
                        }

                        var source_node_ids = std.ArrayList(patch.NodeId).init(self.parent.allocator);
                        defer source_node_ids.deinit();

                        // find the source node ids that aren't in target
                        next_node_id = source_node_id;
                        next_node_id_hash = source_node_id_hash;
                        while (try self.parent.source_live_parent_to_children.getCursor(next_node_id_hash)) |next_children_cursor| {
                            if (null == try self.parent.target_live_parent_to_children.getCursor(next_node_id_hash)) {
                                try source_node_ids.append(next_node_id);
                            } else {
                                if (next_node_id_hash != join_node_id_hash_maybe) return error.ExpectedJoinNode;
                                break;
                            }
                            var next_children_iter = try next_children_cursor.iterator();
                            defer next_children_iter.deinit();
                            if (try next_children_iter.next()) |next_child_cursor| {
                                if (try next_children_iter.next() != null) return error.ExpectedOneChild;
                                const next_kv_pair = try next_child_cursor.readKeyValuePair();
                                var next_child_bytes = [_]u8{0} ** patch.NODE_ID_SIZE;
                                const next_child_slice = try next_kv_pair.key_cursor.readBytes(&next_child_bytes);
                                next_node_id = blk: {
                                    var stream = std.io.fixedBufferStream(next_child_slice);
                                    var node_id_reader = stream.reader();
                                    break :blk @bitCast(try node_id_reader.readInt(patch.NodeIdInt, .big));
                                };
                                next_node_id_hash = hash.hashBuffer(next_child_slice);
                            } else {
                                break;
                            }
                        }

                        var base_node_ids = std.ArrayList(patch.NodeId).init(self.parent.allocator);
                        defer base_node_ids.deinit();

                        // find the base node ids up to (but not including) the join node id if it exists,
                        // or until the end of the file
                        next_node_id_hash = current_node_id_hash;
                        while (try self.parent.base_live_parent_to_children.getCursor(next_node_id_hash)) |next_children_cursor| {
                            var next_children_iter = try next_children_cursor.iterator();
                            defer next_children_iter.deinit();
                            if (try next_children_iter.next()) |next_child_cursor| {
                                if (try next_children_iter.next() != null) return error.ExpectedOneChild;
                                const next_kv_pair = try next_child_cursor.readKeyValuePair();
                                var next_child_bytes = [_]u8{0} ** patch.NODE_ID_SIZE;
                                const next_child_slice = try next_kv_pair.key_cursor.readBytes(&next_child_bytes);
                                next_node_id = blk: {
                                    var stream = std.io.fixedBufferStream(next_child_slice);
                                    var node_id_reader = stream.reader();
                                    break :blk @bitCast(try node_id_reader.readInt(patch.NodeIdInt, .big));
                                };
                                next_node_id_hash = hash.hashBuffer(next_child_slice);
                                if (join_node_id_hash_maybe) |join_node_id_hash| {
                                    if (next_node_id_hash != join_node_id_hash) {
                                        try base_node_ids.append(next_node_id);
                                    } else {
                                        break;
                                    }
                                } else {
                                    try base_node_ids.append(next_node_id);
                                }
                            } else {
                                break;
                            }
                        }

                        // set the current node id to be the parent of the join node id if it exists,
                        // otherwise we're at the end of the file
                        if (join_node_id_hash_maybe) |join_node_id_hash| {
                            if (source_node_ids.items.len == 0) return error.ExpectedAtLeastOneSourceNodeId;
                            const join_parent_node_id = source_node_ids.items[source_node_ids.items.len - 1];
                            var join_parent_bytes = [_]u8{0} ** patch.NODE_ID_SIZE;
                            {
                                var stream = std.io.fixedBufferStream(&join_parent_bytes);
                                var node_id_writer = stream.writer();
                                try node_id_writer.writeInt(patch.NodeIdInt, @bitCast(join_parent_node_id), .big);
                            }
                            const join_parent_node_id_hash = hash.hashBuffer(&join_parent_bytes);
                            self.parent.current_node_id_hash = join_parent_node_id_hash;

                            // TODO: is it actually guaranteed that the join node is in base?
                            if (null == try self.parent.base_live_parent_to_children.getCursor(join_node_id_hash)) return error.ExpectedBaseToContainJoinNode;
                        } else {
                            self.parent.current_node_id_hash = null;
                        }

                        var base_lines = try LineRange.init(self.parent.allocator, self.parent.patch_id_to_change_content_list, base_node_ids.items);
                        defer base_lines.deinit();
                        var target_lines = try LineRange.init(self.parent.allocator, self.parent.patch_id_to_change_content_list, target_node_ids.items);
                        defer target_lines.deinit();
                        var source_lines = try LineRange.init(self.parent.allocator, self.parent.patch_id_to_change_content_list, source_node_ids.items);
                        defer source_lines.deinit();

                        // if base == target or target == source, return source to autoresolve conflict
                        if (base_lines.eql(target_lines) or target_lines.eql(source_lines)) {
                            if (source_lines.lines.items.len > 0) {
                                try self.parent.line_buffer.appendSlice(source_lines.lines.items);
                                self.parent.current_line = self.parent.line_buffer.items[0];
                                source_lines.lines.clearAndFree();
                            }
                            return self.readStep(buf);
                        }
                        // if base == source, return target to autoresolve conflict
                        else if (base_lines.eql(source_lines)) {
                            if (target_lines.lines.items.len > 0) {
                                try self.parent.line_buffer.appendSlice(target_lines.lines.items);
                                self.parent.current_line = self.parent.line_buffer.items[0];
                                target_lines.lines.clearAndFree();
                            }
                            return self.readStep(buf);
                        }

                        // return conflict

                        const target_marker = try self.parent.allocator.dupe(u8, self.parent.target_marker);
                        {
                            errdefer self.parent.allocator.free(target_marker);
                            try self.parent.line_buffer.append(target_marker);
                        }
                        try self.parent.line_buffer.appendSlice(target_lines.lines.items);
                        target_lines.lines.clearAndFree();

                        const base_marker = try self.parent.allocator.dupe(u8, self.parent.base_marker);
                        {
                            errdefer self.parent.allocator.free(base_marker);
                            try self.parent.line_buffer.append(base_marker);
                        }
                        try self.parent.line_buffer.appendSlice(base_lines.lines.items);
                        base_lines.lines.clearAndFree();

                        const separate_marker = try self.parent.allocator.dupe(u8, self.parent.separate_marker);
                        {
                            errdefer self.parent.allocator.free(separate_marker);
                            try self.parent.line_buffer.append(separate_marker);
                        }

                        try self.parent.line_buffer.appendSlice(source_lines.lines.items);
                        source_lines.lines.clearAndFree();
                        const source_marker = try self.parent.allocator.dupe(u8, self.parent.source_marker);
                        {
                            errdefer self.parent.allocator.free(source_marker);
                            try self.parent.line_buffer.append(source_marker);
                        }

                        self.parent.current_line = self.parent.line_buffer.items[0];
                        self.parent.has_conflict = true;
                    } else {
                        const change_content_list_cursor = (try self.parent.patch_id_to_change_content_list.getCursor(first_node_id.patch_id)) orelse return error.KeyNotFound;
                        const change_content_list = try rp.Repo(.xit).DB.ArrayList(.read_only).init(change_content_list_cursor);

                        const change_content_cursor = (try change_content_list.getCursor(first_node_id.node)) orelse return error.KeyNotFound;
                        const change_content = try change_content_cursor.readBytesAlloc(self.parent.allocator, MAX_READ_BYTES);
                        {
                            errdefer self.parent.allocator.free(change_content);
                            try self.parent.line_buffer.append(change_content);
                        }
                        self.parent.current_line = self.parent.line_buffer.items[0];

                        const next_children_cursor = (try self.parent.merge_live_parent_to_children.getCursor(first_node_id_hash)) orelse return error.KeyNotFound;
                        var next_children_iter = try next_children_cursor.iterator();
                        defer next_children_iter.deinit();
                        if (try next_children_iter.next()) |_| {
                            self.parent.current_node_id_hash = first_node_id_hash;
                        } else {
                            self.parent.current_node_id_hash = null;
                        }
                    }
                    return self.readStep(buf);
                } else {
                    return 0;
                }
            }
        };

        pub fn seekTo(self: *@This(), offset: usize) !void {
            if (offset == 0) {
                self.current_node_id_hash = hash.hashBuffer(&patch.FIRST_NODE_ID_BYTES);
            } else {
                return error.InvalidOffset;
            }
        }

        pub fn reader(self: *@This()) Reader {
            return Reader{
                .parent = self,
            };
        }

        pub fn count(self: *@This()) !usize {
            var n: usize = 0;
            var read_buffer = [_]u8{0} ** MAX_READ_BYTES;
            try self.seekTo(0);
            while (true) {
                const size = try self.reader().read(&read_buffer);
                if (size == 0) {
                    break;
                }
                n += size;
            }
            try self.seekTo(0);
            return n;
        }
    };

    const target_marker = try std.fmt.allocPrint(allocator, "<<<<<<< {s}", .{target_name});
    defer allocator.free(target_marker);
    const base_marker = try std.fmt.allocPrint(allocator, "||||||| original ({s})", .{base_oid});
    defer allocator.free(base_marker);
    const separate_marker = try std.fmt.allocPrint(allocator, "=======", .{});
    defer allocator.free(separate_marker);
    const source_marker = try std.fmt.allocPrint(allocator, ">>>>>>> {s}", .{source_name});
    defer allocator.free(source_marker);
    var stream = Stream{
        .allocator = allocator,
        .target_marker = target_marker,
        .base_marker = base_marker,
        .separate_marker = separate_marker,
        .source_marker = source_marker,
        .merge_live_parent_to_children = &merge_live_parent_to_children,
        .base_live_parent_to_children = &base_live_parent_to_children,
        .target_live_parent_to_children = &target_live_parent_to_children,
        .source_live_parent_to_children = &source_live_parent_to_children,
        .patch_id_to_change_content_list = &patch_id_to_change_content_list,
        .line_buffer = &line_buffer,
        .current_line = null,
        .current_node_id_hash = hash.hashBuffer(&patch.FIRST_NODE_ID_BYTES),
        .has_conflict = false,
    };

    var oid = [_]u8{0} ** hash.SHA1_BYTES_LEN;
    try obj.writeObject(.xit, state, &stream, .{ .kind = .blob, .size = try stream.count() }, &oid);
    has_conflict.* = stream.has_conflict;
    return oid;
}

pub const SamePathConflictResult = struct {
    change: ?obj.Change,
    conflict: ?MergeConflict,
};

fn samePathConflict(
    comptime repo_kind: rp.RepoKind,
    state: rp.Repo(repo_kind).State(.read_write),
    allocator: std.mem.Allocator,
    base_oid: *const [hash.SHA1_HEX_LEN]u8,
    target_oid: *const [hash.SHA1_HEX_LEN]u8,
    source_oid: *const [hash.SHA1_HEX_LEN]u8,
    target_name: []const u8,
    source_name: []const u8,
    target_change_maybe: ?obj.Change,
    source_change: obj.Change,
    path: []const u8,
    comptime merge_algo: MergeAlgorithm,
) !SamePathConflictResult {
    if (target_change_maybe) |target_change| {
        const base_entry_maybe = source_change.old;

        if (target_change.new) |target_entry| {
            if (source_change.new) |source_entry| {
                if (target_entry.eql(source_entry)) {
                    // the target and source changes are the same,
                    // so no need to do anything
                    return .{ .change = null, .conflict = null };
                }

                // three-way merge of the oids
                const oid_maybe = blk: {
                    if (std.mem.eql(u8, &target_entry.oid, &source_entry.oid)) {
                        break :blk target_entry.oid;
                    } else if (base_entry_maybe) |base_entry| {
                        if (std.mem.eql(u8, &base_entry.oid, &target_entry.oid)) {
                            break :blk source_entry.oid;
                        } else if (std.mem.eql(u8, &base_entry.oid, &source_entry.oid)) {
                            break :blk target_entry.oid;
                        }
                    }
                    break :blk null;
                };

                // three-way merge of the modes
                const mode_maybe = blk: {
                    if (target_entry.mode.eql(source_entry.mode)) {
                        break :blk target_entry.mode;
                    } else if (base_entry_maybe) |base_entry| {
                        if (base_entry.mode.eql(target_entry.mode)) {
                            break :blk source_entry.mode;
                        } else if (base_entry.mode.eql(source_entry.mode)) {
                            break :blk target_entry.mode;
                        }
                    }
                    break :blk null;
                };

                var has_conflict = oid_maybe == null or mode_maybe == null;

                const base_file_oid_maybe = if (base_entry_maybe) |base_entry| &base_entry.oid else null;
                const oid = oid_maybe orelse switch (merge_algo) {
                    .diff3 => try writeBlobWithDiff3(repo_kind, state, allocator, base_file_oid_maybe, &target_entry.oid, &source_entry.oid, base_oid, target_name, source_name, &has_conflict),
                    .patch => try writeBlobWithPatches(state, allocator, &source_entry.oid, base_oid, target_oid, source_oid, target_name, source_name, &has_conflict, path),
                };
                const mode = mode_maybe orelse target_entry.mode;

                return .{
                    .change = .{
                        .old = target_change.new,
                        .new = .{ .oid = oid, .mode = mode },
                    },
                    .conflict = if (has_conflict)
                        .{
                            .base = base_entry_maybe,
                            .target = target_entry,
                            .source = source_entry,
                            .renamed = null,
                        }
                    else
                        null,
                };
            } else {
                // source is null so just use the target oid and mode
                return .{
                    .change = .{
                        .old = target_change.new,
                        .new = .{ .oid = target_entry.oid, .mode = target_entry.mode },
                    },
                    .conflict = .{
                        .base = base_entry_maybe,
                        .target = target_entry,
                        .source = null,
                        .renamed = null,
                    },
                };
            }
        } else {
            if (source_change.new) |source_entry| {
                // target is null so just use the source oid and mode
                return .{
                    .change = .{
                        .old = target_change.new,
                        .new = .{ .oid = source_entry.oid, .mode = source_entry.mode },
                    },
                    .conflict = .{
                        .base = base_entry_maybe,
                        .target = null,
                        .source = source_entry,
                        .renamed = null,
                    },
                };
            } else {
                // deleted in target and source change,
                // so no need to do anything
                return .{ .change = null, .conflict = null };
            }
        }
    } else {
        // no conflict because the target diff doesn't touch this path
        return .{ .change = source_change, .conflict = null };
    }
}

fn fileDirConflict(
    arena: *std.heap.ArenaAllocator,
    comptime repo_kind: rp.RepoKind,
    path: []const u8,
    diff: *obj.TreeDiff(repo_kind),
    diff_kind: enum { target, source },
    branch_name: []const u8,
    conflicts: *std.StringArrayHashMap(MergeConflict),
    clean_diff: *obj.TreeDiff(repo_kind),
) !void {
    var parent_path_maybe = std.fs.path.dirname(path);
    while (parent_path_maybe) |parent_path| {
        if (diff.changes.get(parent_path)) |change| {
            if (change.new) |new| {
                const new_path = try std.fmt.allocPrint(arena.allocator(), "{s}~{s}", .{ parent_path, branch_name });
                switch (diff_kind) {
                    .target => {
                        // add the conflict
                        try conflicts.put(parent_path, .{
                            .base = change.old,
                            .target = new,
                            .source = null,
                            .renamed = .{
                                .path = new_path,
                                .tree_entry = new,
                            },
                        });
                        // remove from the working tree
                        try clean_diff.changes.put(parent_path, .{ .old = new, .new = null });
                    },
                    .source => {
                        // add the conflict
                        try conflicts.put(parent_path, .{
                            .base = change.old,
                            .target = null,
                            .source = new,
                            .renamed = .{
                                .path = new_path,
                                .tree_entry = new,
                            },
                        });
                        // prevent from being added to working tree
                        _ = clean_diff.changes.swapRemove(parent_path);
                    },
                }
            }
        }
        parent_path_maybe = std.fs.path.dirname(parent_path);
    }
}

pub const MergeKind = enum {
    merge,
    cherry_pick,
};

pub const MergeInput = union(enum) {
    new: struct {
        source_name: []const u8,
    },
    cont,
};

pub const MergeAlgorithm = enum {
    diff3, // three-way merge
    patch, // patch-based (xit only)
};

pub const Merge = struct {
    arena: *std.heap.ArenaAllocator,
    allocator: std.mem.Allocator,
    changes: std.StringArrayHashMap(obj.Change),
    auto_resolved_conflicts: std.StringArrayHashMap(void),
    base_oid: [hash.SHA1_HEX_LEN]u8,
    target_name: []const u8,
    source_name: []const u8,
    data: union(enum) {
        success: struct {
            oid: [hash.SHA1_HEX_LEN]u8,
        },
        nothing,
        fast_forward,
        conflict: struct {
            conflicts: std.StringArrayHashMap(MergeConflict),
        },
    },

    pub fn init(
        comptime repo_kind: rp.RepoKind,
        state: rp.Repo(repo_kind).State(.read_write),
        allocator: std.mem.Allocator,
        merge_input: MergeInput,
        comptime merge_kind: MergeKind,
        comptime merge_algo: MergeAlgorithm,
    ) !Merge {
        // TODO: exit early if working tree is dirty

        const arena = try allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        errdefer {
            arena.deinit();
            allocator.destroy(arena);
        }

        // get the current branch name and oid
        const target_name = try ref.readHeadName(repo_kind, state.readOnly(), arena.allocator());
        const target_oid = try ref.readHead(repo_kind, state.readOnly());

        // init the diff that we will use for the migration and the conflicts maps.
        // they're using the arena because they'll be included in the result.
        var clean_diff = obj.TreeDiff(repo_kind).init(arena.allocator());
        var auto_resolved_conflicts = std.StringArrayHashMap(void).init(arena.allocator());
        var conflicts = std.StringArrayHashMap(MergeConflict).init(arena.allocator());

        switch (merge_input) {
            .new => |new| {
                // make sure there is no stored merge state
                switch (repo_kind) {
                    .git => {
                        const merge_head_name = switch (merge_kind) {
                            .merge => "MERGE_HEAD",
                            .cherry_pick => "CHERRY_PICK_HEAD",
                        };
                        if (state.core.git_dir.openFile(merge_head_name, .{ .mode = .read_only })) |merge_head| {
                            defer merge_head.close();
                            return error.UnfinishedMergeAlreadyInProgress;
                        } else |err| switch (err) {
                            error.FileNotFound => {},
                            else => return err,
                        }
                    },
                    .xit => {
                        if (try state.extra.moment.getCursor(hash.hashBuffer("merge-in-progress"))) |_| {
                            return error.UnfinishedMergeAlreadyInProgress;
                        }
                    },
                }

                // we need to return the source name so copy it into a new buffer
                // so we an ensure it lives as long as the rest of the return struct
                const source_name = try arena.allocator().alloc(u8, new.source_name.len);
                @memcpy(source_name, new.source_name);

                // get the oids for the three-way merge
                const source_oid = try ref.readRecur(repo_kind, state.readOnly(), ref.RefInput.init(source_name)) orelse return error.InvalidTarget;
                var base_oid: [hash.SHA1_HEX_LEN]u8 = undefined;
                switch (merge_kind) {
                    .merge => base_oid = try commonAncestor(repo_kind, allocator, state.readOnly(), &target_oid, &source_oid),
                    .cherry_pick => {
                        var object = try obj.Object(repo_kind, .full).init(allocator, state.readOnly(), &source_oid);
                        defer object.deinit();
                        const parent_oid = if (object.content.commit.parents.items.len == 1) object.content.commit.parents.items[0] else return error.CommitMustHaveOneParent;
                        switch (object.content) {
                            .commit => base_oid = parent_oid,
                            else => return error.NotACommitObject,
                        }
                    },
                }

                // if the base ancestor is the source oid, do nothing
                if (std.mem.eql(u8, &source_oid, &base_oid)) {
                    return .{
                        .arena = arena,
                        .allocator = allocator,
                        .changes = clean_diff.changes,
                        .auto_resolved_conflicts = auto_resolved_conflicts,
                        .base_oid = base_oid,
                        .target_name = target_name,
                        .source_name = source_name,
                        .data = .nothing,
                    };
                }

                // diff the base ancestor with the target oid
                var target_diff = obj.TreeDiff(repo_kind).init(arena.allocator());
                try target_diff.compare(state.readOnly(), base_oid, target_oid, null);

                // diff the base ancestor with the source oid
                var source_diff = obj.TreeDiff(repo_kind).init(arena.allocator());
                try source_diff.compare(state.readOnly(), base_oid, source_oid, null);

                // look for same path conflicts while populating the clean diff
                for (source_diff.changes.keys(), source_diff.changes.values()) |path, source_change| {
                    const same_path_result = try samePathConflict(repo_kind, state, allocator, &base_oid, &target_oid, &source_oid, target_name, source_name, target_diff.changes.get(path), source_change, path, merge_algo);
                    if (same_path_result.change) |change| {
                        try clean_diff.changes.put(path, change);
                    }
                    if (same_path_result.conflict) |conflict| {
                        try conflicts.put(path, conflict);
                    } else {
                        try auto_resolved_conflicts.put(path, {});
                    }
                }

                // look for file/dir conflicts
                for (source_diff.changes.keys(), source_diff.changes.values()) |path, source_change| {
                    if (source_change.new) |_| {
                        try fileDirConflict(arena, repo_kind, path, &target_diff, .target, target_name, &conflicts, &clean_diff);
                    }
                }
                for (target_diff.changes.keys(), target_diff.changes.values()) |path, target_change| {
                    if (target_change.new) |_| {
                        try fileDirConflict(arena, repo_kind, path, &source_diff, .source, source_name, &conflicts, &clean_diff);
                    }
                }

                // create commit message
                const commit_metadata: obj.CommitMetadata = switch (merge_kind) {
                    .merge => .{
                        .message = try std.fmt.allocPrint(arena.allocator(), "merge from {s}", .{source_name}),
                    },
                    .cherry_pick => blk: {
                        const object = try obj.Object(repo_kind, .full).init(arena.allocator(), state.readOnly(), &source_oid);
                        switch (object.content) {
                            .commit => break :blk object.content.commit.metadata,
                            else => return error.NotACommitObject,
                        }
                    },
                };

                switch (repo_kind) {
                    .git => {
                        // create lock file
                        var lock = try io.LockFile.init(state.core.git_dir, "index");
                        defer lock.deinit();

                        // read index
                        var index = try idx.Index(repo_kind).init(allocator, state.readOnly());
                        defer index.deinit();

                        // update the working tree
                        try cht.migrate(repo_kind, state, allocator, clean_diff, &index, null);

                        for (conflicts.keys(), conflicts.values()) |path, conflict| {
                            // add conflict to index
                            try index.addConflictEntries(path, .{ conflict.base, conflict.target, conflict.source });
                            // write renamed file if necessary
                            if (conflict.renamed) |renamed| {
                                try cht.objectToFile(repo_kind, state.readOnly(), allocator, renamed.path, renamed.tree_entry);
                            }
                        }

                        // update the index
                        try index.write(allocator, .{ .core = state.core, .extra = .{ .lock_file_maybe = lock.lock_file } });

                        // finish lock
                        lock.success = true;

                        // exit early if there were conflicts
                        if (conflicts.count() > 0) {
                            const merge_head_name = switch (merge_kind) {
                                .merge => "MERGE_HEAD",
                                .cherry_pick => "CHERRY_PICK_HEAD",
                            };
                            const merge_head = try state.core.git_dir.createFile(merge_head_name, .{ .truncate = true, .lock = .exclusive });
                            defer merge_head.close();
                            try merge_head.writeAll(&source_oid);

                            const merge_msg = try state.core.git_dir.createFile("MERGE_MSG", .{ .truncate = true, .lock = .exclusive });
                            defer merge_msg.close();
                            try merge_msg.writeAll(commit_metadata.message);

                            return .{
                                .arena = arena,
                                .allocator = allocator,
                                .changes = clean_diff.changes,
                                .auto_resolved_conflicts = auto_resolved_conflicts,
                                .base_oid = base_oid,
                                .target_name = target_name,
                                .source_name = source_name,
                                .data = .{ .conflict = .{ .conflicts = conflicts } },
                            };
                        }
                    },
                    .xit => {
                        // read index
                        var index = try idx.Index(repo_kind).init(allocator, state.readOnly());
                        defer index.deinit();

                        // update the working tree
                        try cht.migrate(repo_kind, state, allocator, clean_diff, &index, null);

                        for (conflicts.keys(), conflicts.values()) |path, conflict| {
                            // add conflict to index
                            try index.addConflictEntries(path, .{ conflict.base, conflict.target, conflict.source });
                            // write renamed file if necessary
                            if (conflict.renamed) |renamed| {
                                try cht.objectToFile(repo_kind, state.readOnly(), allocator, renamed.path, renamed.tree_entry);
                            }
                        }

                        // add conflicts to index
                        for (conflicts.keys(), conflicts.values()) |path, conflict| {
                            try index.addConflictEntries(path, .{ conflict.base, conflict.target, conflict.source });
                        }

                        // update the index
                        try index.write(allocator, state);

                        // exit early if there were conflicts
                        if (conflicts.count() > 0) {
                            const merge_in_progress_cursor = try state.extra.moment.putCursor(hash.hashBuffer("merge-in-progress"));
                            const merge_in_progress = try rp.Repo(.xit).DB.HashMap(.read_write).init(merge_in_progress_cursor);

                            var merge_head_cursor = try merge_in_progress.putCursor(hash.hashBuffer("source-oid"));
                            try merge_head_cursor.write(.{ .bytes = &source_oid });

                            var message_cursor = try merge_in_progress.putCursor(hash.hashBuffer("message"));
                            try message_cursor.write(.{ .bytes = commit_metadata.message });

                            return .{
                                .arena = arena,
                                .allocator = allocator,
                                .changes = clean_diff.changes,
                                .auto_resolved_conflicts = auto_resolved_conflicts,
                                .base_oid = base_oid,
                                .target_name = target_name,
                                .source_name = source_name,
                                .data = .{ .conflict = .{ .conflicts = conflicts } },
                            };
                        } else {
                            // if any file conflicts were auto-resolved, there will be temporary state that must be cleaned up
                            _ = try state.extra.moment.remove(hash.hashBuffer("merge-in-progress"));
                        }
                    },
                }

                if (std.mem.eql(u8, &target_oid, &base_oid)) {
                    // the base ancestor is the target oid, so just update HEAD
                    try ref.updateRecur(repo_kind, state, allocator, &.{"HEAD"}, &source_oid);
                    return .{
                        .arena = arena,
                        .allocator = allocator,
                        .changes = clean_diff.changes,
                        .auto_resolved_conflicts = auto_resolved_conflicts,
                        .base_oid = base_oid,
                        .target_name = target_name,
                        .source_name = source_name,
                        .data = .fast_forward,
                    };
                }

                // commit the change
                const parent_oids = switch (merge_kind) {
                    .merge => &.{ target_oid, source_oid },
                    .cherry_pick => &.{base_oid},
                };
                const commit_oid = try obj.writeCommit(repo_kind, state, allocator, parent_oids, commit_metadata);

                return .{
                    .arena = arena,
                    .allocator = allocator,
                    .changes = clean_diff.changes,
                    .auto_resolved_conflicts = auto_resolved_conflicts,
                    .base_oid = base_oid,
                    .target_name = target_name,
                    .source_name = source_name,
                    .data = .{ .success = .{ .oid = commit_oid } },
                };
            },
            .cont => {
                // ensure there are no conflict entries in the index
                {
                    var index = try idx.Index(repo_kind).init(allocator, state.readOnly());
                    defer index.deinit();

                    for (index.entries.values()) |*entries_for_path| {
                        if (null == entries_for_path[0]) {
                            return error.CannotContinueMergeWithUnresolvedConflicts;
                        }
                    }
                }

                var source_oid: [hash.SHA1_HEX_LEN]u8 = undefined;
                var commit_metadata = obj.CommitMetadata{};

                // read the stored merge state
                switch (repo_kind) {
                    .git => {
                        const merge_head_name = switch (merge_kind) {
                            .merge => "MERGE_HEAD",
                            .cherry_pick => "CHERRY_PICK_HEAD",
                        };
                        const merge_head = state.core.git_dir.openFile(merge_head_name, .{ .mode = .read_only }) catch |err| switch (err) {
                            error.FileNotFound => return error.MergeHeadNotFound,
                            else => return err,
                        };
                        defer merge_head.close();
                        const merge_head_len = try merge_head.readAll(&source_oid);
                        if (merge_head_len != source_oid.len) {
                            return error.InvalidMergeHead;
                        }

                        const merge_msg = state.core.git_dir.openFile("MERGE_MSG", .{ .mode = .read_only }) catch |err| switch (err) {
                            error.FileNotFound => return error.MergeMessageNotFound,
                            else => return err,
                        };
                        defer merge_msg.close();
                        commit_metadata.message = try merge_msg.readToEndAlloc(arena.allocator(), MAX_READ_BYTES);
                    },
                    .xit => {
                        const merge_in_progress_cursor = try state.extra.moment.putCursor(hash.hashBuffer("merge-in-progress"));
                        const merge_in_progress = try rp.Repo(.xit).DB.HashMap(.read_write).init(merge_in_progress_cursor);

                        const source_oid_cursor = (try merge_in_progress.getCursor(hash.hashBuffer("source-oid"))) orelse return error.MergeHeadNotFound;
                        const source_oid_slice = try source_oid_cursor.readBytes(&source_oid);
                        if (source_oid_slice.len != source_oid.len) {
                            return error.InvalidMergeHead;
                        }

                        const message_cursor = (try merge_in_progress.getCursor(hash.hashBuffer("message"))) orelse return error.MergeMessageNotFound;
                        commit_metadata.message = try message_cursor.readBytesAlloc(arena.allocator(), MAX_READ_BYTES);
                    },
                }

                // we need to return the source name but we don't have it,
                // so just copy the source oid into a buffer and return that instead
                const source_name = try arena.allocator().alloc(u8, source_oid.len);
                @memcpy(source_name, &source_oid);

                // get the base oid
                var base_oid: [hash.SHA1_HEX_LEN]u8 = undefined;
                switch (merge_kind) {
                    .merge => base_oid = try commonAncestor(repo_kind, allocator, state.readOnly(), &target_oid, &source_oid),
                    .cherry_pick => {
                        var object = try obj.Object(repo_kind, .full).init(allocator, state.readOnly(), &source_oid);
                        defer object.deinit();
                        const parent_oid = if (object.content.commit.parents.items.len == 1) object.content.commit.parents.items[0] else return error.CommitMustHaveOneParent;
                        switch (object.content) {
                            .commit => base_oid = parent_oid,
                            else => return error.NotACommitObject,
                        }
                    },
                }

                // commit the change
                const parent_oids = switch (merge_kind) {
                    .merge => &.{ target_oid, source_oid },
                    .cherry_pick => &.{base_oid},
                };
                const commit_oid = try obj.writeCommit(repo_kind, state, allocator, parent_oids, commit_metadata);

                // clean up the stored merge state
                switch (repo_kind) {
                    .git => {
                        const merge_head_name = switch (merge_kind) {
                            .merge => "MERGE_HEAD",
                            .cherry_pick => "CHERRY_PICK_HEAD",
                        };
                        try state.core.git_dir.deleteFile(merge_head_name);
                        try state.core.git_dir.deleteFile("MERGE_MSG");
                    },
                    .xit => {
                        _ = try state.extra.moment.remove(hash.hashBuffer("merge-in-progress"));
                    },
                }

                return .{
                    .arena = arena,
                    .allocator = allocator,
                    .changes = clean_diff.changes,
                    .auto_resolved_conflicts = auto_resolved_conflicts,
                    .base_oid = base_oid,
                    .target_name = target_name,
                    .source_name = source_name,
                    .data = .{ .success = .{ .oid = commit_oid } },
                };
            },
        }
    }

    pub fn deinit(self: *Merge) void {
        self.arena.deinit();
        self.allocator.destroy(self.arena);
    }
};
