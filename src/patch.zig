const std = @import("std");
const xitdb = @import("xitdb");
const rp = @import("./repo.zig");
const hash = @import("./hash.zig");
const st = @import("./status.zig");
const df = @import("./diff.zig");

pub const NodeId = struct {
    patch_id: [hash.SHA1_BYTES_LEN]u8,
    node: u64,
};

pub const ChangeKind = enum(u8) {
    new_node = 0,
    delete_node = 1,
    new_edge = 2,
};

pub const Change = union(ChangeKind) {
    new_node: struct {
        id: NodeId,
        contents: []const u8,
    },
    delete_node: struct {
        id: NodeId,
    },
    new_edge: struct {
        src: NodeId,
        dest: NodeId,
    },
};

fn writePatchChange(comptime repo_kind: rp.RepoKind, edit: df.MyersDiffIterator(repo_kind).Edit, writer: anytype) !void {
    switch (edit) {
        .eql => {},
        .ins => {
            try writer.writeInt(u8, @intFromEnum(ChangeKind.new_node), .big);
            try writer.writeInt(u64, edit.ins.new_line.num, .big);
            try writer.writeInt(u64, edit.ins.new_line.text.len, .big);
            try writer.writeAll(edit.ins.new_line.text);
        },
        .del => {
            try writer.writeInt(u8, @intFromEnum(ChangeKind.delete_node), .big);
            try writer.writeInt(u64, edit.del.old_line.num, .big);
        },
    }
}

pub fn writePatches(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator) !void {
    comptime std.debug.assert(repo_kind == .xit);

    var file_iter = blk: {
        var stat = try st.Status(repo_kind).init(allocator, core_cursor);
        errdefer stat.deinit();
        break :blk try df.FileIterator(repo_kind).init(allocator, core_cursor.core, .index, stat);
    };
    defer file_iter.deinit();

    while (try file_iter.next()) |*hunk_iter_ptr| {
        var hunk_iter = hunk_iter_ptr.*;
        defer hunk_iter.deinit();

        // generate hash of the patch
        var h = std.crypto.hash.Sha1.init(.{});
        while (try hunk_iter.next()) |*hunk_ptr| {
            var hunk = hunk_ptr.*;
            defer hunk.deinit();
            for (hunk.edits.items) |edit| {
                var entry_buffer = std.ArrayList(u8).init(allocator);
                defer entry_buffer.deinit();
                try writePatchChange(repo_kind, edit, entry_buffer.writer());
                h.update(entry_buffer.items);
            }
        }
        var patch_hash = [_]u8{0} ** hash.SHA1_BYTES_LEN;
        h.final(&patch_hash);

        var writer = try core_cursor.cursor.writer(void, &[_]xitdb.PathPart(void){
            .{ .hash_map_get = hash.hashBuffer("patches") },
            .hash_map_create,
            .{ .hash_map_get = hash.bytesToHash(&patch_hash) },
        });

        // write header
        try writer.writeAll(&patch_hash);
        try writer.writeInt(u64, hunk_iter.path.len, .big);
        try writer.writeAll(hunk_iter.path);

        // write the edits
        try hunk_iter.reset();
        while (try hunk_iter.next()) |*hunk_ptr| {
            var hunk = hunk_ptr.*;
            defer hunk.deinit();
            for (hunk.edits.items) |edit| {
                try writePatchChange(repo_kind, edit, &writer);
            }
        }

        try writer.finish();
    }
}
