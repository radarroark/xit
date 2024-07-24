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

pub fn patchHash(comptime repo_kind: rp.RepoKind, allocator: std.mem.Allocator, myers_diff_iter: *df.MyersDiffIterator(repo_kind)) ![hash.SHA1_BYTES_LEN]u8 {
    var h = std.crypto.hash.Sha1.init(.{});
    while (try myers_diff_iter.next()) |edit| {
        defer edit.deinit(allocator);
        var entry_buffer = std.ArrayList(u8).init(allocator);
        defer entry_buffer.deinit();
        var writer = entry_buffer.writer();

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

        h.update(entry_buffer.items);
    }
    try myers_diff_iter.reset();

    var patch_hash = [_]u8{0} ** hash.SHA1_BYTES_LEN;
    h.final(&patch_hash);
    return patch_hash;
}

pub fn writePatchesForFile(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator, line_iter_pair: *df.LineIteratorPair(repo_kind)) !void {
    var myers_diff_iter = try df.MyersDiffIterator(repo_kind).init(allocator, &line_iter_pair.a, &line_iter_pair.b);
    defer myers_diff_iter.deinit();

    const patch_hash = try patchHash(repo_kind, allocator, &myers_diff_iter);

    // exit early if patch already exists
    if (try core_cursor.cursor.readCursor(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("patches") } },
        .{ .hash_map_get = .{ .key = hash.bytesToHash(&patch_hash) } },
    })) |_| {
        return;
    }

    var new_node_count: u64 = 0;

    while (try myers_diff_iter.next()) |edit| {
        defer edit.deinit(allocator);
        var entry_buffer = std.ArrayList(u8).init(allocator);
        defer entry_buffer.deinit();
        var writer = entry_buffer.writer();

        switch (edit) {
            .eql => {},
            .ins => {
                try writer.writeInt(u8, @intFromEnum(ChangeKind.new_node), .big);
                try writer.writeInt(u64, new_node_count, .big);
            },
            .del => {
                try writer.writeInt(u8, @intFromEnum(ChangeKind.delete_node), .big);
                try writer.writeInt(u64, edit.del.old_line.num, .big);
            },
        }

        // put change list in the key
        _ = try core_cursor.cursor.readSlot(.read_write, void, &[_]xitdb.PathPart(void){
            .{ .hash_map_get = .{ .value = hash.hashBuffer("patches") } },
            .hash_map_create,
            .{ .hash_map_get = .{ .key = hash.bytesToHash(&patch_hash) } },
            .array_list_create,
            .{ .array_list_get = .append },
            .{ .write = .{ .bytes = entry_buffer.items } },
        });

        // put content list in the value
        if (edit == .ins) {
            _ = try core_cursor.cursor.readSlot(.read_write, void, &[_]xitdb.PathPart(void){
                .{ .hash_map_get = .{ .value = hash.hashBuffer("patches") } },
                .hash_map_create,
                .{ .hash_map_get = .{ .value = hash.bytesToHash(&patch_hash) } },
                .array_list_create,
                .{ .array_list_get = .append },
                .{ .write = .{ .bytes = edit.ins.new_line.text } },
            });

            new_node_count += 1;
        }
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

    while (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();
        try writePatchesForFile(repo_kind, core_cursor, allocator, &line_iter_pair);
    }
}
