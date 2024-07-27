const std = @import("std");
const xitdb = @import("xitdb");
const rp = @import("./repo.zig");
const hash = @import("./hash.zig");
const st = @import("./status.zig");
const df = @import("./diff.zig");

const MAX_READ_BYTES = 1024; // FIXME: this is arbitrary...

const NodeIdInt = u224;
const NodeId = packed struct {
    node: u64,
    patch_id: xitdb.Hash,
};

const ChangeKind = enum(u8) {
    new_node = 0,
    delete_node = 1,
    new_edge = 2,
};

const Change = union(ChangeKind) {
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

pub fn patchHash(comptime repo_kind: rp.RepoKind, allocator: std.mem.Allocator, myers_diff_iter: *df.MyersDiffIterator(repo_kind)) !xitdb.Hash {
    var h = std.crypto.hash.Sha1.init(.{});
    while (try myers_diff_iter.next()) |edit| {
        defer edit.deinit(allocator);

        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();
        var writer = buffer.writer();

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
                // TODO: store the node id of the line deleted at edit.del.old_line.num
            },
        }

        h.update(buffer.items);
    }
    try myers_diff_iter.reset();

    var patch_hash = [_]u8{0} ** hash.SHA1_BYTES_LEN;
    h.final(&patch_hash);
    return hash.hashBuffer(&patch_hash);
}

pub fn writePatchForFile(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator, line_iter_pair: *df.LineIteratorPair(repo_kind)) !xitdb.Hash {
    var myers_diff_iter = try df.MyersDiffIterator(repo_kind).init(allocator, &line_iter_pair.a, &line_iter_pair.b);
    defer myers_diff_iter.deinit();

    const patch_hash = try patchHash(repo_kind, allocator, &myers_diff_iter);

    // exit early if patch already exists
    if (try core_cursor.cursor.readPath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("change-lists") } },
        .{ .hash_map_get = .{ .key = patch_hash } },
    })) |_| {
        return patch_hash;
    }

    // init change set
    var change_list_cursor = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("change-lists") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = patch_hash } },
        .array_list_init,
    });
    var change_content_list_cursor = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("change-lists") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .value = patch_hash } },
        .array_list_init,
    });

    // get path slot
    const path_hash = hash.hashBuffer(line_iter_pair.path);
    var path_cursor = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path-set") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = path_hash } },
    });
    try path_cursor.writeBytes(line_iter_pair.path, .once);
    const path_slot = path_cursor.slot_ptr.slot;

    // init node set
    _ = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("node-sets") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = path_hash } },
        .{ .write = .{ .slot = path_slot } },
    });
    var node_set_cursor = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("node-sets") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .value = path_hash } },
        .hash_map_init,
    });

    var new_node_count: u64 = 0;
    const LastNodeId = struct {
        id: NodeId,
        origin: enum { old, new },
    };
    var last_node_maybe: ?LastNodeId = null;

    while (try myers_diff_iter.next()) |edit| {
        defer edit.deinit(allocator);

        var patch_entries = std.ArrayList([]const u8).init(allocator);
        defer patch_entries.deinit();

        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        switch (edit) {
            .eql => {},
            .ins => {
                {
                    var buffer = std.ArrayList(u8).init(arena.allocator());
                    try buffer.writer().writeInt(u8, @intFromEnum(ChangeKind.new_node), .big);
                    try buffer.writer().writeInt(u64, new_node_count, .big);
                    try patch_entries.append(buffer.items);
                }

                const node_id = NodeId{
                    .node = new_node_count,
                    .patch_id = patch_hash,
                };
                if (last_node_maybe) |last_node| {
                    var buffer = std.ArrayList(u8).init(arena.allocator());
                    try buffer.writer().writeInt(u8, @intFromEnum(ChangeKind.new_edge), .big);
                    try buffer.writer().writeInt(NodeIdInt, @bitCast(last_node.id), .big); // src
                    try buffer.writer().writeInt(NodeIdInt, @bitCast(node_id), .big); // dest
                    try patch_entries.append(buffer.items);
                }
                last_node_maybe = .{ .id = node_id, .origin = .new };

                // put content from new node in the value
                _ = try change_content_list_cursor.writePath(void, &[_]xitdb.PathPart(void){
                    .{ .array_list_get = .append },
                    .{ .write = .{ .bytes = edit.ins.new_line.text } },
                });

                // add node id to node-sets
                var node_id_buffer = std.ArrayList(u8).init(allocator);
                defer node_id_buffer.deinit();
                var node_id_writer = node_id_buffer.writer();
                try node_id_writer.writeInt(NodeIdInt, @bitCast(NodeId{ .patch_id = patch_hash, .node = new_node_count }), .big);
                const node_id_hash = hash.hashBuffer(node_id_buffer.items);
                _ = try node_set_cursor.writePath(void, &[_]xitdb.PathPart(void){
                    .{ .hash_map_get = .{ .key = node_id_hash } },
                    .{ .write = .{ .bytes = node_id_buffer.items } },
                });

                new_node_count += 1;
            },
            .del => {
                var buffer = std.ArrayList(u8).init(arena.allocator());
                try buffer.writer().writeInt(u8, @intFromEnum(ChangeKind.delete_node), .big);
                // TODO: store the node id of the line deleted at edit.del.old_line.num
                try patch_entries.append(buffer.items);
            },
        }

        // put changes in the key
        for (patch_entries.items) |entry| {
            _ = try change_list_cursor.writePath(void, &[_]xitdb.PathPart(void){
                .{ .array_list_get = .append },
                .{ .write = .{ .bytes = entry } },
            });
        }
    }

    return patch_hash;
}

pub fn applyPatchForFile(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator, patch_hash: xitdb.Hash) !void {
    var change_list_cursor = (try core_cursor.cursor.readPath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("change-lists") } },
        .{ .hash_map_get = .{ .key = patch_hash } },
    })) orelse return error.PatchNotFound;

    var iter = try change_list_cursor.iter();
    while (try iter.next()) |*next_cursor| {
        const change_buffer = try next_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(change_buffer);

        var stream = std.io.fixedBufferStream(change_buffer);
        var reader = stream.reader();
        const change_kind = try reader.readInt(u8, .big);
        switch (try std.meta.intToEnum(ChangeKind, change_kind)) {
            .new_node => {
                const node = try reader.readInt(u64, .big);
                _ = node;
            },
            .delete_node => {},
            .new_edge => {
                const src_node_id = try reader.readInt(NodeIdInt, .big);
                _ = src_node_id;
                const dest_node_id = try reader.readInt(NodeIdInt, .big);
                _ = dest_node_id;
            },
        }
    }
}

pub fn writePatch(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator) !void {
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
        const patch_hash = try writePatchForFile(repo_kind, core_cursor, allocator, &line_iter_pair);
        try applyPatchForFile(repo_kind, core_cursor, allocator, patch_hash);
    }
}
