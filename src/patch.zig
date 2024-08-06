const std = @import("std");
const xitdb = @import("xitdb");
const rp = @import("./repo.zig");
const hash = @import("./hash.zig");
const st = @import("./status.zig");
const df = @import("./diff.zig");
const ref = @import("./ref.zig");

const MAX_READ_BYTES = 1024; // FIXME: this is arbitrary...

const NodeIdInt = u224;
const NodeId = packed struct {
    node: u64,
    patch_id: xitdb.Hash,
};

// reordering is a breaking change
const ChangeKind = enum(u8) {
    new_node,
    delete_node,
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

    // get path slot
    const path_hash = hash.hashBuffer(line_iter_pair.path);
    var path_cursor = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path-set") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = path_hash } },
    });
    try path_cursor.writeBytes(line_iter_pair.path, .once);
    const path_slot = path_cursor.slot_ptr.slot;

    // exit early if patch already exists
    if (try core_cursor.cursor.readPath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->patch-id->change-list") } },
        .{ .hash_map_get = .{ .value = path_hash } },
        .{ .hash_map_get = .{ .key = patch_hash } },
    })) |_| {
        return patch_hash;
    }

    // init change set
    var change_list = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->patch-id->change-list") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .value = path_hash } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = patch_hash } },
        .array_list_init,
    });
    var change_content_list = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->patch-id->change-list") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .value = path_hash } },
        .hash_map_init,
        .{ .hash_map_get = .{ .value = patch_hash } },
        .array_list_init,
    });

    // init node list
    _ = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->node-id-list") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = path_hash } },
        .{ .write = .{ .slot = path_slot } },
    });
    const node_list_maybe = try core_cursor.cursor.readPath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->node-id-list") } },
        .{ .hash_map_get = .{ .value = path_hash } },
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
                    if (last_node_maybe) |last_node| {
                        try buffer.writer().writeInt(NodeIdInt, @bitCast(last_node.id), .big);
                    }
                    try patch_entries.append(buffer.items);
                }

                const node_id = NodeId{
                    .node = new_node_count,
                    .patch_id = patch_hash,
                };
                last_node_maybe = .{ .id = node_id, .origin = .new };

                // put content from new node in the value
                _ = try change_content_list.writePath(void, &[_]xitdb.PathPart(void){
                    .{ .array_list_get = .append },
                    .{ .write = .{ .bytes = edit.ins.new_line.text } },
                });

                new_node_count += 1;
            },
            .del => {
                var buffer = std.ArrayList(u8).init(arena.allocator());
                try buffer.writer().writeInt(u8, @intFromEnum(ChangeKind.delete_node), .big);

                const node_list = node_list_maybe orelse return error.NodeListNotFound;
                const node_id_cursor = (try node_list.readPath(void, &[_]xitdb.PathPart(void){
                    .{ .array_list_get = .{ .index = edit.del.old_line.num - 1 } },
                })) orelse return error.ExpectedNode;

                const node_id_bytes = try node_id_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
                defer allocator.free(node_id_bytes);

                var stream = std.io.fixedBufferStream(node_id_bytes);
                var reader = stream.reader();
                const node_id: NodeId = @bitCast(try reader.readInt(NodeIdInt, .big));

                try buffer.writer().writeInt(NodeIdInt, @bitCast(node_id), .big);

                try patch_entries.append(buffer.items);
            },
        }

        // put changes in the key
        for (patch_entries.items) |entry| {
            _ = try change_list.writePath(void, &[_]xitdb.PathPart(void){
                .{ .array_list_get = .append },
                .{ .write = .{ .bytes = entry } },
            });
        }
    }

    return patch_hash;
}

pub fn applyPatchForFile(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator, patch_hash: xitdb.Hash, path: []const u8) !void {
    // get path slot
    const path_hash = hash.hashBuffer(path);
    var path_cursor = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path-set") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = path_hash } },
    });
    try path_cursor.writeBytes(path, .once);
    const path_slot = path_cursor.slot_ptr.slot;

    var change_list = (try core_cursor.cursor.readPath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->patch-id->change-list") } },
        .{ .hash_map_get = .{ .value = path_hash } },
        .{ .hash_map_get = .{ .key = patch_hash } },
    })) orelse return error.PatchNotFound;

    // init parent->children node map
    _ = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->parent->children") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = path_hash } },
        .{ .write = .{ .slot = path_slot } },
    });
    var parent_to_children = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->parent->children") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .value = path_hash } },
        .hash_map_init,
    });

    // init child->parent node map
    _ = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->child->parent") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = path_hash } },
        .{ .write = .{ .slot = path_slot } },
    });
    var child_to_parent = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->child->parent") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .value = path_hash } },
        .hash_map_init,
    });

    const first_node_id: NodeId = @bitCast(@as(NodeIdInt, 0));

    var iter = try change_list.iter();
    defer iter.deinit();
    while (try iter.next()) |*next_cursor| {
        const change_buffer = try next_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(change_buffer);

        var stream = std.io.fixedBufferStream(change_buffer);
        var reader = stream.reader();
        const change_kind = try reader.readInt(u8, .big);
        switch (try std.meta.intToEnum(ChangeKind, change_kind)) {
            .new_node => {
                const node = try reader.readInt(u64, .big);
                const node_id = NodeId{ .patch_id = patch_hash, .node = node };
                const parent_node_id: NodeId = if (try stream.getPos() == try stream.getEndPos())
                    first_node_id
                else
                    @bitCast(try reader.readInt(NodeIdInt, .big));

                var node_id_buffer = std.ArrayList(u8).init(allocator);
                defer node_id_buffer.deinit();
                var node_id_writer = node_id_buffer.writer();
                try node_id_writer.writeInt(NodeIdInt, @bitCast(node_id), .big);
                const node_id_hash = hash.hashBuffer(node_id_buffer.items);

                var parent_node_id_buffer = std.ArrayList(u8).init(allocator);
                defer parent_node_id_buffer.deinit();
                var parent_node_id_writer = parent_node_id_buffer.writer();
                try parent_node_id_writer.writeInt(NodeIdInt, @bitCast(parent_node_id), .big);
                const parent_node_id_hash = hash.hashBuffer(parent_node_id_buffer.items);

                _ = try parent_to_children.writePath(void, &[_]xitdb.PathPart(void){
                    .{ .hash_map_get = .{ .value = parent_node_id_hash } },
                    .hash_map_init,
                    .{ .hash_map_get = .{ .key = node_id_hash } },
                    .{ .write = .{ .bytes = node_id_buffer.items } },
                });

                _ = try child_to_parent.writePath(void, &[_]xitdb.PathPart(void){
                    .{ .hash_map_get = .{ .value = node_id_hash } },
                    .{ .write = .{ .bytes = parent_node_id_buffer.items } },
                });
            },
            .delete_node => {
                const node_id: NodeId = @bitCast(try reader.readInt(NodeIdInt, .big));

                var node_id_buffer = std.ArrayList(u8).init(allocator);
                defer node_id_buffer.deinit();
                var node_id_writer = node_id_buffer.writer();
                try node_id_writer.writeInt(NodeIdInt, @bitCast(node_id), .big);
                const node_id_hash = hash.hashBuffer(node_id_buffer.items);

                var parent_cursor = (try child_to_parent.readPath(void, &[_]xitdb.PathPart(void){
                    .{ .hash_map_get = .{ .value = node_id_hash } },
                })) orelse return error.ExpectedParentNode;

                const parent_node_id_bytes = try parent_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
                defer allocator.free(parent_node_id_bytes);
                const parent_node_id_hash = hash.hashBuffer(parent_node_id_bytes);

                _ = try parent_to_children.writePath(void, &[_]xitdb.PathPart(void){
                    .{ .hash_map_get = .{ .value = parent_node_id_hash } },
                    .{ .hash_map_remove = node_id_hash },
                });
            },
        }
    }

    // init node list
    _ = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->node-id-list") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = path_hash } },
        .{ .write = .{ .slot = path_slot } },
    });
    var node_list = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->node-id-list") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .value = path_hash } },
        // create a new array list every time for now
        .{ .write = .none },
        .array_list_init,
    });

    var current_node_id = first_node_id;

    while (true) {
        var node_id_buffer = std.ArrayList(u8).init(allocator);
        defer node_id_buffer.deinit();
        var node_id_writer = node_id_buffer.writer();
        try node_id_writer.writeInt(NodeIdInt, @bitCast(current_node_id), .big);
        const node_id_hash = hash.hashBuffer(node_id_buffer.items);

        if (try parent_to_children.readPath(void, &[_]xitdb.PathPart(void){
            .{ .hash_map_get = .{ .value = node_id_hash } },
        })) |child_node_id_set| {
            var count: usize = 0;
            {
                var child_node_id_iter = try child_node_id_set.iter();
                defer child_node_id_iter.deinit();
                while (try child_node_id_iter.next()) |_| {
                    count += 1;
                }
            }

            if (count != 1) {
                // remove node list because there is a conflict, and thus
                // the node map cannot be "flattened" into a list
                _ = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
                    .{ .hash_map_get = .{ .value = hash.hashBuffer("path->node-id-list") } },
                    .hash_map_init,
                    .{ .hash_map_get = .{ .value = path_hash } },
                    .{ .write = .none },
                });
                break;
            } else {
                var child_node_id_iter = try child_node_id_set.iter();
                defer child_node_id_iter.deinit();
                var node_id_cursor = (try child_node_id_iter.next()) orelse return error.ExpectedChildNode;

                const kv_pair = try node_id_cursor.readKeyValuePair();
                const child_node_id_bytes = try kv_pair.key_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
                defer allocator.free(child_node_id_bytes);

                _ = try node_list.writePath(void, &[_]xitdb.PathPart(void){
                    .{ .array_list_get = .append },
                    .{ .write = .{ .bytes = child_node_id_bytes } },
                });

                var stream = std.io.fixedBufferStream(child_node_id_bytes);
                var reader = stream.reader();
                current_node_id = @bitCast(try reader.readInt(NodeIdInt, .big));
            }
        } else {
            break;
        }
    }
}

pub fn writePatch(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator) !void {
    comptime std.debug.assert(repo_kind == .xit);

    // exit early if we're not on master (doesn't handle separate branches currently)
    const current_branch_name = try ref.readHeadName(repo_kind, core_cursor, allocator);
    defer allocator.free(current_branch_name);
    if (!std.mem.eql(u8, "master", current_branch_name)) {
        return;
    }

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
        try applyPatchForFile(repo_kind, core_cursor, allocator, patch_hash, line_iter_pair.path);
    }
}
