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
    patch_id: hash.Hash,
};

// reordering is a breaking change
const ChangeKind = enum(u8) {
    new_edge,
    delete_node,
};

const FIRST_NODE_ID_INT: NodeIdInt = 0;

/// TODO: turn this into an iterator all entries don't need to be in memory at the same time
fn createPatchEntries(
    root_cursor: *xitdb.Database(.file, hash.Hash).Cursor(.read_write),
    branch_cursor: *xitdb.Database(.file, hash.Hash).Cursor(.read_write),
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    line_iter_pair: *df.LineIteratorPair(.xit),
    patch_entries: *std.ArrayList([]const u8),
    patch_content_entries: *std.ArrayList([]const u8),
    patch_hash: hash.Hash,
) !void {
    var myers_diff_iter = try df.MyersDiffIterator(.xit).init(allocator, &line_iter_pair.a, &line_iter_pair.b);
    defer myers_diff_iter.deinit();

    // get path slot
    const path_hash = hash.hashBuffer(line_iter_pair.path);
    var path_cursor = try root_cursor.writePath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path-set") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = path_hash } },
    });
    try path_cursor.writeBytes(line_iter_pair.path, .once);
    const path_slot = path_cursor.slot_ptr.slot;

    // init node list
    _ = try branch_cursor.writePath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->node-id-list") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = path_hash } },
        .{ .write = .{ .slot = path_slot } },
    });
    const node_list_maybe = try branch_cursor.readPath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->node-id-list") } },
        .{ .hash_map_get = .{ .value = path_hash } },
    });

    var new_node_count: u64 = 0;
    const LastNodeId = struct {
        id: NodeId,
        origin: enum { old, new },
    };
    var last_node = LastNodeId{ .id = @bitCast(FIRST_NODE_ID_INT), .origin = .old };

    while (try myers_diff_iter.next()) |edit| {
        defer edit.deinit(allocator);

        switch (edit) {
            .eql => |eql| {
                const node_list = node_list_maybe orelse return error.NodeListNotFound;
                const node_id_cursor = (try node_list.readPath(void, &.{
                    .{ .array_list_get = .{ .index = eql.old_line.num - 1 } },
                })) orelse return error.ExpectedNode;

                const node_id_bytes = try node_id_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
                defer allocator.free(node_id_bytes);

                var stream = std.io.fixedBufferStream(node_id_bytes);
                var reader = stream.reader();
                const node_id: NodeId = @bitCast(try reader.readInt(NodeIdInt, .big));

                if (last_node.origin == .new) {
                    var buffer = std.ArrayList(u8).init(arena.allocator());
                    try buffer.writer().writeInt(u8, @intFromEnum(ChangeKind.new_edge), .big);
                    try buffer.writer().writeInt(NodeIdInt, @bitCast(node_id), .big);
                    try buffer.writer().writeInt(NodeIdInt, @bitCast(last_node.id), .big);
                    try patch_entries.append(buffer.items);
                }

                last_node = .{ .id = node_id, .origin = .old };
            },
            .ins => |ins| {
                const node_id = NodeId{
                    .node = new_node_count,
                    .patch_id = patch_hash,
                };

                var buffer = std.ArrayList(u8).init(arena.allocator());
                try buffer.writer().writeInt(u8, @intFromEnum(ChangeKind.new_edge), .big);
                try buffer.writer().writeInt(NodeIdInt, @bitCast(node_id), .big);
                try buffer.writer().writeInt(NodeIdInt, @bitCast(last_node.id), .big);
                try patch_entries.append(buffer.items);

                const content = try arena.allocator().dupe(u8, ins.new_line.text);
                try patch_content_entries.append(content);

                new_node_count += 1;

                last_node = .{ .id = node_id, .origin = .new };
            },
            .del => |del| {
                var buffer = std.ArrayList(u8).init(arena.allocator());
                try buffer.writer().writeInt(u8, @intFromEnum(ChangeKind.delete_node), .big);

                const node_list = node_list_maybe orelse return error.NodeListNotFound;
                const node_id_cursor = (try node_list.readPath(void, &.{
                    .{ .array_list_get = .{ .index = del.old_line.num - 1 } },
                })) orelse return error.ExpectedNode;

                const node_id_bytes = try node_id_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
                defer allocator.free(node_id_bytes);

                var stream = std.io.fixedBufferStream(node_id_bytes);
                var reader = stream.reader();
                const node_id: NodeId = @bitCast(try reader.readInt(NodeIdInt, .big));

                try buffer.writer().writeInt(NodeIdInt, @bitCast(node_id), .big);

                try patch_entries.append(buffer.items);

                last_node = .{ .id = last_node.id, .origin = .new };
            },
        }
    }
}

fn patchHash(
    root_cursor: *xitdb.Database(.file, hash.Hash).Cursor(.read_write),
    branch_cursor: *xitdb.Database(.file, hash.Hash).Cursor(.read_write),
    allocator: std.mem.Allocator,
    line_iter_pair: *df.LineIteratorPair(.xit),
) !hash.Hash {
    var patch_entries = std.ArrayList([]const u8).init(allocator);
    defer patch_entries.deinit();

    var patch_content_entries = std.ArrayList([]const u8).init(allocator);
    defer patch_content_entries.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    try createPatchEntries(root_cursor, branch_cursor, allocator, &arena, line_iter_pair, &patch_entries, &patch_content_entries, 0);

    var h = std.crypto.hash.Sha1.init(.{});

    for (patch_entries.items) |patch_entry| {
        h.update(patch_entry);
    }

    for (patch_content_entries.items) |patch_content_entry| {
        h.update(patch_content_entry);
    }

    var patch_hash = [_]u8{0} ** hash.SHA1_BYTES_LEN;
    h.final(&patch_hash);
    return hash.hashBuffer(&patch_hash);
}

fn writePatchForFile(
    root_cursor: *xitdb.Database(.file, hash.Hash).Cursor(.read_write),
    branch_cursor: *xitdb.Database(.file, hash.Hash).Cursor(.read_write),
    allocator: std.mem.Allocator,
    line_iter_pair: *df.LineIteratorPair(.xit),
) !hash.Hash {
    const patch_hash = try patchHash(root_cursor, branch_cursor, allocator, line_iter_pair);

    // exit early if patch already exists
    if (try root_cursor.readPath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashBuffer("patch-id->change-list") } },
        .{ .hash_map_get = .{ .key = patch_hash } },
    })) |_| {
        return patch_hash;
    }

    // init change list
    var change_list = try root_cursor.writePath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashBuffer("patch-id->change-list") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = patch_hash } },
        .array_list_init,
    });
    var change_content_list = try root_cursor.writePath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashBuffer("patch-id->change-list") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .value = patch_hash } },
        .array_list_init,
    });

    var patch_entries = std.ArrayList([]const u8).init(allocator);
    defer patch_entries.deinit();

    var patch_content_entries = std.ArrayList([]const u8).init(allocator);
    defer patch_content_entries.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    try createPatchEntries(root_cursor, branch_cursor, allocator, &arena, line_iter_pair, &patch_entries, &patch_content_entries, patch_hash);

    for (patch_entries.items) |patch_entry| {
        _ = try change_list.writePath(void, &.{
            .{ .array_list_get = .append },
            .{ .write = .{ .bytes = patch_entry } },
        });
    }

    for (patch_content_entries.items) |patch_content_entry| {
        _ = try change_content_list.writePath(void, &.{
            .{ .array_list_get = .append },
            .{ .write = .{ .bytes = patch_content_entry } },
        });
    }

    return patch_hash;
}

fn applyPatchForFile(
    root_cursor: *xitdb.Database(.file, hash.Hash).Cursor(.read_write),
    branch_cursor: *xitdb.Database(.file, hash.Hash).Cursor(.read_write),
    allocator: std.mem.Allocator,
    patch_hash: hash.Hash,
    path: []const u8,
) !void {
    var change_list = (try root_cursor.readPath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashBuffer("patch-id->change-list") } },
        .{ .hash_map_get = .{ .key = patch_hash } },
    })) orelse return error.PatchNotFound;

    // get path slot
    const path_hash = hash.hashBuffer(path);
    var path_cursor = try root_cursor.writePath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path-set") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = path_hash } },
    });
    try path_cursor.writeBytes(path, .once);
    const path_slot = path_cursor.slot_ptr.slot;

    // init parent->children node map
    _ = try branch_cursor.writePath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->parent->children") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = path_hash } },
        .{ .write = .{ .slot = path_slot } },
    });
    var parent_to_children = try branch_cursor.writePath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->parent->children") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .value = path_hash } },
        .hash_map_init,
    });

    // init child->parent node map
    _ = try branch_cursor.writePath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->child->parent") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = path_hash } },
        .{ .write = .{ .slot = path_slot } },
    });
    var child_to_parent = try branch_cursor.writePath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->child->parent") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .value = path_hash } },
        .hash_map_init,
    });

    var iter = try change_list.iter();
    defer iter.deinit();
    while (try iter.next()) |*next_cursor| {
        const change_buffer = try next_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
        defer allocator.free(change_buffer);

        var stream = std.io.fixedBufferStream(change_buffer);
        var reader = stream.reader();
        const change_kind = try reader.readInt(u8, .big);
        switch (try std.meta.intToEnum(ChangeKind, change_kind)) {
            .new_edge => {
                const node_id_int = try reader.readInt(NodeIdInt, .big);
                const parent_node_id_int = try reader.readInt(NodeIdInt, .big);

                const node_id_bytes = try hash.numToBytes(NodeIdInt, node_id_int);
                const parent_node_id_bytes = try hash.numToBytes(NodeIdInt, parent_node_id_int);

                const node_id_hash = hash.hashBuffer(&node_id_bytes);
                const parent_node_id_hash = hash.hashBuffer(&parent_node_id_bytes);

                // if child has an existing parent, remove it
                if (try child_to_parent.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = node_id_hash } },
                })) |*existing_parent_cursor| {
                    const existing_parent_node_id_bytes = try existing_parent_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
                    defer allocator.free(existing_parent_node_id_bytes);
                    const existing_parent_node_id_hash = hash.hashBuffer(existing_parent_node_id_bytes);
                    _ = try parent_to_children.writePath(void, &.{
                        .{ .hash_map_get = .{ .value = existing_parent_node_id_hash } },
                        .hash_map_init,
                        .{ .hash_map_remove = node_id_hash },
                    });
                }

                _ = try parent_to_children.writePath(void, &.{
                    .{ .hash_map_get = .{ .value = parent_node_id_hash } },
                    .hash_map_init,
                    .{ .hash_map_get = .{ .key = node_id_hash } },
                    .{ .write = .{ .bytes = &node_id_bytes } },
                });

                _ = try child_to_parent.writePath(void, &.{
                    .{ .hash_map_get = .{ .value = node_id_hash } },
                    .{ .write = .{ .bytes = &parent_node_id_bytes } },
                });
            },
            .delete_node => {
                const node_id_int = try reader.readInt(NodeIdInt, .big);
                const node_id_bytes = try hash.numToBytes(NodeIdInt, node_id_int);
                const node_id_hash = hash.hashBuffer(&node_id_bytes);

                var parent_cursor = (try child_to_parent.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = node_id_hash } },
                })) orelse return error.ExpectedParentNode;

                const parent_node_id_bytes = try parent_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
                defer allocator.free(parent_node_id_bytes);
                const parent_node_id_hash = hash.hashBuffer(parent_node_id_bytes);

                _ = try parent_to_children.writePath(void, &.{
                    .{ .hash_map_get = .{ .value = parent_node_id_hash } },
                    .{ .hash_map_remove = node_id_hash },
                });

                _ = try child_to_parent.writePath(void, &.{
                    .{ .hash_map_remove = node_id_hash },
                });
            },
        }
    }

    // init node list
    _ = try branch_cursor.writePath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->node-id-list") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = path_hash } },
        .{ .write = .{ .slot = path_slot } },
    });
    var node_list = try branch_cursor.writePath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->node-id-list") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .value = path_hash } },
        // create a new array list every time for now
        .{ .write = .none },
        .array_list_init,
    });

    var current_node_id_int = FIRST_NODE_ID_INT;

    while (true) {
        const current_node_id_bytes = try hash.numToBytes(NodeIdInt, current_node_id_int);
        const current_node_id_hash = hash.hashBuffer(&current_node_id_bytes);

        if (try parent_to_children.readPath(void, &.{
            .{ .hash_map_get = .{ .value = current_node_id_hash } },
        })) |child_node_id_set| {
            var child_node_id_iter = try child_node_id_set.iter();
            defer child_node_id_iter.deinit();

            if (try child_node_id_iter.next()) |node_id_cursor| {
                // if there are any other children, remove the node list
                // because there is a conflict, and thus the node map
                // cannot be "flattened" into a list
                if (try child_node_id_iter.next() != null) {
                    _ = try branch_cursor.writePath(void, &.{
                        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->node-id-list") } },
                        .hash_map_init,
                        .{ .hash_map_get = .{ .value = path_hash } },
                        .{ .write = .none },
                    });
                    break;
                }
                // append child to the node list
                else {
                    const kv_pair = try node_id_cursor.readKeyValuePair();
                    const child_node_id_bytes = try kv_pair.key_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
                    defer allocator.free(child_node_id_bytes);

                    _ = try node_list.writePath(void, &.{
                        .{ .array_list_get = .append },
                        .{ .write = .{ .bytes = child_node_id_bytes } },
                    });

                    var stream = std.io.fixedBufferStream(child_node_id_bytes);
                    var reader = stream.reader();
                    current_node_id_int = try reader.readInt(NodeIdInt, .big);
                }
            } else {
                break;
            }
        } else {
            break;
        }
    }
}

pub fn writePatch(core_cursor: rp.Repo(.xit).CoreCursor, allocator: std.mem.Allocator) !void {
    // get current branch name
    const current_branch_name = try ref.readHeadName(.xit, core_cursor, allocator);
    defer allocator.free(current_branch_name);

    // get current branch name slot
    const branch_name_hash = hash.hashBuffer(current_branch_name);
    var branch_name_cursor = try core_cursor.cursor.writePath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashBuffer("ref-name-set") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = branch_name_hash } },
    });
    try branch_name_cursor.writeBytes(current_branch_name, .once);
    const branch_name_slot = branch_name_cursor.slot_ptr.slot;

    // init branch map
    _ = try core_cursor.cursor.writePath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashBuffer("branches") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = branch_name_hash } },
        .{ .write = .{ .slot = branch_name_slot } },
    });
    var branch_cursor = try core_cursor.cursor.writePath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashBuffer("branches") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .value = branch_name_hash } },
        .hash_map_init,
    });

    // init file iterator for index diff
    var status = try st.Status(.xit).init(allocator, core_cursor);
    defer status.deinit();
    var file_iter = try df.FileIterator(.xit).init(allocator, core_cursor.core, .{ .index = .{ .status = &status } });

    // iterate over each modified file and create/apply the patch
    while (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();
        const patch_hash = try writePatchForFile(core_cursor.cursor, &branch_cursor, allocator, &line_iter_pair);
        try applyPatchForFile(core_cursor.cursor, &branch_cursor, allocator, patch_hash, line_iter_pair.path);
    }
}
