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
    new_edge,
    delete_node,
};

const FIRST_NODE_ID_INT: NodeIdInt = 0;

/// TODO: turn this into an iterator all entries don't need to be in memory at the same time
fn createPatchEntries(
    comptime repo_kind: rp.RepoKind,
    core_cursor: rp.Repo(repo_kind).CoreCursor,
    branch_cursor: *xitdb.Cursor(.file),
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    line_iter_pair: *df.LineIteratorPair(repo_kind),
    patch_entries: *std.ArrayList([]const u8),
    patch_content_entries: *std.ArrayList([]const u8),
    patch_hash: xitdb.Hash,
) !void {
    var myers_diff_iter = try df.MyersDiffIterator(repo_kind).init(allocator, &line_iter_pair.a, &line_iter_pair.b);
    defer myers_diff_iter.deinit();

    // get path slot
    const path_hash = hash.hashBuffer(line_iter_pair.path);
    var path_cursor = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path-set") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = path_hash } },
    });
    try path_cursor.writeBytes(line_iter_pair.path, .once);
    const path_slot = path_cursor.slot_ptr.slot;

    // init node list
    _ = try branch_cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->node-id-list") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = path_hash } },
        .{ .write = .{ .slot = path_slot } },
    });
    const node_list_maybe = try branch_cursor.readPath(void, &[_]xitdb.PathPart(void){
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

        switch (edit) {
            .eql => {
                const node_list = node_list_maybe orelse return error.NodeListNotFound;
                const node_id_cursor = (try node_list.readPath(void, &[_]xitdb.PathPart(void){
                    .{ .array_list_get = .{ .index = edit.eql.old_line.num - 1 } },
                })) orelse return error.ExpectedNode;

                const node_id_bytes = try node_id_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
                defer allocator.free(node_id_bytes);

                var stream = std.io.fixedBufferStream(node_id_bytes);
                var reader = stream.reader();
                const node_id: NodeId = @bitCast(try reader.readInt(NodeIdInt, .big));

                if (last_node_maybe) |last_node| {
                    if (last_node.origin == .new) {
                        var buffer = std.ArrayList(u8).init(arena.allocator());
                        try buffer.writer().writeInt(u8, @intFromEnum(ChangeKind.new_edge), .big);
                        try buffer.writer().writeInt(NodeIdInt, @bitCast(node_id), .big);
                        try buffer.writer().writeInt(NodeIdInt, @bitCast(last_node.id), .big);
                        try patch_entries.append(buffer.items);
                    }
                }

                last_node_maybe = .{ .id = node_id, .origin = .old };
            },
            .ins => {
                const node_id = NodeId{
                    .node = new_node_count,
                    .patch_id = patch_hash,
                };

                var buffer = std.ArrayList(u8).init(arena.allocator());
                try buffer.writer().writeInt(u8, @intFromEnum(ChangeKind.new_edge), .big);
                try buffer.writer().writeInt(NodeIdInt, @bitCast(node_id), .big);
                if (last_node_maybe) |last_node| {
                    try buffer.writer().writeInt(NodeIdInt, @bitCast(last_node.id), .big);
                } else {
                    try buffer.writer().writeInt(NodeIdInt, FIRST_NODE_ID_INT, .big);
                }
                try patch_entries.append(buffer.items);

                last_node_maybe = .{ .id = node_id, .origin = .new };

                const content = try arena.allocator().dupe(u8, edit.ins.new_line.text);
                try patch_content_entries.append(content);

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
    }
}

fn patchHash(
    comptime repo_kind: rp.RepoKind,
    core_cursor: rp.Repo(repo_kind).CoreCursor,
    branch_cursor: *xitdb.Cursor(.file),
    allocator: std.mem.Allocator,
    line_iter_pair: *df.LineIteratorPair(repo_kind),
) !xitdb.Hash {
    var patch_entries = std.ArrayList([]const u8).init(allocator);
    defer patch_entries.deinit();

    var patch_content_entries = std.ArrayList([]const u8).init(allocator);
    defer patch_content_entries.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    try createPatchEntries(repo_kind, core_cursor, branch_cursor, allocator, &arena, line_iter_pair, &patch_entries, &patch_content_entries, 0);

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
    comptime repo_kind: rp.RepoKind,
    core_cursor: rp.Repo(repo_kind).CoreCursor,
    branch_cursor: *xitdb.Cursor(.file),
    allocator: std.mem.Allocator,
    line_iter_pair: *df.LineIteratorPair(repo_kind),
) !xitdb.Hash {
    const patch_hash = try patchHash(repo_kind, core_cursor, branch_cursor, allocator, line_iter_pair);

    // exit early if patch already exists
    if (try core_cursor.cursor.readPath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("patch-id->change-list") } },
        .{ .hash_map_get = .{ .key = patch_hash } },
    })) |_| {
        return patch_hash;
    }

    // init change list
    var change_list = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("patch-id->change-list") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = patch_hash } },
        .array_list_init,
    });
    var change_content_list = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
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

    try createPatchEntries(repo_kind, core_cursor, branch_cursor, allocator, &arena, line_iter_pair, &patch_entries, &patch_content_entries, patch_hash);

    for (patch_entries.items) |patch_entry| {
        _ = try change_list.writePath(void, &[_]xitdb.PathPart(void){
            .{ .array_list_get = .append },
            .{ .write = .{ .bytes = patch_entry } },
        });
    }

    for (patch_content_entries.items) |patch_content_entry| {
        _ = try change_content_list.writePath(void, &[_]xitdb.PathPart(void){
            .{ .array_list_get = .append },
            .{ .write = .{ .bytes = patch_content_entry } },
        });
    }

    return patch_hash;
}

fn applyPatchForFile(
    comptime repo_kind: rp.RepoKind,
    core_cursor: rp.Repo(repo_kind).CoreCursor,
    branch_cursor: *xitdb.Cursor(.file),
    allocator: std.mem.Allocator,
    patch_hash: xitdb.Hash,
    path: []const u8,
) !void {
    var change_list = (try core_cursor.cursor.readPath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("patch-id->change-list") } },
        .{ .hash_map_get = .{ .key = patch_hash } },
    })) orelse return error.PatchNotFound;

    // get path slot
    const path_hash = hash.hashBuffer(path);
    var path_cursor = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path-set") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = path_hash } },
    });
    try path_cursor.writeBytes(path, .once);
    const path_slot = path_cursor.slot_ptr.slot;

    // init parent->children node map
    _ = try branch_cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->parent->children") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = path_hash } },
        .{ .write = .{ .slot = path_slot } },
    });
    var parent_to_children = try branch_cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->parent->children") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .value = path_hash } },
        .hash_map_init,
    });

    // init child->parent node map
    _ = try branch_cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->child->parent") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = path_hash } },
        .{ .write = .{ .slot = path_slot } },
    });
    var child_to_parent = try branch_cursor.writePath(void, &[_]xitdb.PathPart(void){
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
                if (try child_to_parent.readPath(void, &[_]xitdb.PathPart(void){
                    .{ .hash_map_get = .{ .value = node_id_hash } },
                })) |*existing_parent_cursor| {
                    const existing_parent_node_id_bytes = try existing_parent_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
                    defer allocator.free(existing_parent_node_id_bytes);
                    const existing_parent_node_id_hash = hash.hashBuffer(existing_parent_node_id_bytes);
                    _ = try parent_to_children.writePath(void, &[_]xitdb.PathPart(void){
                        .{ .hash_map_get = .{ .value = existing_parent_node_id_hash } },
                        .hash_map_init,
                        .{ .hash_map_remove = node_id_hash },
                    });
                }

                _ = try parent_to_children.writePath(void, &[_]xitdb.PathPart(void){
                    .{ .hash_map_get = .{ .value = parent_node_id_hash } },
                    .hash_map_init,
                    .{ .hash_map_get = .{ .key = node_id_hash } },
                    .{ .write = .{ .bytes = &node_id_bytes } },
                });

                _ = try child_to_parent.writePath(void, &[_]xitdb.PathPart(void){
                    .{ .hash_map_get = .{ .value = node_id_hash } },
                    .{ .write = .{ .bytes = &parent_node_id_bytes } },
                });
            },
            .delete_node => {
                const node_id_int = try reader.readInt(NodeIdInt, .big);
                const node_id_bytes = try hash.numToBytes(NodeIdInt, node_id_int);
                const node_id_hash = hash.hashBuffer(&node_id_bytes);

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

                _ = try child_to_parent.writePath(void, &[_]xitdb.PathPart(void){
                    .{ .hash_map_remove = node_id_hash },
                });
            },
        }
    }

    // init node list
    _ = try branch_cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->node-id-list") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = path_hash } },
        .{ .write = .{ .slot = path_slot } },
    });
    var node_list = try branch_cursor.writePath(void, &[_]xitdb.PathPart(void){
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

        if (try parent_to_children.readPath(void, &[_]xitdb.PathPart(void){
            .{ .hash_map_get = .{ .value = current_node_id_hash } },
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
                _ = try branch_cursor.writePath(void, &[_]xitdb.PathPart(void){
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
                current_node_id_int = try reader.readInt(NodeIdInt, .big);
            }
        } else {
            break;
        }
    }
}

pub fn writePatch(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator) !void {
    comptime std.debug.assert(repo_kind == .xit);

    // get current branch name
    const current_branch_name = try ref.readHeadName(repo_kind, core_cursor, allocator);
    defer allocator.free(current_branch_name);

    // get current branch name slot
    const branch_name_hash = hash.hashBuffer(current_branch_name);
    var branch_name_cursor = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("ref-name-set") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = branch_name_hash } },
    });
    try branch_name_cursor.writeBytes(current_branch_name, .once);
    const branch_name_slot = branch_name_cursor.slot_ptr.slot;

    // init branch map
    _ = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("branches") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = branch_name_hash } },
        .{ .write = .{ .slot = branch_name_slot } },
    });
    var branch_cursor = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("branches") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .value = branch_name_hash } },
        .hash_map_init,
    });

    // init file iterator for index diff
    var file_iter = blk: {
        var stat = try st.Status(repo_kind).init(allocator, core_cursor);
        errdefer stat.deinit();
        break :blk try df.FileIterator(repo_kind).init(allocator, core_cursor.core, .index, stat);
    };
    defer file_iter.deinit();

    // iterate over each modified file and create/apply the patch
    while (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();
        const patch_hash = try writePatchForFile(repo_kind, core_cursor, &branch_cursor, allocator, &line_iter_pair);
        try applyPatchForFile(repo_kind, core_cursor, &branch_cursor, allocator, patch_hash, line_iter_pair.path);
    }
}
