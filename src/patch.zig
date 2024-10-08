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
    moment: *rp.Repo(.xit).DB.HashMap(.read_write),
    branch: *rp.Repo(.xit).DB.HashMap(.read_write),
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    line_iter_pair: *df.LineIteratorPair(.xit),
    patch_entries: *std.ArrayList([]const u8),
    patch_content_entries: *std.ArrayList([]const u8),
    patch_hash: hash.Hash,
) !void {
    var myers_diff_iter = try df.MyersDiffIterator(.xit).init(allocator, &line_iter_pair.a, &line_iter_pair.b);
    defer myers_diff_iter.deinit();

    // store path
    const path_hash = hash.hashBuffer(line_iter_pair.path);
    const path_set_cursor = try moment.put(hash.hashBuffer("path-set"));
    const path_set = try rp.Repo(.xit).DB.HashMap(.read_write).init(path_set_cursor);
    var path_cursor = try path_set.putKey(path_hash);
    try path_cursor.writeBytes(line_iter_pair.path, .once);

    // init node list
    const path_to_node_id_list_cursor = try branch.put(hash.hashBuffer("path->node-id-list"));
    const path_to_node_id_list = try rp.Repo(.xit).DB.HashMap(.read_write).init(path_to_node_id_list_cursor);
    try path_to_node_id_list.putKeyData(path_hash, .{ .slot = path_cursor.slot() });
    const node_id_list_cursor_maybe = try path_to_node_id_list.get(path_hash);

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
                const node_id_list_cursor = node_id_list_cursor_maybe orelse return error.NodeListNotFound;
                const node_id_list = try rp.Repo(.xit).DB.ArrayList(.read_only).init(node_id_list_cursor);
                const node_id_cursor = (try node_id_list.get(eql.old_line.num - 1)) orelse return error.ExpectedNode;

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

                const node_id_list_cursor = node_id_list_cursor_maybe orelse return error.NodeListNotFound;
                const node_id_list = try rp.Repo(.xit).DB.ArrayList(.read_only).init(node_id_list_cursor);
                const node_id_cursor = (try node_id_list.get(del.old_line.num - 1)) orelse return error.ExpectedNode;

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
    moment: *rp.Repo(.xit).DB.HashMap(.read_write),
    branch: *rp.Repo(.xit).DB.HashMap(.read_write),
    allocator: std.mem.Allocator,
    line_iter_pair: *df.LineIteratorPair(.xit),
) !hash.Hash {
    var patch_entries = std.ArrayList([]const u8).init(allocator);
    defer patch_entries.deinit();

    var patch_content_entries = std.ArrayList([]const u8).init(allocator);
    defer patch_content_entries.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    try createPatchEntries(moment, branch, allocator, &arena, line_iter_pair, &patch_entries, &patch_content_entries, 0);

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
    moment: *rp.Repo(.xit).DB.HashMap(.read_write),
    branch: *rp.Repo(.xit).DB.HashMap(.read_write),
    allocator: std.mem.Allocator,
    line_iter_pair: *df.LineIteratorPair(.xit),
) !hash.Hash {
    const patch_hash = try patchHash(moment, branch, allocator, line_iter_pair);

    // exit early if patch already exists
    if (try moment.cursor.readPath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashBuffer("patch-id->change-list") } },
        .{ .hash_map_get = .{ .key = patch_hash } },
    })) |_| {
        return patch_hash;
    }

    const patch_id_to_change_list_cursor = try moment.put(hash.hashBuffer("patch-id->change-list"));
    const patch_id_to_change_list = try rp.Repo(.xit).DB.HashMap(.read_write).init(patch_id_to_change_list_cursor);

    // init change list
    const change_list_cursor = try patch_id_to_change_list.putKey(patch_hash);
    const change_list = try rp.Repo(.xit).DB.ArrayList(.read_write).init(change_list_cursor);
    const change_content_list_cursor = try patch_id_to_change_list.put(patch_hash);
    const change_content_list = try rp.Repo(.xit).DB.ArrayList(.read_write).init(change_content_list_cursor);

    var patch_entries = std.ArrayList([]const u8).init(allocator);
    defer patch_entries.deinit();

    var patch_content_entries = std.ArrayList([]const u8).init(allocator);
    defer patch_content_entries.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    try createPatchEntries(moment, branch, allocator, &arena, line_iter_pair, &patch_entries, &patch_content_entries, patch_hash);

    for (patch_entries.items) |patch_entry| {
        try change_list.appendData(.{ .bytes = patch_entry });
    }

    for (patch_content_entries.items) |patch_content_entry| {
        try change_content_list.appendData(.{ .bytes = patch_content_entry });
    }

    return patch_hash;
}

fn applyPatchForFile(
    moment: *rp.Repo(.xit).DB.HashMap(.read_write),
    branch: *rp.Repo(.xit).DB.HashMap(.read_write),
    allocator: std.mem.Allocator,
    patch_hash: hash.Hash,
    path: []const u8,
) !void {
    var change_list_cursor = (try moment.cursor.readPath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashBuffer("patch-id->change-list") } },
        .{ .hash_map_get = .{ .key = patch_hash } },
    })) orelse return error.PatchNotFound;

    // store path
    const path_hash = hash.hashBuffer(path);
    const path_set_cursor = try moment.put(hash.hashBuffer("path-set"));
    const path_set = try rp.Repo(.xit).DB.HashMap(.read_write).init(path_set_cursor);
    var path_cursor = try path_set.putKey(path_hash);
    try path_cursor.writeBytes(path, .once);

    // init parent->children node map
    const path_to_parent_to_children_cursor = try branch.put(hash.hashBuffer("path->parent->children"));
    const path_to_parent_to_children = try rp.Repo(.xit).DB.HashMap(.read_write).init(path_to_parent_to_children_cursor);
    try path_to_parent_to_children.putKeyData(path_hash, .{ .slot = path_cursor.slot() });
    const parent_to_children_cursor = try path_to_parent_to_children.put(path_hash);
    const parent_to_children = try rp.Repo(.xit).DB.HashMap(.read_write).init(parent_to_children_cursor);

    // init child->parent node map
    const path_to_child_to_parent_cursor = try branch.put(hash.hashBuffer("path->child->parent"));
    const path_to_child_to_parent = try rp.Repo(.xit).DB.HashMap(.read_write).init(path_to_child_to_parent_cursor);
    try path_to_child_to_parent.putKeyData(path_hash, .{ .slot = path_cursor.slot() });
    const child_to_parent_cursor = try path_to_child_to_parent.put(path_hash);
    const child_to_parent = try rp.Repo(.xit).DB.HashMap(.read_write).init(child_to_parent_cursor);

    var iter = try change_list_cursor.iterator();
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
                if (try child_to_parent.get(node_id_hash)) |*existing_parent_cursor| {
                    const existing_parent_node_id_bytes = try existing_parent_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
                    defer allocator.free(existing_parent_node_id_bytes);
                    const old_children_cursor = try parent_to_children.put(hash.hashBuffer(existing_parent_node_id_bytes));
                    const old_children = try rp.Repo(.xit).DB.HashMap(.read_write).init(old_children_cursor);
                    try old_children.remove(node_id_hash);
                }

                const children_cursor = try parent_to_children.put(parent_node_id_hash);
                const children = try rp.Repo(.xit).DB.HashMap(.read_write).init(children_cursor);
                try children.putKeyData(node_id_hash, .{ .bytes = &node_id_bytes });

                try child_to_parent.putData(node_id_hash, .{ .bytes = &parent_node_id_bytes });
            },
            .delete_node => {
                const node_id_int = try reader.readInt(NodeIdInt, .big);
                const node_id_bytes = try hash.numToBytes(NodeIdInt, node_id_int);
                const node_id_hash = hash.hashBuffer(&node_id_bytes);

                var parent_cursor = (try child_to_parent.get(node_id_hash)) orelse return error.ExpectedParentNode;

                const parent_node_id_bytes = try parent_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
                defer allocator.free(parent_node_id_bytes);
                const parent_node_id_hash = hash.hashBuffer(parent_node_id_bytes);

                const children_cursor = try parent_to_children.put(parent_node_id_hash);
                const children = try rp.Repo(.xit).DB.HashMap(.read_write).init(children_cursor);
                try children.remove(node_id_hash);

                try child_to_parent.remove(node_id_hash);
            },
        }
    }

    // init node list
    const path_to_node_id_list_cursor = try branch.put(hash.hashBuffer("path->node-id-list"));
    const path_to_node_id_list = try rp.Repo(.xit).DB.HashMap(.read_write).init(path_to_node_id_list_cursor);
    try path_to_node_id_list.putKeyData(path_hash, .{ .slot = path_cursor.slot() });
    try path_to_node_id_list.putData(path_hash, .{ .slot = null }); // create a new array list every time for now
    const node_id_list_cursor = try path_to_node_id_list.put(path_hash);
    const node_id_list = try rp.Repo(.xit).DB.ArrayList(.read_write).init(node_id_list_cursor);

    var current_node_id_int = FIRST_NODE_ID_INT;

    while (true) {
        const current_node_id_bytes = try hash.numToBytes(NodeIdInt, current_node_id_int);
        const current_node_id_hash = hash.hashBuffer(&current_node_id_bytes);

        if (try parent_to_children.get(current_node_id_hash)) |child_node_id_set| {
            var child_node_id_iter = try child_node_id_set.iterator();
            defer child_node_id_iter.deinit();

            if (try child_node_id_iter.next()) |node_id_cursor| {
                // if there are any other children, remove the node list
                // because there is a conflict, and thus the node map
                // cannot be "flattened" into a list
                if (try child_node_id_iter.next() != null) {
                    try path_to_node_id_list.remove(path_hash);
                    break;
                }
                // append child to the node list
                else {
                    const kv_pair = try node_id_cursor.readKeyValuePair();
                    const child_node_id_bytes = try kv_pair.key_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
                    defer allocator.free(child_node_id_bytes);

                    try node_id_list.appendData(.{ .bytes = child_node_id_bytes });

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

fn removePatch(branch: *rp.Repo(.xit).DB.HashMap(.read_write), path: []const u8) !void {
    const path_hash = hash.hashBuffer(path);

    if (try branch.cursor.readPath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->node-id-list") } },
        .{ .hash_map_get = .{ .key = path_hash } },
    })) |_| {
        const path_to_parent_to_children_cursor = try branch.put(hash.hashBuffer("path->parent->children"));
        const path_to_parent_to_children = try rp.Repo(.xit).DB.HashMap(.read_write).init(path_to_parent_to_children_cursor);
        try path_to_parent_to_children.remove(path_hash);

        const path_to_child_to_parent_cursor = try branch.put(hash.hashBuffer("path->child->parent"));
        const path_to_child_to_parent = try rp.Repo(.xit).DB.HashMap(.read_write).init(path_to_child_to_parent_cursor);
        try path_to_child_to_parent.remove(path_hash);

        const path_to_node_id_list_cursor = try branch.put(hash.hashBuffer("path->node-id-list"));
        const path_to_node_id_list = try rp.Repo(.xit).DB.HashMap(.read_write).init(path_to_node_id_list_cursor);
        try path_to_node_id_list.remove(path_hash);
    }
}

pub fn writePatch(state: rp.Repo(.xit).State(.read_write), allocator: std.mem.Allocator) !void {
    // get current branch name
    const current_branch_name = try ref.readHeadName(.xit, state.readOnly(), allocator);
    defer allocator.free(current_branch_name);

    const branch_name_hash = hash.hashBuffer(current_branch_name);

    // store branch name
    const ref_name_set_cursor = try state.moment.put(hash.hashBuffer("ref-name-set"));
    const ref_name_set = try rp.Repo(.xit).DB.HashMap(.read_write).init(ref_name_set_cursor);
    var branch_name_cursor = try ref_name_set.putKey(branch_name_hash);
    try branch_name_cursor.writeBytes(current_branch_name, .once);

    // init branch map
    const branches_cursor = try state.moment.put(hash.hashBuffer("branches"));
    const branches = try rp.Repo(.xit).DB.HashMap(.read_write).init(branches_cursor);
    try branches.putKeyData(branch_name_hash, .{ .slot = branch_name_cursor.slot() });
    const branch_cursor = try branches.put(branch_name_hash);
    var branch = try rp.Repo(.xit).DB.HashMap(.read_write).init(branch_cursor);

    // init file iterator for index diff
    var status = try st.Status(.xit).init(allocator, state.readOnly());
    defer status.deinit();
    var file_iter = try df.FileIterator(.xit).init(allocator, state.readOnly(), .{ .index = .{ .status = &status } });

    // iterate over each modified file and create/apply the patch
    while (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();
        if (line_iter_pair.a.source == .binary or line_iter_pair.b.source == .binary) {
            // the file is or was binary, so we can't create a patch for it.
            // remove existing patch data if there is any.
            try removePatch(&branch, line_iter_pair.path);
        } else {
            const patch_hash = try writePatchForFile(state.moment, &branch, allocator, &line_iter_pair);
            try applyPatchForFile(state.moment, &branch, allocator, patch_hash, line_iter_pair.path);
        }
    }
}
