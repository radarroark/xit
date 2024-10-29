const std = @import("std");
const rp = @import("./repo.zig");
const hash = @import("./hash.zig");
const st = @import("./status.zig");
const df = @import("./diff.zig");
const ref = @import("./ref.zig");

const MAX_READ_BYTES = 1024; // FIXME: this is arbitrary...

pub const NodeIdInt = u224;
pub const NodeId = packed struct {
    node: u64,
    patch_id: hash.Hash,
};

// reordering is a breaking change
const ChangeKind = enum(u8) {
    new_edge,
    delete_node,
};

pub const NODE_ID_SIZE = @bitSizeOf(NodeId) / 8;
pub const FIRST_NODE_ID_INT: NodeIdInt = 0;
pub const FIRST_NODE_ID_BYTES = [_]u8{0} ** NODE_ID_SIZE;

/// TODO: turn this into an iterator all entries don't need to be in memory at the same time
fn createPatchEntries(
    moment: *const rp.Repo(.xit).DB.HashMap(.read_write),
    branch: *const rp.Repo(.xit).DB.HashMap(.read_write),
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    line_iter_pair: *df.LineIteratorPair(.xit),
    path_hash: hash.Hash,
    patch_hash: hash.Hash,
    patch_entries: *std.ArrayList([]const u8),
    patch_content_entries: *std.ArrayList([]const u8),
) !void {
    var myers_diff_iter = try df.MyersDiffIterator(.xit).init(allocator, &line_iter_pair.a, &line_iter_pair.b);
    defer myers_diff_iter.deinit();

    // get path slot
    const path_set_cursor = (try moment.getCursor(hash.hashBuffer("path-set"))) orelse return error.KeyNotFound;
    const path_set = try rp.Repo(.xit).DB.HashMap(.read_only).init(path_set_cursor);
    const path_slot = try path_set.getSlot(path_hash);

    // init node list
    const path_to_node_id_list_cursor = try branch.putCursor(hash.hashBuffer("path->node-id-list"));
    const path_to_node_id_list = try rp.Repo(.xit).DB.HashMap(.read_write).init(path_to_node_id_list_cursor);
    try path_to_node_id_list.putKey(path_hash, .{ .slot = path_slot });
    const node_id_list_cursor_maybe = try path_to_node_id_list.getCursor(path_hash);

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
                const node_id_list = try rp.Repo(.xit).DB.LinkedArrayList(.read_only).init(node_id_list_cursor);
                const node_id_cursor = (try node_id_list.getCursor(eql.old_line.num - 1)) orelse return error.ExpectedNode;

                var node_id_bytes = [_]u8{0} ** NODE_ID_SIZE;
                const node_id_slice = try node_id_cursor.readBytes(&node_id_bytes);

                var stream = std.io.fixedBufferStream(node_id_slice);
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
                const node_id_list = try rp.Repo(.xit).DB.LinkedArrayList(.read_only).init(node_id_list_cursor);
                const node_id_cursor = (try node_id_list.getCursor(del.old_line.num - 1)) orelse return error.ExpectedNode;

                var node_id_bytes = [_]u8{0} ** NODE_ID_SIZE;
                const node_id_slice = try node_id_cursor.readBytes(&node_id_bytes);

                var stream = std.io.fixedBufferStream(node_id_slice);
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
    moment: *const rp.Repo(.xit).DB.HashMap(.read_write),
    branch: *const rp.Repo(.xit).DB.HashMap(.read_write),
    allocator: std.mem.Allocator,
    line_iter_pair: *df.LineIteratorPair(.xit),
    path_hash: hash.Hash,
) ![hash.SHA1_BYTES_LEN]u8 {
    var patch_entries = std.ArrayList([]const u8).init(allocator);
    defer patch_entries.deinit();

    var patch_content_entries = std.ArrayList([]const u8).init(allocator);
    defer patch_content_entries.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    try createPatchEntries(moment, branch, allocator, &arena, line_iter_pair, path_hash, 0, &patch_entries, &patch_content_entries);

    var h = std.crypto.hash.Sha1.init(.{});

    for (patch_entries.items) |patch_entry| {
        h.update(patch_entry);
    }

    for (patch_content_entries.items) |patch_content_entry| {
        h.update(patch_content_entry);
    }

    var patch_hash = [_]u8{0} ** hash.SHA1_BYTES_LEN;
    h.final(&patch_hash);
    return patch_hash;
}

fn writePatch(
    moment: *const rp.Repo(.xit).DB.HashMap(.read_write),
    branch: *const rp.Repo(.xit).DB.HashMap(.read_write),
    allocator: std.mem.Allocator,
    line_iter_pair: *df.LineIteratorPair(.xit),
    path_hash: hash.Hash,
) ![hash.SHA1_BYTES_LEN]u8 {
    const patch_hash_bytes = try patchHash(moment, branch, allocator, line_iter_pair, path_hash);
    const patch_hash = hash.bytesToHash(&patch_hash_bytes);

    // exit early if patch already exists
    if (try moment.cursor.readPath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashBuffer("patch-id->change-list") } },
        .{ .hash_map_get = .{ .value = patch_hash } },
    })) |_| {
        return patch_hash_bytes;
    }

    // init change list
    const patch_id_to_change_list_cursor = try moment.putCursor(hash.hashBuffer("patch-id->change-list"));
    const patch_id_to_change_list = try rp.Repo(.xit).DB.HashMap(.read_write).init(patch_id_to_change_list_cursor);
    const change_list_cursor = try patch_id_to_change_list.putCursor(patch_hash);
    const change_list = try rp.Repo(.xit).DB.ArrayList(.read_write).init(change_list_cursor);

    // init change content list
    const patch_id_to_change_content_list_cursor = try moment.putCursor(hash.hashBuffer("patch-id->change-content-list"));
    const patch_id_to_change_content_list = try rp.Repo(.xit).DB.HashMap(.read_write).init(patch_id_to_change_content_list_cursor);
    const change_content_list_cursor = try patch_id_to_change_content_list.putCursor(patch_hash);
    const change_content_list = try rp.Repo(.xit).DB.ArrayList(.read_write).init(change_content_list_cursor);

    var patch_entries = std.ArrayList([]const u8).init(allocator);
    defer patch_entries.deinit();

    var patch_content_entries = std.ArrayList([]const u8).init(allocator);
    defer patch_content_entries.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    try createPatchEntries(moment, branch, allocator, &arena, line_iter_pair, path_hash, patch_hash, &patch_entries, &patch_content_entries);

    for (patch_entries.items) |patch_entry| {
        try change_list.append(.{ .bytes = patch_entry });
    }

    for (patch_content_entries.items) |patch_content_entry| {
        try change_content_list.append(.{ .bytes = patch_content_entry });
    }

    return patch_hash_bytes;
}

pub fn applyPatch(
    moment: *const rp.Repo(.xit).DB.HashMap(.read_only),
    branch: *const rp.Repo(.xit).DB.HashMap(.read_write),
    allocator: std.mem.Allocator,
    path_hash: hash.Hash,
    patch_hash: hash.Hash,
) !void {
    // exit early if patch has already been applied
    if (try branch.cursor.readPath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashBuffer("patch-id-set") } },
        .{ .hash_map_get = .{ .value = patch_hash } },
    })) |_| {
        return;
    } else {
        const patch_id_set_cursor = try branch.putCursor(hash.hashBuffer("patch-id-set"));
        const patch_id_set = try rp.Repo(.xit).DB.HashMap(.read_write).init(patch_id_set_cursor);
        try patch_id_set.putKey(patch_hash, .{ .slot = .{ .tag = .none } });
    }

    var change_list_cursor = (try moment.cursor.readPath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashBuffer("patch-id->change-list") } },
        .{ .hash_map_get = .{ .value = patch_hash } },
    })) orelse return error.PatchNotFound;

    // get path slot
    const path_set_cursor = (try moment.getCursor(hash.hashBuffer("path-set"))) orelse return error.KeyNotFound;
    const path_set = try rp.Repo(.xit).DB.HashMap(.read_only).init(path_set_cursor);
    const path_slot = try path_set.getSlot(path_hash);

    // init live-parent->children node map
    const path_to_live_parent_to_children_cursor = try branch.putCursor(hash.hashBuffer("path->live-parent->children"));
    const path_to_live_parent_to_children = try rp.Repo(.xit).DB.HashMap(.read_write).init(path_to_live_parent_to_children_cursor);
    try path_to_live_parent_to_children.putKey(path_hash, .{ .slot = path_slot });
    const live_parent_to_children_cursor = try path_to_live_parent_to_children.putCursor(path_hash);
    const live_parent_to_children = try rp.Repo(.xit).DB.HashMap(.read_write).init(live_parent_to_children_cursor);

    // init child->parent node map
    const path_to_child_to_parent_cursor = try branch.putCursor(hash.hashBuffer("path->child->parent"));
    const path_to_child_to_parent = try rp.Repo(.xit).DB.HashMap(.read_write).init(path_to_child_to_parent_cursor);
    try path_to_child_to_parent.putKey(path_hash, .{ .slot = path_slot });
    const child_to_parent_cursor = try path_to_child_to_parent.putCursor(path_hash);
    const child_to_parent = try rp.Repo(.xit).DB.HashMap(.read_write).init(child_to_parent_cursor);

    var parent_to_removed_child = std.AutoArrayHashMap(hash.Hash, hash.Hash).init(allocator);
    defer parent_to_removed_child.deinit();
    var parent_to_added_child = std.AutoArrayHashMap(hash.Hash, [NODE_ID_SIZE]u8).init(allocator);
    defer parent_to_added_child.deinit();

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
                const node_id_hash = hash.hashBuffer(&node_id_bytes);

                // if child has an existing parent, remove it
                if (try child_to_parent.getCursor(node_id_hash)) |*existing_parent_cursor| {
                    const existing_parent_node_id_bytes = try existing_parent_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
                    defer allocator.free(existing_parent_node_id_bytes);
                    if (null != try live_parent_to_children.getCursor(hash.hashBuffer(existing_parent_node_id_bytes))) {
                        const old_live_children_cursor = try live_parent_to_children.putCursor(hash.hashBuffer(existing_parent_node_id_bytes));
                        const old_live_children = try rp.Repo(.xit).DB.HashMap(.read_write).init(old_live_children_cursor);
                        _ = try old_live_children.remove(node_id_hash);
                    }
                }

                // add to live-parent->children with empty children
                {
                    const live_children_cursor = try live_parent_to_children.putCursor(node_id_hash);
                    _ = try rp.Repo(.xit).DB.HashMap(.read_write).init(live_children_cursor);
                }

                // add to parent's children
                {
                    var parent_node_id_bytes = try hash.numToBytes(NodeIdInt, parent_node_id_int);
                    var parent_node_id_hash = hash.hashBuffer(&parent_node_id_bytes);

                    try parent_to_added_child.put(parent_node_id_hash, node_id_bytes);

                    // if parent is a ghost node, keep going up the chain until we find a live parent
                    while (!std.mem.eql(u8, &FIRST_NODE_ID_BYTES, &parent_node_id_bytes) and null == try live_parent_to_children.getCursor(parent_node_id_hash)) {
                        const next_parent_cursor = (try child_to_parent.getCursor(parent_node_id_hash)) orelse return error.ExpectedParent;
                        var next_parent_node_id_bytes = [_]u8{0} ** NODE_ID_SIZE;
                        const next_parent_node_id_slice = try next_parent_cursor.readBytes(&next_parent_node_id_bytes);
                        @memcpy(&parent_node_id_bytes, next_parent_node_id_slice);
                        parent_node_id_hash = hash.hashBuffer(next_parent_node_id_slice);
                    }

                    const live_children_cursor = try live_parent_to_children.putCursor(parent_node_id_hash);
                    const live_children = try rp.Repo(.xit).DB.HashMap(.read_write).init(live_children_cursor);
                    try live_children.putKey(node_id_hash, .{ .bytes = &node_id_bytes });

                    // add to child->parent
                    try child_to_parent.put(node_id_hash, .{ .bytes = &parent_node_id_bytes });
                }
            },
            .delete_node => {
                const node_id_int = try reader.readInt(NodeIdInt, .big);
                const node_id_bytes = try hash.numToBytes(NodeIdInt, node_id_int);
                const node_id_hash = hash.hashBuffer(&node_id_bytes);

                // remove from live-parent->children
                _ = try live_parent_to_children.remove(node_id_hash);

                // remove from parent's children
                // normally the parent should be in here, but if we are cherry-picking
                // without bringing along dependent patches, it may not
                if (try child_to_parent.getCursor(node_id_hash)) |parent_cursor| {
                    var parent_node_id_bytes = [_]u8{0} ** NODE_ID_SIZE;
                    const parent_node_id_slice = try parent_cursor.readBytes(&parent_node_id_bytes);
                    const parent_node_id_hash = hash.hashBuffer(parent_node_id_slice);

                    try parent_to_removed_child.put(parent_node_id_hash, node_id_hash);

                    const live_children_cursor = try live_parent_to_children.putCursor(parent_node_id_hash);
                    const live_children = try rp.Repo(.xit).DB.HashMap(.read_write).init(live_children_cursor);
                    _ = try live_children.remove(node_id_hash);
                }
            },
        }
    }

    // if any node has a child removed and a new one added,
    // make the new child the parent of the removed child.
    // this avoids an unnecessary merge conflict when
    // applying a patch from another branch, in which a
    // parent node doesn't exist because it's been replaced.
    for (parent_to_removed_child.keys(), parent_to_removed_child.values()) |parent, removed_child| {
        if (parent_to_added_child.get(parent)) |*added_child_bytes| {
            try child_to_parent.put(removed_child, .{ .bytes = added_child_bytes });
        }
    }

    // init node list
    const path_to_node_id_list_cursor = try branch.putCursor(hash.hashBuffer("path->node-id-list"));
    const path_to_node_id_list = try rp.Repo(.xit).DB.HashMap(.read_write).init(path_to_node_id_list_cursor);
    try path_to_node_id_list.putKey(path_hash, .{ .slot = path_slot });
    const node_id_list_cursor = try path_to_node_id_list.putCursor(path_hash);
    const node_id_list = try rp.Repo(.xit).DB.LinkedArrayList(.read_write).init(node_id_list_cursor);

    var current_node_id_int = FIRST_NODE_ID_INT;
    var current_index_maybe: ?usize = 0;

    while (true) {
        const current_node_id_bytes = try hash.numToBytes(NodeIdInt, current_node_id_int);
        const current_node_id_hash = hash.hashBuffer(&current_node_id_bytes);

        if (try live_parent_to_children.getCursor(current_node_id_hash)) |children_cursor| {
            var children_iter = try children_cursor.iterator();
            defer children_iter.deinit();

            if (try children_iter.next()) |child_cursor| {
                // if there are any other children, remove the node list
                // because there is a conflict, and thus the node map
                // cannot be "flattened" into a list
                if (try children_iter.next() != null) {
                    _ = try path_to_node_id_list.remove(path_hash);
                    break;
                }
                // append child to the node list
                else {
                    const kv_pair = try child_cursor.readKeyValuePair();
                    var child_bytes = [_]u8{0} ** NODE_ID_SIZE;
                    const child_slice = try kv_pair.key_cursor.readBytes(&child_bytes);

                    if (current_index_maybe) |*current_index| {
                        if (try node_id_list.getCursor(current_index.*)) |existing_node_id_cursor| {
                            var existing_node_id_bytes = [_]u8{0} ** NODE_ID_SIZE;
                            const existing_node_id_slice = try existing_node_id_cursor.readBytes(&existing_node_id_bytes);
                            if (std.mem.eql(u8, existing_node_id_slice, child_slice)) {
                                // node id hasn't changed, so just continue without changing the data
                                current_index.* += 1;
                            } else {
                                // node id is different, so slice the list and begin appending the node ids from here
                                try node_id_list.slice(0, current_index.*);
                                current_index_maybe = null;
                            }
                        } else {
                            // we've reached the end of the existing list so begin appending the node ids from here
                            current_index_maybe = null;
                        }
                    }

                    if (current_index_maybe == null) {
                        try node_id_list.append(.{ .bytes = child_slice });
                    }

                    var stream = std.io.fixedBufferStream(child_slice);
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

    // if the current index is less than the size of the node id list,
    // that means the only change was that lines were deleted at the end
    // of the file. we just need to slice the node id list in that case.
    if (current_index_maybe) |current_index| {
        if (current_index < try node_id_list.count()) {
            try node_id_list.slice(0, current_index);
        }
    }
}

fn removePatch(branch: *const rp.Repo(.xit).DB.HashMap(.read_write), path: []const u8) !void {
    const path_hash = hash.hashBuffer(path);

    if (try branch.cursor.readPath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path->node-id-list") } },
        .{ .hash_map_get = .{ .key = path_hash } },
    })) |_| {
        const path_to_live_parent_to_children_cursor = try branch.putCursor(hash.hashBuffer("path->live-parent->children"));
        const path_to_live_parent_to_children = try rp.Repo(.xit).DB.HashMap(.read_write).init(path_to_live_parent_to_children_cursor);
        _ = try path_to_live_parent_to_children.remove(path_hash);

        const path_to_child_to_parent_cursor = try branch.putCursor(hash.hashBuffer("path->child->parent"));
        const path_to_child_to_parent = try rp.Repo(.xit).DB.HashMap(.read_write).init(path_to_child_to_parent_cursor);
        _ = try path_to_child_to_parent.remove(path_hash);

        const path_to_node_id_list_cursor = try branch.putCursor(hash.hashBuffer("path->node-id-list"));
        const path_to_node_id_list = try rp.Repo(.xit).DB.HashMap(.read_write).init(path_to_node_id_list_cursor);
        _ = try path_to_node_id_list.remove(path_hash);
    }
}

pub fn writeAndApplyPatches(
    state: rp.Repo(.xit).State(.read_write),
    allocator: std.mem.Allocator,
    status: *st.Status(.xit),
    commit_oid: *const [hash.SHA1_HEX_LEN]u8,
) !void {
    // get current branch name
    const current_branch_name = try ref.readHeadName(.xit, state.readOnly(), allocator);
    defer allocator.free(current_branch_name);

    const branch_name_hash = hash.hashBuffer(current_branch_name);

    // store branch name
    const ref_name_set_cursor = try state.extra.moment.putCursor(hash.hashBuffer("ref-name-set"));
    const ref_name_set = try rp.Repo(.xit).DB.HashMap(.read_write).init(ref_name_set_cursor);
    var branch_name_cursor = try ref_name_set.putKeyCursor(branch_name_hash);
    try branch_name_cursor.writeIfEmpty(.{ .bytes = current_branch_name });

    // init branch map
    const branches_cursor = try state.extra.moment.putCursor(hash.hashBuffer("branches"));
    const branches = try rp.Repo(.xit).DB.HashMap(.read_write).init(branches_cursor);
    try branches.putKey(branch_name_hash, .{ .slot = branch_name_cursor.slot() });
    const branch_cursor = try branches.putCursor(branch_name_hash);
    const branch = try rp.Repo(.xit).DB.HashMap(.read_write).init(branch_cursor);

    // init file iterator for index diff
    var file_iter = try df.FileIterator(.xit).init(allocator, state.readOnly(), .{ .index = .{ .status = status } });

    // iterate over each modified file and create/apply the patch
    while (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();
        if (line_iter_pair.a.source == .binary or line_iter_pair.b.source == .binary) {
            // the file is or was binary, so we can't create a patch for it.
            // remove existing patch data if there is any.
            try removePatch(&branch, line_iter_pair.path);
        } else {
            // store path
            const path_hash = hash.hashBuffer(line_iter_pair.path);
            const path_set_cursor = try state.extra.moment.putCursor(hash.hashBuffer("path-set"));
            const path_set = try rp.Repo(.xit).DB.HashMap(.read_write).init(path_set_cursor);
            var path_cursor = try path_set.putKeyCursor(path_hash);
            try path_cursor.writeIfEmpty(.{ .bytes = line_iter_pair.path });

            // create patch
            const patch_hash_bytes = try writePatch(state.extra.moment, &branch, allocator, &line_iter_pair, path_hash);
            const patch_hash = hash.bytesToHash(&patch_hash_bytes);

            // apply patch
            try applyPatch(state.readOnly().extra.moment, &branch, allocator, path_hash, patch_hash);

            // associate patch hash with path/commit
            const commit_id_to_path_to_patch_id_cursor = try state.extra.moment.putCursor(hash.hashBuffer("commit-id->path->patch-id"));
            const commit_id_to_path_to_patch_id = try rp.Repo(.xit).DB.HashMap(.read_write).init(commit_id_to_path_to_patch_id_cursor);
            const path_to_patch_id_cursor = try commit_id_to_path_to_patch_id.putCursor(try hash.hexToHash(commit_oid));
            const path_to_patch_id = try rp.Repo(.xit).DB.HashMap(.read_write).init(path_to_patch_id_cursor);
            try path_to_patch_id.putKey(path_hash, .{ .slot = path_cursor.slot() });
            try path_to_patch_id.put(path_hash, .{ .bytes = &patch_hash_bytes });
        }
    }

    // associate the path->live-parent->children map with commit
    const commit_id_to_path_to_live_parent_to_children_cursor = try state.extra.moment.putCursor(hash.hashBuffer("commit-id->path->live-parent->children"));
    const commit_id_to_path_to_live_parent_to_children = try rp.Repo(.xit).DB.HashMap(.read_write).init(commit_id_to_path_to_live_parent_to_children_cursor);
    const commit_hash = try hash.hexToHash(commit_oid);
    if (try branch.getCursor(hash.hashBuffer("path->live-parent->children"))) |path_to_live_parent_to_children_cursor| {
        try commit_id_to_path_to_live_parent_to_children.put(commit_hash, .{ .slot = path_to_live_parent_to_children_cursor.slot() });
    } else {
        const path_to_live_parent_to_children_cursor = try commit_id_to_path_to_live_parent_to_children.putCursor(commit_hash);
        _ = try rp.Repo(.xit).DB.HashMap(.read_write).init(path_to_live_parent_to_children_cursor);
    }
}
