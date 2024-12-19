const std = @import("std");
const rp = @import("./repo.zig");
const hash = @import("./hash.zig");
const st = @import("./status.zig");
const df = @import("./diff.zig");
const ref = @import("./ref.zig");

pub fn NodeId(comptime hash_kind: hash.HashKind) type {
    return packed struct {
        node: u64,
        patch_id: hash.HashInt(hash_kind),

        pub const Int = @typeInfo(NodeId(hash_kind)).Struct.backing_integer.?;
        pub const byte_size = @bitSizeOf(NodeId(hash_kind)) / 8;
        pub const first_int: Int = 0;
        pub const first_bytes: [byte_size]u8 = [_]u8{0} ** byte_size;
    };
}

// reordering is a breaking change
const ChangeKind = enum(u8) {
    new_edge,
    delete_node,
};

/// TODO: turn this into an iterator all entries don't need to be in memory at the same time
fn createPatchEntries(
    comptime repo_opts: rp.RepoOpts(.xit),
    moment: *const rp.Repo(.xit, repo_opts).DB.HashMap(.read_write),
    branch: *const rp.Repo(.xit, repo_opts).DB.HashMap(.read_write),
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    line_iter_pair: *df.LineIteratorPair(.xit, repo_opts),
    path_hash: hash.HashInt(repo_opts.hash),
    patch_hash: hash.HashInt(repo_opts.hash),
    patch_entries: *std.ArrayList([]const u8),
    patch_offsets: *std.ArrayList(u64),
) !void {
    var myers_diff_iter = try df.MyersDiffIterator(.xit, repo_opts).init(allocator, &line_iter_pair.a, &line_iter_pair.b);
    defer myers_diff_iter.deinit();

    // get path slot
    const path_set_cursor = (try moment.getCursor(hash.hashInt(repo_opts.hash, "path-set"))) orelse return error.KeyNotFound;
    const path_set = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_only).init(path_set_cursor);
    const path_slot = try path_set.getSlot(path_hash);

    // init node list
    const path_to_node_id_list_cursor = try branch.putCursor(hash.hashInt(repo_opts.hash, "path->node-id-list"));
    const path_to_node_id_list = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(path_to_node_id_list_cursor);
    try path_to_node_id_list.putKey(path_hash, .{ .slot = path_slot });
    const node_id_list_cursor_maybe = try path_to_node_id_list.getCursor(path_hash);

    var new_node_count: u64 = 0;
    const LastNodeId = struct {
        id: NodeId(repo_opts.hash),
        origin: enum { old, new },
    };
    var last_node = LastNodeId{ .id = @bitCast(NodeId(repo_opts.hash).first_int), .origin = .old };

    while (try myers_diff_iter.next()) |edit| {
        defer edit.deinit(allocator);

        switch (edit) {
            .eql => |eql| {
                const node_id_list_cursor = node_id_list_cursor_maybe orelse return error.NodeListNotFound;
                const node_id_list = try rp.Repo(.xit, repo_opts).DB.LinkedArrayList(.read_only).init(node_id_list_cursor);
                const node_id_cursor = (try node_id_list.getCursor(eql.old_line.num - 1)) orelse return error.ExpectedNode;

                var node_id_bytes = [_]u8{0} ** NodeId(repo_opts.hash).byte_size;
                const node_id_slice = try node_id_cursor.readBytes(&node_id_bytes);

                var stream = std.io.fixedBufferStream(node_id_slice);
                var reader = stream.reader();
                const node_id: NodeId(repo_opts.hash) = @bitCast(try reader.readInt(NodeId(repo_opts.hash).Int, .big));

                if (last_node.origin == .new) {
                    var buffer = std.ArrayList(u8).init(arena.allocator());
                    try buffer.writer().writeInt(u8, @intFromEnum(ChangeKind.new_edge), .big);
                    try buffer.writer().writeInt(NodeId(repo_opts.hash).Int, @bitCast(node_id), .big);
                    try buffer.writer().writeInt(NodeId(repo_opts.hash).Int, @bitCast(last_node.id), .big);
                    try patch_entries.append(buffer.items);
                }

                last_node = .{ .id = node_id, .origin = .old };
            },
            .ins => |ins| {
                const node_id = NodeId(repo_opts.hash){
                    .node = new_node_count,
                    .patch_id = patch_hash,
                };

                var buffer = std.ArrayList(u8).init(arena.allocator());
                try buffer.writer().writeInt(u8, @intFromEnum(ChangeKind.new_edge), .big);
                try buffer.writer().writeInt(NodeId(repo_opts.hash).Int, @bitCast(node_id), .big);
                try buffer.writer().writeInt(NodeId(repo_opts.hash).Int, @bitCast(last_node.id), .big);
                try patch_entries.append(buffer.items);

                try patch_offsets.append(ins.new_line.offset);

                new_node_count += 1;

                last_node = .{ .id = node_id, .origin = .new };
            },
            .del => |del| {
                var buffer = std.ArrayList(u8).init(arena.allocator());
                try buffer.writer().writeInt(u8, @intFromEnum(ChangeKind.delete_node), .big);

                const node_id_list_cursor = node_id_list_cursor_maybe orelse return error.NodeListNotFound;
                const node_id_list = try rp.Repo(.xit, repo_opts).DB.LinkedArrayList(.read_only).init(node_id_list_cursor);
                const node_id_cursor = (try node_id_list.getCursor(del.old_line.num - 1)) orelse return error.ExpectedNode;

                var node_id_bytes = [_]u8{0} ** NodeId(repo_opts.hash).byte_size;
                const node_id_slice = try node_id_cursor.readBytes(&node_id_bytes);

                var stream = std.io.fixedBufferStream(node_id_slice);
                var reader = stream.reader();
                const node_id: NodeId(repo_opts.hash) = @bitCast(try reader.readInt(NodeId(repo_opts.hash).Int, .big));

                try buffer.writer().writeInt(NodeId(repo_opts.hash).Int, @bitCast(node_id), .big);

                try patch_entries.append(buffer.items);

                last_node = .{ .id = last_node.id, .origin = .new };
            },
        }
    }
}

fn patchHash(
    comptime repo_opts: rp.RepoOpts(.xit),
    moment: *const rp.Repo(.xit, repo_opts).DB.HashMap(.read_write),
    branch: *const rp.Repo(.xit, repo_opts).DB.HashMap(.read_write),
    allocator: std.mem.Allocator,
    line_iter_pair: *df.LineIteratorPair(.xit, repo_opts),
    path_hash: hash.HashInt(repo_opts.hash),
) ![hash.byteLen(repo_opts.hash)]u8 {
    var patch_entries = std.ArrayList([]const u8).init(allocator);
    defer patch_entries.deinit();

    var patch_offsets = std.ArrayList(u64).init(allocator);
    defer patch_offsets.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    try createPatchEntries(repo_opts, moment, branch, allocator, &arena, line_iter_pair, path_hash, 0, &patch_entries, &patch_offsets);

    var hasher = hash.Hasher(repo_opts.hash).init();

    for (patch_entries.items) |patch_entry| {
        hasher.update(patch_entry);
    }

    hasher.update(&line_iter_pair.b.oid);
    for (patch_offsets.items) |patch_offset| {
        var buffer = [_]u8{0} ** (@bitSizeOf(u64) / 8);
        std.mem.writeInt(u64, &buffer, patch_offset, .big);
        hasher.update(&buffer);
    }

    var patch_hash = [_]u8{0} ** hash.byteLen(repo_opts.hash);
    hasher.final(&patch_hash);
    return patch_hash;
}

fn writePatch(
    comptime repo_opts: rp.RepoOpts(.xit),
    moment: *const rp.Repo(.xit, repo_opts).DB.HashMap(.read_write),
    branch: *const rp.Repo(.xit, repo_opts).DB.HashMap(.read_write),
    allocator: std.mem.Allocator,
    line_iter_pair: *df.LineIteratorPair(.xit, repo_opts),
    path_hash: hash.HashInt(repo_opts.hash),
) ![hash.byteLen(repo_opts.hash)]u8 {
    const patch_hash_bytes = try patchHash(repo_opts, moment, branch, allocator, line_iter_pair, path_hash);
    const patch_hash = hash.bytesToInt(repo_opts.hash, &patch_hash_bytes);

    // exit early if patch already exists
    if (try moment.cursor.readPath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashInt(repo_opts.hash, "patch-id->change-list") } },
        .{ .hash_map_get = .{ .value = patch_hash } },
    })) |_| {
        return patch_hash_bytes;
    }

    // init change list
    const patch_id_to_change_list_cursor = try moment.putCursor(hash.hashInt(repo_opts.hash, "patch-id->change-list"));
    const patch_id_to_change_list = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(patch_id_to_change_list_cursor);
    const change_list_cursor = try patch_id_to_change_list.putCursor(patch_hash);
    const change_list = try rp.Repo(.xit, repo_opts).DB.ArrayList(.read_write).init(change_list_cursor);

    // init offset list
    const patch_id_to_offset_list_cursor = try moment.putCursor(hash.hashInt(repo_opts.hash, "patch-id->offset-list"));
    const patch_id_to_offset_list = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(patch_id_to_offset_list_cursor);
    var offset_list_cursor = try patch_id_to_offset_list.putCursor(patch_hash);

    var patch_entries = std.ArrayList([]const u8).init(allocator);
    defer patch_entries.deinit();

    var patch_offsets = std.ArrayList(u64).init(allocator);
    defer patch_offsets.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    try createPatchEntries(repo_opts, moment, branch, allocator, &arena, line_iter_pair, path_hash, patch_hash, &patch_entries, &patch_offsets);

    for (patch_entries.items) |patch_entry| {
        try change_list.append(.{ .bytes = patch_entry });
    }

    var offset_list_writer = try offset_list_cursor.writer();
    try offset_list_writer.writeAll(&line_iter_pair.b.oid);
    for (patch_offsets.items) |patch_offset| {
        try offset_list_writer.writeInt(u64, patch_offset, .big);
    }
    try offset_list_writer.finish();

    return patch_hash_bytes;
}

pub fn applyPatch(
    comptime repo_opts: rp.RepoOpts(.xit),
    moment: *const rp.Repo(.xit, repo_opts).DB.HashMap(.read_only),
    branch: *const rp.Repo(.xit, repo_opts).DB.HashMap(.read_write),
    allocator: std.mem.Allocator,
    path_hash: hash.HashInt(repo_opts.hash),
    patch_hash: hash.HashInt(repo_opts.hash),
) !void {
    // exit early if patch has already been applied
    if (try branch.cursor.readPath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashInt(repo_opts.hash, "patch-id-set") } },
        .{ .hash_map_get = .{ .value = patch_hash } },
    })) |_| {
        return;
    } else {
        const patch_id_set_cursor = try branch.putCursor(hash.hashInt(repo_opts.hash, "patch-id-set"));
        const patch_id_set = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(patch_id_set_cursor);
        try patch_id_set.putKey(patch_hash, .{ .slot = .{ .tag = .none } });
    }

    var change_list_cursor = (try moment.cursor.readPath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashInt(repo_opts.hash, "patch-id->change-list") } },
        .{ .hash_map_get = .{ .value = patch_hash } },
    })) orelse return error.PatchNotFound;

    // get path slot
    const path_set_cursor = (try moment.getCursor(hash.hashInt(repo_opts.hash, "path-set"))) orelse return error.KeyNotFound;
    const path_set = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_only).init(path_set_cursor);
    const path_slot = try path_set.getSlot(path_hash);

    // init live-parent->children node map
    const path_to_live_parent_to_children_cursor = try branch.putCursor(hash.hashInt(repo_opts.hash, "path->live-parent->children"));
    const path_to_live_parent_to_children = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(path_to_live_parent_to_children_cursor);
    try path_to_live_parent_to_children.putKey(path_hash, .{ .slot = path_slot });
    const live_parent_to_children_cursor = try path_to_live_parent_to_children.putCursor(path_hash);
    const live_parent_to_children = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(live_parent_to_children_cursor);

    // init child->parent node map
    const path_to_child_to_parent_cursor = try branch.putCursor(hash.hashInt(repo_opts.hash, "path->child->parent"));
    const path_to_child_to_parent = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(path_to_child_to_parent_cursor);
    try path_to_child_to_parent.putKey(path_hash, .{ .slot = path_slot });
    const child_to_parent_cursor = try path_to_child_to_parent.putCursor(path_hash);
    const child_to_parent = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(child_to_parent_cursor);

    var parent_to_removed_child = std.AutoArrayHashMap(hash.HashInt(repo_opts.hash), hash.HashInt(repo_opts.hash)).init(allocator);
    defer parent_to_removed_child.deinit();
    var parent_to_added_child = std.AutoArrayHashMap(hash.HashInt(repo_opts.hash), [NodeId(repo_opts.hash).byte_size]u8).init(allocator);
    defer parent_to_added_child.deinit();

    var iter = try change_list_cursor.iterator();
    defer iter.deinit();
    while (try iter.next()) |*next_cursor| {
        const change_buffer = try next_cursor.readBytesAlloc(allocator, repo_opts.max_read_size);
        defer allocator.free(change_buffer);

        var stream = std.io.fixedBufferStream(change_buffer);
        var reader = stream.reader();
        const change_kind = try reader.readInt(u8, .big);
        switch (try std.meta.intToEnum(ChangeKind, change_kind)) {
            .new_edge => {
                const node_id_int = try reader.readInt(NodeId(repo_opts.hash).Int, .big);
                const parent_node_id_int = try reader.readInt(NodeId(repo_opts.hash).Int, .big);

                const node_id_bytes = try hash.numToBytes(NodeId(repo_opts.hash).Int, node_id_int);
                const node_id_hash = hash.hashInt(repo_opts.hash, &node_id_bytes);

                // if child has an existing parent, remove it
                if (try child_to_parent.getCursor(node_id_hash)) |*existing_parent_cursor| {
                    const existing_parent_node_id_bytes = try existing_parent_cursor.readBytesAlloc(allocator, repo_opts.max_read_size);
                    defer allocator.free(existing_parent_node_id_bytes);
                    if (null != try live_parent_to_children.getCursor(hash.hashInt(repo_opts.hash, existing_parent_node_id_bytes))) {
                        const old_live_children_cursor = try live_parent_to_children.putCursor(hash.hashInt(repo_opts.hash, existing_parent_node_id_bytes));
                        const old_live_children = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(old_live_children_cursor);
                        _ = try old_live_children.remove(node_id_hash);
                    }
                }

                // add to live-parent->children with empty children
                {
                    const live_children_cursor = try live_parent_to_children.putCursor(node_id_hash);
                    _ = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(live_children_cursor);
                }

                // add to parent's children
                {
                    var parent_node_id_bytes = try hash.numToBytes(NodeId(repo_opts.hash).Int, parent_node_id_int);
                    var parent_node_id_hash = hash.hashInt(repo_opts.hash, &parent_node_id_bytes);

                    try parent_to_added_child.put(parent_node_id_hash, node_id_bytes);

                    // if parent is a ghost node, keep going up the chain until we find a live parent
                    while (!std.mem.eql(u8, &NodeId(repo_opts.hash).first_bytes, &parent_node_id_bytes) and null == try live_parent_to_children.getCursor(parent_node_id_hash)) {
                        const next_parent_cursor = (try child_to_parent.getCursor(parent_node_id_hash)) orelse return error.ExpectedParent;
                        var next_parent_node_id_bytes = [_]u8{0} ** NodeId(repo_opts.hash).byte_size;
                        const next_parent_node_id_slice = try next_parent_cursor.readBytes(&next_parent_node_id_bytes);
                        @memcpy(&parent_node_id_bytes, next_parent_node_id_slice);
                        parent_node_id_hash = hash.hashInt(repo_opts.hash, next_parent_node_id_slice);
                    }

                    const live_children_cursor = try live_parent_to_children.putCursor(parent_node_id_hash);
                    const live_children = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(live_children_cursor);
                    try live_children.putKey(node_id_hash, .{ .bytes = &node_id_bytes });

                    // add to child->parent
                    try child_to_parent.put(node_id_hash, .{ .bytes = &parent_node_id_bytes });
                }
            },
            .delete_node => {
                const node_id_int = try reader.readInt(NodeId(repo_opts.hash).Int, .big);
                const node_id_bytes = try hash.numToBytes(NodeId(repo_opts.hash).Int, node_id_int);
                const node_id_hash = hash.hashInt(repo_opts.hash, &node_id_bytes);

                // remove from live-parent->children
                _ = try live_parent_to_children.remove(node_id_hash);

                // remove from parent's children
                // normally the parent should be in here, but if we are cherry-picking
                // without bringing along dependent patches, it may not
                if (try child_to_parent.getCursor(node_id_hash)) |parent_cursor| {
                    var parent_node_id_bytes = [_]u8{0} ** NodeId(repo_opts.hash).byte_size;
                    const parent_node_id_slice = try parent_cursor.readBytes(&parent_node_id_bytes);
                    const parent_node_id_hash = hash.hashInt(repo_opts.hash, parent_node_id_slice);

                    try parent_to_removed_child.put(parent_node_id_hash, node_id_hash);

                    const live_children_cursor = try live_parent_to_children.putCursor(parent_node_id_hash);
                    const live_children = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(live_children_cursor);
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
    const path_to_node_id_list_cursor = try branch.putCursor(hash.hashInt(repo_opts.hash, "path->node-id-list"));
    const path_to_node_id_list = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(path_to_node_id_list_cursor);
    try path_to_node_id_list.putKey(path_hash, .{ .slot = path_slot });
    const node_id_list_cursor = try path_to_node_id_list.putCursor(path_hash);
    const node_id_list = try rp.Repo(.xit, repo_opts).DB.LinkedArrayList(.read_write).init(node_id_list_cursor);

    var current_node_id_int = NodeId(repo_opts.hash).first_int;
    var current_index_maybe: ?usize = 0;

    while (true) {
        const current_node_id_bytes = try hash.numToBytes(NodeId(repo_opts.hash).Int, current_node_id_int);
        const current_node_id_hash = hash.hashInt(repo_opts.hash, &current_node_id_bytes);

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
                    var child_bytes = [_]u8{0} ** NodeId(repo_opts.hash).byte_size;
                    const child_slice = try kv_pair.key_cursor.readBytes(&child_bytes);

                    if (current_index_maybe) |*current_index| {
                        if (try node_id_list.getCursor(current_index.*)) |existing_node_id_cursor| {
                            var existing_node_id_bytes = [_]u8{0} ** NodeId(repo_opts.hash).byte_size;
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
                    current_node_id_int = try reader.readInt(NodeId(repo_opts.hash).Int, .big);
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

fn removePatch(comptime repo_opts: rp.RepoOpts(.xit), branch: *const rp.Repo(.xit, repo_opts).DB.HashMap(.read_write), path: []const u8) !void {
    const path_hash = hash.hashInt(repo_opts.hash, path);

    if (try branch.cursor.readPath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashInt(repo_opts.hash, "path->node-id-list") } },
        .{ .hash_map_get = .{ .key = path_hash } },
    })) |_| {
        const path_to_live_parent_to_children_cursor = try branch.putCursor(hash.hashInt(repo_opts.hash, "path->live-parent->children"));
        const path_to_live_parent_to_children = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(path_to_live_parent_to_children_cursor);
        _ = try path_to_live_parent_to_children.remove(path_hash);

        const path_to_child_to_parent_cursor = try branch.putCursor(hash.hashInt(repo_opts.hash, "path->child->parent"));
        const path_to_child_to_parent = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(path_to_child_to_parent_cursor);
        _ = try path_to_child_to_parent.remove(path_hash);

        const path_to_node_id_list_cursor = try branch.putCursor(hash.hashInt(repo_opts.hash, "path->node-id-list"));
        const path_to_node_id_list = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(path_to_node_id_list_cursor);
        _ = try path_to_node_id_list.remove(path_hash);
    }
}

pub fn writeAndApplyPatches(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_write),
    allocator: std.mem.Allocator,
    status: *st.Status(.xit, repo_opts),
    commit_oid: *const [hash.hexLen(repo_opts.hash)]u8,
) !void {
    // get current branch name
    var current_branch_name_buffer = [_]u8{0} ** ref.MAX_REF_CONTENT_SIZE;
    const current_branch_name = try ref.readHeadName(.xit, repo_opts, state.readOnly(), &current_branch_name_buffer);

    const branch_name_hash = hash.hashInt(repo_opts.hash, current_branch_name);

    // store branch name
    const ref_name_set_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "ref-name-set"));
    const ref_name_set = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(ref_name_set_cursor);
    var branch_name_cursor = try ref_name_set.putKeyCursor(branch_name_hash);
    try branch_name_cursor.writeIfEmpty(.{ .bytes = current_branch_name });

    // init branch map
    const branches_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "branches"));
    const branches = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(branches_cursor);
    try branches.putKey(branch_name_hash, .{ .slot = branch_name_cursor.slot() });
    const branch_cursor = try branches.putCursor(branch_name_hash);
    const branch = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(branch_cursor);

    // init file iterator for index diff
    var file_iter = try df.FileIterator(.xit, repo_opts).init(allocator, state.readOnly(), .{ .index = .{ .status = status } });

    // iterate over each modified file and create/apply the patch
    while (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();
        if (line_iter_pair.a.source == .binary or line_iter_pair.b.source == .binary) {
            // the file is or was binary, so we can't create a patch for it.
            // remove existing patch data if there is any.
            try removePatch(repo_opts, &branch, line_iter_pair.path);
        } else {
            // store path
            const path_hash = hash.hashInt(repo_opts.hash, line_iter_pair.path);
            const path_set_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "path-set"));
            const path_set = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(path_set_cursor);
            var path_cursor = try path_set.putKeyCursor(path_hash);
            try path_cursor.writeIfEmpty(.{ .bytes = line_iter_pair.path });

            // create patch
            const patch_hash_bytes = try writePatch(repo_opts, state.extra.moment, &branch, allocator, &line_iter_pair, path_hash);
            const patch_hash = hash.bytesToInt(repo_opts.hash, &patch_hash_bytes);

            // apply patch
            try applyPatch(repo_opts, state.readOnly().extra.moment, &branch, allocator, path_hash, patch_hash);

            // associate patch hash with path/commit
            const commit_id_to_path_to_patch_id_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "commit-id->path->patch-id"));
            const commit_id_to_path_to_patch_id = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(commit_id_to_path_to_patch_id_cursor);
            const path_to_patch_id_cursor = try commit_id_to_path_to_patch_id.putCursor(try hash.hexToInt(repo_opts.hash, commit_oid));
            const path_to_patch_id = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(path_to_patch_id_cursor);
            try path_to_patch_id.putKey(path_hash, .{ .slot = path_cursor.slot() });
            try path_to_patch_id.put(path_hash, .{ .bytes = &patch_hash_bytes });
        }
    }

    // associate the path->live-parent->children map with commit
    const commit_id_to_path_to_live_parent_to_children_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "commit-id->path->live-parent->children"));
    const commit_id_to_path_to_live_parent_to_children = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(commit_id_to_path_to_live_parent_to_children_cursor);
    const commit_hash = try hash.hexToInt(repo_opts.hash, commit_oid);
    if (try branch.getCursor(hash.hashInt(repo_opts.hash, "path->live-parent->children"))) |path_to_live_parent_to_children_cursor| {
        try commit_id_to_path_to_live_parent_to_children.put(commit_hash, .{ .slot = path_to_live_parent_to_children_cursor.slot() });
    } else {
        const path_to_live_parent_to_children_cursor = try commit_id_to_path_to_live_parent_to_children.putCursor(commit_hash);
        _ = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(path_to_live_parent_to_children_cursor);
    }
}
