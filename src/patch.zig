const std = @import("std");
const rp = @import("./repo.zig");
const hash = @import("./hash.zig");
const df = @import("./diff.zig");
const obj = @import("./object.zig");
const tr = @import("./tree.zig");
const cfg = @import("./config.zig");

// a globally-unique id representing a line.
// it's just the hash of the patch it came from,
// and the number representing which line from
// the patch it is. it's not that complicated.
pub fn LineId(comptime hash_kind: hash.HashKind) type {
    return packed struct {
        line: u64,
        patch_id: hash.HashInt(hash_kind),

        pub const Int = @typeInfo(LineId(hash_kind)).@"struct".backing_integer.?;
        pub const byte_size = @bitSizeOf(LineId(hash_kind)) / 8;
        pub const first_int: Int = 0;
        pub const first_bytes: [byte_size]u8 = [_]u8{0} ** byte_size;
    };
}

// reordering is a breaking change
const ChangeKind = enum(u8) {
    new_edge,
    delete_line,
};

pub fn writeAndApplyPatches(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_write),
    allocator: std.mem.Allocator,
    commit_oid: *const [hash.hexLen(repo_opts.hash)]u8,
) !void {
    // if the merge algo isn't set to patch, exit early
    if (!try cfg.patchEnabled(repo_opts, state.readOnly(), allocator)) {
        return;
    }

    const parent_commit_oid_maybe = blk: {
        var commit_object = try obj.Object(.xit, repo_opts, .full).init(allocator, state.readOnly(), commit_oid);
        defer commit_object.deinit();

        if (commit_object.content.commit.metadata.firstParent()) |oid| {
            break :blk oid.*;
        } else {
            break :blk null;
        }
    };

    // init snapshot
    const commit_id_to_snapshot_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "commit-id->snapshot"));
    const commit_id_to_snapshot = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(commit_id_to_snapshot_cursor);
    const commit_id_int = try hash.hexToInt(repo_opts.hash, commit_oid);
    if (try commit_id_to_snapshot.getCursor(commit_id_int)) |_| {
        return; // exit early if patches have already been created for this commit
    }
    var snapshot_cursor = try commit_id_to_snapshot.putCursor(commit_id_int);

    // if there is a parent commit, set the initial value of the snapshot to the one from that commit
    if (parent_commit_oid_maybe) |*parent_commit_oid| {
        if (try commit_id_to_snapshot.getCursor(try hash.hexToInt(repo_opts.hash, parent_commit_oid))) |parent_snapshot_cursor| {
            try snapshot_cursor.write(.{ .slot = parent_snapshot_cursor.slot() });
        } else {
            return error.ParentCommitSnapshotNotFound;
        }
    }

    const snapshot = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(snapshot_cursor);

    // init file iterator
    var tree_diff = tr.TreeDiff(.xit, repo_opts).init(allocator);
    defer tree_diff.deinit();
    try tree_diff.compare(state.readOnly(), if (parent_commit_oid_maybe) |parent_commit_oid| &parent_commit_oid else null, commit_oid, null);
    var file_iter = try df.FileIterator(.xit, repo_opts).init(allocator, state.readOnly(), .{ .tree = .{ .tree_diff = &tree_diff } });

    // iterate over each modified file and create/apply the patch
    while (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();
        if (line_iter_pair.a.source == .binary or line_iter_pair.b.source == .binary) {
            // the file is or was binary, so we can't create a patch for it.
            // remove existing patch data if there is any.
            try removePatch(repo_opts, &snapshot, line_iter_pair.path);
        } else {
            // store path
            const path_hash = hash.hashInt(repo_opts.hash, line_iter_pair.path);
            const path_set_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "path-set"));
            const path_set = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(path_set_cursor);
            var path_cursor = try path_set.putKeyCursor(path_hash);
            try path_cursor.writeIfEmpty(.{ .bytes = line_iter_pair.path });

            // create patch
            const patch_hash_bytes = try writePatch(repo_opts, state.extra.moment, &snapshot, allocator, &line_iter_pair, path_hash);
            const patch_hash = hash.bytesToInt(repo_opts.hash, &patch_hash_bytes);

            // apply patch
            try applyPatch(repo_opts, state.readOnly().extra.moment, &snapshot, allocator, path_hash, patch_hash);

            // associate patch hash with path/commit
            const path_to_patch_id_cursor = try snapshot.putCursor(hash.hashInt(repo_opts.hash, "path->patch-id"));
            const path_to_patch_id = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(path_to_patch_id_cursor);
            try path_to_patch_id.putKey(path_hash, .{ .slot = path_cursor.slot() });
            try path_to_patch_id.put(path_hash, .{ .bytes = &patch_hash_bytes });
        }
    }

    // this will force xitdb consider the start of the transaction
    // to be at the very end of the file. this is necessary in case
    // this function is called again in this transaction, which can
    // happen during a clone or fetch. this could be bad because,
    // as you can see above, we are getting the snapshot from the
    // parent commit and copying it. we don't want that snapshot to
    // be mutable, so we have to make xitdb think the transaction
    // just started.
    // TODO: this should definitely be a feature in it xitdb because
    // doing it manually like this is pretty hacky.
    try state.core.db.core.seekFromEnd(0);
    state.core.db.tx_start = try state.core.db.core.getPos();
}

fn removePatch(comptime repo_opts: rp.RepoOpts(.xit), snapshot: *const rp.Repo(.xit, repo_opts).DB.HashMap(.read_write), path: []const u8) !void {
    const path_hash = hash.hashInt(repo_opts.hash, path);

    if (try snapshot.cursor.readPath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashInt(repo_opts.hash, "path->line-id-list") } },
        .{ .hash_map_get = .{ .key = path_hash } },
    })) |_| {
        const path_to_live_parent_to_children_cursor = try snapshot.putCursor(hash.hashInt(repo_opts.hash, "path->live-parent->children"));
        const path_to_live_parent_to_children = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(path_to_live_parent_to_children_cursor);
        _ = try path_to_live_parent_to_children.remove(path_hash);

        const path_to_child_to_parent_cursor = try snapshot.putCursor(hash.hashInt(repo_opts.hash, "path->child->parent"));
        const path_to_child_to_parent = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(path_to_child_to_parent_cursor);
        _ = try path_to_child_to_parent.remove(path_hash);

        const path_to_line_id_list_cursor = try snapshot.putCursor(hash.hashInt(repo_opts.hash, "path->line-id-list"));
        const path_to_line_id_list = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(path_to_line_id_list_cursor);
        _ = try path_to_line_id_list.remove(path_hash);
    }
}

pub fn applyPatch(
    comptime repo_opts: rp.RepoOpts(.xit),
    moment: *const rp.Repo(.xit, repo_opts).DB.HashMap(.read_only),
    snapshot: *const rp.Repo(.xit, repo_opts).DB.HashMap(.read_write),
    allocator: std.mem.Allocator,
    path_hash: hash.HashInt(repo_opts.hash),
    patch_hash: hash.HashInt(repo_opts.hash),
) !void {
    // exit early if patch has already been applied
    if (try snapshot.cursor.readPath(void, &.{
        .{ .hash_map_get = .{ .value = hash.hashInt(repo_opts.hash, "patch-id-set") } },
        .{ .hash_map_get = .{ .value = patch_hash } },
    })) |_| {
        return;
    } else {
        const patch_id_set_cursor = try snapshot.putCursor(hash.hashInt(repo_opts.hash, "patch-id-set"));
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

    // init live-parent->children line map
    const path_to_live_parent_to_children_cursor = try snapshot.putCursor(hash.hashInt(repo_opts.hash, "path->live-parent->children"));
    const path_to_live_parent_to_children = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(path_to_live_parent_to_children_cursor);
    try path_to_live_parent_to_children.putKey(path_hash, .{ .slot = path_slot });
    const live_parent_to_children_cursor = try path_to_live_parent_to_children.putCursor(path_hash);
    const live_parent_to_children = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(live_parent_to_children_cursor);

    // init child->parent line map
    const path_to_child_to_parent_cursor = try snapshot.putCursor(hash.hashInt(repo_opts.hash, "path->child->parent"));
    const path_to_child_to_parent = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(path_to_child_to_parent_cursor);
    try path_to_child_to_parent.putKey(path_hash, .{ .slot = path_slot });
    const child_to_parent_cursor = try path_to_child_to_parent.putCursor(path_hash);
    const child_to_parent = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(child_to_parent_cursor);

    var parent_to_removed_child = std.AutoArrayHashMap(hash.HashInt(repo_opts.hash), hash.HashInt(repo_opts.hash)).init(allocator);
    defer parent_to_removed_child.deinit();
    var parent_to_added_child = std.AutoArrayHashMap(hash.HashInt(repo_opts.hash), [LineId(repo_opts.hash).byte_size]u8).init(allocator);
    defer parent_to_added_child.deinit();

    var buffered_reader = std.io.bufferedReaderSize(repo_opts.read_size, try change_list_cursor.reader());
    const change_list_reader = buffered_reader.reader();
    while (true) {
        const change_kind = change_list_reader.readInt(u8, .big) catch |err| switch (err) {
            error.EndOfStream => break,
            else => |e| return e,
        };

        switch (try std.meta.intToEnum(ChangeKind, change_kind)) {
            .new_edge => {
                const line_id_int = try change_list_reader.readInt(LineId(repo_opts.hash).Int, .big);
                const parent_line_id_int = try change_list_reader.readInt(LineId(repo_opts.hash).Int, .big);

                const line_id_bytes = hash.intToBytes(LineId(repo_opts.hash).Int, line_id_int);
                const line_id_hash = hash.hashInt(repo_opts.hash, &line_id_bytes);

                // if child has an existing parent, remove it
                if (try child_to_parent.getCursor(line_id_hash)) |*existing_parent_cursor| {
                    const existing_parent_line_id_bytes = try existing_parent_cursor.readBytesAlloc(allocator, repo_opts.max_read_size);
                    defer allocator.free(existing_parent_line_id_bytes);
                    if (null != try live_parent_to_children.getCursor(hash.hashInt(repo_opts.hash, existing_parent_line_id_bytes))) {
                        const old_live_children_cursor = try live_parent_to_children.putCursor(hash.hashInt(repo_opts.hash, existing_parent_line_id_bytes));
                        const old_live_children = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(old_live_children_cursor);
                        _ = try old_live_children.remove(line_id_hash);
                    }
                }

                // add to live-parent->children with empty children
                {
                    const live_children_cursor = try live_parent_to_children.putCursor(line_id_hash);
                    _ = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(live_children_cursor);
                }

                // add to parent's children
                {
                    var parent_line_id_bytes = hash.intToBytes(LineId(repo_opts.hash).Int, parent_line_id_int);
                    var parent_line_id_hash = hash.hashInt(repo_opts.hash, &parent_line_id_bytes);

                    try parent_to_added_child.put(parent_line_id_hash, line_id_bytes);

                    // if parent is a ghost line, keep going up the chain until we find a live parent
                    while (!std.mem.eql(u8, &LineId(repo_opts.hash).first_bytes, &parent_line_id_bytes) and null == try live_parent_to_children.getCursor(parent_line_id_hash)) {
                        const next_parent_cursor = (try child_to_parent.getCursor(parent_line_id_hash)) orelse return error.ExpectedParent;
                        var next_parent_line_id_bytes = [_]u8{0} ** LineId(repo_opts.hash).byte_size;
                        const next_parent_line_id_slice = try next_parent_cursor.readBytes(&next_parent_line_id_bytes);
                        @memcpy(&parent_line_id_bytes, next_parent_line_id_slice);
                        parent_line_id_hash = hash.hashInt(repo_opts.hash, next_parent_line_id_slice);
                    }

                    const live_children_cursor = try live_parent_to_children.putCursor(parent_line_id_hash);
                    const live_children = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(live_children_cursor);
                    try live_children.putKey(line_id_hash, .{ .bytes = &line_id_bytes });

                    // add to child->parent
                    try child_to_parent.put(line_id_hash, .{ .bytes = &parent_line_id_bytes });
                }
            },
            .delete_line => {
                const line_id_int = try change_list_reader.readInt(LineId(repo_opts.hash).Int, .big);
                const line_id_bytes = hash.intToBytes(LineId(repo_opts.hash).Int, line_id_int);
                const line_id_hash = hash.hashInt(repo_opts.hash, &line_id_bytes);

                // remove from live-parent->children
                _ = try live_parent_to_children.remove(line_id_hash);

                // remove from parent's children
                // normally the parent should be in here, but if we are cherry-picking
                // without bringing along dependent patches, it may not
                if (try child_to_parent.getCursor(line_id_hash)) |parent_cursor| {
                    var parent_line_id_bytes = [_]u8{0} ** LineId(repo_opts.hash).byte_size;
                    const parent_line_id_slice = try parent_cursor.readBytes(&parent_line_id_bytes);
                    const parent_line_id_hash = hash.hashInt(repo_opts.hash, parent_line_id_slice);

                    try parent_to_removed_child.put(parent_line_id_hash, line_id_hash);

                    const live_children_cursor = try live_parent_to_children.putCursor(parent_line_id_hash);
                    const live_children = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(live_children_cursor);
                    _ = try live_children.remove(line_id_hash);
                }
            },
        }
    }

    // if any line has a child removed and a new one added,
    // make the new child the parent of the removed child.
    // this avoids an unnecessary merge conflict when
    // applying a patch from another branch, in which a
    // parent line doesn't exist because it's been replaced.
    for (parent_to_removed_child.keys(), parent_to_removed_child.values()) |parent, removed_child| {
        if (parent_to_added_child.get(parent)) |*added_child_bytes| {
            try child_to_parent.put(removed_child, .{ .bytes = added_child_bytes });
        }
    }

    // init line id list
    const path_to_line_id_list_cursor = try snapshot.putCursor(hash.hashInt(repo_opts.hash, "path->line-id-list"));
    const path_to_line_id_list = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(path_to_line_id_list_cursor);
    try path_to_line_id_list.putKey(path_hash, .{ .slot = path_slot });
    var line_id_list_cursor = try path_to_line_id_list.putCursor(path_hash);
    var line_id_list_writer = try line_id_list_cursor.writer();

    var current_line_id_int = LineId(repo_opts.hash).first_int;

    while (true) {
        const current_line_id_bytes = hash.intToBytes(LineId(repo_opts.hash).Int, current_line_id_int);
        const current_line_id_hash = hash.hashInt(repo_opts.hash, &current_line_id_bytes);

        if (try live_parent_to_children.getCursor(current_line_id_hash)) |children_cursor| {
            var children_iter = try children_cursor.iterator();
            defer children_iter.deinit();

            if (try children_iter.next()) |child_cursor| {
                // if there are any other children, remove the line list
                // because there is a conflict, and thus the line map
                // cannot be "flattened" into a list
                if (try children_iter.next() != null) {
                    _ = try path_to_line_id_list.remove(path_hash);
                    return;
                }
                // append child to the line list
                else {
                    var kv_pair_cursor = try child_cursor.readKeyValuePair();
                    var key_reader = try kv_pair_cursor.key_cursor.reader();
                    var child_bytes = [_]u8{0} ** LineId(repo_opts.hash).byte_size;
                    try key_reader.readNoEof(&child_bytes);

                    const line_id_position = kv_pair_cursor.key_cursor.slot().value;
                    try line_id_list_writer.writeInt(u64, line_id_position, .big);

                    var stream = std.io.fixedBufferStream(&child_bytes);
                    var reader = stream.reader();
                    current_line_id_int = try reader.readInt(LineId(repo_opts.hash).Int, .big);
                }
            } else {
                break;
            }
        } else {
            break;
        }
    }

    try line_id_list_writer.finish();
}

fn writePatch(
    comptime repo_opts: rp.RepoOpts(.xit),
    moment: *const rp.Repo(.xit, repo_opts).DB.HashMap(.read_write),
    snapshot: *const rp.Repo(.xit, repo_opts).DB.HashMap(.read_write),
    allocator: std.mem.Allocator,
    line_iter_pair: *df.LineIteratorPair(.xit, repo_opts),
    path_hash: hash.HashInt(repo_opts.hash),
) ![hash.byteLen(repo_opts.hash)]u8 {
    var myers_diff_iter = try df.MyersDiffIterator(.xit, repo_opts).init(allocator, &line_iter_pair.a, &line_iter_pair.b);
    defer myers_diff_iter.deinit();

    const new_oid = &line_iter_pair.b.oid;

    const patch_hash_bytes = try patchHash(repo_opts, moment, snapshot, allocator, &myers_diff_iter, new_oid, path_hash);
    const patch_hash = hash.bytesToInt(repo_opts.hash, &patch_hash_bytes);

    try myers_diff_iter.reset();

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
    var change_list_cursor = try patch_id_to_change_list.putCursor(patch_hash);

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

    try createPatchEntries(repo_opts, moment, snapshot, &arena, &myers_diff_iter, path_hash, patch_hash, &patch_entries, &patch_offsets);

    var change_list_writer = try change_list_cursor.writer();
    for (patch_entries.items) |patch_entry| {
        try change_list_writer.writeAll(patch_entry);
    }
    try change_list_writer.finish();

    var offset_list_writer = try offset_list_cursor.writer();
    try offset_list_writer.writeAll(new_oid);
    for (patch_offsets.items) |patch_offset| {
        try offset_list_writer.writeInt(u64, patch_offset, .big);
    }
    try offset_list_writer.finish();

    return patch_hash_bytes;
}

fn patchHash(
    comptime repo_opts: rp.RepoOpts(.xit),
    moment: *const rp.Repo(.xit, repo_opts).DB.HashMap(.read_write),
    snapshot: *const rp.Repo(.xit, repo_opts).DB.HashMap(.read_write),
    allocator: std.mem.Allocator,
    myers_diff_iter: *df.MyersDiffIterator(.xit, repo_opts),
    new_oid: *const [hash.byteLen(repo_opts.hash)]u8,
    path_hash: hash.HashInt(repo_opts.hash),
) ![hash.byteLen(repo_opts.hash)]u8 {
    var patch_entries = std.ArrayList([]const u8).init(allocator);
    defer patch_entries.deinit();

    var patch_offsets = std.ArrayList(u64).init(allocator);
    defer patch_offsets.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    try createPatchEntries(repo_opts, moment, snapshot, &arena, myers_diff_iter, path_hash, 0, &patch_entries, &patch_offsets);

    var hasher = hash.Hasher(repo_opts.hash).init();

    for (patch_entries.items) |patch_entry| {
        hasher.update(patch_entry);
    }

    hasher.update(new_oid);
    for (patch_offsets.items) |patch_offset| {
        var buffer = [_]u8{0} ** (@bitSizeOf(u64) / 8);
        std.mem.writeInt(u64, &buffer, patch_offset, .big);
        hasher.update(&buffer);
    }

    var patch_hash = [_]u8{0} ** hash.byteLen(repo_opts.hash);
    hasher.final(&patch_hash);
    return patch_hash;
}

fn createPatchEntries(
    comptime repo_opts: rp.RepoOpts(.xit),
    moment: *const rp.Repo(.xit, repo_opts).DB.HashMap(.read_write),
    snapshot: *const rp.Repo(.xit, repo_opts).DB.HashMap(.read_write),
    arena: *std.heap.ArenaAllocator,
    myers_diff_iter: *df.MyersDiffIterator(.xit, repo_opts),
    path_hash: hash.HashInt(repo_opts.hash),
    patch_hash: hash.HashInt(repo_opts.hash),
    patch_entries: *std.ArrayList([]const u8),
    patch_offsets: *std.ArrayList(u64),
) !void {
    // get path slot
    const path_set_cursor = (try moment.getCursor(hash.hashInt(repo_opts.hash, "path-set"))) orelse return error.KeyNotFound;
    const path_set = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_only).init(path_set_cursor);
    const path_slot = try path_set.getSlot(path_hash);

    // init line list
    const path_to_line_id_list_cursor = try snapshot.putCursor(hash.hashInt(repo_opts.hash, "path->line-id-list"));
    const path_to_line_id_list = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(path_to_line_id_list_cursor);
    try path_to_line_id_list.putKey(path_hash, .{ .slot = path_slot });
    const line_id_list_cursor_maybe = try path_to_line_id_list.getCursor(path_hash);

    var new_line_count: u64 = 0;
    const LastLineId = struct {
        id: LineId(repo_opts.hash),
        origin: enum { old, new },
    };
    var last_line = LastLineId{ .id = @bitCast(LineId(repo_opts.hash).first_int), .origin = .old };

    while (try myers_diff_iter.next()) |edit| {
        switch (edit) {
            .eql => |eql| {
                var line_id_list_cursor = line_id_list_cursor_maybe orelse return error.LineListNotFound;
                var line_id_list_reader = try line_id_list_cursor.reader();
                try line_id_list_reader.seekTo(eql.old_line.num * @sizeOf(u64));

                const line_id_position = try line_id_list_reader.readInt(u64, .big);
                var line_id_cursor = rp.Repo(.xit, repo_opts).DB.Cursor(.read_only){
                    .slot_ptr = .{
                        .position = null,
                        .slot = .{ .tag = .bytes, .value = line_id_position },
                    },
                    .db = moment.cursor.db,
                };

                var line_id_reader = try line_id_cursor.reader();
                var line_id_bytes = [_]u8{0} ** LineId(repo_opts.hash).byte_size;
                try line_id_reader.readNoEof(&line_id_bytes);

                if (last_line.origin == .new) {
                    var buffer = std.ArrayList(u8).init(arena.allocator());
                    try buffer.writer().writeInt(u8, @intFromEnum(ChangeKind.new_edge), .big);
                    try buffer.writer().writeAll(&line_id_bytes);
                    try buffer.writer().writeInt(LineId(repo_opts.hash).Int, @bitCast(last_line.id), .big);
                    try patch_entries.append(buffer.items);
                }

                var stream = std.io.fixedBufferStream(&line_id_bytes);
                var reader = stream.reader();
                const line_id_int = try reader.readInt(LineId(repo_opts.hash).Int, .big);

                last_line = .{ .id = @bitCast(line_id_int), .origin = .old };
            },
            .ins => |ins| {
                const line_id = LineId(repo_opts.hash){
                    .line = new_line_count,
                    .patch_id = patch_hash,
                };

                var buffer = std.ArrayList(u8).init(arena.allocator());
                try buffer.writer().writeInt(u8, @intFromEnum(ChangeKind.new_edge), .big);
                try buffer.writer().writeInt(LineId(repo_opts.hash).Int, @bitCast(line_id), .big);
                try buffer.writer().writeInt(LineId(repo_opts.hash).Int, @bitCast(last_line.id), .big);
                try patch_entries.append(buffer.items);

                try patch_offsets.append(ins.new_line.offset);

                new_line_count += 1;

                last_line = .{ .id = line_id, .origin = .new };
            },
            .del => |del| {
                var buffer = std.ArrayList(u8).init(arena.allocator());
                try buffer.writer().writeInt(u8, @intFromEnum(ChangeKind.delete_line), .big);

                var line_id_list_cursor = line_id_list_cursor_maybe orelse return error.LineListNotFound;
                var line_id_list_reader = try line_id_list_cursor.reader();
                try line_id_list_reader.seekTo(del.old_line.num * @sizeOf(u64));

                const line_id_position = try line_id_list_reader.readInt(u64, .big);
                var line_id_cursor = rp.Repo(.xit, repo_opts).DB.Cursor(.read_only){
                    .slot_ptr = .{
                        .position = null,
                        .slot = .{ .tag = .bytes, .value = line_id_position },
                    },
                    .db = moment.cursor.db,
                };

                var line_id_reader = try line_id_cursor.reader();
                var line_id_bytes = [_]u8{0} ** LineId(repo_opts.hash).byte_size;
                try line_id_reader.readNoEof(&line_id_bytes);

                try buffer.writer().writeAll(&line_id_bytes);

                try patch_entries.append(buffer.items);

                last_line = .{ .id = last_line.id, .origin = .new };
            },
        }
    }
}
