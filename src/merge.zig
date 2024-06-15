const std = @import("std");
const xitdb = @import("xitdb");
const hash = @import("./hash.zig");
const obj = @import("./object.zig");
const idx = @import("./index.zig");
const ref = @import("./ref.zig");
const chk = @import("./checkout.zig");
const io = @import("./io.zig");
const rp = @import("./repo.zig");

const MAX_READ_BYTES = 1024; // FIXME: this is arbitrary...

pub const RenamedEntry = struct {
    path: []const u8,
    tree_entry: obj.TreeEntry,
};
pub const MergeConflict = struct {
    common: ?obj.TreeEntry,
    current: ?obj.TreeEntry,
    source: ?obj.TreeEntry,
    renamed: ?RenamedEntry,
};

fn writeBlobWithConflict(
    comptime repo_kind: rp.RepoKind,
    core_cursor: rp.Repo(repo_kind).CoreCursor,
    allocator: std.mem.Allocator,
    current_oid: [hash.SHA1_BYTES_LEN]u8,
    source_oid: [hash.SHA1_BYTES_LEN]u8,
    current_name: []const u8,
    source_name: []const u8,
) ![hash.SHA1_BYTES_LEN]u8 {
    // TODO: don't read it all into memory
    var current_buf = [_]u8{0} ** 1024;
    const current_content = try chk.objectToBuffer(repo_kind, core_cursor, std.fmt.bytesToHex(current_oid, .lower), &current_buf);
    var source_buf = [_]u8{0} ** 1024;
    const source_content = try chk.objectToBuffer(repo_kind, core_cursor, std.fmt.bytesToHex(source_oid, .lower), &source_buf);

    const content = try std.fmt.allocPrint(allocator, "<<<<<<< {s}\n{s}\n=======\n{s}\n>>>>>>> {s}", .{ current_name, current_content, source_content, source_name });
    defer allocator.free(content);
    var stream = std.io.fixedBufferStream(content);

    var oid = [_]u8{0} ** hash.SHA1_BYTES_LEN;
    try obj.writeBlob(repo_kind, core_cursor, allocator, &stream, content.len, std.io.FixedBufferStream([]u8).Reader, &oid);
    return oid;
}

pub const SamePathConflictResult = struct {
    change: ?obj.Change,
    conflict: ?MergeConflict,
};

fn samePathConflict(
    comptime repo_kind: rp.RepoKind,
    core_cursor: rp.Repo(repo_kind).CoreCursor,
    allocator: std.mem.Allocator,
    current_name: []const u8,
    source_name: []const u8,
    current_change_maybe: ?obj.Change,
    source_change: obj.Change,
) !SamePathConflictResult {
    if (current_change_maybe) |current_change| {
        const common_entry_maybe = source_change.old;

        if (current_change.new) |current_entry| {
            if (source_change.new) |source_entry| {
                if (current_entry.eql(source_entry)) {
                    // the current and source changes are the same,
                    // so no need to do anything
                    return .{ .change = null, .conflict = null };
                }

                // three-way merge of the oids
                const oid_maybe = blk: {
                    if (std.mem.eql(u8, &current_entry.oid, &source_entry.oid)) {
                        break :blk current_entry.oid;
                    } else if (common_entry_maybe) |common_entry| {
                        if (std.mem.eql(u8, &common_entry.oid, &current_entry.oid)) {
                            break :blk source_entry.oid;
                        } else if (std.mem.eql(u8, &common_entry.oid, &source_entry.oid)) {
                            break :blk current_entry.oid;
                        }
                    }
                    break :blk null;
                };

                // three-way merge of the modes
                const mode_maybe = blk: {
                    if (current_entry.mode.eql(source_entry.mode)) {
                        break :blk current_entry.mode;
                    } else if (common_entry_maybe) |common_entry| {
                        if (common_entry.mode.eql(current_entry.mode)) {
                            break :blk source_entry.mode;
                        } else if (common_entry.mode.eql(source_entry.mode)) {
                            break :blk current_entry.mode;
                        }
                    }
                    break :blk null;
                };

                const oid = oid_maybe orelse try writeBlobWithConflict(repo_kind, core_cursor, allocator, current_entry.oid, source_entry.oid, current_name, source_name);
                const mode = mode_maybe orelse current_entry.mode;

                return .{
                    .change = .{
                        .old = current_change.new,
                        .new = .{ .oid = oid, .mode = mode },
                    },
                    .conflict = if (oid_maybe == null or mode_maybe == null)
                        .{
                            .common = common_entry_maybe,
                            .current = current_entry,
                            .source = source_entry,
                            .renamed = null,
                        }
                    else
                        null,
                };
            } else {
                // source is null so just use the current oid and mode
                return .{
                    .change = .{
                        .old = current_change.new,
                        .new = .{ .oid = current_entry.oid, .mode = current_entry.mode },
                    },
                    .conflict = .{
                        .common = common_entry_maybe,
                        .current = current_entry,
                        .source = null,
                        .renamed = null,
                    },
                };
            }
        } else {
            if (source_change.new) |source_entry| {
                // current is null so just use the source oid and mode
                return .{
                    .change = .{
                        .old = current_change.new,
                        .new = .{ .oid = source_entry.oid, .mode = source_entry.mode },
                    },
                    .conflict = .{
                        .common = common_entry_maybe,
                        .current = null,
                        .source = source_entry,
                        .renamed = null,
                    },
                };
            } else {
                // deleted in current and source change,
                // so no need to do anything
                return .{ .change = null, .conflict = null };
            }
        }
    } else {
        // no conflict because the current diff doesn't touch this path
        return .{ .change = source_change, .conflict = null };
    }
}

fn fileDirConflict(
    arena: *std.heap.ArenaAllocator,
    comptime repo_kind: rp.RepoKind,
    path: []const u8,
    diff: *obj.TreeDiff(repo_kind),
    diff_kind: enum { current, source },
    branch_name: []const u8,
    conflicts: *std.StringArrayHashMap(MergeConflict),
    clean_diff: *obj.TreeDiff(repo_kind),
) !void {
    var parent_path_maybe = std.fs.path.dirname(path);
    while (parent_path_maybe) |parent_path| {
        if (diff.changes.get(parent_path)) |change| {
            if (change.new) |new| {
                const new_path = try std.fmt.allocPrint(arena.allocator(), "{s}~{s}", .{ parent_path, branch_name });
                switch (diff_kind) {
                    .current => {
                        // add the conflict
                        try conflicts.put(parent_path, .{
                            .common = change.old,
                            .current = new,
                            .source = null,
                            .renamed = .{
                                .path = new_path,
                                .tree_entry = new,
                            },
                        });
                        // remove from the working tree
                        try clean_diff.changes.put(parent_path, .{ .old = new, .new = null });
                    },
                    .source => {
                        // add the conflict
                        try conflicts.put(parent_path, .{
                            .common = change.old,
                            .current = null,
                            .source = new,
                            .renamed = .{
                                .path = new_path,
                                .tree_entry = new,
                            },
                        });
                        // prevent from being added to working tree
                        _ = clean_diff.changes.swapRemove(parent_path);
                    },
                }
            }
        }
        parent_path_maybe = std.fs.path.dirname(parent_path);
    }
}

pub const MergeInput = union(enum) {
    new: struct {
        source_name: []const u8,
    },
    cont,
};

pub const MergeResultData = union(enum) {
    success: struct {
        oid: [hash.SHA1_HEX_LEN]u8,
    },
    nothing,
    fast_forward,
    conflict: struct {
        conflicts: std.StringArrayHashMap(MergeConflict),
    },
};

pub const MergeResult = struct {
    arena: std.heap.ArenaAllocator,
    changes: std.StringArrayHashMap(obj.Change),
    auto_resolved_conflicts: std.StringArrayHashMap(void),
    current_name: []const u8,
    source_name: []const u8,
    data: MergeResultData,

    pub fn deinit(self: *MergeResult) void {
        self.arena.deinit();
    }
};

pub fn merge(
    comptime repo_kind: rp.RepoKind,
    core_cursor: rp.Repo(repo_kind).CoreCursor,
    allocator: std.mem.Allocator,
    input: MergeInput,
) !MergeResult {
    // TODO: exit early if working tree is dirty

    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();

    // get the current branch name and oid
    const current_name = try ref.readHeadName(repo_kind, core_cursor, arena.allocator());
    const current_oid = try ref.readHead(repo_kind, core_cursor);

    // init the diff that we will use for the migration and the conflicts maps.
    // they're using the arena because they'll be included in the result.
    var clean_diff = obj.TreeDiff(repo_kind).init(arena.allocator());
    var auto_resolved_conflicts = std.StringArrayHashMap(void).init(arena.allocator());
    var conflicts = std.StringArrayHashMap(MergeConflict).init(arena.allocator());

    switch (input) {
        .new => {
            // make sure there is no stored merge state
            switch (repo_kind) {
                .git => {
                    if (core_cursor.core.git_dir.openFile("MERGE_HEAD", .{ .mode = .read_only })) |merge_head| {
                        defer merge_head.close();
                        return error.UnfinishedMergeAlreadyInProgress;
                    } else |err| switch (err) {
                        error.FileNotFound => {},
                        else => return err,
                    }
                },
                .xit => {
                    if (try core_cursor.cursor.readCursor(void, &[_]xitdb.PathPart(void){
                        .{ .hash_map_get = hash.hashBuffer("MERGE_HEAD") },
                    })) |_| {
                        return error.UnfinishedMergeAlreadyInProgress;
                    }
                },
            }

            // we need to return the source name so copy it into a new buffer
            // so we an ensure it lives as long as the rest of the return struct
            const source_name = try arena.allocator().alloc(u8, input.new.source_name.len);
            @memcpy(source_name, input.new.source_name);

            // get the oids for the three-way merge
            const source_oid = try ref.resolve(repo_kind, core_cursor, source_name) orelse return error.InvalidTarget;
            const common_oid = try obj.commonAncestor(repo_kind, allocator, core_cursor, &current_oid, &source_oid);

            // if the common ancestor is the source oid, do nothing
            if (std.mem.eql(u8, &source_oid, &common_oid)) {
                return .{
                    .arena = arena,
                    .changes = clean_diff.changes,
                    .auto_resolved_conflicts = auto_resolved_conflicts,
                    .current_name = current_name,
                    .source_name = source_name,
                    .data = .nothing,
                };
            }

            // diff the common ancestor with the current oid
            var current_diff = obj.TreeDiff(repo_kind).init(arena.allocator());
            try current_diff.compare(core_cursor, common_oid, current_oid, null);

            // diff the common ancestor with the source oid
            var source_diff = obj.TreeDiff(repo_kind).init(arena.allocator());
            try source_diff.compare(core_cursor, common_oid, source_oid, null);

            // look for same path conflicts while populating the clean diff
            for (source_diff.changes.keys(), source_diff.changes.values()) |path, source_change| {
                const same_path_result = try samePathConflict(repo_kind, core_cursor, allocator, current_name, source_name, current_diff.changes.get(path), source_change);
                if (same_path_result.change) |change| {
                    try clean_diff.changes.put(path, change);
                }
                if (same_path_result.conflict) |conflict| {
                    try conflicts.put(path, conflict);
                } else {
                    try auto_resolved_conflicts.put(path, {});
                }
            }

            // look for file/dir conflicts
            for (source_diff.changes.keys(), source_diff.changes.values()) |path, source_change| {
                if (source_change.new) |_| {
                    try fileDirConflict(&arena, repo_kind, path, &current_diff, .current, current_name, &conflicts, &clean_diff);
                }
            }
            for (current_diff.changes.keys(), current_diff.changes.values()) |path, current_change| {
                if (current_change.new) |_| {
                    try fileDirConflict(&arena, repo_kind, path, &source_diff, .source, source_name, &conflicts, &clean_diff);
                }
            }

            // create commit message
            const commit_message = try std.fmt.allocPrint(allocator, "merge from {s}", .{source_name});
            defer allocator.free(commit_message);

            switch (repo_kind) {
                .git => {
                    // create lock file
                    var lock = try io.LockFile.init(allocator, core_cursor.core.git_dir, "index");
                    defer lock.deinit();

                    // read index
                    var index = try idx.Index(repo_kind).init(allocator, core_cursor);
                    defer index.deinit();

                    // update the working tree
                    try chk.migrate(repo_kind, core_cursor, allocator, clean_diff, &index, null);

                    for (conflicts.keys(), conflicts.values()) |path, conflict| {
                        // add conflict to index
                        try index.addConflictEntries(path, .{ conflict.common, conflict.current, conflict.source });
                        // write renamed file if necessary
                        if (conflict.renamed) |renamed| {
                            try chk.objectToFile(repo_kind, core_cursor, allocator, renamed.path, renamed.tree_entry);
                        }
                    }

                    // update the index
                    try index.write(allocator, .{ .core = core_cursor.core, .lock_file_maybe = lock.lock_file });

                    // finish lock
                    lock.success = true;

                    // exit early if there were conflicts
                    if (conflicts.count() > 0) {
                        const merge_head = try core_cursor.core.git_dir.createFile("MERGE_HEAD", .{ .truncate = true, .lock = .exclusive });
                        defer merge_head.close();
                        try merge_head.writeAll(&source_oid);

                        const merge_msg = try core_cursor.core.git_dir.createFile("MERGE_MSG", .{ .truncate = true, .lock = .exclusive });
                        defer merge_msg.close();
                        try merge_msg.writeAll(commit_message);

                        return .{
                            .arena = arena,
                            .changes = clean_diff.changes,
                            .auto_resolved_conflicts = auto_resolved_conflicts,
                            .current_name = current_name,
                            .source_name = source_name,
                            .data = .{ .conflict = .{ .conflicts = conflicts } },
                        };
                    }
                },
                .xit => {
                    // read index
                    var index = try idx.Index(repo_kind).init(allocator, core_cursor);
                    defer index.deinit();

                    // update the working tree
                    try chk.migrate(repo_kind, core_cursor, allocator, clean_diff, &index, null);

                    for (conflicts.keys(), conflicts.values()) |path, conflict| {
                        // add conflict to index
                        try index.addConflictEntries(path, .{ conflict.common, conflict.current, conflict.source });
                        // write renamed file if necessary
                        if (conflict.renamed) |renamed| {
                            try chk.objectToFile(repo_kind, core_cursor, allocator, renamed.path, renamed.tree_entry);
                        }
                    }

                    // add conflicts to index
                    for (conflicts.keys(), conflicts.values()) |path, conflict| {
                        try index.addConflictEntries(path, .{ conflict.common, conflict.current, conflict.source });
                    }

                    // update the index
                    try index.write(allocator, core_cursor);

                    // exit early if there were conflicts
                    if (conflicts.count() > 0) {
                        _ = try core_cursor.cursor.writeBytes(&source_oid, .replace, void, &[_]xitdb.PathPart(void){
                            .{ .hash_map_get = hash.hashBuffer("MERGE_HEAD") },
                        });
                        _ = try core_cursor.cursor.writeBytes(commit_message, .replace, void, &[_]xitdb.PathPart(void){
                            .{ .hash_map_get = hash.hashBuffer("MERGE_MSG") },
                        });
                        return .{
                            .arena = arena,
                            .changes = clean_diff.changes,
                            .auto_resolved_conflicts = auto_resolved_conflicts,
                            .current_name = current_name,
                            .source_name = source_name,
                            .data = .{ .conflict = .{ .conflicts = conflicts } },
                        };
                    }
                },
            }

            if (std.mem.eql(u8, &current_oid, &common_oid)) {
                // the common ancestor is the current oid, so just update HEAD
                try ref.updateRecur(repo_kind, core_cursor, allocator, &[_][]const u8{"HEAD"}, &source_oid);
                return .{
                    .arena = arena,
                    .changes = clean_diff.changes,
                    .auto_resolved_conflicts = auto_resolved_conflicts,
                    .current_name = current_name,
                    .source_name = source_name,
                    .data = .fast_forward,
                };
            }

            // commit the change
            const parent_oids = &[_][hash.SHA1_HEX_LEN]u8{ current_oid, source_oid };
            const commit_oid = try obj.writeCommit(repo_kind, core_cursor, allocator, parent_oids, commit_message);

            return .{
                .arena = arena,
                .changes = clean_diff.changes,
                .auto_resolved_conflicts = auto_resolved_conflicts,
                .current_name = current_name,
                .source_name = source_name,
                .data = .{ .success = .{ .oid = commit_oid } },
            };
        },
        .cont => {
            var source_oid: [hash.SHA1_HEX_LEN]u8 = undefined;
            var commit_message: []const u8 = undefined;

            // read the stored merge state
            switch (repo_kind) {
                .git => {
                    const merge_head = core_cursor.core.git_dir.openFile("MERGE_HEAD", .{ .mode = .read_only }) catch |err| switch (err) {
                        error.FileNotFound => return error.MergeHeadNotFound,
                        else => return err,
                    };
                    defer merge_head.close();
                    const merge_head_len = try merge_head.readAll(&source_oid);
                    if (merge_head_len != source_oid.len) {
                        return error.InvalidMergeHead;
                    }

                    const merge_msg = core_cursor.core.git_dir.openFile("MERGE_MSG", .{ .mode = .read_only }) catch |err| switch (err) {
                        error.FileNotFound => return error.MergeMessageNotFound,
                        else => return err,
                    };
                    defer merge_msg.close();
                    commit_message = try merge_msg.readToEndAlloc(arena.allocator(), MAX_READ_BYTES);
                },
                .xit => {
                    const source_oid_slice = (try core_cursor.cursor.readBytes(&source_oid, void, &[_]xitdb.PathPart(void){
                        .{ .hash_map_get = hash.hashBuffer("MERGE_HEAD") },
                    })) orelse return error.MergeHeadNotFound;
                    if (source_oid_slice.len != source_oid.len) {
                        return error.InvalidMergeHead;
                    }

                    commit_message = (try core_cursor.cursor.readBytesAlloc(arena.allocator(), MAX_READ_BYTES, void, &[_]xitdb.PathPart(void){
                        .{ .hash_map_get = hash.hashBuffer("MERGE_MSG") },
                    })) orelse return error.MergeMessageNotFound;
                },
            }

            // we need to return the source name but we don't have it,
            // so just copy the source oid into a buffer and return that instead
            const source_name = try arena.allocator().alloc(u8, source_oid.len);
            @memcpy(source_name, &source_oid);

            // commit the change
            const parent_oids = &[_][hash.SHA1_HEX_LEN]u8{ current_oid, source_oid };
            const commit_oid = try obj.writeCommit(repo_kind, core_cursor, allocator, parent_oids, commit_message);

            // clean up the stored merge state
            switch (repo_kind) {
                .git => {
                    try core_cursor.core.git_dir.deleteFile("MERGE_HEAD");
                    try core_cursor.core.git_dir.deleteFile("MERGE_MSG");
                },
                .xit => {
                    _ = try core_cursor.cursor.execute(void, &[_]xitdb.PathPart(void){
                        .{ .hash_map_remove = hash.hashBuffer("MERGE_HEAD") },
                    });
                    _ = try core_cursor.cursor.execute(void, &[_]xitdb.PathPart(void){
                        .{ .hash_map_remove = hash.hashBuffer("MERGE_MSG") },
                    });
                },
            }

            return .{
                .arena = arena,
                .changes = clean_diff.changes,
                .auto_resolved_conflicts = auto_resolved_conflicts,
                .current_name = current_name,
                .source_name = source_name,
                .data = .{ .success = .{ .oid = commit_oid } },
            };
        },
    }
}
