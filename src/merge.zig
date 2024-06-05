const std = @import("std");
const xitdb = @import("xitdb");
const hash = @import("./hash.zig");
const obj = @import("./object.zig");
const idx = @import("./index.zig");
const ref = @import("./ref.zig");
const chk = @import("./checkout.zig");
const io = @import("./io.zig");
const rp = @import("./repo.zig");

fn writeBlobWithConflict(
    comptime repo_kind: rp.RepoKind,
    core: *rp.Repo(repo_kind).Core,
    allocator: std.mem.Allocator,
    current_oid: [hash.SHA1_BYTES_LEN]u8,
    source_oid: [hash.SHA1_BYTES_LEN]u8,
    current_name: []const u8,
    source_name: []const u8,
) ![hash.SHA1_BYTES_LEN]u8 {
    // TODO: don't read it all into memory
    var current_buf = [_]u8{0} ** 1024;
    const current_content = try chk.objectToBuffer(repo_kind, core, std.fmt.bytesToHex(current_oid, .lower), &current_buf);
    var source_buf = [_]u8{0} ** 1024;
    const source_content = try chk.objectToBuffer(repo_kind, core, std.fmt.bytesToHex(source_oid, .lower), &source_buf);
    const content = try std.fmt.allocPrint(allocator, "<<<<<<< {s}\n{s}\n=======\n{s}\n>>>>>>> {s}", .{ current_name, current_content, source_content, source_name });
    defer allocator.free(content);
    var stream = std.io.fixedBufferStream(content);

    switch (repo_kind) {
        .git => {
            var objects_dir = try core.git_dir.openDir("objects", .{});
            defer objects_dir.close();

            var oid = [_]u8{0} ** hash.SHA1_BYTES_LEN;
            try obj.writeBlob(repo_kind, .{ .objects_dir = objects_dir }, allocator, &stream, content.len, std.io.FixedBufferStream([]u8).Reader, &oid);
            return oid;
        },
        .xit => {
            var oid = [_]u8{0} ** hash.SHA1_BYTES_LEN;
            const Ctx = struct {
                core: *rp.Repo(repo_kind).Core,
                allocator: std.mem.Allocator,
                oid: *[hash.SHA1_BYTES_LEN]u8,
                stream: *std.io.FixedBufferStream([]u8),
                content: []const u8,

                pub fn run(ctx_self: @This(), cursor: *xitdb.Database(.file).Cursor) !void {
                    try obj.writeBlob(repo_kind, .{ .root_cursor = cursor }, ctx_self.allocator, ctx_self.stream, ctx_self.content.len, std.io.FixedBufferStream([]u8).Reader, ctx_self.oid);
                }
            };
            _ = try core.db.rootCursor().execute(Ctx, &[_]xitdb.PathPart(Ctx){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .ctx = Ctx{ .core = core, .allocator = allocator, .oid = &oid, .stream = &stream, .content = content } },
            });
            return oid;
        },
    }
}

fn SamePathConflictResult(comptime repo_kind: rp.RepoKind) type {
    return struct {
        change: ?obj.TreeDiff(repo_kind).Change,
        conflict: ?[3]?obj.TreeEntry,
    };
}

fn samePathConflict(
    comptime repo_kind: rp.RepoKind,
    core: *rp.Repo(repo_kind).Core,
    allocator: std.mem.Allocator,
    current_name: []const u8,
    source_name: []const u8,
    current_change_maybe: ?obj.TreeDiff(repo_kind).Change,
    source_change: obj.TreeDiff(repo_kind).Change,
) !SamePathConflictResult(repo_kind) {
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

                const oid = oid_maybe orelse try writeBlobWithConflict(repo_kind, core, allocator, current_entry.oid, source_entry.oid, current_name, source_name);
                const mode = mode_maybe orelse current_entry.mode;

                return .{
                    .change = .{
                        .old = current_change.new,
                        .new = .{ .oid = oid, .mode = mode },
                    },
                    .conflict = if (oid_maybe == null or mode_maybe == null)
                        .{
                            common_entry_maybe,
                            current_entry,
                            source_entry,
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
                        common_entry_maybe,
                        current_entry,
                        null,
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
                        common_entry_maybe,
                        null,
                        source_entry,
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

const DiffKind = enum { current, source };
const RenamedEntry = struct { tree_entry: obj.TreeEntry, diff_kind: DiffKind };

fn fileDirConflict(
    comptime repo_kind: rp.RepoKind,
    path: []const u8,
    diff: *obj.TreeDiff(repo_kind),
    diff_kind: DiffKind,
    conflicts: *std.StringArrayHashMap([3]?obj.TreeEntry),
    clean_diff: *obj.TreeDiff(repo_kind),
    renamed: *std.StringArrayHashMap(RenamedEntry),
) !void {
    var parent_path_maybe = std.fs.path.dirname(path);
    while (parent_path_maybe) |parent_path| {
        if (diff.changes.get(parent_path)) |change| {
            if (change.new) |new| {
                switch (diff_kind) {
                    .current => {
                        // add the conflict
                        try conflicts.put(parent_path, .{ change.old, change.new, null });
                        // remove from the working tree
                        try clean_diff.changes.put(parent_path, .{ .old = new, .new = null });
                    },
                    .source => {
                        // add the conflict
                        try conflicts.put(parent_path, .{ change.old, null, change.new });
                        // prevent from being added to working tree
                        _ = clean_diff.changes.swapRemove(parent_path);
                    },
                }
                // add to renamed so we can put the file in a new place in the working tree
                try renamed.put(parent_path, .{ .tree_entry = new, .diff_kind = diff_kind });
            }
        }
        parent_path_maybe = std.fs.path.dirname(parent_path);
    }
}

fn writeRenamedFile(
    comptime repo_kind: rp.RepoKind,
    core: *rp.Repo(repo_kind).Core,
    allocator: std.mem.Allocator,
    current_name: []const u8,
    source_name: []const u8,
    path: []const u8,
    renamed_entry: RenamedEntry,
) !void {
    const suffix = switch (renamed_entry.diff_kind) {
        .current => current_name,
        .source => source_name,
    };
    const new_path = try std.fmt.allocPrint(allocator, "{s}~{s}", .{ path, suffix });
    defer allocator.free(new_path);
    try chk.objectToFile(repo_kind, core, allocator, new_path, renamed_entry.tree_entry);
}

pub const MergeResultData = union(enum) {
    success: struct {
        oid: [hash.SHA1_HEX_LEN]u8,
    },
    nothing,
    fast_forward,
    conflict,
};

pub const MergeResult = struct {
    data: MergeResultData,

    pub fn deinit(_: *MergeResult) void {}
};

pub fn merge(comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core, allocator: std.mem.Allocator, source_name: []const u8) !MergeResult {
    // get the current oid, source oid, and common oid
    const current_oid = try ref.readHead(repo_kind, core);
    const source_oid = try ref.resolve(repo_kind, core, source_name) orelse return error.InvalidTarget;
    const common_oid = try obj.commonAncestor(repo_kind, allocator, core, &current_oid, &source_oid);

    // get the name of HEAD
    const current_name = try ref.readHeadName(repo_kind, core, allocator);
    defer allocator.free(current_name);

    // if the common ancestor is the source oid, do nothing
    if (std.mem.eql(u8, &source_oid, &common_oid)) {
        return .{ .data = .nothing };
    }

    // diff the common ancestor with the current oid
    var current_diff = obj.TreeDiff(repo_kind).init(allocator);
    defer current_diff.deinit();
    try current_diff.compare(core, common_oid, current_oid, null);

    // diff the common ancestor with the source oid
    var source_diff = obj.TreeDiff(repo_kind).init(allocator);
    defer source_diff.deinit();
    try source_diff.compare(core, common_oid, source_oid, null);

    var clean_diff = obj.TreeDiff(repo_kind).init(allocator);
    defer clean_diff.deinit();
    var conflicts = std.StringArrayHashMap([3]?obj.TreeEntry).init(allocator);
    defer conflicts.deinit();

    // look for same path conflicts while populating the clean diff
    for (source_diff.changes.keys(), source_diff.changes.values()) |path, source_change| {
        const same_path_result = try samePathConflict(repo_kind, core, allocator, current_name, source_name, current_diff.changes.get(path), source_change);
        if (same_path_result.change) |change| {
            try clean_diff.changes.put(path, change);
        }
        if (same_path_result.conflict) |conflict| {
            try conflicts.put(path, conflict);
        }
    }

    // look for file/dir conflicts
    var renamed = std.StringArrayHashMap(RenamedEntry).init(allocator);
    defer renamed.deinit();
    for (source_diff.changes.keys(), source_diff.changes.values()) |path, source_change| {
        if (source_change.new) |_| {
            _ = try fileDirConflict(repo_kind, path, &current_diff, .current, &conflicts, &clean_diff, &renamed);
        }
    }
    for (current_diff.changes.keys(), current_diff.changes.values()) |path, current_change| {
        if (current_change.new) |_| {
            _ = try fileDirConflict(repo_kind, path, &source_diff, .source, &conflicts, &clean_diff, &renamed);
        }
    }

    // TODO: exit early if working tree is dirty

    switch (repo_kind) {
        .git => {
            // create lock file
            var lock = try io.LockFile.init(allocator, core.git_dir, "index");
            defer lock.deinit();

            // read index
            var index = try idx.Index(repo_kind).init(allocator, core);
            defer index.deinit();

            // update the working tree
            try chk.migrate(repo_kind, core, allocator, clean_diff, &index, null);

            // rename files that conflicted with dir names
            for (renamed.keys(), renamed.values()) |path, renamed_entry| {
                try writeRenamedFile(repo_kind, core, allocator, current_name, source_name, path, renamed_entry);
            }

            // add conflicts to index
            for (conflicts.keys(), conflicts.values()) |path, conflict_entries| {
                try index.addConflictEntries(path, conflict_entries);
            }

            // update the index
            try index.write(allocator, .{ .lock_file = lock.lock_file });

            // finish lock
            lock.success = true;

            // exit early if there were conflicts
            if (conflicts.count() > 0) {
                return .{ .data = .conflict };
            }
        },
        .xit => {
            // read index
            var index = try idx.Index(repo_kind).init(allocator, core);
            defer index.deinit();

            // update the working tree
            try chk.migrate(repo_kind, core, allocator, clean_diff, &index, null);

            // rename files that conflicted with dir names
            for (renamed.keys(), renamed.values()) |path, renamed_entry| {
                try writeRenamedFile(repo_kind, core, allocator, current_name, source_name, path, renamed_entry);
            }

            // add conflicts to index
            for (conflicts.keys(), conflicts.values()) |path, conflict_entries| {
                try index.addConflictEntries(path, conflict_entries);
            }

            // update the index
            try index.write(allocator, .{ .db = &core.db });

            // exit early if there were conflicts
            if (conflicts.count() > 0) {
                return .{ .data = .conflict };
            }
        },
    }

    if (std.mem.eql(u8, &current_oid, &common_oid)) {
        // the common ancestor is the current oid, so just update HEAD
        switch (repo_kind) {
            .git => {
                try ref.updateRecur(repo_kind, core, .{ .dir = core.git_dir }, allocator, "HEAD", &source_oid);
            },
            .xit => {
                const Ctx = struct {
                    core: *rp.Repo(repo_kind).Core,
                    allocator: std.mem.Allocator,
                    oid: *const [hash.SHA1_HEX_LEN]u8,

                    pub fn run(ctx_self: *@This(), cursor: *xitdb.Database(.file).Cursor) !void {
                        try ref.updateRecur(repo_kind, ctx_self.core, .{ .root_cursor = cursor }, ctx_self.allocator, "HEAD", ctx_self.oid);
                    }
                };
                var ctx = Ctx{
                    .core = core,
                    .allocator = allocator,
                    .oid = &source_oid,
                };
                // TODO: do the index.write above in the same transaction as this
                _ = try core.db.rootCursor().execute(*Ctx, &[_]xitdb.PathPart(*Ctx){
                    .{ .array_list_get = .append_copy },
                    .hash_map_create,
                    .{ .ctx = &ctx },
                });
            },
        }
        return .{ .data = .fast_forward };
    } else {
        // create commit message
        const commit_message = try std.fmt.allocPrint(allocator, "merge from {s}", .{source_name});
        defer allocator.free(commit_message);

        // commit the change
        const parent_oids = &[_][hash.SHA1_HEX_LEN]u8{ current_oid, source_oid };
        var sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
        try obj.writeCommit(repo_kind, core, allocator, parent_oids, commit_message, &sha1_bytes_buffer);

        return .{ .data = .{ .success = .{ .oid = std.fmt.bytesToHex(sha1_bytes_buffer, .lower) } } };
    }
}
