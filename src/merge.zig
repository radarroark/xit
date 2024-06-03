const std = @import("std");
const xitdb = @import("xitdb");
const hash = @import("./hash.zig");
const obj = @import("./object.zig");
const idx = @import("./index.zig");
const ref = @import("./ref.zig");
const chk = @import("./checkout.zig");
const io = @import("./io.zig");
const rp = @import("./repo.zig");

fn ThreeWayMergeResult(comptime T: type) type {
    return struct {
        ok: bool,
        value: T,
    };
}

fn eql(comptime T: type, a: T, b: T) bool {
    if (T == [hash.SHA1_BYTES_LEN]u8) {
        return std.mem.eql(u8, &a, &b);
    } else {
        return a.eql(b);
    }
}

fn threeWayMerge(comptime T: type, common_maybe: ?T, current_maybe: ?T, source_maybe: ?T) ?ThreeWayMergeResult(T) {
    if (current_maybe) |current| {
        if (source_maybe) |source| {
            if (eql(T, current, source)) {
                return .{
                    .ok = true,
                    .value = current,
                };
            } else if (common_maybe) |common| {
                if (eql(T, common, current)) {
                    return .{
                        .ok = true,
                        .value = source,
                    };
                } else if (eql(T, common, source)) {
                    return .{
                        .ok = true,
                        .value = current,
                    };
                }
            }

            return null;
        } else {
            return .{
                .ok = false,
                .value = current,
            };
        }
    } else {
        if (source_maybe) |source| {
            return .{
                .ok = true,
                .value = source,
            };
        } else {
            // should never get here, one of source or current should be non-null
            return null;
        }
    }
}

fn writeBlobWithConflict(
    comptime repo_kind: rp.RepoKind,
    core: *rp.Repo(repo_kind).Core,
    allocator: std.mem.Allocator,
    path: []const u8,
) ![hash.SHA1_BYTES_LEN]u8 {
    // TODO: actually write the blob with conflict markers correctly
    switch (repo_kind) {
        .git => {
            var objects_dir = try core.git_dir.openDir("objects", .{});
            defer objects_dir.close();

            // write the object
            var oid = [_]u8{0} ** hash.SHA1_BYTES_LEN;
            try obj.writeBlob(repo_kind, core, .{ .objects_dir = objects_dir }, allocator, path, &oid);
            return oid;
        },
        .xit => {
            var oid = [_]u8{0} ** hash.SHA1_BYTES_LEN;
            const Ctx = struct {
                core: *rp.Repo(repo_kind).Core,
                allocator: std.mem.Allocator,
                path: []const u8,
                oid: *[hash.SHA1_BYTES_LEN]u8,

                pub fn run(ctx_self: @This(), cursor: *xitdb.Database(.file).Cursor) !void {
                    try obj.writeBlob(repo_kind, ctx_self.core, .{ .root_cursor = cursor }, ctx_self.allocator, ctx_self.path, ctx_self.oid);
                }
            };
            _ = try core.db.rootCursor().execute(Ctx, &[_]xitdb.PathPart(Ctx){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .ctx = Ctx{ .core = core, .allocator = allocator, .path = path, .oid = &oid } },
            });
            return oid;
        },
    }
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

pub fn merge(comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core, allocator: std.mem.Allocator, source: []const u8) !MergeResult {
    // get the current oid, source oid, and common oid
    const current_oid = try ref.readHead(repo_kind, core);
    const source_oid = try ref.resolve(repo_kind, core, source) orelse return error.InvalidTarget;
    const common_oid = try obj.commonAncestor(repo_kind, allocator, core, &current_oid, &source_oid);

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

    // build a diff that can be applied cleanly,
    // and separately keep track of conflicts
    var clean_diff = obj.TreeDiff(repo_kind).init(allocator);
    defer clean_diff.deinit();
    var conflicts = std.ArrayList(obj.TreeEntry).init(allocator);
    defer conflicts.deinit();
    for (source_diff.changes.keys(), source_diff.changes.values()) |path, source_change| {
        if (current_diff.changes.get(path)) |current_change| {
            const common_entry_maybe = source_change.old;

            if (source_change.new) |source_entry| {
                if (current_change.new) |current_entry| {
                    if (source_entry.eql(current_entry)) {
                        // the source and current changes are the same,
                        // so no need to do anything
                        continue;
                    }
                }

                const oid_result_maybe = threeWayMerge(
                    [hash.SHA1_BYTES_LEN]u8,
                    if (common_entry_maybe) |old| old.oid else null,
                    if (current_change.new) |new| new.oid else null,
                    source_entry.oid,
                );
                const mode_result_maybe = threeWayMerge(
                    io.Mode,
                    if (common_entry_maybe) |old| old.mode else null,
                    if (current_change.new) |new| new.mode else null,
                    source_entry.mode,
                );

                const oid_result: ThreeWayMergeResult([hash.SHA1_BYTES_LEN]u8) = oid_result_maybe orelse .{
                    .ok = false,
                    .value = try writeBlobWithConflict(repo_kind, core, allocator, path),
                };
                const mode_result: ThreeWayMergeResult(io.Mode) = mode_result_maybe orelse .{
                    .ok = false,
                    .value = if (current_change.new) |current_entry| current_entry.mode else source_entry.mode,
                };
                try clean_diff.changes.put(path, .{
                    .old = current_change.new,
                    .new = .{ .oid = oid_result.value, .mode = mode_result.value },
                });
            } else {
                if (current_change.new) |current_entry| {
                    const oid_result_maybe = threeWayMerge(
                        [hash.SHA1_BYTES_LEN]u8,
                        if (common_entry_maybe) |old| old.oid else null,
                        current_entry.oid,
                        null,
                    );
                    const mode_result_maybe = threeWayMerge(
                        io.Mode,
                        if (common_entry_maybe) |old| old.mode else null,
                        current_entry.mode,
                        null,
                    );

                    const oid_result: ThreeWayMergeResult([hash.SHA1_BYTES_LEN]u8) = oid_result_maybe orelse .{
                        .ok = false,
                        .value = try writeBlobWithConflict(repo_kind, core, allocator, path),
                    };
                    const mode_result: ThreeWayMergeResult(io.Mode) = mode_result_maybe orelse .{ .ok = false, .value = current_entry.mode };
                    try clean_diff.changes.put(path, .{
                        .old = current_change.new,
                        .new = .{ .oid = oid_result.value, .mode = mode_result.value },
                    });
                } else {
                    // deleted in source and current change,
                    // so no need to do anything
                    continue;
                }
            }
        } else {
            // the current diff doesn't touch this path, so there
            // can't be a conflict
            try clean_diff.changes.put(path, source_change);
        }
    }

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

            // update the index
            try index.write(allocator, .{ .lock_file = lock.lock_file });

            // finish lock
            lock.success = true;
        },
        .xit => {
            // read index
            var index = try idx.Index(repo_kind).init(allocator, core);
            defer index.deinit();

            // update the working tree
            try chk.migrate(repo_kind, core, allocator, clean_diff, &index, null);

            // update the index
            try index.write(allocator, .{ .db = &core.db });
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
        const commit_message = try std.fmt.allocPrint(allocator, "merge from {s}", .{source});
        defer allocator.free(commit_message);

        // commit the change
        const parent_oids = &[_][hash.SHA1_HEX_LEN]u8{ current_oid, source_oid };
        var sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
        try obj.writeCommit(repo_kind, core, allocator, parent_oids, commit_message, &sha1_bytes_buffer);

        return .{ .data = .{ .success = .{ .oid = std.fmt.bytesToHex(sha1_bytes_buffer, .lower) } } };
    }
}
