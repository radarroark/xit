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

fn threeWayMergeOid(common_maybe: ?[hash.SHA1_BYTES_LEN]u8, current: [hash.SHA1_BYTES_LEN]u8, source: [hash.SHA1_BYTES_LEN]u8) ?ThreeWayMergeResult([hash.SHA1_BYTES_LEN]u8) {
    if (std.mem.eql(u8, &current, &source)) {
        return .{
            .ok = true,
            .value = current,
        };
    } else if (common_maybe) |common| {
        if (std.mem.eql(u8, &common, &current)) {
            return .{
                .ok = true,
                .value = source,
            };
        } else if (std.mem.eql(u8, &common, &source)) {
            return .{
                .ok = true,
                .value = current,
            };
        }
    }

    return null;
}

fn threeWayMergeMode(common_maybe: ?io.Mode, current: io.Mode, source: io.Mode) ?ThreeWayMergeResult(io.Mode) {
    if (current.eql(source)) {
        return .{
            .ok = true,
            .value = current,
        };
    } else if (common_maybe) |common| {
        if (common.eql(current)) {
            return .{
                .ok = true,
                .value = source,
            };
        } else if (common.eql(source)) {
            return .{
                .ok = true,
                .value = current,
            };
        }
    }

    return null;
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

            var file = try core.repo_dir.openFile(path, .{ .mode = .read_only });
            defer file.close();

            // get file size
            const meta = try file.metadata();
            if (meta.kind() != std.fs.File.Kind.file) {
                return error.NotAFile;
            }
            const file_size = meta.size();

            // write the object
            var oid = [_]u8{0} ** hash.SHA1_BYTES_LEN;
            try obj.writeBlob(repo_kind, .{ .objects_dir = objects_dir }, allocator, file, file_size, std.fs.File.Reader, &oid);
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
                    var file = try ctx_self.core.repo_dir.openFile(ctx_self.path, .{ .mode = .read_only });
                    defer file.close();

                    // get file size
                    const meta = try file.metadata();
                    if (meta.kind() != std.fs.File.Kind.file) {
                        return error.NotAFile;
                    }
                    const file_size = meta.size();

                    try obj.writeBlob(repo_kind, .{ .root_cursor = cursor }, ctx_self.allocator, file, file_size, std.fs.File.Reader, ctx_self.oid);
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

                    const oid_result = threeWayMergeOid(
                        if (common_entry_maybe) |old| old.oid else null,
                        current_entry.oid,
                        source_entry.oid,
                    ) orelse ThreeWayMergeResult([hash.SHA1_BYTES_LEN]u8){
                        .ok = false,
                        .value = try writeBlobWithConflict(repo_kind, core, allocator, path),
                    };
                    const mode_result = threeWayMergeMode(
                        if (common_entry_maybe) |old| old.mode else null,
                        current_entry.mode,
                        source_entry.mode,
                    ) orelse ThreeWayMergeResult(io.Mode){
                        .ok = false,
                        .value = current_entry.mode,
                    };

                    try clean_diff.changes.put(path, .{
                        .old = current_change.new,
                        .new = .{ .oid = oid_result.value, .mode = mode_result.value },
                    });
                } else {
                    // current is null so we just use the source oid and mode
                    try clean_diff.changes.put(path, .{
                        .old = current_change.new,
                        .new = .{ .oid = source_entry.oid, .mode = source_entry.mode },
                    });
                }
            } else {
                if (current_change.new) |current_entry| {
                    // source is null so we just use the current oid and mode
                    try clean_diff.changes.put(path, .{
                        .old = current_change.new,
                        .new = .{ .oid = current_entry.oid, .mode = current_entry.mode },
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
