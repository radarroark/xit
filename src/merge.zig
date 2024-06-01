const std = @import("std");
const xitdb = @import("xitdb");
const hash = @import("./hash.zig");
const obj = @import("./object.zig");
const idx = @import("./index.zig");
const ref = @import("./ref.zig");
const chk = @import("./checkout.zig");
const io = @import("./io.zig");
const rp = @import("./repo.zig");

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

    // compare the commits
    var tree_diff = obj.TreeDiff(repo_kind).init(allocator);
    defer tree_diff.deinit();
    try tree_diff.compare(core, common_oid, source_oid, null);

    switch (repo_kind) {
        .git => {
            // create lock file
            var lock = try io.LockFile.init(allocator, core.git_dir, "index");
            defer lock.deinit();

            // read index
            var index = try idx.Index(repo_kind).init(allocator, core);
            defer index.deinit();

            // update the working tree
            try chk.migrate(repo_kind, core, allocator, tree_diff, &index, null);

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
            try chk.migrate(repo_kind, core, allocator, tree_diff, &index, null);

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
                        try ref.updateRecur(repo_kind, ctx_self.core, .{ .root_cursor = cursor, .cursor = cursor }, ctx_self.allocator, "HEAD", ctx_self.oid);
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
