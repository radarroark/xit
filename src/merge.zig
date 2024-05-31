const std = @import("std");
const hash = @import("./hash.zig");
const obj = @import("./object.zig");
const idx = @import("./index.zig");
const ref = @import("./ref.zig");
const chk = @import("./checkout.zig");
const io = @import("./io.zig");
const rp = @import("./repo.zig");

pub fn merge(comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core, allocator: std.mem.Allocator, source: []const u8) ![hash.SHA1_HEX_LEN]u8 {
    // get the current oid, source oid, and common oid
    const current_oid = try ref.readHead(repo_kind, core);
    const source_oid = try ref.resolve(repo_kind, core, source) orelse return error.InvalidTarget;
    const common_oid = try obj.commonAncestor(repo_kind, allocator, core, &current_oid, &source_oid);

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

    // create commit message
    const commit_message = try std.fmt.allocPrint(allocator, "merge from {s}", .{source});
    defer allocator.free(commit_message);

    // commit the change
    const parent_oids = &[_][hash.SHA1_HEX_LEN]u8{ current_oid, source_oid };
    var sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
    try obj.writeCommit(repo_kind, core, allocator, parent_oids, commit_message, &sha1_bytes_buffer);

    return std.fmt.bytesToHex(sha1_bytes_buffer, .lower);
}
