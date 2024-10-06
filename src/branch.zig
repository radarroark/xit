const std = @import("std");
const hash = @import("./hash.zig");
const ref = @import("./ref.zig");
const io = @import("./io.zig");
const rp = @import("./repo.zig");

pub const BranchCommand = union(enum) {
    list,
    add: AddBranchInput,
    remove: RemoveBranchInput,
};

pub const AddBranchInput = struct {
    name: []const u8,
};

pub const RemoveBranchInput = struct {
    name: []const u8,
};

pub fn add(comptime repo_kind: rp.RepoKind, state: rp.Repo(repo_kind).State, allocator: std.mem.Allocator, input: AddBranchInput) !void {
    const name = input.name;
    if (name.len == 0 or
        name[0] == '.' or
        name[0] == '/' or
        std.mem.endsWith(u8, name, "/") or
        std.mem.endsWith(u8, name, ".lock") or
        std.mem.indexOf(u8, name, "..") != null or
        std.mem.indexOf(u8, name, "@") != null or
        std.mem.indexOf(u8, name, "//") != null)
    {
        return error.InvalidBranchName;
    }

    switch (repo_kind) {
        .git => {
            var refs_dir = try state.core.git_dir.openDir("refs", .{});
            defer refs_dir.close();
            var heads_dir = try refs_dir.makeOpenPath("heads", .{});
            defer heads_dir.close();

            // if there are any slashes in the branch name,
            // we must treat it as a path and make dirs.
            // why? i have no idea! what is the point of this, linus!
            var leaf_name = name;
            var subdir_maybe = blk: {
                if (std.mem.lastIndexOf(u8, name, "/")) |last_slash| {
                    leaf_name = name[last_slash + 1 ..];
                    break :blk try heads_dir.makeOpenPath(name[0..last_slash], .{});
                } else {
                    break :blk null;
                }
            };
            defer if (subdir_maybe) |*subdir| subdir.close();

            // create lock file
            var lock = try io.LockFile.init(allocator, if (subdir_maybe) |subdir| subdir else heads_dir, leaf_name);
            defer lock.deinit();

            // get HEAD contents
            const head_file_buffer = try ref.readHead(repo_kind, state);

            // write to lock file
            try lock.lock_file.writeAll(&head_file_buffer);
            try lock.lock_file.writeAll("\n");

            // finish lock
            lock.success = true;
        },
        .xit => {
            const name_hash = hash.hashBuffer(name);

            // store ref name
            var ref_name_cursor = try state.cursor.writePath(void, &.{
                .{ .hash_map_get = .{ .value = hash.hashBuffer("ref-name-set") } },
                .hash_map_init,
                .{ .hash_map_get = .{ .key = name_hash } },
            });
            try ref_name_cursor.writeBytes(name, .once);
            const name_slot = ref_name_cursor.slot_ptr.slot;

            // add ref name to refs/heads/{refname}
            _ = try state.cursor.writePath(void, &.{
                .{ .hash_map_get = .{ .value = hash.hashBuffer("refs") } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = hash.hashBuffer("heads") } },
                .hash_map_init,
                .{ .hash_map_get = .{ .key = name_hash } },
                .{ .write = .{ .slot = name_slot } },
            });

            // store ref content
            const head_file_buffer = try ref.readHead(repo_kind, state);
            var ref_content_cursor = try state.cursor.writePath(void, &.{
                .{ .hash_map_get = .{ .value = hash.hashBuffer("ref-content-set") } },
                .hash_map_init,
                .{ .hash_map_get = .{ .key = hash.hashBuffer(&head_file_buffer) } },
            });
            try ref_content_cursor.writeBytes(&head_file_buffer, .once);
            const ref_content_slot = ref_content_cursor.slot_ptr.slot;

            // add ref content to refs/heads/{refname}
            _ = try state.cursor.writePath(void, &.{
                .{ .hash_map_get = .{ .value = hash.hashBuffer("refs") } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = hash.hashBuffer("heads") } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = name_hash } },
                .{ .write = .{ .slot = ref_content_slot } },
            });

            // get current branch name
            const current_branch_name = try ref.readHeadName(repo_kind, state, allocator);
            defer allocator.free(current_branch_name);

            // if there is a branch map for the current branch,
            // make one for the new branch with the same value
            const branch_name_hash = hash.hashBuffer(current_branch_name);
            if (try state.cursor.readPath(void, &.{
                .{ .hash_map_get = .{ .value = hash.hashBuffer("branches") } },
                .{ .hash_map_get = .{ .value = branch_name_hash } },
            })) |*current_branch_cursor| {
                _ = try state.cursor.writePath(void, &.{
                    .{ .hash_map_get = .{ .value = hash.hashBuffer("branches") } },
                    .hash_map_init,
                    .{ .hash_map_get = .{ .key = name_hash } },
                    .{ .write = .{ .slot = name_slot } },
                });
                _ = try state.cursor.writePath(void, &.{
                    .{ .hash_map_get = .{ .value = hash.hashBuffer("branches") } },
                    .hash_map_init,
                    .{ .hash_map_get = .{ .value = name_hash } },
                    .{ .write = .{ .slot = current_branch_cursor.slot_ptr.slot } },
                });
            }
        },
    }
}

pub fn remove(comptime repo_kind: rp.RepoKind, state: rp.Repo(repo_kind).State, allocator: std.mem.Allocator, input: RemoveBranchInput) !void {
    switch (repo_kind) {
        .git => {
            var refs_dir = try state.core.git_dir.openDir("refs", .{});
            defer refs_dir.close();
            var heads_dir = try refs_dir.makeOpenPath("heads", .{});
            defer heads_dir.close();

            // get absolute paths
            var heads_dir_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
            const heads_dir_path = try heads_dir.realpath(".", &heads_dir_buffer);
            var ref_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
            const ref_path = try heads_dir.realpath(input.name, &ref_buffer);

            // create lock file for HEAD
            var head_lock = try io.LockFile.init(allocator, state.core.git_dir, "HEAD");
            defer head_lock.deinit();

            // don't allow current branch to be deleted
            var current_branch_maybe = try ref.Ref.initFromLink(repo_kind, state, allocator, "HEAD");
            defer if (current_branch_maybe) |*current_branch| current_branch.deinit();
            if (current_branch_maybe) |current_branch| {
                if (std.mem.eql(u8, current_branch.name, input.name)) {
                    return error.CannotDeleteCurrentBranch;
                }
            }

            // delete file
            try heads_dir.deleteFile(input.name);

            // delete parent dirs
            // this is only necessary because branches with a slash
            // in their name are stored on disk as subdirectories
            var parent_path_maybe = std.fs.path.dirname(ref_path);
            while (parent_path_maybe) |parent_path| {
                if (std.mem.eql(u8, heads_dir_path, parent_path)) {
                    break;
                }

                std.fs.deleteDirAbsolute(parent_path) catch |err| switch (err) {
                    error.DirNotEmpty => break,
                    else => return err,
                };
                parent_path_maybe = std.fs.path.dirname(parent_path);
            }
        },
        .xit => {
            // don't allow current branch to be deleted
            var current_branch_maybe = try ref.Ref.initFromLink(repo_kind, state, allocator, "HEAD");
            defer if (current_branch_maybe) |*current_branch| current_branch.deinit();
            if (current_branch_maybe) |current_branch| {
                if (std.mem.eql(u8, current_branch.name, input.name)) {
                    return error.CannotDeleteCurrentBranch;
                }
            }

            const name_hash = hash.hashBuffer(input.name);

            // remove from refs/heads/{name}
            _ = try state.cursor.writePath(void, &.{
                .{ .hash_map_get = .{ .value = hash.hashBuffer("refs") } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = hash.hashBuffer("heads") } },
                .hash_map_init,
                .{ .hash_map_remove = name_hash },
            });

            // remove branch map
            _ = try state.cursor.writePath(void, &.{
                .{ .hash_map_get = .{ .value = hash.hashBuffer("branches") } },
                .hash_map_init,
                .{ .hash_map_remove = name_hash },
            });
        },
    }
}
