const std = @import("std");
const hash = @import("./hash.zig");
const ref = @import("./ref.zig");
const fs = @import("./fs.zig");
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

pub fn validateName(name: []const u8) bool {
    return ref.validateName(name) and !std.mem.eql(u8, "HEAD", name);
}

pub fn add(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    input: AddBranchInput,
) !void {
    const name = input.name;
    if (!validateName(name)) {
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
            var lock = try fs.LockFile.init(if (subdir_maybe) |subdir| subdir else heads_dir, leaf_name);
            defer lock.deinit();

            // get HEAD contents
            const head_file_buffer = try ref.readHead(repo_kind, repo_opts, state.readOnly());

            // write to lock file
            try lock.lock_file.writeAll(&head_file_buffer);
            try lock.lock_file.writeAll("\n");

            // finish lock
            lock.success = true;
        },
        .xit => {
            const name_hash = hash.hashInt(repo_opts.hash, name);

            // store ref name
            const ref_name_set_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "ref-name-set"));
            const ref_name_set = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(ref_name_set_cursor);
            var ref_name_cursor = try ref_name_set.putKeyCursor(name_hash);
            try ref_name_cursor.writeIfEmpty(.{ .bytes = name });

            // store ref content
            const head_file_buffer = try ref.readHead(repo_kind, repo_opts, state.readOnly());
            const ref_content_set_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "ref-content-set"));
            const ref_content_set = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(ref_content_set_cursor);
            var ref_content_cursor = try ref_content_set.putKeyCursor(hash.hashInt(repo_opts.hash, &head_file_buffer));
            try ref_content_cursor.writeIfEmpty(.{ .bytes = &head_file_buffer });

            // add ref name and content to refs/heads/{refname}
            const refs_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "refs"));
            const refs = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(refs_cursor);
            const heads_cursor = try refs.putCursor(hash.hashInt(repo_opts.hash, "heads"));
            const heads = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(heads_cursor);
            try heads.putKey(name_hash, .{ .slot = ref_name_cursor.slot() });
            try heads.put(name_hash, .{ .slot = ref_content_cursor.slot() });

            // get current branch name
            var current_branch_name_buffer = [_]u8{0} ** ref.MAX_REF_CONTENT_SIZE;
            const current_branch_name = try ref.readHeadName(repo_kind, repo_opts, state.readOnly(), &current_branch_name_buffer);

            // if there is a branch map for the current branch,
            // make one for the new branch with the same value
            const branches_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "branches"));
            const branches = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(branches_cursor);
            try branches.putKey(name_hash, .{ .slot = ref_name_cursor.slot() });
            if (try branches.getCursor(hash.hashInt(repo_opts.hash, current_branch_name))) |*current_branch_cursor| {
                try branches.put(name_hash, .{ .slot = current_branch_cursor.slot() });
            }
        },
    }
}

pub fn remove(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    input: RemoveBranchInput,
) !void {
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
            var head_lock = try fs.LockFile.init(state.core.git_dir, "HEAD");
            defer head_lock.deinit();

            // don't allow current branch to be deleted
            var current_branch_name_buffer = [_]u8{0} ** ref.MAX_REF_CONTENT_SIZE;
            const current_branch_name = try ref.readHeadName(repo_kind, repo_opts, state.readOnly(), &current_branch_name_buffer);
            if (std.mem.eql(u8, current_branch_name, input.name)) {
                return error.CannotDeleteCurrentBranch;
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
                    else => |e| return e,
                };
                parent_path_maybe = std.fs.path.dirname(parent_path);
            }
        },
        .xit => {
            // don't allow current branch to be deleted
            var current_branch_name_buffer = [_]u8{0} ** ref.MAX_REF_CONTENT_SIZE;
            const current_branch_name = try ref.readHeadName(repo_kind, repo_opts, state.readOnly(), &current_branch_name_buffer);
            if (std.mem.eql(u8, current_branch_name, input.name)) {
                return error.CannotDeleteCurrentBranch;
            }

            const name_hash = hash.hashInt(repo_opts.hash, input.name);

            // remove from refs/heads/{name}
            const refs_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "refs"));
            const refs = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(refs_cursor);
            const heads_cursor = try refs.putCursor(hash.hashInt(repo_opts.hash, "heads"));
            const heads = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(heads_cursor);
            _ = try heads.remove(name_hash);

            // remove branch map
            const branches_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "branches"));
            const branches = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(branches_cursor);
            _ = try branches.remove(name_hash);
        },
    }
}
