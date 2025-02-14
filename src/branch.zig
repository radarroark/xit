const std = @import("std");
const hash = @import("./hash.zig");
const rf = @import("./ref.zig");
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
    return rf.validateName(name) and !std.mem.eql(u8, "HEAD", name);
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

    if (try rf.exists(repo_kind, repo_opts, state.readOnly(), .{ .kind = .head, .name = input.name })) {
        return error.BranchAlreadyExists;
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

            // get HEAD contents and write to lock file
            const oid_maybe = rf.readHeadRecurMaybe(repo_kind, repo_opts, state.readOnly()) catch |err| switch (err) {
                error.RefNotFound => null,
                else => |e| return e,
            };
            if (oid_maybe) |oid| {
                try lock.lock_file.writeAll(&oid);
                try lock.lock_file.writeAll("\n");
                lock.success = true;
            }
        },
        .xit => {
            const name_hash = hash.hashInt(repo_opts.hash, name);

            // store ref name
            const ref_name_set_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "ref-name-set"));
            const ref_name_set = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(ref_name_set_cursor);
            var ref_name_cursor = try ref_name_set.putKeyCursor(name_hash);
            try ref_name_cursor.writeIfEmpty(.{ .bytes = name });

            // add ref name to refs/heads/{refname}
            const refs_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "refs"));
            const refs = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(refs_cursor);
            const heads_cursor = try refs.putCursor(hash.hashInt(repo_opts.hash, "heads"));
            const heads = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(heads_cursor);
            try heads.putKey(name_hash, .{ .slot = ref_name_cursor.slot() });

            // store ref content
            const oid_maybe = rf.readHeadRecurMaybe(repo_kind, repo_opts, state.readOnly()) catch |err| switch (err) {
                error.RefNotFound => null,
                else => |e| return e,
            };
            if (oid_maybe) |oid| {
                const ref_content_set_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "ref-content-set"));
                const ref_content_set = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(ref_content_set_cursor);
                var ref_content_cursor = try ref_content_set.putKeyCursor(hash.hashInt(repo_opts.hash, &oid));
                try ref_content_cursor.writeIfEmpty(.{ .bytes = &oid });
                try heads.put(name_hash, .{ .slot = ref_content_cursor.slot() });
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
    // don't allow current branch to be deleted
    var current_branch_buffer = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
    if (try rf.readHead(repo_kind, repo_opts, state.readOnly(), &current_branch_buffer)) |current_branch| {
        switch (current_branch) {
            .ref => |ref| if (std.mem.eql(u8, input.name, ref.name)) {
                return error.CannotDeleteCurrentBranch;
            },
            .oid => {},
        }
    }

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
            const name_hash = hash.hashInt(repo_opts.hash, input.name);

            // remove from refs/heads/{name}
            const refs_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "refs"));
            const refs = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(refs_cursor);
            const heads_cursor = try refs.putCursor(hash.hashInt(repo_opts.hash, "heads"));
            const heads = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(heads_cursor);
            _ = try heads.remove(name_hash);
        },
    }
}
