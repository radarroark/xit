const std = @import("std");
const xitdb = @import("xitdb");
const ref = @import("./ref.zig");
const io = @import("./io.zig");
const rp = @import("./repo.zig");

pub const BranchError = error{
    InvalidBranchName,
    CannotDeleteCurrentBranch,
};

pub fn create(comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core, allocator: std.mem.Allocator, name: []const u8) !void {
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
            var refs_dir = try core.git_dir.openDir("refs", .{});
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
            const head_file_buffer = try ref.readHead(repo_kind, core);

            // write to lock file
            try lock.lock_file.writeAll(&head_file_buffer);
            try lock.lock_file.writeAll("\n");

            // finish lock
            lock.success = true;
        },
        .xit => {
            const Ctx = struct {
                core: *rp.Repo(repo_kind).Core,
                name: []const u8,

                pub fn update(ctx_self: @This(), cursor: xitdb.Database(.file).Cursor, _: bool) !void {
                    // get HEAD contents
                    // TODO: make `readHead` use cursor for tx safety
                    const head_file_buffer = try ref.readHead(repo_kind, ctx_self.core);

                    const HeadsCtx = struct {
                        name: []const u8,
                        head_file_buffer: []const u8,

                        pub fn update(heads_ctx_self: @This(), heads_cursor: xitdb.Database(.file).Cursor, _: bool) !void {
                            try heads_cursor.execute(void, &[_]xitdb.PathPart(void){
                                .{ .map_get = .{ .bytes = heads_ctx_self.name } },
                                .{ .value = .{ .bytes = heads_ctx_self.head_file_buffer } },
                            });
                        }
                    };
                    try cursor.execute(HeadsCtx, &[_]xitdb.PathPart(HeadsCtx){
                        .{ .map_get = .{ .bytes = "refs" } },
                        .map_create,
                        .{ .map_get = .{ .bytes = "heads" } },
                        .map_create,
                        .{ .update = HeadsCtx{ .name = ctx_self.name, .head_file_buffer = &head_file_buffer } },
                    });
                }
            };
            try core.db.rootCursor().execute(Ctx, &[_]xitdb.PathPart(Ctx){
                .{ .list_get = .append_copy },
                .map_create,
                .{ .update = Ctx{ .core = core, .name = name } },
            });
        },
    }
}

pub fn delete(comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core, allocator: std.mem.Allocator, name: []const u8) !void {
    switch (repo_kind) {
        .git => {
            var refs_dir = try core.git_dir.openDir("refs", .{});
            defer refs_dir.close();
            var heads_dir = try refs_dir.makeOpenPath("heads", .{});
            defer heads_dir.close();

            // get absolute paths
            var heads_dir_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
            const heads_dir_path = try heads_dir.realpath(".", &heads_dir_buffer);
            var ref_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
            const ref_path = try heads_dir.realpath(name, &ref_buffer);

            // create lock file for HEAD
            var head_lock = try io.LockFile.init(allocator, core.git_dir, "HEAD");
            defer head_lock.deinit();

            // don't allow current branch to be deleted
            var current_branch_maybe = try ref.Ref.initFromLink(repo_kind, core, allocator, "HEAD");
            defer if (current_branch_maybe) |*current_branch| current_branch.deinit();
            if (current_branch_maybe) |current_branch| {
                if (std.mem.eql(u8, current_branch.name, name)) {
                    return error.CannotDeleteCurrentBranch;
                }
            }

            // delete file
            try heads_dir.deleteFile(name);

            // delete parent dirs
            // this is only necessary because branches with a slash
            // in their name are stored on disk as subdirectories
            var parent_path_maybe = std.fs.path.dirname(ref_path);
            while (parent_path_maybe) |parent_path| {
                if (std.mem.eql(u8, heads_dir_path, parent_path)) {
                    break;
                }

                std.fs.deleteDirAbsolute(parent_path) catch |err| {
                    switch (err) {
                        error.DirNotEmpty => break,
                        else => return err,
                    }
                };
                parent_path_maybe = std.fs.path.dirname(parent_path);
            }
        },
        .xit => {
            const Ctx = struct {
                core: *rp.Repo(repo_kind).Core,
                name: []const u8,
                allocator: std.mem.Allocator,

                pub fn update(ctx_self: @This(), cursor: xitdb.Database(.file).Cursor, _: bool) !void {
                    // don't allow current branch to be deleted
                    // TODO: make `initFromLink` use cursor for tx safety
                    var current_branch_maybe = try ref.Ref.initFromLink(repo_kind, ctx_self.core, ctx_self.allocator, "HEAD");
                    defer if (current_branch_maybe) |*current_branch| current_branch.deinit();
                    if (current_branch_maybe) |current_branch| {
                        if (std.mem.eql(u8, current_branch.name, ctx_self.name)) {
                            return error.CannotDeleteCurrentBranch;
                        }
                    }

                    const HeadsCtx = struct {
                        name: []const u8,

                        pub fn update(heads_ctx_self: @This(), heads_cursor: xitdb.Database(.file).Cursor, _: bool) !void {
                            try heads_cursor.execute(void, &[_]xitdb.PathPart(void){
                                .{ .map_remove = .{ .bytes = heads_ctx_self.name } },
                            });
                        }
                    };
                    try cursor.execute(HeadsCtx, &[_]xitdb.PathPart(HeadsCtx){
                        .{ .map_get = .{ .bytes = "refs" } },
                        .map_create,
                        .{ .map_get = .{ .bytes = "heads" } },
                        .map_create,
                        .{ .update = HeadsCtx{ .name = ctx_self.name } },
                    });
                }
            };
            try core.db.rootCursor().execute(Ctx, &[_]xitdb.PathPart(Ctx){
                .{ .list_get = .append_copy },
                .map_create,
                .{ .update = Ctx{ .core = core, .name = name, .allocator = allocator } },
            });
        },
    }
}
