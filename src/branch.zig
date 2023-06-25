const std = @import("std");
const ref = @import("./ref.zig");
const io = @import("./io.zig");

pub const BranchError = error{
    InvalidBranchName,
    CannotDeleteCurrentBranch,
};

pub fn create(allocator: std.mem.Allocator, git_dir: std.fs.Dir, name: []const u8) !void {
    if (name.len == 0 or
        name[0] == '.' or
        name[0] == '/' or
        std.mem.endsWith(u8, name, "/") or
        std.mem.endsWith(u8, name, ".lock") or
        std.mem.indexOf(u8, name, "..") != null or
        std.mem.indexOf(u8, name, "@") != null)
    {
        return error.InvalidBranchName;
    }

    var refs_dir = try git_dir.openDir("refs", .{});
    defer refs_dir.close();
    var heads_dir = try refs_dir.makeOpenPath("heads", .{});
    defer heads_dir.close();

    // create lock file
    var lock = try io.LockFile.init(allocator, heads_dir, name);
    defer lock.deinit();

    // get HEAD contents
    const head_file_buffer = try ref.readHead(git_dir);

    // write to lock file
    try lock.lock_file.writeAll(&head_file_buffer);
    try lock.lock_file.writeAll("\n");

    // finish lock
    lock.success = true;
}

pub fn delete(allocator: std.mem.Allocator, git_dir: std.fs.Dir, name: []const u8) !void {
    var current_branch_maybe = try ref.Ref.initWithPath(allocator, git_dir, "HEAD");
    defer if (current_branch_maybe) |*current_branch| current_branch.deinit();
    if (current_branch_maybe) |current_branch| {
        if (std.mem.eql(u8, current_branch.name, name)) {
            return error.CannotDeleteCurrentBranch;
        }
    }

    var refs_dir = try git_dir.openDir("refs", .{});
    defer refs_dir.close();
    var heads_dir = try refs_dir.makeOpenPath("heads", .{});
    defer heads_dir.close();

    // create lock file
    var lock = try io.LockFile.init(allocator, heads_dir, name);
    defer lock.deinit();

    // get absolute paths
    var abs_heads_dir_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
    const abs_heads_dir_path = try heads_dir.realpath(".", &abs_heads_dir_buffer);
    var abs_ref_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
    const abs_ref_path = try heads_dir.realpath(name, &abs_ref_buffer);

    // delete file
    try heads_dir.deleteFile(name);

    // delete parent dirs
    // this is only necessary because branches with a / in their name
    // are stored on disk as subdirectories
    var parent_path_maybe = std.fs.path.dirname(abs_ref_path);
    while (parent_path_maybe) |parent_path| {
        var abs_parent_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
        const abs_parent_path = try heads_dir.realpath(".", &abs_parent_buffer);
        if (std.mem.eql(u8, abs_heads_dir_path, abs_parent_path)) {
            break;
        }

        var parent_dir = try git_dir.openDir(parent_path, .{});
        defer parent_dir.close();
        git_dir.deleteDir(parent_path) catch |err| {
            switch (err) {
                error.DirNotEmpty => break,
                else => return err,
            }
        };
        parent_path_maybe = std.fs.path.dirname(parent_path);
    }
}
