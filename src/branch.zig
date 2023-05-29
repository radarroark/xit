const std = @import("std");
const ref = @import("./ref.zig");
const io = @import("./io.zig");

pub const BranchError = error{
    InvalidBranchName,
};

pub fn create(allocator: std.mem.Allocator, repo_dir: std.fs.Dir, name: []const u8) !void {
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

    var git_dir = try repo_dir.openDir(".git", .{});
    defer git_dir.close();
    var refs_dir = try git_dir.openDir("refs", .{});
    defer refs_dir.close();
    var heads_dir = try refs_dir.makeOpenPath("heads", .{});
    defer heads_dir.close();

    // create lock file
    var lock = try io.LockFile.init(allocator, heads_dir, name);
    errdefer lock.fail();

    // get HEAD contents
    const head_file_buffer = try ref.readHead(git_dir);

    // write to lock file
    try lock.lock_file.writeAll(&head_file_buffer);
    try lock.lock_file.writeAll("\n");

    // finish lock
    try lock.succeed();
}
