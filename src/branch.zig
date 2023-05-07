const std = @import("std");
const ref = @import("./ref.zig");

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

    // get HEAD contents
    const head_file_buffer = try ref.readHead(git_dir);

    const lock_name = try std.fmt.allocPrint(allocator, "{s}.lock", .{name});
    defer allocator.free(lock_name);

    // create branch ref
    const branch_file = try heads_dir.createFile(lock_name, .{ .exclusive = true, .lock = .Exclusive });
    errdefer heads_dir.deleteFile(lock_name) catch {};
    {
        defer branch_file.close();
        try branch_file.writeAll(&head_file_buffer);
        try branch_file.writeAll("\n");
    }
    try heads_dir.rename(lock_name, name);
}
