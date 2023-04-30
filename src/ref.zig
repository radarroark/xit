const std = @import("std");

const MAX_FILE_READ_SIZE = 1000; // FIXME: this is arbitrary...

pub fn readHead(allocator: std.mem.Allocator, git_dir: std.fs.Dir) ![]u8 {
    const head_file = try git_dir.openFile("HEAD", .{ .mode = .read_only });
    defer head_file.close();
    return try head_file.reader().readAllAlloc(allocator, MAX_FILE_READ_SIZE);
}

pub fn writeHead(git_dir: std.fs.Dir, content: []const u8) !void {
    // first write to a lock file and then rename it to HEAD for safety
    const head_file = try git_dir.createFile("HEAD.lock", .{ .exclusive = true, .lock = .Exclusive });
    errdefer git_dir.deleteFile("HEAD.lock") catch {};
    {
        defer head_file.close();
        try head_file.writeAll(content);
    }
    try git_dir.rename("HEAD.lock", "HEAD");
}
