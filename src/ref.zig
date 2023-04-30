const std = @import("std");

const MAX_FILE_READ_SIZE = 1000; // FIXME: this is arbitrary...

pub fn readHead(allocator: std.mem.Allocator, git_dir: std.fs.Dir) ![]u8 {
    const head_file = try git_dir.openFile("HEAD", .{ .mode = .read_only });
    defer head_file.close();
    return try head_file.reader().readAllAlloc(allocator, MAX_FILE_READ_SIZE);
}
