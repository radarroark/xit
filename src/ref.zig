const std = @import("std");
const hash = @import("./hash.zig");

pub const RefError = error{
    ReadHeadInvalidHash,
};

pub fn readHead(git_dir: std.fs.Dir) ![hash.SHA1_HEX_LEN]u8 {
    const head_file = try git_dir.openFile("HEAD", .{ .mode = .read_only });
    defer head_file.close();
    var buffer = [_]u8{0} ** hash.SHA1_HEX_LEN;
    const size = try head_file.reader().readAll(&buffer);
    if (size != hash.SHA1_HEX_LEN) {
        // TODO: if not a hash, resolve it
        return error.ReadHeadInvalidHash;
    }
    return buffer;
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
