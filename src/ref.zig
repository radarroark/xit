const std = @import("std");
const hash = @import("./hash.zig");

const MAX_READ_BYTES = 1024;

pub const RefError = error{
    RefInvalidHash,
};

pub fn resolve(git_dir: std.fs.Dir, content: []const u8) ![hash.SHA1_HEX_LEN]u8 {
    const ref_start_str = "ref: refs/heads/";
    if (std.mem.startsWith(u8, content, ref_start_str) and content.len > ref_start_str.len) {
        const target = content[ref_start_str.len..];
        return try resolve(git_dir, target);
    }

    blk: {
        var refs_dir = git_dir.openDir("refs", .{}) catch break :blk;
        defer refs_dir.close();
        var heads_dir = refs_dir.openDir("heads", .{}) catch break :blk;
        defer heads_dir.close();
        const ref_file = heads_dir.openFile(content, .{ .mode = .read_only }) catch break :blk;
        defer ref_file.close();

        var buffer = [_]u8{0} ** MAX_READ_BYTES;
        const size = try ref_file.reader().readAll(&buffer);
        return try resolve(git_dir, buffer[0..size]);
    }

    if (content.len >= hash.SHA1_HEX_LEN) {
        var buffer = [_]u8{0} ** hash.SHA1_HEX_LEN;
        std.mem.copy(u8, &buffer, content[0..hash.SHA1_HEX_LEN]);
        return buffer;
    } else {
        return error.RefInvalidHash;
    }
}

pub fn readHead(git_dir: std.fs.Dir) ![hash.SHA1_HEX_LEN]u8 {
    var buffer = [_]u8{0} ** MAX_READ_BYTES;
    const head_file = try git_dir.openFile("HEAD", .{ .mode = .read_only });
    defer head_file.close();
    const size = try head_file.reader().readAll(&buffer);
    return try resolve(git_dir, buffer[0..size]);
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
