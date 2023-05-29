const std = @import("std");
const hash = @import("./hash.zig");

const MAX_READ_BYTES = 1024;
const REF_START_STR = "ref: refs/heads/";

pub const RefError = error{
    RefInvalidHash,
};

pub fn resolve(git_dir: std.fs.Dir, content: []const u8) ![hash.SHA1_HEX_LEN]u8 {
    if (std.mem.startsWith(u8, content, REF_START_STR) and content.len > REF_START_STR.len) {
        return try resolve(git_dir, content[REF_START_STR.len..]);
    }

    blk: {
        var refs_dir = git_dir.openDir("refs", .{}) catch break :blk;
        defer refs_dir.close();
        var heads_dir = refs_dir.openDir("heads", .{}) catch break :blk;
        defer heads_dir.close();
        var ref_file = heads_dir.openFile(content, .{ .mode = .read_only }) catch break :blk;
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

pub fn read(git_dir: std.fs.Dir, path: []const u8, buffer: *[MAX_READ_BYTES]u8) ![]u8 {
    const head_file = try git_dir.openFile(path, .{ .mode = .read_only });
    defer head_file.close();
    const size = try head_file.reader().readAll(buffer);
    return buffer[0..size];
}

pub fn write(dir: std.fs.Dir, file_name: []const u8, content: []const u8) !void {
    // first write to a lock file and then rename it for safety
    var path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
    const lock_name = try std.fmt.bufPrint(&path_buffer, "{s}.lock", .{file_name});
    const lock_file = try dir.createFile(lock_name, .{ .exclusive = true, .lock = .Exclusive });
    errdefer dir.deleteFile(lock_name) catch {};
    {
        defer lock_file.close();
        try lock_file.writeAll(content);
    }
    try dir.rename(lock_name, file_name);
}

pub fn readHead(git_dir: std.fs.Dir) ![hash.SHA1_HEX_LEN]u8 {
    var buffer = [_]u8{0} ** MAX_READ_BYTES;
    return try resolve(git_dir, try read(git_dir, "HEAD", &buffer));
}

pub fn writeHead(git_dir: std.fs.Dir, oid: [hash.SHA1_HEX_LEN]u8, target: []const u8) !void {
    // if the target is a ref, just update HEAD to point to it
    blk: {
        var refs_dir = git_dir.openDir("refs", .{}) catch break :blk;
        defer refs_dir.close();
        var heads_dir = refs_dir.openDir("heads", .{}) catch break :blk;
        defer heads_dir.close();
        var ref_file = heads_dir.openFile(target, .{ .mode = .read_only }) catch break :blk;
        defer ref_file.close();
        var write_buffer = [_]u8{0} ** MAX_READ_BYTES;
        const content = try std.fmt.bufPrint(&write_buffer, "ref: refs/heads/{s}", .{target});
        try write(git_dir, "HEAD", content);
        return;
    }
    // otherwise, the HEAD is detached, so just updated it with the oid
    try write(git_dir, "HEAD", &oid);
}

pub fn advanceHead(git_dir: std.fs.Dir, oid: [hash.SHA1_HEX_LEN]u8) !void {
    // read HEAD
    var buffer = [_]u8{0} ** MAX_READ_BYTES;
    const old_content = try read(git_dir, "HEAD", &buffer);

    // if it's a ref, update the ref with the new oid
    if (std.mem.startsWith(u8, old_content, REF_START_STR) and old_content.len > REF_START_STR.len) {
        const target = old_content[REF_START_STR.len..];
        var refs_dir = try git_dir.openDir("refs", .{});
        defer refs_dir.close();
        var heads_dir = try refs_dir.openDir("heads", .{});
        defer heads_dir.close();
        var ref_file = try heads_dir.openFile(target, .{ .mode = .read_only });
        defer ref_file.close();
        try write(heads_dir, target, &oid);
    }
    // otherwise the HEAD is detached, so just update it with the oid
    else {
        try write(git_dir, "HEAD", &oid);
    }
}
