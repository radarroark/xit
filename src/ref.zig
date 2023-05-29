const std = @import("std");
const hash = @import("./hash.zig");
const io = @import("./io.zig");

const MAX_READ_BYTES = 1024;
const REF_START_STR = "ref: refs/heads/";

pub const RefError = error{
    RefInvalidHash,
};

pub fn resolve(git_dir: std.fs.Dir, content: []const u8) !?[hash.SHA1_HEX_LEN]u8 {
    if (std.mem.startsWith(u8, content, REF_START_STR) and content.len > REF_START_STR.len) {
        return try resolve(git_dir, content[REF_START_STR.len..]);
    }

    var refs_dir = try git_dir.openDir("refs", .{});
    defer refs_dir.close();
    var heads_dir = try refs_dir.openDir("heads", .{});
    defer heads_dir.close();

    blk: {
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
        return null;
    }
}

pub fn read(git_dir: std.fs.Dir, file_name: []const u8, buffer: *[MAX_READ_BYTES]u8) ![]u8 {
    const head_file = try git_dir.openFile(file_name, .{ .mode = .read_only });
    defer head_file.close();
    const size = try head_file.reader().readAll(buffer);
    return buffer[0..size];
}

pub fn readHeadMaybe(git_dir: std.fs.Dir) !?[hash.SHA1_HEX_LEN]u8 {
    var buffer = [_]u8{0} ** MAX_READ_BYTES;
    return try resolve(git_dir, try read(git_dir, "HEAD", &buffer));
}

pub fn readHead(git_dir: std.fs.Dir) ![hash.SHA1_HEX_LEN]u8 {
    if (try readHeadMaybe(git_dir)) |buffer| {
        return buffer;
    } else {
        return error.RefInvalidHash;
    }
}

pub fn writeHead(allocator: std.mem.Allocator, git_dir: std.fs.Dir, target: []const u8, oid_maybe: ?[hash.SHA1_HEX_LEN]u8) !void {
    var lock = try io.LockFile.init(allocator, git_dir, "HEAD");
    errdefer lock.fail();
    // if the target is a ref, just update HEAD to point to it
    var refs_dir = try git_dir.openDir("refs", .{});
    defer refs_dir.close();
    var heads_dir = try refs_dir.openDir("heads", .{});
    defer heads_dir.close();
    var ref_file = heads_dir.openFile(target, .{ .mode = .read_only }) catch |err| {
        switch (err) {
            error.FileNotFound => {
                if (oid_maybe) |oid| {
                    // the HEAD is detached, so just update it with the oid
                    try lock.lock_file.writeAll(&oid);
                    try lock.succeed();
                } else {
                    // point HEAD at the ref, even though the ref doesn't exist
                    var write_buffer = [_]u8{0} ** MAX_READ_BYTES;
                    const content = try std.fmt.bufPrint(&write_buffer, "ref: refs/heads/{s}", .{target});
                    try lock.lock_file.writeAll(content);
                    try lock.succeed();
                }
                return;
            },
            else => return err,
        }
    };
    defer ref_file.close();
    // point HEAD at the ref
    var write_buffer = [_]u8{0} ** MAX_READ_BYTES;
    const content = try std.fmt.bufPrint(&write_buffer, "ref: refs/heads/{s}", .{target});
    try lock.lock_file.writeAll(content);
    try lock.succeed();
}

/// update the given file with the given oid,
/// following refs recursively if necessary.
/// used after a commit is made.
pub fn update(allocator: std.mem.Allocator, dir: std.fs.Dir, file_name: []const u8, oid: [hash.SHA1_HEX_LEN]u8) !void {
    var lock = try io.LockFile.init(allocator, dir, file_name);
    errdefer lock.fail();

    // read file and get ref name if necessary
    var buffer = [_]u8{0} ** MAX_READ_BYTES;
    const ref_name_maybe = blk: {
        const old_content = read(dir, file_name, &buffer) catch |err| {
            switch (err) {
                error.FileNotFound => break :blk null,
                else => return err,
            }
        };
        if (std.mem.startsWith(u8, old_content, REF_START_STR) and old_content.len > REF_START_STR.len) {
            break :blk old_content[REF_START_STR.len..];
        } else {
            break :blk null;
        }
    };

    // if it's a ref, update it recursively
    if (ref_name_maybe) |ref_name| {
        var refs_dir = try dir.openDir("refs", .{});
        defer refs_dir.close();
        var heads_dir = try refs_dir.openDir("heads", .{});
        defer heads_dir.close();
        try update(allocator, heads_dir, ref_name, oid);
        lock.fail();
    }
    // otherwise, update it with the oid
    else {
        try lock.lock_file.writeAll(&oid);
        try lock.lock_file.writeAll("\n");
        try lock.succeed();
    }
}
