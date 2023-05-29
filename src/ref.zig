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

pub const LockFile = struct {
    allocator: std.mem.Allocator,
    dir: std.fs.Dir,
    file_name: []const u8,
    lock_name: []const u8,
    lock_file: std.fs.File,

    pub fn init(allocator: std.mem.Allocator, dir: std.fs.Dir, file_name: []const u8) !LockFile {
        const lock_name = try std.fmt.allocPrint(allocator, "{s}.lock", .{file_name});
        errdefer allocator.free(lock_name);
        const lock_file = try dir.createFile(lock_name, .{ .exclusive = true, .lock = .Exclusive });
        errdefer dir.deleteFile(lock_name) catch {};
        return .{
            .allocator = allocator,
            .dir = dir,
            .file_name = file_name,
            .lock_name = lock_name,
            .lock_file = lock_file,
        };
    }

    pub fn writeAll(self: *LockFile, bytes: []const u8) !void {
        try self.lock_file.writeAll(bytes);
    }

    pub fn succeed(self: *LockFile) !void {
        defer self.allocator.free(self.lock_name);
        self.lock_file.close();
        try self.dir.rename(self.lock_name, self.file_name);
    }

    pub fn fail(self: *LockFile) void {
        defer self.allocator.free(self.lock_name);
        self.lock_file.close();
        self.dir.deleteFile(self.lock_name) catch {};
    }
};

pub fn read(git_dir: std.fs.Dir, path: []const u8, buffer: *[MAX_READ_BYTES]u8) ![]u8 {
    const head_file = try git_dir.openFile(path, .{ .mode = .read_only });
    defer head_file.close();
    const size = try head_file.reader().readAll(buffer);
    return buffer[0..size];
}

pub fn readHead(git_dir: std.fs.Dir) ![hash.SHA1_HEX_LEN]u8 {
    var buffer = [_]u8{0} ** MAX_READ_BYTES;
    return try resolve(git_dir, try read(git_dir, "HEAD", &buffer));
}

pub fn writeHead(allocator: std.mem.Allocator, git_dir: std.fs.Dir, target: []const u8, oid: [hash.SHA1_HEX_LEN]u8) !void {
    var lock = try LockFile.init(allocator, git_dir, "HEAD");
    errdefer lock.fail();
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
        try lock.writeAll(content);
        try lock.succeed();
        return;
    }
    // otherwise, the HEAD is detached, so just updated it with the oid
    try lock.writeAll(&oid);
    try lock.succeed();
}

/// update the given file with the given oid,
/// following refs recursively if necessary.
/// used after a commit is made.
pub fn update(allocator: std.mem.Allocator, dir: std.fs.Dir, file_name: []const u8, oid: [hash.SHA1_HEX_LEN]u8) !void {
    var lock = try LockFile.init(allocator, dir, file_name);
    errdefer lock.fail();

    // read file
    var buffer = [_]u8{0} ** MAX_READ_BYTES;
    const old_content = try read(dir, file_name, &buffer);

    // if it's a ref, update it recursively
    if (std.mem.startsWith(u8, old_content, REF_START_STR) and old_content.len > REF_START_STR.len) {
        const new_file_name = old_content[REF_START_STR.len..];
        var refs_dir = try dir.openDir("refs", .{});
        defer refs_dir.close();
        var heads_dir = try refs_dir.openDir("heads", .{});
        defer heads_dir.close();
        try update(allocator, heads_dir, new_file_name, oid);
        lock.fail();
    }
    // otherwise, update it with the oid
    else {
        try lock.writeAll(&oid);
        try lock.succeed();
    }
}
