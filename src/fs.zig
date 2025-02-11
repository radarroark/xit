const std = @import("std");
const builtin = @import("builtin");

pub const LockFile = struct {
    dir: std.fs.Dir,
    file_name: []const u8,
    lock_name_buffer: [lock_name_buffer_size]u8,
    lock_name_len: usize,
    lock_file: std.fs.File,
    success: bool,

    const suffix = ".lock";
    const lock_name_buffer_size = 256;

    pub fn init(dir: std.fs.Dir, file_name: []const u8) !LockFile {
        var lock_name_buffer = [_]u8{0} ** lock_name_buffer_size;
        const lock_name = try std.fmt.bufPrint(&lock_name_buffer, "{s}.lock", .{file_name});
        const lock_file = try dir.createFile(lock_name, .{ .truncate = true, .lock = .exclusive, .read = true });
        errdefer {
            lock_file.close();
            dir.deleteFile(lock_name) catch {};
        }
        return .{
            .dir = dir,
            .file_name = file_name,
            .lock_name_buffer = lock_name_buffer,
            .lock_name_len = lock_name.len,
            .lock_file = lock_file,
            .success = false,
        };
    }

    pub fn deinit(self: *LockFile) void {
        self.lock_file.close();
        const lock_name = self.lock_name_buffer[0..self.lock_name_len];
        if (self.success) {
            self.dir.rename(lock_name, self.file_name) catch {
                self.success = false;
            };
        }
        if (!self.success) {
            self.dir.deleteFile(lock_name) catch {};
        }
    }
};

pub const Mode = packed struct(u32) {
    pub const ObjectType = enum(u4) {
        tree = 0o04,
        regular_file = 0o10,
        symbolic_link = 0o12,
        gitlink = 0o16,
    };

    unix_permission: u9,
    unused: u3 = 0,
    object_type: ObjectType,
    padding: u16 = 0,

    pub fn toStr(self: Mode) []const u8 {
        return if (self.unix_permission == 0o755) "100755" else "100644";
    }

    pub fn eql(self: Mode, m2: Mode) bool {
        return @as(u32, @bitCast(self)) == @as(u32, @bitCast(m2));
    }
};

pub fn getMode(meta: std.fs.File.Metadata) Mode {
    const is_executable = switch (builtin.os.tag) {
        .windows => false,
        else => meta.permissions().inner.unixHas(std.fs.File.PermissionsUnix.Class.user, .execute),
    };
    return .{
        .unix_permission = if (is_executable) 0o755 else 0o644,
        .object_type = .regular_file,
    };
}

pub const Times = struct {
    ctime_secs: u32,
    ctime_nsecs: u32,
    mtime_secs: u32,
    mtime_nsecs: u32,
};

pub fn getTimes(meta: std.fs.File.Metadata) Times {
    const ctime = meta.created() orelse 0;
    const mtime = meta.modified();
    return Times{
        .ctime_secs = @intCast(@divTrunc(ctime, std.time.ns_per_s)),
        .ctime_nsecs = @intCast(@mod(ctime, std.time.ns_per_s)),
        .mtime_secs = @intCast(@divTrunc(mtime, std.time.ns_per_s)),
        .mtime_nsecs = @intCast(@mod(mtime, std.time.ns_per_s)),
    };
}

pub const Stat = struct {
    dev: u32,
    ino: u32,
    uid: u32,
    gid: u32,
};

pub fn getStat(file: std.fs.File) !Stat {
    switch (builtin.os.tag) {
        .windows => return .{
            .dev = 0,
            .ino = 0,
            .uid = 0,
            .gid = 0,
        },
        else => {
            const stat = try std.posix.fstat(file.handle);
            return .{
                .dev = @intCast(stat.dev),
                .ino = @intCast(stat.ino),
                .uid = stat.uid,
                .gid = stat.gid,
            };
        },
    }
}

pub fn getMetadata(parent_dir: std.fs.Dir, path: []const u8) !std.fs.File.Metadata {
    // on windows, openFile returns error.IsDir on a dir.
    // so we need to call openDir in that case.
    if (parent_dir.openFile(path, .{ .mode = .read_only })) |file| {
        defer file.close();
        return try file.metadata();
    } else |err| {
        switch (err) {
            error.IsDir => {
                var dir = try parent_dir.openDir(path, .{});
                defer dir.close();
                return try dir.metadata();
            },
            else => |e| return e,
        }
    }
}

pub fn joinPath(allocator: std.mem.Allocator, paths: []const []const u8) ![]u8 {
    var total_len: usize = 0;
    for (paths, 0..) |path, i| {
        if (path.len == 0) {
            continue;
        }
        total_len += path.len;
        if (i < paths.len - 1) {
            total_len += 1;
        }
    }

    const buf = try allocator.alloc(u8, total_len);
    errdefer allocator.free(buf);

    var buf_slice = buf[0..];
    for (paths, 0..) |path, i| {
        if (path.len == 0) {
            continue;
        }
        @memcpy(buf_slice[0..path.len], path);
        if (i < paths.len - 1) {
            // even on windows we want the / separator
            buf_slice[path.len] = '/';
            buf_slice = buf_slice[path.len + 1 ..];
        }
    }

    return buf;
}

pub fn relativePath(allocator: std.mem.Allocator, repo_dir: std.fs.Dir, cwd: std.fs.Dir, path: []const u8) ![]const u8 {
    // get the absolute paths to the repo and the input
    const repo_path = try repo_dir.realpathAlloc(allocator, ".");
    defer allocator.free(repo_path);
    const cwd_path = try cwd.realpathAlloc(allocator, ".");
    defer allocator.free(cwd_path);
    const input_path =
        if (std.fs.path.isAbsolute(path))
        try allocator.dupe(u8, path)
    else
        try std.fs.path.resolve(allocator, &.{ cwd_path, path });
    defer allocator.free(input_path);

    // make sure the input path is in the repo
    if (!std.mem.startsWith(u8, input_path, repo_path)) {
        return error.PathIsOutsideRepo;
    }

    // compute the path relative to the repo path
    return try std.fs.path.relative(allocator, repo_path, input_path);
}
