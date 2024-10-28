const std = @import("std");
const builtin = @import("builtin");

pub const LockFile = struct {
    allocator: std.mem.Allocator,
    dir: std.fs.Dir,
    file_name: []const u8,
    lock_name: []const u8,
    lock_file: std.fs.File,
    success: bool,

    pub fn init(allocator: std.mem.Allocator, dir: std.fs.Dir, file_name: []const u8) !LockFile {
        const lock_name = try std.fmt.allocPrint(allocator, "{s}.lock", .{file_name});
        errdefer allocator.free(lock_name);
        const lock_file = try dir.createFile(lock_name, .{ .truncate = true, .lock = .exclusive, .read = true });
        errdefer dir.deleteFile(lock_name) catch {};
        return .{
            .allocator = allocator,
            .dir = dir,
            .file_name = file_name,
            .lock_name = lock_name,
            .lock_file = lock_file,
            .success = false,
        };
    }

    pub fn deinit(self: *LockFile) void {
        self.lock_file.close();
        if (self.success) {
            self.dir.rename(self.lock_name, self.file_name) catch {
                self.success = false;
            };
        }
        if (!self.success) {
            self.dir.deleteFile(self.lock_name) catch {};
        }
        self.allocator.free(self.lock_name);
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
            else => return err,
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
