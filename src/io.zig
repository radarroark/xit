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
        const lock_file = try dir.createFile(lock_name, .{ .exclusive = true, .lock = .exclusive });
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

pub fn modeEquals(m1: Mode, m2: Mode) bool {
    return @as(u32, @bitCast(m1)) == @as(u32, @bitCast(m2));
}

pub const Times = struct {
    ctime_secs: i32,
    ctime_nsecs: i32,
    mtime_secs: i32,
    mtime_nsecs: i32,
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
            const stat = try std.os.fstat(file.handle);
            return .{
                .dev = @intCast(stat.dev),
                .ino = @intCast(stat.ino),
                .uid = stat.uid,
                .gid = stat.gid,
            };
        },
    }
}
