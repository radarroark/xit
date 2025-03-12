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

    content: packed struct(u16) {
        unix_permission: u9,
        unused: u3 = 0,
        object_type: ObjectType,
    },
    padding: u16 = 0,

    pub fn init(meta: std.fs.File.Metadata) Mode {
        const is_executable = switch (builtin.os.tag) {
            .windows => false,
            else => meta.permissions().inner.unixHas(std.fs.File.PermissionsUnix.Class.user, .execute),
        };
        const obj_type: Mode.ObjectType = switch (meta.kind()) {
            .sym_link => .symbolic_link,
            else => .regular_file,
        };
        return .{
            .content = .{
                .unix_permission = switch (obj_type) {
                    .regular_file => if (is_executable) 0o755 else 0o644,
                    else => 0,
                },
                .object_type = obj_type,
            },
        };
    }

    pub fn toStr(self: Mode) []const u8 {
        return switch (self.content.object_type) {
            .tree => "40000",
            .regular_file => if (self.content.unix_permission == 0o755) "100755" else "100644",
            .symbolic_link => "120000",
            .gitlink => "160000",
        };
    }

    pub fn eql(self: Mode, other: Mode) bool {
        switch (builtin.os.tag) {
            .windows => {
                // on windows, we are not comparing permissions,
                // and we are treating symlinks as if they are normal files.
                const self_obj_type = switch (self.content.object_type) {
                    .symbolic_link => .regular_file,
                    else => |obj_type| obj_type,
                };
                const other_obj_type = switch (other.content.object_type) {
                    .symbolic_link => .regular_file,
                    else => |obj_type| obj_type,
                };
                return self_obj_type == other_obj_type;
            },
            else => return self.eqlExact(other),
        }
    }

    pub fn eqlExact(self: Mode, other: Mode) bool {
        return switch (self.content.object_type) {
            .regular_file => @as(u32, @bitCast(self)) == @as(u32, @bitCast(other)),
            else => self.content.object_type == other.content.object_type,
        };
    }
};

pub const Times = struct {
    ctime_secs: u32,
    ctime_nsecs: u32,
    mtime_secs: u32,
    mtime_nsecs: u32,

    pub fn init(meta: std.fs.File.Metadata) Times {
        const ctime = meta.created() orelse 0;
        const mtime = meta.modified();
        return .{
            .ctime_secs = @intCast(@divTrunc(ctime, std.time.ns_per_s)),
            .ctime_nsecs = @intCast(@mod(ctime, std.time.ns_per_s)),
            .mtime_secs = @intCast(@divTrunc(mtime, std.time.ns_per_s)),
            .mtime_nsecs = @intCast(@mod(mtime, std.time.ns_per_s)),
        };
    }

    pub fn eql(self: Times, other: Times) bool {
        return self.ctime_secs == other.ctime_secs and
            self.ctime_nsecs == other.ctime_nsecs and
            self.mtime_secs == other.mtime_secs and
            self.mtime_nsecs == other.mtime_nsecs;
    }
};

pub const Stat = struct {
    dev: u32,
    ino: u32,
    uid: u32,
    gid: u32,

    pub fn init(fd: std.posix.fd_t) !Stat {
        switch (builtin.os.tag) {
            .windows => return .{
                .dev = 0,
                .ino = 0,
                .uid = 0,
                .gid = 0,
            },
            else => {
                const stat = try std.posix.fstat(fd);
                return .{
                    .dev = @intCast(stat.dev),
                    .ino = @intCast(stat.ino),
                    .uid = stat.uid,
                    .gid = stat.gid,
                };
            },
        }
    }
};

pub const Metadata = struct {
    kind: std.fs.File.Kind,
    times: Times,
    stat: Stat,
    mode: Mode,
    size: u64,

    pub fn init(parent_dir: std.fs.Dir, path: []const u8) !Metadata {
        // special handling for symlinks
        if (.windows != builtin.os.tag) {
            var target_path_buffer = [_]u8{0} ** std.fs.max_path_bytes;
            if (parent_dir.readLink(path, &target_path_buffer)) |target_path| {
                return .{
                    .kind = .sym_link,
                    .times = std.mem.zeroes(Times),
                    .stat = std.mem.zeroes(Stat),
                    .mode = .{ .content = .{ .unix_permission = 0, .object_type = .symbolic_link } },
                    .size = target_path.len,
                };
            } else |err| switch (err) {
                error.NotLink => {},
                else => |e| return e,
            }
        }

        // on windows, openFile returns error.IsDir on a dir.
        // so we need to call openDir in that case.
        var meta: std.fs.File.Metadata = undefined;
        var stat: Stat = undefined;
        if (parent_dir.openFile(path, .{ .mode = .read_only })) |file| {
            defer file.close();
            meta = try file.metadata();
            stat = try Stat.init(file.handle);
        } else |err| switch (err) {
            error.IsDir => {
                var dir = try parent_dir.openDir(path, .{});
                defer dir.close();
                meta = try dir.metadata();
                stat = try Stat.init(dir.fd);
            },
            else => |e| return e,
        }

        return try initFromFileMetadata(meta, stat);
    }

    pub fn initFromFile(file: std.fs.File) !Metadata {
        const meta = try file.metadata();
        return initFromFileMetadata(meta, try Stat.init(file.handle));
    }

    pub fn initFromFileMetadata(file_meta: std.fs.File.Metadata, stat: Stat) !Metadata {
        return .{
            .kind = file_meta.kind(),
            .times = Times.init(file_meta),
            .stat = stat,
            .mode = Mode.init(file_meta),
            .size = file_meta.size(),
        };
    }
};

pub fn joinPath(allocator: std.mem.Allocator, paths: []const []const u8) ![]u8 {
    if (paths.len == 0 or (paths.len == 1 and std.mem.eql(u8, ".", paths[0]))) {
        return try allocator.dupe(u8, ".");
    }

    var total_len: usize = 0;
    for (paths, 0..) |path, i| {
        if (path.len == 0 or std.mem.eql(u8, ".", path)) {
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
        if (path.len == 0 or std.mem.eql(u8, ".", path)) {
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

pub fn relativePath(allocator: std.mem.Allocator, work_dir: std.fs.Dir, cwd: std.fs.Dir, path: []const u8) ![]const u8 {
    // get the absolute paths to the repo and the input
    const repo_path = try work_dir.realpathAlloc(allocator, ".");
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

pub fn splitPath(allocator: std.mem.Allocator, path: []const u8) ![]const []const u8 {
    var path_parts = std.ArrayList([]const u8).init(allocator);
    errdefer path_parts.deinit();
    var path_iter = try std.fs.path.componentIterator(path);
    while (path_iter.next()) |component| {
        try path_parts.append(component.name);
    }
    return try path_parts.toOwnedSlice();
}
