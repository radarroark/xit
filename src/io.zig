const std = @import("std");

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

    pub fn deinit(self: *LockFile) void {
        self.lock_file.close();
        self.allocator.free(self.lock_name);
    }

    pub fn succeed(self: *LockFile) !void {
        try self.dir.rename(self.lock_name, self.file_name);
    }

    pub fn fail(self: *LockFile) void {
        self.dir.deleteFile(self.lock_name) catch {};
    }
};
