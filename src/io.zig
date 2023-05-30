const std = @import("std");

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
        const lock_file = try dir.createFile(lock_name, .{ .exclusive = true, .lock = .Exclusive });
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
