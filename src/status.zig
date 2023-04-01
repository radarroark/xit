//! the status of the files in the repo.
//! this must be the command i personally run most
//! often. it's the "tell me the state of this repo so
//! i don't screw it up any further" command. the struct
//! mainly just builds a list of entries, which will be
//! printed out in main.zig. maybe the printing should
//! be done in here instead...

const std = @import("std");
const idx = @import("./index.zig");

pub const Status = struct {
    entries: std.ArrayList([]const u8),
    arena: std.heap.ArenaAllocator,

    pub fn init(allocator: std.mem.Allocator, repo_dir: std.fs.Dir, git_dir: std.fs.Dir) !Status {
        var entries = std.ArrayList([]const u8).init(allocator);
        errdefer entries.deinit();

        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        var index = try idx.readIndex(allocator, git_dir);
        defer index.deinit();

        try addEntry(arena.allocator(), &entries, repo_dir, ".", index);

        return Status{
            .entries = entries,
            .arena = arena,
        };
    }

    pub fn deinit(self: *Status) void {
        self.entries.deinit();
        self.arena.deinit();
    }
};

fn addEntry(allocator: std.mem.Allocator, entries: *std.ArrayList([]const u8), repo_dir: std.fs.Dir, path: []const u8, index: idx.Index) !void {
    const file = try repo_dir.openFile(path, .{ .mode = .read_only });
    defer file.close();
    const meta = try file.metadata();
    switch (meta.kind()) {
        std.fs.File.Kind.File => {
            if (!index.entries.contains(path)) {
                try entries.append(path);
            }
        },
        std.fs.File.Kind.Directory => {
            var dir = try repo_dir.openIterableDir(path, .{});
            defer dir.close();
            var iter = dir.iterate();
            while (try iter.next()) |entry| {
                // don't traverse the .git dir
                if (std.mem.eql(u8, entry.name, ".git")) {
                    continue;
                }

                const subpath = if (std.mem.eql(u8, path, "."))
                    try std.fmt.allocPrint(allocator, "{s}", .{entry.name})
                else
                    try std.fs.path.join(allocator, &[_][]const u8{ path, entry.name });
                try addEntry(allocator, entries, repo_dir, subpath, index);
            }
        },
        else => return,
    }
}
