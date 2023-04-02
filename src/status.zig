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
    entries: std.ArrayList(Entry),
    arena: std.heap.ArenaAllocator,

    pub const Entry = struct {
        path: []const u8,
        meta: std.fs.File.Metadata,
    };

    pub fn init(allocator: std.mem.Allocator, repo_dir: std.fs.Dir, git_dir: std.fs.Dir) !Status {
        var entries = std.ArrayList(Entry).init(allocator);
        errdefer entries.deinit();

        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        var index = try idx.readIndex(allocator, git_dir);
        defer index.deinit();

        _ = try addEntries(arena.allocator(), &entries, index, repo_dir, ".");

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

fn addEntries(allocator: std.mem.Allocator, entries: *std.ArrayList(Status.Entry), index: idx.Index, repo_dir: std.fs.Dir, path: []const u8) !bool {
    const file = try repo_dir.openFile(path, .{ .mode = .read_only });
    defer file.close();
    const meta = try file.metadata();
    switch (meta.kind()) {
        std.fs.File.Kind.File => {
            if (!index.entries.contains(path)) {
                try entries.append(Status.Entry{ .path = path, .meta = meta });
            }
            return true;
        },
        std.fs.File.Kind.Directory => {
            var dir = try repo_dir.openIterableDir(path, .{});
            defer dir.close();
            var iter = dir.iterate();

            var child_entries = std.ArrayList(Status.Entry).init(allocator);
            defer child_entries.deinit();
            var contains_file = false;

            while (try iter.next()) |entry| {
                // don't traverse the .git dir
                if (std.mem.eql(u8, entry.name, ".git")) {
                    continue;
                }

                const subpath = if (std.mem.eql(u8, path, "."))
                    try std.fmt.allocPrint(allocator, "{s}", .{entry.name})
                else
                    try std.fs.path.join(allocator, &[_][]const u8{ path, entry.name });

                var grandchild_entries = std.ArrayList(Status.Entry).init(allocator);
                defer grandchild_entries.deinit();

                const is_file = try addEntries(allocator, &grandchild_entries, index, repo_dir, subpath);
                contains_file = contains_file or is_file;

                try child_entries.appendSlice(grandchild_entries.items);
            }

            // add the dir if it isn't tracked and contains a file
            if (!(std.mem.eql(u8, path, ".") or index.dir_to_paths.contains(path) or index.entries.contains(path))) {
                if (contains_file) {
                    try entries.append(Status.Entry{ .path = path, .meta = meta });
                }
            }
            // add its children
            else {
                try entries.appendSlice(child_entries.items);
            }
        },
        else => {},
    }
    return false;
}
