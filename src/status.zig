//! the status of the files in the repo.
//! this must be the command i personally run most
//! often. it's the "tell me the state of this repo so
//! i don't screw it up any further" command. the struct
//! mainly just builds a list of entries, which will be
//! printed out in main.zig. maybe the printing should
//! be done in here instead...

const std = @import("std");
const idx = @import("./index.zig");
const hash = @import("./hash.zig");

pub const Status = struct {
    untracked: std.ArrayList(Entry),
    modified: std.ArrayList(Entry),
    deleted: std.ArrayList([]const u8),
    index: idx.Index,
    arena: std.heap.ArenaAllocator,

    pub const Entry = struct {
        path: []const u8,
        meta: std.fs.File.Metadata,
    };

    pub fn init(allocator: std.mem.Allocator, repo_dir: std.fs.Dir, git_dir: std.fs.Dir) !Status {
        var untracked = std.ArrayList(Entry).init(allocator);
        errdefer untracked.deinit();

        var modified = std.ArrayList(Entry).init(allocator);
        errdefer modified.deinit();

        var deleted = std.ArrayList([]const u8).init(allocator);
        errdefer deleted.deinit();

        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        var index = try idx.readIndex(allocator, git_dir);
        errdefer index.deinit();

        var index_bools = try allocator.alloc(bool, index.entries.count());
        defer allocator.free(index_bools);

        _ = try addEntries(arena.allocator(), &untracked, &modified, index, &index_bools, repo_dir, ".");

        for (index_bools, 0..) |exists, i| {
            if (!exists) {
                try deleted.append(index.entries.keys()[i]);
            }
        }

        return Status{
            .untracked = untracked,
            .modified = modified,
            .deleted = deleted,
            .index = index,
            .arena = arena,
        };
    }

    pub fn deinit(self: *Status) void {
        self.untracked.deinit();
        self.modified.deinit();
        self.deleted.deinit();
        self.index.deinit();
        self.arena.deinit();
    }
};

fn addEntries(allocator: std.mem.Allocator, untracked: *std.ArrayList(Status.Entry), modified: *std.ArrayList(Status.Entry), index: idx.Index, index_bools: *[]bool, repo_dir: std.fs.Dir, path: []const u8) !bool {
    const file = try repo_dir.openFile(path, .{ .mode = .read_only });
    defer file.close();
    const meta = try file.metadata();
    switch (meta.kind()) {
        std.fs.File.Kind.File => {
            if (index.entries.getIndex(path)) |entry_index| {
                index_bools.*[entry_index] = true;

                const entry = index.entries.values()[entry_index];
                if (meta.size() != entry.file_size or idx.getMode(meta) != entry.mode) {
                    try modified.append(Status.Entry{ .path = path, .meta = meta });
                } else {
                    const times = idx.getTimes(meta);
                    if (times.ctime_secs != entry.ctime_secs or
                        times.ctime_nsecs != entry.ctime_nsecs or
                        times.mtime_secs != entry.mtime_secs or
                        times.mtime_nsecs != entry.mtime_nsecs)
                    {
                        var oid = [_]u8{0} ** hash.SHA1_BYTES_LEN;
                        try hash.sha1_file(file, &oid);
                        if (!std.mem.eql(u8, &entry.oid, &oid)) {
                            try modified.append(Status.Entry{ .path = path, .meta = meta });
                        }
                    }
                }
            } else {
                try untracked.append(Status.Entry{ .path = path, .meta = meta });
            }
            return true;
        },
        std.fs.File.Kind.Directory => {
            const is_untracked = !(std.mem.eql(u8, path, ".") or index.dir_to_paths.contains(path) or index.entries.contains(path));

            var dir = try repo_dir.openIterableDir(path, .{});
            defer dir.close();
            var iter = dir.iterate();

            var child_untracked = std.ArrayList(Status.Entry).init(allocator);
            defer child_untracked.deinit();
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

                var grandchild_untracked = std.ArrayList(Status.Entry).init(allocator);
                defer grandchild_untracked.deinit();

                const is_file = try addEntries(allocator, &grandchild_untracked, modified, index, index_bools, repo_dir, subpath);
                contains_file = contains_file or is_file;
                if (is_file and is_untracked) break; // no need to continue because child_untracked will be discarded anyway

                try child_untracked.appendSlice(grandchild_untracked.items);
            }

            // add the dir if it isn't tracked and contains a file
            if (is_untracked) {
                if (contains_file) {
                    try untracked.append(Status.Entry{ .path = path, .meta = meta });
                }
            }
            // add its children
            else {
                try untracked.appendSlice(child_untracked.items);
            }
        },
        else => {},
    }
    return false;
}
