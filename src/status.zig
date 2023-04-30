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
const obj = @import("./object.zig");
const ref = @import("./ref.zig");

pub const Status = struct {
    untracked: std.ArrayList(Entry),
    workspace_modified: std.ArrayList(Entry),
    workspace_deleted: std.ArrayList([]const u8),
    index_added: std.ArrayList([]const u8),
    index_modified: std.ArrayList([]const u8),
    index_deleted: std.ArrayList([]const u8),
    index: idx.Index,
    head_tree: HeadTree,
    arena: std.heap.ArenaAllocator,

    pub const Entry = struct {
        path: []const u8,
        meta: std.fs.File.Metadata,
    };

    pub fn init(allocator: std.mem.Allocator, repo_dir: std.fs.Dir, git_dir: std.fs.Dir) !Status {
        var untracked = std.ArrayList(Entry).init(allocator);
        errdefer untracked.deinit();

        var workspace_modified = std.ArrayList(Entry).init(allocator);
        errdefer workspace_modified.deinit();

        var workspace_deleted = std.ArrayList([]const u8).init(allocator);
        errdefer workspace_deleted.deinit();

        var index_added = std.ArrayList([]const u8).init(allocator);
        errdefer index_added.deinit();

        var index_modified = std.ArrayList([]const u8).init(allocator);
        errdefer index_modified.deinit();

        var index_deleted = std.ArrayList([]const u8).init(allocator);
        errdefer index_deleted.deinit();

        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        var index = try idx.readIndex(allocator, git_dir);
        errdefer index.deinit();

        var index_bools = try allocator.alloc(bool, index.entries.count());
        defer allocator.free(index_bools);

        _ = try addEntries(arena.allocator(), &untracked, &workspace_modified, index, &index_bools, repo_dir, ".");

        for (index_bools, 0..) |exists, i| {
            if (!exists) {
                try workspace_deleted.append(index.entries.keys()[i]);
            }
        }

        var head_tree = try HeadTree.init(allocator, repo_dir, git_dir);
        errdefer head_tree.deinit();

        for (index.entries.values()) |index_entry| {
            if (head_tree.entries.get(index_entry.path)) |head_entry| {
                if (index_entry.mode != head_entry.mode or !std.mem.eql(u8, &index_entry.oid, &head_entry.oid)) {
                    try index_modified.append(index_entry.path);
                }
            } else {
                try index_added.append(index_entry.path);
            }
        }

        var iter = head_tree.entries.keyIterator();
        while (iter.next()) |path| {
            if (!index.entries.contains(path.*)) {
                try index_deleted.append(path.*);
            }
        }

        return Status{
            .untracked = untracked,
            .workspace_modified = workspace_modified,
            .workspace_deleted = workspace_deleted,
            .index_added = index_added,
            .index_modified = index_modified,
            .index_deleted = index_deleted,
            .index = index,
            .head_tree = head_tree,
            .arena = arena,
        };
    }

    pub fn deinit(self: *Status) void {
        self.untracked.deinit();
        self.workspace_modified.deinit();
        self.workspace_deleted.deinit();
        self.index_added.deinit();
        self.index_modified.deinit();
        self.index_deleted.deinit();
        self.index.deinit();
        self.head_tree.deinit();
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

pub const HeadTree = struct {
    objects: std.ArrayList(obj.Object),
    entries: std.StringHashMap(obj.TreeEntry),

    pub fn init(allocator: std.mem.Allocator, repo_dir: std.fs.Dir, git_dir: std.fs.Dir) !HeadTree {
        var objects = std.ArrayList(obj.Object).init(allocator);
        errdefer {
            for (objects.items) |*object| {
                object.deinit();
            }
            objects.deinit();
        }

        var entries = std.StringHashMap(obj.TreeEntry).init(allocator);
        errdefer entries.deinit();

        // get HEAD contents
        const head_file_buffer = try ref.readHead(allocator, git_dir);
        defer allocator.free(head_file_buffer);

        // read commit
        var commit_object = try obj.Object.init(allocator, repo_dir, head_file_buffer);
        defer commit_object.deinit();

        var tree = HeadTree{
            .objects = objects,
            .entries = entries,
        };

        try tree.read(allocator, repo_dir, commit_object.content.commit.tree);

        return tree;
    }

    pub fn deinit(self: *HeadTree) void {
        for (self.objects.items) |*object| {
            object.deinit();
        }
        self.objects.deinit();
        self.entries.deinit();
    }

    fn read(self: *HeadTree, allocator: std.mem.Allocator, repo_dir: std.fs.Dir, oid: []const u8) !void {
        var object = try obj.Object.init(allocator, repo_dir, oid);
        try self.objects.append(object);

        switch (object.content) {
            .blob => {},
            .tree => {
                var iter = object.content.tree.entries.iterator();
                while (iter.next()) |entry| {
                    if (obj.isTree(entry.value_ptr.*)) {
                        try self.read(allocator, repo_dir, &entry.value_ptr.*.oid);
                    } else {
                        try self.entries.put(entry.key_ptr.*, entry.value_ptr.*);
                    }
                }
            },
            .commit => {},
        }
    }
};
