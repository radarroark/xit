//! the status of the files in the repo. the struct
//! mainly just builds a list of entries, which will be
//! printed out in main.zig. this module doesn't attempt
//! to print anything out. i'm saving that for later, if
//! i decide to implement the git CLI. for now, it just
//! organizes the data so you can display it how you want.

const std = @import("std");
const xitdb = @import("xitdb");
const idx = @import("./index.zig");
const hash = @import("./hash.zig");
const obj = @import("./object.zig");
const ref = @import("./ref.zig");
const io = @import("./io.zig");
const rp = @import("./repo.zig");

pub fn Status(comptime repo_kind: rp.RepoKind) type {
    return struct {
        untracked: std.ArrayList(Entry),
        workspace_modified: std.ArrayList(Entry),
        workspace_deleted: std.ArrayList([]const u8),
        index_added: std.ArrayList([]const u8),
        index_modified: std.ArrayList([]const u8),
        index_deleted: std.ArrayList([]const u8),
        index: idx.Index(repo_kind),
        head_tree: HeadTree(repo_kind),
        arena: std.heap.ArenaAllocator,

        pub const Entry = struct {
            path: []const u8,
            meta: std.fs.File.Metadata,
        };

        pub fn init(allocator: std.mem.Allocator, core: *rp.Repo(repo_kind).Core) !Status(repo_kind) {
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

            var index = try idx.Index(repo_kind).init(allocator, core);
            errdefer index.deinit();

            var index_bools = try allocator.alloc(bool, index.entries.count());
            defer allocator.free(index_bools);

            _ = try addEntries(repo_kind, arena.allocator(), &untracked, &workspace_modified, index, &index_bools, core.repo_dir, ".");

            for (index_bools, 0..) |exists, i| {
                if (!exists) {
                    try workspace_deleted.append(index.entries.keys()[i]);
                }
            }

            var head_tree = try HeadTree(repo_kind).init(allocator, core);
            errdefer head_tree.deinit();

            for (index.entries.values()) |*index_entries_for_path| {
                const index_entry = index_entries_for_path[0] orelse return error.NullEntry;
                if (head_tree.entries.get(index_entry.path)) |head_entry| {
                    if (!index_entry.mode.eql(head_entry.mode) or !std.mem.eql(u8, &index_entry.oid, &head_entry.oid)) {
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

            return Status(repo_kind){
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

        pub fn deinit(self: *Status(repo_kind)) void {
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
}

fn addEntries(comptime repo_kind: rp.RepoKind, allocator: std.mem.Allocator, untracked: *std.ArrayList(Status(repo_kind).Entry), modified: *std.ArrayList(Status(repo_kind).Entry), index: idx.Index(repo_kind), index_bools: *[]bool, repo_dir: std.fs.Dir, path: []const u8) !bool {
    const file = try repo_dir.openFile(path, .{ .mode = .read_only });
    defer file.close();
    const meta = try file.metadata();
    switch (meta.kind()) {
        std.fs.File.Kind.file => {
            if (index.entries.getIndex(path)) |entry_index| {
                index_bools.*[entry_index] = true;
                if (index.entries.values()[entry_index][0]) |entry| {
                    if (try idx.indexDiffersFromWorkspace(repo_kind, entry, file, meta)) {
                        try modified.append(Status(repo_kind).Entry{ .path = path, .meta = meta });
                    }
                } else {
                    return error.NullEntry;
                }
            } else {
                try untracked.append(Status(repo_kind).Entry{ .path = path, .meta = meta });
            }
            return true;
        },
        std.fs.File.Kind.directory => {
            const is_untracked = !(std.mem.eql(u8, path, ".") or index.dir_to_paths.contains(path) or index.entries.contains(path));

            var dir = try repo_dir.openDir(path, .{ .iterate = true });
            defer dir.close();
            var iter = dir.iterate();

            var child_untracked = std.ArrayList(Status(repo_kind).Entry).init(allocator);
            defer child_untracked.deinit();
            var contains_file = false;

            while (try iter.next()) |entry| {
                // ignore internal dir/file
                switch (repo_kind) {
                    .git => {
                        if (std.mem.eql(u8, entry.name, ".git")) {
                            continue;
                        }
                    },
                    .xit => {
                        if (std.mem.eql(u8, entry.name, ".xit")) {
                            continue;
                        }
                    },
                }

                const subpath = if (std.mem.eql(u8, path, "."))
                    try std.fmt.allocPrint(allocator, "{s}", .{entry.name})
                else
                    try std.fs.path.join(allocator, &[_][]const u8{ path, entry.name });

                var grandchild_untracked = std.ArrayList(Status(repo_kind).Entry).init(allocator);
                defer grandchild_untracked.deinit();

                const is_file = try addEntries(repo_kind, allocator, &grandchild_untracked, modified, index, index_bools, repo_dir, subpath);
                contains_file = contains_file or is_file;
                if (is_file and is_untracked) break; // no need to continue because child_untracked will be discarded anyway

                try child_untracked.appendSlice(grandchild_untracked.items);
            }

            // add the dir if it isn't tracked and contains a file
            if (is_untracked) {
                if (contains_file) {
                    try untracked.append(Status(repo_kind).Entry{ .path = path, .meta = meta });
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

pub fn HeadTree(comptime repo_kind: rp.RepoKind) type {
    return struct {
        entries: std.StringHashMap(obj.TreeEntry),
        arena: std.heap.ArenaAllocator,

        pub fn init(allocator: std.mem.Allocator, core: *rp.Repo(repo_kind).Core) !HeadTree(repo_kind) {
            var entries = std.StringHashMap(obj.TreeEntry).init(allocator);
            errdefer entries.deinit();

            var tree = HeadTree(repo_kind){
                .entries = entries,
                .arena = std.heap.ArenaAllocator.init(allocator),
            };

            // if head points to a valid object, read it
            if (try ref.readHeadMaybe(repo_kind, core)) |head_file_buffer| {
                var commit_object = try obj.Object(repo_kind).init(allocator, core, head_file_buffer);
                defer commit_object.deinit();
                try tree.read(core, "", commit_object.content.commit.tree);
            }

            return tree;
        }

        pub fn deinit(self: *HeadTree(repo_kind)) void {
            self.entries.deinit();
            self.arena.deinit();
        }

        fn read(self: *HeadTree(repo_kind), core: *rp.Repo(repo_kind).Core, prefix: []const u8, oid: [hash.SHA1_HEX_LEN]u8) !void {
            var object = try obj.Object(repo_kind).init(self.arena.allocator(), core, oid);

            switch (object.content) {
                .blob => {},
                .tree => {
                    var iter = object.content.tree.entries.iterator();
                    while (iter.next()) |entry| {
                        const name = entry.key_ptr.*;
                        const path = try std.fs.path.join(self.arena.allocator(), &[_][]const u8{ prefix, name });
                        if (obj.isTree(entry.value_ptr.*)) {
                            const oid_hex = std.fmt.bytesToHex(entry.value_ptr.*.oid[0..hash.SHA1_BYTES_LEN], .lower);
                            try self.read(core, path, oid_hex);
                        } else {
                            try self.entries.put(path, entry.value_ptr.*);
                        }
                    }
                },
                .commit => {},
            }
        }
    };
}
