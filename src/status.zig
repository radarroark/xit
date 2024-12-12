//! the status of the files in the repo. the struct
//! mainly just builds a list of entries, which will be
//! printed out in main.zig. this module doesn't attempt
//! to print anything out. i'm saving that for later, if
//! i decide to implement the git CLI. for now, it just
//! organizes the data so you can display it how you want.

const std = @import("std");
const idx = @import("./index.zig");
const hash = @import("./hash.zig");
const obj = @import("./object.zig");
const ref = @import("./ref.zig");
const io = @import("./io.zig");
const rp = @import("./repo.zig");

pub const IndexKind = enum {
    added,
    not_added,
    not_tracked,
};

pub const StatusKind = union(IndexKind) {
    added: enum {
        created,
        modified,
        deleted,
    },
    not_added: enum {
        modified,
        deleted,
    },
    not_tracked,
};

pub const MergeConflictStatus = struct {
    base: bool,
    target: bool,
    source: bool,
};

pub fn Status(comptime repo_kind: rp.RepoKind, comptime hash_kind: hash.HashKind) type {
    return struct {
        untracked: std.StringArrayHashMap(Entry),
        workspace_modified: std.StringArrayHashMap(Entry),
        workspace_deleted: std.StringArrayHashMap(void),
        index_added: std.StringArrayHashMap(void),
        index_modified: std.StringArrayHashMap(void),
        index_deleted: std.StringArrayHashMap(void),
        conflicts: std.StringArrayHashMap(MergeConflictStatus),
        index: idx.Index(repo_kind, hash_kind),
        head_tree: HeadTree(repo_kind, hash_kind),
        arena: *std.heap.ArenaAllocator,
        allocator: std.mem.Allocator,

        pub const Entry = struct {
            path: []const u8,
            meta: std.fs.File.Metadata,
        };

        pub fn init(allocator: std.mem.Allocator, state: rp.Repo(repo_kind, hash_kind).State(.read_only)) !Status(repo_kind, hash_kind) {
            var untracked = std.StringArrayHashMap(Entry).init(allocator);
            errdefer untracked.deinit();

            var workspace_modified = std.StringArrayHashMap(Entry).init(allocator);
            errdefer workspace_modified.deinit();

            var workspace_deleted = std.StringArrayHashMap(void).init(allocator);
            errdefer workspace_deleted.deinit();

            var index_added = std.StringArrayHashMap(void).init(allocator);
            errdefer index_added.deinit();

            var index_modified = std.StringArrayHashMap(void).init(allocator);
            errdefer index_modified.deinit();

            var index_deleted = std.StringArrayHashMap(void).init(allocator);
            errdefer index_deleted.deinit();

            var conflicts = std.StringArrayHashMap(MergeConflictStatus).init(allocator);
            errdefer conflicts.deinit();

            const arena = try allocator.create(std.heap.ArenaAllocator);
            arena.* = std.heap.ArenaAllocator.init(allocator);
            errdefer {
                arena.deinit();
                allocator.destroy(arena);
            }

            var index = try idx.Index(repo_kind, hash_kind).init(allocator, state);
            errdefer index.deinit();

            var index_bools = try allocator.alloc(bool, index.entries.count());
            defer allocator.free(index_bools);

            _ = try addEntries(repo_kind, hash_kind, arena.allocator(), &untracked, &workspace_modified, index, &index_bools, state.core.repo_dir, ".");

            var head_tree = try HeadTree(repo_kind, hash_kind).init(allocator, state);
            errdefer head_tree.deinit();

            // for each entry in the index
            for (index.entries.keys(), index.entries.values(), 0..) |path, *index_entries_for_path, i| {
                // if it is a non-conflict entry
                if (index_entries_for_path[0]) |index_entry| {
                    if (!index_bools[i]) {
                        try workspace_deleted.put(path, {});
                    }
                    if (head_tree.entries.get(index_entry.path)) |head_entry| {
                        if (!index_entry.mode.eql(head_entry.mode) or !std.mem.eql(u8, &index_entry.oid, &head_entry.oid)) {
                            try index_modified.put(index_entry.path, {});
                        }
                    } else {
                        try index_added.put(index_entry.path, {});
                    }
                }
                // add to conflicts
                else {
                    try conflicts.put(path, .{
                        .base = index_entries_for_path[1] != null,
                        .target = index_entries_for_path[2] != null,
                        .source = index_entries_for_path[3] != null,
                    });
                }
            }

            for (head_tree.entries.keys()) |path| {
                if (!index.entries.contains(path)) {
                    try index_deleted.put(path, {});
                }
            }

            return Status(repo_kind, hash_kind){
                .untracked = untracked,
                .workspace_modified = workspace_modified,
                .workspace_deleted = workspace_deleted,
                .index_added = index_added,
                .index_modified = index_modified,
                .index_deleted = index_deleted,
                .conflicts = conflicts,
                .index = index,
                .head_tree = head_tree,
                .arena = arena,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Status(repo_kind, hash_kind)) void {
            self.untracked.deinit();
            self.workspace_modified.deinit();
            self.workspace_deleted.deinit();
            self.index_added.deinit();
            self.index_modified.deinit();
            self.index_deleted.deinit();
            self.conflicts.deinit();
            self.index.deinit();
            self.head_tree.deinit();
            self.arena.deinit();
            self.allocator.destroy(self.arena);
        }
    };
}

fn addEntries(
    comptime repo_kind: rp.RepoKind,
    comptime hash_kind: hash.HashKind,
    allocator: std.mem.Allocator,
    untracked: *std.StringArrayHashMap(Status(repo_kind, hash_kind).Entry),
    modified: *std.StringArrayHashMap(Status(repo_kind, hash_kind).Entry),
    index: idx.Index(repo_kind, hash_kind),
    index_bools: *[]bool,
    repo_dir: std.fs.Dir,
    path: []const u8,
) !bool {
    const meta = try io.getMetadata(repo_dir, path);
    switch (meta.kind()) {
        .file => {
            const file = try repo_dir.openFile(path, .{ .mode = .read_only });
            defer file.close();

            if (index.entries.getIndex(path)) |entry_index| {
                index_bools.*[entry_index] = true;
                const entries_for_path = index.entries.values()[entry_index];
                if (entries_for_path[0]) |entry| {
                    if (try idx.indexDiffersFromWorkspace(repo_kind, hash_kind, entry, file, meta)) {
                        try modified.put(path, Status(repo_kind, hash_kind).Entry{ .path = path, .meta = meta });
                    }
                }
            } else {
                try untracked.put(path, Status(repo_kind, hash_kind).Entry{ .path = path, .meta = meta });
            }
            return true;
        },
        .directory => {
            const is_untracked = !(std.mem.eql(u8, path, ".") or index.dir_to_paths.contains(path) or index.entries.contains(path));

            var dir = try repo_dir.openDir(path, .{ .iterate = true });
            defer dir.close();
            var iter = dir.iterate();

            var child_untracked = std.ArrayList(Status(repo_kind, hash_kind).Entry).init(allocator);
            defer child_untracked.deinit();
            var contains_file = false;

            while (try iter.next()) |entry| {
                // ignore internal dir
                const file_name = switch (repo_kind) {
                    .git => ".git",
                    .xit => ".xit",
                };
                if (std.mem.eql(u8, file_name, entry.name)) {
                    continue;
                }

                const subpath = if (std.mem.eql(u8, path, "."))
                    try allocator.dupe(u8, entry.name)
                else
                    try io.joinPath(allocator, &.{ path, entry.name });

                var grandchild_untracked = std.StringArrayHashMap(Status(repo_kind, hash_kind).Entry).init(allocator);
                defer grandchild_untracked.deinit();

                const is_file = try addEntries(repo_kind, hash_kind, allocator, &grandchild_untracked, modified, index, index_bools, repo_dir, subpath);
                contains_file = contains_file or is_file;
                if (is_file and is_untracked) break; // no need to continue because child_untracked will be discarded anyway

                try child_untracked.appendSlice(grandchild_untracked.values());
            }

            // add the dir if it isn't tracked and contains a file
            if (is_untracked) {
                if (contains_file) {
                    try untracked.put(path, Status(repo_kind, hash_kind).Entry{ .path = path, .meta = meta });
                }
            }
            // add its children
            else {
                for (child_untracked.items) |entry| {
                    try untracked.put(entry.path, entry);
                }
            }
        },
        else => {},
    }
    return false;
}

pub fn HeadTree(comptime repo_kind: rp.RepoKind, comptime hash_kind: hash.HashKind) type {
    return struct {
        entries: std.StringArrayHashMap(obj.TreeEntry(hash_kind)),
        arena: *std.heap.ArenaAllocator,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, state: rp.Repo(repo_kind, hash_kind).State(.read_only)) !HeadTree(repo_kind, hash_kind) {
            const arena = try allocator.create(std.heap.ArenaAllocator);
            arena.* = std.heap.ArenaAllocator.init(allocator);
            var tree = HeadTree(repo_kind, hash_kind){
                .entries = std.StringArrayHashMap(obj.TreeEntry(hash_kind)).init(allocator),
                .arena = arena,
                .allocator = allocator,
            };
            errdefer tree.deinit();

            // if head points to a valid object, read it
            if (try ref.readHeadMaybe(repo_kind, hash_kind, state)) |head_file_buffer| {
                var commit_object = try obj.Object(repo_kind, hash_kind, .full).init(allocator, state, &head_file_buffer);
                defer commit_object.deinit();
                try tree.read(state, "", &commit_object.content.commit.tree);
            }

            return tree;
        }

        pub fn deinit(self: *HeadTree(repo_kind, hash_kind)) void {
            self.entries.deinit();
            self.arena.deinit();
            self.allocator.destroy(self.arena);
        }

        fn read(self: *HeadTree(repo_kind, hash_kind), state: rp.Repo(repo_kind, hash_kind).State(.read_only), prefix: []const u8, oid: *const [hash.hexLen(.sha1)]u8) !void {
            const object = try obj.Object(repo_kind, hash_kind, .full).init(self.arena.allocator(), state, oid);

            switch (object.content) {
                .blob => {},
                .tree => |tree| {
                    for (tree.entries.keys(), tree.entries.values()) |name, tree_entry| {
                        const path = try io.joinPath(self.arena.allocator(), &.{ prefix, name });
                        if (tree_entry.isTree()) {
                            const oid_hex = std.fmt.bytesToHex(tree_entry.oid, .lower);
                            try self.read(state, path, &oid_hex);
                        } else {
                            try self.entries.put(path, tree_entry);
                        }
                    }
                },
                .commit => {},
            }
        }
    };
}
