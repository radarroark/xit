const std = @import("std");
const builtin = @import("builtin");
const hash = @import("./hash.zig");
const obj = @import("./object.zig");
const rf = @import("./ref.zig");
const idx = @import("./index.zig");
const fs = @import("./fs.zig");
const rp = @import("./repo.zig");
const tr = @import("./tree.zig");

pub const IndexStatusKind = enum {
    added,
    not_added,
    not_tracked,
};

pub const StatusKind = union(IndexStatusKind) {
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

pub fn Status(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        untracked: std.StringArrayHashMapUnmanaged(Entry),
        work_dir_modified: std.StringArrayHashMapUnmanaged(Entry),
        work_dir_deleted: std.StringArrayHashMapUnmanaged(void),
        index_added: std.StringArrayHashMapUnmanaged(void),
        index_modified: std.StringArrayHashMapUnmanaged(void),
        index_deleted: std.StringArrayHashMapUnmanaged(void),
        conflicts: std.StringArrayHashMapUnmanaged(MergeConflictStatus),
        index: idx.Index(repo_kind, repo_opts),
        head_tree: tr.Tree(repo_kind, repo_opts),
        arena: *std.heap.ArenaAllocator,

        pub const Entry = struct {
            path: []const u8,
            meta: std.fs.File.Metadata,
        };

        pub fn init(
            allocator: std.mem.Allocator,
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            oid_maybe: ?*const [hash.hexLen(repo_opts.hash)]u8,
        ) !Status(repo_kind, repo_opts) {
            var untracked = std.StringArrayHashMapUnmanaged(Entry){};
            errdefer untracked.deinit(allocator);

            var work_dir_modified = std.StringArrayHashMapUnmanaged(Entry){};
            errdefer work_dir_modified.deinit(allocator);

            var work_dir_deleted = std.StringArrayHashMapUnmanaged(void){};
            errdefer work_dir_deleted.deinit(allocator);

            var index_added = std.StringArrayHashMapUnmanaged(void){};
            errdefer index_added.deinit(allocator);

            var index_modified = std.StringArrayHashMapUnmanaged(void){};
            errdefer index_modified.deinit(allocator);

            var index_deleted = std.StringArrayHashMapUnmanaged(void){};
            errdefer index_deleted.deinit(allocator);

            var conflicts = std.StringArrayHashMapUnmanaged(MergeConflictStatus){};
            errdefer conflicts.deinit(allocator);

            const arena = try allocator.create(std.heap.ArenaAllocator);
            arena.* = std.heap.ArenaAllocator.init(allocator);
            errdefer {
                arena.deinit();
                allocator.destroy(arena);
            }

            var index = try idx.Index(repo_kind, repo_opts).init(allocator, state);
            errdefer index.deinit();

            var index_bools = try allocator.alloc(bool, index.entries.count());
            defer allocator.free(index_bools);

            _ = try addEntries(allocator, arena, &untracked, &work_dir_modified, &index, &index_bools, state.core.work_dir, ".");

            var head_tree = try tr.Tree(repo_kind, repo_opts).init(allocator, state, oid_maybe);
            errdefer head_tree.deinit();

            // for each entry in the index
            for (index.entries.keys(), index.entries.values(), 0..) |path, *index_entries_for_path, i| {
                // if it is a non-conflict entry
                if (index_entries_for_path[0]) |index_entry| {
                    if (!index_bools[i]) {
                        try work_dir_deleted.put(allocator, path, {});
                    }
                    if (head_tree.entries.get(index_entry.path)) |head_entry| {
                        if (!index_entry.mode.eql(head_entry.mode) or !std.mem.eql(u8, &index_entry.oid, &head_entry.oid)) {
                            try index_modified.put(allocator, index_entry.path, {});
                        }
                    } else {
                        try index_added.put(allocator, index_entry.path, {});
                    }
                }
                // add to conflicts
                else {
                    try conflicts.put(allocator, path, .{
                        .base = index_entries_for_path[1] != null,
                        .target = index_entries_for_path[2] != null,
                        .source = index_entries_for_path[3] != null,
                    });
                }
            }

            for (head_tree.entries.keys()) |path| {
                if (!index.entries.contains(path)) {
                    try index_deleted.put(allocator, path, {});
                }
            }

            return Status(repo_kind, repo_opts){
                .untracked = untracked,
                .work_dir_modified = work_dir_modified,
                .work_dir_deleted = work_dir_deleted,
                .index_added = index_added,
                .index_modified = index_modified,
                .index_deleted = index_deleted,
                .conflicts = conflicts,
                .index = index,
                .head_tree = head_tree,
                .arena = arena,
            };
        }

        pub fn deinit(self: *Status(repo_kind, repo_opts), allocator: std.mem.Allocator) void {
            self.untracked.deinit(allocator);
            self.work_dir_modified.deinit(allocator);
            self.work_dir_deleted.deinit(allocator);
            self.index_added.deinit(allocator);
            self.index_modified.deinit(allocator);
            self.index_deleted.deinit(allocator);
            self.conflicts.deinit(allocator);
            self.index.deinit();
            self.head_tree.deinit();
            self.arena.deinit();
            allocator.destroy(self.arena);
        }

        fn addEntries(
            allocator: std.mem.Allocator,
            arena: *std.heap.ArenaAllocator,
            untracked: *std.StringArrayHashMapUnmanaged(Status(repo_kind, repo_opts).Entry),
            modified: *std.StringArrayHashMapUnmanaged(Status(repo_kind, repo_opts).Entry),
            index: *const idx.Index(repo_kind, repo_opts),
            index_bools: *[]bool,
            work_dir: std.fs.Dir,
            path: []const u8,
        ) !bool {
            const meta = try fs.getMetadata(work_dir, path);
            switch (meta.kind()) {
                .file => {
                    const file = try work_dir.openFile(path, .{ .mode = .read_only });
                    defer file.close();

                    if (index.entries.getIndex(path)) |entry_index| {
                        index_bools.*[entry_index] = true;
                        const entries_for_path = index.entries.values()[entry_index];
                        if (entries_for_path[0]) |entry| {
                            if (try indexDiffersFromWorkDir(repo_kind, repo_opts, &entry, file, meta)) {
                                try modified.put(allocator, path, Status(repo_kind, repo_opts).Entry{ .path = path, .meta = meta });
                            }
                        }
                    } else {
                        try untracked.put(allocator, path, Status(repo_kind, repo_opts).Entry{ .path = path, .meta = meta });
                    }
                    return true;
                },
                .directory => {
                    const is_untracked = !(std.mem.eql(u8, path, ".") or index.dir_to_paths.contains(path) or index.entries.contains(path));

                    var dir = try work_dir.openDir(path, .{ .iterate = true });
                    defer dir.close();
                    var iter = dir.iterate();

                    var child_untracked = std.ArrayList(Status(repo_kind, repo_opts).Entry).init(allocator);
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
                            try arena.allocator().dupe(u8, entry.name)
                        else
                            try fs.joinPath(arena.allocator(), &.{ path, entry.name });

                        var grandchild_untracked = std.StringArrayHashMapUnmanaged(Status(repo_kind, repo_opts).Entry){};
                        defer grandchild_untracked.deinit(allocator);

                        const is_file = try addEntries(allocator, arena, &grandchild_untracked, modified, index, index_bools, work_dir, subpath);
                        contains_file = contains_file or is_file;
                        if (is_file and is_untracked) break; // no need to continue because child_untracked will be discarded anyway

                        try child_untracked.appendSlice(grandchild_untracked.values());
                    }

                    // add the dir if it isn't tracked and contains a file
                    if (is_untracked) {
                        if (contains_file) {
                            try untracked.put(allocator, path, Status(repo_kind, repo_opts).Entry{ .path = path, .meta = meta });
                        }
                    }
                    // add its children
                    else {
                        for (child_untracked.items) |entry| {
                            try untracked.put(allocator, entry.path, entry);
                        }
                    }

                    return contains_file;
                },
                else => return false,
            }
        }
    };
}

pub const UnaddOptions = struct {
    recursive: bool = false,
};

pub const UntrackOptions = struct {
    force: bool = false,
    recursive: bool = false,
};

pub const RemoveOptions = struct {
    force: bool = false,
    recursive: bool = false,
    update_work_dir: bool = true,
};

pub fn indexDiffersFromWorkDir(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    entry: *const idx.Index(repo_kind, repo_opts).Entry,
    file: std.fs.File,
    meta: std.fs.File.Metadata,
) !bool {
    if (meta.size() != entry.file_size or !fs.getMode(meta).eql(entry.mode)) {
        return true;
    } else {
        const times = fs.getTimes(meta);
        if (times.ctime_secs != entry.ctime_secs or
            times.ctime_nsecs != entry.ctime_nsecs or
            times.mtime_secs != entry.mtime_secs or
            times.mtime_nsecs != entry.mtime_nsecs)
        {
            // create blob header
            const file_size = meta.size();
            var header_buffer = [_]u8{0} ** 256; // should be plenty of space
            const header = try std.fmt.bufPrint(&header_buffer, "blob {}\x00", .{file_size});

            var oid = [_]u8{0} ** hash.byteLen(repo_opts.hash);
            try hash.hashReader(repo_opts.hash, repo_opts.read_size, file.reader(), header, &oid);
            if (!std.mem.eql(u8, &entry.oid, &oid)) {
                return true;
            }
        }
    }
    return false;
}

/// adds the given paths to the index
pub fn addPaths(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    allocator: std.mem.Allocator,
    paths: []const []const u8,
) !void {
    var index = try idx.Index(repo_kind, repo_opts).init(allocator, state.readOnly());
    defer index.deinit();

    for (paths) |path| {
        const path_parts = try fs.splitPath(allocator, path);
        defer allocator.free(path_parts);

        try index.addOrRemovePath(state, path_parts, .add, null);
    }

    try index.write(allocator, state);
}

/// removes the given paths from the index
pub fn unaddPaths(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    allocator: std.mem.Allocator,
    paths: []const []const u8,
    opts: UnaddOptions,
) !void {
    var index = try idx.Index(repo_kind, repo_opts).init(allocator, state.readOnly());
    defer index.deinit();

    for (paths) |path| {
        const path_parts = try fs.splitPath(allocator, path);
        defer allocator.free(path_parts);

        if (!opts.recursive and index.dir_to_paths.contains(path)) {
            return error.RecursiveOptionRequired;
        }

        try index.addOrRemovePath(state, path_parts, .rm, null);

        // iterate over the HEAD entries and add them to the index
        if (try tr.headTreeEntry(repo_kind, repo_opts, state.readOnly(), allocator, path_parts)) |*tree_entry| {
            try index.addTreeEntry(state.readOnly(), allocator, tree_entry, path_parts);
        }
    }

    try index.write(allocator, state);
}

/// removes the given paths from the index and optionally from the work dir
pub fn removePaths(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    allocator: std.mem.Allocator,
    paths: []const []const u8,
    opts: RemoveOptions,
) !void {
    var removed_paths = std.StringArrayHashMap(void).init(allocator);
    defer removed_paths.deinit();

    var index = try idx.Index(repo_kind, repo_opts).init(allocator, state.readOnly());
    defer index.deinit();

    for (paths) |path| {
        if (!opts.recursive and index.dir_to_paths.contains(path)) {
            return error.RecursiveOptionRequired;
        }

        // remove from index
        const path_parts = try fs.splitPath(allocator, path);
        defer allocator.free(path_parts);
        try index.addOrRemovePath(state, path_parts, .rm, &removed_paths);
    }

    // safety check on the files we're about to remove
    if (!opts.force) {
        var clean_index = try idx.Index(repo_kind, repo_opts).init(allocator, state.readOnly());
        defer clean_index.deinit();

        var head_tree = try tr.Tree(repo_kind, repo_opts).init(allocator, state.readOnly(), null);
        defer head_tree.deinit();

        for (removed_paths.keys()) |path| {
            const meta = fs.getMetadata(state.core.work_dir, path) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => |e| return e,
            };

            switch (meta.kind()) {
                .file => {
                    var differs_from_head = false;
                    var differs_from_work_dir = false;

                    if (clean_index.entries.get(path)) |*index_entries_for_path| {
                        if (index_entries_for_path[0]) |index_entry| {
                            if (head_tree.entries.get(path)) |head_entry| {
                                if (!index_entry.mode.eql(head_entry.mode) or !std.mem.eql(u8, &index_entry.oid, &head_entry.oid)) {
                                    differs_from_head = true;
                                }
                            }

                            const file = try state.core.work_dir.openFile(path, .{ .mode = .read_only });
                            defer file.close();
                            if (try indexDiffersFromWorkDir(repo_kind, repo_opts, &index_entry, file, meta)) {
                                differs_from_work_dir = true;
                            }
                        }
                    }

                    if (differs_from_head and differs_from_work_dir) {
                        return error.CannotRemoveFileWithStagedAndUnstagedChanges;
                    } else if (differs_from_head and opts.update_work_dir) {
                        return error.CannotRemoveFileWithStagedChanges;
                    } else if (differs_from_work_dir and opts.update_work_dir) {
                        return error.CannotRemoveFileWithUnstagedChanges;
                    }
                },
                else => {},
            }
        }
    }

    // remove files from the work dir
    if (opts.update_work_dir) {
        for (removed_paths.keys()) |path| {
            try state.core.work_dir.deleteFile(path);

            var dir_path_maybe = std.fs.path.dirname(path);
            while (dir_path_maybe) |dir_path| {
                state.core.work_dir.deleteDir(dir_path) catch |err| switch (err) {
                    error.DirNotEmpty, error.FileNotFound => break,
                    else => |e| return e,
                };
                dir_path_maybe = std.fs.path.dirname(dir_path);
            }
        }
    }

    try index.write(allocator, state);
}

pub fn objectToFile(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    allocator: std.mem.Allocator,
    path: []const u8,
    tree_entry: tr.TreeEntry(repo_opts.hash),
) !void {
    const oid_hex = std.fmt.bytesToHex(tree_entry.oid, .lower);

    switch (tree_entry.mode.content.object_type) {
        .regular_file => {
            // open the reader
            var obj_rdr = try obj.ObjectReader(repo_kind, repo_opts).init(allocator, state, &oid_hex);
            defer obj_rdr.deinit();

            // create parent dir(s)
            if (std.fs.path.dirname(path)) |dir| {
                try state.core.work_dir.makePath(dir);
            }

            // open the out file
            const out_flags: std.fs.File.CreateFlags = switch (builtin.os.tag) {
                .windows => .{},
                else => .{ .mode = @as(u16, @bitCast(tree_entry.mode.content)) },
            };
            const out_file = try state.core.work_dir.createFile(path, out_flags);
            defer out_file.close();

            // write the decompressed data to the output file
            const writer = out_file.writer();
            var buf = [_]u8{0} ** repo_opts.read_size;
            while (true) {
                // read from file
                const size = try obj_rdr.reader.read(&buf);
                if (size == 0) break;
                // decompress
                _ = try writer.write(buf[0..size]);
            }
        },
        .tree => {
            // load the tree
            var tree_object = try obj.Object(repo_kind, repo_opts, .full).init(allocator, state, &oid_hex);
            defer tree_object.deinit();

            // update each entry recursively
            for (tree_object.content.tree.entries.keys(), tree_object.content.tree.entries.values()) |sub_path, entry| {
                const new_path = try fs.joinPath(allocator, &.{ path, sub_path });
                defer allocator.free(new_path);
                try objectToFile(repo_kind, repo_opts, state, allocator, new_path, entry);
            }
        },
        // TODO: handle symlinks
        else => return error.ObjectInvalid,
    }
}

pub const TreeToWorkDirChange = enum {
    none,
    untracked,
    deleted,
    modified,
};

fn compareIndexToWorkDir(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    entry_maybe: ?idx.Index(repo_kind, repo_opts).Entry,
    file_maybe: ?std.fs.File,
) !TreeToWorkDirChange {
    if (entry_maybe) |entry| {
        if (file_maybe) |file| {
            if (try indexDiffersFromWorkDir(repo_kind, repo_opts, &entry, file, try file.metadata())) {
                return .modified;
            } else {
                return .none;
            }
        } else {
            return .deleted;
        }
    } else {
        return .untracked;
    }
}

pub const TreeToIndexChange = enum {
    none,
    added,
    deleted,
    modified,
};

fn compareTreeToIndex(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    item_maybe: ?tr.TreeEntry(repo_opts.hash),
    entry_maybe: ?idx.Index(repo_kind, repo_opts).Entry,
) TreeToIndexChange {
    if (item_maybe) |item| {
        if (entry_maybe) |entry| {
            if (!entry.mode.eql(item.mode) or !std.mem.eql(u8, &entry.oid, &item.oid)) {
                return .modified;
            } else {
                return .none;
            }
        } else {
            return .deleted;
        }
    } else {
        if (entry_maybe) |_| {
            return .added;
        } else {
            return .none;
        }
    }
}

/// returns any parent of the given path that is a file and isn't
/// tracked by the index, so it cannot be safely removed by checkout.
fn untrackedParent(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    work_dir: std.fs.Dir,
    path: []const u8,
    index: *const idx.Index(repo_kind, repo_opts),
) ?[]const u8 {
    var parent = path;
    while (std.fs.path.dirname(parent)) |next_parent| {
        parent = next_parent;
        const meta = fs.getMetadata(work_dir, next_parent) catch continue;
        if (meta.kind() != .file) continue;
        if (!index.entries.contains(next_parent)) {
            return next_parent;
        }
    }
    return null;
}

/// returns true if the given file or one of its descendents (if a dir)
/// isn't tracked by the index, so it cannot be safely removed by checkout
fn untrackedFile(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    allocator: std.mem.Allocator,
    work_dir: std.fs.Dir,
    path: []const u8,
    index: *const idx.Index(repo_kind, repo_opts),
) !bool {
    const meta = try fs.getMetadata(work_dir, path);
    switch (meta.kind()) {
        .file => {
            return !index.entries.contains(path);
        },
        .directory => {
            var dir = try work_dir.openDir(path, .{ .iterate = true });
            defer dir.close();
            var iter = dir.iterate();
            while (try iter.next()) |dir_entry| {
                const subpath = try fs.joinPath(allocator, &.{ path, dir_entry.name });
                defer allocator.free(subpath);
                if (try untrackedFile(repo_kind, repo_opts, allocator, work_dir, subpath, index)) {
                    return true;
                }
            }
            return false;
        },
        else => return false,
    }
}

pub fn migrate(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    allocator: std.mem.Allocator,
    tree_diff: tr.TreeDiff(repo_kind, repo_opts),
    index: *idx.Index(repo_kind, repo_opts),
    update_work_dir: bool,
    switch_result_maybe: ?*Switch(repo_kind, repo_opts),
) !void {
    var add_files = std.StringArrayHashMap(tr.TreeEntry(repo_opts.hash)).init(allocator);
    defer add_files.deinit();
    var edit_files = std.StringArrayHashMap(tr.TreeEntry(repo_opts.hash)).init(allocator);
    defer edit_files.deinit();
    var remove_files = std.StringArrayHashMap(void).init(allocator);
    defer remove_files.deinit();

    for (tree_diff.changes.keys(), tree_diff.changes.values()) |path, change| {
        if (change.old == null) {
            // if the old change doesn't exist and the new change does, it's an added file
            if (change.new) |new| {
                try add_files.put(path, new);
            }
        } else if (change.new == null) {
            // if the new change doesn't exist, it's a removed file
            try remove_files.put(path, {});
        } else {
            // otherwise, it's an edited file
            if (change.new) |new| {
                try edit_files.put(path, new);
            }
        }
        // check for conflicts
        if (switch_result_maybe) |switch_result| {
            const entry_maybe = if (index.entries.get(path)) |*entries_for_path| (entries_for_path[0] orelse return error.NullEntry) else null;
            if (compareTreeToIndex(repo_kind, repo_opts, change.old, entry_maybe) != .none and compareTreeToIndex(repo_kind, repo_opts, change.new, entry_maybe) != .none) {
                switch_result.setConflict();
                try switch_result.result.conflict.stale_files.put(path, {});
            } else {
                const meta = fs.getMetadata(state.core.work_dir, path) catch |err| switch (err) {
                    error.FileNotFound, error.NotDir => {
                        // if the path doesn't exist in the work dir,
                        // but one of its parents *does* exist and isn't tracked
                        if (untrackedParent(repo_kind, repo_opts, state.core.work_dir, path, index)) |_| {
                            switch_result.setConflict();
                            if (entry_maybe) |_| {
                                try switch_result.result.conflict.stale_files.put(path, {});
                            } else if (change.new) |_| {
                                try switch_result.result.conflict.untracked_overwritten.put(path, {});
                            } else {
                                try switch_result.result.conflict.untracked_removed.put(path, {});
                            }
                        }
                        continue;
                    },
                    else => |e| return e,
                };
                switch (meta.kind()) {
                    .file => {
                        const file = try state.core.work_dir.openFile(path, .{ .mode = .read_only });
                        defer file.close();
                        // if the path is a file that differs from the index
                        if (try compareIndexToWorkDir(repo_kind, repo_opts, entry_maybe, file) != .none) {
                            switch_result.setConflict();
                            if (entry_maybe) |_| {
                                try switch_result.result.conflict.stale_files.put(path, {});
                            } else if (change.new) |_| {
                                try switch_result.result.conflict.untracked_overwritten.put(path, {});
                            } else {
                                try switch_result.result.conflict.untracked_removed.put(path, {});
                            }
                        }
                    },
                    .directory => {
                        // if the path is a dir with a descendent that isn't in the index
                        if (try untrackedFile(repo_kind, repo_opts, allocator, state.core.work_dir, path, index)) {
                            switch_result.setConflict();
                            if (entry_maybe) |_| {
                                try switch_result.result.conflict.stale_files.put(path, {});
                            } else {
                                try switch_result.result.conflict.stale_dirs.put(path, {});
                            }
                        }
                    },
                    else => {},
                }
            }
        }
    }

    if (switch_result_maybe) |switch_result| {
        if (.conflict == switch_result.result) {
            return;
        }
    }

    for (remove_files.keys()) |path| {
        // update work dir
        if (update_work_dir) {
            state.core.work_dir.deleteFile(path) catch |err| switch (err) {
                error.FileNotFound => {},
                else => |e| return e,
            };
            var dir_path_maybe = std.fs.path.dirname(path);
            while (dir_path_maybe) |dir_path| {
                state.core.work_dir.deleteDir(dir_path) catch |err| switch (err) {
                    error.DirNotEmpty, error.FileNotFound => break,
                    else => |e| return e,
                };
                dir_path_maybe = std.fs.path.dirname(dir_path);
            }
        }
        // update index
        try index.removePath(path, null);
        try index.removeChildren(path, null);
    }

    for (add_files.keys(), add_files.values()) |path, tree_entry| {
        // update work dir
        if (update_work_dir) {
            try objectToFile(repo_kind, repo_opts, state.readOnly(), allocator, path, tree_entry);
        }
        // update index
        try index.addPath(state, path);
    }

    for (edit_files.keys(), edit_files.values()) |path, tree_entry| {
        // update work dir
        if (update_work_dir) {
            try objectToFile(repo_kind, repo_opts, state.readOnly(), allocator, path, tree_entry);
        }
        // update index
        try index.addPath(state, path);
    }
}

pub fn restore(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    allocator: std.mem.Allocator,
    path_parts: []const []const u8,
) !void {
    if (path_parts.len == 0) {
        // get the current commit
        const current_oid = try rf.readHeadRecur(repo_kind, repo_opts, state);
        var commit_object = try obj.Object(repo_kind, repo_opts, .full).init(allocator, state, &current_oid);
        defer commit_object.deinit();

        // get the tree of the current commit
        var tree_object = try obj.Object(repo_kind, repo_opts, .full).init(allocator, state, &commit_object.content.commit.tree);
        defer tree_object.deinit();

        const entries = &tree_object.content.tree.entries;
        for (entries.keys(), entries.values()) |name, tree_entry| {
            try objectToFile(repo_kind, repo_opts, state, allocator, name, tree_entry);
        }
    } else {
        const tree_entry = try tr.headTreeEntry(repo_kind, repo_opts, state, allocator, path_parts) orelse return error.ObjectNotFound;
        const path = try fs.joinPath(allocator, path_parts);
        defer allocator.free(path);
        try objectToFile(repo_kind, repo_opts, state, allocator, path, tree_entry);
    }
}

pub fn ResetInput(comptime hash_kind: hash.HashKind) type {
    return struct {
        target: rf.RefOrOid(hash_kind),
        force: bool = false,
    };
}

pub fn SwitchInput(comptime hash_kind: hash.HashKind) type {
    return struct {
        kind: enum {
            @"switch",
            reset,
        } = .@"switch",
        target: rf.RefOrOid(hash_kind),
        update_work_dir: bool = true,
        force: bool = false,
    };
}

pub fn Switch(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        arena: *std.heap.ArenaAllocator,
        allocator: std.mem.Allocator,
        result: union(enum) {
            success,
            conflict: struct {
                stale_files: std.StringArrayHashMap(void),
                stale_dirs: std.StringArrayHashMap(void),
                untracked_overwritten: std.StringArrayHashMap(void),
                untracked_removed: std.StringArrayHashMap(void),
            },
        },

        pub fn init(
            state: rp.Repo(repo_kind, repo_opts).State(.read_write),
            allocator: std.mem.Allocator,
            input: SwitchInput(repo_opts.hash),
        ) !Switch(repo_kind, repo_opts) {
            // get the current commit and target oid
            const current_oid_maybe = try rf.readHeadRecurMaybe(repo_kind, repo_opts, state.readOnly());
            const target_oid = try rf.readRecur(repo_kind, repo_opts, state.readOnly(), input.target) orelse return error.InvalidSwitchTarget;

            const arena = try allocator.create(std.heap.ArenaAllocator);
            arena.* = std.heap.ArenaAllocator.init(allocator);
            errdefer {
                arena.deinit();
                allocator.destroy(arena);
            }

            // compare the commits
            var tree_diff = tr.TreeDiff(repo_kind, repo_opts).init(arena.allocator());
            try tree_diff.compare(state.readOnly(), if (current_oid_maybe) |current_oid| &current_oid else null, &target_oid, null);

            var switch_result = Switch(repo_kind, repo_opts){
                .arena = arena,
                .allocator = allocator,
                .result = .{ .success = {} },
            };
            errdefer switch_result.deinit();

            switch (repo_kind) {
                .git => {
                    // create lock file
                    var lock = try fs.LockFile.init(state.core.git_dir, "index");
                    defer lock.deinit();

                    // read index
                    var index = try idx.Index(repo_kind, repo_opts).init(allocator, state.readOnly());
                    defer index.deinit();

                    // update the work dir
                    try migrate(repo_kind, repo_opts, state, allocator, tree_diff, &index, input.update_work_dir, if (input.force) null else &switch_result);

                    // return early if conflict
                    if (.conflict == switch_result.result) {
                        return switch_result;
                    }

                    // update the index
                    try index.write(allocator, .{ .core = state.core, .extra = .{ .lock_file_maybe = lock.lock_file } });

                    // update HEAD
                    switch (input.kind) {
                        .@"switch" => try rf.replaceHead(repo_kind, repo_opts, state, input.target),
                        .reset => try rf.updateHead(repo_kind, repo_opts, state, &target_oid),
                    }

                    // finish lock
                    lock.success = true;
                },
                .xit => {
                    // read index
                    var index = try idx.Index(repo_kind, repo_opts).init(allocator, state.readOnly());
                    defer index.deinit();

                    // update the work dir
                    try migrate(repo_kind, repo_opts, state, allocator, tree_diff, &index, input.update_work_dir, if (input.force) null else &switch_result);

                    // return early if conflict
                    if (.conflict == switch_result.result) {
                        return switch_result;
                    }

                    // update the index
                    try index.write(allocator, state);

                    // update HEAD
                    switch (input.kind) {
                        .@"switch" => try rf.replaceHead(repo_kind, repo_opts, state, input.target),
                        .reset => try rf.updateHead(repo_kind, repo_opts, state, &target_oid),
                    }
                },
            }

            return switch_result;
        }

        pub fn deinit(self: *Switch(repo_kind, repo_opts)) void {
            self.arena.deinit();
            self.allocator.destroy(self.arena);
        }

        pub fn setConflict(self: *Switch(repo_kind, repo_opts)) void {
            if (.conflict != self.result) {
                self.result = .{
                    .conflict = .{
                        .stale_files = std.StringArrayHashMap(void).init(self.arena.allocator()),
                        .stale_dirs = std.StringArrayHashMap(void).init(self.arena.allocator()),
                        .untracked_overwritten = std.StringArrayHashMap(void).init(self.arena.allocator()),
                        .untracked_removed = std.StringArrayHashMap(void).init(self.arena.allocator()),
                    },
                };
            }
        }
    };
}
