//! functionality related to reading and updating the "mount",
//! which is xit's term for what git calls the working tree,
//! working copy, or workspace. I don't like those terms because:
//!
//! 1. "tree" is an overloaded term...it also refers to internal
//!    tree objects.
//! 2. "work" is too narrow. if you're using a VCS for source
//!    code, then yes, you "work" in that directory. but people
//!    are increasingly using VCSes for other things, like
//!    deploying static files to a web server. in that case, you
//!    aren't really working out of the directory, you just want
//!    the VCS to mount files so they can be served.
//! 3. those terms are too long and I'm friggin lazy.

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
        untracked: std.StringArrayHashMap(Entry),
        mount_modified: std.StringArrayHashMap(Entry),
        mount_deleted: std.StringArrayHashMap(void),
        index_added: std.StringArrayHashMap(void),
        index_modified: std.StringArrayHashMap(void),
        index_deleted: std.StringArrayHashMap(void),
        conflicts: std.StringArrayHashMap(MergeConflictStatus),
        index: idx.Index(repo_kind, repo_opts),
        head_tree: tr.Tree(repo_kind, repo_opts),
        arena: *std.heap.ArenaAllocator,
        allocator: std.mem.Allocator,

        pub const Entry = struct {
            path: []const u8,
            meta: std.fs.File.Metadata,
        };

        pub fn init(
            allocator: std.mem.Allocator,
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            oid_maybe: ?*const [hash.hexLen(repo_opts.hash)]u8,
        ) !Status(repo_kind, repo_opts) {
            var untracked = std.StringArrayHashMap(Entry).init(allocator);
            errdefer untracked.deinit();

            var mount_modified = std.StringArrayHashMap(Entry).init(allocator);
            errdefer mount_modified.deinit();

            var mount_deleted = std.StringArrayHashMap(void).init(allocator);
            errdefer mount_deleted.deinit();

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

            var index = try idx.Index(repo_kind, repo_opts).init(allocator, state);
            errdefer index.deinit();

            var index_bools = try allocator.alloc(bool, index.entries.count());
            defer allocator.free(index_bools);

            _ = try addEntries(arena.allocator(), &untracked, &mount_modified, &index, &index_bools, state.core.repo_dir, ".");

            var head_tree = try tr.Tree(repo_kind, repo_opts).init(allocator, state, oid_maybe);
            errdefer head_tree.deinit();

            // for each entry in the index
            for (index.entries.keys(), index.entries.values(), 0..) |path, *index_entries_for_path, i| {
                // if it is a non-conflict entry
                if (index_entries_for_path[0]) |index_entry| {
                    if (!index_bools[i]) {
                        try mount_deleted.put(path, {});
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

            return Status(repo_kind, repo_opts){
                .untracked = untracked,
                .mount_modified = mount_modified,
                .mount_deleted = mount_deleted,
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

        pub fn deinit(self: *Status(repo_kind, repo_opts)) void {
            self.untracked.deinit();
            self.mount_modified.deinit();
            self.mount_deleted.deinit();
            self.index_added.deinit();
            self.index_modified.deinit();
            self.index_deleted.deinit();
            self.conflicts.deinit();
            self.index.deinit();
            self.head_tree.deinit();
            self.arena.deinit();
            self.allocator.destroy(self.arena);
        }

        fn addEntries(
            allocator: std.mem.Allocator,
            untracked: *std.StringArrayHashMap(Status(repo_kind, repo_opts).Entry),
            modified: *std.StringArrayHashMap(Status(repo_kind, repo_opts).Entry),
            index: *const idx.Index(repo_kind, repo_opts),
            index_bools: *[]bool,
            repo_dir: std.fs.Dir,
            path: []const u8,
        ) !bool {
            const meta = try fs.getMetadata(repo_dir, path);
            switch (meta.kind()) {
                .file => {
                    const file = try repo_dir.openFile(path, .{ .mode = .read_only });
                    defer file.close();

                    if (index.entries.getIndex(path)) |entry_index| {
                        index_bools.*[entry_index] = true;
                        const entries_for_path = index.entries.values()[entry_index];
                        if (entries_for_path[0]) |entry| {
                            if (try indexDiffersFromMount(repo_kind, repo_opts, &entry, file, meta)) {
                                try modified.put(path, Status(repo_kind, repo_opts).Entry{ .path = path, .meta = meta });
                            }
                        }
                    } else {
                        try untracked.put(path, Status(repo_kind, repo_opts).Entry{ .path = path, .meta = meta });
                    }
                    return true;
                },
                .directory => {
                    const is_untracked = !(std.mem.eql(u8, path, ".") or index.dir_to_paths.contains(path) or index.entries.contains(path));

                    var dir = try repo_dir.openDir(path, .{ .iterate = true });
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
                            try allocator.dupe(u8, entry.name)
                        else
                            try fs.joinPath(allocator, &.{ path, entry.name });

                        var grandchild_untracked = std.StringArrayHashMap(Status(repo_kind, repo_opts).Entry).init(allocator);
                        defer grandchild_untracked.deinit();

                        const is_file = try addEntries(allocator, &grandchild_untracked, modified, index, index_bools, repo_dir, subpath);
                        contains_file = contains_file or is_file;
                        if (is_file and is_untracked) break; // no need to continue because child_untracked will be discarded anyway

                        try child_untracked.appendSlice(grandchild_untracked.values());
                    }

                    // add the dir if it isn't tracked and contains a file
                    if (is_untracked) {
                        if (contains_file) {
                            try untracked.put(path, Status(repo_kind, repo_opts).Entry{ .path = path, .meta = meta });
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
    };
}

pub const UntrackOptions = struct {
    force: bool = false,
};

pub const RemoveOptions = struct {
    force: bool = false,
    remove_from_mount: bool = true,
};

pub fn indexDiffersFromMount(
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

        try index.addOrRemovePath(state, path_parts, .add);
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
) !void {
    var index = try idx.Index(repo_kind, repo_opts).init(allocator, state.readOnly());
    defer index.deinit();

    for (paths) |path| {
        const path_parts = try fs.splitPath(allocator, path);
        defer allocator.free(path_parts);

        try index.addOrRemovePath(state, path_parts, .rm);

        // iterate over the HEAD entries and add them to the index
        if (try tr.headTreeEntry(repo_kind, repo_opts, state.readOnly(), allocator, path_parts)) |*tree_entry| {
            try index.addTreeEntry(state.readOnly(), allocator, tree_entry, path_parts);
        }
    }

    try index.write(allocator, state);
}

/// removes the given paths from the index and optionally from the mount
pub fn removePaths(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    allocator: std.mem.Allocator,
    paths: []const []const u8,
    opts: RemoveOptions,
) !void {
    var index = try idx.Index(repo_kind, repo_opts).init(allocator, state.readOnly());
    defer index.deinit();

    var head_tree = try tr.Tree(repo_kind, repo_opts).init(allocator, state.readOnly(), null);
    defer head_tree.deinit();

    for (paths) |path| {
        const meta = fs.getMetadata(state.core.repo_dir, path) catch |err| switch (err) {
            error.FileNotFound => return error.RemoveIndexPathNotFound,
            else => |e| return e,
        };
        switch (meta.kind()) {
            .file => {
                // if force isn't enabled, do a safety check
                if (!opts.force) {
                    var differs_from_head = false;
                    var differs_from_mount = false;

                    if (index.entries.get(path)) |*index_entries_for_path| {
                        if (index_entries_for_path[0]) |index_entry| {
                            if (head_tree.entries.get(path)) |head_entry| {
                                if (!index_entry.mode.eql(head_entry.mode) or !std.mem.eql(u8, &index_entry.oid, &head_entry.oid)) {
                                    differs_from_head = true;
                                }
                            }

                            const file = try state.core.repo_dir.openFile(path, .{ .mode = .read_only });
                            defer file.close();
                            if (try indexDiffersFromMount(repo_kind, repo_opts, &index_entry, file, meta)) {
                                differs_from_mount = true;
                            }
                        }
                    }

                    if (differs_from_head and differs_from_mount) {
                        return error.CannotRemoveFileWithStagedAndUnstagedChanges;
                    } else if (differs_from_head and opts.remove_from_mount) {
                        return error.CannotRemoveFileWithStagedChanges;
                    } else if (differs_from_mount and opts.remove_from_mount) {
                        return error.CannotRemoveFileWithUnstagedChanges;
                    }
                }

                const path_parts = try fs.splitPath(allocator, path);
                defer allocator.free(path_parts);
                try index.addOrRemovePath(state, path_parts, .rm);
            },
            else => return error.UnexpectedPathType,
        }
    }

    if (opts.remove_from_mount) {
        for (paths) |path| {
            const meta = try fs.getMetadata(state.core.repo_dir, path);
            switch (meta.kind()) {
                .file => try state.core.repo_dir.deleteFile(path),
                .directory => return error.CannotDeleteDir,
                else => return error.UnexpectedPathType,
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

    switch (tree_entry.mode.object_type) {
        .regular_file => {
            // open the reader
            var obj_rdr = try obj.ObjectReader(repo_kind, repo_opts).init(allocator, state, &oid_hex);
            defer obj_rdr.deinit();

            // create parent dir(s)
            if (std.fs.path.dirname(path)) |dir| {
                try state.core.repo_dir.makePath(dir);
            }

            // open the out file
            const out_flags: std.fs.File.CreateFlags = switch (builtin.os.tag) {
                .windows => .{},
                else => .{ .mode = @as(u32, @bitCast(tree_entry.mode)) },
            };
            const out_file = try state.core.repo_dir.createFile(path, out_flags);
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

pub const TreeToMountChange = enum {
    none,
    untracked,
    deleted,
    modified,
};

fn compareIndexToMount(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    entry_maybe: ?idx.Index(repo_kind, repo_opts).Entry,
    file_maybe: ?std.fs.File,
) !TreeToMountChange {
    if (entry_maybe) |entry| {
        if (file_maybe) |file| {
            if (try indexDiffersFromMount(repo_kind, repo_opts, &entry, file, try file.metadata())) {
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
    repo_dir: std.fs.Dir,
    path: []const u8,
    index: *const idx.Index(repo_kind, repo_opts),
) ?[]const u8 {
    var parent = path;
    while (std.fs.path.dirname(parent)) |next_parent| {
        parent = next_parent;
        const meta = fs.getMetadata(repo_dir, next_parent) catch continue;
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
    repo_dir: std.fs.Dir,
    path: []const u8,
    index: *const idx.Index(repo_kind, repo_opts),
) !bool {
    const meta = try fs.getMetadata(repo_dir, path);
    switch (meta.kind()) {
        .file => {
            return !index.entries.contains(path);
        },
        .directory => {
            var dir = try repo_dir.openDir(path, .{ .iterate = true });
            defer dir.close();
            var iter = dir.iterate();
            while (try iter.next()) |dir_entry| {
                const subpath = try fs.joinPath(allocator, &.{ path, dir_entry.name });
                defer allocator.free(subpath);
                if (try untrackedFile(repo_kind, repo_opts, allocator, repo_dir, subpath, index)) {
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
    update_mount: bool,
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
                const meta = fs.getMetadata(state.core.repo_dir, path) catch |err| switch (err) {
                    error.FileNotFound, error.NotDir => {
                        // if the path doesn't exist in the mount,
                        // but one of its parents *does* exist and isn't tracked
                        if (untrackedParent(repo_kind, repo_opts, state.core.repo_dir, path, index)) |_| {
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
                        const file = try state.core.repo_dir.openFile(path, .{ .mode = .read_only });
                        defer file.close();
                        // if the path is a file that differs from the index
                        if (try compareIndexToMount(repo_kind, repo_opts, entry_maybe, file) != .none) {
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
                        if (try untrackedFile(repo_kind, repo_opts, allocator, state.core.repo_dir, path, index)) {
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
        // update mount
        if (update_mount) {
            state.core.repo_dir.deleteFile(path) catch |err| switch (err) {
                error.FileNotFound => {},
                else => |e| return e,
            };
            var dir_path_maybe = std.fs.path.dirname(path);
            while (dir_path_maybe) |dir_path| {
                state.core.repo_dir.deleteDir(dir_path) catch |err| switch (err) {
                    error.DirNotEmpty, error.FileNotFound => break,
                    else => |e| return e,
                };
                dir_path_maybe = std.fs.path.dirname(dir_path);
            }
        }
        // update index
        index.removePath(path);
        try index.removeChildren(path);
    }

    for (add_files.keys(), add_files.values()) |path, tree_entry| {
        // update mount
        if (update_mount) {
            try objectToFile(repo_kind, repo_opts, state.readOnly(), allocator, path, tree_entry);
        }
        // update index
        try index.addPath(state, path);
    }

    for (edit_files.keys(), edit_files.values()) |path, tree_entry| {
        // update mount
        if (update_mount) {
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
    const tree_entry = try tr.headTreeEntry(repo_kind, repo_opts, state, allocator, path_parts) orelse return error.ObjectNotFound;
    const path = try fs.joinPath(allocator, path_parts);
    defer allocator.free(path);
    try objectToFile(repo_kind, repo_opts, state, allocator, path, tree_entry);
}

pub fn ResetInput(comptime hash_kind: hash.HashKind) type {
    return struct {
        target: rf.RefOrOid(hash_kind),
        update_mount: bool = true,
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
        update_mount: bool = true,
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
            const current_oid_maybe = try rf.readHeadMaybe(repo_kind, repo_opts, state.readOnly());
            const target_oid = try rf.readRecur(repo_kind, repo_opts, state.readOnly(), input.target) orelse return error.InvalidTarget;

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

                    // update the mount
                    try migrate(repo_kind, repo_opts, state, allocator, tree_diff, &index, input.update_mount, if (input.force) null else &switch_result);

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

                    // update the mount
                    try migrate(repo_kind, repo_opts, state, allocator, tree_diff, &index, input.update_mount, if (input.force) null else &switch_result);

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
