const std = @import("std");
const builtin = @import("builtin");
const hash = @import("./hash.zig");
const obj = @import("./object.zig");
const rf = @import("./ref.zig");
const idx = @import("./index.zig");
const fs = @import("./fs.zig");
const rp = @import("./repo.zig");
const st = @import("./status.zig");

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

    var head_tree = try st.HeadTree(repo_kind, repo_opts).init(allocator, state.readOnly());
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
    tree_entry: obj.TreeEntry(repo_opts.hash),
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

fn pathToTreeEntry(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    allocator: std.mem.Allocator,
    parent: obj.Object(repo_kind, repo_opts, .full),
    path_parts: []const []const u8,
) !?obj.TreeEntry(repo_opts.hash) {
    const path_part = path_parts[0];
    const tree_entry = parent.content.tree.entries.get(path_part) orelse return null;

    if (path_parts.len == 1) {
        return tree_entry;
    }

    const oid_hex = std.fmt.bytesToHex(tree_entry.oid, .lower);
    var tree_object = try obj.Object(repo_kind, repo_opts, .full).init(allocator, state, &oid_hex);
    defer tree_object.deinit();

    switch (tree_object.content) {
        .blob, .tag => return null,
        .tree => return pathToTreeEntry(repo_kind, repo_opts, state, allocator, tree_object, path_parts[1..]),
        .commit => return error.ObjectInvalid,
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
    item_maybe: ?obj.TreeEntry(repo_opts.hash),
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
    index: idx.Index(repo_kind, repo_opts),
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
    index: idx.Index(repo_kind, repo_opts),
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
    tree_diff: obj.TreeDiff(repo_kind, repo_opts),
    index: *idx.Index(repo_kind, repo_opts),
    result_maybe: ?*Switch(repo_kind, repo_opts),
) !void {
    var add_files = std.StringArrayHashMap(obj.TreeEntry(repo_opts.hash)).init(allocator);
    defer add_files.deinit();
    var edit_files = std.StringArrayHashMap(obj.TreeEntry(repo_opts.hash)).init(allocator);
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
        if (result_maybe) |result| {
            const entry_maybe = if (index.entries.get(path)) |*entries_for_path| (entries_for_path[0] orelse return error.NullEntry) else null;
            if (compareTreeToIndex(repo_kind, repo_opts, change.old, entry_maybe) != .none and compareTreeToIndex(repo_kind, repo_opts, change.new, entry_maybe) != .none) {
                result.setConflict(allocator);
                try result.conflict.stale_files.put(path, {});
            } else {
                const meta = fs.getMetadata(state.core.repo_dir, path) catch |err| switch (err) {
                    error.FileNotFound, error.NotDir => {
                        // if the path doesn't exist in the mount,
                        // but one of its parents *does* exist and isn't tracked
                        if (untrackedParent(repo_kind, repo_opts, state.core.repo_dir, path, index.*)) |_| {
                            result.setConflict(allocator);
                            if (entry_maybe) |_| {
                                try result.conflict.stale_files.put(path, {});
                            } else if (change.new) |_| {
                                try result.conflict.untracked_overwritten.put(path, {});
                            } else {
                                try result.conflict.untracked_removed.put(path, {});
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
                            result.setConflict(allocator);
                            if (entry_maybe) |_| {
                                try result.conflict.stale_files.put(path, {});
                            } else if (change.new) |_| {
                                try result.conflict.untracked_overwritten.put(path, {});
                            } else {
                                try result.conflict.untracked_removed.put(path, {});
                            }
                        }
                    },
                    .directory => {
                        // if the path is a dir with a descendent that isn't in the index
                        if (try untrackedFile(repo_kind, repo_opts, allocator, state.core.repo_dir, path, index.*)) {
                            result.setConflict(allocator);
                            if (entry_maybe) |_| {
                                try result.conflict.stale_files.put(path, {});
                            } else {
                                try result.conflict.stale_dirs.put(path, {});
                            }
                        }
                    },
                    else => {},
                }
            }
        }
    }

    if (result_maybe) |result| {
        if (.conflict == result.*) {
            return;
        }
    }

    for (remove_files.keys()) |path| {
        // update mount
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
        // update index
        index.removePath(path);
        try index.removeChildren(path);
    }

    for (add_files.keys(), add_files.values()) |path, tree_entry| {
        // update mount
        try objectToFile(repo_kind, repo_opts, state.readOnly(), allocator, path, tree_entry);
        // update index
        try index.addPath(state, path);
    }

    for (edit_files.keys(), edit_files.values()) |path, tree_entry| {
        // update mount
        try objectToFile(repo_kind, repo_opts, state.readOnly(), allocator, path, tree_entry);
        // update index
        try index.addPath(state, path);
    }
}

pub fn headTreeEntry(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    allocator: std.mem.Allocator,
    path_parts: []const []const u8,
) !?obj.TreeEntry(repo_opts.hash) {
    // get the current commit
    const current_oid = try rf.readHead(repo_kind, repo_opts, state);
    var commit_object = try obj.Object(repo_kind, repo_opts, .full).init(allocator, state, &current_oid);
    defer commit_object.deinit();

    // get the tree of the current commit
    var tree_object = try obj.Object(repo_kind, repo_opts, .full).init(allocator, state, &commit_object.content.commit.tree);
    defer tree_object.deinit();

    // get the entry for the given path
    return try pathToTreeEntry(repo_kind, repo_opts, state, allocator, tree_object, path_parts);
}

pub fn restore(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    allocator: std.mem.Allocator,
    path_parts: []const []const u8,
) !void {
    const tree_entry = try headTreeEntry(repo_kind, repo_opts, state, allocator, path_parts) orelse return error.ObjectNotFound;
    const path = try fs.joinPath(allocator, path_parts);
    defer allocator.free(path);
    try objectToFile(repo_kind, repo_opts, state, allocator, path, tree_entry);
}

pub fn SwitchInput(comptime hash_kind: hash.HashKind) type {
    return struct {
        head: union(enum) {
            replace: rf.RefOrOid(hash_kind),
            update: *const [hash.hexLen(hash_kind)]u8,
        },
        force: bool = false,
    };
}

pub fn Switch(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return union(enum) {
        success,
        conflict: struct {
            stale_files: std.StringArrayHashMap(void),
            stale_dirs: std.StringArrayHashMap(void),
            untracked_overwritten: std.StringArrayHashMap(void),
            untracked_removed: std.StringArrayHashMap(void),
        },

        pub fn init(
            state: rp.Repo(repo_kind, repo_opts).State(.read_write),
            allocator: std.mem.Allocator,
            input: SwitchInput(repo_opts.hash),
        ) !Switch(repo_kind, repo_opts) {
            // get the current commit and target oid
            const current_oid_maybe = try rf.readHeadMaybe(repo_kind, repo_opts, state.readOnly());
            const target_oid = switch (input.head) {
                .replace => |ref_or_oid| (try rf.readRecur(repo_kind, repo_opts, state.readOnly(), ref_or_oid)) orelse return error.InvalidTarget,
                .update => |oid| oid.*,
            };

            // compare the commits
            var tree_diff = obj.TreeDiff(repo_kind, repo_opts).init(allocator);
            defer tree_diff.deinit();
            try tree_diff.compare(state.readOnly(), current_oid_maybe, target_oid, null);

            var result = Switch(repo_kind, repo_opts){ .success = {} };
            errdefer result.deinit();

            switch (repo_kind) {
                .git => {
                    // create lock file
                    var lock = try fs.LockFile.init(state.core.git_dir, "index");
                    defer lock.deinit();

                    // read index
                    var index = try idx.Index(repo_kind, repo_opts).init(allocator, state.readOnly());
                    defer index.deinit();

                    // update the mount
                    try migrate(repo_kind, repo_opts, state, allocator, tree_diff, &index, if (input.force) null else &result);

                    // return early if conflict
                    if (.conflict == result) {
                        return result;
                    }

                    // update the index
                    try index.write(allocator, .{ .core = state.core, .extra = .{ .lock_file_maybe = lock.lock_file } });

                    // update HEAD
                    switch (input.head) {
                        .replace => |ref_or_oid| try rf.replaceHead(repo_kind, repo_opts, state, ref_or_oid),
                        .update => |oid| try rf.updateHead(repo_kind, repo_opts, state, oid),
                    }

                    // finish lock
                    lock.success = true;
                },
                .xit => {
                    // read index
                    var index = try idx.Index(repo_kind, repo_opts).init(allocator, state.readOnly());
                    defer index.deinit();

                    // update the mount
                    try migrate(repo_kind, repo_opts, state, allocator, tree_diff, &index, if (input.force) null else &result);

                    // return early if conflict
                    if (.conflict == result) {
                        return result;
                    }

                    // update the index
                    try index.write(allocator, state);

                    // update HEAD
                    switch (input.head) {
                        .replace => |ref_or_oid| try rf.replaceHead(repo_kind, repo_opts, state, ref_or_oid),
                        .update => |oid| try rf.updateHead(repo_kind, repo_opts, state, oid),
                    }
                },
            }

            return result;
        }

        pub fn deinit(self: *Switch(repo_kind, repo_opts)) void {
            switch (self.*) {
                .success => {},
                .conflict => |*result_conflict| {
                    result_conflict.stale_files.deinit();
                    result_conflict.stale_dirs.deinit();
                    result_conflict.untracked_overwritten.deinit();
                    result_conflict.untracked_removed.deinit();
                },
            }
        }

        pub fn setConflict(self: *Switch(repo_kind, repo_opts), allocator: std.mem.Allocator) void {
            if (.conflict != self.*) {
                self.* = .{
                    .conflict = .{
                        .stale_files = std.StringArrayHashMap(void).init(allocator),
                        .stale_dirs = std.StringArrayHashMap(void).init(allocator),
                        .untracked_overwritten = std.StringArrayHashMap(void).init(allocator),
                        .untracked_removed = std.StringArrayHashMap(void).init(allocator),
                    },
                };
            }
        }
    };
}
