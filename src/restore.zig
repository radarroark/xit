//! restores files from a given commit to the working tree.
//! the checkout command is pretty overloaded...switching
//! branches and restoring files are very different from a
//! user's perspective. i can see why they combined them,
//! since they use the same functionality underneath, but
//! it's one of those times when you have to set aside your
//! engineer brain and think about it as a user. oh well.
//! anyway, i didn't mix them up internally, at least.
//! the Switch struct below only switches branches/commits,
//! while the restore fn can be used to restore files.

const std = @import("std");
const builtin = @import("builtin");
const hash = @import("./hash.zig");
const obj = @import("./object.zig");
const rf = @import("./ref.zig");
const idx = @import("./index.zig");
const fs = @import("./fs.zig");
const rp = @import("./repo.zig");

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
        .blob => return null,
        .tree => return pathToTreeEntry(repo_kind, repo_opts, state, allocator, tree_object, path_parts[1..]),
        .commit => return error.ObjectInvalid,
    }
}

pub const TreeToWorkspaceChange = enum {
    none,
    untracked,
    deleted,
    modified,
};

fn compareIndexToWorkspace(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    entry_maybe: ?idx.Index(repo_kind, repo_opts).Entry,
    file_maybe: ?std.fs.File,
) !TreeToWorkspaceChange {
    if (entry_maybe) |entry| {
        if (file_maybe) |file| {
            if (try idx.indexDiffersFromWorkspace(repo_kind, repo_opts, entry, file, try file.metadata())) {
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
                        // if the path doesn't exist in the workspace,
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
                        if (try compareIndexToWorkspace(repo_kind, repo_opts, entry_maybe, file) != .none) {
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
        // update working tree
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
        // update working tree
        try objectToFile(repo_kind, repo_opts, state.readOnly(), allocator, path, tree_entry);
        // update index
        try index.addPath(state, path);
    }

    for (edit_files.keys(), edit_files.values()) |path, tree_entry| {
        // update working tree
        try objectToFile(repo_kind, repo_opts, state.readOnly(), allocator, path, tree_entry);
        // update index
        try index.addPath(state, path);
    }
}

pub fn restore(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    allocator: std.mem.Allocator,
    path: []const u8,
) !void {
    // get the current commit
    const current_oid = try rf.readHead(repo_kind, repo_opts, state);
    var commit_object = try obj.Object(repo_kind, repo_opts, .full).init(allocator, state, &current_oid);
    defer commit_object.deinit();

    // get the tree of the current commit
    var tree_object = try obj.Object(repo_kind, repo_opts, .full).init(allocator, state, &commit_object.content.commit.tree);
    defer tree_object.deinit();

    // get the entry for the given path
    var path_parts = std.ArrayList([]const u8).init(allocator);
    defer path_parts.deinit();
    var start: usize = 0;
    for (path, 0..) |ch, i| {
        if (std.fs.path.isSep(ch) and i > start) {
            try path_parts.append(path[start..i]);
            start = i + 1;
        }
    }
    try path_parts.append(path[start..]);
    const tree_entry = try pathToTreeEntry(repo_kind, repo_opts, state, allocator, tree_object, path_parts.items) orelse return error.ObjectNotFound;

    // restore file in the working tree
    try objectToFile(repo_kind, repo_opts, state, allocator, path, tree_entry);
}

pub fn SwitchOptions(comptime hash_kind: hash.HashKind) type {
    return struct {
        force: bool,
        target_oid: ?*const [hash.hexLen(hash_kind)]u8 = null,
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

        /// TODO: this is confusingly designed right now because `target` can be
        /// either an oid or branch name, and you can also specify `options.target_oid`.
        /// in reality it should take either an oid or a (branch name, optional target oid)
        /// combo. but we'll clean this up another time...
        pub fn init(
            state: rp.Repo(repo_kind, repo_opts).State(.read_write),
            allocator: std.mem.Allocator,
            target: []const u8,
            options: SwitchOptions(repo_opts.hash),
        ) !Switch(repo_kind, repo_opts) {
            // get the current commit and target oid
            const current_oid_maybe = try rf.readHeadMaybe(repo_kind, repo_opts, state.readOnly());
            const target_oid = if (options.target_oid) |oid|
                oid.*
            else
                try rf.readRecur(repo_kind, repo_opts, state.readOnly(), rf.RefOrOid(repo_opts.hash).initFromUser(target)) orelse return error.InvalidTarget;

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

                    // update the working tree
                    try migrate(repo_kind, repo_opts, state, allocator, tree_diff, &index, if (options.force) null else &result);

                    // return early if conflict
                    if (.conflict == result) {
                        return result;
                    }

                    // update the index
                    try index.write(allocator, .{ .core = state.core, .extra = .{ .lock_file_maybe = lock.lock_file } });

                    // update HEAD
                    try rf.writeHead(repo_kind, repo_opts, state, target, target_oid);

                    // finish lock
                    lock.success = true;
                },
                .xit => {
                    // read index
                    var index = try idx.Index(repo_kind, repo_opts).init(allocator, state.readOnly());
                    defer index.deinit();

                    // update the working tree
                    try migrate(repo_kind, repo_opts, state, allocator, tree_diff, &index, if (options.force) null else &result);

                    // return early if conflict
                    if (.conflict == result) {
                        return result;
                    }

                    // update the index
                    try index.write(allocator, state);

                    // update HEAD
                    try rf.writeHead(repo_kind, repo_opts, state, target, target_oid);
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
