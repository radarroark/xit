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
const compress = @import("./compress.zig");
const obj = @import("./object.zig");
const ref = @import("./ref.zig");
const idx = @import("./index.zig");
const io = @import("./io.zig");
const rp = @import("./repo.zig");

const MAX_FILE_READ_BYTES = 1024; // FIXME: this is arbitrary...

pub fn objectToFile(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator, path: []const u8, tree_entry: obj.TreeEntry) !void {
    const oid_hex = std.fmt.bytesToHex(tree_entry.oid, .lower);

    switch (tree_entry.mode.object_type) {
        .regular_file => {
            // open the reader
            var obj_rdr = try obj.ObjectReader(repo_kind).init(allocator, core_cursor, oid_hex);
            defer obj_rdr.deinit();

            // create parent dir(s)
            if (std.fs.path.dirname(path)) |dir| {
                try core_cursor.core.repo_dir.makePath(dir);
            }

            // open the out file
            const out_flags: std.fs.File.CreateFlags = switch (builtin.os.tag) {
                .windows => .{},
                else => .{ .mode = @as(u32, @bitCast(tree_entry.mode)) },
            };
            const out_file = try core_cursor.core.repo_dir.createFile(path, out_flags);
            defer out_file.close();

            // write the decompressed data to the output file
            const writer = out_file.writer();
            var buf = [_]u8{0} ** MAX_FILE_READ_BYTES;
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
            var tree_object = try obj.Object(repo_kind, .full).init(allocator, core_cursor, oid_hex);
            defer tree_object.deinit();

            // update each entry recursively
            for (tree_object.content.tree.entries.keys(), tree_object.content.tree.entries.values()) |sub_path, entry| {
                const new_path = try io.joinPath(allocator, &.{ path, sub_path });
                defer allocator.free(new_path);
                try objectToFile(repo_kind, core_cursor, allocator, new_path, entry);
            }
        },
        // TODO: handle symlinks
        else => return error.ObjectInvalid,
    }
}

fn pathToTreeEntry(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator, parent: obj.Object(repo_kind, .full), path_parts: []const []const u8) !?obj.TreeEntry {
    const path_part = path_parts[0];
    const tree_entry = parent.content.tree.entries.get(path_part) orelse return null;

    if (path_parts.len == 1) {
        return tree_entry;
    }

    const oid_hex = std.fmt.bytesToHex(tree_entry.oid, .lower);
    var tree_object = try obj.Object(repo_kind, .full).init(allocator, core_cursor, oid_hex);
    defer tree_object.deinit();

    switch (tree_object.content) {
        .blob => return null,
        .tree => return pathToTreeEntry(repo_kind, core_cursor, allocator, tree_object, path_parts[1..]),
        .commit => return error.ObjectInvalid,
    }
}

pub const TreeToWorkspaceChange = enum {
    none,
    untracked,
    deleted,
    modified,
};

fn compareIndexToWorkspace(comptime repo_kind: rp.RepoKind, entry_maybe: ?idx.Index(repo_kind).Entry, file_maybe: ?std.fs.File) !TreeToWorkspaceChange {
    if (entry_maybe) |entry| {
        if (file_maybe) |file| {
            if (try idx.indexDiffersFromWorkspace(repo_kind, entry, file, try file.metadata())) {
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

fn compareTreeToIndex(comptime repo_kind: rp.RepoKind, item_maybe: ?obj.TreeEntry, entry_maybe: ?idx.Index(repo_kind).Entry) TreeToIndexChange {
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
fn untrackedParent(comptime repo_kind: rp.RepoKind, repo_dir: std.fs.Dir, path: []const u8, index: idx.Index(repo_kind)) ?[]const u8 {
    var parent = path;
    while (std.fs.path.dirname(parent)) |next_parent| {
        parent = next_parent;
        const meta = io.getMetadata(repo_dir, next_parent) catch continue;
        if (meta.kind() != .file) continue;
        if (!index.entries.contains(next_parent)) {
            return next_parent;
        }
    }
    return null;
}

/// returns true if the given file or one of its descendents (if a dir)
/// isn't tracked by the index, so it cannot be safely removed by checkout
fn untrackedFile(comptime repo_kind: rp.RepoKind, allocator: std.mem.Allocator, repo_dir: std.fs.Dir, path: []const u8, index: idx.Index(repo_kind)) !bool {
    const meta = try io.getMetadata(repo_dir, path);
    switch (meta.kind()) {
        .file => {
            return !index.entries.contains(path);
        },
        .directory => {
            var dir = try repo_dir.openDir(path, .{ .iterate = true });
            defer dir.close();
            var iter = dir.iterate();
            while (try iter.next()) |dir_entry| {
                const subpath = try io.joinPath(allocator, &.{ path, dir_entry.name });
                defer allocator.free(subpath);
                if (try untrackedFile(repo_kind, allocator, repo_dir, subpath, index)) {
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
    core_cursor: rp.Repo(repo_kind).CoreCursor,
    allocator: std.mem.Allocator,
    tree_diff: obj.TreeDiff(repo_kind),
    index: *idx.Index(repo_kind),
    result_maybe: ?*Switch,
) !void {
    var add_files = std.StringArrayHashMap(obj.TreeEntry).init(allocator);
    defer add_files.deinit();
    var edit_files = std.StringArrayHashMap(obj.TreeEntry).init(allocator);
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
            if (compareTreeToIndex(repo_kind, change.old, entry_maybe) != .none and compareTreeToIndex(repo_kind, change.new, entry_maybe) != .none) {
                result.conflict(allocator);
                try result.data.conflict.stale_files.put(path, {});
            } else {
                const meta = io.getMetadata(core_cursor.core.repo_dir, path) catch |err| {
                    switch (err) {
                        error.FileNotFound, error.NotDir => {
                            // if the path doesn't exist in the workspace,
                            // but one of its parents *does* exist and isn't tracked
                            if (untrackedParent(repo_kind, core_cursor.core.repo_dir, path, index.*)) |_| {
                                result.conflict(allocator);
                                if (entry_maybe) |_| {
                                    try result.data.conflict.stale_files.put(path, {});
                                } else if (change.new) |_| {
                                    try result.data.conflict.untracked_overwritten.put(path, {});
                                } else {
                                    try result.data.conflict.untracked_removed.put(path, {});
                                }
                            }
                            continue;
                        },
                        else => return err,
                    }
                };
                switch (meta.kind()) {
                    .file => {
                        const file = try core_cursor.core.repo_dir.openFile(path, .{ .mode = .read_only });
                        defer file.close();
                        // if the path is a file that differs from the index
                        if (try compareIndexToWorkspace(repo_kind, entry_maybe, file) != .none) {
                            result.conflict(allocator);
                            if (entry_maybe) |_| {
                                try result.data.conflict.stale_files.put(path, {});
                            } else if (change.new) |_| {
                                try result.data.conflict.untracked_overwritten.put(path, {});
                            } else {
                                try result.data.conflict.untracked_removed.put(path, {});
                            }
                        }
                    },
                    .directory => {
                        // if the path is a dir with a descendent that isn't in the index
                        if (try untrackedFile(repo_kind, allocator, core_cursor.core.repo_dir, path, index.*)) {
                            result.conflict(allocator);
                            if (entry_maybe) |_| {
                                try result.data.conflict.stale_files.put(path, {});
                            } else {
                                try result.data.conflict.stale_dirs.put(path, {});
                            }
                        }
                    },
                    else => {},
                }
            }
        }
    }

    if (result_maybe) |result| {
        if (result.data == .conflict) {
            return;
        }
    }

    for (remove_files.keys()) |path| {
        // update working tree
        try core_cursor.core.repo_dir.deleteFile(path);
        var dir_path_maybe = std.fs.path.dirname(path);
        while (dir_path_maybe) |dir_path| {
            core_cursor.core.repo_dir.deleteDir(dir_path) catch |err| switch (err) {
                error.DirNotEmpty => break,
                else => return err,
            };
            dir_path_maybe = std.fs.path.dirname(dir_path);
        }
        // update index
        index.removePath(path);
        try index.removeChildren(path);
    }

    for (add_files.keys(), add_files.values()) |path, tree_entry| {
        // update working tree
        try objectToFile(repo_kind, core_cursor, allocator, path, tree_entry);
        // update index
        try index.addPath(core_cursor, path);
    }

    for (edit_files.keys(), edit_files.values()) |path, tree_entry| {
        // update working tree
        try objectToFile(repo_kind, core_cursor, allocator, path, tree_entry);
        // update index
        try index.addPath(core_cursor, path);
    }
}

pub fn restore(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator, path: []const u8) !void {
    // get the current commit
    const current_oid = try ref.readHead(repo_kind, core_cursor);
    var commit_object = try obj.Object(repo_kind, .full).init(allocator, core_cursor, current_oid);
    defer commit_object.deinit();

    // get the tree of the current commit
    var tree_object = try obj.Object(repo_kind, .full).init(allocator, core_cursor, commit_object.content.commit.tree);
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
    const tree_entry = try pathToTreeEntry(repo_kind, core_cursor, allocator, tree_object, path_parts.items) orelse return error.ObjectNotFound;

    // restore file in the working tree
    try objectToFile(repo_kind, core_cursor, allocator, path, tree_entry);
}

pub const Switch = struct {
    data: union(enum) {
        success,
        conflict: struct {
            stale_files: std.StringArrayHashMap(void),
            stale_dirs: std.StringArrayHashMap(void),
            untracked_overwritten: std.StringArrayHashMap(void),
            untracked_removed: std.StringArrayHashMap(void),
        },
    },

    pub const Options = struct {
        force: bool,
    };

    pub fn init(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator, target: []const u8, options: Options) !Switch {
        // get the current commit and target oid
        const current_oid = try ref.readHead(repo_kind, core_cursor);
        const target_oid = try ref.resolve(repo_kind, core_cursor, target) orelse return error.InvalidTarget;

        // compare the commits
        var tree_diff = obj.TreeDiff(repo_kind).init(allocator);
        defer tree_diff.deinit();
        try tree_diff.compare(core_cursor, current_oid, target_oid, null);

        var result = Switch{ .data = .{ .success = {} } };
        errdefer result.deinit();

        switch (repo_kind) {
            .git => {
                // create lock file
                var lock = try io.LockFile.init(allocator, core_cursor.core.git_dir, "index");
                defer lock.deinit();

                // read index
                var index = try idx.Index(repo_kind).init(allocator, core_cursor);
                defer index.deinit();

                // update the working tree
                try migrate(repo_kind, core_cursor, allocator, tree_diff, &index, if (options.force) null else &result);

                // return early if conflict
                if (result.data == .conflict) {
                    return result;
                }

                // update the index
                try index.write(allocator, .{ .core = core_cursor.core, .lock_file_maybe = lock.lock_file });

                // update HEAD
                try ref.writeHead(repo_kind, core_cursor, allocator, target, target_oid);

                // finish lock
                lock.success = true;
            },
            .xit => {
                // read index
                var index = try idx.Index(repo_kind).init(allocator, core_cursor);
                defer index.deinit();

                // update the working tree
                try migrate(repo_kind, core_cursor, allocator, tree_diff, &index, if (options.force) null else &result);

                // return early if conflict
                if (result.data == .conflict) {
                    return result;
                }

                // update the index
                try index.write(allocator, core_cursor);

                // update HEAD
                try ref.writeHead(repo_kind, core_cursor, allocator, target, target_oid);
            },
        }

        return result;
    }

    pub fn deinit(self: *Switch) void {
        switch (self.data) {
            .success => {},
            .conflict => {
                self.data.conflict.stale_files.deinit();
                self.data.conflict.stale_dirs.deinit();
                self.data.conflict.untracked_overwritten.deinit();
                self.data.conflict.untracked_removed.deinit();
            },
        }
    }

    pub fn conflict(self: *Switch, allocator: std.mem.Allocator) void {
        if (self.data != .conflict) {
            self.data = .{
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
