//! restores files from a given commit to the working tree.
//! the checkout command is pretty overloaded...switching
//! branches and restoring files are very different from a
//! user's perspective. i can see why they combined them,
//! since they use the same functionality underneath, but
//! it's one of those times when you have to set aside your
//! engineer brain and think about it as a user. oh well.
//! anyway, i didn't mix them up internally, at least.
//! the switch_head fn below only switches branches/commits,
//! while the restore fn can be used to restore files.

const std = @import("std");
const builtin = @import("builtin");
const xitdb = @import("xitdb");
const hash = @import("./hash.zig");
const compress = @import("./compress.zig");
const obj = @import("./object.zig");
const ref = @import("./ref.zig");
const idx = @import("./index.zig");
const io = @import("./io.zig");
const rp = @import("./repo.zig");

const MAX_FILE_READ_BYTES = 1024; // FIXME: this is arbitrary...

pub const SwitchResultData = union(enum) {
    success,
    conflict: struct {
        stale_files: std.StringHashMap(void),
        stale_dirs: std.StringHashMap(void),
        untracked_overwritten: std.StringHashMap(void),
        untracked_removed: std.StringHashMap(void),
    },
};

pub const SwitchResult = struct {
    data: SwitchResultData,

    pub fn init() SwitchResult {
        return SwitchResult{ .data = SwitchResultData{ .success = {} } };
    }

    pub fn deinit(self: *SwitchResult) void {
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

    pub fn conflict(self: *SwitchResult, allocator: std.mem.Allocator) void {
        if (self.data != .conflict) {
            self.data = SwitchResultData{
                .conflict = .{
                    .stale_files = std.StringHashMap(void).init(allocator),
                    .stale_dirs = std.StringHashMap(void).init(allocator),
                    .untracked_overwritten = std.StringHashMap(void).init(allocator),
                    .untracked_removed = std.StringHashMap(void).init(allocator),
                },
            };
        }
    }
};

pub fn objectToFile(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator, path: []const u8, tree_entry: obj.TreeEntry) !void {
    const oid_hex = std.fmt.bytesToHex(tree_entry.oid, .lower);

    switch (tree_entry.mode.object_type) {
        .regular_file => {
            switch (repo_kind) {
                .git => {
                    // open the internal dirs
                    var objects_dir = try core_cursor.core.git_dir.openDir("objects", .{});
                    defer objects_dir.close();

                    // open the in file
                    var hash_prefix_dir = try objects_dir.openDir(oid_hex[0..2], .{});
                    defer hash_prefix_dir.close();
                    const hash_suffix = oid_hex[2..];
                    var in_file = try hash_prefix_dir.openFile(hash_suffix, .{});
                    defer in_file.close();

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

                    // create the file
                    try compress.decompress(in_file, out_file, true);
                },
                .xit => {
                    var reader_maybe = try core_cursor.root_cursor.reader(void, &[_]xitdb.PathPart(void){
                        .{ .hash_map_get = hash.hashBuffer("objects") },
                        .{ .hash_map_get = try hash.hexToHash(&oid_hex) },
                    });
                    if (reader_maybe) |*reader| {
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

                        var read_buffer = [_]u8{0} ** MAX_FILE_READ_BYTES;
                        var header_skipped = false;
                        while (true) {
                            const size = try reader.read(&read_buffer);
                            if (size == 0) break;
                            if (!header_skipped) {
                                if (std.mem.indexOf(u8, read_buffer[0..size], &[_]u8{0})) |index| {
                                    if (index + 1 < size) {
                                        try out_file.writeAll(read_buffer[index + 1 .. size]);
                                    }
                                    header_skipped = true;
                                }
                            } else {
                                try out_file.writeAll(read_buffer[0..size]);
                            }
                        }
                        if (header_skipped) return;

                        return error.ObjectInvalid;
                    } else {
                        return error.ObjectNotFound;
                    }
                },
            }
        },
        .tree => {
            // load the tree
            var tree_object = try obj.Object(repo_kind).init(allocator, core_cursor.core, oid_hex);
            defer tree_object.deinit();

            // update each entry recursively
            for (tree_object.content.tree.entries.keys(), tree_object.content.tree.entries.values()) |sub_path, entry| {
                const new_path = try io.joinPath(allocator, &[_][]const u8{ path, sub_path });
                defer allocator.free(new_path);
                try objectToFile(repo_kind, core_cursor, allocator, new_path, entry);
            }
        },
        // TODO: handle symlinks
        else => return error.ObjectInvalid,
    }
}

pub fn objectToBuffer(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, oid_hex: [hash.SHA1_HEX_LEN]u8, buffer: []u8) ![]u8 {
    switch (repo_kind) {
        .git => {
            // open the internal dirs
            var objects_dir = try core_cursor.core.git_dir.openDir("objects", .{});
            defer objects_dir.close();

            // open the in file
            var hash_prefix_dir = try objects_dir.openDir(oid_hex[0..2], .{});
            defer hash_prefix_dir.close();
            const hash_suffix = oid_hex[2..];
            var in_file = try hash_prefix_dir.openFile(hash_suffix, .{});
            defer in_file.close();

            // decompress into arraylist
            var decompressed = try compress.Decompressed.init(in_file);
            var reader = decompressed.stream.reader();
            try reader.skipUntilDelimiterOrEof(0);
            const size = try reader.read(buffer);
            return buffer[0..size];
        },
        .xit => {
            var reader_maybe = try core_cursor.root_cursor.reader(void, &[_]xitdb.PathPart(void){
                .{ .hash_map_get = hash.hashBuffer("objects") },
                .{ .hash_map_get = try hash.hexToHash(&oid_hex) },
            });
            if (reader_maybe) |*reader| {
                var read_buffer = [_]u8{0} ** 1;
                var header_skipped = false;
                while (true) {
                    const size = try reader.read(&read_buffer);
                    if (size == 0) break;
                    if (!header_skipped) {
                        if (read_buffer[0] == 0) {
                            header_skipped = true;
                            break;
                        }
                    }
                }
                if (header_skipped) {
                    const out_size = try reader.read(buffer);
                    return buffer[0..out_size];
                }

                return error.ObjectInvalid;
            } else {
                return error.ObjectNotFound;
            }
        },
    }
}

fn pathToTreeEntry(comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core, allocator: std.mem.Allocator, parent: obj.Object(repo_kind), path_parts: []const []const u8) !?obj.TreeEntry {
    const path_part = path_parts[0];
    const tree_entry = parent.content.tree.entries.get(path_part) orelse return null;

    if (path_parts.len == 1) {
        return tree_entry;
    }

    const oid_hex = std.fmt.bytesToHex(tree_entry.oid, .lower);
    var tree_object = try obj.Object(repo_kind).init(allocator, core, oid_hex);
    defer tree_object.deinit();

    switch (tree_object.content) {
        .blob => return null,
        .tree => return pathToTreeEntry(repo_kind, core, allocator, tree_object, path_parts[1..]),
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
                const subpath = try io.joinPath(allocator, &[_][]const u8{ path, dir_entry.name });
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
    result_maybe: ?*SwitchResult,
) !void {
    var add_files = std.StringHashMap(obj.TreeEntry).init(allocator);
    defer add_files.deinit();
    var edit_files = std.StringHashMap(obj.TreeEntry).init(allocator);
    defer edit_files.deinit();
    var remove_files = std.StringHashMap(void).init(allocator);
    defer remove_files.deinit();
    var add_dirs = std.StringHashMap(void).init(allocator);
    defer add_dirs.deinit();
    var remove_dirs = std.StringHashMap(void).init(allocator);
    defer remove_dirs.deinit();

    var iter = tree_diff.changes.iterator();
    while (iter.next()) |entry| {
        const path = entry.key_ptr.*;
        const change = entry.value_ptr.*;
        if (change.old == null) {
            // if the old change doesn't exist and the new change does, it's an added file
            if (change.new) |new| {
                try add_files.put(path, new);
                if (std.fs.path.dirname(path)) |parent_path| {
                    try add_dirs.put(parent_path, {});
                }
            }
        } else if (change.new == null) {
            // if the new change doesn't exist, it's a removed file
            try remove_files.put(path, {});
            if (std.fs.path.dirname(path)) |parent_path| {
                try remove_dirs.put(parent_path, {});
            }
        } else {
            // otherwise, it's an edited file
            if (change.new) |new| {
                try edit_files.put(path, new);
                if (std.fs.path.dirname(path)) |parent_path| {
                    try add_dirs.put(parent_path, {});
                }
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

    var remove_files_iter = remove_files.iterator();
    while (remove_files_iter.next()) |entry| {
        // update working tree
        var path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
        const path = try core_cursor.core.repo_dir.realpath(entry.key_ptr.*, &path_buffer);
        try std.fs.deleteFileAbsolute(path);
        // update index
        index.removePath(entry.key_ptr.*);
        try index.removeChildren(entry.key_ptr.*);
    }

    var remove_dirs_iter = remove_dirs.keyIterator();
    while (remove_dirs_iter.next()) |key| {
        // update working tree
        try core_cursor.core.repo_dir.deleteTree(key.*);
        // update index
        index.removePath(key.*);
        try index.removeChildren(key.*);
    }

    var add_dirs_iter = add_dirs.keyIterator();
    while (add_dirs_iter.next()) |key| {
        // update working tree
        try core_cursor.core.repo_dir.makePath(key.*);
        // update index
        try index.addPath(core_cursor, key.*);
    }

    var add_files_iter = add_files.iterator();
    while (add_files_iter.next()) |entry| {
        // update working tree
        try objectToFile(repo_kind, core_cursor, allocator, entry.key_ptr.*, entry.value_ptr.*);
        // update index
        try index.addPath(core_cursor, entry.key_ptr.*);
    }

    var edit_files_iter = edit_files.iterator();
    while (edit_files_iter.next()) |entry| {
        // update working tree
        try objectToFile(repo_kind, core_cursor, allocator, entry.key_ptr.*, entry.value_ptr.*);
        // update index
        try index.addPath(core_cursor, entry.key_ptr.*);
    }
}

pub fn switch_head(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator, target: []const u8) !SwitchResult {
    // get the current commit and target oid
    const current_oid = try ref.readHead(repo_kind, core_cursor.core);
    const target_oid = try ref.resolve(repo_kind, core_cursor.core, target) orelse return error.InvalidTarget;

    // compare the commits
    var tree_diff = obj.TreeDiff(repo_kind).init(allocator);
    defer tree_diff.deinit();
    try tree_diff.compare(core_cursor.core, current_oid, target_oid, null);

    var result = SwitchResult.init();
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
            try migrate(repo_kind, core_cursor, allocator, tree_diff, &index, &result);

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
            try migrate(repo_kind, core_cursor, allocator, tree_diff, &index, &result);

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

pub fn restore(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator, path: []const u8) !void {
    // get the current commit
    const current_oid = try ref.readHead(repo_kind, core_cursor.core);
    var commit_object = try obj.Object(repo_kind).init(allocator, core_cursor.core, current_oid);
    defer commit_object.deinit();

    // get the tree of the current commit
    var tree_object = try obj.Object(repo_kind).init(allocator, core_cursor.core, commit_object.content.commit.tree);
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
    const tree_entry = try pathToTreeEntry(repo_kind, core_cursor.core, allocator, tree_object, path_parts.items) orelse return error.ObjectNotFound;

    // restore file in the working tree
    try objectToFile(repo_kind, core_cursor, allocator, path, tree_entry);
}
