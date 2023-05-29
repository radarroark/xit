//! restores files from a given commit to the working tree.
//! the checkout command is pretty overloaded...switching
//! branches and restoring files are very different from a
//! user's perspective. i can see why they combined them,
//! since they use the same functionality underneath, but
//! it's one of those times when you have to set aside your
//! engineer brain and think about it as a user. oh well.

const std = @import("std");
const hash = @import("./hash.zig");
const compress = @import("./compress.zig");
const obj = @import("./object.zig");
const ref = @import("./ref.zig");
const idx = @import("./index.zig");

pub const CheckoutError = error{
    CheckoutConflict,
};

pub const CheckoutResultKind = enum {
    success,
    conflict,
};

pub const CheckoutResultData = union(CheckoutResultKind) {
    success,
    conflict: struct {
        stale_files: std.StringHashMap(void),
        stale_dirs: std.StringHashMap(void),
        untracked_overwritten: std.StringHashMap(void),
        untracked_removed: std.StringHashMap(void),
    },
};

pub const CheckoutResult = struct {
    data: CheckoutResultData,

    pub fn init() CheckoutResult {
        return CheckoutResult{ .data = CheckoutResultData{ .success = {} } };
    }

    pub fn deinit(self: *CheckoutResult) void {
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

    pub fn conflict(self: *CheckoutResult, allocator: std.mem.Allocator) void {
        if (self.data != .conflict) {
            self.data = CheckoutResultData{
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

fn createFileFromObject(allocator: std.mem.Allocator, repo_dir: std.fs.Dir, path: []const u8, tree_entry: obj.TreeEntry) !void {
    // open the internal dirs
    var git_dir = try repo_dir.openDir(".git", .{});
    defer git_dir.close();
    var objects_dir = try git_dir.openDir("objects", .{});
    defer objects_dir.close();

    // open the in file
    const oid_hex = std.fmt.bytesToHex(tree_entry.oid, .lower);
    var hash_prefix_dir = try objects_dir.makeOpenPath(oid_hex[0..2], .{});
    defer hash_prefix_dir.close();
    const hash_suffix = oid_hex[2..];
    var in_file = try hash_prefix_dir.openFile(hash_suffix, .{});
    defer in_file.close();

    // open the out file
    const out_file = try repo_dir.createFile(path, .{ .mode = tree_entry.mode });
    defer out_file.close();

    // create the file
    try compress.decompress(allocator, in_file, out_file, true);
}

pub const TreeToWorkspaceChange = enum {
    none,
    untracked,
    deleted,
    modified,
};

fn compareIndexToWorkspace(entry_maybe: ?idx.Index.Entry, file_maybe: ?std.fs.File) !TreeToWorkspaceChange {
    if (entry_maybe) |entry| {
        if (file_maybe) |file| {
            if (try idx.indexDiffersFromWorkspace(entry, file, try file.metadata())) {
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

fn compareTreeToIndex(item_maybe: ?obj.TreeEntry, entry_maybe: ?idx.Index.Entry) TreeToIndexChange {
    if (item_maybe) |item| {
        if (entry_maybe) |entry| {
            if (entry.mode != item.mode or !std.mem.eql(u8, &entry.oid, &item.oid)) {
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
fn untrackedParent(repo_dir: std.fs.Dir, path: []const u8, index: idx.Index) ?[]const u8 {
    var parent = path;
    while (std.fs.path.dirname(parent)) |next_parent| {
        parent = next_parent;
        const file = repo_dir.openFile(next_parent, .{ .mode = .read_only }) catch continue;
        defer file.close();
        const meta = file.metadata() catch continue;
        if (meta.kind() != std.fs.File.Kind.File) continue;
        if (!index.entries.contains(next_parent)) {
            return next_parent;
        }
    }
    return null;
}

/// returns true if the given file or one of its descendents (if a dir)
/// isn't tracked by the index, so it cannot be safely removed by checkout
fn untrackedFile(allocator: std.mem.Allocator, repo_dir: std.fs.Dir, path: []const u8, index: idx.Index) !bool {
    const file = try repo_dir.openFile(path, .{ .mode = .read_only });
    const meta = try file.metadata();
    switch (meta.kind()) {
        std.fs.File.Kind.File => {
            return !index.entries.contains(path);
        },
        std.fs.File.Kind.Directory => {
            var dir = try repo_dir.openIterableDir(path, .{});
            defer dir.close();
            var iter = dir.iterate();
            while (try iter.next()) |dir_entry| {
                const subpath = try std.fs.path.join(allocator, &[_][]const u8{ path, dir_entry.name });
                defer allocator.free(subpath);
                if (try untrackedFile(allocator, repo_dir, subpath, index)) {
                    return true;
                }
            }
            return false;
        },
        else => return false,
    }
}

pub fn migrate(allocator: std.mem.Allocator, repo_dir: std.fs.Dir, tree_diff: obj.TreeDiff, index: *idx.Index, result: *CheckoutResult) !void {
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
        const entry_maybe = index.entries.get(path);
        if (compareTreeToIndex(change.old, entry_maybe) != .none and compareTreeToIndex(change.new, entry_maybe) != .none) {
            result.conflict(allocator);
            try result.data.conflict.stale_files.put(path, {});
        } else {
            const file = repo_dir.openFile(path, .{ .mode = .read_only }) catch |err| {
                switch (err) {
                    error.FileNotFound, error.NotDir => {
                        // if the path doesn't exist in the workspace,
                        // but one of its parents *does* exist and isn't tracked
                        if (untrackedParent(repo_dir, path, index.*)) |_| {
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
            defer file.close();
            const meta = try file.metadata();
            switch (meta.kind()) {
                std.fs.File.Kind.File => {
                    // if the path is a file that differs from the index
                    if (try compareIndexToWorkspace(entry_maybe, file) != .none) {
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
                std.fs.File.Kind.Directory => {
                    // if the path is a dir with a descendent that isn't in the index
                    if (try untrackedFile(allocator, repo_dir, path, index.*)) {
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

    if (result.data == .conflict) {
        return error.CheckoutConflict;
    }

    var remove_files_iter = remove_files.iterator();
    while (remove_files_iter.next()) |entry| {
        // update working tree
        var path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
        const path = try repo_dir.realpath(entry.key_ptr.*, &path_buffer);
        try std.fs.deleteFileAbsolute(path);
        // update index
        index.removePath(entry.key_ptr.*);
        try index.removeChildren(entry.key_ptr.*);
    }

    var remove_dirs_iter = remove_dirs.keyIterator();
    while (remove_dirs_iter.next()) |key| {
        // update working tree
        try repo_dir.deleteTree(key.*);
        // update index
        index.removePath(key.*);
        try index.removeChildren(key.*);
    }

    var add_dirs_iter = add_dirs.keyIterator();
    while (add_dirs_iter.next()) |key| {
        // update working tree
        try repo_dir.makePath(key.*);
        // update index
        try index.addPath(repo_dir, key.*);
    }

    var add_files_iter = add_files.iterator();
    while (add_files_iter.next()) |entry| {
        // update working tree
        try createFileFromObject(allocator, repo_dir, entry.key_ptr.*, entry.value_ptr.*);
        // update index
        try index.addPath(repo_dir, entry.key_ptr.*);
    }

    var edit_files_iter = edit_files.iterator();
    while (edit_files_iter.next()) |entry| {
        // update working tree
        try createFileFromObject(allocator, repo_dir, entry.key_ptr.*, entry.value_ptr.*);
        // update index
        try index.addPath(repo_dir, entry.key_ptr.*);
    }
}

pub fn checkout(allocator: std.mem.Allocator, repo_dir: std.fs.Dir, target: []const u8, result: *CheckoutResult) !void {
    var git_dir = try repo_dir.openDir(".git", .{});
    defer git_dir.close();

    // get the current commit and target oid
    const current_hash = try ref.readHead(git_dir);
    const oid_hex = try ref.resolve(git_dir, target);

    // compare the commits
    var tree_diff = obj.TreeDiff.init(allocator);
    defer tree_diff.deinit();
    try tree_diff.compare(repo_dir, current_hash, oid_hex, null);

    // open index
    // first write to a lock file and then rename it to index for safety
    const index_lock_file = try git_dir.createFile("index.lock", .{ .exclusive = true, .lock = .Exclusive });
    defer index_lock_file.close();
    errdefer git_dir.deleteFile("index.lock") catch {}; // make sure the lock file is deleted on error

    // read index
    var index = try idx.Index.init(allocator, git_dir);
    defer index.deinit();

    // update the working tree
    try migrate(allocator, repo_dir, tree_diff, &index, result);

    // update the index
    try index.write(allocator, index_lock_file);

    // rename lock file to index
    try git_dir.rename("index.lock", "index");

    // update HEAD
    try ref.writeHead(allocator, git_dir, target, oid_hex);
}
