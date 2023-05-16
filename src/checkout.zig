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

pub fn migrate(allocator: std.mem.Allocator, repo_dir: std.fs.Dir, tree_diff: obj.TreeDiff, index: *idx.Index) !void {
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

pub fn checkout(allocator: std.mem.Allocator, repo_dir: std.fs.Dir, oid_hex: [hash.SHA1_HEX_LEN]u8) !void {
    var git_dir = try repo_dir.openDir(".git", .{});
    defer git_dir.close();

    // get the current commit
    const current_hash = try ref.readHead(git_dir);

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
    try migrate(allocator, repo_dir, tree_diff, &index);

    // update the index
    try index.write(allocator, index_lock_file);

    // rename lock file to index
    try git_dir.rename("index.lock", "index");

    // update HEAD
    try ref.writeHead(git_dir, &oid_hex);
}
