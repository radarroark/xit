const std = @import("std");
const hash = @import("./hash.zig");
const compress = @import("./compress.zig");
const obj = @import("./object.zig");

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
    const out_file = try repo_dir.createFile(path, .{}); // TODO: set mode
    defer out_file.close();

    // create the file
    try compress.decompress(allocator, in_file, out_file, true);
}

pub fn checkout(allocator: std.mem.Allocator, repo_dir: std.fs.Dir, tree_diff: obj.TreeDiff) !void {
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
            if (change.new) |new| {
                try add_files.put(path, new);
                if (std.fs.path.dirname(path)) |parent_path| {
                    try add_dirs.put(parent_path, {});
                }
            }
        } else if (change.new == null) {
            try remove_files.put(path, {});
            if (std.fs.path.dirname(path)) |parent_path| {
                try remove_dirs.put(parent_path, {});
            }
        } else {
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
        var path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
        const path = try repo_dir.realpath(entry.key_ptr.*, &path_buffer);
        try std.fs.deleteFileAbsolute(path);
    }

    var remove_dirs_iter = remove_dirs.keyIterator();
    while (remove_dirs_iter.next()) |key| {
        try repo_dir.deleteTree(key.*);
    }

    var add_dirs_iter = add_dirs.keyIterator();
    while (add_dirs_iter.next()) |key| {
        try repo_dir.makePath(key.*);
    }

    var add_files_iter = add_files.iterator();
    while (add_files_iter.next()) |entry| {
        try createFileFromObject(allocator, repo_dir, entry.key_ptr.*, entry.value_ptr.*);
    }

    var edit_files_iter = edit_files.iterator();
    while (edit_files_iter.next()) |entry| {
        try createFileFromObject(allocator, repo_dir, entry.key_ptr.*, entry.value_ptr.*);
    }
}
