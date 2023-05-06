const std = @import("std");
const obj = @import("./object.zig");

pub fn checkout(allocator: std.mem.Allocator, tree_diff: obj.TreeDiff) !void {
    var add_files = std.StringHashMap(obj.TreeDiff.Change).init(allocator);
    defer add_files.deinit();
    var edit_files = std.StringHashMap(obj.TreeDiff.Change).init(allocator);
    defer edit_files.deinit();
    var remove_files = std.StringHashMap(obj.TreeDiff.Change).init(allocator);
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
            try add_files.put(path, change);
            if (std.fs.path.dirname(path)) |parent_path| {
                try add_dirs.put(parent_path, {});
            }
        } else if (change.new == null) {
            try remove_files.put(path, change);
            if (std.fs.path.dirname(path)) |parent_path| {
                try remove_dirs.put(parent_path, {});
            }
        } else {
            try edit_files.put(path, change);
            if (std.fs.path.dirname(path)) |parent_path| {
                try add_dirs.put(parent_path, {});
            }
        }
    }
}
