const std = @import("std");
const builtin = @import("builtin");
const hash = @import("./hash.zig");
const compress = @import("./compress.zig");
const cmd = @import("./command.zig");
const idx = @import("./index.zig");

const MAX_FILE_READ_SIZE: comptime_int = 1000; // FIXME: this is arbitrary...

/// returns a single random character. just lower case for now.
/// eventually i'll make it return upper case and maybe numbers too.
fn randChar() !u8 {
    var rand_int: u8 = 0;
    try std.os.getrandom(std.mem.asBytes(&rand_int));
    var rand_float: f32 = (@intToFloat(f32, rand_int) / @intToFloat(f32, std.math.maxInt(u8)));
    const min = 'a';
    const max = 'z';
    return @floatToInt(u8, rand_float * (max - min)) + min;
}

/// fills the given buffer with random chars.
fn fillWithRandChars(buffer: []u8) !void {
    var i: u32 = 0;
    while (i < buffer.len) {
        buffer[i] = try randChar();
        i += 1;
    }
}

pub const Tree = struct {
    const Self = @This();

    entries: std.ArrayList([]const u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Tree {
        return .{
            .entries = std.ArrayList([]const u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.entries.items) |entry| {
            self.allocator.free(entry);
        }
        self.entries.deinit();
    }

    pub fn addBlobEntry(self: *Self, mode: u32, path: []const u8, oid: []const u8) !void {
        const mode_str = if (mode == 100755) "100755" else "100644";
        const entry = try std.fmt.allocPrint(self.allocator, "{s} {s}\x00{s}", .{ mode_str, path, oid });
        try self.entries.append(entry);
    }

    pub fn addTreeEntry(self: *Self, path: []const u8, oid: []const u8) !void {
        const entry = try std.fmt.allocPrint(self.allocator, "40000 {s}\x00{s}", .{ path, oid });
        try self.entries.append(entry);
    }
};

fn writeBlob(file: std.fs.File, meta: std.fs.File.Metadata, objects_dir: std.fs.Dir, allocator: std.mem.Allocator, sha1_bytes_buffer: *[hash.SHA1_BYTES_LEN]u8) !void {
    // calc the sha1 of its contents
    try hash.sha1_file(file, sha1_bytes_buffer);
    var sha1_hex_buffer = [_]u8{0} ** hash.SHA1_HEX_LEN;
    const sha1_hex = try std.fmt.bufPrint(&sha1_hex_buffer, "{}", .{std.fmt.fmtSliceHexLower(sha1_bytes_buffer)});

    // make the two char dir
    var hash_prefix_dir = try objects_dir.makeOpenPath(sha1_hex[0..2], .{});
    defer hash_prefix_dir.close();

    // if the file already exists, exit early
    const rest_of_hash = sha1_hex[2..];
    if (hash_prefix_dir.openFile(rest_of_hash, .{})) |rest_of_hash_file| {
        rest_of_hash_file.close();
        return;
    } else |err| {
        if (err != error.FileNotFound) {
            return err;
        }
    }

    // open temp file
    var rand_chars = [_]u8{0} ** 6;
    try fillWithRandChars(&rand_chars);
    const tmp_file_name = "tmp_obj_" ++ rand_chars;
    const tmp_file = try hash_prefix_dir.createFile(tmp_file_name, .{ .read = true });
    defer tmp_file.close();

    // create blob header
    const file_size = meta.size();
    const blob = try std.fmt.allocPrint(allocator, "blob {}\x00", .{file_size});
    defer allocator.free(blob);
    try tmp_file.writeAll(blob);

    // copy file into temp file
    var read_buffer = [_]u8{0} ** MAX_FILE_READ_SIZE;
    var offset: u64 = 0;
    while (true) {
        const size = try file.pread(&read_buffer, offset);
        offset += size;
        if (size == 0) {
            break;
        }
        try tmp_file.writeAll(read_buffer[0..size]);
    }

    // compress the file
    const compressed_tmp_file_name = tmp_file_name ++ ".compressed";
    const compressed_tmp_file = try hash_prefix_dir.createFile(compressed_tmp_file_name, .{});
    defer compressed_tmp_file.close();
    try compress.compress(tmp_file, compressed_tmp_file, allocator);

    // delete uncompressed temp file
    try hash_prefix_dir.deleteFile(tmp_file_name);

    // rename the compressed temp file
    try std.fs.rename(hash_prefix_dir, compressed_tmp_file_name, hash_prefix_dir, rest_of_hash);
}

fn writeTree(objects_dir: std.fs.Dir, allocator: std.mem.Allocator, entries: *std.ArrayList([]const u8), sha1_bytes_buffer: *[hash.SHA1_BYTES_LEN]u8) !void {
    // create tree contents
    const tree_contents = try std.mem.join(allocator, "", entries.items);
    defer allocator.free(tree_contents);

    // create tree
    const tree = try std.fmt.allocPrint(allocator, "tree {}\x00{s}", .{ tree_contents.len, tree_contents });
    defer allocator.free(tree);

    // calc the sha1 of its contents
    try hash.sha1_buffer(tree, sha1_bytes_buffer);
    var tree_sha1_hex_buffer = [_]u8{0} ** hash.SHA1_HEX_LEN;
    const tree_sha1_hex = try std.fmt.bufPrint(&tree_sha1_hex_buffer, "{}", .{std.fmt.fmtSliceHexLower(sha1_bytes_buffer)});

    // make the two char dir
    var tree_hash_prefix_dir = try objects_dir.makeOpenPath(tree_sha1_hex[0..2], .{});
    defer tree_hash_prefix_dir.close();

    // open temp file
    var tree_rand_chars = [_]u8{0} ** 6;
    try fillWithRandChars(&tree_rand_chars);
    const tree_tmp_file_name = "tmp_obj_" ++ tree_rand_chars;
    const tree_tmp_file = try tree_hash_prefix_dir.createFile(tree_tmp_file_name, .{ .read = true });
    defer tree_tmp_file.close();

    // write to the temp file
    try tree_tmp_file.pwriteAll(tree, 0);

    // open compressed temp file
    var tree_comp_rand_chars = [_]u8{0} ** 6;
    try fillWithRandChars(&tree_comp_rand_chars);
    const tree_comp_tmp_file_name = "tmp_obj_" ++ tree_comp_rand_chars;
    const tree_comp_tmp_file = try tree_hash_prefix_dir.createFile(tree_comp_tmp_file_name, .{});
    defer tree_comp_tmp_file.close();

    // compress the file
    try compress.compress(tree_tmp_file, tree_comp_tmp_file, allocator);

    // delete first temp file
    try tree_hash_prefix_dir.deleteFile(tree_tmp_file_name);

    // rename the file
    try std.fs.rename(tree_hash_prefix_dir, tree_comp_tmp_file_name, tree_hash_prefix_dir, tree_sha1_hex[2..]);
}

/// writes the file/dir at the given path into the .git dir.
/// if it's a dir, all of its contents will be added too.
/// entries can be null when first called and sha1_hex_buffer
/// will have the oid when it's done. on windows files are
/// never marked as executable because apparently i can't
/// even check if they are...maybe i'll figure that out later.
pub fn writeObject(cwd: std.fs.Dir, path: []const u8, allocator: std.mem.Allocator, tree_maybe: ?*Tree, sha1_bytes_buffer: *[hash.SHA1_BYTES_LEN]u8) !void {
    // open the internal dirs
    var git_dir = try cwd.openDir(".git", .{});
    defer git_dir.close();
    var objects_dir = try git_dir.openDir("objects", .{});
    defer objects_dir.close();

    // get absolute path of the file
    var path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
    const file_path = try cwd.realpath(path, &path_buffer);
    var file = try std.fs.openFileAbsolute(file_path, .{ .mode = std.fs.File.OpenMode.read_only });
    defer file.close();

    // see if it's a file or dir
    const meta = try file.metadata();
    switch (meta.kind()) {
        std.fs.File.Kind.File => {
            try writeBlob(file, meta, objects_dir, allocator, sha1_bytes_buffer);

            // add to entries if it's not null
            if (tree_maybe) |tree| {
                const is_executable = switch (builtin.os.tag) {
                    .windows => false,
                    else => meta.permissions().inner.unixHas(std.fs.File.PermissionsUnix.Class.user, .execute),
                };
                const mode: u32 = if (is_executable) 100755 else 100644;
                try tree.addBlobEntry(mode, path, sha1_bytes_buffer);
            }
        },
        std.fs.File.Kind.Directory => {
            var subtree = Tree.init(allocator);
            defer subtree.deinit();

            // iterate recursively
            var subdir = try cwd.openIterableDir(path, .{});
            defer subdir.close();
            var iter = subdir.iterate();
            while (try iter.next()) |entry| {
                // don't traverse the .git dir
                if (std.mem.eql(u8, entry.name, ".git")) {
                    continue;
                }

                const subpath = try std.fs.path.join(allocator, &[_][]const u8{ path, entry.name });
                defer allocator.free(subpath);
                var sub_sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
                try writeObject(cwd, subpath, allocator, &subtree, &sub_sha1_bytes_buffer);
            }

            try writeTree(objects_dir, allocator, &subtree.entries, sha1_bytes_buffer);

            // add to entries if it's not null
            if (tree_maybe) |tree| {
                try tree.addTreeEntry(path, sha1_bytes_buffer);
            }
        },
        else => return,
    }
}

/// makes a new commit as a child of whatever is in HEAD.
/// uses the commit message provided to the command.
/// updates HEAD when it's done using a file locking thingy
/// so other processes don't step on each others' toes.
pub fn writeCommit(cwd: std.fs.Dir, allocator: std.mem.Allocator, command: cmd.CommandData) !void {
    // open the internal dirs
    var git_dir = try cwd.openDir(".git", .{});
    defer git_dir.close();
    var objects_dir = try git_dir.openDir("objects", .{});
    defer objects_dir.close();

    // create tree
    var tree = Tree.init(allocator);
    defer tree.deinit();

    // read index
    var index = try idx.readIndex(git_dir, allocator);
    defer index.deinit();
    for (index.entries.values()) |entry| {
        try tree.addBlobEntry(entry.mode, entry.path, &entry.oid);
    }

    // write and hash tree
    var tree_sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
    try writeTree(objects_dir, allocator, &tree.entries, &tree_sha1_bytes_buffer);
    var tree_sha1_hex_buffer = [_]u8{0} ** hash.SHA1_HEX_LEN;
    const tree_sha1_hex = try std.fmt.bufPrint(&tree_sha1_hex_buffer, "{}", .{std.fmt.fmtSliceHexLower(&tree_sha1_bytes_buffer)});

    // read HEAD
    var head_file_buffer = [_]u8{0} ** MAX_FILE_READ_SIZE;
    var head_file_size: usize = 0;
    {
        const head_file_or_err = git_dir.openFile("HEAD", .{ .mode = .read_only });
        const head_file = try if (head_file_or_err == error.FileNotFound)
            git_dir.createFile("HEAD", .{ .read = true })
        else
            head_file_or_err;
        defer head_file.close();
        head_file_size = try head_file.pread(&head_file_buffer, 0);
    }
    const head_file_slice = head_file_buffer[0..head_file_size];

    // metadata
    const author = "radar <radar@foo.com> 1512325222 +0000";
    const message = command.commit.message orelse "";
    const parent = if (head_file_size > 0)
        try std.fmt.allocPrint(allocator, "parent {s}\n", .{head_file_slice})
    else
        try std.fmt.allocPrint(allocator, "", .{});
    defer allocator.free(parent);

    // create commit contents
    const commit_contents = try std.fmt.allocPrint(allocator, "tree {s}\n{s}author {s}\ncommitter {s}\n\n{s}", .{ tree_sha1_hex, parent, author, author, message });
    defer allocator.free(commit_contents);

    // create commit
    const commit = try std.fmt.allocPrint(allocator, "commit {}\x00{s}", .{ commit_contents.len, commit_contents });
    defer allocator.free(commit);

    // calc the sha1 of its contents
    var commit_sha1_bytes = [_]u8{0} ** hash.SHA1_BYTES_LEN;
    try hash.sha1_buffer(commit, &commit_sha1_bytes);
    var commit_sha1_hex_buffer = [_]u8{0} ** hash.SHA1_HEX_LEN;
    const commit_sha1_hex = try std.fmt.bufPrint(&commit_sha1_hex_buffer, "{}", .{std.fmt.fmtSliceHexLower(&commit_sha1_bytes)});

    // make the two char dir
    var commit_hash_prefix_dir = try objects_dir.makeOpenPath(commit_sha1_hex[0..2], .{});
    defer commit_hash_prefix_dir.close();

    // open temp file
    var commit_rand_chars = [_]u8{0} ** 6;
    try fillWithRandChars(&commit_rand_chars);
    const commit_tmp_file_name = "tmp_obj_" ++ commit_rand_chars;
    const commit_tmp_file = try commit_hash_prefix_dir.createFile(commit_tmp_file_name, .{ .read = true });
    defer commit_tmp_file.close();

    // write to the temp file
    try commit_tmp_file.pwriteAll(commit, 0);

    // open compressed temp file
    var commit_comp_rand_chars = [_]u8{0} ** 6;
    try fillWithRandChars(&commit_comp_rand_chars);
    const commit_comp_tmp_file_name = "tmp_obj_" ++ commit_comp_rand_chars;
    const commit_comp_tmp_file = try commit_hash_prefix_dir.createFile(commit_comp_tmp_file_name, .{});
    defer commit_comp_tmp_file.close();

    // compress the file
    try compress.compress(commit_tmp_file, commit_comp_tmp_file, allocator);

    // delete first temp file
    try commit_hash_prefix_dir.deleteFile(commit_tmp_file_name);

    // rename the file
    try std.fs.rename(commit_hash_prefix_dir, commit_comp_tmp_file_name, commit_hash_prefix_dir, commit_sha1_hex[2..]);

    // write commit id to HEAD
    // first write to a lock file and then rename it to HEAD for safety
    {
        const head_file = try git_dir.createFile("HEAD.lock", .{ .exclusive = true, .lock = .Exclusive });
        defer head_file.close();
        try head_file.pwriteAll(commit_sha1_hex, 0);
    }
    try git_dir.rename("HEAD.lock", "HEAD");
}
