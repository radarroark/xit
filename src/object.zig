//! an object is a file or dir stored in the repo.
//! at least, that's how i think of it. no packed
//! objects for now, but that'll come eventually.

const std = @import("std");
const builtin = @import("builtin");
const hash = @import("./hash.zig");
const compress = @import("./compress.zig");
const cmd = @import("./command.zig");
const idx = @import("./index.zig");
const ref = @import("./ref.zig");

const MAX_FILE_READ_SIZE: comptime_int = 1000; // FIXME: this is arbitrary...

pub const ObjectWriteError = error{
    ObjectAlreadyExists,
    ObjectEntryNotFound,
};

/// returns a single random character. just lower case for now.
/// eventually i'll make it return upper case and maybe numbers too.
fn randChar() !u8 {
    var rand_int: u8 = 0;
    try std.os.getrandom(std.mem.asBytes(&rand_int));
    var rand_float: f32 = @as(f32, @floatFromInt(rand_int)) / @as(f32, @floatFromInt(std.math.maxInt(u8)));
    const min = 'a';
    const max = 'z';
    return @as(u8, @intFromFloat(rand_float * (max - min))) + min;
}

/// fills the given buffer with random chars.
fn fillWithRandChars(buffer: []u8) !void {
    for (buffer) |*ch| {
        ch.* = try randChar();
    }
}

pub const Tree = struct {
    entries: std.ArrayList([]const u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Tree {
        return .{
            .entries = std.ArrayList([]const u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Tree) void {
        for (self.entries.items) |entry| {
            self.allocator.free(entry);
        }
        self.entries.deinit();
    }

    pub fn addBlobEntry(self: *Tree, mode: u32, name: []const u8, oid: []const u8) !void {
        const mode_str = if (mode == 100755) "100755" else "100644";
        const entry = try std.fmt.allocPrint(self.allocator, "{s} {s}\x00{s}", .{ mode_str, name, oid });
        try self.entries.append(entry);
    }

    pub fn addTreeEntry(self: *Tree, name: []const u8, oid: []const u8) !void {
        const entry = try std.fmt.allocPrint(self.allocator, "40000 {s}\x00{s}", .{ name, oid });
        try self.entries.append(entry);
    }
};

fn writeBlob(file: std.fs.File, meta: std.fs.File.Metadata, objects_dir: std.fs.Dir, allocator: std.mem.Allocator, sha1_bytes_buffer: *[hash.SHA1_BYTES_LEN]u8) !void {
    // calc the sha1 of its contents
    try hash.sha1_file(file, sha1_bytes_buffer);
    const sha1_hex = std.fmt.bytesToHex(sha1_bytes_buffer, .lower);

    // make the two char dir
    var hash_prefix_dir = try objects_dir.makeOpenPath(sha1_hex[0..2], .{});
    defer hash_prefix_dir.close();
    const hash_suffix = sha1_hex[2..];

    // exit early if the file already exists
    if (hash_prefix_dir.openFile(hash_suffix, .{})) |hash_suffix_file| {
        hash_suffix_file.close();
        return error.ObjectAlreadyExists;
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
    try compress.compress(allocator, tmp_file, compressed_tmp_file);

    // delete uncompressed temp file
    try hash_prefix_dir.deleteFile(tmp_file_name);

    // rename the compressed temp file
    try std.fs.rename(hash_prefix_dir, compressed_tmp_file_name, hash_prefix_dir, hash_suffix);
}

/// writes the file at the given path into the .git dir.
/// sha1_bytes_buffer will have the oid when it's done.
/// on windows files are never marked as executable because
/// apparently i can't even check if they are...
/// maybe i'll figure that out later.
pub fn writeBlobFromPath(allocator: std.mem.Allocator, cwd: std.fs.Dir, path: []const u8, sha1_bytes_buffer: *[hash.SHA1_BYTES_LEN]u8) !void {
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
        std.fs.File.Kind.file => {
            writeBlob(file, meta, objects_dir, allocator, sha1_bytes_buffer) catch |err| {
                switch (err) {
                    error.ObjectAlreadyExists => {},
                    else => return err,
                }
            };
        },
        else => return,
    }
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
    const tree_sha1_hex = std.fmt.bytesToHex(sha1_bytes_buffer, .lower);

    // make the two char dir
    var tree_hash_prefix_dir = try objects_dir.makeOpenPath(tree_sha1_hex[0..2], .{});
    defer tree_hash_prefix_dir.close();
    const tree_hash_suffix = tree_sha1_hex[2..];

    // exit early if there is nothing to commit
    if (tree_hash_prefix_dir.openFile(tree_hash_suffix, .{})) |tree_hash_suffix_file| {
        tree_hash_suffix_file.close();
        return error.ObjectAlreadyExists;
    } else |err| {
        if (err != error.FileNotFound) {
            return err;
        }
    }

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
    try compress.compress(allocator, tree_tmp_file, tree_comp_tmp_file);

    // delete first temp file
    try tree_hash_prefix_dir.deleteFile(tree_tmp_file_name);

    // rename the file
    try std.fs.rename(tree_hash_prefix_dir, tree_comp_tmp_file_name, tree_hash_prefix_dir, tree_hash_suffix);
}

// add each entry to the given tree.
// if the entry is itself a tree, create a tree object
// for it and add that as an entry to the original tree.
fn addIndexEntries(objects_dir: std.fs.Dir, allocator: std.mem.Allocator, tree: *Tree, index: idx.Index, prefix: []const u8, entries: [][]const u8) !void {
    for (entries) |name| {
        const path = try std.fs.path.join(allocator, &[_][]const u8{ prefix, name });
        defer allocator.free(path);
        if (index.entries.get(path)) |entry| {
            try tree.addBlobEntry(entry.mode, name, &entry.oid);
        } else if (index.dir_to_children.get(path)) |children| {
            var subtree = Tree.init(allocator);
            defer subtree.deinit();

            var child_names = std.ArrayList([]const u8).init(allocator);
            defer child_names.deinit();
            for (children.keys()) |child| {
                try child_names.append(child);
            }

            try addIndexEntries(
                objects_dir,
                allocator,
                &subtree,
                index,
                path,
                child_names.items,
            );

            var tree_sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
            writeTree(objects_dir, allocator, &subtree.entries, &tree_sha1_bytes_buffer) catch |err| {
                switch (err) {
                    error.ObjectAlreadyExists => {},
                    else => return err,
                }
            };

            try tree.addTreeEntry(name, &tree_sha1_bytes_buffer);
        } else {
            return error.ObjectEntryNotFound;
        }
    }
}

/// makes a new commit as a child of whatever is in HEAD.
/// uses the commit message provided to the command.
/// updates HEAD when it's done using a file locking thingy
/// so other processes don't step on each others' toes.
pub fn writeCommit(allocator: std.mem.Allocator, cwd: std.fs.Dir, command: cmd.CommandData) !void {
    // open the internal dirs
    var git_dir = try cwd.openDir(".git", .{});
    defer git_dir.close();
    var objects_dir = try git_dir.openDir("objects", .{});
    defer objects_dir.close();

    // read index
    var index = try idx.Index.init(allocator, git_dir);
    defer index.deinit();

    // create tree and add index entries
    var tree = Tree.init(allocator);
    defer tree.deinit();
    try addIndexEntries(objects_dir, allocator, &tree, index, "", index.root_children.keys());

    // write and hash tree
    var tree_sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
    try writeTree(objects_dir, allocator, &tree.entries, &tree_sha1_bytes_buffer);
    const tree_sha1_hex = std.fmt.bytesToHex(tree_sha1_bytes_buffer, .lower);

    // read HEAD
    const head_oid_maybe = try ref.readHeadMaybe(git_dir);

    // metadata
    const author = "radar <radar@foo.com> 1512325222 +0000";
    const message = command.commit.message orelse "";
    const parent = if (head_oid_maybe) |head_oid|
        try std.fmt.allocPrint(allocator, "parent {s}\n", .{head_oid})
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
    var commit_sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
    try hash.sha1_buffer(commit, &commit_sha1_bytes_buffer);
    const commit_sha1_hex = std.fmt.bytesToHex(commit_sha1_bytes_buffer, .lower);

    // make the two char dir
    var commit_hash_prefix_dir = try objects_dir.makeOpenPath(commit_sha1_hex[0..2], .{});
    defer commit_hash_prefix_dir.close();
    const commit_hash_suffix = commit_sha1_hex[2..];

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
    try compress.compress(allocator, commit_tmp_file, commit_comp_tmp_file);

    // delete first temp file
    try commit_hash_prefix_dir.deleteFile(commit_tmp_file_name);

    // rename the file
    try std.fs.rename(commit_hash_prefix_dir, commit_comp_tmp_file_name, commit_hash_prefix_dir, commit_hash_suffix);

    // write commit id to HEAD
    try ref.update(allocator, git_dir, "HEAD", commit_sha1_hex);
}

pub const ObjectKind = enum {
    blob,
    tree,
    commit,
};

pub const TreeEntry = struct {
    oid: [hash.SHA1_BYTES_LEN]u8,
    mode: u32,

    pub fn eql(self: TreeEntry, other: TreeEntry) bool {
        return std.mem.eql(u8, &self.oid, &other.oid) and self.mode == other.mode;
    }
};

pub fn isTree(entry: TreeEntry) bool {
    return entry.mode == 40000;
}

pub const ObjectContent = union(ObjectKind) {
    blob,
    tree: struct {
        entries: std.StringArrayHashMap(TreeEntry),
    },
    commit: struct {
        tree: [hash.SHA1_HEX_LEN]u8,
        parent: ?[]const u8,
        author: ?[]const u8,
        committer: ?[]const u8,
        message: []const u8,
    },
};

pub const ObjectReadError = error{
    InvalidObjectKind,
    InvalidCommitTreeHash,
    InvalidCommitParentHash,
};

pub const Object = struct {
    allocator: std.mem.Allocator,
    content: ObjectContent,

    pub fn init(allocator: std.mem.Allocator, repo_dir: std.fs.Dir, oid: [hash.SHA1_HEX_LEN]u8) !Object {
        // open the internal dirs
        var git_dir = try repo_dir.openDir(".git", .{});
        defer git_dir.close();
        var objects_dir = try git_dir.openDir("objects", .{});
        defer objects_dir.close();

        // open the object file
        var commit_hash_prefix_dir = try objects_dir.openDir(oid[0..2], .{});
        defer commit_hash_prefix_dir.close();
        var commit_hash_suffix_file = try commit_hash_prefix_dir.openFile(oid[2..], .{ .mode = .read_only });
        defer commit_hash_suffix_file.close();

        // decompress the object file
        var decompressed = try compress.Decompressed.init(allocator, commit_hash_suffix_file);
        defer decompressed.deinit();
        const reader = decompressed.stream.reader();

        // read the object kind
        const object_kind = try reader.readUntilDelimiterAlloc(allocator, ' ', MAX_FILE_READ_SIZE);
        defer allocator.free(object_kind);

        // read the length (currently unused)
        const object_len = try reader.readUntilDelimiterAlloc(allocator, 0, MAX_FILE_READ_SIZE);
        defer allocator.free(object_len);
        _ = try std.fmt.parseInt(usize, object_len, 10);

        if (std.mem.eql(u8, "blob", object_kind)) {
            return Object{
                .allocator = allocator,
                .content = ObjectContent{ .blob = {} },
            };
        } else if (std.mem.eql(u8, "tree", object_kind)) {
            var entries = std.StringArrayHashMap(TreeEntry).init(allocator);
            errdefer {
                for (entries.keys()) |key| {
                    allocator.free(key);
                }
                entries.deinit();
            }

            while (true) {
                const entry_mode = reader.readUntilDelimiterAlloc(allocator, ' ', MAX_FILE_READ_SIZE) catch |err| {
                    switch (err) {
                        error.EndOfStream => break,
                        else => return err,
                    }
                };
                defer allocator.free(entry_mode);
                const entry_mode_num = try std.fmt.parseInt(u32, entry_mode, 10);

                const entry_name = try reader.readUntilDelimiterAlloc(allocator, 0, MAX_FILE_READ_SIZE);
                errdefer allocator.free(entry_name);

                const entry_oid = try reader.readBytesNoEof(hash.SHA1_BYTES_LEN);

                try entries.put(entry_name, TreeEntry{ .oid = entry_oid, .mode = entry_mode_num });
            }

            return Object{
                .allocator = allocator,
                .content = ObjectContent{ .tree = .{ .entries = entries } },
            };
        } else if (std.mem.eql(u8, "commit", object_kind)) {
            // read the content kind
            const content_kind = try reader.readUntilDelimiterAlloc(allocator, ' ', MAX_FILE_READ_SIZE);
            defer allocator.free(content_kind);
            if (!std.mem.eql(u8, "tree", content_kind)) {
                return error.InvalidCommitContentKind;
            }

            // read the tree hash
            var tree_hash = [_]u8{0} ** (hash.SHA1_HEX_LEN + 1);
            const tree_hash_slice = try reader.readUntilDelimiter(&tree_hash, '\n');
            if (tree_hash_slice.len != hash.SHA1_HEX_LEN) {
                return error.InvalidCommitTreeHash;
            }

            // init the object
            var object = Object{
                .allocator = allocator,
                .content = ObjectContent{
                    .commit = .{
                        .tree = undefined,
                        .parent = null,
                        .author = null,
                        .committer = null,
                        .message = undefined,
                    },
                },
            };
            std.mem.copy(u8, &object.content.commit.tree, tree_hash_slice);

            // read the metadata
            var metadata = std.StringHashMap([]const u8).init(allocator);
            defer {
                var iter = metadata.valueIterator();
                while (iter.next()) |value| {
                    allocator.free(value.*);
                }
                metadata.deinit();
            }
            while (true) {
                const line = try reader.readUntilDelimiterAlloc(allocator, '\n', MAX_FILE_READ_SIZE);
                defer allocator.free(line);
                if (line.len == 0) {
                    break;
                }
                if (std.mem.indexOf(u8, line, " ")) |line_idx| {
                    if (line_idx == line.len) {
                        break;
                    }
                    const key = line[0..line_idx];
                    const value = line[line_idx + 1 ..];
                    var value_copy = try allocator.alloc(u8, value.len);
                    std.mem.copy(u8, value_copy, value);
                    try metadata.put(key, value_copy);
                }
            }

            // read the message
            object.content.commit.message = try reader.readAllAlloc(allocator, MAX_FILE_READ_SIZE);
            errdefer allocator.free(object.content.commit.message);

            // set metadata fields
            if (metadata.fetchRemove("parent")) |parent| {
                if (parent.value.len != hash.SHA1_HEX_LEN) {
                    return error.InvalidCommitParentHash;
                }
                object.content.commit.parent = parent.value;
            }
            if (metadata.fetchRemove("author")) |author| {
                object.content.commit.author = author.value;
            }
            if (metadata.fetchRemove("committer")) |committer| {
                object.content.commit.committer = committer.value;
            }

            return object;
        } else {
            return error.InvalidObjectKind;
        }
    }

    pub fn deinit(self: *Object) void {
        switch (self.content) {
            .blob => {},
            .tree => {
                for (self.content.tree.entries.keys()) |key| {
                    self.allocator.free(key);
                }
                self.content.tree.entries.deinit();
            },
            .commit => {
                if (self.content.commit.parent) |parent| {
                    self.allocator.free(parent);
                }
                if (self.content.commit.parent) |author| {
                    self.allocator.free(author);
                }
                if (self.content.commit.committer) |committer| {
                    self.allocator.free(committer);
                }
                self.allocator.free(self.content.commit.message);
            },
        }
    }
};

pub const TreeDiff = struct {
    changes: std.StringHashMap(Change),
    arena: std.heap.ArenaAllocator,

    pub const Change = struct {
        old: ?TreeEntry,
        new: ?TreeEntry,
    };

    pub fn init(allocator: std.mem.Allocator) TreeDiff {
        return TreeDiff{
            .changes = std.StringHashMap(Change).init(allocator),
            .arena = std.heap.ArenaAllocator.init(allocator),
        };
    }

    pub fn deinit(self: *TreeDiff) void {
        self.arena.deinit();
        self.changes.deinit();
    }

    pub fn compare(self: *TreeDiff, repo_dir: std.fs.Dir, old_oid_maybe: ?[hash.SHA1_HEX_LEN]u8, new_oid_maybe: ?[hash.SHA1_HEX_LEN]u8, path_list_maybe: ?std.ArrayList([]const u8)) !void {
        if (old_oid_maybe == null and new_oid_maybe == null) {
            return;
        }
        const old_entries = try self.loadTree(repo_dir, old_oid_maybe);
        const new_entries = try self.loadTree(repo_dir, new_oid_maybe);
        // deletions and edits
        {
            var iter = old_entries.iterator();
            while (iter.next()) |old_entry| {
                const old_key = old_entry.key_ptr.*;
                const old_value = old_entry.value_ptr.*;
                var path_list = if (path_list_maybe) |path_list| try path_list.clone() else std.ArrayList([]const u8).init(self.arena.allocator());
                try path_list.append(old_key);
                const path = try std.fs.path.join(self.arena.allocator(), path_list.items);
                if (new_entries.get(old_key)) |new_value| {
                    if (!old_value.eql(new_value)) {
                        const old_value_tree = isTree(old_value);
                        const new_value_tree = isTree(new_value);
                        try self.compare(repo_dir, if (old_value_tree) std.fmt.bytesToHex(&old_value.oid, .lower) else null, if (new_value_tree) std.fmt.bytesToHex(&new_value.oid, .lower) else null, path_list);
                        if (!old_value_tree or !new_value_tree) {
                            try self.changes.put(path, Change{ .old = if (old_value_tree) null else old_value, .new = if (new_value_tree) null else new_value });
                        }
                    }
                } else {
                    if (isTree(old_value)) {
                        try self.compare(repo_dir, std.fmt.bytesToHex(&old_value.oid, .lower), null, path_list);
                    } else {
                        try self.changes.put(path, Change{ .old = old_value, .new = null });
                    }
                }
            }
        }
        // additions
        {
            var iter = new_entries.iterator();
            while (iter.next()) |new_entry| {
                const new_key = new_entry.key_ptr.*;
                const new_value = new_entry.value_ptr.*;
                var path_list = if (path_list_maybe) |path_list| try path_list.clone() else std.ArrayList([]const u8).init(self.arena.allocator());
                try path_list.append(new_key);
                const path = try std.fs.path.join(self.arena.allocator(), path_list.items);
                if (old_entries.get(new_key)) |_| {
                    continue;
                } else if (isTree(new_value)) {
                    try self.compare(repo_dir, null, std.fmt.bytesToHex(&new_value.oid, .lower), path_list);
                } else {
                    try self.changes.put(path, Change{ .old = null, .new = new_value });
                }
            }
        }
    }

    fn loadTree(self: *TreeDiff, repo_dir: std.fs.Dir, oid_maybe: ?[hash.SHA1_HEX_LEN]u8) !std.StringArrayHashMap(TreeEntry) {
        if (oid_maybe) |oid| {
            var obj = try Object.init(self.arena.allocator(), repo_dir, oid);
            return switch (obj.content) {
                .blob => std.StringArrayHashMap(TreeEntry).init(self.arena.allocator()),
                .tree => obj.content.tree.entries,
                .commit => self.loadTree(repo_dir, obj.content.commit.tree),
            };
        } else {
            return std.StringArrayHashMap(TreeEntry).init(self.arena.allocator());
        }
    }
};
