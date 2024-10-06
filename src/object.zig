//! an object is a file or dir stored in the repo.
//! at least, that's how i think of it. it's a
//! pretty generic name. may as well call it thing.

const std = @import("std");
const builtin = @import("builtin");
const hash = @import("./hash.zig");
const compress = @import("./compress.zig");
const cmd = @import("./command.zig");
const idx = @import("./index.zig");
const ref = @import("./ref.zig");
const io = @import("./io.zig");
const rp = @import("./repo.zig");
const pack = @import("./pack.zig");

const MAX_READ_BYTES = 1024; // FIXME: this is arbitrary...

/// returns a single random character. just lower case for now.
/// eventually i'll make it return upper case and maybe numbers too.
fn randChar() !u8 {
    var rand_int: u8 = 0;
    try std.posix.getrandom(std.mem.asBytes(&rand_int));
    const rand_float: f32 = @as(f32, @floatFromInt(rand_int)) / @as(f32, @floatFromInt(std.math.maxInt(u8)));
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
    entries: std.StringArrayHashMap([]const u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Tree {
        return .{
            .entries = std.StringArrayHashMap([]const u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Tree) void {
        for (self.entries.values()) |entry| {
            self.allocator.free(entry);
        }
        self.entries.deinit();
    }

    pub fn addBlobEntry(self: *Tree, mode: io.Mode, name: []const u8, oid: []const u8) !void {
        const entry = try std.fmt.allocPrint(self.allocator, "{s} {s}\x00{s}", .{ mode.toStr(), name, oid });
        errdefer self.allocator.free(entry);
        try self.entries.put(name, entry);
    }

    pub fn addTreeEntry(self: *Tree, name: []const u8, oid: []const u8) !void {
        const entry = try std.fmt.allocPrint(self.allocator, "40000 {s}\x00{s}", .{ name, oid });
        errdefer self.allocator.free(entry);
        try self.entries.put(name, entry);
    }
};

/// writes the file at the given path as a blob.
/// sha1_bytes_buffer will have the oid when it's done.
/// on windows files are never marked as executable because
/// apparently i can't even check if they are...
/// maybe i'll figure that out later.
pub fn writeBlob(
    comptime repo_kind: rp.RepoKind,
    state: rp.Repo(repo_kind).State,
    allocator: std.mem.Allocator,
    file: anytype,
    file_size: u64,
    sha1_bytes_buffer: *[hash.SHA1_BYTES_LEN]u8,
) !void {
    // create blob header
    const header = try std.fmt.allocPrint(allocator, "blob {}\x00", .{file_size});
    defer allocator.free(header);

    // calc the sha1 of its contents
    const reader = file.reader();
    try hash.sha1Reader(reader, header, sha1_bytes_buffer);
    const sha1_hex = std.fmt.bytesToHex(sha1_bytes_buffer, .lower);

    // reset seek pos so we can reuse the reader for copying
    try file.seekTo(0);

    switch (repo_kind) {
        .git => {
            var objects_dir = try state.core.git_dir.openDir("objects", .{});
            defer objects_dir.close();

            // make the two char dir
            var hash_prefix_dir = try objects_dir.makeOpenPath(sha1_hex[0..2], .{});
            defer hash_prefix_dir.close();
            const hash_suffix = sha1_hex[2..];

            // exit early if the file already exists
            if (hash_prefix_dir.openFile(hash_suffix, .{})) |hash_suffix_file| {
                hash_suffix_file.close();
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
            const tmp_file = try hash_prefix_dir.createFile(tmp_file_name, .{ .read = true, .truncate = true });
            defer tmp_file.close();
            try tmp_file.writeAll(header);

            // copy file into temp file
            // TODO: use buffered io
            var read_buffer = [_]u8{0} ** MAX_READ_BYTES;
            while (true) {
                const size = try reader.read(&read_buffer);
                if (size == 0) {
                    break;
                }
                try tmp_file.writeAll(read_buffer[0..size]);
            }

            // compress the file
            const compressed_tmp_file_name = tmp_file_name ++ ".compressed";
            const compressed_tmp_file = try hash_prefix_dir.createFile(compressed_tmp_file_name, .{});
            defer compressed_tmp_file.close();
            try compress.compress(tmp_file, compressed_tmp_file);

            // delete uncompressed temp file
            try hash_prefix_dir.deleteFile(tmp_file_name);

            // rename the compressed temp file
            try std.fs.rename(hash_prefix_dir, compressed_tmp_file_name, hash_prefix_dir, hash_suffix);
        },
        .xit => {
            const file_hash = hash.bytesToHash(sha1_bytes_buffer);
            const FileReaderType = @TypeOf(reader);

            const Ctx = struct {
                state: rp.Repo(repo_kind).State,
                reader: *const FileReaderType,
                sha1_hex: [hash.SHA1_HEX_LEN]u8,
                header: []const u8,

                pub fn run(ctx: @This(), cursor: *rp.Repo(repo_kind).DB.Cursor(.read_write)) !void {
                    if (cursor.slot() == null) {
                        var writer = try cursor.writer();
                        try writer.writeAll(ctx.header);
                        // TODO: use buffered io
                        var read_buffer = [_]u8{0} ** MAX_READ_BYTES;
                        while (true) {
                            const size = try ctx.reader.read(&read_buffer);
                            if (size == 0) {
                                break;
                            }
                            try writer.writeAll(read_buffer[0..size]);
                        }
                        try writer.finish();

                        _ = try ctx.state.moment.cursor.writePath(void, &.{
                            .{ .hash_map_get = .{ .value = hash.hashBuffer("objects") } },
                            .hash_map_init,
                            .{ .hash_map_get = .{ .value = try hash.hexToHash(&ctx.sha1_hex) } },
                            .{ .write = .{ .slot = writer.slot } },
                        });
                    }
                }
            };
            _ = try state.moment.cursor.writePath(Ctx, &.{
                .{ .hash_map_get = .{ .value = hash.hashBuffer("file-values") } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = file_hash } },
                .{ .ctx = Ctx{ .state = state, .reader = &reader, .sha1_hex = sha1_hex, .header = header } },
            });
        },
    }
}

fn writeTree(comptime repo_kind: rp.RepoKind, state: rp.Repo(repo_kind).State, allocator: std.mem.Allocator, tree: *Tree, sha1_bytes_buffer: *[hash.SHA1_BYTES_LEN]u8) !void {
    // sort the entries. this is needed for xit,
    // because its index entries are stored as a
    // hash map, thus making their order random.
    // sorting them allows the hashes to be the
    // same as they are in git.
    if (repo_kind == .xit) {
        const SortCtx = struct {
            keys: [][]const u8,
            pub fn lessThan(ctx: @This(), a_index: usize, b_index: usize) bool {
                return std.mem.lessThan(u8, ctx.keys[a_index], ctx.keys[b_index]);
            }
        };
        tree.entries.sort(SortCtx{ .keys = tree.entries.keys() });
    }

    // create tree contents
    const tree_contents = try std.mem.join(allocator, "", tree.entries.values());
    defer allocator.free(tree_contents);

    // create tree
    const tree_bytes = try std.fmt.allocPrint(allocator, "tree {}\x00{s}", .{ tree_contents.len, tree_contents });
    defer allocator.free(tree_bytes);

    // calc the sha1 of its contents
    try hash.sha1Buffer(tree_bytes, sha1_bytes_buffer);
    const tree_sha1_hex = std.fmt.bytesToHex(sha1_bytes_buffer, .lower);

    switch (repo_kind) {
        .git => {
            var objects_dir = try state.core.git_dir.openDir("objects", .{});
            defer objects_dir.close();

            // make the two char dir
            var tree_hash_prefix_dir = try objects_dir.makeOpenPath(tree_sha1_hex[0..2], .{});
            defer tree_hash_prefix_dir.close();
            const tree_hash_suffix = tree_sha1_hex[2..];

            // exit early if there is nothing to commit
            if (tree_hash_prefix_dir.openFile(tree_hash_suffix, .{})) |tree_hash_suffix_file| {
                tree_hash_suffix_file.close();
                return;
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
            try tree_tmp_file.pwriteAll(tree_bytes, 0);

            // open compressed temp file
            var tree_comp_rand_chars = [_]u8{0} ** 6;
            try fillWithRandChars(&tree_comp_rand_chars);
            const tree_comp_tmp_file_name = "tmp_obj_" ++ tree_comp_rand_chars;
            const tree_comp_tmp_file = try tree_hash_prefix_dir.createFile(tree_comp_tmp_file_name, .{});
            defer tree_comp_tmp_file.close();

            // compress the file
            try compress.compress(tree_tmp_file, tree_comp_tmp_file);

            // delete first temp file
            try tree_hash_prefix_dir.deleteFile(tree_tmp_file_name);

            // rename the file
            try std.fs.rename(tree_hash_prefix_dir, tree_comp_tmp_file_name, tree_hash_prefix_dir, tree_hash_suffix);
        },
        .xit => {
            const Ctx = struct {
                cursor: *rp.Repo(repo_kind).DB.Cursor(.read_write),
                tree_sha1_bytes: *const [hash.SHA1_BYTES_LEN]u8,
                tree_bytes: []const u8,

                pub fn run(ctx: @This(), cursor: *rp.Repo(repo_kind).DB.Cursor(.read_write)) !void {
                    // exit early if there is nothing to commit
                    if (cursor.slot() != null) {
                        return;
                    }
                    var tree_cursor = try ctx.cursor.writePath(void, &.{
                        .{ .hash_map_get = .{ .value = hash.hashBuffer("object-values") } },
                        .hash_map_init,
                        .{ .hash_map_get = .{ .value = hash.bytesToHash(ctx.tree_sha1_bytes) } },
                    });
                    try tree_cursor.writeBytes(ctx.tree_bytes, .once);
                    _ = try cursor.writePath(void, &.{
                        .{ .write = .{ .slot = tree_cursor.slot() } },
                    });
                }
            };
            _ = try state.moment.cursor.writePath(Ctx, &.{
                .{ .hash_map_get = .{ .value = hash.hashBuffer("objects") } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = hash.bytesToHash(sha1_bytes_buffer) } },
                .{ .ctx = Ctx{
                    .cursor = &state.moment.cursor,
                    .tree_sha1_bytes = sha1_bytes_buffer,
                    .tree_bytes = tree_bytes,
                } },
            });
        },
    }
}

// add each entry to the given tree.
// if the entry is itself a tree, create a tree object
// for it and add that as an entry to the original tree.
fn addIndexEntries(
    comptime repo_kind: rp.RepoKind,
    state: rp.Repo(repo_kind).State,
    allocator: std.mem.Allocator,
    tree: *Tree,
    index: idx.Index(repo_kind),
    prefix: []const u8,
    entries: [][]const u8,
) !void {
    for (entries) |name| {
        const path = try io.joinPath(allocator, &.{ prefix, name });
        defer allocator.free(path);
        if (index.entries.get(path)) |*entries_for_path| {
            const entry = entries_for_path[0] orelse return error.NullEntry;
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
                repo_kind,
                state,
                allocator,
                &subtree,
                index,
                path,
                child_names.items,
            );

            var tree_sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
            try writeTree(repo_kind, state, allocator, &subtree, &tree_sha1_bytes_buffer);

            try tree.addTreeEntry(name, &tree_sha1_bytes_buffer);
        } else {
            return error.ObjectEntryNotFound;
        }
    }
}

pub const CommitMetadata = struct {
    author: ?[]const u8 = null,
    committer: ?[]const u8 = null,
    message: []const u8 = "",
};

fn createCommitContents(allocator: std.mem.Allocator, tree_sha1_hex: [hash.SHA1_HEX_LEN]u8, parent_oids: []const [hash.SHA1_HEX_LEN]u8, metadata: CommitMetadata) ![]const u8 {
    var metadata_lines = std.ArrayList([]const u8).init(allocator);
    defer {
        for (metadata_lines.items) |line| {
            allocator.free(line);
        }
        metadata_lines.deinit();
    }

    try metadata_lines.append(try std.fmt.allocPrint(allocator, "tree {s}", .{tree_sha1_hex}));

    for (parent_oids) |parent_oid| {
        try metadata_lines.append(try std.fmt.allocPrint(allocator, "parent {s}", .{parent_oid}));
    }

    // TODO: read author and committer from config
    const author = metadata.author orelse "radar <radar@foo.com> 1512325222 +0000";
    const committer = metadata.committer orelse author;
    try metadata_lines.append(try std.fmt.allocPrint(allocator, "author {s}", .{author}));
    try metadata_lines.append(try std.fmt.allocPrint(allocator, "committer {s}", .{committer}));
    try metadata_lines.append(try std.fmt.allocPrint(allocator, "\n{s}", .{metadata.message}));

    return try std.mem.join(allocator, "\n", metadata_lines.items);
}

pub fn writeCommit(
    comptime repo_kind: rp.RepoKind,
    state: rp.Repo(repo_kind).State,
    allocator: std.mem.Allocator,
    parent_oids_maybe: ?[]const [hash.SHA1_HEX_LEN]u8,
    metadata: CommitMetadata,
) ![hash.SHA1_HEX_LEN]u8 {
    var commit_sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
    const parent_oids = if (parent_oids_maybe) |oids| oids else blk: {
        const head_oid_maybe = try ref.readHeadMaybe(repo_kind, state);
        break :blk if (head_oid_maybe) |head_oid| &.{head_oid} else &.{};
    };

    // read index
    var index = try idx.Index(repo_kind).init(allocator, state);
    defer index.deinit();

    switch (repo_kind) {
        .git => {
            // open the objects dir
            var objects_dir = try state.core.git_dir.openDir("objects", .{});
            defer objects_dir.close();

            // create tree and add index entries
            var tree = Tree.init(allocator);
            defer tree.deinit();
            try addIndexEntries(repo_kind, state, allocator, &tree, index, "", index.root_children.keys());

            // write and hash tree
            var tree_sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
            try writeTree(repo_kind, state, allocator, &tree, &tree_sha1_bytes_buffer);
            const tree_sha1_hex = std.fmt.bytesToHex(tree_sha1_bytes_buffer, .lower);

            // create commit contents
            const commit_contents = try createCommitContents(allocator, tree_sha1_hex, parent_oids, metadata);
            defer allocator.free(commit_contents);

            // create commit
            const commit = try std.fmt.allocPrint(allocator, "commit {}\x00{s}", .{ commit_contents.len, commit_contents });
            defer allocator.free(commit);

            // calc the sha1 of its contents
            try hash.sha1Buffer(commit, &commit_sha1_bytes_buffer);
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
            try compress.compress(commit_tmp_file, commit_comp_tmp_file);

            // delete first temp file
            try commit_hash_prefix_dir.deleteFile(commit_tmp_file_name);

            // rename the file
            try std.fs.rename(commit_hash_prefix_dir, commit_comp_tmp_file_name, commit_hash_prefix_dir, commit_hash_suffix);

            // write commit id to HEAD
            try ref.updateRecur(repo_kind, state, allocator, &.{"HEAD"}, &commit_sha1_hex);
        },
        .xit => {
            // create tree and add index entries
            var tree = Tree.init(allocator);
            defer tree.deinit();
            try addIndexEntries(repo_kind, state, allocator, &tree, index, "", index.root_children.keys());

            // write and hash tree
            var tree_sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
            try writeTree(repo_kind, state, allocator, &tree, &tree_sha1_bytes_buffer);
            const tree_sha1_hex = std.fmt.bytesToHex(tree_sha1_bytes_buffer, .lower);

            // create commit contents
            const commit_contents = try createCommitContents(allocator, tree_sha1_hex, parent_oids, metadata);
            defer allocator.free(commit_contents);

            // create commit
            const commit = try std.fmt.allocPrint(allocator, "commit {}\x00{s}", .{ commit_contents.len, commit_contents });
            defer allocator.free(commit);

            // calc the sha1 of its contents
            try hash.sha1Buffer(commit, &commit_sha1_bytes_buffer);
            const commit_sha1_hex = std.fmt.bytesToHex(commit_sha1_bytes_buffer, .lower);

            // write commit content
            var content_cursor = try state.moment.cursor.writePath(void, &.{
                .{ .hash_map_get = .{ .value = hash.hashBuffer("object-values") } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = hash.bytesToHash(&commit_sha1_bytes_buffer) } },
            });
            try content_cursor.writeBytes(commit, .once);

            // write commit
            _ = try state.moment.cursor.writePath(void, &.{
                .{ .hash_map_get = .{ .value = hash.hashBuffer("objects") } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = hash.bytesToHash(&commit_sha1_bytes_buffer) } },
                .{ .write = .{ .slot = content_cursor.slot() } },
            });

            // write commit id to HEAD
            try ref.updateRecur(repo_kind, state, allocator, &.{"HEAD"}, &commit_sha1_hex);
        },
    }

    return std.fmt.bytesToHex(commit_sha1_bytes_buffer, .lower);
}

pub const Change = struct {
    old: ?TreeEntry,
    new: ?TreeEntry,
};

pub fn TreeDiff(comptime repo_kind: rp.RepoKind) type {
    return struct {
        changes: std.StringArrayHashMap(Change),
        arena: std.heap.ArenaAllocator,

        pub fn init(allocator: std.mem.Allocator) TreeDiff(repo_kind) {
            return .{
                .changes = std.StringArrayHashMap(Change).init(allocator),
                .arena = std.heap.ArenaAllocator.init(allocator),
            };
        }

        pub fn deinit(self: *TreeDiff(repo_kind)) void {
            self.changes.deinit();
            self.arena.deinit();
        }

        pub fn compare(self: *TreeDiff(repo_kind), state: rp.Repo(repo_kind).State, old_oid_maybe: ?[hash.SHA1_HEX_LEN]u8, new_oid_maybe: ?[hash.SHA1_HEX_LEN]u8, path_list_maybe: ?std.ArrayList([]const u8)) !void {
            if (old_oid_maybe == null and new_oid_maybe == null) {
                return;
            }
            const old_entries = try self.loadTree(state, old_oid_maybe);
            const new_entries = try self.loadTree(state, new_oid_maybe);
            // deletions and edits
            {
                var iter = old_entries.iterator();
                while (iter.next()) |old_entry| {
                    const old_key = old_entry.key_ptr.*;
                    const old_value = old_entry.value_ptr.*;
                    var path_list = if (path_list_maybe) |path_list| try path_list.clone() else std.ArrayList([]const u8).init(self.arena.allocator());
                    try path_list.append(old_key);
                    const path = try io.joinPath(self.arena.allocator(), path_list.items);
                    if (new_entries.get(old_key)) |new_value| {
                        if (!old_value.eql(new_value)) {
                            const old_value_tree = isTree(old_value);
                            const new_value_tree = isTree(new_value);
                            try self.compare(state, if (old_value_tree) std.fmt.bytesToHex(&old_value.oid, .lower) else null, if (new_value_tree) std.fmt.bytesToHex(&new_value.oid, .lower) else null, path_list);
                            if (!old_value_tree or !new_value_tree) {
                                try self.changes.put(path, Change{ .old = if (old_value_tree) null else old_value, .new = if (new_value_tree) null else new_value });
                            }
                        }
                    } else {
                        if (isTree(old_value)) {
                            try self.compare(state, std.fmt.bytesToHex(&old_value.oid, .lower), null, path_list);
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
                    const path = try io.joinPath(self.arena.allocator(), path_list.items);
                    if (old_entries.get(new_key)) |_| {
                        continue;
                    } else if (isTree(new_value)) {
                        try self.compare(state, null, std.fmt.bytesToHex(&new_value.oid, .lower), path_list);
                    } else {
                        try self.changes.put(path, Change{ .old = null, .new = new_value });
                    }
                }
            }
        }

        fn loadTree(self: *TreeDiff(repo_kind), state: rp.Repo(repo_kind).State, oid_maybe: ?[hash.SHA1_HEX_LEN]u8) !std.StringArrayHashMap(TreeEntry) {
            if (oid_maybe) |oid| {
                const obj = try Object(repo_kind, .full).init(self.arena.allocator(), state, oid);
                return switch (obj.content) {
                    .blob => std.StringArrayHashMap(TreeEntry).init(self.arena.allocator()),
                    .tree => |tree| tree.entries,
                    .commit => |commit| self.loadTree(state, commit.tree),
                };
            } else {
                return std.StringArrayHashMap(TreeEntry).init(self.arena.allocator());
            }
        }
    };
}

pub const ObjectKind = enum {
    blob,
    tree,
    commit,

    pub fn init(kind_str: []const u8) !ObjectKind {
        return if (std.mem.eql(u8, "blob", kind_str)) .blob else if (std.mem.eql(u8, "tree", kind_str)) .tree else if (std.mem.eql(u8, "commit", kind_str)) .commit else error.InvalidObjectKind;
    }
};

pub const TreeEntry = struct {
    oid: [hash.SHA1_BYTES_LEN]u8,
    mode: io.Mode,

    pub fn eql(self: TreeEntry, other: TreeEntry) bool {
        return std.mem.eql(u8, &self.oid, &other.oid) and self.mode.eql(other.mode);
    }
};

pub fn isTree(entry: TreeEntry) bool {
    return entry.mode.object_type == .tree;
}

pub fn ObjectReader(comptime repo_kind: rp.RepoKind) type {
    const BUFFER_SIZE = 2048;
    return struct {
        allocator: std.mem.Allocator,
        header: ObjectHeader,
        reader: std.io.BufferedReader(BUFFER_SIZE, Reader),
        internal: switch (repo_kind) {
            .git => void,
            .xit => struct {
                header_offset: u64,
                cursor: *rp.Repo(repo_kind).DB.Cursor(.read_only),
            },
        },

        pub const Reader = switch (repo_kind) {
            .git => pack.LooseOrPackObjectReader,
            .xit => rp.Repo(repo_kind).DB.Cursor(.read_only).Reader,
        };

        pub fn init(allocator: std.mem.Allocator, state: rp.Repo(repo_kind).State, oid: [hash.SHA1_HEX_LEN]u8) !@This() {
            switch (repo_kind) {
                .git => {
                    const reader = try pack.LooseOrPackObjectReader.init(allocator, state.core, oid);
                    return .{
                        .allocator = allocator,
                        .header = reader.header(),
                        .reader = std.io.bufferedReaderSize(BUFFER_SIZE, reader),
                        .internal = {},
                    };
                },
                .xit => {
                    if (try state.moment.cursor.readPath(void, &.{
                        .{ .hash_map_get = .{ .value = hash.hashBuffer("objects") } },
                        .{ .hash_map_get = .{ .value = try hash.hexToHash(&oid) } },
                    })) |cursor| {
                        // put cursor on the heap so the pointer is stable (the reader uses it internally)
                        const cursor_ptr = try allocator.create(rp.Repo(repo_kind).DB.Cursor(.read_only));
                        errdefer allocator.destroy(cursor_ptr);
                        cursor_ptr.* = cursor;
                        var rdr = try cursor_ptr.reader();

                        return .{
                            .allocator = allocator,
                            .header = try readObjectHeader(&rdr),
                            .reader = std.io.bufferedReaderSize(BUFFER_SIZE, rdr),
                            .internal = .{
                                .header_offset = rdr.relative_position,
                                .cursor = cursor_ptr,
                            },
                        };
                    } else {
                        return error.ObjectNotFound;
                    }
                },
            }
        }

        pub fn deinit(self: *ObjectReader(repo_kind)) void {
            switch (repo_kind) {
                .git => self.reader.unbuffered_reader.deinit(),
                .xit => self.allocator.destroy(self.internal.cursor),
            }
        }

        pub fn reset(self: *ObjectReader(repo_kind)) !void {
            switch (repo_kind) {
                .git => {
                    try self.reader.unbuffered_reader.reset();
                    self.reader = std.io.bufferedReaderSize(BUFFER_SIZE, self.reader.unbuffered_reader);
                },
                .xit => {
                    try self.reader.unbuffered_reader.seekTo(self.internal.header_offset);
                    self.reader = std.io.bufferedReaderSize(BUFFER_SIZE, self.reader.unbuffered_reader);
                },
            }
        }

        pub fn seekTo(self: *ObjectReader(repo_kind), position: u64) !void {
            switch (repo_kind) {
                .git => try self.reader.unbuffered_reader.skipBytes(position), // assumes that reset() has just been called!
                .xit => try self.reader.unbuffered_reader.seekTo(self.internal.header_offset + position),
            }
        }
    };
}

pub fn readObjectHeader(reader: anytype) !ObjectHeader {
    const MAX_SIZE: usize = 16;

    // read the object kind
    var object_kind_buf = [_]u8{0} ** MAX_SIZE;
    const object_kind = try reader.readUntilDelimiter(&object_kind_buf, ' ');

    // read the length
    var object_len_buf = [_]u8{0} ** MAX_SIZE;
    const object_len_str = try reader.readUntilDelimiter(&object_len_buf, 0);
    const object_len = try std.fmt.parseInt(u64, object_len_str, 10);

    return .{
        .kind = try ObjectKind.init(object_kind),
        .size = object_len,
    };
}

pub const ObjectHeader = struct {
    kind: ObjectKind,
    size: u64,
};

pub const ObjectContent = union(ObjectKind) {
    blob,
    tree: struct {
        entries: std.StringArrayHashMap(TreeEntry),
    },
    commit: struct {
        tree: [hash.SHA1_HEX_LEN]u8,
        parents: std.ArrayList([hash.SHA1_HEX_LEN]u8),
        metadata: CommitMetadata,
    },
};

pub const ObjectLoadKind = enum {
    // only load the header to determine the object kind,
    // but not any of the remaining content
    raw,
    // read the entire content of the object
    full,
};

pub fn Object(comptime repo_kind: rp.RepoKind, comptime load_kind: ObjectLoadKind) type {
    return struct {
        allocator: std.mem.Allocator,
        arena: *std.heap.ArenaAllocator,
        content: switch (load_kind) {
            .raw => ObjectKind,
            .full => ObjectContent,
        },
        oid: [hash.SHA1_HEX_LEN]u8,
        len: u64,
        object_reader: ObjectReader(repo_kind),

        pub fn init(allocator: std.mem.Allocator, state: rp.Repo(repo_kind).State, oid: [hash.SHA1_HEX_LEN]u8) !Object(repo_kind, load_kind) {
            var obj_rdr = try ObjectReader(repo_kind).init(allocator, state, oid);
            errdefer obj_rdr.deinit();

            const arena = try allocator.create(std.heap.ArenaAllocator);
            arena.* = std.heap.ArenaAllocator.init(allocator);
            errdefer {
                arena.deinit();
                allocator.destroy(arena);
            }

            switch (obj_rdr.header.kind) {
                .blob => return .{
                    .allocator = allocator,
                    .arena = arena,
                    .content = switch (load_kind) {
                        .raw => .blob,
                        .full => .{ .blob = {} },
                    },
                    .oid = oid,
                    .len = obj_rdr.header.size,
                    .object_reader = obj_rdr,
                },
                .tree => {
                    switch (load_kind) {
                        .raw => return .{
                            .allocator = allocator,
                            .arena = arena,
                            .content = .tree,
                            .oid = oid,
                            .len = obj_rdr.header.size,
                            .object_reader = obj_rdr,
                        },
                        .full => {
                            var entries = std.StringArrayHashMap(TreeEntry).init(arena.allocator());

                            while (true) {
                                const entry_mode_str = obj_rdr.reader.unbuffered_reader.readUntilDelimiterAlloc(arena.allocator(), ' ', MAX_READ_BYTES) catch |err| switch (err) {
                                    error.EndOfStream => break,
                                    else => return err,
                                };
                                const entry_mode: io.Mode = @bitCast(try std.fmt.parseInt(u32, entry_mode_str, 8));
                                const entry_name = try obj_rdr.reader.unbuffered_reader.readUntilDelimiterAlloc(arena.allocator(), 0, MAX_READ_BYTES);
                                var entry_oid = [_]u8{0} ** hash.SHA1_BYTES_LEN;
                                try obj_rdr.reader.unbuffered_reader.readNoEof(&entry_oid);
                                try entries.put(entry_name, .{ .oid = entry_oid, .mode = entry_mode });
                            }

                            return .{
                                .allocator = allocator,
                                .arena = arena,
                                .content = ObjectContent{ .tree = .{ .entries = entries } },
                                .oid = oid,
                                .len = obj_rdr.header.size,
                                .object_reader = obj_rdr,
                            };
                        },
                    }
                },
                .commit => {
                    switch (load_kind) {
                        .raw => return .{
                            .allocator = allocator,
                            .arena = arena,
                            .content = .commit,
                            .oid = oid,
                            .len = obj_rdr.header.size,
                            .object_reader = obj_rdr,
                        },
                        .full => {
                            // read the content kind
                            const content_kind = try obj_rdr.reader.unbuffered_reader.readUntilDelimiterAlloc(allocator, ' ', MAX_READ_BYTES);
                            defer allocator.free(content_kind);
                            if (!std.mem.eql(u8, "tree", content_kind)) {
                                return error.InvalidCommitContentKind;
                            }

                            // read the tree hash
                            var tree_hash = [_]u8{0} ** (hash.SHA1_HEX_LEN + 1);
                            const tree_hash_slice = try obj_rdr.reader.unbuffered_reader.readUntilDelimiter(&tree_hash, '\n');
                            if (tree_hash_slice.len != hash.SHA1_HEX_LEN) {
                                return error.InvalidCommitTreeHash;
                            }

                            // init the content
                            var content = ObjectContent{
                                .commit = .{
                                    .tree = tree_hash_slice[0..hash.SHA1_HEX_LEN].*,
                                    .parents = std.ArrayList([hash.SHA1_HEX_LEN]u8).init(arena.allocator()),
                                    .metadata = .{},
                                },
                            };

                            // read the metadata
                            while (true) {
                                const line = try obj_rdr.reader.unbuffered_reader.readUntilDelimiterAlloc(arena.allocator(), '\n', MAX_READ_BYTES);
                                if (line.len == 0) {
                                    break;
                                }
                                if (std.mem.indexOf(u8, line, " ")) |line_idx| {
                                    if (line_idx == line.len) {
                                        break;
                                    }
                                    const key = line[0..line_idx];
                                    const value = line[line_idx + 1 ..];

                                    if (std.mem.eql(u8, "parent", key)) {
                                        if (value.len != hash.SHA1_HEX_LEN) {
                                            return error.InvalidCommitParentHash;
                                        }
                                        try content.commit.parents.append(value[0..hash.SHA1_HEX_LEN].*);
                                    } else if (std.mem.eql(u8, "author", key)) {
                                        content.commit.metadata.author = value;
                                    } else if (std.mem.eql(u8, "committer", key)) {
                                        content.commit.metadata.committer = value;
                                    }
                                }
                            }

                            // read the message
                            content.commit.metadata.message = try obj_rdr.reader.unbuffered_reader.readAllAlloc(arena.allocator(), MAX_READ_BYTES);

                            return .{
                                .allocator = allocator,
                                .arena = arena,
                                .content = content,
                                .oid = oid,
                                .len = obj_rdr.header.size,
                                .object_reader = obj_rdr,
                            };
                        },
                    }
                },
            }
        }

        pub fn deinit(self: *Object(repo_kind, load_kind)) void {
            self.arena.deinit();
            self.allocator.destroy(self.arena);
            self.object_reader.deinit();
        }
    };
}

pub fn ObjectIterator(comptime repo_kind: rp.RepoKind, comptime load_kind: ObjectLoadKind) type {
    return struct {
        allocator: std.mem.Allocator,
        core: *rp.Repo(repo_kind).Core,
        moment: switch (repo_kind) {
            .git => void,
            .xit => rp.Repo(repo_kind).DB.HashMap(.read_write),
        },
        oid_queue: std.DoublyLinkedList([hash.SHA1_HEX_LEN]u8),
        oid_excludes: std.AutoHashMap([hash.SHA1_HEX_LEN]u8, void),
        object: Object(repo_kind, load_kind),
        options: Options,

        pub const Options = struct {
            recursive: bool,
        };

        pub fn init(
            allocator: std.mem.Allocator,
            state: rp.Repo(repo_kind).State,
            start_oids: []const [hash.SHA1_HEX_LEN]u8,
            options: Options,
        ) !ObjectIterator(repo_kind, load_kind) {
            var self = ObjectIterator(repo_kind, load_kind){
                .allocator = allocator,
                .core = state.core,
                .moment = switch (repo_kind) {
                    .git => {},
                    .xit => state.moment.*,
                },
                .oid_queue = std.DoublyLinkedList([hash.SHA1_HEX_LEN]u8){},
                .oid_excludes = std.AutoHashMap([hash.SHA1_HEX_LEN]u8, void).init(allocator),
                .object = undefined,
                .options = options,
            };
            errdefer self.deinit();

            for (start_oids) |start_oid| {
                var node = try allocator.create(std.DoublyLinkedList([hash.SHA1_HEX_LEN]u8).Node);
                errdefer allocator.destroy(node);
                node.data = start_oid;
                self.oid_queue.append(node);
            }

            return self;
        }

        pub fn deinit(self: *ObjectIterator(repo_kind, load_kind)) void {
            while (self.oid_queue.popFirst()) |node| {
                self.allocator.destroy(node);
            }
            self.oid_excludes.deinit();
        }

        pub fn next(self: *ObjectIterator(repo_kind, load_kind)) !?*Object(repo_kind, load_kind) {
            const state = switch (repo_kind) {
                .git => .{ .core = self.core },
                .xit => .{ .core = self.core, .moment = &self.moment },
            };
            while (self.oid_queue.popFirst()) |node| {
                const next_oid = node.data;
                self.allocator.destroy(node);
                if (!self.oid_excludes.contains(next_oid)) {
                    try self.oid_excludes.put(next_oid, {});
                    switch (load_kind) {
                        .raw => {
                            var object = try Object(repo_kind, .full).init(self.allocator, state, next_oid);
                            defer object.deinit();
                            try self.addToQueue(object.content);

                            var raw_object = try Object(repo_kind, .raw).init(self.allocator, state, next_oid);
                            errdefer raw_object.deinit();
                            self.object = raw_object;
                            return &self.object;
                        },
                        .full => {
                            var object = try Object(repo_kind, .full).init(self.allocator, state, next_oid);
                            errdefer object.deinit();
                            try self.addToQueue(object.content);
                            self.object = object;
                            return &self.object;
                        },
                    }
                }
            }
            return null;
        }

        fn addToQueue(self: *ObjectIterator(repo_kind, load_kind), content: ObjectContent) !void {
            switch (content) {
                .blob => {},
                .tree => |tree| {
                    if (self.options.recursive) {
                        for (tree.entries.values()) |entry| {
                            const entry_oid = std.fmt.bytesToHex(entry.oid, .lower);
                            if (!self.oid_excludes.contains(entry_oid)) {
                                var new_node = try self.allocator.create(std.DoublyLinkedList([hash.SHA1_HEX_LEN]u8).Node);
                                errdefer self.allocator.destroy(new_node);
                                new_node.data = entry_oid;
                                self.oid_queue.append(new_node);
                            }
                        }
                    }
                },
                .commit => |commit| {
                    for (commit.parents.items) |parent_oid| {
                        var new_node = try self.allocator.create(std.DoublyLinkedList([hash.SHA1_HEX_LEN]u8).Node);
                        errdefer self.allocator.destroy(new_node);
                        new_node.data = parent_oid;
                        self.oid_queue.append(new_node);
                    }
                    if (self.options.recursive) {
                        if (!self.oid_excludes.contains(commit.tree)) {
                            var new_node = try self.allocator.create(std.DoublyLinkedList([hash.SHA1_HEX_LEN]u8).Node);
                            errdefer self.allocator.destroy(new_node);
                            new_node.data = commit.tree;
                            self.oid_queue.append(new_node);
                        }
                    }
                },
            }
        }

        pub fn exclude(self: *ObjectIterator(repo_kind, load_kind), oid: [hash.SHA1_HEX_LEN]u8) !void {
            try self.oid_excludes.put(oid, {});

            const state = switch (repo_kind) {
                .git => .{ .core = self.core },
                .xit => .{ .core = self.core, .moment = &self.moment },
            };
            var object = try Object(repo_kind, .full).init(self.allocator, state, oid);
            defer object.deinit();
            switch (object.content) {
                .blob => {},
                .tree => |tree| {
                    if (self.options.recursive) {
                        for (tree.entries.values()) |entry| {
                            try self.exclude(std.fmt.bytesToHex(entry.oid, .lower));
                        }
                    }
                },
                .commit => |commit| {
                    for (commit.parents.items) |parent_oid| {
                        try self.oid_excludes.put(parent_oid, {});
                    }
                    if (self.options.recursive) {
                        try self.exclude(commit.tree);
                    }
                },
            }
        }
    };
}
