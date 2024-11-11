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
const chunk = @import("./chunk.zig");

const MAX_READ_BYTES = 1024; // FIXME: this is arbitrary...

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

pub fn writeObject(
    comptime repo_kind: rp.RepoKind,
    state: rp.Repo(repo_kind).State(.read_write),
    allocator: std.mem.Allocator,
    file: anytype,
    header: ObjectHeader,
    sha1_bytes_buffer: *[hash.SHA1_BYTES_LEN]u8,
) !void {
    // serialize object header
    var header_bytes = [_]u8{0} ** 32;
    const header_str = try writeObjectHeader(header, &header_bytes);

    // calc the sha1 of its contents
    const reader = file.reader();
    try hash.sha1Reader(reader, header_str, sha1_bytes_buffer);
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

            // create lock file
            var lock = try io.LockFile.init(allocator, hash_prefix_dir, hash_suffix ++ ".uncompressed");
            defer lock.deinit();
            try lock.lock_file.writeAll(header_str);

            // copy file into temp file
            var read_buffer = [_]u8{0} ** MAX_READ_BYTES;
            while (true) {
                const size = try reader.read(&read_buffer);
                if (size == 0) {
                    break;
                }
                try lock.lock_file.writeAll(read_buffer[0..size]);
            }

            // create compressed lock file
            var compressed_lock = try io.LockFile.init(allocator, hash_prefix_dir, hash_suffix);
            defer compressed_lock.deinit();
            try compress.compress(lock.lock_file, compressed_lock.lock_file);
            compressed_lock.success = true;
        },
        .xit => {
            const file_hash = hash.bytesToHash(sha1_bytes_buffer);
            try chunk.writeChunks(state, allocator, file, file_hash, header_str);
        },
    }
}

fn writeTree(
    comptime repo_kind: rp.RepoKind,
    state: rp.Repo(repo_kind).State(.read_write),
    allocator: std.mem.Allocator,
    tree: *Tree,
    sha1_bytes_buffer: *[hash.SHA1_BYTES_LEN]u8,
) !void {
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

    // create tree header
    var header_buffer = [_]u8{0} ** 32;
    const header = try std.fmt.bufPrint(&header_buffer, "tree {}\x00", .{tree_contents.len});

    // create tree
    const tree_bytes = try std.fmt.allocPrint(allocator, "{s}{s}", .{ header, tree_contents });
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

            // create lock file
            var lock = try io.LockFile.init(allocator, tree_hash_prefix_dir, tree_hash_suffix ++ ".uncompressed");
            defer lock.deinit();
            try lock.lock_file.writeAll(tree_bytes);

            // create compressed lock file
            var compressed_lock = try io.LockFile.init(allocator, tree_hash_prefix_dir, tree_hash_suffix);
            defer compressed_lock.deinit();
            try compress.compress(lock.lock_file, compressed_lock.lock_file);
            compressed_lock.success = true;
        },
        .xit => {
            const object_hash = hash.bytesToHash(sha1_bytes_buffer);
            var stream = std.io.fixedBufferStream(tree_contents);
            try chunk.writeChunks(state, allocator, &stream, object_hash, header);
        },
    }
}

// add each entry to the given tree.
// if the entry is itself a tree, create a tree object
// for it and add that as an entry to the original tree.
fn addIndexEntries(
    comptime repo_kind: rp.RepoKind,
    state: rp.Repo(repo_kind).State(.read_write),
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

fn createCommitContents(
    allocator: std.mem.Allocator,
    tree_sha1_hex: *const [hash.SHA1_HEX_LEN]u8,
    parent_oids: []const [hash.SHA1_HEX_LEN]u8,
    metadata: CommitMetadata,
) ![]const u8 {
    var metadata_lines = std.ArrayList([]const u8).init(allocator);
    defer {
        for (metadata_lines.items) |line| {
            allocator.free(line);
        }
        metadata_lines.deinit();
    }

    try metadata_lines.append(try std.fmt.allocPrint(allocator, "tree {s}", .{tree_sha1_hex.*}));

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
    state: rp.Repo(repo_kind).State(.read_write),
    allocator: std.mem.Allocator,
    parent_oids_maybe: ?[]const [hash.SHA1_HEX_LEN]u8,
    metadata: CommitMetadata,
) ![hash.SHA1_HEX_LEN]u8 {
    var commit_sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
    const parent_oids = if (parent_oids_maybe) |oids| oids else blk: {
        const head_oid_maybe = try ref.readHeadMaybe(repo_kind, state.readOnly());
        break :blk if (head_oid_maybe) |head_oid| &.{head_oid} else &.{};
    };

    // read index
    var index = try idx.Index(repo_kind).init(allocator, state.readOnly());
    defer index.deinit();

    // create tree and add index entries
    var tree = Tree.init(allocator);
    defer tree.deinit();
    try addIndexEntries(repo_kind, state, allocator, &tree, index, "", index.root_children.keys());

    // write and hash tree
    var tree_sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
    try writeTree(repo_kind, state, allocator, &tree, &tree_sha1_bytes_buffer);
    const tree_sha1_hex = std.fmt.bytesToHex(tree_sha1_bytes_buffer, .lower);

    // don't allow commit if the tree hasn't changed
    if (parent_oids.len == 1) {
        var first_parent = try Object(repo_kind, .full).init(allocator, state.readOnly(), &parent_oids[0]);
        defer first_parent.deinit();
        if (std.mem.eql(u8, &first_parent.content.commit.tree, &tree_sha1_hex)) {
            return error.EmptyCommit;
        }
    }

    // create commit contents
    const commit_contents = try createCommitContents(allocator, &tree_sha1_hex, parent_oids, metadata);
    defer allocator.free(commit_contents);

    // create commit header
    var header_buffer = [_]u8{0} ** 32;
    const header = try std.fmt.bufPrint(&header_buffer, "commit {}\x00", .{commit_contents.len});

    // create commit
    const commit = try std.fmt.allocPrint(allocator, "{s}{s}", .{ header, commit_contents });
    defer allocator.free(commit);

    // calc the sha1 of its contents
    try hash.sha1Buffer(commit, &commit_sha1_bytes_buffer);
    const commit_sha1_hex = std.fmt.bytesToHex(commit_sha1_bytes_buffer, .lower);
    const commit_hash = hash.bytesToHash(&commit_sha1_bytes_buffer);

    switch (repo_kind) {
        .git => {
            // open the objects dir
            var objects_dir = try state.core.git_dir.openDir("objects", .{});
            defer objects_dir.close();

            // make the two char dir
            var commit_hash_prefix_dir = try objects_dir.makeOpenPath(commit_sha1_hex[0..2], .{});
            defer commit_hash_prefix_dir.close();
            const commit_hash_suffix = commit_sha1_hex[2..];

            // create lock file
            var lock = try io.LockFile.init(allocator, commit_hash_prefix_dir, commit_hash_suffix ++ ".uncompressed");
            defer lock.deinit();
            try lock.lock_file.writeAll(commit);

            // create compressed lock file
            var compressed_lock = try io.LockFile.init(allocator, commit_hash_prefix_dir, commit_hash_suffix);
            defer compressed_lock.deinit();
            try compress.compress(lock.lock_file, compressed_lock.lock_file);
            compressed_lock.success = true;

            // write commit id to HEAD
            try ref.updateRecur(repo_kind, state, allocator, &.{"HEAD"}, &commit_sha1_hex);
        },
        .xit => {
            var stream = std.io.fixedBufferStream(commit_contents);
            try chunk.writeChunks(state, allocator, &stream, commit_hash, header);

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

        pub fn compare(self: *TreeDiff(repo_kind), state: rp.Repo(repo_kind).State(.read_only), old_oid_maybe: ?[hash.SHA1_HEX_LEN]u8, new_oid_maybe: ?[hash.SHA1_HEX_LEN]u8, path_list_maybe: ?std.ArrayList([]const u8)) !void {
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

        fn loadTree(self: *TreeDiff(repo_kind), state: rp.Repo(repo_kind).State(.read_only), oid_maybe: ?[hash.SHA1_HEX_LEN]u8) !std.StringArrayHashMap(TreeEntry) {
            if (oid_maybe) |oid| {
                const obj = try Object(repo_kind, .full).init(self.arena.allocator(), state, &oid);
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
                cursor: *rp.Repo(repo_kind).DB.Cursor(.read_only),
            },
        },

        pub const Reader = switch (repo_kind) {
            .git => pack.LooseOrPackObjectReader,
            .xit => chunk.ChunkObjectReader,
        };

        pub fn init(allocator: std.mem.Allocator, state: rp.Repo(repo_kind).State(.read_only), oid: *const [hash.SHA1_HEX_LEN]u8) !@This() {
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
                    const chunk_hashes_cursor = (try state.extra.moment.cursor.readPath(void, &.{
                        .{ .hash_map_get = .{ .value = hash.hashBuffer("object-id->chunk-hashes") } },
                        .{ .hash_map_get = .{ .value = try hash.hexToHash(oid) } },
                    })) orelse return error.ObjectNotFound;

                    const header_cursor = (try state.extra.moment.cursor.readPath(void, &.{
                        .{ .hash_map_get = .{ .value = hash.hashBuffer("object-id->header") } },
                        .{ .hash_map_get = .{ .value = try hash.hexToHash(oid) } },
                    })) orelse return error.ObjectNotFound;

                    var header_buffer = [_]u8{0} ** 32;
                    const header_slice = try header_cursor.readBytes(&header_buffer);
                    var stream = std.io.fixedBufferStream(header_slice);
                    const header = try readObjectHeader(stream.reader());

                    // put cursor on the heap so the pointer is stable (the reader uses it internally)
                    const chunk_hashes_ptr = try allocator.create(rp.Repo(repo_kind).DB.Cursor(.read_only));
                    errdefer allocator.destroy(chunk_hashes_ptr);
                    chunk_hashes_ptr.* = chunk_hashes_cursor;

                    return .{
                        .allocator = allocator,
                        .header = header,
                        .reader = std.io.bufferedReaderSize(BUFFER_SIZE, Reader{
                            .xit_dir = state.core.xit_dir,
                            .chunk_hashes_reader = try chunk_hashes_ptr.reader(),
                            .position = 0,
                        }),
                        .internal = .{
                            .cursor = chunk_hashes_ptr,
                        },
                    };
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
            try self.reader.unbuffered_reader.reset();
            self.reader = std.io.bufferedReaderSize(BUFFER_SIZE, self.reader.unbuffered_reader);
        }

        pub fn seekTo(self: *ObjectReader(repo_kind), position: u64) !void {
            switch (repo_kind) {
                .git => try self.reader.unbuffered_reader.skipBytes(position), // assumes that reset() has just been called!
                .xit => try self.reader.unbuffered_reader.seekTo(position),
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

pub fn writeObjectHeader(header: ObjectHeader, buffer: []u8) ![]const u8 {
    const type_name = switch (header.kind) {
        .blob => "blob",
        .tree => "tree",
        .commit => "commit",
    };
    const file_size = header.size;
    return try std.fmt.bufPrint(buffer, "{s} {}\x00", .{ type_name, file_size });
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

        pub fn init(allocator: std.mem.Allocator, state: rp.Repo(repo_kind).State(.read_only), oid: *const [hash.SHA1_HEX_LEN]u8) !Object(repo_kind, load_kind) {
            var obj_rdr = try ObjectReader(repo_kind).init(allocator, state, oid);
            errdefer obj_rdr.deinit();
            const reader = obj_rdr.reader.reader();

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
                    .oid = oid.*,
                    .len = obj_rdr.header.size,
                    .object_reader = obj_rdr,
                },
                .tree => {
                    switch (load_kind) {
                        .raw => return .{
                            .allocator = allocator,
                            .arena = arena,
                            .content = .tree,
                            .oid = oid.*,
                            .len = obj_rdr.header.size,
                            .object_reader = obj_rdr,
                        },
                        .full => {
                            var entries = std.StringArrayHashMap(TreeEntry).init(arena.allocator());

                            while (true) {
                                const entry_mode_str = reader.readUntilDelimiterAlloc(arena.allocator(), ' ', MAX_READ_BYTES) catch |err| switch (err) {
                                    error.EndOfStream => break,
                                    else => return err,
                                };
                                const entry_mode: io.Mode = @bitCast(try std.fmt.parseInt(u32, entry_mode_str, 8));
                                const entry_name = try reader.readUntilDelimiterAlloc(arena.allocator(), 0, MAX_READ_BYTES);
                                var entry_oid = [_]u8{0} ** hash.SHA1_BYTES_LEN;
                                try reader.readNoEof(&entry_oid);
                                try entries.put(entry_name, .{ .oid = entry_oid, .mode = entry_mode });
                            }

                            return .{
                                .allocator = allocator,
                                .arena = arena,
                                .content = ObjectContent{ .tree = .{ .entries = entries } },
                                .oid = oid.*,
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
                            .oid = oid.*,
                            .len = obj_rdr.header.size,
                            .object_reader = obj_rdr,
                        },
                        .full => {
                            // read the content kind
                            const content_kind = try reader.readUntilDelimiterAlloc(allocator, ' ', MAX_READ_BYTES);
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
                                const line = try reader.readUntilDelimiterAlloc(arena.allocator(), '\n', MAX_READ_BYTES);
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
                            content.commit.metadata.message = try reader.readAllAlloc(arena.allocator(), MAX_READ_BYTES);

                            return .{
                                .allocator = allocator,
                                .arena = arena,
                                .content = content,
                                .oid = oid.*,
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
        moment: rp.Repo(repo_kind).Moment(.read_only),
        oid_queue: std.DoublyLinkedList([hash.SHA1_HEX_LEN]u8),
        oid_excludes: std.AutoHashMap([hash.SHA1_HEX_LEN]u8, void),
        object: Object(repo_kind, load_kind),
        options: Options,

        pub const Options = struct {
            recursive: bool,
        };

        pub fn init(
            allocator: std.mem.Allocator,
            state: rp.Repo(repo_kind).State(.read_only),
            start_oids: []const [hash.SHA1_HEX_LEN]u8,
            options: Options,
        ) !ObjectIterator(repo_kind, load_kind) {
            var self = ObjectIterator(repo_kind, load_kind){
                .allocator = allocator,
                .core = state.core,
                .moment = state.extra.moment.*,
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
            const state = rp.Repo(repo_kind).State(.read_only){ .core = self.core, .extra = .{ .moment = &self.moment } };
            while (self.oid_queue.popFirst()) |node| {
                const next_oid = node.data;
                self.allocator.destroy(node);
                if (!self.oid_excludes.contains(next_oid)) {
                    try self.oid_excludes.put(next_oid, {});
                    switch (load_kind) {
                        .raw => {
                            var object = try Object(repo_kind, .full).init(self.allocator, state, &next_oid);
                            defer object.deinit();
                            try self.addToQueue(object.content);

                            var raw_object = try Object(repo_kind, .raw).init(self.allocator, state, &next_oid);
                            errdefer raw_object.deinit();
                            self.object = raw_object;
                            return &self.object;
                        },
                        .full => {
                            var object = try Object(repo_kind, .full).init(self.allocator, state, &next_oid);
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

        pub fn exclude(self: *ObjectIterator(repo_kind, load_kind), oid: *const [hash.SHA1_HEX_LEN]u8) !void {
            try self.oid_excludes.put(oid.*, {});

            const state = rp.Repo(repo_kind).State(.read_only){ .core = self.core, .extra = .{ .moment = &self.moment } };
            var object = try Object(repo_kind, .full).init(self.allocator, state, oid);
            defer object.deinit();
            switch (object.content) {
                .blob => {},
                .tree => |tree| {
                    if (self.options.recursive) {
                        for (tree.entries.values()) |entry| {
                            try self.exclude(&std.fmt.bytesToHex(entry.oid, .lower));
                        }
                    }
                },
                .commit => |commit| {
                    for (commit.parents.items) |parent_oid| {
                        try self.oid_excludes.put(parent_oid, {});
                    }
                    if (self.options.recursive) {
                        try self.exclude(&commit.tree);
                    }
                },
            }
        }
    };
}
