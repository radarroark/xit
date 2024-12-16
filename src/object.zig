//! an object is a file or dir stored in the repo.
//! at least, that's how i think of it. it's a
//! pretty generic name. may as well call it thing.

const std = @import("std");
const hash = @import("./hash.zig");
const compress = @import("./compress.zig");
const idx = @import("./index.zig");
const ref = @import("./ref.zig");
const io = @import("./io.zig");
const rp = @import("./repo.zig");
const pack = @import("./pack.zig");
const chunk = @import("./chunk.zig");

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
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    file: anytype,
    header: ObjectHeader,
    hash_bytes_buffer: *[hash.byteLen(repo_opts.hash)]u8,
) !void {
    // serialize object header
    var header_bytes = [_]u8{0} ** 32;
    const header_str = try writeObjectHeader(header, &header_bytes);

    // calc the hash of its contents
    const reader = file.reader();
    try hash.hashReader(repo_opts.hash, reader, header_str, hash_bytes_buffer);
    const hash_hex = std.fmt.bytesToHex(hash_bytes_buffer, .lower);

    // reset seek pos so we can reuse the reader for copying
    try file.seekTo(0);

    switch (repo_kind) {
        .git => {
            var objects_dir = try state.core.git_dir.openDir("objects", .{});
            defer objects_dir.close();

            // make the two char dir
            var hash_prefix_dir = try objects_dir.makeOpenPath(hash_hex[0..2], .{});
            defer hash_prefix_dir.close();
            const hash_suffix = hash_hex[2..];

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
            var lock = try io.LockFile.init(hash_prefix_dir, hash_suffix ++ ".uncompressed");
            defer lock.deinit();
            try lock.lock_file.writeAll(header_str);

            // copy file into temp file
            var read_buffer = [_]u8{0} ** repo_opts.read_size;
            while (true) {
                const size = try reader.read(&read_buffer);
                if (size == 0) {
                    break;
                }
                try lock.lock_file.writeAll(read_buffer[0..size]);
            }

            // create compressed lock file
            var compressed_lock = try io.LockFile.init(hash_prefix_dir, hash_suffix);
            defer compressed_lock.deinit();
            try compress.compress(repo_opts.read_size, lock.lock_file, compressed_lock.lock_file);
            compressed_lock.success = true;
        },
        .xit => {
            const file_hash = hash.bytesToInt(repo_opts.hash, hash_bytes_buffer);
            try chunk.writeChunks(repo_opts, state, file, file_hash, header_str);
        },
    }
}

fn writeTree(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    allocator: std.mem.Allocator,
    tree: *Tree,
    hash_bytes_buffer: *[hash.byteLen(repo_opts.hash)]u8,
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

    // calc the hash of its contents
    try hash.hashBuffer(repo_opts.hash, tree_bytes, hash_bytes_buffer);
    const tree_hash_hex = std.fmt.bytesToHex(hash_bytes_buffer, .lower);

    switch (repo_kind) {
        .git => {
            var objects_dir = try state.core.git_dir.openDir("objects", .{});
            defer objects_dir.close();

            // make the two char dir
            var tree_hash_prefix_dir = try objects_dir.makeOpenPath(tree_hash_hex[0..2], .{});
            defer tree_hash_prefix_dir.close();
            const tree_hash_suffix = tree_hash_hex[2..];

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
            var lock = try io.LockFile.init(tree_hash_prefix_dir, tree_hash_suffix ++ ".uncompressed");
            defer lock.deinit();
            try lock.lock_file.writeAll(tree_bytes);

            // create compressed lock file
            var compressed_lock = try io.LockFile.init(tree_hash_prefix_dir, tree_hash_suffix);
            defer compressed_lock.deinit();
            try compress.compress(repo_opts.read_size, lock.lock_file, compressed_lock.lock_file);
            compressed_lock.success = true;
        },
        .xit => {
            const object_hash = hash.bytesToInt(repo_opts.hash, hash_bytes_buffer);
            var stream = std.io.fixedBufferStream(tree_contents);
            try chunk.writeChunks(repo_opts, state, &stream, object_hash, header);
        },
    }
}

// add each entry to the given tree.
// if the entry is itself a tree, create a tree object
// for it and add that as an entry to the original tree.
fn addIndexEntries(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    allocator: std.mem.Allocator,
    tree: *Tree,
    index: idx.Index(repo_kind, repo_opts),
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
                repo_opts,
                state,
                allocator,
                &subtree,
                index,
                path,
                child_names.items,
            );

            var tree_hash_bytes_buffer = [_]u8{0} ** hash.byteLen(repo_opts.hash);
            try writeTree(repo_kind, repo_opts, state, allocator, &subtree, &tree_hash_bytes_buffer);

            try tree.addTreeEntry(name, &tree_hash_bytes_buffer);
        } else {
            return error.ObjectEntryNotFound;
        }
    }
}

pub fn CommitMetadata(comptime hash_kind: hash.HashKind) type {
    return struct {
        author: ?[]const u8 = null,
        committer: ?[]const u8 = null,
        message: []const u8 = "",
        parent_oids: ?[]const [hash.hexLen(hash_kind)]u8 = null,
        allow_empty: bool = false,
    };
}

fn createCommitContents(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    allocator: std.mem.Allocator,
    tree_hash_hex: *const [hash.hexLen(repo_opts.hash)]u8,
    metadata: CommitMetadata(repo_opts.hash),
    parent_oids: []const [hash.hexLen(repo_opts.hash)]u8,
) ![]const u8 {
    var metadata_lines = std.ArrayList([]const u8).init(allocator);
    defer {
        for (metadata_lines.items) |line| {
            allocator.free(line);
        }
        metadata_lines.deinit();
    }

    try metadata_lines.append(try std.fmt.allocPrint(allocator, "tree {s}", .{tree_hash_hex.*}));

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
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    allocator: std.mem.Allocator,
    metadata: CommitMetadata(repo_opts.hash),
) ![hash.hexLen(repo_opts.hash)]u8 {
    var commit_hash_bytes_buffer = [_]u8{0} ** hash.byteLen(repo_opts.hash);
    const parent_oids = if (metadata.parent_oids) |oids| oids else blk: {
        const head_oid_maybe = try ref.readHeadMaybe(repo_kind, repo_opts, state.readOnly());
        break :blk if (head_oid_maybe) |head_oid| &.{head_oid} else &.{};
    };

    // read index
    var index = try idx.Index(repo_kind, repo_opts).init(allocator, state.readOnly());
    defer index.deinit();

    // create tree and add index entries
    var tree = Tree.init(allocator);
    defer tree.deinit();
    try addIndexEntries(repo_kind, repo_opts, state, allocator, &tree, index, "", index.root_children.keys());

    // write and hash tree
    var tree_hash_bytes_buffer = [_]u8{0} ** hash.byteLen(repo_opts.hash);
    try writeTree(repo_kind, repo_opts, state, allocator, &tree, &tree_hash_bytes_buffer);
    const tree_hash_hex = std.fmt.bytesToHex(tree_hash_bytes_buffer, .lower);

    // don't allow commit if the tree hasn't changed
    if (!metadata.allow_empty) {
        if (parent_oids.len == 0) {
            if (tree.entries.count() == 0) {
                return error.EmptyCommit;
            }
        } else if (parent_oids.len == 1) {
            var first_parent = try Object(repo_kind, repo_opts, .full).init(allocator, state.readOnly(), &parent_oids[0]);
            defer first_parent.deinit();
            if (std.mem.eql(u8, &first_parent.content.commit.tree, &tree_hash_hex)) {
                return error.EmptyCommit;
            }
        }
    }

    // create commit contents
    const commit_contents = try createCommitContents(repo_kind, repo_opts, allocator, &tree_hash_hex, metadata, parent_oids);
    defer allocator.free(commit_contents);

    // create commit header
    var header_buffer = [_]u8{0} ** 32;
    const header = try std.fmt.bufPrint(&header_buffer, "commit {}\x00", .{commit_contents.len});

    // create commit
    const commit = try std.fmt.allocPrint(allocator, "{s}{s}", .{ header, commit_contents });
    defer allocator.free(commit);

    // calc the hash of its contents
    try hash.hashBuffer(repo_opts.hash, commit, &commit_hash_bytes_buffer);
    const commit_hash_hex = std.fmt.bytesToHex(commit_hash_bytes_buffer, .lower);
    const commit_hash = hash.bytesToInt(repo_opts.hash, &commit_hash_bytes_buffer);

    switch (repo_kind) {
        .git => {
            // open the objects dir
            var objects_dir = try state.core.git_dir.openDir("objects", .{});
            defer objects_dir.close();

            // make the two char dir
            var commit_hash_prefix_dir = try objects_dir.makeOpenPath(commit_hash_hex[0..2], .{});
            defer commit_hash_prefix_dir.close();
            const commit_hash_suffix = commit_hash_hex[2..];

            // create lock file
            var lock = try io.LockFile.init(commit_hash_prefix_dir, commit_hash_suffix ++ ".uncompressed");
            defer lock.deinit();
            try lock.lock_file.writeAll(commit);

            // create compressed lock file
            var compressed_lock = try io.LockFile.init(commit_hash_prefix_dir, commit_hash_suffix);
            defer compressed_lock.deinit();
            try compress.compress(repo_opts.read_size, lock.lock_file, compressed_lock.lock_file);
            compressed_lock.success = true;

            // write commit id to HEAD
            try ref.writeRecur(repo_kind, repo_opts, state, "HEAD", &commit_hash_hex);
        },
        .xit => {
            var stream = std.io.fixedBufferStream(commit_contents);
            try chunk.writeChunks(repo_opts, state, &stream, commit_hash, header);

            // write commit id to HEAD
            try ref.writeRecur(repo_kind, repo_opts, state, "HEAD", &commit_hash_hex);
        },
    }

    return std.fmt.bytesToHex(commit_hash_bytes_buffer, .lower);
}

pub fn Change(comptime hash_kind: hash.HashKind) type {
    return struct {
        old: ?TreeEntry(hash_kind),
        new: ?TreeEntry(hash_kind),
    };
}

pub fn TreeDiff(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        changes: std.StringArrayHashMap(Change(repo_opts.hash)),
        arena: std.heap.ArenaAllocator,

        pub fn init(allocator: std.mem.Allocator) TreeDiff(repo_kind, repo_opts) {
            return .{
                .changes = std.StringArrayHashMap(Change(repo_opts.hash)).init(allocator),
                .arena = std.heap.ArenaAllocator.init(allocator),
            };
        }

        pub fn deinit(self: *TreeDiff(repo_kind, repo_opts)) void {
            self.changes.deinit();
            self.arena.deinit();
        }

        pub fn compare(
            self: *TreeDiff(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            old_oid_maybe: ?[hash.hexLen(repo_opts.hash)]u8,
            new_oid_maybe: ?[hash.hexLen(repo_opts.hash)]u8,
            path_list_maybe: ?std.ArrayList([]const u8),
        ) !void {
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
                            const old_value_tree = old_value.isTree();
                            const new_value_tree = new_value.isTree();
                            try self.compare(state, if (old_value_tree) std.fmt.bytesToHex(&old_value.oid, .lower) else null, if (new_value_tree) std.fmt.bytesToHex(&new_value.oid, .lower) else null, path_list);
                            if (!old_value_tree or !new_value_tree) {
                                try self.changes.put(path, Change(repo_opts.hash){ .old = if (old_value_tree) null else old_value, .new = if (new_value_tree) null else new_value });
                            }
                        }
                    } else {
                        if (old_value.isTree()) {
                            try self.compare(state, std.fmt.bytesToHex(&old_value.oid, .lower), null, path_list);
                        } else {
                            try self.changes.put(path, Change(repo_opts.hash){ .old = old_value, .new = null });
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
                    } else if (new_value.isTree()) {
                        try self.compare(state, null, std.fmt.bytesToHex(&new_value.oid, .lower), path_list);
                    } else {
                        try self.changes.put(path, Change(repo_opts.hash){ .old = null, .new = new_value });
                    }
                }
            }
        }

        fn loadTree(
            self: *TreeDiff(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            oid_maybe: ?[hash.hexLen(repo_opts.hash)]u8,
        ) !std.StringArrayHashMap(TreeEntry(repo_opts.hash)) {
            if (oid_maybe) |oid| {
                const obj = try Object(repo_kind, repo_opts, .full).init(self.arena.allocator(), state, &oid);
                return switch (obj.content) {
                    .blob => std.StringArrayHashMap(TreeEntry(repo_opts.hash)).init(self.arena.allocator()),
                    .tree => |tree| tree.entries,
                    .commit => |commit| self.loadTree(state, commit.tree),
                };
            } else {
                return std.StringArrayHashMap(TreeEntry(repo_opts.hash)).init(self.arena.allocator());
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

pub fn TreeEntry(comptime hash_kind: hash.HashKind) type {
    return struct {
        oid: [hash.byteLen(hash_kind)]u8,
        mode: io.Mode,

        pub fn eql(self: TreeEntry(hash_kind), other: TreeEntry(hash_kind)) bool {
            return std.mem.eql(u8, &self.oid, &other.oid) and self.mode.eql(other.mode);
        }

        pub fn isTree(self: TreeEntry(hash_kind)) bool {
            return self.mode.object_type == .tree;
        }
    };
}

pub fn ObjectReader(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    const BUFFER_SIZE = 2048;
    return struct {
        allocator: std.mem.Allocator,
        header: ObjectHeader,
        reader: std.io.BufferedReader(BUFFER_SIZE, Reader),
        internal: switch (repo_kind) {
            .git => void,
            .xit => struct {
                cursor: *rp.Repo(repo_kind, repo_opts).DB.Cursor(.read_only),
            },
        },

        pub const Reader = switch (repo_kind) {
            .git => pack.LooseOrPackObjectReader,
            .xit => chunk.ChunkObjectReader(repo_opts),
        };

        pub fn init(allocator: std.mem.Allocator, state: rp.Repo(repo_kind, repo_opts).State(.read_only), oid: *const [hash.hexLen(repo_opts.hash)]u8) !@This() {
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
                    const chunk_info_cursor = (try state.extra.moment.cursor.readPath(void, &.{
                        .{ .hash_map_get = .{ .value = hash.hashInt(repo_opts.hash, "object-id->chunk-info") } },
                        .{ .hash_map_get = .{ .value = try hash.hexToInt(repo_opts.hash, oid) } },
                    })) orelse return error.ObjectNotFound;

                    const header_cursor = (try state.extra.moment.cursor.readPath(void, &.{
                        .{ .hash_map_get = .{ .value = hash.hashInt(repo_opts.hash, "object-id->header") } },
                        .{ .hash_map_get = .{ .value = try hash.hexToInt(repo_opts.hash, oid) } },
                    })) orelse return error.ObjectNotFound;

                    var header_buffer = [_]u8{0} ** 32;
                    const header_slice = try header_cursor.readBytes(&header_buffer);
                    var stream = std.io.fixedBufferStream(header_slice);
                    const header = try readObjectHeader(stream.reader());

                    // put cursor on the heap so the pointer is stable (the reader uses it internally)
                    const chunk_info_ptr = try allocator.create(rp.Repo(repo_kind, repo_opts).DB.Cursor(.read_only));
                    errdefer allocator.destroy(chunk_info_ptr);
                    chunk_info_ptr.* = chunk_info_cursor;

                    return .{
                        .allocator = allocator,
                        .header = header,
                        .reader = std.io.bufferedReaderSize(BUFFER_SIZE, Reader{
                            .xit_dir = state.core.xit_dir,
                            .chunk_info_reader = try chunk_info_ptr.reader(),
                            .position = 0,
                        }),
                        .internal = .{
                            .cursor = chunk_info_ptr,
                        },
                    };
                },
            }
        }

        pub fn deinit(self: *ObjectReader(repo_kind, repo_opts)) void {
            switch (repo_kind) {
                .git => self.reader.unbuffered_reader.deinit(),
                .xit => self.allocator.destroy(self.internal.cursor),
            }
        }

        pub fn reset(self: *ObjectReader(repo_kind, repo_opts)) !void {
            try self.reader.unbuffered_reader.reset();
            self.reader = std.io.bufferedReaderSize(BUFFER_SIZE, self.reader.unbuffered_reader);
        }

        pub fn seekTo(self: *ObjectReader(repo_kind, repo_opts), position: u64) !void {
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

pub fn ObjectContent(comptime hash_kind: hash.HashKind) type {
    return union(ObjectKind) {
        blob,
        tree: struct {
            entries: std.StringArrayHashMap(TreeEntry(hash_kind)),
        },
        commit: struct {
            tree: [hash.hexLen(hash_kind)]u8,
            parents: std.ArrayList([hash.hexLen(hash_kind)]u8),
            metadata: CommitMetadata(hash_kind),
        },
    };
}

pub const ObjectLoadKind = enum {
    // only load the header to determine the object kind,
    // but not any of the remaining content
    raw,
    // read the entire content of the object
    full,
};

pub fn Object(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind), comptime load_kind: ObjectLoadKind) type {
    return struct {
        allocator: std.mem.Allocator,
        arena: *std.heap.ArenaAllocator,
        content: switch (load_kind) {
            .raw => ObjectKind,
            .full => ObjectContent(repo_opts.hash),
        },
        oid: [hash.hexLen(repo_opts.hash)]u8,
        len: u64,
        object_reader: ObjectReader(repo_kind, repo_opts),

        pub fn init(
            allocator: std.mem.Allocator,
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            oid: *const [hash.hexLen(repo_opts.hash)]u8,
        ) !Object(repo_kind, repo_opts, load_kind) {
            var obj_rdr = try ObjectReader(repo_kind, repo_opts).init(allocator, state, oid);
            errdefer obj_rdr.deinit();

            // to turn off the buffered reader, just replace the
            // following line with:
            //var reader = obj_rdr.reader.unbuffered_reader;
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
                            var entries = std.StringArrayHashMap(TreeEntry(repo_opts.hash)).init(arena.allocator());

                            while (true) {
                                const entry_mode_str = reader.readUntilDelimiterAlloc(arena.allocator(), ' ', repo_opts.max_read_size) catch |err| switch (err) {
                                    error.EndOfStream => break,
                                    else => |e| return e,
                                };
                                const entry_mode: io.Mode = @bitCast(try std.fmt.parseInt(u32, entry_mode_str, 8));
                                const entry_name = try reader.readUntilDelimiterAlloc(arena.allocator(), 0, repo_opts.max_read_size);
                                var entry_oid = [_]u8{0} ** hash.byteLen(repo_opts.hash);
                                try reader.readNoEof(&entry_oid);
                                try entries.put(entry_name, .{ .oid = entry_oid, .mode = entry_mode });
                            }

                            return .{
                                .allocator = allocator,
                                .arena = arena,
                                .content = ObjectContent(repo_opts.hash){ .tree = .{ .entries = entries } },
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
                            const content_kind = try reader.readUntilDelimiterAlloc(allocator, ' ', repo_opts.max_read_size);
                            defer allocator.free(content_kind);
                            if (!std.mem.eql(u8, "tree", content_kind)) {
                                return error.InvalidCommitContentKind;
                            }

                            // read the tree hash
                            var tree_hash = [_]u8{0} ** (hash.hexLen(repo_opts.hash) + 1);
                            const tree_hash_slice = try reader.readUntilDelimiter(&tree_hash, '\n');
                            if (tree_hash_slice.len != hash.hexLen(repo_opts.hash)) {
                                return error.InvalidCommitTreeHash;
                            }

                            // init the content
                            var content = ObjectContent(repo_opts.hash){
                                .commit = .{
                                    .tree = tree_hash_slice[0..comptime hash.hexLen(repo_opts.hash)].*,
                                    .parents = std.ArrayList([hash.hexLen(repo_opts.hash)]u8).init(arena.allocator()),
                                    .metadata = .{},
                                },
                            };

                            // read the metadata
                            while (true) {
                                const line = try reader.readUntilDelimiterAlloc(arena.allocator(), '\n', repo_opts.max_read_size);
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
                                        if (value.len != hash.hexLen(repo_opts.hash)) {
                                            return error.InvalidCommitParentHash;
                                        }
                                        try content.commit.parents.append(value[0..comptime hash.hexLen(repo_opts.hash)].*);
                                    } else if (std.mem.eql(u8, "author", key)) {
                                        content.commit.metadata.author = value;
                                    } else if (std.mem.eql(u8, "committer", key)) {
                                        content.commit.metadata.committer = value;
                                    }
                                }
                            }

                            // read the message
                            content.commit.metadata.message = try reader.readAllAlloc(arena.allocator(), repo_opts.max_read_size);

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

        pub fn deinit(self: *Object(repo_kind, repo_opts, load_kind)) void {
            self.arena.deinit();
            self.allocator.destroy(self.arena);
            self.object_reader.deinit();
        }
    };
}

pub fn ObjectIterator(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind), comptime load_kind: ObjectLoadKind) type {
    return struct {
        allocator: std.mem.Allocator,
        core: *rp.Repo(repo_kind, repo_opts).Core,
        moment: rp.Repo(repo_kind, repo_opts).Moment(.read_only),
        oid_queue: std.DoublyLinkedList([hash.hexLen(repo_opts.hash)]u8),
        oid_excludes: std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void),
        object: Object(repo_kind, repo_opts, load_kind),
        options: Options,

        pub const Options = struct {
            recursive: bool,
        };

        pub fn init(
            allocator: std.mem.Allocator,
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            start_oids: []const [hash.hexLen(repo_opts.hash)]u8,
            options: Options,
        ) !ObjectIterator(repo_kind, repo_opts, load_kind) {
            var self = ObjectIterator(repo_kind, repo_opts, load_kind){
                .allocator = allocator,
                .core = state.core,
                .moment = state.extra.moment.*,
                .oid_queue = std.DoublyLinkedList([hash.hexLen(repo_opts.hash)]u8){},
                .oid_excludes = std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void).init(allocator),
                .object = undefined,
                .options = options,
            };
            errdefer self.deinit();

            for (start_oids) |start_oid| {
                var node = try allocator.create(std.DoublyLinkedList([hash.hexLen(repo_opts.hash)]u8).Node);
                errdefer allocator.destroy(node);
                node.data = start_oid;
                self.oid_queue.append(node);
            }

            return self;
        }

        pub fn deinit(self: *ObjectIterator(repo_kind, repo_opts, load_kind)) void {
            while (self.oid_queue.popFirst()) |node| {
                self.allocator.destroy(node);
            }
            self.oid_excludes.deinit();
        }

        pub fn next(self: *ObjectIterator(repo_kind, repo_opts, load_kind)) !?*Object(repo_kind, repo_opts, load_kind) {
            const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = self.core, .extra = .{ .moment = &self.moment } };
            while (self.oid_queue.popFirst()) |node| {
                const next_oid = node.data;
                self.allocator.destroy(node);
                if (!self.oid_excludes.contains(next_oid)) {
                    try self.oid_excludes.put(next_oid, {});
                    switch (load_kind) {
                        .raw => {
                            var object = try Object(repo_kind, repo_opts, .full).init(self.allocator, state, &next_oid);
                            defer object.deinit();
                            try self.addToQueue(object.content);

                            var raw_object = try Object(repo_kind, repo_opts, .raw).init(self.allocator, state, &next_oid);
                            errdefer raw_object.deinit();
                            self.object = raw_object;
                            return &self.object;
                        },
                        .full => {
                            var object = try Object(repo_kind, repo_opts, .full).init(self.allocator, state, &next_oid);
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

        fn addToQueue(self: *ObjectIterator(repo_kind, repo_opts, load_kind), content: ObjectContent(repo_opts.hash)) !void {
            switch (content) {
                .blob => {},
                .tree => |tree| {
                    if (self.options.recursive) {
                        for (tree.entries.values()) |entry| {
                            const entry_oid = std.fmt.bytesToHex(entry.oid, .lower);
                            if (!self.oid_excludes.contains(entry_oid)) {
                                var new_node = try self.allocator.create(std.DoublyLinkedList([hash.hexLen(repo_opts.hash)]u8).Node);
                                errdefer self.allocator.destroy(new_node);
                                new_node.data = entry_oid;
                                self.oid_queue.append(new_node);
                            }
                        }
                    }
                },
                .commit => |commit| {
                    for (commit.parents.items) |parent_oid| {
                        var new_node = try self.allocator.create(std.DoublyLinkedList([hash.hexLen(repo_opts.hash)]u8).Node);
                        errdefer self.allocator.destroy(new_node);
                        new_node.data = parent_oid;
                        self.oid_queue.append(new_node);
                    }
                    if (self.options.recursive) {
                        if (!self.oid_excludes.contains(commit.tree)) {
                            var new_node = try self.allocator.create(std.DoublyLinkedList([hash.hexLen(repo_opts.hash)]u8).Node);
                            errdefer self.allocator.destroy(new_node);
                            new_node.data = commit.tree;
                            self.oid_queue.append(new_node);
                        }
                    }
                },
            }
        }

        pub fn exclude(self: *ObjectIterator(repo_kind, repo_opts, load_kind), oid: *const [hash.hexLen(repo_opts.hash)]u8) !void {
            try self.oid_excludes.put(oid.*, {});

            const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = self.core, .extra = .{ .moment = &self.moment } };
            var object = try Object(repo_kind, repo_opts, .full).init(self.allocator, state, oid);
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
