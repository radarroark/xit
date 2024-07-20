//! an object is a file or dir stored in the repo.
//! at least, that's how i think of it. no packed
//! objects for now, but that'll come eventually.

const std = @import("std");
const xitdb = @import("xitdb");
const builtin = @import("builtin");
const hash = @import("./hash.zig");
const compress = @import("./compress.zig");
const cmd = @import("./command.zig");
const idx = @import("./index.zig");
const ref = @import("./ref.zig");
const io = @import("./io.zig");
const rp = @import("./repo.zig");

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
    core_cursor: rp.Repo(repo_kind).CoreCursor,
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
            var objects_dir = try core_cursor.core.git_dir.openDir("objects", .{});
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
                core_cursor: rp.Repo(repo_kind).CoreCursor,
                reader: *const FileReaderType,
                sha1_hex: [hash.SHA1_HEX_LEN]u8,
                header: []const u8,

                pub fn run(ctx_self: @This(), cursor: *xitdb.Database(.file).Cursor) !void {
                    if (cursor.pointer() == null) {
                        var writer = try cursor.writer(void, &[_]xitdb.PathPart(void){});
                        try writer.writeAll(ctx_self.header);
                        // TODO: use buffered io
                        var read_buffer = [_]u8{0} ** MAX_READ_BYTES;
                        while (true) {
                            const size = try ctx_self.reader.read(&read_buffer);
                            if (size == 0) {
                                break;
                            }
                            try writer.writeAll(read_buffer[0..size]);
                        }
                        try writer.finish();

                        _ = try ctx_self.core_cursor.cursor.execute(void, &[_]xitdb.PathPart(void){
                            .{ .hash_map_get = .{ .value = hash.hashBuffer("objects") } },
                            .hash_map_create,
                            .{ .hash_map_get = .{ .value = try hash.hexToHash(&ctx_self.sha1_hex) } },
                            .{ .write = .{ .slot = writer.slot } },
                        });
                    }
                }
            };
            _ = try core_cursor.cursor.execute(Ctx, &[_]xitdb.PathPart(Ctx){
                .{ .hash_map_get = .{ .value = hash.hashBuffer("file-values") } },
                .hash_map_create,
                .{ .hash_map_get = .{ .value = file_hash } },
                .{ .ctx = Ctx{ .core_cursor = core_cursor, .reader = &reader, .sha1_hex = sha1_hex, .header = header } },
            });
        },
    }
}

fn writeTree(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator, tree: *Tree, sha1_bytes_buffer: *[hash.SHA1_BYTES_LEN]u8) !void {
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
            var objects_dir = try core_cursor.core.git_dir.openDir("objects", .{});
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
                cursor: *xitdb.Database(.file).Cursor,
                tree_sha1_bytes: *const [hash.SHA1_BYTES_LEN]u8,
                tree_bytes: []const u8,

                pub fn run(ctx_self: @This(), cursor: *xitdb.Database(.file).Cursor) !void {
                    // exit early if there is nothing to commit
                    if (cursor.pointer() != null) {
                        return;
                    }
                    const tree_slot = try ctx_self.cursor.writeBytes(ctx_self.tree_bytes, .once, void, &[_]xitdb.PathPart(void){
                        .{ .hash_map_get = .{ .value = hash.hashBuffer("object-values") } },
                        .hash_map_create,
                        .{ .hash_map_get = .{ .value = hash.bytesToHash(ctx_self.tree_sha1_bytes) } },
                    });
                    _ = try cursor.execute(void, &[_]xitdb.PathPart(void){
                        .{ .write = .{ .slot = tree_slot } },
                    });
                }
            };
            _ = try core_cursor.cursor.execute(Ctx, &[_]xitdb.PathPart(Ctx){
                .{ .hash_map_get = .{ .value = hash.hashBuffer("objects") } },
                .hash_map_create,
                .{ .hash_map_get = .{ .value = hash.bytesToHash(sha1_bytes_buffer) } },
                .{ .ctx = Ctx{
                    .cursor = core_cursor.cursor,
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
    core_cursor: rp.Repo(repo_kind).CoreCursor,
    allocator: std.mem.Allocator,
    tree: *Tree,
    index: idx.Index(repo_kind),
    prefix: []const u8,
    entries: [][]const u8,
) !void {
    for (entries) |name| {
        const path = try io.joinPath(allocator, &[_][]const u8{ prefix, name });
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
                core_cursor,
                allocator,
                &subtree,
                index,
                path,
                child_names.items,
            );

            var tree_sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
            try writeTree(repo_kind, core_cursor, allocator, &subtree, &tree_sha1_bytes_buffer);

            try tree.addTreeEntry(name, &tree_sha1_bytes_buffer);
        } else {
            return error.ObjectEntryNotFound;
        }
    }
}

fn createCommitContents(allocator: std.mem.Allocator, tree_sha1_hex: [hash.SHA1_HEX_LEN]u8, parent_oids: []const [hash.SHA1_HEX_LEN]u8, message_maybe: ?[]const u8) ![]const u8 {
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

    const author = "radar <radar@foo.com> 1512325222 +0000";
    try metadata_lines.append(try std.fmt.allocPrint(allocator, "author {s}", .{author}));
    try metadata_lines.append(try std.fmt.allocPrint(allocator, "committer {s}", .{author}));

    try metadata_lines.append(try std.fmt.allocPrint(allocator, "\n{s}", .{message_maybe orelse ""}));

    return try std.mem.join(allocator, "\n", metadata_lines.items);
}

pub fn writeCommit(
    comptime repo_kind: rp.RepoKind,
    core_cursor: rp.Repo(repo_kind).CoreCursor,
    allocator: std.mem.Allocator,
    parent_oids_maybe: ?[]const [hash.SHA1_HEX_LEN]u8,
    message_maybe: ?[]const u8,
) ![hash.SHA1_HEX_LEN]u8 {
    var commit_sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
    const parent_oids = if (parent_oids_maybe) |oids| oids else blk: {
        const head_oid_maybe = try ref.readHeadMaybe(repo_kind, core_cursor);
        break :blk if (head_oid_maybe) |head_oid| &[_][hash.SHA1_HEX_LEN]u8{head_oid} else &[_][hash.SHA1_HEX_LEN]u8{};
    };

    // read index
    var index = try idx.Index(repo_kind).init(allocator, core_cursor);
    defer index.deinit();

    switch (repo_kind) {
        .git => {
            // open the objects dir
            var objects_dir = try core_cursor.core.git_dir.openDir("objects", .{});
            defer objects_dir.close();

            // create tree and add index entries
            var tree = Tree.init(allocator);
            defer tree.deinit();
            try addIndexEntries(repo_kind, core_cursor, allocator, &tree, index, "", index.root_children.keys());

            // write and hash tree
            var tree_sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
            try writeTree(repo_kind, core_cursor, allocator, &tree, &tree_sha1_bytes_buffer);
            const tree_sha1_hex = std.fmt.bytesToHex(tree_sha1_bytes_buffer, .lower);

            // create commit contents
            const commit_contents = try createCommitContents(allocator, tree_sha1_hex, parent_oids, message_maybe);
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
            try ref.updateRecur(repo_kind, core_cursor, allocator, &[_][]const u8{"HEAD"}, &commit_sha1_hex);
        },
        .xit => {
            // create tree and add index entries
            var tree = Tree.init(allocator);
            defer tree.deinit();
            try addIndexEntries(repo_kind, core_cursor, allocator, &tree, index, "", index.root_children.keys());

            // write and hash tree
            var tree_sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
            try writeTree(repo_kind, core_cursor, allocator, &tree, &tree_sha1_bytes_buffer);
            const tree_sha1_hex = std.fmt.bytesToHex(tree_sha1_bytes_buffer, .lower);

            // create commit contents
            const commit_contents = try createCommitContents(allocator, tree_sha1_hex, parent_oids, message_maybe);
            defer allocator.free(commit_contents);

            // create commit
            const commit = try std.fmt.allocPrint(allocator, "commit {}\x00{s}", .{ commit_contents.len, commit_contents });
            defer allocator.free(commit);

            // calc the sha1 of its contents
            try hash.sha1Buffer(commit, &commit_sha1_bytes_buffer);
            const commit_sha1_hex = std.fmt.bytesToHex(commit_sha1_bytes_buffer, .lower);

            // write commit content
            const content_slot = try core_cursor.cursor.writeBytes(commit, .once, void, &[_]xitdb.PathPart(void){
                .{ .hash_map_get = .{ .value = hash.hashBuffer("object-values") } },
                .hash_map_create,
                .{ .hash_map_get = .{ .value = hash.bytesToHash(&commit_sha1_bytes_buffer) } },
            });

            // write commit
            _ = try core_cursor.cursor.execute(void, &[_]xitdb.PathPart(void){
                .{ .hash_map_get = .{ .value = hash.hashBuffer("objects") } },
                .hash_map_create,
                .{ .hash_map_get = .{ .value = hash.bytesToHash(&commit_sha1_bytes_buffer) } },
                .{ .write = .{ .slot = content_slot } },
            });

            // write commit id to HEAD
            try ref.updateRecur(repo_kind, core_cursor, allocator, &[_][]const u8{"HEAD"}, &commit_sha1_hex);
        },
    }

    return std.fmt.bytesToHex(commit_sha1_bytes_buffer, .lower);
}

pub const ObjectKind = enum {
    blob,
    tree,
    commit,
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
    return struct {
        internal: switch (repo_kind) {
            .git => struct {
                file: std.fs.File,
                skip_header: bool,
                stream: compress.ZlibStream,
                rdr: Reader,
            },
            .xit => struct {
                header_offset: u64,
                rdr: Reader,
            },
        },

        pub const Reader = switch (repo_kind) {
            .git => compress.ZlibStream.Reader,
            .xit => xitdb.Database(.file).Cursor.Reader,
        };

        pub fn init(core_cursor: rp.Repo(repo_kind).CoreCursor, oid: [hash.SHA1_HEX_LEN]u8, skip_header: bool) !@This() {
            switch (repo_kind) {
                .git => {
                    // open the objects dir
                    var objects_dir = try core_cursor.core.git_dir.openDir("objects", .{});
                    defer objects_dir.close();

                    // open the object file
                    var commit_hash_prefix_dir = try objects_dir.openDir(oid[0..2], .{});
                    defer commit_hash_prefix_dir.close();
                    var commit_hash_suffix_file = try commit_hash_prefix_dir.openFile(oid[2..], .{ .mode = .read_only });
                    errdefer commit_hash_suffix_file.close();

                    return .{
                        .internal = .{
                            .file = commit_hash_suffix_file,
                            .skip_header = skip_header,
                            .stream = try compress.decompressStream(commit_hash_suffix_file, skip_header),
                            .rdr = undefined,
                        },
                    };
                },
                .xit => {
                    var reader_maybe = try core_cursor.cursor.reader(void, &[_]xitdb.PathPart(void){
                        .{ .hash_map_get = .{ .value = hash.hashBuffer("objects") } },
                        .{ .hash_map_get = .{ .value = try hash.hexToHash(&oid) } },
                    });
                    if (reader_maybe) |*rdr| {
                        var header_offset: u64 = 0;
                        if (skip_header) {
                            var read_buffer = [_]u8{0} ** 1;
                            while (true) {
                                const size = try rdr.read(&read_buffer);
                                header_offset += 1;
                                if (size == 0) {
                                    return error.ObjectInvalid;
                                } else if (read_buffer[0] == 0) {
                                    break;
                                }
                            }
                        }
                        return .{
                            .internal = .{
                                .header_offset = header_offset,
                                .rdr = rdr.*,
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
                .git => self.internal.file.close(),
                .xit => {},
            }
        }

        pub fn reset(self: *ObjectReader(repo_kind)) !void {
            switch (repo_kind) {
                .git => self.internal.stream = try compress.decompressStream(self.internal.file, self.internal.skip_header),
                .xit => try self.internal.rdr.seekTo(self.internal.header_offset),
            }
        }

        pub fn reader(self: *ObjectReader(repo_kind)) *Reader {
            switch (repo_kind) {
                .git => {
                    self.internal.rdr = self.internal.stream.reader();
                    return &self.internal.rdr;
                },
                .xit => return &self.internal.rdr,
            }
        }
    };
}

pub const ObjectContent = union(ObjectKind) {
    blob,
    tree: struct {
        entries: std.StringArrayHashMap(TreeEntry),
    },
    commit: struct {
        tree: [hash.SHA1_HEX_LEN]u8,
        parents: std.ArrayList([hash.SHA1_HEX_LEN]u8),
        author: ?[]const u8,
        committer: ?[]const u8,
        message: []const u8,
    },
};

pub fn Object(comptime repo_kind: rp.RepoKind) type {
    return struct {
        allocator: std.mem.Allocator,
        arena: std.heap.ArenaAllocator,
        content: ObjectContent,
        oid: [hash.SHA1_HEX_LEN]u8,
        len: u64,

        pub fn init(allocator: std.mem.Allocator, core_cursor: rp.Repo(repo_kind).CoreCursor, oid: [hash.SHA1_HEX_LEN]u8) !Object(repo_kind) {
            var object_reader = try ObjectReader(repo_kind).init(core_cursor, oid, false);
            defer object_reader.deinit();
            var reader = object_reader.reader();

            // read the object kind
            const object_kind = try reader.readUntilDelimiterAlloc(allocator, ' ', MAX_READ_BYTES);
            defer allocator.free(object_kind);

            // read the length
            const object_len_str = try reader.readUntilDelimiterAlloc(allocator, 0, MAX_READ_BYTES);
            defer allocator.free(object_len_str);
            const object_len = try std.fmt.parseInt(usize, object_len_str, 10);

            if (std.mem.eql(u8, "blob", object_kind)) {
                return Object(repo_kind){
                    .allocator = allocator,
                    .arena = std.heap.ArenaAllocator.init(allocator),
                    .content = ObjectContent{ .blob = {} },
                    .oid = oid,
                    .len = object_len,
                };
            } else if (std.mem.eql(u8, "tree", object_kind)) {
                var arena = std.heap.ArenaAllocator.init(allocator);
                errdefer arena.deinit();

                var entries = std.StringArrayHashMap(TreeEntry).init(arena.allocator());

                while (true) {
                    const entry_mode_str = reader.readUntilDelimiterAlloc(arena.allocator(), ' ', MAX_READ_BYTES) catch |err| {
                        switch (err) {
                            error.EndOfStream => break,
                            else => return err,
                        }
                    };
                    const entry_mode: io.Mode = @bitCast(try std.fmt.parseInt(u32, entry_mode_str, 8));
                    const entry_name = try reader.readUntilDelimiterAlloc(arena.allocator(), 0, MAX_READ_BYTES);
                    var entry_oid = [_]u8{0} ** hash.SHA1_BYTES_LEN;
                    try reader.readNoEof(&entry_oid);
                    try entries.put(entry_name, TreeEntry{ .oid = entry_oid, .mode = entry_mode });
                }

                return Object(repo_kind){
                    .allocator = allocator,
                    .arena = arena,
                    .content = ObjectContent{ .tree = .{ .entries = entries } },
                    .oid = oid,
                    .len = object_len,
                };
            } else if (std.mem.eql(u8, "commit", object_kind)) {
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
                var arena = std.heap.ArenaAllocator.init(allocator);
                errdefer arena.deinit();
                var content = ObjectContent{
                    .commit = .{
                        .tree = tree_hash_slice[0..hash.SHA1_HEX_LEN].*,
                        .parents = std.ArrayList([hash.SHA1_HEX_LEN]u8).init(arena.allocator()),
                        .author = null,
                        .committer = null,
                        .message = undefined,
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
                            content.commit.author = value;
                        } else if (std.mem.eql(u8, "committer", key)) {
                            content.commit.committer = value;
                        }
                    }
                }

                // read the message
                content.commit.message = try reader.readAllAlloc(arena.allocator(), MAX_READ_BYTES);

                return Object(repo_kind){
                    .allocator = allocator,
                    .arena = arena,
                    .content = content,
                    .oid = oid,
                    .len = object_len,
                };
            } else {
                return error.InvalidObjectKind;
            }
        }

        pub fn deinit(self: *Object(repo_kind)) void {
            self.arena.deinit();
        }
    };
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
            return TreeDiff(repo_kind){
                .changes = std.StringArrayHashMap(Change).init(allocator),
                .arena = std.heap.ArenaAllocator.init(allocator),
            };
        }

        pub fn deinit(self: *TreeDiff(repo_kind)) void {
            self.arena.deinit();
            self.changes.deinit();
        }

        pub fn compare(self: *TreeDiff(repo_kind), core_cursor: rp.Repo(repo_kind).CoreCursor, old_oid_maybe: ?[hash.SHA1_HEX_LEN]u8, new_oid_maybe: ?[hash.SHA1_HEX_LEN]u8, path_list_maybe: ?std.ArrayList([]const u8)) !void {
            if (old_oid_maybe == null and new_oid_maybe == null) {
                return;
            }
            const old_entries = try self.loadTree(core_cursor, old_oid_maybe);
            const new_entries = try self.loadTree(core_cursor, new_oid_maybe);
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
                            try self.compare(core_cursor, if (old_value_tree) std.fmt.bytesToHex(&old_value.oid, .lower) else null, if (new_value_tree) std.fmt.bytesToHex(&new_value.oid, .lower) else null, path_list);
                            if (!old_value_tree or !new_value_tree) {
                                try self.changes.put(path, Change{ .old = if (old_value_tree) null else old_value, .new = if (new_value_tree) null else new_value });
                            }
                        }
                    } else {
                        if (isTree(old_value)) {
                            try self.compare(core_cursor, std.fmt.bytesToHex(&old_value.oid, .lower), null, path_list);
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
                        try self.compare(core_cursor, null, std.fmt.bytesToHex(&new_value.oid, .lower), path_list);
                    } else {
                        try self.changes.put(path, Change{ .old = null, .new = new_value });
                    }
                }
            }
        }

        fn loadTree(self: *TreeDiff(repo_kind), core_cursor: rp.Repo(repo_kind).CoreCursor, oid_maybe: ?[hash.SHA1_HEX_LEN]u8) !std.StringArrayHashMap(TreeEntry) {
            if (oid_maybe) |oid| {
                const obj = try Object(repo_kind).init(self.arena.allocator(), core_cursor, oid);
                return switch (obj.content) {
                    .blob => std.StringArrayHashMap(TreeEntry).init(self.arena.allocator()),
                    .tree => obj.content.tree.entries,
                    .commit => self.loadTree(core_cursor, obj.content.commit.tree),
                };
            } else {
                return std.StringArrayHashMap(TreeEntry).init(self.arena.allocator());
            }
        }
    };
}

pub fn ObjectIterator(comptime repo_kind: rp.RepoKind) type {
    return struct {
        allocator: std.mem.Allocator,
        core: *rp.Repo(repo_kind).Core,
        oid_queue: std.DoublyLinkedList([hash.SHA1_HEX_LEN]u8),
        object: Object(repo_kind),

        pub fn init(allocator: std.mem.Allocator, core: *rp.Repo(repo_kind).Core, oid: [hash.SHA1_HEX_LEN]u8) !ObjectIterator(repo_kind) {
            var oid_queue = std.DoublyLinkedList([hash.SHA1_HEX_LEN]u8){};
            var node = try allocator.create(std.DoublyLinkedList([hash.SHA1_HEX_LEN]u8).Node);
            errdefer allocator.destroy(node);
            node.data = oid;
            oid_queue.append(node);
            return .{
                .allocator = allocator,
                .core = core,
                .oid_queue = oid_queue,
                .object = undefined,
            };
        }

        pub fn deinit(self: *ObjectIterator(repo_kind)) void {
            while (self.oid_queue.popFirst()) |node| {
                self.allocator.destroy(node);
            }
        }

        pub fn next(self: *ObjectIterator(repo_kind)) !?*Object(repo_kind) {
            // TODO: instead of latest cursor, store the tx id so we always use the
            // same transaction even if the db is written to while calling next
            var cursor = try self.core.latestCursor();
            const core_cursor = switch (repo_kind) {
                .git => .{ .core = self.core },
                .xit => .{ .core = self.core, .cursor = &cursor },
            };
            if (self.oid_queue.popFirst()) |node| {
                const next_oid = node.data;
                self.allocator.destroy(node);
                var commit_object = try Object(repo_kind).init(self.allocator, core_cursor, next_oid);
                errdefer commit_object.deinit();
                self.object = commit_object;
                for (commit_object.content.commit.parents.items) |parent_oid| {
                    var new_node = try self.allocator.create(std.DoublyLinkedList([hash.SHA1_HEX_LEN]u8).Node);
                    errdefer self.allocator.destroy(new_node);
                    new_node.data = parent_oid;
                    self.oid_queue.append(new_node);
                }
                return &self.object;
            } else {
                return null;
            }
        }
    };
}

fn getDescendent(comptime repo_kind: rp.RepoKind, allocator: std.mem.Allocator, core_cursor: rp.Repo(repo_kind).CoreCursor, oid1: *const [hash.SHA1_HEX_LEN]u8, oid2: *const [hash.SHA1_HEX_LEN]u8) ![hash.SHA1_HEX_LEN]u8 {
    if (std.mem.eql(u8, oid1, oid2)) {
        return oid1.*;
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const ParentKind = enum {
        one,
        two,
    };
    const Parent = struct {
        oid: [hash.SHA1_HEX_LEN]u8,
        kind: ParentKind,
    };
    var queue = std.DoublyLinkedList(Parent){};

    {
        const object = try Object(repo_kind).init(arena.allocator(), core_cursor, oid1.*);
        for (object.content.commit.parents.items) |parent_oid| {
            var node = try arena.allocator().create(std.DoublyLinkedList(Parent).Node);
            node.data = .{ .oid = parent_oid, .kind = .one };
            queue.append(node);
        }
    }

    {
        const object = try Object(repo_kind).init(arena.allocator(), core_cursor, oid2.*);
        for (object.content.commit.parents.items) |parent_oid| {
            var node = try arena.allocator().create(std.DoublyLinkedList(Parent).Node);
            node.data = .{ .oid = parent_oid, .kind = .two };
            queue.append(node);
        }
    }

    while (queue.popFirst()) |node| {
        switch (node.data.kind) {
            .one => {
                if (std.mem.eql(u8, oid2, &node.data.oid)) {
                    return oid1.*;
                } else if (std.mem.eql(u8, oid1, &node.data.oid)) {
                    continue; // this oid was already added to the queue
                }
            },
            .two => {
                if (std.mem.eql(u8, oid1, &node.data.oid)) {
                    return oid2.*;
                } else if (std.mem.eql(u8, oid2, &node.data.oid)) {
                    continue; // this oid was already added to the queue
                }
            },
        }

        // TODO: instead of appending to the end, append it in descending order of timestamp
        // so we prioritize more recent commits and avoid wasteful traversal deep in the history.
        const object = try Object(repo_kind).init(arena.allocator(), core_cursor, node.data.oid);
        for (object.content.commit.parents.items) |parent_oid| {
            var new_node = try arena.allocator().create(std.DoublyLinkedList(Parent).Node);
            new_node.data = .{ .oid = parent_oid, .kind = node.data.kind };
            queue.append(new_node);
        }
    }

    return error.DescendentNotFound;
}

pub fn commonAncestor(comptime repo_kind: rp.RepoKind, allocator: std.mem.Allocator, core_cursor: rp.Repo(repo_kind).CoreCursor, oid1: *const [hash.SHA1_HEX_LEN]u8, oid2: *const [hash.SHA1_HEX_LEN]u8) ![hash.SHA1_HEX_LEN]u8 {
    if (std.mem.eql(u8, oid1, oid2)) {
        return oid1.*;
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const Parent = struct {
        oid: [hash.SHA1_HEX_LEN]u8,
        kind: enum {
            one,
            two,
            stale,
        },
    };
    var queue = std.DoublyLinkedList(Parent){};

    {
        var node = try arena.allocator().create(std.DoublyLinkedList(Parent).Node);
        node.data = .{ .oid = oid1.*, .kind = .one };
        queue.append(node);
    }

    {
        var node = try arena.allocator().create(std.DoublyLinkedList(Parent).Node);
        node.data = .{ .oid = oid2.*, .kind = .two };
        queue.append(node);
    }

    var parents_of_1 = std.StringHashMap(void).init(arena.allocator());
    var parents_of_2 = std.StringHashMap(void).init(arena.allocator());
    var parents_of_both = std.StringArrayHashMap(void).init(arena.allocator());
    var stale_oids = std.StringHashMap(void).init(arena.allocator());

    while (queue.popFirst()) |node| {
        switch (node.data.kind) {
            .one => {
                if (parents_of_2.contains(&node.data.oid)) {
                    try parents_of_both.put(&node.data.oid, {});
                } else if (parents_of_1.contains(&node.data.oid)) {
                    continue; // this oid was already added to the queue
                } else {
                    try parents_of_1.put(&node.data.oid, {});
                }
            },
            .two => {
                if (parents_of_1.contains(&node.data.oid)) {
                    try parents_of_both.put(&node.data.oid, {});
                } else if (parents_of_2.contains(&node.data.oid)) {
                    continue; // this oid was already added to the queue
                } else {
                    try parents_of_2.put(&node.data.oid, {});
                }
            },
            .stale => {
                try stale_oids.put(&node.data.oid, {});
            },
        }

        const is_common_ancestor = parents_of_both.contains(&node.data.oid);

        // TODO: instead of appending to the end, append it in descending order of timestamp
        // so we prioritize more recent commits and avoid wasteful traversal deep in the history.
        const object = try Object(repo_kind).init(arena.allocator(), core_cursor, node.data.oid);
        for (object.content.commit.parents.items) |parent_oid| {
            const is_stale = is_common_ancestor or stale_oids.contains(&parent_oid);
            var new_node = try arena.allocator().create(std.DoublyLinkedList(Parent).Node);
            new_node.data = .{ .oid = parent_oid, .kind = if (is_stale) .stale else node.data.kind };
            queue.append(new_node);
        }

        // stop if queue only has stale nodes
        var queue_is_stale = true;
        var next_node_maybe = queue.first;
        while (next_node_maybe) |next_node| {
            if (!stale_oids.contains(&next_node.data.oid)) {
                queue_is_stale = false;
                break;
            }
            next_node_maybe = next_node.next;
        }
        if (queue_is_stale) {
            break;
        }
    }

    const common_ancestor_count = parents_of_both.count();
    if (common_ancestor_count > 1) {
        var oid = parents_of_both.keys()[0][0..hash.SHA1_HEX_LEN].*;
        for (parents_of_both.keys()[1..]) |next_oid| {
            oid = try getDescendent(repo_kind, allocator, core_cursor, oid[0..hash.SHA1_HEX_LEN], next_oid[0..hash.SHA1_HEX_LEN]);
        }
        return oid;
    } else if (common_ancestor_count == 1) {
        return parents_of_both.keys()[0][0..hash.SHA1_HEX_LEN].*;
    } else {
        return error.NoCommonAncestor;
    }
}
