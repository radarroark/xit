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

const MAX_FILE_READ_BYTES = 1024; // FIXME: this is arbitrary...

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
        const entry = try std.fmt.allocPrint(self.allocator, "{s} {s}\x00{s}", .{ mode.to_str(), name, oid });
        errdefer self.allocator.free(entry);
        try self.entries.put(name, entry);
    }

    pub fn addTreeEntry(self: *Tree, name: []const u8, oid: []const u8) !void {
        const entry = try std.fmt.allocPrint(self.allocator, "40000 {s}\x00{s}", .{ name, oid });
        errdefer self.allocator.free(entry);
        try self.entries.put(name, entry);
    }
};

pub fn ObjectOpts(comptime repo_kind: rp.RepoKind) type {
    return switch (repo_kind) {
        .git => struct {
            objects_dir: std.fs.Dir,
        },
        .xit => struct {
            root_cursor: *xitdb.Database(.file).Cursor,
            cursor: *xitdb.Database(.file).Cursor,
        },
    };
}

/// writes the file at the given path as a blob.
/// sha1_bytes_buffer will have the oid when it's done.
/// on windows files are never marked as executable because
/// apparently i can't even check if they are...
/// maybe i'll figure that out later.
pub fn writeBlob(comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core, opts: ObjectOpts(repo_kind), allocator: std.mem.Allocator, path: []const u8, sha1_bytes_buffer: *[hash.SHA1_BYTES_LEN]u8) !void {
    // get absolute path of the file
    var path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
    const file_path = try core.repo_dir.realpath(path, &path_buffer);
    var file = try std.fs.openFileAbsolute(file_path, .{ .mode = std.fs.File.OpenMode.read_only });
    defer file.close();

    // exit early if it's not a file
    const meta = try file.metadata();
    if (meta.kind() != std.fs.File.Kind.file) {
        return;
    }

    // create blob header
    const file_size = meta.size();
    const header = try std.fmt.allocPrint(allocator, "blob {}\x00", .{file_size});
    defer allocator.free(header);

    // calc the sha1 of its contents
    try hash.sha1File(file, header, sha1_bytes_buffer);
    const sha1_hex = std.fmt.bytesToHex(sha1_bytes_buffer, .lower);

    switch (repo_kind) {
        .git => {
            // make the two char dir
            var hash_prefix_dir = try opts.objects_dir.makeOpenPath(sha1_hex[0..2], .{});
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
            const tmp_file = try hash_prefix_dir.createFile(tmp_file_name, .{ .read = true });
            defer tmp_file.close();
            try tmp_file.writeAll(header);

            // copy file into temp file
            var read_buffer = [_]u8{0} ** MAX_FILE_READ_BYTES;
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
            try compress.compress(tmp_file, compressed_tmp_file);

            // delete uncompressed temp file
            try hash_prefix_dir.deleteFile(tmp_file_name);

            // rename the compressed temp file
            try std.fs.rename(hash_prefix_dir, compressed_tmp_file_name, hash_prefix_dir, hash_suffix);
        },
        .xit => {
            const file_hash = hash.bytesToHash(sha1_bytes_buffer);

            const Ctx = struct {
                opts: ObjectOpts(repo_kind),
                file: std.fs.File,
                sha1_hex: [hash.SHA1_HEX_LEN]u8,
                header: []const u8,

                pub fn run(ctx_self: @This(), cursor: *xitdb.Database(.file).Cursor) !void {
                    if (cursor.pointer() == null) {
                        var writer = try cursor.writer(void, &[_]xitdb.PathPart(void){});

                        try writer.writeAll(ctx_self.header);
                        var read_buffer = [_]u8{0} ** MAX_FILE_READ_BYTES;
                        var offset: u64 = 0;
                        while (true) {
                            const size = try ctx_self.file.pread(&read_buffer, offset);
                            offset += size;
                            if (size == 0) {
                                break;
                            }
                            try writer.writeAll(read_buffer[0..size]);
                        }
                        try writer.finish();

                        _ = try ctx_self.opts.cursor.execute(void, &[_]xitdb.PathPart(void){
                            .{ .hash_map_get = try hash.hexToHash(&ctx_self.sha1_hex) },
                            .{ .value = .{ .bytes_ptr = writer.ptr_position } },
                        });
                    }
                }
            };
            _ = try opts.root_cursor.execute(Ctx, &[_]xitdb.PathPart(Ctx){
                .{ .hash_map_get = hash.hashBuffer("file-values") },
                .hash_map_create,
                .{ .hash_map_get = file_hash },
                .{ .ctx = Ctx{ .opts = opts, .file = file, .sha1_hex = sha1_hex, .header = header } },
            });
        },
    }
}

fn writeTree(comptime repo_kind: rp.RepoKind, opts: ObjectOpts(repo_kind), allocator: std.mem.Allocator, tree: *Tree, sha1_bytes_buffer: *[hash.SHA1_BYTES_LEN]u8) !void {
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
            // make the two char dir
            var tree_hash_prefix_dir = try opts.objects_dir.makeOpenPath(tree_sha1_hex[0..2], .{});
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
                root_cursor: *xitdb.Database(.file).Cursor,
                tree_sha1_bytes: *const [hash.SHA1_BYTES_LEN]u8,
                tree_bytes: []const u8,

                pub fn run(ctx_self: @This(), cursor: *xitdb.Database(.file).Cursor) !void {
                    // exit early if there is nothing to commit
                    if (cursor.pointer() != null) {
                        return;
                    }
                    const tree_ptr = try ctx_self.root_cursor.writeBytes(ctx_self.tree_bytes, .once, void, &[_]xitdb.PathPart(void){
                        .{ .hash_map_get = hash.hashBuffer("object-values") },
                        .hash_map_create,
                        .{ .hash_map_get = hash.bytesToHash(ctx_self.tree_sha1_bytes) },
                    });
                    _ = try cursor.execute(void, &[_]xitdb.PathPart(void){
                        .{ .value = .{ .bytes_ptr = tree_ptr } },
                    });
                }
            };
            _ = try opts.cursor.execute(Ctx, &[_]xitdb.PathPart(Ctx){
                .{ .hash_map_get = hash.bytesToHash(sha1_bytes_buffer) },
                .{ .ctx = Ctx{
                    .root_cursor = opts.root_cursor,
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
fn addIndexEntries(comptime repo_kind: rp.RepoKind, opts: ObjectOpts(repo_kind), allocator: std.mem.Allocator, tree: *Tree, index: idx.Index(repo_kind), prefix: []const u8, entries: [][]const u8) !void {
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
                repo_kind,
                opts,
                allocator,
                &subtree,
                index,
                path,
                child_names.items,
            );

            var tree_sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
            try writeTree(repo_kind, opts, allocator, &subtree, &tree_sha1_bytes_buffer);

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

pub fn writeCommit(comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core, allocator: std.mem.Allocator, parent_oids: []const [hash.SHA1_HEX_LEN]u8, message_maybe: ?[]const u8, sha1_bytes_out_maybe: ?*[hash.SHA1_BYTES_LEN]u8) !void {
    // read index
    var index = try idx.Index(repo_kind).init(allocator, core);
    defer index.deinit();

    switch (repo_kind) {
        .git => {
            // open the objects dir
            var objects_dir = try core.git_dir.openDir("objects", .{});
            defer objects_dir.close();

            // create tree and add index entries
            var tree = Tree.init(allocator);
            defer tree.deinit();
            try addIndexEntries(repo_kind, .{ .objects_dir = objects_dir }, allocator, &tree, index, "", index.root_children.keys());

            // write and hash tree
            var tree_sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
            try writeTree(repo_kind, .{ .objects_dir = objects_dir }, allocator, &tree, &tree_sha1_bytes_buffer);
            const tree_sha1_hex = std.fmt.bytesToHex(tree_sha1_bytes_buffer, .lower);

            // create commit contents
            const commit_contents = try createCommitContents(allocator, tree_sha1_hex, parent_oids, message_maybe);
            defer allocator.free(commit_contents);

            // create commit
            const commit = try std.fmt.allocPrint(allocator, "commit {}\x00{s}", .{ commit_contents.len, commit_contents });
            defer allocator.free(commit);

            // calc the sha1 of its contents
            var commit_sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
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
            try ref.updateRecur(repo_kind, core, .{ .dir = core.git_dir }, allocator, "HEAD", commit_sha1_hex);

            // update out param
            if (sha1_bytes_out_maybe) |sha1_bytes_out| sha1_bytes_out.* = commit_sha1_bytes_buffer;
        },
        .xit => {
            const Ctx = struct {
                core: *rp.Repo(repo_kind).Core,
                index: idx.Index(repo_kind),
                parent_oids: []const [hash.SHA1_HEX_LEN]u8,
                message_maybe: ?[]const u8,
                commit_sha1_bytes: [hash.SHA1_BYTES_LEN]u8,
                allocator: std.mem.Allocator,

                pub fn run(ctx_self: *@This(), cursor: *xitdb.Database(.file).Cursor) !void {
                    const ObjectsCtx = struct {
                        root_cursor: *xitdb.Database(.file).Cursor,
                        core: *rp.Repo(repo_kind).Core,
                        index: idx.Index(repo_kind),
                        parent_oids: []const [hash.SHA1_HEX_LEN]u8,
                        message_maybe: ?[]const u8,
                        commit_sha1_bytes: [hash.SHA1_BYTES_LEN]u8,
                        allocator: std.mem.Allocator,

                        pub fn run(obj_ctx_self: *@This(), obj_cursor: *xitdb.Database(.file).Cursor) !void {
                            // create tree and add index entries
                            var tree = Tree.init(obj_ctx_self.allocator);
                            defer tree.deinit();
                            try addIndexEntries(repo_kind, .{ .root_cursor = obj_ctx_self.root_cursor, .cursor = obj_cursor }, obj_ctx_self.allocator, &tree, obj_ctx_self.index, "", obj_ctx_self.index.root_children.keys());

                            // write and hash tree
                            var tree_sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
                            try writeTree(repo_kind, .{ .root_cursor = obj_ctx_self.root_cursor, .cursor = obj_cursor }, obj_ctx_self.allocator, &tree, &tree_sha1_bytes_buffer);
                            const tree_sha1_hex = std.fmt.bytesToHex(tree_sha1_bytes_buffer, .lower);

                            // create commit contents
                            const commit_contents = try createCommitContents(obj_ctx_self.allocator, tree_sha1_hex, obj_ctx_self.parent_oids, obj_ctx_self.message_maybe);
                            defer obj_ctx_self.allocator.free(commit_contents);

                            // create commit
                            const commit = try std.fmt.allocPrint(obj_ctx_self.allocator, "commit {}\x00{s}", .{ commit_contents.len, commit_contents });
                            defer obj_ctx_self.allocator.free(commit);

                            // calc the sha1 of its contents
                            try hash.sha1Buffer(commit, &obj_ctx_self.commit_sha1_bytes);

                            // write commit content
                            const content_ptr = try obj_ctx_self.root_cursor.writeBytes(commit, .once, void, &[_]xitdb.PathPart(void){
                                .{ .hash_map_get = hash.hashBuffer("object-values") },
                                .hash_map_create,
                                .{ .hash_map_get = hash.bytesToHash(&obj_ctx_self.commit_sha1_bytes) },
                            });

                            // write commit
                            _ = try obj_cursor.execute(void, &[_]xitdb.PathPart(void){
                                .{ .hash_map_get = hash.bytesToHash(&obj_ctx_self.commit_sha1_bytes) },
                                .{ .value = .{ .bytes_ptr = content_ptr } },
                            });
                        }
                    };
                    var obj_ctx = ObjectsCtx{
                        .root_cursor = cursor,
                        .core = ctx_self.core,
                        .index = ctx_self.index,
                        .parent_oids = ctx_self.parent_oids,
                        .message_maybe = ctx_self.message_maybe,
                        .commit_sha1_bytes = undefined,
                        .allocator = ctx_self.allocator,
                    };
                    _ = try cursor.execute(*ObjectsCtx, &[_]xitdb.PathPart(*ObjectsCtx){
                        .{ .hash_map_get = hash.hashBuffer("objects") },
                        .hash_map_create,
                        .{ .ctx = &obj_ctx },
                    });

                    ctx_self.commit_sha1_bytes = obj_ctx.commit_sha1_bytes;
                    const commit_sha1_hex = std.fmt.bytesToHex(obj_ctx.commit_sha1_bytes, .lower);

                    // write commit id to HEAD
                    try ref.updateRecur(repo_kind, ctx_self.core, .{ .root_cursor = cursor, .cursor = cursor }, ctx_self.allocator, "HEAD", commit_sha1_hex);
                }
            };
            var ctx = Ctx{
                .core = core,
                .index = index,
                .parent_oids = parent_oids,
                .message_maybe = message_maybe,
                .commit_sha1_bytes = undefined,
                .allocator = allocator,
            };
            _ = try core.db.rootCursor().execute(*Ctx, &[_]xitdb.PathPart(*Ctx){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .ctx = &ctx },
            });

            // update out param
            if (sha1_bytes_out_maybe) |sha1_bytes_out| sha1_bytes_out.* = ctx.commit_sha1_bytes;
        },
    }
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
        return std.mem.eql(u8, &self.oid, &other.oid) and io.modeEquals(self.mode, other.mode);
    }
};

pub fn isTree(entry: TreeEntry) bool {
    return entry.mode.object_type == .tree;
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

        pub fn init(allocator: std.mem.Allocator, core: *rp.Repo(repo_kind).Core, oid: [hash.SHA1_HEX_LEN]u8) !Object(repo_kind) {
            var state = blk: {
                switch (repo_kind) {
                    .git => {
                        // open the objects dir
                        var objects_dir = try core.git_dir.openDir("objects", .{});
                        errdefer objects_dir.close();

                        // open the object file
                        var commit_hash_prefix_dir = try objects_dir.openDir(oid[0..2], .{});
                        errdefer commit_hash_prefix_dir.close();
                        var commit_hash_suffix_file = try commit_hash_prefix_dir.openFile(oid[2..], .{ .mode = .read_only });
                        errdefer commit_hash_suffix_file.close();

                        // decompress the object file
                        var decompressed = try compress.Decompressed.init(commit_hash_suffix_file);
                        const reader = decompressed.stream.reader();

                        const Reader = @TypeOf(reader);
                        const State = struct {
                            objects_dir: std.fs.Dir,
                            commit_hash_prefix_dir: std.fs.Dir,
                            commit_hash_suffix_file: std.fs.File,
                            decompressed: compress.Decompressed,
                            reader: Reader,

                            fn deinit(self: *@This()) void {
                                self.commit_hash_suffix_file.close();
                                self.commit_hash_prefix_dir.close();
                                self.objects_dir.close();
                            }
                        };

                        break :blk State{
                            .objects_dir = objects_dir,
                            .commit_hash_prefix_dir = commit_hash_prefix_dir,
                            .commit_hash_suffix_file = commit_hash_suffix_file,
                            .decompressed = decompressed,
                            .reader = reader,
                        };
                    },
                    .xit => {
                        const State = struct {
                            allocator: std.mem.Allocator,
                            buffer: []u8,
                            stream: std.io.FixedBufferStream([]u8),
                            reader: std.io.FixedBufferStream([]u8).Reader,

                            fn deinit(self: *@This()) void {
                                self.allocator.free(self.buffer);
                            }
                        };
                        if (try core.db.rootCursor().readBytesAlloc(allocator, void, &[_]xitdb.PathPart(void){
                            .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                            .{ .hash_map_get = hash.hashBuffer("objects") },
                            .{ .hash_map_get = try hash.hexToHash(&oid) },
                        })) |bytes| {
                            var stream = std.io.fixedBufferStream(bytes);
                            break :blk State{
                                .allocator = allocator,
                                .buffer = bytes,
                                .stream = stream,
                                .reader = stream.reader(),
                            };
                        } else {
                            return error.ObjectNotFound;
                        }
                    },
                }
            };
            defer state.deinit();

            // read the object kind
            const object_kind = try state.reader.readUntilDelimiterAlloc(allocator, ' ', MAX_FILE_READ_BYTES);
            defer allocator.free(object_kind);

            // read the length (currently unused)
            const object_len = try state.reader.readUntilDelimiterAlloc(allocator, 0, MAX_FILE_READ_BYTES);
            defer allocator.free(object_len);
            _ = try std.fmt.parseInt(usize, object_len, 10);

            if (std.mem.eql(u8, "blob", object_kind)) {
                return Object(repo_kind){
                    .allocator = allocator,
                    .arena = std.heap.ArenaAllocator.init(allocator),
                    .content = ObjectContent{ .blob = {} },
                    .oid = oid,
                };
            } else if (std.mem.eql(u8, "tree", object_kind)) {
                var arena = std.heap.ArenaAllocator.init(allocator);
                errdefer arena.deinit();

                var entries = std.StringArrayHashMap(TreeEntry).init(arena.allocator());

                while (true) {
                    const entry_mode_str = state.reader.readUntilDelimiterAlloc(arena.allocator(), ' ', MAX_FILE_READ_BYTES) catch |err| {
                        switch (err) {
                            error.EndOfStream => break,
                            else => return err,
                        }
                    };
                    const entry_mode: io.Mode = @bitCast(try std.fmt.parseInt(u32, entry_mode_str, 8));
                    const entry_name = try state.reader.readUntilDelimiterAlloc(arena.allocator(), 0, MAX_FILE_READ_BYTES);
                    const entry_oid = try state.reader.readBytesNoEof(hash.SHA1_BYTES_LEN);
                    try entries.put(entry_name, TreeEntry{ .oid = entry_oid, .mode = entry_mode });
                }

                return Object(repo_kind){
                    .allocator = allocator,
                    .arena = arena,
                    .content = ObjectContent{ .tree = .{ .entries = entries } },
                    .oid = oid,
                };
            } else if (std.mem.eql(u8, "commit", object_kind)) {
                // read the content kind
                const content_kind = try state.reader.readUntilDelimiterAlloc(allocator, ' ', MAX_FILE_READ_BYTES);
                defer allocator.free(content_kind);
                if (!std.mem.eql(u8, "tree", content_kind)) {
                    return error.InvalidCommitContentKind;
                }

                // read the tree hash
                var tree_hash = [_]u8{0} ** (hash.SHA1_HEX_LEN + 1);
                const tree_hash_slice = try state.reader.readUntilDelimiter(&tree_hash, '\n');
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
                    const line = try state.reader.readUntilDelimiterAlloc(arena.allocator(), '\n', MAX_FILE_READ_BYTES);
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
                content.commit.message = try state.reader.readAllAlloc(arena.allocator(), MAX_FILE_READ_BYTES);

                return Object(repo_kind){
                    .allocator = allocator,
                    .arena = arena,
                    .content = content,
                    .oid = oid,
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

pub fn TreeDiff(comptime repo_kind: rp.RepoKind) type {
    return struct {
        changes: std.StringHashMap(Change),
        arena: std.heap.ArenaAllocator,

        pub const Change = struct {
            old: ?TreeEntry,
            new: ?TreeEntry,
        };

        pub fn init(allocator: std.mem.Allocator) TreeDiff(repo_kind) {
            return TreeDiff(repo_kind){
                .changes = std.StringHashMap(Change).init(allocator),
                .arena = std.heap.ArenaAllocator.init(allocator),
            };
        }

        pub fn deinit(self: *TreeDiff(repo_kind)) void {
            self.arena.deinit();
            self.changes.deinit();
        }

        pub fn compare(self: *TreeDiff(repo_kind), core: *rp.Repo(repo_kind).Core, old_oid_maybe: ?[hash.SHA1_HEX_LEN]u8, new_oid_maybe: ?[hash.SHA1_HEX_LEN]u8, path_list_maybe: ?std.ArrayList([]const u8)) !void {
            if (old_oid_maybe == null and new_oid_maybe == null) {
                return;
            }
            const old_entries = try self.loadTree(core, old_oid_maybe);
            const new_entries = try self.loadTree(core, new_oid_maybe);
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
                            try self.compare(core, if (old_value_tree) std.fmt.bytesToHex(&old_value.oid, .lower) else null, if (new_value_tree) std.fmt.bytesToHex(&new_value.oid, .lower) else null, path_list);
                            if (!old_value_tree or !new_value_tree) {
                                try self.changes.put(path, Change{ .old = if (old_value_tree) null else old_value, .new = if (new_value_tree) null else new_value });
                            }
                        }
                    } else {
                        if (isTree(old_value)) {
                            try self.compare(core, std.fmt.bytesToHex(&old_value.oid, .lower), null, path_list);
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
                        try self.compare(core, null, std.fmt.bytesToHex(&new_value.oid, .lower), path_list);
                    } else {
                        try self.changes.put(path, Change{ .old = null, .new = new_value });
                    }
                }
            }
        }

        fn loadTree(self: *TreeDiff(repo_kind), core: *rp.Repo(repo_kind).Core, oid_maybe: ?[hash.SHA1_HEX_LEN]u8) !std.StringArrayHashMap(TreeEntry) {
            if (oid_maybe) |oid| {
                const obj = try Object(repo_kind).init(self.arena.allocator(), core, oid);
                return switch (obj.content) {
                    .blob => std.StringArrayHashMap(TreeEntry).init(self.arena.allocator()),
                    .tree => obj.content.tree.entries,
                    .commit => self.loadTree(core, obj.content.commit.tree),
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
            if (self.oid_queue.popFirst()) |node| {
                const next_oid = node.data;
                self.allocator.destroy(node);
                var commit_object = try Object(repo_kind).init(self.allocator, self.core, next_oid);
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

fn getDescendent(comptime repo_kind: rp.RepoKind, allocator: std.mem.Allocator, core: *rp.Repo(repo_kind).Core, oid1: *const [hash.SHA1_HEX_LEN]u8, oid2: *const [hash.SHA1_HEX_LEN]u8) ![hash.SHA1_HEX_LEN]u8 {
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
        parent_kind: ParentKind,
    };
    var queue = std.DoublyLinkedList(Parent){};

    {
        const object = try Object(repo_kind).init(arena.allocator(), core, oid1.*);
        for (object.content.commit.parents.items) |parent_oid| {
            var node = try arena.allocator().create(std.DoublyLinkedList(Parent).Node);
            node.data = .{ .oid = parent_oid, .parent_kind = .one };
            queue.append(node);
        }
    }

    {
        const object = try Object(repo_kind).init(arena.allocator(), core, oid2.*);
        for (object.content.commit.parents.items) |parent_oid| {
            var node = try arena.allocator().create(std.DoublyLinkedList(Parent).Node);
            node.data = .{ .oid = parent_oid, .parent_kind = .two };
            queue.append(node);
        }
    }

    while (queue.popFirst()) |node| {
        switch (node.data.parent_kind) {
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
        const object = try Object(repo_kind).init(arena.allocator(), core, node.data.oid);
        for (object.content.commit.parents.items) |parent_oid| {
            var new_node = try arena.allocator().create(std.DoublyLinkedList(Parent).Node);
            new_node.data = .{ .oid = parent_oid, .parent_kind = node.data.parent_kind };
            queue.append(new_node);
        }
    }

    return error.DescendentNotFound;
}

pub fn commonAncestor(comptime repo_kind: rp.RepoKind, allocator: std.mem.Allocator, core: *rp.Repo(repo_kind).Core, oid1: *const [hash.SHA1_HEX_LEN]u8, oid2: *const [hash.SHA1_HEX_LEN]u8) ![hash.SHA1_HEX_LEN]u8 {
    if (std.mem.eql(u8, oid1, oid2)) {
        return oid1.*;
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const ParentKind = enum {
        one,
        two,
        stale,
    };
    const Parent = struct {
        oid: [hash.SHA1_HEX_LEN]u8,
        parent_kind: ParentKind,
    };
    var queue = std.DoublyLinkedList(Parent){};

    {
        const object = try Object(repo_kind).init(arena.allocator(), core, oid1.*);
        for (object.content.commit.parents.items) |parent_oid| {
            var node = try arena.allocator().create(std.DoublyLinkedList(Parent).Node);
            node.data = .{ .oid = parent_oid, .parent_kind = .one };
            queue.append(node);
        }
    }

    {
        const object = try Object(repo_kind).init(arena.allocator(), core, oid2.*);
        for (object.content.commit.parents.items) |parent_oid| {
            var node = try arena.allocator().create(std.DoublyLinkedList(Parent).Node);
            node.data = .{ .oid = parent_oid, .parent_kind = .two };
            queue.append(node);
        }
    }

    var parents_of_1 = std.StringHashMap(void).init(arena.allocator());
    var parents_of_2 = std.StringHashMap(void).init(arena.allocator());
    var parents_of_both = std.StringArrayHashMap(void).init(arena.allocator());
    var stale_oids = std.StringHashMap(void).init(arena.allocator());

    while (queue.popFirst()) |node| {
        switch (node.data.parent_kind) {
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
        const object = try Object(repo_kind).init(arena.allocator(), core, node.data.oid);
        for (object.content.commit.parents.items) |parent_oid| {
            const is_stale = is_common_ancestor or stale_oids.contains(&parent_oid);
            var new_node = try arena.allocator().create(std.DoublyLinkedList(Parent).Node);
            new_node.data = .{ .oid = parent_oid, .parent_kind = if (is_stale) .stale else node.data.parent_kind };
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
            oid = try getDescendent(repo_kind, allocator, core, oid[0..hash.SHA1_HEX_LEN], next_oid[0..hash.SHA1_HEX_LEN]);
        }
        return oid;
    } else if (common_ancestor_count == 1) {
        return parents_of_both.keys()[0][0..hash.SHA1_HEX_LEN].*;
    } else {
        return error.NoCommonAncestor;
    }
}
