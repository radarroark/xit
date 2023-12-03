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

    pub fn addBlobEntry(self: *Tree, mode: io.Mode, name: []const u8, oid: []const u8) !void {
        const entry = try std.fmt.allocPrint(self.allocator, "{s} {s}\x00{s}", .{ mode.to_str(), name, oid });
        errdefer self.allocator.free(entry);
        try self.entries.append(entry);
    }

    pub fn addTreeEntry(self: *Tree, name: []const u8, oid: []const u8) !void {
        const entry = try std.fmt.allocPrint(self.allocator, "40000 {s}\x00{s}", .{ name, oid });
        errdefer self.allocator.free(entry);
        try self.entries.append(entry);
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
    try hash.sha1_file(file, header, sha1_bytes_buffer);
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
            try compress.compress(allocator, tmp_file, compressed_tmp_file);

            // delete uncompressed temp file
            try hash_prefix_dir.deleteFile(tmp_file_name);

            // rename the compressed temp file
            try std.fs.rename(hash_prefix_dir, compressed_tmp_file_name, hash_prefix_dir, hash_suffix);
        },
        .xit => {
            var file_hash_bytes = [_]u8{0} ** xitdb.HASH_INT_SIZE;
            @memcpy(file_hash_bytes[0..hash.SHA1_BYTES_LEN], sha1_bytes_buffer);
            const file_hash = std.mem.bytesToValue(xitdb.Hash, &file_hash_bytes);

            const Ctx = struct {
                opts: ObjectOpts(repo_kind),
                file: std.fs.File,
                sha1_hex: [hash.SHA1_HEX_LEN]u8,
                header: []const u8,

                pub fn run(ctx_self: @This(), cursor: *xitdb.Database(.file).Cursor) !void {
                    if (cursor.getPointer() == null) {
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
                            .{ .map_get = hash.hash_buffer(&ctx_self.sha1_hex) },
                            .{ .value = .{ .bytes_ptr = writer.ptr_position } },
                        });
                    }
                }
            };
            _ = try opts.root_cursor.execute(Ctx, &[_]xitdb.PathPart(Ctx){
                .{ .map_get = hash.hash_buffer("file-values") },
                .map_create,
                .{ .map_get = file_hash },
                .{ .ctx = Ctx{ .opts = opts, .file = file, .sha1_hex = sha1_hex, .header = header } },
            });
        },
    }
}

fn writeTree(comptime repo_kind: rp.RepoKind, opts: ObjectOpts(repo_kind), allocator: std.mem.Allocator, entries: *std.ArrayList([]const u8), sha1_bytes_buffer: *[hash.SHA1_BYTES_LEN]u8) !void {
    // create tree contents
    const tree_contents = try std.mem.join(allocator, "", entries.items);
    defer allocator.free(tree_contents);

    // create tree
    const tree = try std.fmt.allocPrint(allocator, "tree {}\x00{s}", .{ tree_contents.len, tree_contents });
    defer allocator.free(tree);

    // calc the sha1 of its contents
    try hash.sha1_buffer(tree, sha1_bytes_buffer);
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
        },
        .xit => {
            const Ctx = struct {
                root_cursor: *xitdb.Database(.file).Cursor,
                tree: []const u8,

                pub fn run(ctx_self: @This(), cursor: *xitdb.Database(.file).Cursor) !void {
                    if (cursor.getPointer() != null) {
                        return error.ObjectAlreadyExists;
                    }
                    const tree_ptr = try ctx_self.root_cursor.writeBytes(ctx_self.tree, .once, void, &[_]xitdb.PathPart(void){
                        .{ .map_get = hash.hash_buffer("object-values") },
                        .map_create,
                        .{ .map_get = hash.hash_buffer(ctx_self.tree) },
                    });
                    _ = try cursor.execute(void, &[_]xitdb.PathPart(void){
                        .{ .value = .{ .bytes_ptr = tree_ptr } },
                    });
                }
            };
            _ = try opts.cursor.execute(Ctx, &[_]xitdb.PathPart(Ctx){
                .{ .map_get = hash.hash_buffer(&tree_sha1_hex) },
                .{ .ctx = Ctx{ .root_cursor = opts.root_cursor, .tree = tree } },
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
            writeTree(repo_kind, opts, allocator, &subtree.entries, &tree_sha1_bytes_buffer) catch |err| {
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
pub fn writeCommit(comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core, allocator: std.mem.Allocator, command: cmd.CommandData) !void {
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
            try writeTree(repo_kind, .{ .objects_dir = objects_dir }, allocator, &tree.entries, &tree_sha1_bytes_buffer);
            const tree_sha1_hex = std.fmt.bytesToHex(tree_sha1_bytes_buffer, .lower);

            // read HEAD
            const head_oid_maybe = try ref.readHeadMaybe(repo_kind, core);

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
            try ref.updateRecur(repo_kind, core, .{ .dir = core.git_dir }, allocator, "HEAD", commit_sha1_hex);
        },
        .xit => {
            const Ctx = struct {
                core: *rp.Repo(repo_kind).Core,
                index: idx.Index(repo_kind),
                command: cmd.CommandData,
                allocator: std.mem.Allocator,

                pub fn run(ctx_self: @This(), cursor: *xitdb.Database(.file).Cursor) !void {
                    const ObjectsCtx = struct {
                        root_cursor: *xitdb.Database(.file).Cursor,
                        core: *rp.Repo(repo_kind).Core,
                        index: idx.Index(repo_kind),
                        command: cmd.CommandData,
                        allocator: std.mem.Allocator,
                        commit_sha1_hex: [hash.SHA1_HEX_LEN]u8,

                        pub fn run(obj_ctx_self: *@This(), obj_cursor: *xitdb.Database(.file).Cursor) !void {
                            // create tree and add index entries
                            var tree = Tree.init(obj_ctx_self.allocator);
                            defer tree.deinit();
                            try addIndexEntries(repo_kind, .{ .root_cursor = obj_ctx_self.root_cursor, .cursor = obj_cursor }, obj_ctx_self.allocator, &tree, obj_ctx_self.index, "", obj_ctx_self.index.root_children.keys());

                            // write and hash tree
                            var tree_sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
                            try writeTree(repo_kind, .{ .root_cursor = obj_ctx_self.root_cursor, .cursor = obj_cursor }, obj_ctx_self.allocator, &tree.entries, &tree_sha1_bytes_buffer);
                            const tree_sha1_hex = std.fmt.bytesToHex(tree_sha1_bytes_buffer, .lower);

                            // read HEAD
                            // TODO: make `readHeadMaybe` use root cursor for tx safety
                            const head_oid_maybe = try ref.readHeadMaybe(repo_kind, obj_ctx_self.core);

                            // metadata
                            const author = "radar <radar@foo.com> 1512325222 +0000";
                            const message = obj_ctx_self.command.commit.message orelse "";
                            const parent = if (head_oid_maybe) |head_oid|
                                try std.fmt.allocPrint(obj_ctx_self.allocator, "parent {s}\n", .{head_oid})
                            else
                                try std.fmt.allocPrint(obj_ctx_self.allocator, "", .{});
                            defer obj_ctx_self.allocator.free(parent);

                            // create commit contents
                            const commit_contents = try std.fmt.allocPrint(obj_ctx_self.allocator, "tree {s}\n{s}author {s}\ncommitter {s}\n\n{s}", .{ tree_sha1_hex, parent, author, author, message });
                            defer obj_ctx_self.allocator.free(commit_contents);

                            // create commit
                            const commit = try std.fmt.allocPrint(obj_ctx_self.allocator, "commit {}\x00{s}", .{ commit_contents.len, commit_contents });
                            defer obj_ctx_self.allocator.free(commit);

                            // calc the sha1 of its contents
                            var commit_sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
                            try hash.sha1_buffer(commit, &commit_sha1_bytes_buffer);
                            obj_ctx_self.commit_sha1_hex = std.fmt.bytesToHex(commit_sha1_bytes_buffer, .lower);

                            // write commit content
                            const content_ptr = try obj_ctx_self.root_cursor.writeBytes(commit, .once, void, &[_]xitdb.PathPart(void){
                                .{ .map_get = hash.hash_buffer("object-values") },
                                .map_create,
                                .{ .map_get = hash.hash_buffer(commit) },
                            });

                            // write commit
                            _ = try obj_cursor.execute(void, &[_]xitdb.PathPart(void){
                                .{ .map_get = hash.hash_buffer(&obj_ctx_self.commit_sha1_hex) },
                                .{ .value = .{ .bytes_ptr = content_ptr } },
                            });
                        }
                    };
                    var obj_ctx = ObjectsCtx{
                        .root_cursor = cursor,
                        .core = ctx_self.core,
                        .index = ctx_self.index,
                        .command = ctx_self.command,
                        .allocator = ctx_self.allocator,
                        .commit_sha1_hex = undefined,
                    };
                    _ = try cursor.execute(*ObjectsCtx, &[_]xitdb.PathPart(*ObjectsCtx){
                        .{ .map_get = hash.hash_buffer("objects") },
                        .map_create,
                        .{ .ctx = &obj_ctx },
                    });

                    // write commit id to HEAD
                    try ref.updateRecur(repo_kind, ctx_self.core, .{ .root_cursor = cursor, .cursor = cursor }, ctx_self.allocator, "HEAD", obj_ctx.commit_sha1_hex);
                }
            };
            _ = try core.db.rootCursor().execute(Ctx, &[_]xitdb.PathPart(Ctx){
                .{ .list_get = .append_copy },
                .map_create,
                .{ .ctx = Ctx{ .core = core, .index = index, .command = command, .allocator = allocator } },
            });
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
        parent: ?[]const u8,
        author: ?[]const u8,
        committer: ?[]const u8,
        message: []const u8,
    },
};

pub const ObjectReadError = error{
    ObjectNotFound,
    InvalidObjectKind,
    InvalidCommitTreeHash,
    InvalidCommitParentHash,
};

pub fn Object(comptime repo_kind: rp.RepoKind) type {
    return struct {
        allocator: std.mem.Allocator,
        arena: std.heap.ArenaAllocator,
        content: ObjectContent,

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
                        var decompressed = try compress.Decompressed.init(allocator, commit_hash_suffix_file);
                        errdefer decompressed.deinit();
                        const reader = decompressed.stream.reader();

                        const Reader = @TypeOf(reader);
                        const State = struct {
                            objects_dir: std.fs.Dir,
                            commit_hash_prefix_dir: std.fs.Dir,
                            commit_hash_suffix_file: std.fs.File,
                            decompressed: compress.Decompressed,
                            reader: Reader,

                            fn deinit(self: *@This()) void {
                                self.decompressed.deinit();
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
                            .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                            .{ .map_get = hash.hash_buffer("objects") },
                            .{ .map_get = hash.hash_buffer(&oid) },
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

                // init the object
                var object = Object(repo_kind){
                    .allocator = allocator,
                    .arena = std.heap.ArenaAllocator.init(allocator),
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
                errdefer object.arena.deinit();
                std.mem.copy(u8, &object.content.commit.tree, tree_hash_slice);

                // read the metadata
                var metadata = std.StringHashMap([]const u8).init(allocator);
                defer metadata.deinit();
                while (true) {
                    const line = try state.reader.readUntilDelimiterAlloc(object.arena.allocator(), '\n', MAX_FILE_READ_BYTES);
                    if (line.len == 0) {
                        break;
                    }
                    if (std.mem.indexOf(u8, line, " ")) |line_idx| {
                        if (line_idx == line.len) {
                            break;
                        }
                        const key = line[0..line_idx];
                        const value = line[line_idx + 1 ..];
                        try metadata.put(key, value);
                    }
                }

                // read the message
                object.content.commit.message = try state.reader.readAllAlloc(object.arena.allocator(), MAX_FILE_READ_BYTES);

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
                var obj = try Object(repo_kind).init(self.arena.allocator(), core, oid);
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
