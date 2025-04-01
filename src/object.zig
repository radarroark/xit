const std = @import("std");
const builtin = @import("builtin");
const hash = @import("./hash.zig");
const idx = @import("./index.zig");
const rf = @import("./ref.zig");
const fs = @import("./fs.zig");
const rp = @import("./repo.zig");
const pack = @import("./pack.zig");
const chunk = @import("./chunk.zig");
const cfg = @import("./config.zig");
const tag = @import("./tag.zig");
const tr = @import("./tree.zig");
const mrg = @import("./merge.zig");

fn compressZlib(comptime read_size: usize, in: std.fs.File, out: std.fs.File) !void {
    // init stream from input file
    var zlib_stream = try std.compress.zlib.compressor(out.writer(), .{ .level = .default });

    // write the compressed data to the output file
    try in.seekTo(0);
    const reader = in.reader();
    var buf = [_]u8{0} ** read_size;
    while (true) {
        // read from file
        const size = try reader.read(&buf);
        if (size == 0) break;
        // compress
        try zlib_stream.writer().writeAll(buf[0..size]);
    }
    try zlib_stream.finish();
}

pub fn writeObject(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    stream: anytype,
    reader: anytype,
    header: ObjectHeader,
    hash_bytes_buffer: *[hash.byteLen(repo_opts.hash)]u8,
) !void {
    // serialize object header
    var header_bytes = [_]u8{0} ** 32;
    const header_str = try writeObjectHeader(header, &header_bytes);

    // calc the hash of its contents
    try hash.hashReader(repo_opts.hash, repo_opts.read_size, reader, header_str, hash_bytes_buffer);
    const hash_hex = std.fmt.bytesToHex(hash_bytes_buffer, .lower);

    // reset seek pos so we can reuse the reader for copying
    try stream.seekTo(0);

    switch (repo_kind) {
        .git => {
            var objects_dir = try state.core.repo_dir.openDir("objects", .{});
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
            var lock = try fs.LockFile.init(hash_prefix_dir, hash_suffix ++ ".uncompressed");
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
            var compressed_lock = try fs.LockFile.init(hash_prefix_dir, hash_suffix);
            defer compressed_lock.deinit();
            try compressZlib(repo_opts.read_size, lock.lock_file, compressed_lock.lock_file);
            compressed_lock.success = true;
        },
        .xit => {
            const object_hash = hash.bytesToInt(repo_opts.hash, hash_bytes_buffer);
            try chunk.writeChunks(repo_opts, state, reader, object_hash, header.size, header.kind.name());
        },
    }
}

const Tree = struct {
    entries: std.StringArrayHashMap([]const u8),
    arena: *std.heap.ArenaAllocator,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) !Tree {
        const arena = try allocator.create(std.heap.ArenaAllocator);
        errdefer allocator.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        return .{
            .entries = std.StringArrayHashMap([]const u8).init(arena.allocator()),
            .arena = arena,
            .allocator = allocator,
        };
    }

    fn deinit(self: *Tree) void {
        self.arena.deinit();
        self.allocator.destroy(self.arena);
    }

    fn addBlobEntry(self: *Tree, mode: fs.Mode, name: []const u8, oid: []const u8) !void {
        const entry = try std.fmt.allocPrint(self.arena.allocator(), "{s} {s}\x00{s}", .{ mode.toStr(), name, oid });
        try self.entries.put(name, entry);
    }

    fn addTreeEntry(self: *Tree, name: []const u8, oid: []const u8) !void {
        const entry = try std.fmt.allocPrint(self.arena.allocator(), "40000 {s}\x00{s}", .{ name, oid });
        // git sorts tree names as if they had a trailing slash
        const sort_name = try std.fmt.allocPrint(self.arena.allocator(), "{s}/", .{name});
        try self.entries.put(sort_name, entry);
    }

    fn addIndexEntries(
        self: *Tree,
        comptime repo_kind: rp.RepoKind,
        comptime repo_opts: rp.RepoOpts(repo_kind),
        state: rp.Repo(repo_kind, repo_opts).State(.read_write),
        allocator: std.mem.Allocator,
        index: *const idx.Index(repo_kind, repo_opts),
        prefix: []const u8,
        entries: [][]const u8,
    ) !void {
        for (entries) |name| {
            const path = try fs.joinPath(allocator, &.{ prefix, name });
            defer allocator.free(path);

            if (index.entries.get(path)) |*entries_for_path| {
                const entry = entries_for_path[0] orelse return error.NullEntry;
                try self.addBlobEntry(entry.mode, name, &entry.oid);
            } else if (index.dir_to_children.get(path)) |children| {
                var subtree = try Tree.init(allocator);
                defer subtree.deinit();

                var child_names = std.ArrayList([]const u8).init(allocator);
                defer child_names.deinit();
                for (children.keys()) |child| {
                    try child_names.append(child);
                }

                try subtree.addIndexEntries(
                    repo_kind,
                    repo_opts,
                    state,
                    allocator,
                    index,
                    path,
                    child_names.items,
                );

                var tree_hash_bytes_buffer = [_]u8{0} ** hash.byteLen(repo_opts.hash);
                try writeTree(repo_kind, repo_opts, state, allocator, &subtree, &tree_hash_bytes_buffer);

                try self.addTreeEntry(name, &tree_hash_bytes_buffer);
            } else {
                return error.ObjectEntryNotFound;
            }
        }
    }
};

fn writeTree(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    allocator: std.mem.Allocator,
    tree: *Tree,
    hash_bytes_buffer: *[hash.byteLen(repo_opts.hash)]u8,
) !void {
    // sort the entries so the tree hashes the same way it would from git
    const SortCtx = struct {
        keys: [][]const u8,
        pub fn lessThan(ctx: @This(), a_index: usize, b_index: usize) bool {
            return std.mem.lessThan(u8, ctx.keys[a_index], ctx.keys[b_index]);
        }
    };
    tree.entries.sort(SortCtx{ .keys = tree.entries.keys() });

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
            var objects_dir = try state.core.repo_dir.openDir("objects", .{});
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
            var lock = try fs.LockFile.init(tree_hash_prefix_dir, tree_hash_suffix ++ ".uncompressed");
            defer lock.deinit();
            try lock.lock_file.writeAll(tree_bytes);

            // create compressed lock file
            var compressed_lock = try fs.LockFile.init(tree_hash_prefix_dir, tree_hash_suffix);
            defer compressed_lock.deinit();
            try compressZlib(repo_opts.read_size, lock.lock_file, compressed_lock.lock_file);
            compressed_lock.success = true;
        },
        .xit => {
            const object_hash = hash.bytesToInt(repo_opts.hash, hash_bytes_buffer);
            var stream = std.io.fixedBufferStream(tree_contents);
            try chunk.writeChunks(repo_opts, state, stream.reader(), object_hash, tree_contents.len, "tree");
        },
    }
}

fn sign(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    lines: []const []const u8,
    signing_key: []const u8,
) ![]const []const u8 {
    const content = try std.mem.join(arena.allocator(), "\n", lines);

    // write the commit content to a file
    const content_file_name = "xit_signing_buffer";
    const content_file = try state.core.repo_dir.createFile(content_file_name, .{ .truncate = true, .lock = .exclusive });
    defer {
        content_file.close();
        state.core.repo_dir.deleteFile(content_file_name) catch {};
    }
    try content_file.writeAll(content);

    // sign the file
    const content_file_path = try state.core.repo_dir.realpathAlloc(arena.allocator(), content_file_name);
    var process = std.process.Child.init(
        &.{ "ssh-keygen", "-Y", "sign", "-n", "git", "-f", signing_key, content_file_path },
        allocator,
    );
    process.stdin_behavior = .Inherit;
    process.stdout_behavior = .Inherit;
    process.stderr_behavior = .Inherit;
    const term = try process.spawnAndWait();
    if (0 != term.Exited) {
        return error.ObjectSigningFailed;
    }

    // read the sig
    const sig_file_name = content_file_name ++ ".sig";
    const sig_file = try state.core.repo_dir.openFile(sig_file_name, .{ .mode = .read_only });
    defer {
        sig_file.close();
        state.core.repo_dir.deleteFile(sig_file_name) catch {};
    }
    const sig_file_reader = sig_file.reader();
    var sig_lines = std.ArrayList([]const u8).init(arena.allocator());
    while (try sig_file_reader.readUntilDelimiterOrEofAlloc(arena.allocator(), '\n', repo_opts.max_read_size)) |line| {
        try sig_lines.append(line);
    }
    return try sig_lines.toOwnedSlice();
}

pub fn CommitMetadata(comptime hash_kind: hash.HashKind) type {
    return struct {
        author: ?[]const u8 = null,
        committer: ?[]const u8 = null,
        message: ?[]const u8 = null,
        parent_oids: ?[]const [hash.hexLen(hash_kind)]u8 = null,
        allow_empty: bool = false,
        timestamp: u64 = 0,

        pub fn firstParent(self: CommitMetadata(hash_kind)) ?*const [hash.hexLen(hash_kind)]u8 {
            if (self.parent_oids) |parent_oids| {
                if (parent_oids.len > 0) {
                    return &parent_oids[0];
                }
            }
            return null;
        }
    };
}

pub fn writeCommit(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    allocator: std.mem.Allocator,
    metadata: CommitMetadata(repo_opts.hash),
) ![hash.hexLen(repo_opts.hash)]u8 {
    const parent_oids = if (metadata.parent_oids) |oids| oids else blk: {
        const head_oid_maybe = try rf.readHeadRecurMaybe(repo_kind, repo_opts, state.readOnly());
        break :blk if (head_oid_maybe) |head_oid| &.{head_oid} else &.{};
    };

    // make sure there is no unfinished merge in progress
    try mrg.checkForUnfinishedMerge(repo_kind, repo_opts, state.readOnly());

    // read index
    var index = try idx.Index(repo_kind, repo_opts).init(allocator, state.readOnly());
    defer index.deinit();

    // create tree and add index entries
    var tree = try Tree.init(allocator);
    defer tree.deinit();
    try tree.addIndexEntries(repo_kind, repo_opts, state, allocator, &index, "", index.root_children.keys());

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
    const commit_contents = blk: {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        var config = try cfg.Config(repo_kind, repo_opts).init(state.readOnly(), arena.allocator());
        defer config.deinit();

        var metadata_lines = std.ArrayList([]const u8).init(arena.allocator());

        try metadata_lines.append(try std.fmt.allocPrint(arena.allocator(), "tree {s}", .{tree_hash_hex}));
        for (parent_oids) |parent_oid| {
            try metadata_lines.append(try std.fmt.allocPrint(arena.allocator(), "parent {s}", .{parent_oid}));
        }

        const ts = if (repo_opts.is_test) 0 else std.time.timestamp();

        const author = metadata.author orelse auth_blk: {
            if (repo_opts.is_test) break :auth_blk "radar <radar@roark>";
            const user_section = config.sections.get("user") orelse return error.UserConfigNotFound;
            const name = user_section.get("name") orelse return error.UserConfigNotFound;
            const email = user_section.get("email") orelse return error.UserConfigNotFound;
            break :auth_blk try std.fmt.allocPrint(arena.allocator(), "{s} <{s}>", .{ name, email });
        };
        try metadata_lines.append(try std.fmt.allocPrint(arena.allocator(), "author {s} {} +0000", .{ author, ts }));

        const committer = metadata.committer orelse author;
        try metadata_lines.append(try std.fmt.allocPrint(arena.allocator(), "committer {s} {} +0000", .{ committer, ts }));

        try metadata_lines.append(try std.fmt.allocPrint(arena.allocator(), "\n{s}", .{metadata.message orelse ""}));

        // sign if key is in config
        if (config.sections.get("user")) |user_section| {
            if (user_section.get("signingkey")) |signing_key| {
                const sig_lines = try sign(repo_kind, repo_opts, state.readOnly(), allocator, &arena, metadata_lines.items, signing_key);

                var header_lines = std.ArrayList([]const u8).init(allocator);
                defer header_lines.deinit();
                for (sig_lines, 0..) |line, i| {
                    const sig_line = if (i == 0)
                        try std.fmt.allocPrint(arena.allocator(), "gpgsig {s}", .{line})
                    else
                        try std.fmt.allocPrint(arena.allocator(), " {s}", .{line});
                    try header_lines.append(sig_line);
                }

                const message = metadata_lines.pop() orelse unreachable; // remove the message
                try metadata_lines.appendSlice(header_lines.items); // add the sig
                try metadata_lines.append(message); // add the message back
            }
        }

        break :blk try std.mem.join(allocator, "\n", metadata_lines.items);
    };
    defer allocator.free(commit_contents);

    // create commit header
    var header_buffer = [_]u8{0} ** 32;
    const header = try std.fmt.bufPrint(&header_buffer, "commit {}\x00", .{commit_contents.len});

    // create commit
    const obj_content = try std.fmt.allocPrint(allocator, "{s}{s}", .{ header, commit_contents });
    defer allocator.free(obj_content);

    // calc the hash of its contents
    var commit_hash_bytes_buffer = [_]u8{0} ** hash.byteLen(repo_opts.hash);
    try hash.hashBuffer(repo_opts.hash, obj_content, &commit_hash_bytes_buffer);
    const commit_hash_hex = std.fmt.bytesToHex(commit_hash_bytes_buffer, .lower);
    const commit_hash = hash.bytesToInt(repo_opts.hash, &commit_hash_bytes_buffer);

    switch (repo_kind) {
        .git => {
            // open the objects dir
            var objects_dir = try state.core.repo_dir.openDir("objects", .{});
            defer objects_dir.close();

            // make the two char dir
            var commit_hash_prefix_dir = try objects_dir.makeOpenPath(commit_hash_hex[0..2], .{});
            defer commit_hash_prefix_dir.close();
            const commit_hash_suffix = commit_hash_hex[2..];

            // create lock file
            var lock = try fs.LockFile.init(commit_hash_prefix_dir, commit_hash_suffix ++ ".uncompressed");
            defer lock.deinit();
            try lock.lock_file.writeAll(obj_content);

            // create compressed lock file
            var compressed_lock = try fs.LockFile.init(commit_hash_prefix_dir, commit_hash_suffix);
            defer compressed_lock.deinit();
            try compressZlib(repo_opts.read_size, lock.lock_file, compressed_lock.lock_file);
            compressed_lock.success = true;

            // write commit id to HEAD
            try rf.writeRecur(repo_kind, repo_opts, state, "HEAD", &commit_hash_hex);
        },
        .xit => {
            var stream = std.io.fixedBufferStream(commit_contents);
            try chunk.writeChunks(repo_opts, state, stream.reader(), commit_hash, commit_contents.len, "commit");

            // write commit id to HEAD
            try rf.writeRecur(repo_kind, repo_opts, state, "HEAD", &commit_hash_hex);
        },
    }

    return std.fmt.bytesToHex(commit_hash_bytes_buffer, .lower);
}

pub fn writeTag(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    allocator: std.mem.Allocator,
    input: tag.AddTagInput,
    target_oid: *const [hash.hexLen(repo_opts.hash)]u8,
) ![hash.hexLen(repo_opts.hash)]u8 {
    const tag_contents = blk: {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        var config = try cfg.Config(repo_kind, repo_opts).init(state.readOnly(), arena.allocator());
        defer config.deinit();

        var metadata_lines = std.ArrayList([]const u8).init(arena.allocator());

        const kind = kind_blk: {
            var obj = try Object(repo_kind, repo_opts, .raw).init(allocator, state.readOnly(), target_oid);
            defer obj.deinit();
            break :kind_blk obj.content;
        };

        try metadata_lines.append(try std.fmt.allocPrint(arena.allocator(), "object {s}", .{target_oid}));
        try metadata_lines.append(try std.fmt.allocPrint(arena.allocator(), "type {s}", .{kind.name()}));
        try metadata_lines.append(try std.fmt.allocPrint(arena.allocator(), "tag {s}", .{input.name}));

        const ts = if (repo_opts.is_test) 0 else std.time.timestamp();

        const tagger = input.tagger orelse auth_blk: {
            if (repo_opts.is_test) break :auth_blk "radar <radar@roark>";
            const user_section = config.sections.get("user") orelse return error.UserConfigNotFound;
            const name = user_section.get("name") orelse return error.UserConfigNotFound;
            const email = user_section.get("email") orelse return error.UserConfigNotFound;
            break :auth_blk try std.fmt.allocPrint(arena.allocator(), "{s} <{s}>", .{ name, email });
        };
        try metadata_lines.append(try std.fmt.allocPrint(arena.allocator(), "tagger {s} {} +0000", .{ tagger, ts }));

        try metadata_lines.append(try std.fmt.allocPrint(arena.allocator(), "\n{s}", .{input.message orelse ""}));

        // sign if key is in config
        if (config.sections.get("user")) |user_section| {
            if (user_section.get("signingkey")) |signing_key| {
                const sig_lines = try sign(repo_kind, repo_opts, state.readOnly(), allocator, &arena, metadata_lines.items, signing_key);
                try metadata_lines.appendSlice(sig_lines);
            }
        }

        break :blk try std.mem.join(allocator, "\n", metadata_lines.items);
    };
    defer allocator.free(tag_contents);

    // create tag header
    var header_buffer = [_]u8{0} ** 32;
    const header = try std.fmt.bufPrint(&header_buffer, "tag {}\x00", .{tag_contents.len});

    // create tag
    const obj_content = try std.fmt.allocPrint(allocator, "{s}{s}", .{ header, tag_contents });
    defer allocator.free(obj_content);

    // calc the hash of its contents
    var tag_hash_bytes_buffer = [_]u8{0} ** hash.byteLen(repo_opts.hash);
    try hash.hashBuffer(repo_opts.hash, obj_content, &tag_hash_bytes_buffer);
    const tag_hash_hex = std.fmt.bytesToHex(tag_hash_bytes_buffer, .lower);
    const tag_hash = hash.bytesToInt(repo_opts.hash, &tag_hash_bytes_buffer);

    switch (repo_kind) {
        .git => {
            // open the objects dir
            var objects_dir = try state.core.repo_dir.openDir("objects", .{});
            defer objects_dir.close();

            // make the two char dir
            var tag_hash_prefix_dir = try objects_dir.makeOpenPath(tag_hash_hex[0..2], .{});
            defer tag_hash_prefix_dir.close();
            const tag_hash_suffix = tag_hash_hex[2..];

            // create lock file
            var lock = try fs.LockFile.init(tag_hash_prefix_dir, tag_hash_suffix ++ ".uncompressed");
            defer lock.deinit();
            try lock.lock_file.writeAll(obj_content);

            // create compressed lock file
            var compressed_lock = try fs.LockFile.init(tag_hash_prefix_dir, tag_hash_suffix);
            defer compressed_lock.deinit();
            try compressZlib(repo_opts.read_size, lock.lock_file, compressed_lock.lock_file);
            compressed_lock.success = true;
        },
        .xit => {
            var stream = std.io.fixedBufferStream(tag_contents);
            try chunk.writeChunks(repo_opts, state, stream.reader(), tag_hash, tag_contents.len, "tag");
        },
    }

    return std.fmt.bytesToHex(tag_hash_bytes_buffer, .lower);
}

pub fn readCommit(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    comptime load_kind: ObjectLoadKind,
    allocator: std.mem.Allocator,
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    oid: *const [hash.hexLen(repo_opts.hash)]u8,
) !Object(repo_kind, repo_opts, load_kind) {
    var object = try Object(repo_kind, repo_opts, load_kind).init(allocator, state, oid);
    errdefer object.deinit();

    switch (object.content) {
        .blob, .tree => return error.CommitNotFound,
        .commit => return object,
        .tag => |tag_content| {
            const commit_object = try readCommit(repo_kind, repo_opts, load_kind, allocator, state, &tag_content.target);
            object.deinit();
            return commit_object;
        },
    }
}

pub const ObjectKind = enum {
    blob,
    tree,
    commit,
    tag,

    pub fn init(kind_str: []const u8) !ObjectKind {
        return if (std.mem.eql(u8, "blob", kind_str))
            .blob
        else if (std.mem.eql(u8, "tree", kind_str))
            .tree
        else if (std.mem.eql(u8, "commit", kind_str))
            .commit
        else if (std.mem.eql(u8, "tag", kind_str))
            .tag
        else
            error.InvalidObjectKind;
    }

    pub fn name(self: ObjectKind) []const u8 {
        return switch (self) {
            .blob => "blob",
            .tree => "tree",
            .commit => "commit",
            .tag => "tag",
        };
    }
};

pub fn ObjectReader(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        allocator: std.mem.Allocator,
        reader: std.io.BufferedReader(repo_opts.read_size, Reader),

        pub const Reader = switch (repo_kind) {
            .git => pack.LooseOrPackObjectReader(repo_opts),
            .xit => chunk.ChunkObjectReader(repo_opts),
        };

        pub fn init(
            allocator: std.mem.Allocator,
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            oid: *const [hash.hexLen(repo_opts.hash)]u8,
        ) !@This() {
            switch (repo_kind) {
                .git => {
                    const reader = try pack.LooseOrPackObjectReader(repo_opts).init(allocator, state, oid);
                    return .{
                        .allocator = allocator,
                        .reader = std.io.bufferedReaderSize(repo_opts.read_size, reader),
                    };
                },
                .xit => {
                    const reader = try chunk.ChunkObjectReader(repo_opts).init(allocator, state, oid);
                    return .{
                        .allocator = allocator,
                        .reader = std.io.bufferedReaderSize(repo_opts.read_size, reader),
                    };
                },
            }
        }

        pub fn deinit(self: *ObjectReader(repo_kind, repo_opts)) void {
            self.reader.unbuffered_reader.deinit(self.allocator);
        }

        pub fn reset(self: *ObjectReader(repo_kind, repo_opts)) !void {
            try self.reader.unbuffered_reader.reset();
            self.reader = std.io.bufferedReaderSize(repo_opts.read_size, self.reader.unbuffered_reader);
        }

        pub fn seekTo(self: *ObjectReader(repo_kind, repo_opts), position: u64) !void {
            try self.reset();
            switch (repo_kind) {
                .git => try self.reader.unbuffered_reader.skipBytes(position),
                .xit => try self.reader.unbuffered_reader.seekTo(position),
            }
        }

        pub fn header(self: *const ObjectReader(repo_kind, repo_opts)) ObjectHeader {
            return switch (repo_kind) {
                .git => self.reader.unbuffered_reader.header(),
                .xit => self.reader.unbuffered_reader.header,
            };
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
    const type_name = header.kind.name();
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
            entries: std.StringArrayHashMap(tr.TreeEntry(hash_kind)),
        },
        commit: struct {
            tree: [hash.hexLen(hash_kind)]u8,
            metadata: CommitMetadata(hash_kind),
            message_position: u64,
        },
        tag: struct {
            target: [hash.hexLen(hash_kind)]u8,
            kind: ObjectKind,
            name: []const u8,
            tagger: []const u8,
            message: ?[]const u8,
            message_position: u64,
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

            const header = obj_rdr.header();

            switch (header.kind) {
                .blob => return .{
                    .allocator = allocator,
                    .arena = arena,
                    .content = switch (load_kind) {
                        .raw => .blob,
                        .full => .{ .blob = {} },
                    },
                    .oid = oid.*,
                    .len = header.size,
                    .object_reader = obj_rdr,
                },
                .tree => switch (load_kind) {
                    .raw => return .{
                        .allocator = allocator,
                        .arena = arena,
                        .content = .tree,
                        .oid = oid.*,
                        .len = header.size,
                        .object_reader = obj_rdr,
                    },
                    .full => {
                        var entries = std.StringArrayHashMap(tr.TreeEntry(repo_opts.hash)).init(arena.allocator());

                        while (true) {
                            const entry_mode_str = reader.readUntilDelimiterAlloc(arena.allocator(), ' ', repo_opts.max_read_size) catch |err| switch (err) {
                                error.EndOfStream => break,
                                else => |e| return e,
                            };
                            const entry_mode: fs.Mode = @bitCast(try std.fmt.parseInt(u32, entry_mode_str, 8));
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
                            .len = header.size,
                            .object_reader = obj_rdr,
                        };
                    },
                },
                .commit => switch (load_kind) {
                    .raw => return .{
                        .allocator = allocator,
                        .arena = arena,
                        .content = .commit,
                        .oid = oid.*,
                        .len = header.size,
                        .object_reader = obj_rdr,
                    },
                    .full => {
                        var position: u64 = 0;

                        // read the content kind
                        const content_kind = try reader.readUntilDelimiterAlloc(allocator, ' ', repo_opts.max_read_size);
                        defer allocator.free(content_kind);
                        if (!std.mem.eql(u8, "tree", content_kind)) {
                            return error.InvalidObject;
                        }
                        position += content_kind.len + 1;

                        // read the tree hash
                        var tree_hash = [_]u8{0} ** (hash.hexLen(repo_opts.hash) + 1);
                        const tree_hash_slice = try reader.readUntilDelimiter(&tree_hash, '\n');
                        if (tree_hash_slice.len != hash.hexLen(repo_opts.hash)) {
                            return error.InvalidObject;
                        }
                        position += tree_hash_slice.len + 1;

                        var parent_oids = std.ArrayList([hash.hexLen(repo_opts.hash)]u8).init(arena.allocator());
                        var metadata = CommitMetadata(repo_opts.hash){};

                        // read the metadata
                        while (true) {
                            const line = try reader.readUntilDelimiterAlloc(arena.allocator(), '\n', repo_opts.max_read_size);
                            position += line.len + 1;
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
                                        return error.InvalidObject;
                                    }
                                    try parent_oids.append(value[0..comptime hash.hexLen(repo_opts.hash)].*);
                                } else if (std.mem.eql(u8, "author", key)) {
                                    metadata.author = value;
                                } else if (std.mem.eql(u8, "committer", key)) {
                                    metadata.committer = value;
                                    var iter = std.mem.splitBackwardsScalar(u8, value, ' ');
                                    _ = iter.next(); // timezone
                                    if (iter.next()) |timestamp_str| {
                                        metadata.timestamp = try std.fmt.parseInt(u64, timestamp_str, 0);
                                    }
                                }
                            }
                        }

                        metadata.parent_oids = parent_oids.items;

                        // read only the first line
                        metadata.message = reader.readUntilDelimiterOrEofAlloc(
                            arena.allocator(),
                            '\n',
                            repo_opts.max_read_size,
                        ) catch |err| switch (err) {
                            error.StreamTooLong => null,
                            else => |e| return e,
                        };

                        return .{
                            .allocator = allocator,
                            .arena = arena,
                            .content = .{
                                .commit = .{
                                    .tree = tree_hash_slice[0..comptime hash.hexLen(repo_opts.hash)].*,
                                    .metadata = metadata,
                                    .message_position = position,
                                },
                            },
                            .oid = oid.*,
                            .len = header.size,
                            .object_reader = obj_rdr,
                        };
                    },
                },
                .tag => switch (load_kind) {
                    .raw => return .{
                        .allocator = allocator,
                        .arena = arena,
                        .content = .tag,
                        .oid = oid.*,
                        .len = header.size,
                        .object_reader = obj_rdr,
                    },
                    .full => {
                        var position: u64 = 0;

                        // read the fields
                        var fields = std.StringArrayHashMap([]const u8).init(allocator);
                        defer fields.deinit();
                        while (true) {
                            const line = try reader.readUntilDelimiterAlloc(arena.allocator(), '\n', repo_opts.max_read_size);
                            position += line.len + 1;
                            if (line.len == 0) {
                                break;
                            }
                            if (std.mem.indexOf(u8, line, " ")) |line_idx| {
                                if (line_idx == line.len) {
                                    break;
                                }
                                const key = line[0..line_idx];
                                const value = line[line_idx + 1 ..];
                                try fields.put(key, value);
                            }
                        }

                        // init the content
                        const target = fields.get("object") orelse return error.InvalidObject;
                        if (target.len != hash.hexLen(repo_opts.hash)) {
                            return error.InvalidObject;
                        }
                        var content = ObjectContent(repo_opts.hash){
                            .tag = .{
                                .target = target[0..comptime hash.hexLen(repo_opts.hash)].*,
                                .kind = try ObjectKind.init(fields.get("type") orelse return error.InvalidObject),
                                .name = fields.get("tag") orelse return error.InvalidObject,
                                .tagger = fields.get("tagger") orelse return error.InvalidObject,
                                .message = null,
                                .message_position = position,
                            },
                        };

                        // read only the first line
                        content.tag.message = reader.readUntilDelimiterOrEofAlloc(
                            arena.allocator(),
                            '\n',
                            repo_opts.max_read_size,
                        ) catch |err| switch (err) {
                            error.StreamTooLong => null,
                            else => |e| return e,
                        };

                        return .{
                            .allocator = allocator,
                            .arena = arena,
                            .content = content,
                            .oid = oid.*,
                            .len = header.size,
                            .object_reader = obj_rdr,
                        };
                    },
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

pub const ObjectIteratorOptions = struct {
    kind: enum {
        all,
        commit,
    },
};

pub fn ObjectIterator(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    comptime load_kind: ObjectLoadKind,
) type {
    return struct {
        allocator: std.mem.Allocator,
        core: *rp.Repo(repo_kind, repo_opts).Core,
        moment: rp.Repo(repo_kind, repo_opts).Moment(.read_only),
        oid_queue: std.DoublyLinkedList([hash.hexLen(repo_opts.hash)]u8),
        oid_excludes: std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void),
        object: Object(repo_kind, repo_opts, load_kind),
        options: ObjectIteratorOptions,

        pub fn init(
            allocator: std.mem.Allocator,
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            options: ObjectIteratorOptions,
        ) !ObjectIterator(repo_kind, repo_opts, load_kind) {
            return .{
                .allocator = allocator,
                .core = state.core,
                .moment = state.extra.moment.*,
                .oid_queue = std.DoublyLinkedList([hash.hexLen(repo_opts.hash)]u8){},
                .oid_excludes = std.AutoHashMap([hash.hexLen(repo_opts.hash)]u8, void).init(allocator),
                .object = undefined,
                .options = options,
            };
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
                            try self.includeContent(object.content);

                            switch (self.options.kind) {
                                .all => {},
                                .commit => if (.commit != object.content) continue,
                            }

                            var raw_object = try Object(repo_kind, repo_opts, .raw).init(self.allocator, state, &next_oid);
                            errdefer raw_object.deinit();
                            self.object = raw_object;
                            return &self.object;
                        },
                        .full => {
                            var object = try Object(repo_kind, repo_opts, .full).init(self.allocator, state, &next_oid);
                            errdefer object.deinit();
                            try self.includeContent(object.content);

                            switch (self.options.kind) {
                                .all => {},
                                .commit => if (.commit != object.content) {
                                    object.deinit();
                                    continue;
                                },
                            }

                            self.object = object;
                            return &self.object;
                        },
                    }
                }
            }
            return null;
        }

        fn includeContent(self: *ObjectIterator(repo_kind, repo_opts, load_kind), content: ObjectContent(repo_opts.hash)) !void {
            switch (content) {
                .blob => {},
                .tree => |tree_content| switch (self.options.kind) {
                    .all => for (tree_content.entries.values()) |entry| {
                        const entry_oid = std.fmt.bytesToHex(entry.oid, .lower);
                        try self.include(&entry_oid);
                    },
                    .commit => {},
                },
                .commit => |commit_content| {
                    if (commit_content.metadata.parent_oids) |parent_oids| {
                        for (parent_oids) |*parent_oid| {
                            try self.include(parent_oid);
                        }
                    }
                    switch (self.options.kind) {
                        .all => try self.include(&commit_content.tree),
                        .commit => {},
                    }
                },
                .tag => |tag_content| try self.include(&tag_content.target),
            }
        }

        pub fn include(self: *ObjectIterator(repo_kind, repo_opts, load_kind), oid: *const [hash.hexLen(repo_opts.hash)]u8) !void {
            if (!self.oid_excludes.contains(oid.*)) {
                var node = try self.allocator.create(std.DoublyLinkedList([hash.hexLen(repo_opts.hash)]u8).Node);
                errdefer self.allocator.destroy(node);
                node.data = oid.*;
                self.oid_queue.append(node);
            }
        }

        pub fn exclude(self: *ObjectIterator(repo_kind, repo_opts, load_kind), oid: *const [hash.hexLen(repo_opts.hash)]u8) !void {
            try self.oid_excludes.put(oid.*, {});

            const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = self.core, .extra = .{ .moment = &self.moment } };
            var object = try Object(repo_kind, repo_opts, .full).init(self.allocator, state, oid);
            defer object.deinit();
            switch (object.content) {
                .blob, .tag => {},
                .tree => |tree| switch (self.options.kind) {
                    .all => for (tree.entries.values()) |entry| {
                        try self.exclude(&std.fmt.bytesToHex(entry.oid, .lower));
                    },
                    .commit => {},
                },
                .commit => |commit| {
                    if (commit.metadata.parent_oids) |parent_oids| {
                        for (parent_oids) |parent_oid| {
                            try self.oid_excludes.put(parent_oid, {});
                        }
                    }
                    switch (self.options.kind) {
                        .all => try self.exclude(&commit.tree),
                        .commit => {},
                    }
                },
            }
        }
    };
}

pub fn copyFromObjectIterator(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    comptime source_repo_kind: rp.RepoKind,
    comptime source_repo_opts: rp.RepoOpts(source_repo_kind),
    obj_iter: *ObjectIterator(source_repo_kind, source_repo_opts, .raw),
    progress_ctx_maybe: ?repo_opts.ProgressCtx,
) !void {
    if (repo_opts.ProgressCtx != void) {
        if (progress_ctx_maybe) |progress_ctx| {
            try progress_ctx.run(.{ .start = .{
                .kind = .writing_object,
                .estimated_total_items = 0,
            } });
        }
    }

    while (try obj_iter.next()) |object| {
        defer object.deinit();

        var oid = [_]u8{0} ** hash.byteLen(repo_opts.hash);
        try writeObject(
            repo_kind,
            repo_opts,
            state,
            &object.object_reader,
            object.object_reader.reader.reader(),
            object.object_reader.header(),
            &oid,
        );

        if (repo_opts.ProgressCtx != void) {
            if (progress_ctx_maybe) |progress_ctx| {
                try progress_ctx.run(.{ .complete_one = .writing_object });
            }
        }
    }

    if (repo_opts.ProgressCtx != void) {
        if (progress_ctx_maybe) |progress_ctx| {
            try progress_ctx.run(.{ .end = .writing_object });
        }
    }
}

pub fn copyFromPackObjectIterator(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    allocator: std.mem.Allocator,
    pack_iter: *pack.PackObjectIterator(repo_kind, repo_opts),
    progress_ctx_maybe: ?repo_opts.ProgressCtx,
) !void {
    if (repo_opts.ProgressCtx != void) {
        if (progress_ctx_maybe) |progress_ctx| {
            try progress_ctx.run(.{ .start = .{
                .kind = .writing_object_from_pack,
                .estimated_total_items = pack_iter.object_count,
            } });
        }
    }

    while (try pack_iter.next(state.readOnly())) |pack_reader| {
        defer pack_reader.deinit(allocator);

        const Stream = struct {
            pack_reader: *pack.PackObjectReader(repo_kind, repo_opts),

            pub fn reader(stream_self: @This()) *pack.PackObjectReader(repo_kind, repo_opts) {
                return stream_self.pack_reader;
            }

            pub fn seekTo(stream_self: @This(), offset: usize) !void {
                if (offset == 0) {
                    try stream_self.pack_reader.reset();
                } else {
                    return error.InvalidOffset;
                }
            }
        };
        const stream = Stream{
            .pack_reader = pack_reader,
        };

        var oid = [_]u8{0} ** hash.byteLen(repo_opts.hash);
        const header = pack_reader.header();
        try writeObject(repo_kind, repo_opts, state, &stream, stream.reader(), header, &oid);

        if (repo_opts.ProgressCtx != void) {
            if (progress_ctx_maybe) |progress_ctx| {
                try progress_ctx.run(.{ .complete_one = .writing_object_from_pack });
            }
        }
    }

    if (repo_opts.ProgressCtx != void) {
        if (progress_ctx_maybe) |progress_ctx| {
            try progress_ctx.run(.{ .end = .writing_object_from_pack });
        }
    }
}
