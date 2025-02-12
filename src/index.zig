//! tracks the files that are staged. the commit
//! command will use this when creating the tree.

const std = @import("std");
const obj = @import("./object.zig");
const hash = @import("./hash.zig");
const fs = @import("./fs.zig");
const rp = @import("./repo.zig");
const st = @import("./status.zig");

pub const IndexUntrackOptions = struct {
    force: bool = false,
};

pub const IndexRemoveOptions = struct {
    force: bool = false,
    remove_from_workspace: bool = true,
};

pub fn Index(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        version: u32,
        // TODO: maybe store pointers to save space,
        // since usually only the first slot is used
        entries: std.StringArrayHashMap([4]?Entry),
        dir_to_paths: std.StringArrayHashMap(std.StringArrayHashMap(void)),
        dir_to_children: std.StringArrayHashMap(std.StringArrayHashMap(void)),
        root_children: std.StringArrayHashMap(void),
        allocator: std.mem.Allocator,
        arena: *std.heap.ArenaAllocator,

        pub const Entry = struct {
            pub const Flags = packed struct(u16) {
                name_length: u12,
                stage: u2,
                extended: bool,
                assume_valid: bool,
            };

            pub const ExtendedFlags = packed struct(u16) {
                unused: u13,
                intent_to_add: bool,
                skip_worktree: bool,
                reserved: bool,
            };

            ctime_secs: u32,
            ctime_nsecs: u32,
            mtime_secs: u32,
            mtime_nsecs: u32,
            dev: u32,
            ino: u32,
            mode: fs.Mode,
            uid: u32,
            gid: u32,
            file_size: switch (repo_kind) {
                .git => u32,
                .xit => u64,
            },
            oid: [hash.byteLen(repo_opts.hash)]u8,
            flags: Flags,
            extended_flags: ?ExtendedFlags,
            path: []const u8,
        };

        pub fn init(allocator: std.mem.Allocator, state: rp.Repo(repo_kind, repo_opts).State(.read_only)) !Index(repo_kind, repo_opts) {
            const arena = try allocator.create(std.heap.ArenaAllocator);
            arena.* = std.heap.ArenaAllocator.init(allocator);
            var self = Index(repo_kind, repo_opts){
                .version = 2,
                .entries = std.StringArrayHashMap([4]?Entry).init(allocator),
                .dir_to_paths = std.StringArrayHashMap(std.StringArrayHashMap(void)).init(allocator),
                .dir_to_children = std.StringArrayHashMap(std.StringArrayHashMap(void)).init(allocator),
                .root_children = std.StringArrayHashMap(void).init(allocator),
                .allocator = allocator,
                .arena = arena,
            };
            errdefer self.deinit();

            switch (repo_kind) {
                .git => {
                    // open index
                    const index_file = state.core.git_dir.openFile("index", .{ .mode = .read_only }) catch |err| switch (err) {
                        error.FileNotFound => return self,
                        else => |e| return e,
                    };
                    defer index_file.close();

                    const reader = index_file.reader();
                    const signature = try reader.readBytesNoEof(4);

                    if (!std.mem.eql(u8, "DIRC", &signature)) {
                        return error.InvalidSignature;
                    }

                    // ignoring version 3 and 4 for now
                    self.version = try reader.readInt(u32, .big);
                    if (self.version != 2) {
                        return error.InvalidVersion;
                    }

                    var entry_count = try reader.readInt(u32, .big);

                    while (entry_count > 0) {
                        entry_count -= 1;
                        const start_pos = try reader.context.getPos();
                        var entry = Entry{
                            .ctime_secs = try reader.readInt(u32, .big),
                            .ctime_nsecs = try reader.readInt(u32, .big),
                            .mtime_secs = try reader.readInt(u32, .big),
                            .mtime_nsecs = try reader.readInt(u32, .big),
                            .dev = try reader.readInt(u32, .big),
                            .ino = try reader.readInt(u32, .big),
                            .mode = @bitCast(try reader.readInt(u32, .big)),
                            .uid = try reader.readInt(u32, .big),
                            .gid = try reader.readInt(u32, .big),
                            .file_size = try reader.readInt(u32, .big),
                            .oid = try reader.readBytesNoEof(hash.byteLen(repo_opts.hash)),
                            .flags = @bitCast(try reader.readInt(u16, .big)),
                            .extended_flags = null, // TODO: read this if necessary
                            .path = try reader.readUntilDelimiterAlloc(self.arena.allocator(), 0, std.fs.MAX_PATH_BYTES),
                        };
                        if (entry.mode.unix_permission != 0o755) { // ensure mode is valid
                            entry.mode.unix_permission = 0o644;
                        }
                        if (entry.path.len != entry.flags.name_length) {
                            return error.InvalidPathSize;
                        }
                        const entry_size = try reader.context.getPos() - start_pos;
                        const entry_zeroes = (8 - (entry_size % 8)) % 8;
                        for (0..entry_zeroes) |_| {
                            if (0 != try reader.readByte()) {
                                return error.InvalidNullPadding;
                            }
                        }
                        try self.addEntry(entry);
                    }

                    // TODO: check the checksum
                    // skipping for now because it will probably require changing
                    // how i read the data above. i need access to the raw bytes
                    // (before the big endian and type conversions) to do the hashing.
                    _ = try reader.readBytesNoEof(hash.byteLen(.sha1));
                },
                .xit => {
                    if (try state.extra.moment.getCursor(hash.hashInt(repo_opts.hash, "index"))) |index_cursor| {
                        var iter = try index_cursor.iterator();
                        defer iter.deinit();
                        while (try iter.next()) |*next_cursor| {
                            const kv_pair = try next_cursor.readKeyValuePair();
                            const path = try kv_pair.key_cursor.readBytesAlloc(self.arena.allocator(), repo_opts.max_read_size);
                            const buffer = try kv_pair.value_cursor.readBytesAlloc(self.allocator, repo_opts.max_read_size);
                            defer self.allocator.free(buffer);

                            var stream = std.io.fixedBufferStream(buffer);
                            var reader = stream.reader();
                            while (try stream.getPos() < buffer.len) {
                                var entry = Entry{
                                    .ctime_secs = try reader.readInt(u32, .big),
                                    .ctime_nsecs = try reader.readInt(u32, .big),
                                    .mtime_secs = try reader.readInt(u32, .big),
                                    .mtime_nsecs = try reader.readInt(u32, .big),
                                    .dev = try reader.readInt(u32, .big),
                                    .ino = try reader.readInt(u32, .big),
                                    .mode = @bitCast(try reader.readInt(u32, .big)),
                                    .uid = try reader.readInt(u32, .big),
                                    .gid = try reader.readInt(u32, .big),
                                    .file_size = try reader.readInt(u64, .big),
                                    .oid = try reader.readBytesNoEof(hash.byteLen(repo_opts.hash)),
                                    .flags = @bitCast(try reader.readInt(u16, .big)),
                                    .extended_flags = null, // TODO: read this if necessary
                                    .path = path,
                                };
                                if (entry.mode.unix_permission != 0o755) { // ensure mode is valid
                                    entry.mode.unix_permission = 0o644;
                                }
                                if (entry.path.len != entry.flags.name_length) {
                                    return error.InvalidPathSize;
                                }
                                try self.addEntry(entry);
                            }
                        }
                    }
                },
            }

            return self;
        }

        pub fn deinit(self: *Index(repo_kind, repo_opts)) void {
            self.arena.deinit();
            self.allocator.destroy(self.arena);
            self.entries.deinit();
            for (self.dir_to_paths.values()) |*paths| {
                paths.deinit();
            }
            self.dir_to_paths.deinit();
            for (self.dir_to_children.values()) |*paths| {
                paths.deinit();
            }
            self.dir_to_children.deinit();
            self.root_children.deinit();
        }

        /// if path is a file, adds it as an entry to the index struct.
        /// if path is a dir, adds its children recursively.
        /// ignoring symlinks for now but will add that later.
        pub fn addPath(self: *Index(repo_kind, repo_opts), state: rp.Repo(repo_kind, repo_opts).State(.read_write), path: []const u8) !void {
            // remove entries that are parents of this path (directory replaces file)
            {
                var parent_path_maybe = std.fs.path.dirname(path);
                while (parent_path_maybe) |parent_path| {
                    if (self.entries.contains(parent_path)) {
                        self.removePath(parent_path);
                    }
                    parent_path_maybe = std.fs.path.dirname(parent_path);
                }
            }
            // remove entries that are children of this path (file replaces directory)
            try self.removeChildren(path);
            // read the metadata
            const meta = try fs.getMetadata(state.core.repo_dir, path);
            switch (meta.kind()) {
                .file => {
                    // open file
                    const file = try state.core.repo_dir.openFile(path, .{ .mode = .read_only });
                    defer file.close();

                    // make reader
                    var buffered_reader = std.io.bufferedReaderSize(repo_opts.read_size, file.reader());
                    const reader = buffered_reader.reader();

                    // write object
                    var oid = [_]u8{0} ** hash.byteLen(repo_opts.hash);
                    try obj.writeObject(repo_kind, repo_opts, state, file, reader, .{ .kind = .blob, .size = meta.size() }, &oid);

                    // add entry
                    const times = fs.getTimes(meta);
                    const stat = try fs.getStat(file);
                    const entry = Entry{
                        .ctime_secs = times.ctime_secs,
                        .ctime_nsecs = times.ctime_nsecs,
                        .mtime_secs = times.mtime_secs,
                        .mtime_nsecs = times.mtime_nsecs,
                        .dev = stat.dev,
                        .ino = stat.ino,
                        .mode = fs.getMode(meta),
                        .uid = stat.uid,
                        .gid = stat.gid,
                        .file_size = switch (repo_kind) {
                            .git => @truncate(meta.size()), // git docs say that the file size is truncated
                            .xit => meta.size(),
                        },
                        .oid = oid,
                        .flags = .{
                            .name_length = @intCast(path.len),
                            .stage = 0,
                            .extended = false,
                            .assume_valid = false,
                        },
                        .extended_flags = null,
                        .path = path,
                    };
                    try self.addEntry(entry);
                },
                .directory => {
                    var dir = try state.core.repo_dir.openDir(path, .{ .iterate = true });
                    defer dir.close();
                    var iter = dir.iterate();
                    while (try iter.next()) |entry| {
                        // ignore internal dir
                        const file_name = switch (repo_kind) {
                            .git => ".git",
                            .xit => ".xit",
                        };
                        if (std.mem.eql(u8, file_name, entry.name)) {
                            continue;
                        }

                        const subpath = if (std.mem.eql(u8, path, "."))
                            try self.arena.allocator().dupe(u8, entry.name)
                        else
                            try fs.joinPath(self.arena.allocator(), &.{ path, entry.name });
                        try self.addPath(state, subpath);
                    }
                },
                else => return,
            }
        }

        fn addEntry(self: *Index(repo_kind, repo_opts), entry: Entry) !void {
            if (self.entries.getEntry(entry.path)) |map_entry| {
                // there is an existing slot for the given path,
                // so evict entries to ensure zero and non-zero stages don't coexist
                if (0 == entry.flags.stage) {
                    map_entry.value_ptr[1] = null;
                    map_entry.value_ptr[2] = null;
                    map_entry.value_ptr[3] = null;
                } else {
                    map_entry.value_ptr[0] = null;
                }
                // add the new entry
                map_entry.value_ptr[entry.flags.stage] = entry;
            } else {
                // there is no existing slot for the given path,
                // so create a new one with the entry included
                var entries_for_path = [4]?Entry{ null, null, null, null };
                entries_for_path[entry.flags.stage] = entry;
                try self.entries.put(entry.path, entries_for_path);
            }

            var child = std.fs.path.basename(entry.path);
            var parent_path_maybe = std.fs.path.dirname(entry.path);

            while (parent_path_maybe) |parent_path| {
                // populate dir_to_children
                const children_maybe = self.dir_to_children.getEntry(parent_path);
                if (children_maybe) |children| {
                    try children.value_ptr.*.put(child, {});
                } else {
                    var children = std.StringArrayHashMap(void).init(self.allocator);
                    try children.put(child, {});
                    try self.dir_to_children.put(parent_path, children);
                }

                // populate dir_to_paths
                const child_paths_maybe = self.dir_to_paths.getEntry(parent_path);
                if (child_paths_maybe) |child_paths| {
                    try child_paths.value_ptr.*.put(entry.path, {});
                } else {
                    var child_paths = std.StringArrayHashMap(void).init(self.allocator);
                    try child_paths.put(entry.path, {});
                    try self.dir_to_paths.put(parent_path, child_paths);
                }

                child = std.fs.path.basename(parent_path);
                parent_path_maybe = std.fs.path.dirname(parent_path);
            }

            try self.root_children.put(child, {});
        }

        pub fn addConflictEntries(self: *Index(repo_kind, repo_opts), path: []const u8, tree_entries: [3]?obj.TreeEntry(repo_opts.hash)) !void {
            const path_parts = try fs.splitPath(self.allocator, path);
            defer self.allocator.free(path_parts);
            for (tree_entries, 1..) |tree_entry_maybe, stage| {
                if (tree_entry_maybe) |*tree_entry| {
                    try self.addTreeEntryFile(tree_entry, path_parts, 0, @intCast(stage));
                }
            }
        }

        pub fn addTreeEntry(
            self: *Index(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            allocator: std.mem.Allocator,
            tree_entry: *const obj.TreeEntry(repo_opts.hash),
            path_parts: []const []const u8,
        ) !void {
            const oid_hex = std.fmt.bytesToHex(tree_entry.oid, .lower);
            var object = try obj.Object(repo_kind, repo_opts, .full).init(allocator, state, &oid_hex);
            defer object.deinit();

            switch (object.content) {
                .blob => try self.addTreeEntryFile(tree_entry, path_parts, object.len, 0),
                .tree => |tree| {
                    for (tree.entries.keys(), tree.entries.values()) |path_part, *child_tree_entry| {
                        var child_path = std.ArrayList([]const u8).init(allocator);
                        defer child_path.deinit();
                        try child_path.appendSlice(path_parts);
                        try child_path.append(path_part);
                        try self.addTreeEntry(state, allocator, child_tree_entry, child_path.items);
                    }
                },
                else => return error.InvalidObjectKind,
            }
        }

        pub fn addTreeEntryFile(
            self: *Index(repo_kind, repo_opts),
            tree_entry: *const obj.TreeEntry(repo_opts.hash),
            path_parts: []const []const u8,
            file_size: u64,
            stage: u2,
        ) !void {
            if (tree_entry.mode.object_type != .regular_file) {
                return error.InvalidObjectKind;
            }
            const normalized_path = if (path_parts.len == 0) return error.InvalidPath else try fs.joinPath(self.arena.allocator(), path_parts);
            const entry = Entry{
                .ctime_secs = 0,
                .ctime_nsecs = 0,
                .mtime_secs = 0,
                .mtime_nsecs = 0,
                .dev = 0,
                .ino = 0,
                .mode = tree_entry.mode,
                .uid = 0,
                .gid = 0,
                .file_size = switch (repo_kind) {
                    .git => @truncate(file_size), // git docs say that the file size is truncated
                    .xit => file_size,
                },
                .oid = tree_entry.oid,
                .flags = .{
                    .name_length = @intCast(normalized_path.len),
                    .stage = stage,
                    .extended = false,
                    .assume_valid = false,
                },
                .extended_flags = null,
                .path = normalized_path,
            };
            try self.addEntry(entry);
        }

        pub fn removePath(self: *Index(repo_kind, repo_opts), path: []const u8) void {
            _ = self.entries.orderedRemove(path);
            var parent_path_maybe = std.fs.path.dirname(path);
            while (parent_path_maybe) |parent_path| {
                const child_paths_maybe = self.dir_to_paths.getEntry(parent_path);
                if (child_paths_maybe) |child_paths| {
                    _ = child_paths.value_ptr.*.orderedRemove(path);
                }
                parent_path_maybe = std.fs.path.dirname(parent_path);
            }
        }

        pub fn removeChildren(self: *Index(repo_kind, repo_opts), path: []const u8) !void {
            const child_paths_maybe = self.dir_to_paths.getEntry(path);
            if (child_paths_maybe) |child_paths| {
                const child_paths_array = child_paths.value_ptr.*.keys();
                // make a copy of the paths because removePath will modify it
                var child_paths_array_copy = std.ArrayList([]const u8).init(self.allocator);
                defer child_paths_array_copy.deinit();
                for (child_paths_array) |child_path| {
                    try child_paths_array_copy.append(child_path);
                }
                for (child_paths_array_copy.items) |child_path| {
                    self.removePath(child_path);
                }
            }
        }

        pub fn addOrRemovePath(
            self: *Index(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_write),
            path_parts: []const []const u8,
            action: enum { add, rm },
        ) !void {
            const normalized_path = if (path_parts.len == 0) "." else try fs.joinPath(self.arena.allocator(), path_parts);

            // if the path doesn't exist, remove it, regardless of what the `action` is
            if (state.core.repo_dir.openFile(normalized_path, .{ .mode = .read_only })) |file| {
                file.close();
            } else |err| {
                switch (err) {
                    error.IsDir => {}, // only happens on windows
                    error.FileNotFound => {
                        if (!self.entries.contains(normalized_path) and !self.dir_to_children.contains(normalized_path)) {
                            return switch (action) {
                                .add => error.AddIndexPathNotFound,
                                .rm => error.RemoveIndexPathNotFound,
                            };
                        }
                        self.removePath(normalized_path);
                        return;
                    },
                    else => |e| return e,
                }
            }

            // add or remove based on the `action`
            switch (action) {
                .add => try self.addPath(state, normalized_path),
                .rm => {
                    if (!self.entries.contains(normalized_path) and !self.dir_to_children.contains(normalized_path)) {
                        return error.RemoveIndexPathNotFound;
                    }
                    self.removePath(normalized_path);
                },
            }
        }

        pub fn write(self: *Index(repo_kind, repo_opts), allocator: std.mem.Allocator, state: rp.Repo(repo_kind, repo_opts).State(.read_write)) !void {
            switch (repo_kind) {
                .git => {
                    // sort the entries
                    const SortCtx = struct {
                        keys: [][]const u8,
                        pub fn lessThan(ctx: @This(), a_index: usize, b_index: usize) bool {
                            return std.mem.lessThan(u8, ctx.keys[a_index], ctx.keys[b_index]);
                        }
                    };
                    self.entries.sort(SortCtx{ .keys = self.entries.keys() });

                    // start the checksum
                    var hasher = hash.Hasher(.sha1).init();

                    // calculate entry count
                    var entry_count: u32 = 0;
                    for (self.entries.values()) |*entries_for_path| {
                        for (entries_for_path) |entry_maybe| {
                            if (entry_maybe != null) {
                                entry_count += 1;
                            }
                        }
                    }

                    const lock_file = state.extra.lock_file_maybe orelse return error.NoLockFile;
                    try lock_file.setEndPos(0); // truncate file in case this method is called multiple times

                    // write the header
                    const version: u32 = 2;
                    const header = try std.fmt.allocPrint(allocator, "DIRC{s}{s}", .{
                        std.mem.asBytes(&std.mem.nativeToBig(u32, version)),
                        std.mem.asBytes(&std.mem.nativeToBig(u32, entry_count)),
                    });
                    defer allocator.free(header);
                    try lock_file.writeAll(header);
                    hasher.update(header);

                    // write the entries
                    for (self.entries.values()) |*entries_for_path| {
                        for (entries_for_path) |entry_maybe| {
                            if (entry_maybe) |entry| {
                                var entry_buffer = std.ArrayList(u8).init(allocator);
                                defer entry_buffer.deinit();
                                const writer = entry_buffer.writer();
                                try writer.writeInt(u32, entry.ctime_secs, .big);
                                try writer.writeInt(u32, entry.ctime_nsecs, .big);
                                try writer.writeInt(u32, entry.mtime_secs, .big);
                                try writer.writeInt(u32, entry.mtime_nsecs, .big);
                                try writer.writeInt(u32, entry.dev, .big);
                                try writer.writeInt(u32, entry.ino, .big);
                                try writer.writeInt(u32, @as(u32, @bitCast(entry.mode)), .big);
                                try writer.writeInt(u32, entry.uid, .big);
                                try writer.writeInt(u32, entry.gid, .big);
                                try writer.writeInt(u32, entry.file_size, .big);
                                try writer.writeAll(&entry.oid);
                                try writer.writeInt(u16, @as(u16, @bitCast(entry.flags)), .big);
                                try writer.writeAll(entry.path);
                                try writer.writeByte(0);
                                const entry_size = entry_buffer.items.len;
                                const entry_zeroes = (8 - (entry_size % 8)) % 8;
                                for (0..entry_zeroes) |_| {
                                    try writer.writeByte(0);
                                }
                                try lock_file.writeAll(entry_buffer.items);
                                hasher.update(entry_buffer.items);
                            }
                        }
                    }

                    // write the checksum
                    var overall_sha1_buffer = [_]u8{0} ** hash.byteLen(.sha1);
                    hasher.final(&overall_sha1_buffer);
                    try lock_file.writeAll(&overall_sha1_buffer);
                },
                .xit => {
                    const index_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "index"));
                    var index = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(index_cursor);

                    // remove items no longer in the index
                    var iter = try index.cursor.iterator();
                    defer iter.deinit();
                    while (try iter.next()) |*next_cursor| {
                        const kv_pair = try next_cursor.readKeyValuePair();
                        const path = try kv_pair.key_cursor.readBytesAlloc(allocator, repo_opts.max_read_size);
                        defer allocator.free(path);

                        if (!self.entries.contains(path)) {
                            _ = try index.remove(hash.hashInt(repo_opts.hash, path));
                        }
                    }

                    for (self.entries.keys(), self.entries.values()) |path, *entries_for_path| {
                        var entry_buffer = std.ArrayList(u8).init(allocator);
                        defer entry_buffer.deinit();
                        const writer = entry_buffer.writer();

                        for (entries_for_path) |entry_maybe| {
                            if (entry_maybe) |entry| {
                                try writer.writeInt(u32, entry.ctime_secs, .big);
                                try writer.writeInt(u32, entry.ctime_nsecs, .big);
                                try writer.writeInt(u32, entry.mtime_secs, .big);
                                try writer.writeInt(u32, entry.mtime_nsecs, .big);
                                try writer.writeInt(u32, entry.dev, .big);
                                try writer.writeInt(u32, entry.ino, .big);
                                try writer.writeInt(u32, @as(u32, @bitCast(entry.mode)), .big);
                                try writer.writeInt(u32, entry.uid, .big);
                                try writer.writeInt(u32, entry.gid, .big);
                                try writer.writeInt(u64, entry.file_size, .big);
                                try writer.writeAll(&entry.oid);
                                try writer.writeInt(u16, @as(u16, @bitCast(entry.flags)), .big);
                            }
                        }

                        const path_hash = hash.hashInt(repo_opts.hash, path);
                        if (try index.getKeyCursor(path_hash)) |existing_entry_cursor| {
                            const existing_entry = try existing_entry_cursor.readBytesAlloc(allocator, repo_opts.max_read_size);
                            defer allocator.free(existing_entry);
                            if (std.mem.eql(u8, entry_buffer.items, existing_entry)) {
                                continue;
                            }
                        }

                        const path_set_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "path-set"));
                        const path_set = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(path_set_cursor);
                        var path_cursor = try path_set.putKeyCursor(path_hash);
                        try path_cursor.writeIfEmpty(.{ .bytes = path });
                        try index.putKey(path_hash, .{ .slot = path_cursor.slot() });

                        const entry_buffer_set_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "entry-buffer-set"));
                        const entry_buffer_set = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(entry_buffer_set_cursor);
                        var entry_buffer_cursor = try entry_buffer_set.putKeyCursor(hash.hashInt(repo_opts.hash, entry_buffer.items));
                        try entry_buffer_cursor.writeIfEmpty(.{ .bytes = entry_buffer.items });
                        try index.put(path_hash, .{ .slot = entry_buffer_cursor.slot() });
                    }
                },
            }
        }
    };
}

pub fn indexDiffersFromWorkspace(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    entry: Index(repo_kind, repo_opts).Entry,
    file: std.fs.File,
    meta: std.fs.File.Metadata,
) !bool {
    if (meta.size() != entry.file_size or !fs.getMode(meta).eql(entry.mode)) {
        return true;
    } else {
        const times = fs.getTimes(meta);
        if (times.ctime_secs != entry.ctime_secs or
            times.ctime_nsecs != entry.ctime_nsecs or
            times.mtime_secs != entry.mtime_secs or
            times.mtime_nsecs != entry.mtime_nsecs)
        {
            // create blob header
            const file_size = meta.size();
            var header_buffer = [_]u8{0} ** 256; // should be plenty of space
            const header = try std.fmt.bufPrint(&header_buffer, "blob {}\x00", .{file_size});

            var oid = [_]u8{0} ** hash.byteLen(repo_opts.hash);
            try hash.hashReader(repo_opts.hash, repo_opts.read_size, file.reader(), header, &oid);
            if (!std.mem.eql(u8, &entry.oid, &oid)) {
                return true;
            }
        }
    }
    return false;
}

pub const DiffersFrom = struct {
    head: bool,
    workspace: bool,
};

pub fn indexDiffersFrom(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    core: *rp.Repo(repo_kind, repo_opts).Core,
    index: Index(repo_kind, repo_opts),
    head_tree: st.HeadTree(repo_kind, repo_opts),
    path: []const u8,
    meta: std.fs.File.Metadata,
) !DiffersFrom {
    var ret = DiffersFrom{
        .head = false,
        .workspace = false,
    };

    if (index.entries.get(path)) |*index_entries_for_path| {
        if (index_entries_for_path[0]) |index_entry| {
            if (head_tree.entries.get(path)) |head_entry| {
                if (!index_entry.mode.eql(head_entry.mode) or !std.mem.eql(u8, &index_entry.oid, &head_entry.oid)) {
                    ret.head = true;
                }
            }

            const file = try core.repo_dir.openFile(path, .{ .mode = .read_only });
            defer file.close();
            if (try indexDiffersFromWorkspace(repo_kind, repo_opts, index_entry, file, meta)) {
                ret.workspace = true;
            }
        }
    }

    return ret;
}
