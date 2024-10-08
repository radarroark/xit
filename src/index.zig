//! tracks the files that are staged. the commit
//! command will use this when creating the tree.

const std = @import("std");
const obj = @import("./object.zig");
const hash = @import("./hash.zig");
const io = @import("./io.zig");
const rp = @import("./repo.zig");
const st = @import("./status.zig");

const MAX_READ_BYTES = 1024; // FIXME: this is arbitrary...

pub const IndexUnaddOptions = struct {
    force: bool = false,
};

pub const IndexRemoveOptions = struct {
    force: bool = false,
    remove_from_workspace: bool = true,
};

pub fn Index(comptime repo_kind: rp.RepoKind) type {
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
            mode: io.Mode,
            uid: u32,
            gid: u32,
            file_size: u32,
            oid: [hash.SHA1_BYTES_LEN]u8,
            flags: Flags,
            extended_flags: ?ExtendedFlags,
            path: []const u8,
        };

        pub fn init(allocator: std.mem.Allocator, state: rp.Repo(repo_kind).State) !Index(repo_kind) {
            const arena = try allocator.create(std.heap.ArenaAllocator);
            arena.* = std.heap.ArenaAllocator.init(allocator);
            var index = Index(repo_kind){
                .version = 2,
                .entries = std.StringArrayHashMap([4]?Entry).init(allocator),
                .dir_to_paths = std.StringArrayHashMap(std.StringArrayHashMap(void)).init(allocator),
                .dir_to_children = std.StringArrayHashMap(std.StringArrayHashMap(void)).init(allocator),
                .root_children = std.StringArrayHashMap(void).init(allocator),
                .allocator = allocator,
                .arena = arena,
            };
            errdefer index.deinit();

            switch (repo_kind) {
                .git => {
                    // open index
                    const index_file = state.core.git_dir.openFile("index", .{ .mode = .read_only }) catch |err| switch (err) {
                        error.FileNotFound => return index,
                        else => return err,
                    };
                    defer index_file.close();

                    const reader = index_file.reader();
                    const signature = try reader.readBytesNoEof(4);

                    if (!std.mem.eql(u8, "DIRC", &signature)) {
                        return error.InvalidSignature;
                    }

                    // ignoring version 3 and 4 for now
                    index.version = try reader.readInt(u32, .big);
                    if (index.version != 2) {
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
                            .oid = try reader.readBytesNoEof(hash.SHA1_BYTES_LEN),
                            .flags = @bitCast(try reader.readInt(u16, .big)),
                            .extended_flags = null, // TODO: read this if necessary
                            .path = try reader.readUntilDelimiterAlloc(index.arena.allocator(), 0, std.fs.MAX_PATH_BYTES),
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
                        try index.addEntry(entry);
                    }

                    // TODO: check the checksum
                    // skipping for now because it will probably require changing
                    // how i read the data above. i need access to the raw bytes
                    // (before the big endian and type conversions) to do the hashing.
                    _ = try reader.readBytesNoEof(hash.SHA1_BYTES_LEN);
                },
                .xit => {
                    if (try state.moment.get(hash.hashBuffer("index"))) |index_cursor| {
                        var iter = try index_cursor.iterator();
                        defer iter.deinit();
                        while (try iter.next()) |*next_cursor| {
                            const kv_pair = try next_cursor.readKeyValuePair();
                            const path = try kv_pair.key_cursor.readBytesAlloc(index.arena.allocator(), MAX_READ_BYTES);
                            const buffer = try kv_pair.value_cursor.readBytesAlloc(index.allocator, MAX_READ_BYTES);
                            defer index.allocator.free(buffer);

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
                                    .file_size = try reader.readInt(u32, .big),
                                    .oid = try reader.readBytesNoEof(hash.SHA1_BYTES_LEN),
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
                                try index.addEntry(entry);
                            }
                        }
                    }
                },
            }

            return index;
        }

        pub fn deinit(self: *Index(repo_kind)) void {
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
        pub fn addPath(self: *Index(repo_kind), state: rp.Repo(repo_kind).State, path: []const u8) !void {
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
            const meta = try io.getMetadata(state.core.repo_dir, path);
            switch (meta.kind()) {
                .file => {
                    const file = try state.core.repo_dir.openFile(path, .{ .mode = .read_only });
                    defer file.close();

                    // write the object
                    var oid = [_]u8{0} ** hash.SHA1_BYTES_LEN;
                    try obj.writeBlob(repo_kind, state, self.allocator, file, meta.size(), &oid);
                    // add the entry
                    const times = io.getTimes(meta);
                    const stat = try io.getStat(file);
                    const entry = Entry{
                        .ctime_secs = times.ctime_secs,
                        .ctime_nsecs = times.ctime_nsecs,
                        .mtime_secs = times.mtime_secs,
                        .mtime_nsecs = times.mtime_nsecs,
                        .dev = stat.dev,
                        .ino = stat.ino,
                        .mode = io.getMode(meta),
                        .uid = stat.uid,
                        .gid = stat.gid,
                        .file_size = @intCast(meta.size()),
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
                            try std.fmt.allocPrint(self.arena.allocator(), "{s}", .{entry.name})
                        else
                            try io.joinPath(self.arena.allocator(), &.{ path, entry.name });
                        try self.addPath(state, subpath);
                    }
                },
                else => return,
            }
        }

        fn addEntry(self: *Index(repo_kind), entry: Entry) !void {
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

        pub fn addConflictEntries(self: *Index(repo_kind), path: []const u8, tree_entries: [3]?obj.TreeEntry) !void {
            // add the conflict entries
            const owned_path = try std.fmt.allocPrint(self.arena.allocator(), "{s}", .{path});
            for (tree_entries, 1..) |tree_entry_maybe, stage| {
                if (tree_entry_maybe) |tree_entry| {
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
                        .file_size = 0,
                        .oid = tree_entry.oid,
                        .flags = .{
                            .name_length = @intCast(owned_path.len),
                            .stage = @intCast(stage),
                            .extended = false,
                            .assume_valid = false,
                        },
                        .extended_flags = null,
                        .path = owned_path,
                    };
                    try self.addEntry(entry);
                }
            }
        }

        pub fn removePath(self: *Index(repo_kind), path: []const u8) void {
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

        pub fn removeChildren(self: *Index(repo_kind), path: []const u8) !void {
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

        pub fn addOrRemovePath(self: *Index(repo_kind), state: rp.Repo(repo_kind).State, path: []const u8, action: enum { add, rm }) !void {
            if (state.core.repo_dir.openFile(path, .{ .mode = .read_only })) |file| {
                file.close();
            } else |err| {
                switch (err) {
                    error.IsDir => {}, // only happens on windows
                    error.FileNotFound => {
                        if (self.entries.contains(path)) {
                            self.removePath(path);
                            return;
                        } else {
                            return err;
                        }
                    },
                    else => return err,
                }
            }
            switch (action) {
                .add => try self.addPath(state, path),
                .rm => {
                    if (!self.entries.contains(path)) {
                        return error.CannotRemoveUnindexedFile;
                    }
                    self.removePath(path);
                },
            }
        }

        pub fn write(self: *Index(repo_kind), allocator: std.mem.Allocator, state: rp.Repo(repo_kind).State) !void {
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
                    var h = std.crypto.hash.Sha1.init(.{});

                    // calculate entry count
                    var entry_count: u32 = 0;
                    for (self.entries.values()) |*entries_for_path| {
                        for (entries_for_path) |entry_maybe| {
                            if (entry_maybe != null) {
                                entry_count += 1;
                            }
                        }
                    }

                    const lock_file = state.lock_file_maybe orelse return error.NoLockFile;
                    try lock_file.setEndPos(0); // truncate file in case this method is called multiple times

                    // write the header
                    const version: u32 = 2;
                    const header = try std.fmt.allocPrint(allocator, "DIRC{s}{s}", .{
                        std.mem.asBytes(&std.mem.nativeToBig(u32, version)),
                        std.mem.asBytes(&std.mem.nativeToBig(u32, entry_count)),
                    });
                    defer allocator.free(header);
                    try lock_file.writeAll(header);
                    h.update(header);

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
                                h.update(entry_buffer.items);
                            }
                        }
                    }

                    // write the checksum
                    var overall_sha1_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
                    h.final(&overall_sha1_buffer);
                    try lock_file.writeAll(&overall_sha1_buffer);
                },
                .xit => {
                    const index_cursor = try state.moment.put(hash.hashBuffer("index"));
                    var index = try rp.Repo(repo_kind).DB.HashMap(.read_write).init(index_cursor);

                    // remove items no longer in the index
                    var iter = try index.cursor.iterator();
                    defer iter.deinit();
                    while (try iter.next()) |*next_cursor| {
                        const kv_pair = try next_cursor.readKeyValuePair();
                        const path = try kv_pair.key_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
                        defer allocator.free(path);

                        if (!self.entries.contains(path)) {
                            try index.remove(hash.hashBuffer(path));
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
                                try writer.writeInt(u32, entry.file_size, .big);
                                try writer.writeAll(&entry.oid);
                                try writer.writeInt(u16, @as(u16, @bitCast(entry.flags)), .big);
                            }
                        }

                        const path_hash = hash.hashBuffer(path);
                        if (try index.get(path_hash)) |existing_entry_cursor| {
                            const existing_entry = try existing_entry_cursor.readBytesAlloc(allocator, MAX_READ_BYTES);
                            defer allocator.free(existing_entry);
                            if (std.mem.eql(u8, entry_buffer.items, existing_entry)) {
                                continue;
                            }
                        }

                        const path_set_cursor = try state.moment.put(hash.hashBuffer("path-set"));
                        const path_set = try rp.Repo(repo_kind).DB.HashMap(.read_write).init(path_set_cursor);
                        var path_cursor = try path_set.putKey(path_hash);
                        try path_cursor.writeBytes(path, .once);
                        try index.putKeyData(path_hash, .{ .slot = path_cursor.slot() });

                        const entry_buffer_set_cursor = try state.moment.put(hash.hashBuffer("entry-buffer-set"));
                        const entry_buffer_set = try rp.Repo(repo_kind).DB.HashMap(.read_write).init(entry_buffer_set_cursor);
                        var entry_buffer_cursor = try entry_buffer_set.putKey(hash.hashBuffer(entry_buffer.items));
                        try entry_buffer_cursor.writeBytes(entry_buffer.items, .once);
                        try index.putData(path_hash, .{ .slot = entry_buffer_cursor.slot() });
                    }
                },
            }
        }
    };
}

pub fn indexDiffersFromWorkspace(comptime repo_kind: rp.RepoKind, entry: Index(repo_kind).Entry, file: std.fs.File, meta: std.fs.File.Metadata) !bool {
    if (meta.size() != entry.file_size or !io.getMode(meta).eql(entry.mode)) {
        return true;
    } else {
        const times = io.getTimes(meta);
        if (times.ctime_secs != entry.ctime_secs or
            times.ctime_nsecs != entry.ctime_nsecs or
            times.mtime_secs != entry.mtime_secs or
            times.mtime_nsecs != entry.mtime_nsecs)
        {
            // create blob header
            const file_size = meta.size();
            var header_buffer = [_]u8{0} ** 256; // should be plenty of space
            const header = try std.fmt.bufPrint(&header_buffer, "blob {}\x00", .{file_size});

            var oid = [_]u8{0} ** hash.SHA1_BYTES_LEN;
            try hash.sha1Reader(file.reader(), header, &oid);
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
    core: *rp.Repo(repo_kind).Core,
    index: Index(repo_kind),
    head_tree: st.HeadTree(repo_kind),
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
            if (try indexDiffersFromWorkspace(repo_kind, index_entry, file, meta)) {
                ret.workspace = true;
            }
        }
    }

    return ret;
}
