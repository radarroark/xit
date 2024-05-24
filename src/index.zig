//! tracks the files that are staged. the commit
//! command will use this when creating the tree.

const std = @import("std");
const xitdb = @import("xitdb");
const object = @import("./object.zig");
const hash = @import("./hash.zig");
const io = @import("./io.zig");
const rp = @import("./repo.zig");

pub const ReadIndexError = error{
    InvalidSignature,
    InvalidVersion,
    InvalidPathSize,
    InvalidNullPadding,
};

pub fn Index(comptime repo_kind: rp.RepoKind) type {
    return struct {
        version: u32,
        entries: std.StringArrayHashMap(Entry),
        dir_to_paths: std.StringArrayHashMap(std.StringArrayHashMap(void)),
        dir_to_children: std.StringArrayHashMap(std.StringArrayHashMap(void)),
        root_children: std.StringArrayHashMap(void),
        allocator: std.mem.Allocator,
        arena: std.heap.ArenaAllocator,

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

        pub fn init(allocator: std.mem.Allocator, core: *rp.Repo(repo_kind).Core) !Index(repo_kind) {
            var index = Index(repo_kind){
                .version = 2,
                .entries = std.StringArrayHashMap(Index(repo_kind).Entry).init(allocator),
                .dir_to_paths = std.StringArrayHashMap(std.StringArrayHashMap(void)).init(allocator),
                .dir_to_children = std.StringArrayHashMap(std.StringArrayHashMap(void)).init(allocator),
                .root_children = std.StringArrayHashMap(void).init(allocator),
                .allocator = allocator,
                .arena = std.heap.ArenaAllocator.init(allocator),
            };
            errdefer index.deinit();

            switch (repo_kind) {
                .git => {
                    // open index
                    const index_file = core.git_dir.openFile("index", .{ .mode = .read_only }) catch |err| {
                        switch (err) {
                            error.FileNotFound => return index,
                            else => return err,
                        }
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
                        var entry = Index(repo_kind).Entry{
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
                        var entry_size = try reader.context.getPos() - start_pos;
                        while (entry_size % 8 != 0) {
                            entry_size += 1;
                            const bytes = try reader.readBytesNoEof(1);
                            if (bytes[0] != 0) {
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
                    if (try core.db.rootCursor().readCursor(void, &[_]xitdb.PathPart(void){
                        .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                        .{ .hash_map_get = hash.hashBuffer("index") },
                    })) |index_cursor| {
                        var iter = try index_cursor.iter(.hash_map);
                        defer iter.deinit();
                        while (try iter.next()) |*next_cursor| {
                            if (try next_cursor.readBytesAlloc(index.allocator, void, &[_]xitdb.PathPart(void){})) |buffer| {
                                defer index.allocator.free(buffer);
                                if (try next_cursor.readHash(void, &[_]xitdb.PathPart(void){})) |path_hash| {
                                    if (try core.db.rootCursor().readBytesAlloc(index.arena.allocator(), void, &[_]xitdb.PathPart(void){
                                        .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                                        .{ .hash_map_get = hash.hashBuffer("paths") },
                                        .{ .hash_map_get = path_hash },
                                    })) |path| {
                                        var stream = std.io.fixedBufferStream(buffer);
                                        var reader = stream.reader();
                                        var entry = Index(repo_kind).Entry{
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
                                    } else {
                                        return error.ValueNotFound;
                                    }
                                }
                            }
                        }
                    }
                },
            }

            return index;
        }

        pub fn deinit(self: *Index(repo_kind)) void {
            self.arena.deinit();
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
        pub fn addPath(self: *Index(repo_kind), core: *rp.Repo(repo_kind).Core, path: []const u8) !void {
            switch (repo_kind) {
                .git => {
                    var objects_dir = try core.git_dir.openDir("objects", .{});
                    defer objects_dir.close();
                    try self.addPathRecur(core, .{ .objects_dir = objects_dir }, path);
                },
                .xit => {
                    const Ctx = struct {
                        core: *rp.Repo(repo_kind).Core,
                        index: *Index(repo_kind),
                        path: []const u8,

                        pub fn run(ctx_self: @This(), cursor: *xitdb.Database(.file).Cursor) !void {
                            const InnerCtx = struct {
                                core: *rp.Repo(repo_kind).Core,
                                index: *Index(repo_kind),
                                path: []const u8,
                                root_cursor: *xitdb.Database(.file).Cursor,

                                pub fn run(inner_ctx_self: @This(), inner_cursor: *xitdb.Database(.file).Cursor) !void {
                                    try inner_ctx_self.index.addPathRecur(inner_ctx_self.core, .{ .root_cursor = inner_ctx_self.root_cursor, .cursor = inner_cursor }, inner_ctx_self.path);
                                }
                            };
                            _ = try cursor.execute(InnerCtx, &[_]xitdb.PathPart(InnerCtx){
                                .{ .hash_map_get = hash.hashBuffer("objects") },
                                .hash_map_create,
                                .{ .ctx = InnerCtx{ .core = ctx_self.core, .index = ctx_self.index, .path = ctx_self.path, .root_cursor = cursor } },
                            });
                        }
                    };
                    _ = try core.db.rootCursor().execute(Ctx, &[_]xitdb.PathPart(Ctx){
                        .{ .array_list_get = .append_copy },
                        .hash_map_create,
                        .{ .ctx = Ctx{ .core = core, .index = self, .path = path } },
                    });
                },
            }
        }

        fn addPathRecur(self: *Index(repo_kind), core: *rp.Repo(repo_kind).Core, opts: object.ObjectOpts(repo_kind), path: []const u8) !void {
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
            const file = try core.repo_dir.openFile(path, .{ .mode = .read_only });
            defer file.close();
            const meta = try file.metadata();
            switch (meta.kind()) {
                std.fs.File.Kind.file => {
                    // write the object
                    var oid = [_]u8{0} ** hash.SHA1_BYTES_LEN;
                    try object.writeBlob(repo_kind, core, opts, self.allocator, path, &oid);
                    // add the entry
                    const times = io.getTimes(meta);
                    const stat = try io.getStat(file);
                    const entry = Index(repo_kind).Entry{
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
                std.fs.File.Kind.directory => {
                    var dir = try core.repo_dir.openDir(path, .{ .iterate = true });
                    defer dir.close();
                    var iter = dir.iterate();
                    while (try iter.next()) |entry| {
                        // ignore internal dir/file
                        switch (repo_kind) {
                            .git => {
                                if (std.mem.eql(u8, entry.name, ".git")) {
                                    continue;
                                }
                            },
                            .xit => {
                                if (std.mem.eql(u8, entry.name, ".xit")) {
                                    continue;
                                }
                            },
                        }

                        const subpath = if (std.mem.eql(u8, path, "."))
                            try std.fmt.allocPrint(self.arena.allocator(), "{s}", .{entry.name})
                        else
                            try std.fs.path.join(self.arena.allocator(), &[_][]const u8{ path, entry.name });
                        try self.addPathRecur(core, opts, subpath);
                    }
                },
                else => return,
            }
        }

        fn addEntry(self: *Index(repo_kind), entry: Entry) !void {
            try self.entries.put(entry.path, entry);

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

        pub const WriteOpts = switch (repo_kind) {
            .git => struct {
                lock_file: std.fs.File,
            },
            .xit => struct {
                db: *xitdb.Database(.file),
            },
        };

        pub fn write(self: *Index(repo_kind), allocator: std.mem.Allocator, opts: WriteOpts) !void {
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

                    // write the header
                    const version: u32 = 2;
                    const entry_count: u32 = @intCast(self.entries.count());
                    const header = try std.fmt.allocPrint(allocator, "DIRC{s}{s}", .{
                        std.mem.asBytes(&std.mem.nativeToBig(u32, version)),
                        std.mem.asBytes(&std.mem.nativeToBig(u32, entry_count)),
                    });
                    defer allocator.free(header);
                    try opts.lock_file.writeAll(header);
                    h.update(header);

                    // write the entries
                    for (self.entries.values()) |entry| {
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
                        while (entry_buffer.items.len % 8 != 0) {
                            try writer.print("\x00", .{});
                        }
                        try opts.lock_file.writeAll(entry_buffer.items);
                        h.update(entry_buffer.items);
                    }

                    // write the checksum
                    var overall_sha1_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
                    h.final(&overall_sha1_buffer);
                    try opts.lock_file.writeAll(&overall_sha1_buffer);
                },
                .xit => {
                    const Ctx = struct {
                        db: *xitdb.Database(.file),
                        allocator: std.mem.Allocator,
                        index: *Index(repo_kind),

                        pub fn run(ctx_self: @This(), cursor: *xitdb.Database(.file).Cursor) !void {
                            const InnerCtx = struct {
                                db: *xitdb.Database(.file),
                                allocator: std.mem.Allocator,
                                index: *Index(repo_kind),
                                root_cursor: *xitdb.Database(.file).Cursor,

                                pub fn run(inner_ctx_self: @This(), inner_cursor: *xitdb.Database(.file).Cursor) !void {
                                    // remove items no longer in the index
                                    var iter = try inner_cursor.iter(.hash_map);
                                    defer iter.deinit();
                                    while (try iter.next()) |*next_cursor| {
                                        if (try next_cursor.readHash(void, &[_]xitdb.PathPart(void){})) |path_hash| {
                                            if (try inner_ctx_self.root_cursor.readBytesAlloc(inner_ctx_self.allocator, void, &[_]xitdb.PathPart(void){
                                                .{ .hash_map_get = hash.hashBuffer("paths") },
                                                .{ .hash_map_get = path_hash },
                                            })) |path| {
                                                defer inner_ctx_self.allocator.free(path);
                                                if (!inner_ctx_self.index.entries.contains(path)) {
                                                    _ = try inner_cursor.execute(void, &[_]xitdb.PathPart(void){
                                                        .{ .hash_map_remove = hash.hashBuffer(path) },
                                                    });
                                                }
                                            } else {
                                                return error.ValueNotFound;
                                            }
                                        }
                                    }

                                    for (inner_ctx_self.index.entries.values()) |entry| {
                                        var entry_buffer = std.ArrayList(u8).init(inner_ctx_self.allocator);
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

                                        const path_hash = hash.hashBuffer(entry.path);

                                        if (try inner_ctx_self.root_cursor.readBytesAlloc(inner_ctx_self.allocator, void, &[_]xitdb.PathPart(void){
                                            .{ .hash_map_get = hash.hashBuffer("index") },
                                            .{ .hash_map_get = path_hash },
                                        })) |existing_entry| {
                                            defer inner_ctx_self.allocator.free(existing_entry);
                                            if (std.mem.eql(u8, entry_buffer.items, existing_entry)) {
                                                continue;
                                            }
                                        }

                                        _ = try inner_ctx_self.root_cursor.writeBytes(entry.path, .once, void, &[_]xitdb.PathPart(void){
                                            .{ .hash_map_get = hash.hashBuffer("paths") },
                                            .hash_map_create,
                                            .{ .hash_map_get = path_hash },
                                        });
                                        const buffer_ptr = try inner_ctx_self.root_cursor.writeBytes(entry_buffer.items, .once, void, &[_]xitdb.PathPart(void){
                                            .{ .hash_map_get = hash.hashBuffer("index-values") },
                                            .hash_map_create,
                                            .{ .hash_map_get = hash.hashBuffer(entry_buffer.items) },
                                        });
                                        _ = try inner_cursor.execute(void, &[_]xitdb.PathPart(void){
                                            .{ .hash_map_get = path_hash },
                                            .{ .value = .{ .bytes_ptr = buffer_ptr } },
                                        });
                                    }
                                }
                            };
                            _ = try cursor.execute(InnerCtx, &[_]xitdb.PathPart(InnerCtx){
                                .{ .hash_map_get = hash.hashBuffer("index") },
                                .hash_map_create,
                                .{ .ctx = InnerCtx{ .db = ctx_self.db, .allocator = ctx_self.allocator, .index = ctx_self.index, .root_cursor = cursor } },
                            });
                        }
                    };
                    _ = try opts.db.rootCursor().execute(Ctx, &[_]xitdb.PathPart(Ctx){
                        .{ .array_list_get = .append_copy },
                        .hash_map_create,
                        .{ .ctx = Ctx{ .db = opts.db, .allocator = allocator, .index = self } },
                    });
                },
            }
        }
    };
}

pub fn indexDiffersFromWorkspace(comptime repo_kind: rp.RepoKind, entry: Index(repo_kind).Entry, file: std.fs.File, meta: std.fs.File.Metadata) !bool {
    if (meta.size() != entry.file_size or !io.modeEquals(io.getMode(meta), entry.mode)) {
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
            try hash.sha1File(file, header, &oid);
            if (!std.mem.eql(u8, &entry.oid, &oid)) {
                return true;
            }
        }
    }
    return false;
}
