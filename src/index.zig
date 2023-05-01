//! tracks the files that are staged. the commit
//! command will use this when creating the tree.

const std = @import("std");
const builtin = @import("builtin");
const object = @import("./object.zig");
const hash = @import("./hash.zig");

pub const Index = struct {
    version: u32,
    entries: std.StringArrayHashMap(Entry),
    dir_to_paths: std.StringArrayHashMap(std.StringArrayHashMap(void)),
    dir_to_children: std.StringArrayHashMap(std.StringArrayHashMap(void)),
    root_children: std.StringArrayHashMap(void),
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,

    pub const Entry = struct {
        ctime_secs: i32,
        ctime_nsecs: i32,
        mtime_secs: i32,
        mtime_nsecs: i32,
        dev: u32,
        ino: u32,
        mode: u32,
        uid: u32,
        gid: u32,
        file_size: u32,
        oid: [hash.SHA1_BYTES_LEN]u8,
        path_size: u16,
        path: []const u8,
    };

    pub fn init(allocator: std.mem.Allocator) Index {
        return .{
            .version = 2,
            .entries = std.StringArrayHashMap(Index.Entry).init(allocator),
            .dir_to_paths = std.StringArrayHashMap(std.StringArrayHashMap(void)).init(allocator),
            .dir_to_children = std.StringArrayHashMap(std.StringArrayHashMap(void)).init(allocator),
            .root_children = std.StringArrayHashMap(void).init(allocator),
            .allocator = allocator,
            .arena = std.heap.ArenaAllocator.init(allocator),
        };
    }

    pub fn deinit(self: *Index) void {
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
    fn putPath(self: *Index, cwd: std.fs.Dir, path: []const u8) !void {
        // remove entries that are parents of this path (directory replaces file)
        {
            var parent_path_maybe = std.fs.path.dirname(path);
            while (parent_path_maybe) |parent_path| {
                if (self.entries.contains(parent_path)) {
                    self.removeEntry(parent_path);
                }
                parent_path_maybe = std.fs.path.dirname(parent_path);
            }
        }
        // remove entries that are children of this path (file replaces directory)
        {
            var child_paths_maybe = self.dir_to_paths.getEntry(path);
            if (child_paths_maybe) |child_paths| {
                const child_paths_array = child_paths.value_ptr.*.keys();
                // make a copy of the paths because removeEntry will modify it
                var child_paths_array_copy = std.ArrayList([]const u8).init(self.allocator);
                defer child_paths_array_copy.deinit();
                for (child_paths_array) |child_path| {
                    try child_paths_array_copy.append(child_path);
                }
                for (child_paths_array_copy.items) |child_path| {
                    self.removeEntry(child_path);
                }
            }
        }
        // read the metadata
        const file = try cwd.openFile(path, .{ .mode = .read_only });
        defer file.close();
        const meta = try file.metadata();
        switch (meta.kind()) {
            std.fs.File.Kind.File => {
                // exit early if this path is already in the index
                if (self.entries.contains(path)) {
                    return;
                }
                // write the object
                var oid = [_]u8{0} ** hash.SHA1_BYTES_LEN;
                try object.writeBlobFromPath(self.allocator, cwd, path, &oid);
                // add the entry
                const times = getTimes(meta);
                const entry = Index.Entry{
                    .ctime_secs = times.ctime_secs,
                    .ctime_nsecs = times.ctime_nsecs,
                    .mtime_secs = times.mtime_secs,
                    .mtime_nsecs = times.mtime_nsecs,
                    .dev = 0,
                    .ino = 0,
                    .mode = getMode(meta),
                    .uid = 0,
                    .gid = 0,
                    .file_size = @truncate(u32, meta.size()),
                    .oid = oid,
                    .path_size = @truncate(u16, path.len),
                    .path = path,
                };
                try self.putEntry(entry);
            },
            std.fs.File.Kind.Directory => {
                var dir = try cwd.openIterableDir(path, .{});
                defer dir.close();
                var iter = dir.iterate();
                while (try iter.next()) |entry| {
                    // don't traverse the .git dir
                    if (std.mem.eql(u8, entry.name, ".git")) {
                        continue;
                    }

                    const subpath = if (std.mem.eql(u8, path, "."))
                        try std.fmt.allocPrint(self.arena.allocator(), "{s}", .{entry.name})
                    else
                        try std.fs.path.join(self.arena.allocator(), &[_][]const u8{ path, entry.name });
                    try self.putPath(cwd, subpath);
                }
            },
            else => return,
        }
    }

    fn putEntry(self: *Index, entry: Entry) !void {
        try self.entries.put(entry.path, entry);

        var child_maybe: ?[]const u8 = std.fs.path.basename(entry.path);
        var parent_path_maybe = std.fs.path.dirname(entry.path);

        while (parent_path_maybe) |parent_path| {
            // populate dir_to_children
            if (child_maybe) |child| {
                var child_paths_maybe = self.dir_to_children.getEntry(parent_path);
                if (child_paths_maybe) |child_paths| {
                    try child_paths.value_ptr.*.put(child, {});
                } else {
                    var child_paths = std.StringArrayHashMap(void).init(self.allocator);
                    try child_paths.put(child, {});
                    try self.dir_to_children.put(parent_path, child_paths);
                }
            }

            // populate dir_to_paths
            var child_paths_maybe = self.dir_to_paths.getEntry(parent_path);
            if (child_paths_maybe) |child_paths| {
                try child_paths.value_ptr.*.put(entry.path, {});
            } else {
                var child_paths = std.StringArrayHashMap(void).init(self.allocator);
                try child_paths.put(entry.path, {});
                try self.dir_to_paths.put(parent_path, child_paths);
            }

            child_maybe = std.fs.path.basename(parent_path);
            parent_path_maybe = std.fs.path.dirname(parent_path);
        }

        if (child_maybe) |child| {
            try self.root_children.put(child, {});
        }
    }

    fn removeEntry(self: *Index, path: []const u8) void {
        _ = self.entries.orderedRemove(path);
        var parent_path_maybe = std.fs.path.dirname(path);
        while (parent_path_maybe) |parent_path| {
            var child_paths_maybe = self.dir_to_paths.getEntry(parent_path);
            if (child_paths_maybe) |child_paths| {
                _ = child_paths.value_ptr.*.orderedRemove(path);
            }
            parent_path_maybe = std.fs.path.dirname(parent_path);
        }
    }
};

pub fn getMode(meta: std.fs.File.Metadata) u32 {
    const is_executable = switch (builtin.os.tag) {
        .windows => false,
        else => meta.permissions().inner.unixHas(std.fs.File.PermissionsUnix.Class.user, .execute),
    };
    return if (is_executable) 100755 else 100644;
}

pub const Times = struct {
    ctime_secs: i32,
    ctime_nsecs: i32,
    mtime_secs: i32,
    mtime_nsecs: i32,
};

pub fn getTimes(meta: std.fs.File.Metadata) Times {
    const ctime = meta.created() orelse 0;
    const mtime = meta.modified();
    return Times{
        .ctime_secs = @truncate(i32, @divTrunc(ctime, std.time.ns_per_s)),
        .ctime_nsecs = @truncate(i32, @mod(ctime, std.time.ns_per_s)),
        .mtime_secs = @truncate(i32, @divTrunc(mtime, std.time.ns_per_s)),
        .mtime_nsecs = @truncate(i32, @mod(mtime, std.time.ns_per_s)),
    };
}

pub const ReadIndexError = error{
    InvalidSignature,
    InvalidVersion,
    InvalidPathSize,
    InvalidNullPadding,
};

pub fn readIndex(allocator: std.mem.Allocator, git_dir: std.fs.Dir) !Index {
    var index = Index.init(allocator);
    errdefer index.deinit();

    // open index
    const index_file = git_dir.openFile("index", .{ .mode = .read_only }) catch |err| {
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
    index.version = try reader.readIntBig(u32);
    if (index.version != 2) {
        return error.InvalidVersion;
    }

    var entry_count = try reader.readIntBig(u32);

    while (entry_count > 0) {
        entry_count -= 1;
        const start_pos = try reader.context.getPos();
        const entry = Index.Entry{
            .ctime_secs = try reader.readIntBig(i32),
            .ctime_nsecs = try reader.readIntBig(i32),
            .mtime_secs = try reader.readIntBig(i32),
            .mtime_nsecs = try reader.readIntBig(i32),
            .dev = try reader.readIntBig(u32),
            .ino = try reader.readIntBig(u32),
            .mode = try reader.readIntBig(u32),
            .uid = try reader.readIntBig(u32),
            .gid = try reader.readIntBig(u32),
            .file_size = try reader.readIntBig(u32),
            .oid = try reader.readBytesNoEof(hash.SHA1_BYTES_LEN),
            .path_size = try reader.readIntBig(u16),
            .path = try reader.readUntilDelimiterAlloc(index.arena.allocator(), 0, std.fs.MAX_PATH_BYTES),
        };
        if (entry.path.len != entry.path_size) {
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
        try index.putEntry(entry);
    }

    // TODO: check the checksum
    // skipping for now because it will probably require changing
    // how i read the data above. i need access to the raw bytes
    // (before the big endian and type conversions) to do the hashing.
    _ = try reader.readBytesNoEof(hash.SHA1_BYTES_LEN);

    return index;
}

pub fn writeIndex(allocator: std.mem.Allocator, cwd: std.fs.Dir, paths: std.ArrayList([]const u8)) !void {
    // open git dir
    var git_dir = try cwd.openDir(".git", .{});
    defer git_dir.close();

    // open index
    // first write to a lock file and then rename it to index for safety
    const index_lock_file = try git_dir.createFile("index.lock", .{ .exclusive = true, .lock = .Exclusive });
    defer index_lock_file.close();
    errdefer git_dir.deleteFile("index.lock") catch {}; // make sure the lock file is deleted on error

    // read index
    var index = try readIndex(allocator, git_dir);
    defer index.deinit();

    // read all the new entries
    for (paths.items) |path| {
        const file = cwd.openFile(path, .{ .mode = .read_only }) catch |err| {
            if (err == error.FileNotFound and index.entries.contains(path)) {
                index.removeEntry(path);
                continue;
            } else {
                return err;
            }
        };
        defer file.close();
        try index.putPath(cwd, path);
    }

    // sort the entries
    const SortCtx = struct {
        keys: [][]const u8,
        pub fn lessThan(ctx: @This(), a_index: usize, b_index: usize) bool {
            return std.mem.lessThan(u8, ctx.keys[a_index], ctx.keys[b_index]);
        }
    };
    index.entries.sort(SortCtx{ .keys = index.entries.keys() });

    // start the checksum
    var h = std.crypto.hash.Sha1.init(.{});

    // write the header
    const version: u32 = 2;
    const entry_count: u32 = @truncate(u32, index.entries.count());
    const header = try std.fmt.allocPrint(allocator, "DIRC{s}{s}", .{
        std.mem.asBytes(&std.mem.nativeToBig(u32, version)),
        std.mem.asBytes(&std.mem.nativeToBig(u32, entry_count)),
    });
    defer allocator.free(header);
    try index_lock_file.writeAll(header);
    h.update(header);

    // write the entries
    for (index.entries.values()) |entry| {
        var entry_buffer = std.ArrayList(u8).init(allocator);
        defer entry_buffer.deinit();
        const writer = entry_buffer.writer();
        try writer.writeIntBig(i32, entry.ctime_secs);
        try writer.writeIntBig(i32, entry.ctime_nsecs);
        try writer.writeIntBig(i32, entry.mtime_secs);
        try writer.writeIntBig(i32, entry.mtime_nsecs);
        try writer.writeIntBig(u32, entry.dev);
        try writer.writeIntBig(u32, entry.ino);
        try writer.writeIntBig(u32, entry.mode);
        try writer.writeIntBig(u32, entry.uid);
        try writer.writeIntBig(u32, entry.gid);
        try writer.writeIntBig(u32, entry.file_size);
        try writer.writeAll(&entry.oid);
        try writer.writeIntBig(u16, entry.path_size);
        try writer.writeAll(entry.path);
        while (entry_buffer.items.len % 8 != 0) {
            try writer.print("\x00", .{});
        }
        try index_lock_file.writeAll(entry_buffer.items);
        h.update(entry_buffer.items);
    }

    // write the checksum
    var overall_sha1_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
    h.final(&overall_sha1_buffer);
    try index_lock_file.writeAll(&overall_sha1_buffer);

    // rename lock file to index
    try git_dir.rename("index.lock", "index");
}
