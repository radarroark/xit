//! tracks the files that are staged. the commit
//! command will use this when creating the tree.

const std = @import("std");
const builtin = @import("builtin");
const object = @import("./object.zig");
const hash = @import("./hash.zig");
const io = @import("./io.zig");

pub const ReadIndexError = error{
    InvalidSignature,
    InvalidVersion,
    InvalidPathSize,
    InvalidNullPadding,
};

pub const Index = struct {
    version: u32,
    entries: std.StringArrayHashMap(Entry),
    dir_to_paths: std.StringArrayHashMap(std.StringArrayHashMap(void)),
    dir_to_children: std.StringArrayHashMap(std.StringArrayHashMap(void)),
    root_children: std.StringArrayHashMap(void),
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,

    pub const Entry = struct {
        pub const Flags = packed struct {
            name_length: u12,
            stage: u2,
            extended: bool,
            assume_valid: bool,
        };

        pub const ExtendedFlags = packed struct {
            unused: u13,
            intent_to_add: bool,
            skip_worktree: bool,
            reserved: bool,
        };

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
        flags: Flags,
        extended_flags: ?ExtendedFlags,
        path: []const u8,
    };

    pub fn init(allocator: std.mem.Allocator, git_dir: std.fs.Dir) !Index {
        var index = Index{
            .version = 2,
            .entries = std.StringArrayHashMap(Index.Entry).init(allocator),
            .dir_to_paths = std.StringArrayHashMap(std.StringArrayHashMap(void)).init(allocator),
            .dir_to_children = std.StringArrayHashMap(std.StringArrayHashMap(void)).init(allocator),
            .root_children = std.StringArrayHashMap(void).init(allocator),
            .allocator = allocator,
            .arena = std.heap.ArenaAllocator.init(allocator),
        };
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
            var entry = Index.Entry{
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
                .flags = @bitCast(try reader.readIntBig(u16)),
                .extended_flags = null, // TODO: read this if necessary
                .path = try reader.readUntilDelimiterAlloc(index.arena.allocator(), 0, std.fs.MAX_PATH_BYTES),
            };
            if (entry.mode != 100755) { // ensure mode is valid
                entry.mode = 100644;
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

        return index;
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
    pub fn addPath(self: *Index, repo_dir: std.fs.Dir, path: []const u8) !void {
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
        const file = try repo_dir.openFile(path, .{ .mode = .read_only });
        defer file.close();
        const meta = try file.metadata();
        switch (meta.kind()) {
            std.fs.File.Kind.file => {
                // write the object
                var oid = [_]u8{0} ** hash.SHA1_BYTES_LEN;
                try object.writeBlobFromPath(self.allocator, repo_dir, path, &oid);
                // add the entry
                const times = getTimes(meta);
                const stat = try getStat(file);
                const entry = Index.Entry{
                    .ctime_secs = times.ctime_secs,
                    .ctime_nsecs = times.ctime_nsecs,
                    .mtime_secs = times.mtime_secs,
                    .mtime_nsecs = times.mtime_nsecs,
                    .dev = stat.dev,
                    .ino = stat.ino,
                    .mode = getMode(meta),
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
                var dir = try repo_dir.openIterableDir(path, .{});
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
                    try self.addPath(repo_dir, subpath);
                }
            },
            else => return,
        }
    }

    fn addEntry(self: *Index, entry: Entry) !void {
        try self.entries.put(entry.path, entry);

        var child = std.fs.path.basename(entry.path);
        var parent_path_maybe = std.fs.path.dirname(entry.path);

        while (parent_path_maybe) |parent_path| {
            // populate dir_to_children
            var children_maybe = self.dir_to_children.getEntry(parent_path);
            if (children_maybe) |children| {
                try children.value_ptr.*.put(child, {});
            } else {
                var children = std.StringArrayHashMap(void).init(self.allocator);
                try children.put(child, {});
                try self.dir_to_children.put(parent_path, children);
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

            child = std.fs.path.basename(parent_path);
            parent_path_maybe = std.fs.path.dirname(parent_path);
        }

        try self.root_children.put(child, {});
    }

    pub fn removePath(self: *Index, path: []const u8) void {
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

    pub fn removeChildren(self: *Index, path: []const u8) !void {
        var child_paths_maybe = self.dir_to_paths.getEntry(path);
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

    pub fn write(self: *Index, allocator: std.mem.Allocator, index_lock_file: std.fs.File) !void {
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
        try index_lock_file.writeAll(header);
        h.update(header);

        // write the entries
        for (self.entries.values()) |entry| {
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
            try writer.writeIntBig(u16, @as(u16, @bitCast(entry.flags)));
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
    }
};

fn getMode(meta: std.fs.File.Metadata) u32 {
    const is_executable = switch (builtin.os.tag) {
        .windows => false,
        else => meta.permissions().inner.unixHas(std.fs.File.PermissionsUnix.Class.user, .execute),
    };
    return if (is_executable) 100755 else 100644;
}

const Times = struct {
    ctime_secs: i32,
    ctime_nsecs: i32,
    mtime_secs: i32,
    mtime_nsecs: i32,
};

fn getTimes(meta: std.fs.File.Metadata) Times {
    const ctime = meta.created() orelse 0;
    const mtime = meta.modified();
    return Times{
        .ctime_secs = @intCast(@divTrunc(ctime, std.time.ns_per_s)),
        .ctime_nsecs = @intCast(@mod(ctime, std.time.ns_per_s)),
        .mtime_secs = @intCast(@divTrunc(mtime, std.time.ns_per_s)),
        .mtime_nsecs = @intCast(@mod(mtime, std.time.ns_per_s)),
    };
}

const Stat = struct {
    dev: u32,
    ino: u32,
    uid: u32,
    gid: u32,
};

fn getStat(file: std.fs.File) !Stat {
    switch (builtin.os.tag) {
        .windows => return .{
            .dev = 0,
            .ino = 0,
            .uid = 0,
            .gid = 0,
        },
        else => {
            const stat = try std.os.fstat(file.handle);
            return .{
                .dev = @intCast(stat.dev),
                .ino = @intCast(stat.ino),
                .uid = stat.uid,
                .gid = stat.gid,
            };
        },
    }
}

pub fn indexDiffersFromWorkspace(entry: Index.Entry, file: std.fs.File, meta: std.fs.File.Metadata) !bool {
    if (meta.size() != entry.file_size or getMode(meta) != entry.mode) {
        return true;
    } else {
        const times = getTimes(meta);
        if (times.ctime_secs != entry.ctime_secs or
            times.ctime_nsecs != entry.ctime_nsecs or
            times.mtime_secs != entry.mtime_secs or
            times.mtime_nsecs != entry.mtime_nsecs)
        {
            var oid = [_]u8{0} ** hash.SHA1_BYTES_LEN;
            try hash.sha1_file(file, &oid);
            if (!std.mem.eql(u8, &entry.oid, &oid)) {
                return true;
            }
        }
    }
    return false;
}

pub fn writeIndex(allocator: std.mem.Allocator, repo_dir: std.fs.Dir, paths: std.ArrayList([]const u8)) !void {
    // open git dir
    var git_dir = try repo_dir.openDir(".git", .{});
    defer git_dir.close();

    // create lock file
    var lock = try io.LockFile.init(allocator, git_dir, "index");
    defer lock.deinit();

    // read index
    var index = try Index.init(allocator, git_dir);
    defer index.deinit();

    // read all the new entries
    for (paths.items) |path| {
        const file = repo_dir.openFile(path, .{ .mode = .read_only }) catch |err| {
            if (err == error.FileNotFound and index.entries.contains(path)) {
                index.removePath(path);
                continue;
            } else {
                return err;
            }
        };
        defer file.close();
        try index.addPath(repo_dir, path);
    }

    try index.write(allocator, lock.lock_file);

    lock.success = true;
}
