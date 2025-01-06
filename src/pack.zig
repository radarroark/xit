const std = @import("std");
const hash = @import("./hash.zig");
const rp = @import("./repo.zig");
const obj = @import("./object.zig");

fn findOid(
    comptime hash_kind: hash.HashKind,
    idx_file: std.fs.File,
    oid_list_pos: u64,
    index: usize,
) ![hash.byteLen(hash_kind)]u8 {
    const reader = idx_file.reader();
    const oid_pos = oid_list_pos + (index * hash.byteLen(hash_kind));
    try idx_file.seekTo(oid_pos);
    return try reader.readBytesNoEof(hash.byteLen(hash_kind));
}

fn findObjectIndex(
    comptime hash_kind: hash.HashKind,
    idx_file: std.fs.File,
    fanout_table: [256]u32,
    oid_list_pos: u64,
    oid_bytes: *const [hash.byteLen(hash_kind)]u8,
) !?usize {
    var left: u32 = 0;
    var right = fanout_table[oid_bytes[0]];

    // binary search for the oid
    while (left < right) {
        const mid = left + ((right - left) / 2);
        const mid_oid_bytes = try findOid(hash_kind, idx_file, oid_list_pos, mid);
        if (std.mem.eql(u8, oid_bytes, &mid_oid_bytes)) {
            return mid;
        } else if (std.mem.lessThan(u8, oid_bytes, &mid_oid_bytes)) {
            if (mid == 0) {
                break;
            } else {
                right = mid - 1;
            }
        } else {
            if (left == fanout_table[oid_bytes[0]]) {
                break;
            } else {
                left = mid + 1;
            }
        }
    }

    const right_oid_bytes = try findOid(hash_kind, idx_file, oid_list_pos, right);
    if (std.mem.eql(u8, oid_bytes, &right_oid_bytes)) {
        return right;
    }

    return null;
}

fn findOffset(
    comptime hash_kind: hash.HashKind,
    idx_file: std.fs.File,
    fanout_table: [256]u32,
    oid_list_pos: u64,
    index: usize,
) !u64 {
    const reader = idx_file.reader();

    const entry_count = fanout_table[fanout_table.len - 1];
    const crc_size: u64 = 4;
    const offset_size: u64 = 4;
    const crc_list_pos = oid_list_pos + (entry_count * hash.byteLen(hash_kind));
    const offset_list_pos = crc_list_pos + (entry_count * crc_size);
    const offset_pos = offset_list_pos + (index * offset_size);

    try idx_file.seekTo(offset_pos);
    const offset: packed struct {
        value: u31,
        extra: bool,
    } = @bitCast(try reader.readInt(u32, .big));
    if (!offset.extra) {
        return offset.value;
    }

    const offset64_size: u64 = 8;
    const offset64_list_pos = offset_list_pos + (entry_count * offset_size);
    const offset64_pos = offset64_list_pos + (offset.value * offset64_size);

    try idx_file.seekTo(offset64_pos);
    return try reader.readInt(u64, .big);
}

fn searchPackIndex(
    comptime hash_kind: hash.HashKind,
    idx_file: std.fs.File,
    oid_bytes: *const [hash.byteLen(hash_kind)]u8,
) !?u64 {
    const reader = idx_file.reader();

    const header = try reader.readBytesNoEof(4);
    const version = if (!std.mem.eql(u8, &.{ 255, 116, 79, 99 }, &header)) 1 else try reader.readInt(u32, .big);
    if (version != 2) {
        return error.NotImplemented;
    }

    var fanout_table = [_]u32{0} ** 256;
    for (&fanout_table) |*entry| {
        entry.* = try reader.readInt(u32, .big);
    }
    const oid_list_pos = try idx_file.getPos();

    if (try findObjectIndex(hash_kind, idx_file, fanout_table, oid_list_pos, oid_bytes)) |index| {
        return try findOffset(hash_kind, idx_file, fanout_table, oid_list_pos, index);
    }

    return null;
}

fn PackOffset(comptime hash_kind: hash.HashKind) type {
    return struct {
        pack_id: [hash.hexLen(hash_kind)]u8,
        value: u64,
    };
}

fn searchPackIndexes(
    comptime hash_kind: hash.HashKind,
    pack_dir: std.fs.Dir,
    oid_hex: *const [hash.hexLen(hash_kind)]u8,
) !PackOffset(hash_kind) {
    const oid_bytes = try hash.hexToBytes(hash_kind, oid_hex.*);

    const prefix = "pack-";
    const suffix = ".idx";

    var iter = pack_dir.iterate();
    while (try iter.next()) |entry| {
        switch (entry.kind) {
            .file => {
                if (std.mem.startsWith(u8, entry.name, prefix) and std.mem.endsWith(u8, entry.name, suffix)) {
                    const pack_id = entry.name[prefix.len .. entry.name.len - suffix.len];

                    if (pack_id.len == hash.hexLen(hash_kind)) {
                        var idx_file = try pack_dir.openFile(entry.name, .{ .mode = .read_only });
                        defer idx_file.close();

                        if (try searchPackIndex(hash_kind, idx_file, &oid_bytes)) |offset| {
                            return .{
                                .pack_id = pack_id[0..comptime hash.hexLen(hash_kind)].*,
                                .value = offset,
                            };
                        }
                    }
                }
            },
            else => {},
        }
    }

    return error.ObjectNotFound;
}

pub fn PackObjectIterator(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        allocator: std.mem.Allocator,
        pack_file_path: []const u8,
        pack_file: std.fs.File,
        start_position: u64,
        object_count: u32,
        object_index: u32,
        pack_reader: PackObjectReader(repo_kind, repo_opts),

        pub fn init(allocator: std.mem.Allocator, pack_file_path: []const u8) !PackObjectIterator(repo_kind, repo_opts) {
            var pack_file = try std.fs.openFileAbsolute(pack_file_path, .{ .mode = .read_only });
            errdefer pack_file.close();
            const reader = pack_file.reader();

            // parse header
            const sig = try reader.readBytesNoEof(4);
            if (!std.mem.eql(u8, "PACK", &sig)) {
                return error.InvalidPackFileSig;
            }
            const version = try reader.readInt(u32, .big);
            if (version != 2) {
                return error.InvalidPackFileVersion;
            }
            const obj_count = try reader.readInt(u32, .big);

            return .{
                .allocator = allocator,
                .pack_file_path = pack_file_path,
                .pack_file = pack_file,
                .start_position = try pack_file.getPos(),
                .object_count = obj_count,
                .object_index = 0,
                .pack_reader = undefined,
            };
        }

        pub fn next(self: *PackObjectIterator(repo_kind, repo_opts)) !?*PackObjectReader(repo_kind, repo_opts) {
            if (self.object_index == self.object_count) {
                return null;
            }

            const start_position = self.start_position;

            var pack_reader = try PackObjectReader(repo_kind, repo_opts).initAtPosition(self.allocator, self.pack_file_path, start_position);
            errdefer pack_reader.deinit();

            // make sure the stream is at the end so the file position is correct
            while (try pack_reader.stream.next()) |_| {}

            self.start_position = try pack_reader.pack_file.getPos();
            self.object_index += 1;

            try pack_reader.reset();
            self.pack_reader = pack_reader;
            return &self.pack_reader;
        }

        pub fn deinit(self: *PackObjectIterator(repo_kind, repo_opts)) void {
            self.pack_file.close();
        }
    };
}

const PackObjectKind = enum(u3) {
    commit = 1,
    tree = 2,
    blob = 3,
    tag = 4,
    ofs_delta = 6,
    ref_delta = 7,
};

const PackObjectHeader = packed struct {
    size: u4,
    kind: PackObjectKind,
    extra: bool,
};

const ZlibStream = std.compress.flate.inflate.Decompressor(.zlib, std.fs.File.Reader);

pub fn PackObjectReader(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        pack_file: std.fs.File,
        stream: ZlibStream,
        start_position: u64,
        relative_position: u64,
        size: u64,
        internal: union(enum) {
            basic: struct {
                header: obj.ObjectHeader,
            },
            delta: struct {
                init: union(enum) {
                    ofs: struct {
                        pack_file_path: []const u8,
                        position: u64,
                    },
                    ref: struct {
                        oid_hex: [hash.hexLen(repo_opts.hash)]u8,
                    },
                },
                allocator: std.mem.Allocator,
                initialized: bool,
                base_reader: *PackObjectReader(repo_kind, repo_opts),
                chunk_index: usize,
                chunk_position: u64,
                real_position: u64,
                chunks: std.ArrayList(Chunk),
                cache: std.AutoArrayHashMap(Location, []const u8),
                cache_arena: *std.heap.ArenaAllocator,
                recon_size: u64,
            },
        },

        const Location = struct {
            offset: usize,
            size: usize,
        };

        const Chunk = struct {
            location: Location,
            kind: enum {
                add_new,
                copy_from_base,
            },
        };

        pub const Error = ZlibStream.Reader.Error || error{ Unseekable, UnexpectedEndOfStream, InvalidDeltaCache };

        pub fn init(allocator: std.mem.Allocator, core: *rp.Repo(repo_kind, repo_opts).Core, oid_hex: *const [hash.hexLen(repo_opts.hash)]u8) !PackObjectReader(repo_kind, repo_opts) {
            var pack_reader = try PackObjectReader(repo_kind, repo_opts).initWithIndex(allocator, core, oid_hex);
            errdefer pack_reader.deinit();

            // make a list of the chain of deltified objects,
            // and initialize each one. we can't do this during the initial
            // creation of the PackObjectReader because it would cause them
            // to be initialized recursively. since delta chains can get
            // really long, that can lead to a stack overflow.
            var delta_objects = std.ArrayList(*PackObjectReader(repo_kind, repo_opts)).init(allocator);
            defer delta_objects.deinit();
            var last_object = &pack_reader;
            while (last_object.internal == .delta) {
                try last_object.initDelta(allocator, core);
                try delta_objects.append(last_object);
                last_object = last_object.internal.delta.base_reader;
            }

            // initialize the cache for each deltified object, starting
            // with the one at the end of the chain. we need to cache
            // "copy_from_base" delta transformations for performance.
            // the base object could itself be a deltified object, so
            // trying to read the data on the fly could lead to a very
            // slow recursive descent into madness.
            for (0..delta_objects.items.len) |i| {
                const delta_object = delta_objects.items[delta_objects.items.len - i - 1];
                try delta_object.initCache();
            }

            return pack_reader;
        }

        pub fn initWithPath(allocator: std.mem.Allocator, pack_file_path: []const u8, oid_hex: *const [hash.hexLen(repo_opts.hash)]u8) !PackObjectReader(repo_kind, repo_opts) {
            var iter = try PackObjectIterator(repo_kind, repo_opts).init(allocator, pack_file_path);
            defer iter.deinit();

            while (try iter.next()) |pack_reader| {
                {
                    errdefer pack_reader.deinit();

                    // serialize object header
                    var header_bytes = [_]u8{0} ** 32;
                    const header_str = try obj.writeObjectHeader(pack_reader.header(), &header_bytes);

                    var oid = [_]u8{0} ** hash.byteLen(repo_opts.hash);
                    try hash.hashReader(repo_opts.hash, repo_opts.read_size, pack_reader, header_str, &oid);

                    if (std.mem.eql(u8, oid_hex, &std.fmt.bytesToHex(oid, .lower))) {
                        try pack_reader.reset();
                        return pack_reader.*;
                    }
                }

                pack_reader.deinit();
            }

            return error.ObjectNotFound;
        }

        fn initWithIndex(allocator: std.mem.Allocator, core: *rp.Repo(repo_kind, repo_opts).Core, oid_hex: *const [hash.hexLen(repo_opts.hash)]u8) !PackObjectReader(repo_kind, repo_opts) {
            var pack_dir = try core.git_dir.openDir("objects/pack", .{ .iterate = true });
            defer pack_dir.close();

            const pack_offset = try searchPackIndexes(repo_opts.hash, pack_dir, oid_hex);

            const pack_prefix = "pack-";
            const pack_suffix = ".pack";
            const pack_file_name_len = pack_prefix.len + comptime hash.hexLen(repo_opts.hash) + pack_suffix.len;

            var file_name_buf = [_]u8{0} ** pack_file_name_len;
            const file_name = try std.fmt.bufPrint(&file_name_buf, "{s}{s}{s}", .{ pack_prefix, pack_offset.pack_id, pack_suffix });

            const pack_file_path = try pack_dir.realpathAlloc(allocator, file_name);
            defer allocator.free(pack_file_path);

            var pack_file = try std.fs.openFileAbsolute(pack_file_path, .{ .mode = .read_only });
            defer pack_file.close();
            const reader = pack_file.reader();

            // parse header
            const sig = try reader.readBytesNoEof(4);
            if (!std.mem.eql(u8, "PACK", &sig)) {
                return error.InvalidPackFileSig;
            }
            const version = try reader.readInt(u32, .big);
            if (version != 2) {
                return error.InvalidPackFileVersion;
            }
            _ = try reader.readInt(u32, .big); // number of objects

            return try PackObjectReader(repo_kind, repo_opts).initAtPosition(allocator, pack_file_path, pack_offset.value);
        }

        fn initAtPosition(allocator: std.mem.Allocator, pack_file_path: []const u8, position: u64) !PackObjectReader(repo_kind, repo_opts) {
            var pack_file = try std.fs.openFileAbsolute(pack_file_path, .{ .mode = .read_only });
            errdefer pack_file.close();
            try pack_file.seekTo(position);
            const reader = pack_file.reader();

            // parse object header
            const obj_header: PackObjectHeader = @bitCast(try reader.readByte());

            // get size of object (little endian variable length format)
            var size: u64 = obj_header.size;
            {
                var shift: u6 = @bitSizeOf(@TypeOf(obj_header.size));
                var cont = obj_header.extra;
                while (cont) {
                    const next_byte: packed struct {
                        value: u7,
                        extra: bool,
                    } = @bitCast(try reader.readByte());
                    cont = next_byte.extra;
                    const value: u64 = next_byte.value;
                    size |= (value << shift);
                    shift += 7;
                }
            }

            switch (obj_header.kind) {
                .commit, .tree, .blob, .tag => {
                    const start_position = try pack_file.getPos();
                    return .{
                        .pack_file = pack_file,
                        .stream = std.compress.zlib.decompressor(reader),
                        .start_position = start_position,
                        .relative_position = 0,
                        .size = size,
                        .internal = .{
                            .basic = .{
                                .header = .{
                                    .kind = switch (obj_header.kind) {
                                        .commit => .commit,
                                        .tree => .tree,
                                        .blob => .blob,
                                        .tag => return error.UnsupportedObjectKind,
                                        else => unreachable,
                                    },
                                    .size = size,
                                },
                            },
                        },
                    };
                },
                .ofs_delta => {
                    // get offset (big endian variable length format)
                    var offset: u64 = 0;
                    {
                        while (true) {
                            const next_byte: packed struct {
                                value: u7,
                                extra: bool,
                            } = @bitCast(try reader.readByte());
                            offset = (offset << 7) | next_byte.value;
                            if (!next_byte.extra) {
                                break;
                            }
                            offset += 1; // "offset encoding" https://git-scm.com/docs/pack-format
                        }
                    }

                    const pack_file_path_copy = try allocator.dupe(u8, pack_file_path);
                    errdefer allocator.free(pack_file_path_copy);

                    const start_position = try pack_file.getPos();

                    return .{
                        .pack_file = pack_file,
                        .stream = undefined,
                        .start_position = start_position,
                        .relative_position = 0,
                        .size = size,
                        .internal = .{
                            .delta = .{
                                .init = .{
                                    .ofs = .{
                                        .pack_file_path = pack_file_path_copy,
                                        .position = position - offset,
                                    },
                                },
                                .allocator = allocator,
                                .initialized = false,
                                .base_reader = undefined,
                                .chunk_index = 0,
                                .chunk_position = 0,
                                .real_position = 0,
                                .chunks = undefined,
                                .cache = undefined,
                                .cache_arena = undefined,
                                .recon_size = undefined,
                            },
                        },
                    };
                },
                .ref_delta => {
                    const base_oid = try reader.readBytesNoEof(hash.byteLen(repo_opts.hash));

                    const start_position = try pack_file.getPos();

                    return .{
                        .pack_file = pack_file,
                        .stream = undefined,
                        .start_position = start_position,
                        .relative_position = 0,
                        .size = size,
                        .internal = .{
                            .delta = .{
                                .init = .{
                                    .ref = .{
                                        .oid_hex = std.fmt.bytesToHex(base_oid, .lower),
                                    },
                                },
                                .allocator = allocator,
                                .initialized = false,
                                .base_reader = undefined,
                                .chunk_index = 0,
                                .chunk_position = 0,
                                .real_position = 0,
                                .chunks = undefined,
                                .cache = undefined,
                                .cache_arena = undefined,
                                .recon_size = undefined,
                            },
                        },
                    };
                },
            }
        }

        fn initDelta(self: *PackObjectReader(repo_kind, repo_opts), allocator: std.mem.Allocator, core: *rp.Repo(repo_kind, repo_opts).Core) !void {
            const reader = self.pack_file.reader();

            const base_reader = try allocator.create(PackObjectReader(repo_kind, repo_opts));
            errdefer allocator.destroy(base_reader);
            base_reader.* = switch (self.internal.delta.init) {
                .ofs => |ofs| try PackObjectReader(repo_kind, repo_opts).initAtPosition(allocator, ofs.pack_file_path, ofs.position),
                .ref => |ref| try PackObjectReader(repo_kind, repo_opts).initWithIndex(allocator, core, &ref.oid_hex),
            };
            errdefer base_reader.deinit();

            var bytes_read: u64 = 0;

            var stream = std.compress.zlib.decompressor(reader);
            const zlib_reader = stream.reader();

            // get size of base object (little endian variable length format)
            var base_size: u64 = 0;
            {
                var shift: u6 = 0;
                var cont = true;
                while (cont) {
                    const next_byte: packed struct {
                        value: u7,
                        extra: bool,
                    } = @bitCast(try zlib_reader.readByte());
                    bytes_read += 1;
                    cont = next_byte.extra;
                    const value: u64 = next_byte.value;
                    base_size |= (value << shift);
                    shift += 7;
                }
            }

            // get size of reconstructed object (little endian variable length format)
            var recon_size: u64 = 0;
            {
                var shift: u6 = 0;
                var cont = true;
                while (cont) {
                    const next_byte: packed struct {
                        value: u7,
                        extra: bool,
                    } = @bitCast(try zlib_reader.readByte());
                    bytes_read += 1;
                    cont = next_byte.extra;
                    const value: u64 = next_byte.value;
                    recon_size |= (value << shift);
                    shift += 7;
                }
            }

            var chunks = std.ArrayList(Chunk).init(allocator);
            errdefer chunks.deinit();

            var cache = std.AutoArrayHashMap(Location, []const u8).init(allocator);
            errdefer cache.deinit();

            const cache_arena = try allocator.create(std.heap.ArenaAllocator);
            cache_arena.* = std.heap.ArenaAllocator.init(allocator);
            errdefer {
                cache_arena.deinit();
                allocator.destroy(cache_arena);
            }

            while (bytes_read < self.size) {
                const next_byte: packed struct {
                    value: u7,
                    high_bit: u1,
                } = @bitCast(try zlib_reader.readByte());
                bytes_read += 1;

                switch (next_byte.high_bit) {
                    // add new data
                    0 => {
                        if (next_byte.value == 0) { // reserved instruction
                            continue;
                        }
                        try chunks.append(.{
                            .location = .{
                                .offset = bytes_read,
                                .size = next_byte.value,
                            },
                            .kind = .add_new,
                        });
                        try zlib_reader.skipBytes(next_byte.value, .{});
                        bytes_read += next_byte.value;
                    },
                    // copy data
                    1 => {
                        var vals = [_]u8{0} ** 7;
                        var i: u3 = 0;
                        for (&vals) |*val| {
                            const mask: u7 = @as(u7, 1) << i;
                            i += 1;
                            if (next_byte.value & mask != 0) {
                                val.* = try zlib_reader.readByte();
                                bytes_read += 1;
                            }
                        }
                        const copy_offset = std.mem.readInt(u32, vals[0..4], .little);
                        const copy_size = std.mem.readInt(u24, vals[4..], .little);
                        const loc = Location{
                            .offset = copy_offset,
                            .size = if (copy_size == 0) 0x10000 else copy_size,
                        };
                        try chunks.append(.{
                            .location = loc,
                            .kind = .copy_from_base,
                        });
                        try cache.put(loc, "");
                    },
                }
            }

            const SortCtx = struct {
                keys: []Location,
                pub fn lessThan(ctx: @This(), a_index: usize, b_index: usize) bool {
                    const a_loc = ctx.keys[a_index];
                    const b_loc = ctx.keys[b_index];
                    if (a_loc.offset == b_loc.offset) {
                        return a_loc.size > b_loc.size;
                    }
                    return a_loc.offset < b_loc.offset;
                }
            };
            cache.sort(SortCtx{ .keys = cache.keys() });

            self.* = .{
                .pack_file = self.pack_file,
                .stream = stream,
                .start_position = self.start_position,
                .relative_position = bytes_read,
                .size = self.size,
                .internal = .{
                    .delta = .{
                        .init = self.internal.delta.init,
                        .allocator = allocator,
                        .initialized = true,
                        .base_reader = base_reader,
                        .chunk_index = 0,
                        .chunk_position = 0,
                        .real_position = bytes_read,
                        .chunks = chunks,
                        .cache = cache,
                        .cache_arena = cache_arena,
                        .recon_size = recon_size,
                    },
                },
            };
        }

        fn initCache(self: *PackObjectReader(repo_kind, repo_opts)) !void {
            const keys = self.internal.delta.cache.keys();
            const values = self.internal.delta.cache.values();
            for (keys, values, 0..) |location, *value, i| {
                // if the value is a subset of the previous value, just get a slice of it
                if (i > 0 and location.offset == keys[i - 1].offset and location.size < keys[i - 1].size) {
                    const last_buffer = values[i - 1];
                    value.* = last_buffer[0..location.size];
                    continue;
                }

                // seek the base reader to the correct position
                // TODO: can we avoid calling reset if position <= location.offset?
                // i tried that already but the cache was
                // getting messed up in rare cases for some reason.
                // currently, position is always 0 because we're always resetting,
                // but maybe in the future i can make it reset only when necessary.
                try self.internal.delta.base_reader.reset();
                const position = switch (self.internal.delta.base_reader.internal) {
                    .basic => self.internal.delta.base_reader.relative_position,
                    .delta => |delta| delta.real_position,
                };
                const bytes_to_skip = location.offset - position;
                try self.internal.delta.base_reader.skipBytes(bytes_to_skip);

                // read into the buffer and put it in the cache
                const buffer = try self.internal.delta.cache_arena.allocator().alloc(u8, location.size);
                var read_so_far: usize = 0;
                while (read_so_far < buffer.len) {
                    const amt = @min(buffer.len - read_so_far, 2048);
                    const read_size = try self.internal.delta.base_reader.read(buffer[read_so_far .. read_so_far + amt]);
                    if (read_size == 0) break;
                    read_so_far += read_size;
                }
                if (read_so_far != buffer.len) {
                    return error.UnexpectedEndOfStream;
                }
                value.* = buffer;
            }

            // now that the cache has been initialized, clear the cache in
            // the base object if necessary, because it won't be used anymore.
            switch (self.internal.delta.base_reader.internal) {
                .basic => {},
                .delta => |*delta| {
                    _ = delta.cache_arena.reset(.free_all);
                    delta.cache.clearAndFree();
                },
            }
        }

        pub fn deinit(self: *PackObjectReader(repo_kind, repo_opts)) void {
            self.pack_file.close();
            switch (self.internal) {
                .basic => {},
                .delta => |*delta| {
                    switch (delta.init) {
                        .ofs => |ofs| delta.allocator.free(ofs.pack_file_path),
                        .ref => {},
                    }
                    if (delta.initialized) {
                        delta.base_reader.deinit();
                        delta.allocator.destroy(delta.base_reader);
                        delta.chunks.deinit();
                        delta.cache.deinit();
                        delta.cache_arena.deinit();
                        delta.allocator.destroy(delta.cache_arena);
                    }
                },
            }
        }

        pub fn header(self: PackObjectReader(repo_kind, repo_opts)) obj.ObjectHeader {
            return switch (self.internal) {
                .basic => self.internal.basic.header,
                .delta => |delta| .{
                    .kind = delta.base_reader.header().kind,
                    .size = delta.recon_size,
                },
            };
        }

        pub fn reset(self: *PackObjectReader(repo_kind, repo_opts)) !void {
            try self.pack_file.seekTo(self.start_position);
            self.stream = std.compress.zlib.decompressor(self.pack_file.reader());
            self.relative_position = 0;

            switch (self.internal) {
                .basic => {},
                .delta => |*delta| {
                    delta.chunk_index = 0;
                    delta.chunk_position = 0;
                    delta.real_position = 0;
                    try delta.base_reader.reset();
                },
            }
        }

        pub fn read(self: *PackObjectReader(repo_kind, repo_opts), dest: []u8) !usize {
            switch (self.internal) {
                .basic => {
                    if (self.size < self.relative_position) return error.EndOfStream;
                    const size = try self.stream.reader().read(dest[0..@min(dest.len, self.size - self.relative_position)]);
                    self.relative_position += size;
                    return size;
                },
                .delta => |*delta| {
                    var bytes_read: usize = 0;
                    while (bytes_read < dest.len) {
                        if (delta.chunk_index == delta.chunks.items.len) {
                            break;
                        }
                        const chunk = delta.chunks.items[delta.chunk_index];
                        var dest_slice = dest[bytes_read..];
                        const bytes_to_read = @min(chunk.location.size - delta.chunk_position, dest_slice.len);
                        switch (chunk.kind) {
                            .add_new => {
                                const offset = chunk.location.offset + delta.chunk_position;
                                if (self.relative_position > offset) {
                                    try self.pack_file.seekTo(self.start_position);
                                    self.stream = std.compress.zlib.decompressor(self.pack_file.reader());
                                    self.relative_position = 0;
                                }
                                if (self.relative_position < offset) {
                                    const bytes_to_skip = offset - self.relative_position;
                                    try self.stream.reader().skipBytes(bytes_to_skip, .{});
                                    self.relative_position += bytes_to_skip;
                                }
                                const size = try self.stream.reader().read(dest_slice[0..bytes_to_read]);
                                // TODO: in rare cases this is not true....why?
                                //if (size != bytes_to_read) return error.UnexpectedEndOfStream;
                                self.relative_position += size;
                                bytes_read += size;
                                delta.chunk_position += size;
                                delta.real_position += size;
                            },
                            .copy_from_base => {
                                const buffer = delta.cache.get(chunk.location) orelse return error.InvalidDeltaCache;
                                @memcpy(dest_slice[0..bytes_to_read], buffer[delta.chunk_position .. delta.chunk_position + bytes_to_read]);
                                bytes_read += bytes_to_read;
                                delta.chunk_position += bytes_to_read;
                                delta.real_position += bytes_to_read;
                            },
                        }
                        if (delta.chunk_position == chunk.location.size) {
                            delta.chunk_index += 1;
                            delta.chunk_position = 0;
                        }
                    }
                    return bytes_read;
                },
            }
        }

        pub fn readNoEof(self: *PackObjectReader(repo_kind, repo_opts), dest: []u8) !void {
            var reader = std.io.GenericReader(*PackObjectReader(repo_kind, repo_opts), Error, PackObjectReader(repo_kind, repo_opts).read){
                .context = self,
            };
            try reader.readNoEof(dest);
        }

        pub fn readUntilDelimiter(self: *PackObjectReader(repo_kind, repo_opts), dest: []u8, delimiter: u8) ![]u8 {
            var reader = std.io.GenericReader(*PackObjectReader(repo_kind, repo_opts), Error, PackObjectReader(repo_kind, repo_opts).read){
                .context = self,
            };
            return reader.readUntilDelimiter(dest, delimiter) catch |err| switch (err) {
                error.StreamTooLong => return error.EndOfStream,
                else => |e| return e,
            };
        }

        pub fn readUntilDelimiterAlloc(self: *PackObjectReader(repo_kind, repo_opts), allocator: std.mem.Allocator, delimiter: u8, max_size: usize) ![]u8 {
            var reader = std.io.GenericReader(*PackObjectReader(repo_kind, repo_opts), Error, PackObjectReader(repo_kind, repo_opts).read){
                .context = self,
            };
            return reader.readUntilDelimiterAlloc(allocator, delimiter, max_size) catch |err| switch (err) {
                error.StreamTooLong => return error.EndOfStream,
                else => |e| return e,
            };
        }

        pub fn readAllAlloc(self: *PackObjectReader(repo_kind, repo_opts), allocator: std.mem.Allocator, max_size: usize) ![]u8 {
            var reader = std.io.GenericReader(*PackObjectReader(repo_kind, repo_opts), Error, PackObjectReader(repo_kind, repo_opts).read){
                .context = self,
            };
            return try reader.readAllAlloc(allocator, max_size);
        }

        pub fn readByte(self: *PackObjectReader(repo_kind, repo_opts)) !u8 {
            var reader = std.io.GenericReader(*PackObjectReader(repo_kind, repo_opts), Error, PackObjectReader(repo_kind, repo_opts).read){
                .context = self,
            };
            return try reader.readByte();
        }

        pub fn skipBytes(self: *PackObjectReader(repo_kind, repo_opts), num_bytes: u64) !void {
            var reader = std.io.GenericReader(*PackObjectReader(repo_kind, repo_opts), Error, PackObjectReader(repo_kind, repo_opts).read){
                .context = self,
            };
            try reader.skipBytes(num_bytes, .{});
        }
    };
}

pub fn LooseOrPackObjectReader(comptime repo_opts: rp.RepoOpts(.git)) type {
    return union(enum) {
        loose: struct {
            file: std.fs.File,
            stream: ZlibStream,
            header: obj.ObjectHeader,
        },
        pack: PackObjectReader(.git, repo_opts),

        pub const Error = PackObjectReader(.git, repo_opts).Error;

        pub fn init(allocator: std.mem.Allocator, core: *rp.Repo(.git, repo_opts).Core, oid_hex: *const [hash.hexLen(repo_opts.hash)]u8) !LooseOrPackObjectReader(repo_opts) {
            // open the objects dir
            var objects_dir = try core.git_dir.openDir("objects", .{});
            defer objects_dir.close();

            // open the object file
            var path_buf = [_]u8{0} ** (hash.hexLen(repo_opts.hash) + 1);
            const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ oid_hex[0..2], oid_hex[2..] });
            var object_file = objects_dir.openFile(path, .{ .mode = .read_only }) catch |err| switch (err) {
                error.FileNotFound => return .{
                    .pack = try PackObjectReader(.git, repo_opts).init(allocator, core, oid_hex),
                },
                else => |e| return e,
            };
            errdefer object_file.close();

            var stream = std.compress.zlib.decompressor(object_file.reader());
            const obj_header = try obj.readObjectHeader(stream.reader());

            return .{
                .loose = .{
                    .file = object_file,
                    .stream = stream,
                    .header = obj_header,
                },
            };
        }

        pub fn deinit(self: *LooseOrPackObjectReader(repo_opts)) void {
            switch (self.*) {
                .loose => self.loose.file.close(),
                .pack => self.pack.deinit(),
            }
        }

        pub fn header(self: LooseOrPackObjectReader(repo_opts)) obj.ObjectHeader {
            return switch (self) {
                .loose => self.loose.header,
                .pack => self.pack.header(),
            };
        }

        pub fn reset(self: *LooseOrPackObjectReader(repo_opts)) !void {
            switch (self.*) {
                .loose => {
                    try self.loose.file.seekTo(0);
                    self.loose.stream = std.compress.zlib.decompressor(self.loose.file.reader());
                    try self.loose.stream.reader().skipUntilDelimiterOrEof(0);
                },
                .pack => try self.pack.reset(),
            }
        }

        pub fn read(self: *LooseOrPackObjectReader(repo_opts), dest: []u8) !usize {
            switch (self.*) {
                .loose => return try self.loose.stream.reader().read(dest),
                .pack => return try self.pack.read(dest),
            }
        }

        pub fn readNoEof(self: *LooseOrPackObjectReader(repo_opts), dest: []u8) !void {
            switch (self.*) {
                .loose => try self.loose.stream.reader().readNoEof(dest),
                .pack => try self.pack.readNoEof(dest),
            }
        }

        pub fn readUntilDelimiter(self: *LooseOrPackObjectReader(repo_opts), dest: []u8, delimiter: u8) ![]u8 {
            switch (self.*) {
                .loose => return try self.loose.stream.reader().readUntilDelimiter(dest, delimiter),
                .pack => return try self.pack.readUntilDelimiter(dest, delimiter),
            }
        }

        pub fn readUntilDelimiterAlloc(self: *LooseOrPackObjectReader(repo_opts), allocator: std.mem.Allocator, delimiter: u8, max_size: usize) ![]u8 {
            switch (self.*) {
                .loose => return try self.loose.stream.reader().readUntilDelimiterAlloc(allocator, delimiter, max_size),
                .pack => return try self.pack.readUntilDelimiterAlloc(allocator, delimiter, max_size),
            }
        }

        pub fn readAllAlloc(self: *LooseOrPackObjectReader(repo_opts), allocator: std.mem.Allocator, max_size: usize) ![]u8 {
            switch (self.*) {
                .loose => return try self.loose.stream.reader().readAllAlloc(allocator, max_size),
                .pack => return try self.pack.readAllAlloc(allocator, max_size),
            }
        }

        pub fn readByte(self: *LooseOrPackObjectReader(repo_opts)) !u8 {
            switch (self.*) {
                .loose => return try self.loose.stream.reader().readByte(),
                .pack => return try self.pack.readByte(),
            }
        }

        pub fn skipBytes(self: *LooseOrPackObjectReader(repo_opts), num_bytes: u64) !void {
            switch (self.*) {
                .loose => try self.loose.stream.reader().skipBytes(num_bytes, .{}),
                .pack => try self.pack.skipBytes(num_bytes),
            }
        }
    };
}

pub fn PackObjectWriter(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        allocator: std.mem.Allocator,
        objects: std.ArrayList(obj.Object(repo_kind, repo_opts, .raw)),
        object_index: usize,
        out_bytes: std.ArrayList(u8),
        out_index: usize,
        mode: union(enum) {
            header,
            object: struct {
                stream: ?std.compress.flate.deflate.Compressor(.zlib, std.ArrayList(u8).Writer),
            },
        },

        pub fn init(allocator: std.mem.Allocator, obj_iter: *obj.ObjectIterator(repo_kind, repo_opts, .raw)) !PackObjectWriter(repo_kind, repo_opts) {
            var self = PackObjectWriter(repo_kind, repo_opts){
                .allocator = allocator,
                .objects = std.ArrayList(obj.Object(repo_kind, repo_opts, .raw)).init(allocator),
                .object_index = 0,
                .out_bytes = std.ArrayList(u8).init(allocator),
                .out_index = 0,
                .mode = .header,
            };
            errdefer self.deinit();

            while (try obj_iter.next()) |object| {
                errdefer object.deinit();
                try self.objects.append(object.*);
            }

            const writer = self.out_bytes.writer();
            _ = try writer.write("PACK");
            try writer.writeInt(u32, 2, .big); // version
            try writer.writeInt(u32, @intCast(self.objects.items.len), .big);

            if (self.objects.items.len > 0) {
                try self.writeObjectHeader();
            }

            return self;
        }

        pub fn deinit(self: *PackObjectWriter(repo_kind, repo_opts)) void {
            for (self.objects.items) |*object| {
                object.deinit();
            }
            self.objects.deinit();
            self.out_bytes.deinit();
        }

        pub fn read(self: *PackObjectWriter(repo_kind, repo_opts), buffer: []u8) !usize {
            var size: usize = 0;
            while (size < buffer.len and self.object_index < self.objects.items.len) {
                size += try self.readStep(buffer[size..]);
            }
            return size;
        }

        fn readStep(self: *PackObjectWriter(repo_kind, repo_opts), buffer: []u8) !usize {
            switch (self.mode) {
                .header => {
                    const size = @min(self.out_bytes.items.len - self.out_index, buffer.len);
                    @memcpy(buffer[0..size], self.out_bytes.items[self.out_index .. self.out_index + size]);
                    if (size < buffer.len) {
                        self.out_bytes.clearAndFree();
                        self.out_index = 0;
                        self.mode = .{
                            .object = .{
                                .stream = try std.compress.zlib.compressor(self.out_bytes.writer(), .{ .level = .default }),
                            },
                        };
                    } else {
                        self.out_index += size;
                    }
                    return size;
                },
                .object => |*o| {
                    if (self.out_index < self.out_bytes.items.len) {
                        const size = @min(self.out_bytes.items.len - self.out_index, buffer.len);
                        @memcpy(buffer[0..size], self.out_bytes.items[self.out_index .. self.out_index + size]);
                        self.out_index += size;
                        return size;
                    } else {
                        // everything in out_bytes has been written, so we can clear it
                        self.out_bytes.clearAndFree();
                        self.out_index = 0;

                        if (o.stream) |*stream| {
                            const object = &self.objects.items[self.object_index];
                            var temp_buffer = [_]u8{0} ** 1024;
                            const uncompressed_size = try object.object_reader.reader.read(&temp_buffer);

                            if (uncompressed_size > 0) {
                                // write to out_bytes and return so we can read it next
                                // time this fn is called
                                _ = try stream.write(temp_buffer[0..uncompressed_size]);
                                return 0;
                            } else {
                                try stream.finish();
                                o.stream = null;
                                // if finish() added more data to out_bytes,
                                // return so we can read it next time this fn is called
                                if (self.out_index < self.out_bytes.items.len) {
                                    return 0;
                                }
                            }
                        }

                        // there is nothing more to write, so move on to the next object
                        self.object_index += 1;
                        self.mode = .header;
                        if (self.object_index < self.objects.items.len) {
                            try self.writeObjectHeader();
                        }
                        return 0;
                    }
                },
            }
        }

        fn writeObjectHeader(self: *PackObjectWriter(repo_kind, repo_opts)) !void {
            const object = self.objects.items[self.object_index];
            const size = object.len;

            const first_size_parts: packed struct {
                low_bits: u4,
                high_bits: u60,
            } = @bitCast(size);

            const obj_header = PackObjectHeader{
                .size = first_size_parts.low_bits,
                .kind = switch (object.content) {
                    .blob => .blob,
                    .tree => .tree,
                    .commit => .commit,
                },
                .extra = first_size_parts.high_bits > 0,
            };

            const writer = self.out_bytes.writer();
            try writer.writeByte(@bitCast(obj_header));

            // set size of object (little endian variable length format)
            var next_size = first_size_parts.high_bits;
            while (next_size > 0) {
                const size_parts: packed struct {
                    low_bits: u7,
                    high_bits: u53,
                } = @bitCast(next_size);
                const next_byte: packed struct {
                    value: u7,
                    extra: bool,
                } = .{
                    .value = size_parts.low_bits,
                    .extra = size_parts.high_bits > 0,
                };
                try writer.writeByte(@bitCast(next_byte));
                next_size = size_parts.high_bits;
            }
        }
    };
}
