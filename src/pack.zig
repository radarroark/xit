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

        pub fn next(self: *PackObjectIterator(repo_kind, repo_opts), state: rp.Repo(repo_kind, repo_opts).State(.read_only)) !?*PackObjectReader(repo_kind, repo_opts) {
            if (self.object_index == self.object_count) {
                return null;
            }

            const start_position = self.start_position;

            var pack_reader = try PackObjectReader(repo_kind, repo_opts).initAtPosition(self.allocator, self.pack_file_path, start_position);
            errdefer pack_reader.deinit(self.allocator);

            switch (pack_reader.internal) {
                .basic => {},
                .delta => try pack_reader.initDeltaAndCache(self.allocator, state),
            }

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

/// used as the type for base objects within delta objects. this is necessary
/// because ref delta objects just contain an oid and must be looked up in
/// the backend's object store. for the xit backend, that means it needs to
/// look it up in the chunk object store. the git backend will never do that,
/// which is why you see all those `unreachable`s.
fn PackOrChunkObjectReader(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return union(enum) {
        pack: PackObjectReader(repo_kind, repo_opts),
        chunk: ChunkObjectReader,

        const ChunkObjectReader = switch (repo_kind) {
            .git => void,
            .xit => @import("./chunk.zig").ChunkObjectReader(repo_opts),
        };

        const Error = switch (repo_kind) {
            .git => error{},
            .xit => ChunkObjectReader.Error,
        };

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            switch (self.*) {
                .pack => |*pack| pack.deinit(allocator),
                .chunk => |*chunk_reader| switch (repo_kind) {
                    .git => unreachable,
                    .xit => chunk_reader.deinit(allocator),
                },
            }
        }

        pub fn header(self: *const @This()) obj.ObjectHeader {
            return switch (self.*) {
                .pack => |*pack| pack.header(),
                .chunk => |*chunk_reader| switch (repo_kind) {
                    .git => unreachable,
                    .xit => chunk_reader.header,
                },
            };
        }

        pub fn reset(self: *@This()) anyerror!void {
            switch (self.*) {
                .pack => |*pack| try pack.reset(),
                .chunk => |*chunk_reader| switch (repo_kind) {
                    .git => unreachable,
                    .xit => try chunk_reader.reset(),
                },
            }
        }

        pub fn position(self: *const @This()) u64 {
            return switch (self.*) {
                .pack => |*pack| switch (pack.internal) {
                    .basic => pack.relative_position,
                    .delta => |delta| if (delta.state) |base_delta_state|
                        base_delta_state.real_position
                    else
                        unreachable,
                },
                .chunk => |*chunk_reader| switch (repo_kind) {
                    .git => unreachable,
                    .xit => chunk_reader.position,
                },
            };
        }

        pub fn skipBytes(self: *@This(), num_bytes: u64) !void {
            switch (self.*) {
                .pack => |*pack| try pack.skipBytes(num_bytes),
                .chunk => |*chunk_reader| switch (repo_kind) {
                    .git => unreachable,
                    .xit => try chunk_reader.skipBytes(num_bytes),
                },
            }
        }

        pub fn read(self: *@This(), buf: []u8) !usize {
            return switch (self.*) {
                .pack => |*pack| try pack.read(buf),
                .chunk => |*chunk_reader| switch (repo_kind) {
                    .git => unreachable,
                    .xit => try chunk_reader.read(buf),
                },
            };
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
                state: ?struct {
                    base_reader: *PackOrChunkObjectReader(repo_kind, repo_opts),
                    chunk_index: usize,
                    chunk_position: u64,
                    real_position: u64,
                    chunks: std.ArrayList(DeltaChunk),
                    cache: std.AutoArrayHashMap(Location, []const u8),
                    cache_arena: *std.heap.ArenaAllocator,
                    recon_size: u64,
                },
            },
        },

        const Location = struct {
            offset: usize,
            size: usize,
        };

        const DeltaChunk = struct {
            location: Location,
            kind: enum {
                add_new,
                copy_from_base,
            },
        };

        pub const Error = ZlibStream.Reader.Error || PackOrChunkObjectReader(repo_kind, repo_opts).Error || error{ Unseekable, UnexpectedEndOfStream, InvalidDeltaCache };

        pub fn init(
            allocator: std.mem.Allocator,
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            oid_hex: *const [hash.hexLen(repo_opts.hash)]u8,
        ) !PackObjectReader(repo_kind, repo_opts) {
            var pack_reader = try PackObjectReader(repo_kind, repo_opts).initWithIndex(allocator, state.core, oid_hex);
            errdefer pack_reader.deinit(allocator);
            try pack_reader.initDeltaAndCache(allocator, state);
            return pack_reader;
        }

        pub fn initWithPath(
            allocator: std.mem.Allocator,
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            pack_file_path: []const u8,
            oid_hex: *const [hash.hexLen(repo_opts.hash)]u8,
        ) !PackObjectReader(repo_kind, repo_opts) {
            var iter = try PackObjectIterator(repo_kind, repo_opts).init(allocator, pack_file_path);
            defer iter.deinit();

            while (try iter.next(state)) |pack_reader| {
                {
                    errdefer pack_reader.deinit(allocator);

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

                pack_reader.deinit(allocator);
            }

            return error.ObjectNotFound;
        }

        fn initWithIndex(allocator: std.mem.Allocator, core: *rp.Repo(repo_kind, repo_opts).Core, oid_hex: *const [hash.hexLen(repo_opts.hash)]u8) !PackObjectReader(repo_kind, repo_opts) {
            var pack_dir = try core.repo_dir.openDir("objects/pack", .{ .iterate = true });
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
                                        .tag => .tag,
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
                                .state = null,
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
                                .state = null,
                            },
                        },
                    };
                },
            }
        }

        fn initDeltaAndCache(
            self: *PackObjectReader(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
        ) !void {
            // make a list of the chain of deltified objects,
            // and initialize each one. we can't do this during the initial
            // creation of the PackObjectReader because it would cause them
            // to be initialized recursively. since delta chains can get
            // really long, that can lead to a stack overflow.
            var delta_objects = std.ArrayList(*PackObjectReader(repo_kind, repo_opts)).init(allocator);
            defer delta_objects.deinit();
            var last_object = self;
            while (last_object.internal == .delta) {
                try last_object.initDelta(allocator, state);
                try delta_objects.append(last_object);
                last_object = if (last_object.internal.delta.state) |delta_state|
                    switch (delta_state.base_reader.*) {
                        .pack => |*pack| pack,
                        .chunk => break,
                    }
                else
                    // delta object wasn't initialized
                    unreachable;
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
        }

        fn initDelta(
            self: *PackObjectReader(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
        ) !void {
            const reader = self.pack_file.reader();

            const base_reader = try allocator.create(PackOrChunkObjectReader(repo_kind, repo_opts));
            errdefer allocator.destroy(base_reader);

            base_reader.* = switch (self.internal.delta.init) {
                .ofs => |ofs| .{ .pack = try PackObjectReader(repo_kind, repo_opts).initAtPosition(allocator, ofs.pack_file_path, ofs.position) },
                .ref => |ref| switch (repo_kind) {
                    .git => .{ .pack = try PackObjectReader(repo_kind, repo_opts).initWithIndex(allocator, state.core, &ref.oid_hex) },
                    .xit => .{ .chunk = try PackOrChunkObjectReader(repo_kind, repo_opts).ChunkObjectReader.init(allocator, state, &ref.oid_hex) },
                },
            };
            errdefer base_reader.deinit(allocator);

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

            var chunks = std.ArrayList(DeltaChunk).init(allocator);
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
                        .state = .{
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
                },
            };
        }

        fn initCache(self: *PackObjectReader(repo_kind, repo_opts)) !void {
            const delta_state = if (self.internal.delta.state) |*state| state else unreachable;
            const keys = delta_state.cache.keys();
            const values = delta_state.cache.values();
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
                try delta_state.base_reader.reset();
                const position = delta_state.base_reader.position();
                const bytes_to_skip = location.offset - position;
                try delta_state.base_reader.skipBytes(bytes_to_skip);

                // read into the buffer and put it in the cache
                const buffer = try delta_state.cache_arena.allocator().alloc(u8, location.size);
                var read_so_far: usize = 0;
                while (read_so_far < buffer.len) {
                    const amt = @min(buffer.len - read_so_far, 2048);
                    const read_size = try delta_state.base_reader.read(buffer[read_so_far .. read_so_far + amt]);
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
            switch (delta_state.base_reader.*) {
                .pack => |*pack| switch (pack.internal) {
                    .basic => {},
                    .delta => |*delta| {
                        const base_delta_state = if (delta.state) |*state| state else unreachable;
                        _ = base_delta_state.cache_arena.reset(.free_all);
                        base_delta_state.cache.clearAndFree();
                    },
                },
                .chunk => {},
            }
        }

        pub fn deinit(self: *PackObjectReader(repo_kind, repo_opts), allocator: std.mem.Allocator) void {
            self.pack_file.close();
            switch (self.internal) {
                .basic => {},
                .delta => |*delta| {
                    switch (delta.init) {
                        .ofs => |ofs| allocator.free(ofs.pack_file_path),
                        .ref => {},
                    }
                    if (delta.state) |*state| {
                        state.base_reader.deinit(allocator);
                        allocator.destroy(state.base_reader);
                        state.chunks.deinit();
                        state.cache.deinit();
                        state.cache_arena.deinit();
                        allocator.destroy(state.cache_arena);
                    }
                },
            }
        }

        pub fn header(self: PackObjectReader(repo_kind, repo_opts)) obj.ObjectHeader {
            return switch (self.internal) {
                .basic => self.internal.basic.header,
                .delta => |delta| if (delta.state) |delta_state| .{
                    .kind = delta_state.base_reader.header().kind,
                    .size = delta_state.recon_size,
                } else unreachable,
            };
        }

        pub fn reset(self: *PackObjectReader(repo_kind, repo_opts)) !void {
            try self.pack_file.seekTo(self.start_position);
            self.stream = std.compress.zlib.decompressor(self.pack_file.reader());
            self.relative_position = 0;

            switch (self.internal) {
                .basic => {},
                .delta => |*delta| if (delta.state) |*state| {
                    state.chunk_index = 0;
                    state.chunk_position = 0;
                    state.real_position = 0;
                    try state.base_reader.reset();
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
                    const delta_state = if (delta.state) |*state| state else unreachable;
                    var bytes_read: usize = 0;
                    while (bytes_read < dest.len) {
                        if (delta_state.chunk_index == delta_state.chunks.items.len) {
                            break;
                        }
                        const delta_chunk = delta_state.chunks.items[delta_state.chunk_index];
                        var dest_slice = dest[bytes_read..];
                        const bytes_to_read = @min(delta_chunk.location.size - delta_state.chunk_position, dest_slice.len);
                        switch (delta_chunk.kind) {
                            .add_new => {
                                const offset = delta_chunk.location.offset + delta_state.chunk_position;
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
                                delta_state.chunk_position += size;
                                delta_state.real_position += size;
                            },
                            .copy_from_base => {
                                const buffer = delta_state.cache.get(delta_chunk.location) orelse return error.InvalidDeltaCache;
                                @memcpy(dest_slice[0..bytes_to_read], buffer[delta_state.chunk_position .. delta_state.chunk_position + bytes_to_read]);
                                bytes_read += bytes_to_read;
                                delta_state.chunk_position += bytes_to_read;
                                delta_state.real_position += bytes_to_read;
                            },
                        }
                        if (delta_state.chunk_position == delta_chunk.location.size) {
                            delta_state.chunk_index += 1;
                            delta_state.chunk_position = 0;
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

        pub fn init(
            allocator: std.mem.Allocator,
            state: rp.Repo(.git, repo_opts).State(.read_only),
            oid_hex: *const [hash.hexLen(repo_opts.hash)]u8,
        ) !LooseOrPackObjectReader(repo_opts) {
            // open the objects dir
            var objects_dir = try state.core.repo_dir.openDir("objects", .{});
            defer objects_dir.close();

            // open the object file
            var path_buf = [_]u8{0} ** (hash.hexLen(repo_opts.hash) + 1);
            const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ oid_hex[0..2], oid_hex[2..] });
            var object_file = objects_dir.openFile(path, .{ .mode = .read_only }) catch |err| switch (err) {
                error.FileNotFound => return .{
                    .pack = try PackObjectReader(.git, repo_opts).init(allocator, state, oid_hex),
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

        pub fn deinit(self: *LooseOrPackObjectReader(repo_opts), allocator: std.mem.Allocator) void {
            switch (self.*) {
                .loose => self.loose.file.close(),
                .pack => self.pack.deinit(allocator),
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
        hasher: hash.Hasher(repo_opts.hash),
        mode: union(enum) {
            header,
            object: struct {
                stream: ?std.compress.flate.deflate.Compressor(.zlib, std.ArrayList(u8).Writer),
            },
            footer,
            finished,
        },

        pub fn init(allocator: std.mem.Allocator, obj_iter: *obj.ObjectIterator(repo_kind, repo_opts, .raw)) !?PackObjectWriter(repo_kind, repo_opts) {
            var self = PackObjectWriter(repo_kind, repo_opts){
                .allocator = allocator,
                .objects = std.ArrayList(obj.Object(repo_kind, repo_opts, .raw)).init(allocator),
                .object_index = 0,
                .out_bytes = std.ArrayList(u8).init(allocator),
                .out_index = 0,
                .hasher = hash.Hasher(repo_opts.hash).init(),
                .mode = .header,
            };
            errdefer self.deinit();

            while (try obj_iter.next()) |object| {
                errdefer object.deinit();
                try self.objects.append(object.*);
            }

            if (self.objects.items.len == 0) {
                return null;
            }

            const writer = self.out_bytes.writer();
            _ = try writer.write("PACK");
            try writer.writeInt(u32, 2, .big); // version
            try writer.writeInt(u32, @intCast(self.objects.items.len), .big);

            try self.writeObjectHeader();

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
            while (size < buffer.len and .finished != self.mode) {
                size += try self.readStep(buffer[size..]);
            }
            return size;
        }

        fn readStep(self: *PackObjectWriter(repo_kind, repo_opts), buffer: []u8) !usize {
            switch (self.mode) {
                .header => {
                    const size = @min(self.out_bytes.items.len - self.out_index, buffer.len);
                    @memcpy(buffer[0..size], self.out_bytes.items[self.out_index .. self.out_index + size]);
                    self.hasher.update(buffer[0..size]);
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
                        self.hasher.update(buffer[0..size]);
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
                        if (self.object_index < self.objects.items.len) {
                            self.mode = .header;
                            try self.writeObjectHeader();
                        } else {
                            self.mode = .footer;
                            var hash_buffer = [_]u8{0} ** hash.byteLen(repo_opts.hash);
                            self.hasher.final(&hash_buffer);
                            try self.out_bytes.appendSlice(&hash_buffer);
                        }
                        return 0;
                    }
                },
                .footer => {
                    const size = @min(self.out_bytes.items.len - self.out_index, buffer.len);
                    @memcpy(buffer[0..size], self.out_bytes.items[self.out_index .. self.out_index + size]);
                    if (size < buffer.len) {
                        self.out_bytes.clearAndFree();
                        self.out_index = 0;
                        self.mode = .finished;
                    } else {
                        self.out_index += size;
                    }
                    return size;
                },
                .finished => return 0,
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
                    .tag => .tag,
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
