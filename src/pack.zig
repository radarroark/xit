const std = @import("std");
const hash = @import("./hash.zig");
const rp = @import("./repo.zig");
const compress = @import("./compress.zig");
const obj = @import("./object.zig");

fn findOid(idx_file: std.fs.File, oid_list_pos: u64, index: usize) ![hash.SHA1_BYTES_LEN]u8 {
    const reader = idx_file.reader();
    const oid_pos = oid_list_pos + (index * hash.SHA1_BYTES_LEN);
    try idx_file.seekTo(oid_pos);
    return try reader.readBytesNoEof(hash.SHA1_BYTES_LEN);
}

fn findObjectIndex(idx_file: std.fs.File, fanout_table: [256]u32, oid_list_pos: u64, oid_bytes: [hash.SHA1_BYTES_LEN]u8) !?usize {
    var left: u32 = 0;
    var right = fanout_table[oid_bytes[0]];

    // binary search for the oid
    while (left < right) {
        const mid = left + ((right - left) / 2);
        const mid_oid_bytes = try findOid(idx_file, oid_list_pos, mid);
        if (std.mem.eql(u8, &oid_bytes, &mid_oid_bytes)) {
            return mid;
        } else if (std.mem.lessThan(u8, &oid_bytes, &mid_oid_bytes)) {
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

    const right_oid_bytes = try findOid(idx_file, oid_list_pos, right);
    if (std.mem.eql(u8, &oid_bytes, &right_oid_bytes)) {
        return right;
    }

    return null;
}

fn findOffset(idx_file: std.fs.File, fanout_table: [256]u32, oid_list_pos: u64, index: usize) !u64 {
    const reader = idx_file.reader();

    const entry_count = fanout_table[fanout_table.len - 1];
    const crc_size: u64 = 4;
    const offset_size: u64 = 4;
    const crc_list_pos = oid_list_pos + (entry_count * hash.SHA1_BYTES_LEN);
    const offset_list_pos = crc_list_pos + (entry_count * crc_size);
    const offset_pos = offset_list_pos + (index * offset_size);

    try idx_file.seekTo(offset_pos);
    const offset: packed struct {
        value: u31,
        high_bit: u1,
    } = @bitCast(try reader.readInt(u32, .big));
    if (offset.high_bit == 0) {
        return offset.value;
    }

    const offset64_size: u64 = 8;
    const offset64_list_pos = offset_list_pos + (entry_count * offset_size);
    const offset64_pos = offset64_list_pos + (offset.value * offset64_size);

    try idx_file.seekTo(offset64_pos);
    return try reader.readInt(u64, .big);
}

fn searchPackIndex(idx_file: std.fs.File, oid_bytes: [hash.SHA1_BYTES_LEN]u8) !?u64 {
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

    if (try findObjectIndex(idx_file, fanout_table, oid_list_pos, oid_bytes)) |index| {
        return try findOffset(idx_file, fanout_table, oid_list_pos, index);
    }

    return null;
}

const PackOffset = struct {
    pack_id: [hash.SHA1_HEX_LEN]u8,
    value: u64,
};

fn searchPackIndexes(pack_dir: std.fs.Dir, oid_hex: [hash.SHA1_HEX_LEN]u8) !PackOffset {
    const oid_bytes = try hash.hexToBytes(oid_hex);

    const prefix = "pack-";
    const suffix = ".idx";

    var iter = pack_dir.iterate();
    while (try iter.next()) |entry| {
        switch (entry.kind) {
            .file => {
                if (std.mem.startsWith(u8, entry.name, prefix) and std.mem.endsWith(u8, entry.name, suffix)) {
                    const pack_id = entry.name[prefix.len .. entry.name.len - suffix.len];

                    if (pack_id.len == hash.SHA1_HEX_LEN) {
                        var idx_file = try pack_dir.openFile(entry.name, .{ .mode = .read_only });
                        defer idx_file.close();

                        if (try searchPackIndex(idx_file, oid_bytes)) |offset| {
                            return .{
                                .pack_id = pack_id[0..hash.SHA1_HEX_LEN].*,
                                .value = offset,
                            };
                        }
                    }
                }
            },
            else => {},
        }
    }

    return error.PackObjectNotFound;
}

pub const PackObjectReader = struct {
    pack_file: std.fs.File,
    stream: compress.ZlibStream,
    start_position: u64,
    relative_position: u64,
    internal: union(enum) {
        basic: struct {
            size: u64,
            header: obj.ObjectHeader,
        },
        delta: struct {
            allocator: std.mem.Allocator,
            base_reader: *PackObjectReader,
            chunk_index: usize,
            chunk_position: u64,
            real_position: u64,
            chunks: std.ArrayList(Chunk),
            cache: std.AutoArrayHashMap(Location, []const u8),
            cache_arena: *std.heap.ArenaAllocator,
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

    pub const Error = compress.ZlibStream.Reader.Error || error{ Unseekable, UnexpectedEndOfStream };

    pub fn init(allocator: std.mem.Allocator, core: *rp.Repo(.git).Core, oid_hex: [hash.SHA1_HEX_LEN]u8) !PackObjectReader {
        var pack_reader = try PackObjectReader.initWithOid(allocator, core, oid_hex);
        var delta_objects = std.ArrayList(*PackObjectReader).init(allocator);
        defer delta_objects.deinit();
        var last_object = &pack_reader;
        while (last_object.internal == .delta) {
            try delta_objects.append(last_object);
            last_object = last_object.internal.delta.base_reader;
        }
        for (0..delta_objects.items.len) |i| {
            const delta_object = delta_objects.items[delta_objects.items.len - i - 1];
            try delta_object.initCache();
        }
        return pack_reader;
    }

    fn initCache(self: *PackObjectReader) !void {
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
            var position = switch (self.internal.delta.base_reader.internal) {
                .basic => self.internal.delta.base_reader.relative_position,
                .delta => self.internal.delta.base_reader.internal.delta.real_position,
            };
            if (position > location.offset) {
                try self.internal.delta.base_reader.reset();
                position = switch (self.internal.delta.base_reader.internal) {
                    .basic => self.internal.delta.base_reader.relative_position,
                    .delta => self.internal.delta.base_reader.internal.delta.real_position,
                };
            }
            if (position < location.offset) {
                const bytes_to_skip = location.offset - position;
                try self.internal.delta.base_reader.skipBytes(bytes_to_skip);
            }

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
    }

    fn initWithOid(allocator: std.mem.Allocator, core: *rp.Repo(.git).Core, oid_hex: [hash.SHA1_HEX_LEN]u8) !PackObjectReader {
        var pack_dir = try core.git_dir.openDir("objects/pack", .{ .iterate = true });
        defer pack_dir.close();

        const pack_offset = try searchPackIndexes(pack_dir, oid_hex);

        const prefix = "pack-";
        const suffix = ".pack";

        var file_name_buf = [_]u8{0} ** (prefix.len + hash.SHA1_HEX_LEN + suffix.len);
        const file_name = try std.fmt.bufPrint(&file_name_buf, "{s}{s}{s}", .{ prefix, pack_offset.pack_id, suffix });

        var pack_file = try pack_dir.openFile(file_name, .{ .mode = .read_only });
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

        return try PackObjectReader.initAtPosition(allocator, core, pack_dir, file_name, pack_offset.value);
    }

    fn initAtPosition(allocator: std.mem.Allocator, core: *rp.Repo(.git).Core, pack_dir: std.fs.Dir, file_name: []const u8, position: u64) anyerror!PackObjectReader {
        var pack_file = try pack_dir.openFile(file_name, .{ .mode = .read_only });
        errdefer pack_file.close();
        try pack_file.seekTo(position);
        const reader = pack_file.reader();

        // parse object header
        const PackObjectKind = enum(u3) {
            commit = 1,
            tree = 2,
            blob = 3,
            tag = 4,
            ofs_delta = 6,
            ref_delta = 7,
        };
        const obj_header: packed struct {
            size: u4,
            kind: PackObjectKind,
            high_bit: u1,
        } = @bitCast(try reader.readByte());

        // get size of object (little endian variable length format)
        var size: u64 = obj_header.size;
        {
            var shift: u6 = @bitSizeOf(@TypeOf(obj_header.size));
            var cont = obj_header.high_bit == 1;
            while (cont) {
                const next_byte: packed struct {
                    value: u7,
                    high_bit: u1,
                } = @bitCast(try reader.readByte());
                cont = next_byte.high_bit == 1;
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
                    .internal = .{
                        .basic = .{
                            .size = size,
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
            .ofs_delta, .ref_delta => {
                const base_reader = try allocator.create(PackObjectReader);
                errdefer allocator.destroy(base_reader);

                switch (obj_header.kind) {
                    .ofs_delta => {
                        // get offset (big endian variable length format)
                        var offset: u64 = 0;
                        {
                            while (true) {
                                const next_byte: packed struct {
                                    value: u7,
                                    high_bit: u1,
                                } = @bitCast(try reader.readByte());
                                offset = (offset << 7) | next_byte.value;
                                if (next_byte.high_bit == 0) {
                                    break;
                                }
                                offset += 1; // "offset encoding" https://git-scm.com/docs/pack-format
                            }
                        }
                        base_reader.* = try PackObjectReader.initAtPosition(allocator, core, pack_dir, file_name, position - offset);
                    },
                    .ref_delta => {
                        const base_oid = try reader.readBytesNoEof(hash.SHA1_BYTES_LEN);
                        base_reader.* = try PackObjectReader.initWithOid(allocator, core, std.fmt.bytesToHex(base_oid, .lower));
                    },
                    else => unreachable,
                }
                errdefer base_reader.deinit();

                const start_position = try pack_file.getPos();

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
                            high_bit: u1,
                        } = @bitCast(try zlib_reader.readByte());
                        bytes_read += 1;
                        cont = next_byte.high_bit == 1;
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
                            high_bit: u1,
                        } = @bitCast(try zlib_reader.readByte());
                        bytes_read += 1;
                        cont = next_byte.high_bit == 1;
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

                while (bytes_read < size) {
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

                return .{
                    .pack_file = pack_file,
                    .stream = stream,
                    .start_position = start_position,
                    .relative_position = bytes_read,
                    .internal = .{
                        .delta = .{
                            .allocator = allocator,
                            .base_reader = base_reader,
                            .chunk_index = 0,
                            .chunk_position = 0,
                            .real_position = bytes_read,
                            .chunks = chunks,
                            .cache = cache,
                            .cache_arena = cache_arena,
                        },
                    },
                };
            },
        }
    }

    pub fn deinit(self: *PackObjectReader) void {
        self.pack_file.close();
        switch (self.internal) {
            .basic => {},
            .delta => {
                self.internal.delta.base_reader.deinit();
                self.internal.delta.allocator.destroy(self.internal.delta.base_reader);
                self.internal.delta.chunks.deinit();
                self.internal.delta.cache.deinit();
                self.internal.delta.cache_arena.deinit();
                self.internal.delta.allocator.destroy(self.internal.delta.cache_arena);
            },
        }
    }

    pub fn header(self: PackObjectReader) obj.ObjectHeader {
        return switch (self.internal) {
            .basic => self.internal.basic.header,
            .delta => self.internal.delta.base_reader.header(),
        };
    }

    pub fn reset(self: *PackObjectReader) !void {
        try self.pack_file.seekTo(self.start_position);
        self.stream = std.compress.zlib.decompressor(self.pack_file.reader());
        self.relative_position = 0;

        switch (self.internal) {
            .basic => {},
            .delta => {
                self.internal.delta.chunk_index = 0;
                self.internal.delta.chunk_position = 0;
                self.internal.delta.real_position = 0;
                try self.internal.delta.base_reader.reset();
            },
        }
    }

    pub fn read(self: *PackObjectReader, dest: []u8) !usize {
        switch (self.internal) {
            .basic => {
                if (self.internal.basic.size < self.relative_position) return error.EndOfStream;
                const size = try self.stream.reader().read(dest[0..@min(dest.len, self.internal.basic.size - self.relative_position)]);
                self.relative_position += size;
                return size;
            },
            .delta => {
                var bytes_read: usize = 0;
                while (bytes_read < dest.len) {
                    if (self.internal.delta.chunk_index == self.internal.delta.chunks.items.len) {
                        break;
                    }
                    const chunk = self.internal.delta.chunks.items[self.internal.delta.chunk_index];
                    var dest_slice = dest[bytes_read..];
                    const bytes_to_read = @min(chunk.location.size - self.internal.delta.chunk_position, dest_slice.len);
                    switch (chunk.kind) {
                        .add_new => {
                            const offset = chunk.location.offset + self.internal.delta.chunk_position;
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
                            if (size != bytes_to_read) {
                                return error.UnexpectedEndOfStream;
                            }
                            self.relative_position += size;
                            bytes_read += size;
                            self.internal.delta.chunk_position += size;
                            self.internal.delta.real_position += size;
                        },
                        .copy_from_base => {
                            const buffer = self.internal.delta.cache.get(chunk.location) orelse return error.UnexpectedEndOfStream;
                            @memcpy(dest_slice[0..bytes_to_read], buffer[self.internal.delta.chunk_position .. self.internal.delta.chunk_position + bytes_to_read]);
                            bytes_read += bytes_to_read;
                            self.internal.delta.chunk_position += bytes_to_read;
                            self.internal.delta.real_position += bytes_to_read;
                        },
                    }
                    if (self.internal.delta.chunk_position == chunk.location.size) {
                        self.internal.delta.chunk_index += 1;
                        self.internal.delta.chunk_position = 0;
                    }
                }
                return bytes_read;
            },
        }
    }

    pub fn readNoEof(self: *PackObjectReader, dest: []u8) !void {
        var reader = std.io.GenericReader(*PackObjectReader, Error, PackObjectReader.read){
            .context = self,
        };
        try reader.readNoEof(dest);
    }

    pub fn readUntilDelimiter(self: *PackObjectReader, dest: []u8, delimiter: u8) ![]u8 {
        var reader = std.io.GenericReader(*PackObjectReader, Error, PackObjectReader.read){
            .context = self,
        };
        return reader.readUntilDelimiter(dest, delimiter) catch |err| switch (err) {
            error.StreamTooLong => return error.EndOfStream,
            else => return err,
        };
    }

    pub fn readUntilDelimiterAlloc(self: *PackObjectReader, allocator: std.mem.Allocator, delimiter: u8, max_size: usize) ![]u8 {
        var reader = std.io.GenericReader(*PackObjectReader, Error, PackObjectReader.read){
            .context = self,
        };
        return reader.readUntilDelimiterAlloc(allocator, delimiter, max_size) catch |err| switch (err) {
            error.StreamTooLong => return error.EndOfStream,
            else => return err,
        };
    }

    pub fn readAllAlloc(self: *PackObjectReader, allocator: std.mem.Allocator, max_size: usize) ![]u8 {
        var reader = std.io.GenericReader(*PackObjectReader, Error, PackObjectReader.read){
            .context = self,
        };
        return try reader.readAllAlloc(allocator, max_size);
    }

    pub fn skipBytes(self: *PackObjectReader, num_bytes: u64) !void {
        var reader = std.io.GenericReader(*PackObjectReader, Error, PackObjectReader.read){
            .context = self,
        };
        try reader.skipBytes(num_bytes, .{});
    }
};

pub const LooseOrPackObjectReader = union(enum) {
    loose: struct {
        file: std.fs.File,
        stream: compress.ZlibStream,
        header: obj.ObjectHeader,
    },
    pack: PackObjectReader,

    pub const Error = PackObjectReader.Error;

    pub fn init(allocator: std.mem.Allocator, core: *rp.Repo(.git).Core, oid_hex: [hash.SHA1_HEX_LEN]u8) !LooseOrPackObjectReader {
        // open the objects dir
        var objects_dir = try core.git_dir.openDir("objects", .{});
        defer objects_dir.close();

        // open the object file
        var path_buf = [_]u8{0} ** (hash.SHA1_HEX_LEN + 1);
        const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ oid_hex[0..2], oid_hex[2..] });
        var object_file = objects_dir.openFile(path, .{ .mode = .read_only }) catch |err| switch (err) {
            error.FileNotFound => return .{
                .pack = PackObjectReader.init(allocator, core, oid_hex) catch return error.ObjectNotFound,
            },
            else => return err,
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

    pub fn deinit(self: *LooseOrPackObjectReader) void {
        switch (self.*) {
            .loose => self.loose.file.close(),
            .pack => self.pack.deinit(),
        }
    }

    pub fn header(self: LooseOrPackObjectReader) obj.ObjectHeader {
        return switch (self) {
            .loose => self.loose.header,
            .pack => self.pack.header(),
        };
    }

    pub fn reset(self: *LooseOrPackObjectReader) !void {
        switch (self.*) {
            .loose => {
                try self.loose.file.seekTo(0);
                self.loose.stream = std.compress.zlib.decompressor(self.loose.file.reader());
                try self.loose.stream.reader().skipUntilDelimiterOrEof(0);
            },
            .pack => try self.pack.reset(),
        }
    }

    pub fn read(self: *LooseOrPackObjectReader, dest: []u8) !usize {
        switch (self.*) {
            .loose => return try self.loose.stream.reader().read(dest),
            .pack => return try self.pack.read(dest),
        }
    }

    pub fn readNoEof(self: *LooseOrPackObjectReader, dest: []u8) !void {
        switch (self.*) {
            .loose => try self.loose.stream.reader().readNoEof(dest),
            .pack => try self.pack.readNoEof(dest),
        }
    }

    pub fn readUntilDelimiter(self: *LooseOrPackObjectReader, dest: []u8, delimiter: u8) ![]u8 {
        switch (self.*) {
            .loose => return try self.loose.stream.reader().readUntilDelimiter(dest, delimiter),
            .pack => return try self.pack.readUntilDelimiter(dest, delimiter),
        }
    }

    pub fn readUntilDelimiterAlloc(self: *LooseOrPackObjectReader, allocator: std.mem.Allocator, delimiter: u8, max_size: usize) ![]u8 {
        switch (self.*) {
            .loose => return try self.loose.stream.reader().readUntilDelimiterAlloc(allocator, delimiter, max_size),
            .pack => return try self.pack.readUntilDelimiterAlloc(allocator, delimiter, max_size),
        }
    }

    pub fn readAllAlloc(self: *LooseOrPackObjectReader, allocator: std.mem.Allocator, max_size: usize) ![]u8 {
        switch (self.*) {
            .loose => return try self.loose.stream.reader().readAllAlloc(allocator, max_size),
            .pack => return try self.pack.readAllAlloc(allocator, max_size),
        }
    }

    pub fn skipBytes(self: *LooseOrPackObjectReader, num_bytes: u64) !void {
        switch (self.*) {
            .loose => try self.loose.stream.reader().skipBytes(num_bytes, .{}),
            .pack => try self.pack.skipBytes(num_bytes),
        }
    }
};
