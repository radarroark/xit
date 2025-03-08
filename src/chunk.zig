const std = @import("std");
const hash = @import("./hash.zig");
const rp = @import("./repo.zig");
const fs = @import("./fs.zig");
const obj = @import("./object.zig");

// reordering is a breaking change
const CompressKind = enum(u8) {
    none,
    zlib,
};

pub const FastCdcOpts = struct {
    min_size: usize,
    avg_size: usize,
    max_size: usize,
    normalization: Normalization,

    const Normalization = enum {
        level0,
        level1,
        level2,
        level3,
    };
};

fn FastCdc(comptime opts: FastCdcOpts) type {
    std.debug.assert(opts.min_size > 0);
    std.debug.assert(opts.min_size <= opts.avg_size);
    std.debug.assert(opts.avg_size <= opts.max_size);
    return struct {
        remaining: usize,

        const gear_hash = computeGearHash();
        // in some tests, avg_size will be very low, so we use @max
        // here so that a valid mask is still used
        const bits = std.math.log2(@max(opts.avg_size, 256));
        const normalization = @intFromEnum(opts.normalization);
        // thanks to https://github.com/nlfiedler/fastcdc-rs
        const masks: [26]u64 = .{
            0, // padding
            0, // padding
            0, // padding
            0, // padding
            0, // padding
            0x0000000001804110, // unused except for NC 3
            0x0000000001803110, // 64B
            0x0000000018035100, // 128B
            0x0000001800035300, // 256B
            0x0000019000353000, // 512B
            0x0000590003530000, // 1KB
            0x0000d90003530000, // 2KB
            0x0000d90103530000, // 4KB
            0x0000d90303530000, // 8KB
            0x0000d90313530000, // 16KB
            0x0000d90f03530000, // 32KB
            0x0000d90303537000, // 64KB
            0x0000d90703537000, // 128KB
            0x0000d90707537000, // 256KB
            0x0000d91707537000, // 512KB
            0x0000d91747537000, // 1MB
            0x0000d91767537000, // 2MB
            0x0000d93767537000, // 4MB
            0x0000d93777537000, // 8MB
            0x0000d93777577000, // 16MB
            0x0000db3777577000, // unused except for NC 3
        };
        const mask_s = masks[bits + normalization];
        const mask_l = masks[bits - normalization];

        pub fn init(total_size: usize) FastCdc(opts) {
            return .{
                .remaining = total_size,
            };
        }

        pub fn next(self: *FastCdc(opts), reader: anytype, buffer: *[opts.max_size]u8) !?[]const u8 {
            if (self.remaining == 0) {
                return null;
            } else {
                const chunk = try self.read(reader, buffer);
                self.remaining -= chunk.len;
                return chunk;
            }
        }

        fn read(self: FastCdc(opts), reader: anytype, buffer: *[opts.max_size]u8) ![]const u8 {
            var remaining = self.remaining;
            if (remaining <= opts.min_size) {
                try reader.readNoEof(buffer[0..remaining]);
                return buffer[0..remaining];
            }

            var center = opts.avg_size;
            if (remaining > opts.max_size) {
                remaining = opts.max_size;
            } else if (remaining < center) {
                center = remaining;
            }

            var index = opts.min_size - 1;
            try reader.readNoEof(buffer[0..index]);

            var h: u64 = 0;
            while (index < center) {
                const byte = try reader.readByte();
                buffer[index] = byte;
                h = (h << 1) +% gear_hash[byte];
                index += 1;
                if (h & mask_s == 0) {
                    return buffer[0..index];
                }
            }

            const last_pos = remaining;
            while (index < last_pos) {
                const byte = try reader.readByte();
                buffer[index] = byte;
                h = (h << 1) +% gear_hash[byte];
                index += 1;
                if (h & mask_l == 0) {
                    return buffer[0..index];
                }
            }

            return buffer[0..index];
        }

        fn computeGearHash() [256]u64 {
            @setEvalBranchQuota(1_000_000);
            var nums: [256]u64 = undefined;
            for (&nums, 0..) |*num, i| {
                var seed = [_]u8{0} ** 64;
                @memset(&seed, i);

                var buffer = [_]u8{0} ** std.crypto.hash.Md5.digest_length;
                std.crypto.hash.Md5.hash(&seed, &buffer, .{});

                var stream = std.io.fixedBufferStream(&buffer);
                const reader = stream.reader();
                num.* = reader.readInt(u64, .big) catch unreachable;
            }
            return nums;
        }
    };
}

test "fastcdc all zeros" {
    const opts = FastCdcOpts{
        .min_size = 1024,
        .avg_size = 2048,
        .max_size = 4096,
        .normalization = .level1,
    };
    const zero_buffer = [_]u8{0} ** (opts.max_size * 3);
    var stream = std.io.fixedBufferStream(&zero_buffer);
    var iter = FastCdc(opts).init(zero_buffer.len);
    var chunk_buffer = [_]u8{0} ** opts.max_size;
    while (try iter.next(stream.reader(), &chunk_buffer)) |chunk| {
        try std.testing.expectEqual(opts.max_size, chunk.len);
    }
}

test "fastcdc sekien 16k chunks" {
    const opts = FastCdcOpts{
        .min_size = 4096,
        .avg_size = 16384,
        .max_size = 65535,
        .normalization = .level1,
    };
    const buffer = @embedFile("test/embed/SekienAkashita.jpg");
    var stream = std.io.fixedBufferStream(buffer);
    var iter = FastCdc(opts).init(buffer.len);
    var chunk_buffer = [_]u8{0} ** opts.max_size;
    const expected_lengths = [_]usize{
        21326,
        17140,
        28084,
        18217,
        24699,
    };
    for (expected_lengths) |expected_length| {
        const actual_chunk = (try iter.next(stream.reader(), &chunk_buffer)).?;
        try std.testing.expectEqual(expected_length, actual_chunk.len);
    }
    try std.testing.expectEqual(0, iter.remaining);
}

test "fastcdc sekien 32k chunks" {
    const opts = FastCdcOpts{
        .min_size = 8192,
        .avg_size = 32768,
        .max_size = 131072,
        .normalization = .level1,
    };
    const buffer = @embedFile("test/embed/SekienAkashita.jpg");
    var stream = std.io.fixedBufferStream(buffer);
    var iter = FastCdc(opts).init(buffer.len);
    var chunk_buffer = [_]u8{0} ** opts.max_size;
    const expected_lengths = [_]usize{
        66550,
        42916,
    };
    for (expected_lengths) |expected_length| {
        const actual_chunk = (try iter.next(stream.reader(), &chunk_buffer)).?;
        try std.testing.expectEqual(expected_length, actual_chunk.len);
    }
    try std.testing.expectEqual(0, iter.remaining);
}

test "fastcdc sekien 64k chunks" {
    const opts = FastCdcOpts{
        .min_size = 16384,
        .avg_size = 65536,
        .max_size = 262144,
        .normalization = .level1,
    };
    const buffer = @embedFile("test/embed/SekienAkashita.jpg");
    var stream = std.io.fixedBufferStream(buffer);
    var iter = FastCdc(opts).init(buffer.len);
    var chunk_buffer = [_]u8{0} ** opts.max_size;
    const expected_lengths = [_]usize{
        109466,
    };
    for (expected_lengths) |expected_length| {
        const actual_chunk = (try iter.next(stream.reader(), &chunk_buffer)).?;
        try std.testing.expectEqual(expected_length, actual_chunk.len);
    }
    try std.testing.expectEqual(0, iter.remaining);
}

/// trims bytes from the beginning and end of the given text
/// if they appear to be part of multi-byte utf8 characters
/// that have been truncated. this is important because we
/// use utf8 validation to decide whether to compress a chunk,
/// and if we don't trim these invalid bytes out beforehand,
/// those chunks will fail validation and won't be compressed.
fn trimTruncatedCodepoints(text: []const u8) []const u8 {
    if (text.len < 6) {
        return text;
    }

    // count continuation bytes at the start
    var start_cont_bytes: u2 = 0;
    for (0..3) |i| {
        if (text[i] & 0b1100_0000 == 0b1000_0000) {
            start_cont_bytes += 1;
        } else {
            break;
        }
    }

    // count continuation bytes at the end
    var end_cont_bytes: u2 = 0;
    for (0..3) |i| {
        if (text[text.len - 1 - i] & 0b1100_0000 == 0b1000_0000) {
            end_cont_bytes += 1;
        } else {
            break;
        }
    }

    const skip_end: u2 = switch (end_cont_bytes) {
        // if there are no continuation bytes at the end, but the last
        // byte appears to be the start of a multi-byte character, skip it
        0 => blk: {
            const last_byte = text[text.len - 1];
            break :blk if (last_byte & 0b1110_0000 == 0b1100_0000 or
                last_byte & 0b1111_0000 == 0b1110_0000 or
                last_byte & 0b1111_1000 == 0b1111_0000) 1 else 0;
        },
        // if the byte before the continuation bytes doesn't appear
        // to be the correct start of the multi-byte character, skip it
        1 => if (text[text.len - 2] & 0b1110_0000 != 0b1100_0000) 2 else 0,
        2 => if (text[text.len - 3] & 0b1111_0000 != 0b1110_0000) 3 else 0,
        // if there are 3 continuation bytes at the end, then there is
        // no truncated utf8 character
        3 => 0,
    };

    return text[start_cont_bytes .. text.len - skip_end];
}

test "trimTruncatedCodepoints" {
    const text = "六四天安門";
    try std.testing.expect(!std.unicode.utf8ValidateSlice(text[1..]));
    try std.testing.expect(std.unicode.utf8ValidateSlice(trimTruncatedCodepoints(text[1..])));
    try std.testing.expect(!std.unicode.utf8ValidateSlice(text[2..]));
    try std.testing.expect(std.unicode.utf8ValidateSlice(trimTruncatedCodepoints(text[2..])));
    try std.testing.expect(!std.unicode.utf8ValidateSlice(text[0 .. text.len - 1]));
    try std.testing.expect(std.unicode.utf8ValidateSlice(trimTruncatedCodepoints(text[0 .. text.len - 1])));
    try std.testing.expect(!std.unicode.utf8ValidateSlice(text[0 .. text.len - 2]));
    try std.testing.expect(std.unicode.utf8ValidateSlice(trimTruncatedCodepoints(text[0 .. text.len - 2])));
    try std.testing.expect(!std.unicode.utf8ValidateSlice(text[1 .. text.len - 1]));
    try std.testing.expect(std.unicode.utf8ValidateSlice(trimTruncatedCodepoints(text[1 .. text.len - 1])));
}

pub fn writeChunks(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_write),
    reader: anytype,
    object_hash: hash.HashInt(repo_opts.hash),
    object_len: usize,
    object_kind_name: []const u8,
) !void {
    // exit early if the chunks for this object already exist
    const blob_id_to_chunk_info_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "object-id->chunk-info"));
    const blob_id_to_chunk_info = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(blob_id_to_chunk_info_cursor);
    if (null != try blob_id_to_chunk_info.getCursor(object_hash)) return;

    // write object kind in the key slot
    try blob_id_to_chunk_info.putKey(object_hash, .{ .bytes = object_kind_name });

    // get a writer to the value slot
    var chunk_info_cursor = try blob_id_to_chunk_info.putCursor(object_hash);
    var writer = try chunk_info_cursor.writer();

    // make the .xit/chunks dir
    var chunks_dir = try state.core.xit_dir.makeOpenPath("chunks", .{});
    defer chunks_dir.close();

    var chunk_buffer = [_]u8{0} ** repo_opts.extra.chunk_opts.max_size;
    var iter = FastCdc(repo_opts.extra.chunk_opts).init(object_len);
    var offset: u64 = 0;
    while (try iter.next(reader, &chunk_buffer)) |chunk| {
        // hash the chunk
        var chunk_hash_bytes = [_]u8{0} ** hash.byteLen(repo_opts.hash);
        try hash.hashBuffer(repo_opts.hash, chunk, &chunk_hash_bytes);

        // write chunk unless it already exists
        const chunk_hash_hex = std.fmt.bytesToHex(chunk_hash_bytes, .lower);
        if (chunks_dir.openFile(&chunk_hash_hex, .{})) |chunk_file| {
            chunk_file.close();
        } else |err| switch (err) {
            error.FileNotFound => {
                var lock = try fs.LockFile.init(chunks_dir, &chunk_hash_hex);
                defer lock.deinit();

                // if it's utf8 text, try compressing it
                // since the beginning and end could have truncated unicode codepoints,
                // we must first trim them. if we don't do this, non-English text will
                // sometimes fail to validate as utf8 and thus won't get compressed.
                if (repo_opts.extra.compress_chunks and std.unicode.utf8ValidateSlice(trimTruncatedCodepoints(chunk))) {
                    try lock.lock_file.writer().writeByte(@intFromEnum(CompressKind.zlib));
                    var zlib_stream = try std.compress.zlib.compressor(lock.lock_file.writer(), .{ .level = .default });
                    try zlib_stream.writer().writeAll(chunk);
                    try zlib_stream.finish();

                    // abort compression if it didn't make it smaller
                    const compress_kind_size = @sizeOf(CompressKind);
                    const checksum_size = @sizeOf(u32);
                    if (try lock.lock_file.getPos() >= compress_kind_size + checksum_size + chunk.len) {
                        try lock.lock_file.seekTo(0);
                        try lock.lock_file.setEndPos(0);
                    } else {
                        lock.success = true;
                    }
                }

                // write the chunk uncompressed
                if (!lock.success) {
                    try lock.lock_file.writer().writeByte(@intFromEnum(CompressKind.none));
                    try lock.lock_file.writer().writeInt(u32, std.hash.Adler32.hash(chunk), .big);
                    try lock.lock_file.writeAll(chunk);
                    lock.success = true;
                }
            },
            else => |e| return e,
        }

        // write hash and offset to db
        // note: we are storing the offset at the *end* of this chunk.
        // this is useful so we can find the total size of the object
        // by looking at the last offset.
        offset += chunk.len;
        try writer.writeAll(&chunk_hash_bytes);
        try writer.writeInt(u64, offset, .big);
    }

    // finish writing to db
    try writer.finish();
}

fn findChunkIndex(
    comptime repo_opts: rp.RepoOpts(.xit),
    chunk_info_reader: *rp.Repo(.xit, repo_opts).DB.Cursor(.read_only).Reader,
    position: u64,
) !?usize {
    const chunk_hash_size = comptime hash.byteLen(repo_opts.hash);
    const chunk_offset_size = @sizeOf(u64);
    const chunk_info_size = chunk_hash_size + chunk_offset_size;
    const chunk_count = chunk_info_reader.size / chunk_info_size;
    if (chunk_count == 0) {
        return null;
    }

    var left: usize = 0;
    var right: usize = chunk_count - 1;

    // binary search for the chunk
    while (left < right) {
        const mid = left + ((right - left) / 2);

        // note: we are storing the *end* offsets of each chunk
        try chunk_info_reader.seekTo(mid * chunk_info_size + chunk_hash_size);
        const end_offset = try chunk_info_reader.readInt(u64, .big);

        if (position < end_offset) {
            if (mid > 0) {
                // since we store end offsets, the offset of the previous
                // chunk is the actual offset of `mid`
                try chunk_info_reader.seekTo((mid - 1) * chunk_info_size + chunk_hash_size);
                const mid_offset = try chunk_info_reader.readInt(u64, .big);

                if (position >= mid_offset) {
                    return mid;
                } else {
                    right = mid - 1;
                }
            } else {
                return mid;
            }
        } else {
            left = mid + 1;
        }
    }

    try chunk_info_reader.seekTo(right * chunk_info_size + chunk_hash_size);
    const right_offset = try chunk_info_reader.readInt(u64, .big);
    if (position < right_offset) {
        return right;
    }

    return null;
}

pub fn readChunk(
    comptime repo_opts: rp.RepoOpts(.xit),
    xit_dir: std.fs.Dir,
    chunk_info_reader: *rp.Repo(.xit, repo_opts).DB.Cursor(.read_only).Reader,
    object_position: u64,
    buf: []u8,
) !usize {
    // find the chunk info position
    const chunk_index = (try findChunkIndex(repo_opts, chunk_info_reader, object_position)) orelse return 0;
    const chunk_hash_size = comptime hash.byteLen(repo_opts.hash);
    const chunk_offset_size = @sizeOf(u64);
    const chunk_info_size = chunk_hash_size + chunk_offset_size;
    const chunk_info_position = chunk_index * chunk_info_size;

    // find the chunk info
    // the offset is where the chunk is located in the object.
    // the hash is the hash of the uncompressed chunk data.
    const object_offset = if (chunk_index == 0) blk: {
        try chunk_info_reader.seekTo(chunk_info_position);
        break :blk 0;
    } else blk: {
        try chunk_info_reader.seekTo(chunk_info_position - chunk_offset_size);
        break :blk try chunk_info_reader.readInt(u64, .big);
    };
    const chunk_offset = object_position - object_offset;
    var chunk_hash_bytes = [_]u8{0} ** chunk_hash_size;
    try chunk_info_reader.readNoEof(&chunk_hash_bytes);
    const chunk_hash_hex = std.fmt.bytesToHex(chunk_hash_bytes, .lower);

    // open the chunk file
    var chunks_dir = try xit_dir.openDir("chunks", .{});
    defer chunks_dir.close();
    const chunk_file = try chunks_dir.openFile(&chunk_hash_hex, .{});
    defer chunk_file.close();

    // make reader
    var buffered_reader = std.io.bufferedReaderSize(repo_opts.read_size, chunk_file.reader());
    const chunk_reader = buffered_reader.reader();

    // read chunk, decompressing if necessary
    const compress_kind = try std.meta.intToEnum(CompressKind, try chunk_reader.readByte());
    switch (compress_kind) {
        .none => {
            const expected_checksum = try chunk_reader.readInt(u32, .big);

            var chunk_buffer = [_]u8{0} ** repo_opts.extra.chunk_opts.max_size;
            const chunk_size = try chunk_reader.readAll(&chunk_buffer);

            const actual_checksum = std.hash.Adler32.hash(chunk_buffer[0..chunk_size]);
            if (actual_checksum != expected_checksum) {
                return error.WrongChunkChecksum;
            }

            const read_size = @min(buf.len, chunk_size - chunk_offset);
            @memcpy(buf[0..read_size], chunk_buffer[chunk_offset .. chunk_offset + read_size]);

            return read_size;
        },
        .zlib => {
            var zlib_stream = std.compress.zlib.decompressor(chunk_reader);
            try zlib_stream.reader().skipBytes(chunk_offset, .{});
            return zlib_stream.reader().read(buf) catch |err| switch (err) {
                error.WrongZlibChecksum => error.WrongChunkChecksum,
                else => |e| e,
            };
        },
    }
}

const ZlibStream = std.compress.flate.inflate.Decompressor(.zlib, std.fs.File.Reader);

pub fn ChunkObjectReader(comptime repo_opts: rp.RepoOpts(.xit)) type {
    return struct {
        xit_dir: std.fs.Dir,
        cursor: *rp.Repo(.xit, repo_opts).DB.Cursor(.read_only),
        chunk_info_reader: rp.Repo(.xit, repo_opts).DB.Cursor(.read_only).Reader,
        position: u64,
        header: obj.ObjectHeader,

        pub const Error = ZlibStream.Reader.Error || std.fs.File.OpenError || rp.Repo(.xit, repo_opts).DB.Cursor(.read_only).Reader.Error || error{ InvalidOffset, InvalidEnumTag, WrongChunkChecksum };

        pub fn init(allocator: std.mem.Allocator, state: rp.Repo(.xit, repo_opts).State(.read_only), oid: *const [hash.hexLen(repo_opts.hash)]u8) !ChunkObjectReader(repo_opts) {
            // chunk info map
            const object_id_to_chunk_info_cursor = (try state.extra.moment.getCursor(hash.hashInt(repo_opts.hash, "object-id->chunk-info"))) orelse return error.ObjectNotFound;
            const object_id_to_chunk_info = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_only).init(object_id_to_chunk_info_cursor);
            var chunk_info_kv_pair = (try object_id_to_chunk_info.getKeyValuePair(try hash.hexToInt(repo_opts.hash, oid))) orelse return error.ObjectNotFound;

            // object kind name
            var object_kind_name_buffer = [_]u8{0} ** 8;
            const object_kind_name = try chunk_info_kv_pair.key_cursor.readBytes(&object_kind_name_buffer);

            // object size
            const object_size = blk: {
                var reader = try chunk_info_kv_pair.value_cursor.reader();
                if (reader.size == 0) {
                    break :blk 0;
                } else {
                    // the last 8 bytes in the chunk info contain the object size
                    try reader.seekFromEnd(-@sizeOf(u64));
                    const size = try reader.readInt(u64, .big);
                    try reader.seekTo(0);
                    break :blk size;
                }
            };

            // put cursor on the heap so the pointer is stable (the reader uses it internally)
            const chunk_info_ptr = try allocator.create(rp.Repo(.xit, repo_opts).DB.Cursor(.read_only));
            errdefer allocator.destroy(chunk_info_ptr);
            chunk_info_ptr.* = chunk_info_kv_pair.value_cursor;

            return .{
                .xit_dir = state.core.xit_dir,
                .cursor = chunk_info_ptr,
                .chunk_info_reader = try chunk_info_ptr.reader(),
                .position = 0,
                .header = .{
                    .kind = try obj.ObjectKind.init(object_kind_name),
                    .size = object_size,
                },
            };
        }

        pub fn deinit(self: *ChunkObjectReader(repo_opts), allocator: std.mem.Allocator) void {
            allocator.destroy(self.cursor);
        }

        pub fn read(self: *ChunkObjectReader(repo_opts), buf: []u8) !usize {
            var size: usize = 0;
            while (size < buf.len) {
                const read_size = try self.readStep(buf[size..]);
                if (read_size == 0) {
                    break;
                }
                size += read_size;
                self.position += read_size;
            }
            return size;
        }

        fn readStep(self: *ChunkObjectReader(repo_opts), buf: []u8) !usize {
            return try readChunk(repo_opts, self.xit_dir, &self.chunk_info_reader, self.position, buf);
        }

        pub fn reset(self: *ChunkObjectReader(repo_opts)) !void {
            try self.seekTo(0);
        }

        pub fn seekTo(self: *ChunkObjectReader(repo_opts), offset: u64) !void {
            self.position = offset;
        }

        pub fn readNoEof(self: *ChunkObjectReader(repo_opts), dest: []u8) !void {
            var reader = std.io.GenericReader(*ChunkObjectReader(repo_opts), Error, ChunkObjectReader(repo_opts).read){
                .context = self,
            };
            try reader.readNoEof(dest);
        }

        pub fn readUntilDelimiter(self: *ChunkObjectReader(repo_opts), dest: []u8, delimiter: u8) ![]u8 {
            var reader = std.io.GenericReader(*ChunkObjectReader(repo_opts), Error, ChunkObjectReader(repo_opts).read){
                .context = self,
            };
            return try reader.readUntilDelimiter(dest, delimiter);
        }

        pub fn readUntilDelimiterAlloc(self: *ChunkObjectReader(repo_opts), allocator: std.mem.Allocator, delimiter: u8, max_size: usize) ![]u8 {
            var reader = std.io.GenericReader(*ChunkObjectReader(repo_opts), Error, ChunkObjectReader(repo_opts).read){
                .context = self,
            };
            return try reader.readUntilDelimiterAlloc(allocator, delimiter, max_size);
        }

        pub fn readAllAlloc(self: *ChunkObjectReader(repo_opts), allocator: std.mem.Allocator, max_size: usize) ![]u8 {
            var reader = std.io.GenericReader(*ChunkObjectReader(repo_opts), Error, ChunkObjectReader(repo_opts).read){
                .context = self,
            };
            return try reader.readAllAlloc(allocator, max_size);
        }

        pub fn skipBytes(self: *ChunkObjectReader(repo_opts), num_bytes: u64) !void {
            var reader = std.io.GenericReader(*ChunkObjectReader(repo_opts), Error, ChunkObjectReader(repo_opts).read){
                .context = self,
            };
            try reader.skipBytes(num_bytes, .{});
        }
    };
}
