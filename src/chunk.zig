const std = @import("std");
const hash = @import("./hash.zig");
const rp = @import("./repo.zig");
const io = @import("./io.zig");

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

const FastCdcChunk = struct {
    hash: u64,
    length: usize,
};

fn FastCdc(comptime opts: FastCdcOpts) type {
    std.debug.assert(opts.min_size <= opts.avg_size);
    std.debug.assert(opts.avg_size <= opts.max_size);
    return struct {
        offset: usize,
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
                .offset = 0,
                .remaining = total_size,
            };
        }

        pub fn next(self: *FastCdc(opts), stream: anytype, reader: anytype) !?FastCdcChunk {
            if (self.remaining == 0) {
                return null;
            } else {
                try stream.seekTo(self.offset);
                const chunk = try self.cut(stream, reader);
                self.offset += chunk.length;
                self.remaining -= chunk.length;
                return chunk;
            }
        }

        fn cut(self: FastCdc(opts), stream: anytype, reader: anytype) !FastCdcChunk {
            var remaining = self.remaining;
            if (remaining <= opts.min_size) {
                return .{
                    .hash = 0,
                    .length = remaining,
                };
            }

            var center = opts.avg_size;
            if (remaining > opts.max_size) {
                remaining = opts.max_size;
            } else if (remaining < center) {
                center = remaining;
            }

            var index = opts.min_size;
            try stream.seekTo(self.offset + index);

            var h: u64 = 0;
            while (index < center) {
                h = (h << 1) +% gear_hash[try reader.readByte()];
                if (h & mask_s == 0) {
                    return .{
                        .hash = h,
                        .length = index,
                    };
                }
                index += 1;
            }

            const last_pos = remaining;
            while (index < last_pos) {
                h = (h << 1) +% gear_hash[try reader.readByte()];
                if (h & mask_l == 0) {
                    return .{
                        .hash = h,
                        .length = index,
                    };
                }
                index += 1;
            }

            return .{
                .hash = h,
                .length = index,
            };
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
    const buffer = [_]u8{0} ** (opts.max_size * 3);
    var stream = std.io.fixedBufferStream(&buffer);
    var iter = FastCdc(opts).init(buffer.len);
    while (try iter.next(&stream, stream.reader())) |chunk| {
        try std.testing.expectEqual(opts.max_size, chunk.length);
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
    const expected_chunks = [_]FastCdcChunk{
        .{ .hash = 17968276318003433923, .length = 21325 },
        .{ .hash = 4098594969649699419, .length = 17140 },
        .{ .hash = 15733367461443853673, .length = 28084 },
        .{ .hash = 4509236223063678303, .length = 18217 },
        .{ .hash = 2504464741100432583, .length = 24700 },
    };
    for (expected_chunks) |expected_chunk| {
        const actual_chunk = (try iter.next(&stream, stream.reader())).?;
        try std.testing.expectEqual(expected_chunk, actual_chunk);
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
    const expected_chunks = [_]FastCdcChunk{
        .{ .hash = 15733367461443853673, .length = 66549 },
        .{ .hash = 2504464741100432583, .length = 42917 },
    };
    for (expected_chunks) |expected_chunk| {
        const actual_chunk = (try iter.next(&stream, stream.reader())).?;
        try std.testing.expectEqual(expected_chunk, actual_chunk);
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
    const expected_chunks = [_]FastCdcChunk{
        .{ .hash = 2504464741100432583, .length = 109466 },
    };
    for (expected_chunks) |expected_chunk| {
        const actual_chunk = (try iter.next(&stream, stream.reader())).?;
        try std.testing.expectEqual(expected_chunk, actual_chunk);
    }
    try std.testing.expectEqual(0, iter.remaining);
}

pub fn writeChunks(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_write),
    stream: anytype,
    reader: anytype,
    object_hash: hash.HashInt(repo_opts.hash),
    object_len: usize,
    object_header: []const u8,
) !void {
    // exit early if the chunks for this object already exist
    const blob_id_to_chunk_info_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "object-id->chunk-info"));
    const blob_id_to_chunk_info = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(blob_id_to_chunk_info_cursor);
    if (null != try blob_id_to_chunk_info.getCursor(object_hash)) return;

    // get the writer
    var chunk_info_cursor = try blob_id_to_chunk_info.putCursor(object_hash);
    var writer = try chunk_info_cursor.writer();

    // make the .xit/chunks dir
    var chunks_dir = try state.core.xit_dir.makeOpenPath("chunks", .{});
    defer chunks_dir.close();

    var iter = FastCdc(repo_opts.extra.chunk_opts).init(object_len);
    var offset: u64 = 0;
    while (try iter.next(stream, reader)) |chunk| {
        // read chunk
        var chunk_buffer = [_]u8{0} ** repo_opts.extra.chunk_opts.max_size;
        try stream.seekTo(offset);
        try stream.reader().readNoEof(chunk_buffer[0..chunk.length]);
        const chunk_bytes = chunk_buffer[0..chunk.length];

        // hash the chunk
        var chunk_hash_bytes = [_]u8{0} ** hash.byteLen(repo_opts.hash);
        try hash.hashBuffer(repo_opts.hash, chunk_bytes, &chunk_hash_bytes);

        // write chunk unless it already exists
        const chunk_hash_hex = std.fmt.bytesToHex(chunk_hash_bytes, .lower);
        if (chunks_dir.openFile(&chunk_hash_hex, .{})) |chunk_file| {
            chunk_file.close();
        } else |err| switch (err) {
            error.FileNotFound => {
                var lock = try io.LockFile.init(chunks_dir, &chunk_hash_hex);
                defer lock.deinit();
                try lock.lock_file.writeAll(chunk_bytes);
                lock.success = true;
            },
            else => |e| return e,
        }

        // write hash and offset to db
        // note: we are storing the offset at the *end* of this chunk.
        // this is useful so we can find the total size of the object
        // by looking at the last offset.
        offset += chunk.length;
        try writer.writeAll(&chunk_hash_bytes);
        try writer.writeInt(u64, offset, .big);
    }

    // finish writing to db
    try writer.finish();

    // write object header
    const object_id_to_header_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "object-id->header"));
    const object_id_to_header = try rp.Repo(.xit, repo_opts).DB.HashMap(.read_write).init(object_id_to_header_cursor);
    try object_id_to_header.put(object_hash, .{ .bytes = object_header });
}

fn findChunkIndex(
    comptime repo_opts: rp.RepoOpts(.xit),
    chunk_info_reader: *rp.Repo(.xit, repo_opts).DB.Cursor(.read_only).Reader,
    position: u64,
) !?usize {
    const chunk_hash_size = comptime hash.byteLen(repo_opts.hash);
    const chunk_offset_size = @bitSizeOf(u64) / 8;
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
    position: u64,
    buf: []u8,
) !usize {
    const chunk_index = (try findChunkIndex(repo_opts, chunk_info_reader, position)) orelse return 0;
    const chunk_hash_size = comptime hash.byteLen(repo_opts.hash);
    const chunk_offset_size = @bitSizeOf(u64) / 8;
    const chunk_info_size = chunk_hash_size + chunk_offset_size;
    const chunk_info_position = chunk_index * chunk_info_size;

    const offset = if (chunk_index == 0) blk: {
        try chunk_info_reader.seekTo(chunk_info_position);
        break :blk 0;
    } else blk: {
        try chunk_info_reader.seekTo(chunk_info_position - chunk_offset_size);
        break :blk try chunk_info_reader.readInt(u64, .big);
    };
    var chunk_hash_bytes = [_]u8{0} ** chunk_hash_size;
    try chunk_info_reader.readNoEof(&chunk_hash_bytes);
    const chunk_hash_hex = std.fmt.bytesToHex(chunk_hash_bytes, .lower);

    var chunks_dir = try xit_dir.openDir("chunks", .{});
    defer chunks_dir.close();

    const chunk_file = try chunks_dir.openFile(&chunk_hash_hex, .{});
    defer chunk_file.close();
    try chunk_file.seekTo(position - offset);
    return try chunk_file.read(buf);
}

pub fn ChunkObjectReader(comptime repo_opts: rp.RepoOpts(.xit)) type {
    return struct {
        xit_dir: std.fs.Dir,
        chunk_info_reader: rp.Repo(.xit, repo_opts).DB.Cursor(.read_only).Reader,
        position: u64,

        pub const Error = std.fs.File.OpenError || rp.Repo(.xit, repo_opts).DB.Cursor(.read_only).Reader.Error || error{InvalidOffset};

        pub fn read(self: *@This(), buf: []u8) !usize {
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

        fn readStep(self: *@This(), buf: []u8) !usize {
            return try readChunk(repo_opts, self.xit_dir, &self.chunk_info_reader, self.position, buf);
        }

        pub fn reset(self: *@This()) !void {
            try self.seekTo(0);
        }

        pub fn seekTo(self: *@This(), offset: u64) !void {
            self.position = offset;
        }

        pub fn readNoEof(self: *@This(), dest: []u8) !void {
            var reader = std.io.GenericReader(*@This(), Error, @This().read){
                .context = self,
            };
            try reader.readNoEof(dest);
        }

        pub fn readUntilDelimiter(self: *@This(), dest: []u8, delimiter: u8) ![]u8 {
            var reader = std.io.GenericReader(*@This(), Error, @This().read){
                .context = self,
            };
            return try reader.readUntilDelimiter(dest, delimiter);
        }

        pub fn readUntilDelimiterAlloc(self: *@This(), allocator: std.mem.Allocator, delimiter: u8, max_size: usize) ![]u8 {
            var reader = std.io.GenericReader(*@This(), Error, @This().read){
                .context = self,
            };
            return try reader.readUntilDelimiterAlloc(allocator, delimiter, max_size);
        }

        pub fn readAllAlloc(self: *@This(), allocator: std.mem.Allocator, max_size: usize) ![]u8 {
            var reader = std.io.GenericReader(*@This(), Error, @This().read){
                .context = self,
            };
            return try reader.readAllAlloc(allocator, max_size);
        }
    };
}
