const std = @import("std");
const hash = @import("./hash.zig");
const rp = @import("./repo.zig");
const io = @import("./io.zig");

pub fn writeChunks(
    comptime repo_opts: rp.RepoOpts(.xit),
    state: rp.Repo(.xit, repo_opts).State(.read_write),
    file: anytype,
    object_hash: hash.HashInt(repo_opts.hash),
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

    var chunk_buffer = [_]u8{0} ** repo_opts.extra.chunk_size;
    const reader = file.reader();

    var offset: u64 = 0;
    while (true) {
        // read chunk
        const size = try reader.read(&chunk_buffer);
        if (size == 0) {
            break;
        }
        const chunk = chunk_buffer[0..size];

        // hash the chunk
        var chunk_hash_bytes = [_]u8{0} ** hash.byteLen(repo_opts.hash);
        try hash.hashBuffer(repo_opts.hash, chunk, &chunk_hash_bytes);

        // write chunk unless it already exists
        const chunk_hash_hex = std.fmt.bytesToHex(chunk_hash_bytes, .lower);
        if (chunks_dir.openFile(&chunk_hash_hex, .{})) |chunk_file| {
            chunk_file.close();
        } else |err| switch (err) {
            error.FileNotFound => {
                var lock = try io.LockFile.init(chunks_dir, &chunk_hash_hex);
                defer lock.deinit();
                try lock.lock_file.writeAll(chunk);
                lock.success = true;
            },
            else => |e| return e,
        }

        // write hash and offset to db
        // note: we are storing the offset at the *end* of this chunk.
        // this is useful so we can find the total size of the file
        // by looking at the last offset.
        offset += size;
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
