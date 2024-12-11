const std = @import("std");
const hash = @import("./hash.zig");
const rp = @import("./repo.zig");
const io = @import("./io.zig");

const CHUNK_SIZE = 2048;

pub fn writeChunks(
    state: rp.Repo(.xit).State(.read_write),
    file: anytype,
    object_hash: hash.Hash,
    object_header: []const u8,
) !void {
    // exit early if the chunks for this object already exist
    const blob_id_to_chunk_hashes_cursor = try state.extra.moment.putCursor(hash.hashBuffer("object-id->chunk-hashes"));
    const blob_id_to_chunk_hashes = try rp.Repo(.xit).DB.HashMap(.read_write).init(blob_id_to_chunk_hashes_cursor);
    if (null != try blob_id_to_chunk_hashes.getCursor(object_hash)) return;

    // get the writer
    var chunk_hashes_cursor = try blob_id_to_chunk_hashes.putCursor(object_hash);
    var writer = try chunk_hashes_cursor.writer();

    // make the .xit/chunks dir
    var chunks_dir = try state.core.xit_dir.makeOpenPath("chunks", .{});
    defer chunks_dir.close();

    var chunk_buffer = [_]u8{0} ** CHUNK_SIZE;
    const reader = file.reader();

    while (true) {
        // read chunk
        const size = try reader.read(&chunk_buffer);
        if (size == 0) {
            break;
        }
        const chunk = chunk_buffer[0..size];

        // hash the chunk
        var chunk_hash_bytes = [_]u8{0} ** hash.SHA1_BYTES_LEN;
        try hash.sha1Buffer(chunk, &chunk_hash_bytes);

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

        // write hash to db
        try writer.writeAll(&chunk_hash_bytes);
    }

    // finish writing to db
    try writer.finish();

    // write object header
    const object_id_to_header_cursor = try state.extra.moment.putCursor(hash.hashBuffer("object-id->header"));
    const object_id_to_header = try rp.Repo(.xit).DB.HashMap(.read_write).init(object_id_to_header_cursor);
    try object_id_to_header.put(object_hash, .{ .bytes = object_header });
}

pub fn readChunk(
    xit_dir: std.fs.Dir,
    chunk_hashes_reader: *rp.Repo(.xit).DB.Cursor(.read_only).Reader,
    position: u64,
    buf: []u8,
) !usize {
    const chunk_index = position / CHUNK_SIZE;
    const chunk_hash_position = chunk_index * hash.SHA1_BYTES_LEN;
    if (chunk_hash_position == chunk_hashes_reader.size) {
        return 0;
    }

    try chunk_hashes_reader.seekTo(chunk_hash_position);
    var chunk_hash_bytes = [_]u8{0} ** hash.SHA1_BYTES_LEN;
    try chunk_hashes_reader.readNoEof(&chunk_hash_bytes);
    const chunk_hash_hex = std.fmt.bytesToHex(chunk_hash_bytes, .lower);

    var chunks_dir = try xit_dir.openDir("chunks", .{});
    defer chunks_dir.close();

    const chunk_file = try chunks_dir.openFile(&chunk_hash_hex, .{});
    defer chunk_file.close();
    try chunk_file.seekTo(position % CHUNK_SIZE);
    return try chunk_file.read(buf);
}

pub const ChunkObjectReader = struct {
    xit_dir: std.fs.Dir,
    chunk_hashes_reader: rp.Repo(.xit).DB.Cursor(.read_only).Reader,
    position: u64,

    pub const Error = std.fs.File.OpenError || rp.Repo(.xit).DB.Cursor(.read_only).Reader.Error || error{InvalidOffset};

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
        return try readChunk(self.xit_dir, &self.chunk_hashes_reader, self.position, buf);
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
