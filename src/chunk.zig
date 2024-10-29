const std = @import("std");
const hash = @import("./hash.zig");
const rp = @import("./repo.zig");
const io = @import("./io.zig");

const CHUNK_SIZE = 1024;

pub fn writeChunks(
    state: rp.Repo(.xit).State(.read_write),
    allocator: std.mem.Allocator,
    file: anytype,
    object_hash: hash.Hash,
    object_header: []const u8,
) !void {
    // get writer to the chunk hashes for the given file hash (null if it already exists)
    const blob_id_to_chunk_hashes_cursor = try state.extra.moment.putCursor(hash.hashBuffer("object-id->chunk-hashes"));
    const blob_id_to_chunk_hashes = try rp.Repo(.xit).DB.HashMap(.read_write).init(blob_id_to_chunk_hashes_cursor);
    var chunk_hashes_cursor = try blob_id_to_chunk_hashes.putCursor(object_hash);
    var writer_maybe = if (chunk_hashes_cursor.slot().tag == .none) try chunk_hashes_cursor.writer() else null;

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

        // write chunk as separate file if necessary
        const chunk_hash_hex = std.fmt.bytesToHex(chunk_hash_bytes, .lower);
        if (chunks_dir.openFile(&chunk_hash_hex, .{})) |chunk_file| {
            chunk_file.close();
        } else |err| switch (err) {
            error.FileNotFound => {
                var lock = try io.LockFile.init(allocator, chunks_dir, &chunk_hash_hex);
                defer lock.deinit();
                try lock.lock_file.writeAll(chunk);
                lock.success = true;
            },
            else => return err,
        }

        // write hash to db if necessary
        if (writer_maybe) |*writer| {
            try writer.writeAll(&chunk_hash_bytes);
        }
    }

    // finish writing to db if necessary
    if (writer_maybe) |*writer| {
        try writer.finish();
    }

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
    try chunk_file.seekTo(position % CHUNK_SIZE);
    return try chunk_file.read(buf);
}
