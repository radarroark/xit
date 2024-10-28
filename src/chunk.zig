const std = @import("std");
const hash = @import("./hash.zig");
const rp = @import("./repo.zig");

const CHUNK_SIZE = 1024;

pub fn writeChunks(state: rp.Repo(.xit).State(.read_write), file: anytype, file_hash: hash.Hash) !void {
    // get writer to the chunk hashes for the given file hash (null if it already exists)
    const blob_id_to_chunk_hashes_cursor = try state.extra.moment.putCursor(hash.hashBuffer("blob-id->chunk-hashes"));
    const blob_id_to_chunk_hashes = try rp.Repo(.xit).DB.HashMap(.read_write).init(blob_id_to_chunk_hashes_cursor);
    var chunk_hashes_cursor = try blob_id_to_chunk_hashes.putCursor(file_hash);
    var writer_maybe = if (chunk_hashes_cursor.slot().tag == .none) try chunk_hashes_cursor.writer() else null;

    // make the .xit/chunks dir
    var chunks_dir = try state.core.xit_dir.makeOpenPath("chunks", .{});
    defer chunks_dir.close();

    var buffer = [_]u8{0} ** CHUNK_SIZE;
    const reader = file.reader();

    while (true) {
        // read chunk
        const size = try reader.read(&buffer);
        if (size == 0) {
            break;
        }
        const chunk = buffer[0..size];

        // write chunk as separate file if necessary
        var chunk_hash_bytes = [_]u8{0} ** hash.SHA1_BYTES_LEN;
        try hash.sha1Buffer(chunk, &chunk_hash_bytes);
        const chunk_hash_hex = std.fmt.bytesToHex(chunk_hash_bytes, .lower);
        if (chunks_dir.openFile(&chunk_hash_hex, .{})) |chunk_file| {
            chunk_file.close();
            continue;
        } else |err| switch (err) {
            error.FileNotFound => {
                const chunk_file = try chunks_dir.createFile(&chunk_hash_hex, .{});
                try chunk_file.writeAll(chunk);
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
}
