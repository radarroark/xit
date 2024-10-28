const std = @import("std");
const hash = @import("./hash.zig");
const rp = @import("./repo.zig");

const CHUNK_SIZE = 1024;

pub fn writeChunks(state: rp.Repo(.xit).State(.read_write), file: anytype) !void {
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
        var hash_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
        try hash.sha1Buffer(chunk, &hash_buffer);
        const chunk_hash = std.fmt.bytesToHex(hash_buffer, .lower);
        if (chunks_dir.openFile(&chunk_hash, .{})) |chunk_file| {
            chunk_file.close();
            continue;
        } else |err| switch (err) {
            error.FileNotFound => {
                const chunk_file = try chunks_dir.createFile(&chunk_hash, .{});
                try chunk_file.writeAll(chunk);
            },
            else => return err,
        }
    }
}
