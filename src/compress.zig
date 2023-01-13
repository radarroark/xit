//! well, this isn't very good so far, but it's not like you
//! could do any better. right now i'm loading the file
//! completely in memory to compress/decompress. i set a
//! really low file size limit and throw an error if it's too big.
//! this will obviously have to change but i don't feel like
//! figuring out incremental file compression right now, and
//! i'd rather make progress elsewhere since i'll be testing with
//! tiny files for a long time anyway.

const std = @import("std");
const deflate = std.compress.deflate;

const MAX_FILE_SIZE_BYTES = 1024;

const CompressError = error{
    FileTooLarge,
};

pub fn compress(in: std.fs.File, out: std.fs.File, allocator: std.mem.Allocator) !void {
    // read the in file into memory
    var read_buffer = [_]u8{0} ** MAX_FILE_SIZE_BYTES;
    const in_size = try in.pread(&read_buffer, 0);
    if (in_size == MAX_FILE_SIZE_BYTES) {
        return CompressError.FileTooLarge;
    }

    // init the compressor
    var write_buffer = std.ArrayList(u8).init(allocator);
    defer write_buffer.deinit();
    var comp = try deflate.compressor(allocator, write_buffer.writer(), .{ .level = .best_speed });
    defer comp.deinit();

    // do the dirty work
    _ = try comp.write(read_buffer[0..in_size]);
    try comp.flush();

    // write the result to the out file
    _ = try out.write(write_buffer.items);
}

pub fn decompress(in: std.fs.File, out: std.fs.File, allocator: std.mem.Allocator) !void {
    // read the in file into memory
    var read_buffer = [_]u8{0} ** MAX_FILE_SIZE_BYTES;
    const in_size = try in.pread(&read_buffer, 0);
    if (in_size == MAX_FILE_SIZE_BYTES) {
        return CompressError.FileTooLarge;
    }

    // init the decompressor
    var fib = std.io.fixedBufferStream(read_buffer[0..in_size]);
    var comp = try deflate.decompressor(allocator, fib.reader(), null);
    defer comp.deinit();

    // do the dirty work
    var write_buffer = [_]u8{0} ** MAX_FILE_SIZE_BYTES;
    const out_size = try comp.reader().read(&write_buffer);
    if (out_size == MAX_FILE_SIZE_BYTES) {
        return CompressError.FileTooLarge;
    }

    // write the result to the out file
    _ = try out.write(write_buffer[0..out_size]);
}
