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

test "compress and decompress" {
    const temp_dir_name = "temp-test-compress";

    const allocator = std.testing.allocator;
    var args = std.ArrayList([]const u8).init(allocator);
    defer args.deinit();

    // get the current working directory path
    var cwd_path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
    const cwd_path = try std.fs.cwd().realpath(".", &cwd_path_buffer);
    var cwd = try std.fs.openDirAbsolute(cwd_path, .{});
    defer cwd.close();

    // create the temp dir
    var temp_dir = try cwd.makeOpenPath(temp_dir_name, .{});
    defer cwd.deleteTree(temp_dir_name) catch {};
    defer temp_dir.close();

    // make file
    const hello_txt_content = "hello, world!";
    var hello_txt = try temp_dir.createFile("hello.txt", .{ .read = true });
    try hello_txt.writeAll(hello_txt_content);
    defer hello_txt.close();

    // compress the file
    var out_compressed = try temp_dir.createFile("hello.txt.compressed", .{ .read = true });
    defer out_compressed.close();
    try compress(hello_txt, out_compressed, allocator);

    // decompress it so we know it works
    var out_decompressed = try temp_dir.createFile("out_decompressed", .{ .read = true });
    defer out_decompressed.close();
    try decompress(out_compressed, out_decompressed, allocator);

    // read the decompressed file into memory and check that it's the same
    var read_buffer = [_]u8{0} ** MAX_FILE_SIZE_BYTES;
    const size = try out_decompressed.pread(&read_buffer, 0);
    try std.testing.expect(std.mem.eql(u8, hello_txt_content, read_buffer[0..size]));
}
