//! well, this isn't very good so far, but it's not like you
//! could do any better.

const std = @import("std");
const deflate = std.compress.deflate;
const zlib = std.compress.zlib;

const MAX_FILE_READ_BYTES = 1024; // FIXME: this is arbitrary...

pub fn compress(in: std.fs.File, out: std.fs.File) !void {
    // init stream from input file
    var zlib_stream = try zlib.compressor(out.writer(), .{ .level = .default });

    // write the compressed data to the output file
    try in.seekTo(0);
    const reader = in.reader();
    var buf = [_]u8{0} ** MAX_FILE_READ_BYTES;
    while (true) {
        // read from file
        const size = try reader.read(&buf);
        if (size == 0) break;
        // compress
        _ = try zlib_stream.write(buf[0..size]);
    }
    try zlib_stream.finish();
}

pub fn decompress(in: std.fs.File, out: std.fs.File, skip_header: bool) !void {
    // init stream from input file
    try in.seekTo(0);
    var zlib_stream = zlib.decompressor(in.reader());
    if (skip_header) {
        // skip section in beginning of file which is not compressed
        try zlib_stream.reader().skipUntilDelimiterOrEof(0);
    }

    // write the decompressed data to the output file
    const writer = out.writer();
    var buf = [_]u8{0} ** MAX_FILE_READ_BYTES;
    while (true) {
        // read from file
        const size = try zlib_stream.read(&buf);
        if (size == 0) break;
        // decompress
        _ = try writer.write(buf[0..size]);
    }
}

// does the same thing as decompress, except it remains completely
// in memory and can clean itself up via deinit.
const MAX_FILE_SIZE_BYTES = 1024;
const CompressError = error{
    FileTooLarge,
};
pub const Decompressed = struct {
    buffer: [MAX_FILE_SIZE_BYTES]u8,
    stream: std.compress.zlib.Decompressor(std.io.Reader(*std.io.FixedBufferStream([]u8), std.io.FixedBufferStream([]u8).ReadError, std.io.FixedBufferStream([]u8).read)),

    pub fn init(in: std.fs.File) !Decompressed {
        var decompressed = Decompressed{
            .buffer = [_]u8{0} ** MAX_FILE_SIZE_BYTES,
            .stream = undefined,
        };

        // read the in file into memory
        const in_size = try in.pread(&decompressed.buffer, 0);
        if (in_size == MAX_FILE_SIZE_BYTES) {
            return CompressError.FileTooLarge;
        }

        // create the stream
        var fixed_buffer = std.io.fixedBufferStream(decompressed.buffer[0..in_size]);
        decompressed.stream = zlib.decompressor(fixed_buffer.reader());

        return decompressed;
    }
};

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
    defer hello_txt.close();
    try hello_txt.writeAll(hello_txt_content);

    // compress the file
    var out_compressed = try temp_dir.createFile("hello.txt.compressed", .{ .read = true });
    defer out_compressed.close();
    try compress(hello_txt, out_compressed);

    // decompress it so we know it works
    var out_decompressed = try temp_dir.createFile("out_decompressed", .{ .read = true });
    defer out_decompressed.close();
    try decompress(out_compressed, out_decompressed, false);

    // read the decompressed file into memory and check that it's the same
    var read_buffer = [_]u8{0} ** MAX_FILE_SIZE_BYTES;
    const size = try out_decompressed.pread(&read_buffer, 0);
    try std.testing.expect(std.mem.eql(u8, hello_txt_content, read_buffer[0..size]));

    // decompress purely in memory
    var decompressed = try Decompressed.init(out_compressed);
    const buf = try decompressed.stream.reader().readAllAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(buf);
    try std.testing.expect(std.mem.eql(u8, hello_txt_content, buf));
}
