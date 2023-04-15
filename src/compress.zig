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
const zlib = std.compress.zlib;

const MAX_FILE_SIZE_BYTES = 1024;

const CompressError = error{
    FileTooLarge,
};

/// zig doesn't have a zlib compressor in the stdlib yet, so this one is implemented
/// manually. once it arrives, this code is getting tossed to the curb.
pub fn compress(in: std.fs.File, out: std.fs.File, allocator: std.mem.Allocator) !void {
    // read the in file into memory
    var read_buffer = [_]u8{0} ** MAX_FILE_SIZE_BYTES;
    const in_size = try in.pread(&read_buffer, 0);
    if (in_size == MAX_FILE_SIZE_BYTES) {
        return CompressError.FileTooLarge;
    }
    const read_slice = read_buffer[0..in_size];

    // define compression level
    const Level = enum(u2) {
        fastest = 0,
        fast = 1,
        default = 2,
        maximum = 3,
    };
    const zlib_level = Level.default;
    const deflate_level: deflate.Compression = switch (zlib_level) {
        .fastest => .no_compression,
        .fast => .best_speed,
        .default => .default_compression,
        .maximum => .best_compression,
    };

    // init the compressor
    const writer = out.writer();
    var comp = try deflate.compressor(allocator, writer, .{ .level = deflate_level });
    defer comp.deinit();

    // write the header
    const CM: u4 = 8;
    const CINFO: u4 = 7;
    const CMF: u8 = (@as(u8, CINFO) << 4) | CM;
    const FLEVEL: u2 = @enumToInt(zlib_level);
    const FDICT: u1 = 0;
    const FLG_temp = (@as(u8, FLEVEL) << 6) | (@as(u8, FDICT) << 5);
    const FCHECK: u5 = 31 - ((@as(u16, CMF) * 256 + FLG_temp) % 31);
    const FLG = FLG_temp | FCHECK;
    try writer.writeAll(&.{ CMF, FLG });

    // do the dirty work
    const comp_size = try comp.write(read_slice);
    try comp.close();

    // write the hash
    var hasher = std.hash.Adler32.init();
    hasher.update(read_slice[0..comp_size]);
    try writer.writeIntBig(u32, hasher.final());
}

pub fn decompress(allocator: std.mem.Allocator, in: std.fs.File, out: std.fs.File) !void {
    // read the in file into memory
    var read_buffer = [_]u8{0} ** MAX_FILE_SIZE_BYTES;
    const in_size = try in.pread(&read_buffer, 0);
    if (in_size == MAX_FILE_SIZE_BYTES) {
        return CompressError.FileTooLarge;
    }
    var fixed_buffer = std.io.fixedBufferStream(read_buffer[0..in_size]);

    // do the dirty work
    var zlib_stream = try zlib.zlibStream(allocator, fixed_buffer.reader());
    defer zlib_stream.deinit();
    const buf = try zlib_stream.reader().readAllAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(buf);

    // write the result to the out file
    _ = try out.write(buf);
}

// does the same thing as decompress, except it remains completely
// in memory and can clean itself up via deinit.
pub const Decompressed = struct {
    stream: std.compress.zlib.ZlibStream(std.io.Reader(*std.io.FixedBufferStream([]u8), std.io.FixedBufferStream([]u8).ReadError, std.io.FixedBufferStream([]u8).read)),

    pub fn init(allocator: std.mem.Allocator, in: std.fs.File) !Decompressed {
        // read the in file into memory
        var read_buffer = [_]u8{0} ** MAX_FILE_SIZE_BYTES;
        const in_size = try in.pread(&read_buffer, 0);
        if (in_size == MAX_FILE_SIZE_BYTES) {
            return CompressError.FileTooLarge;
        }
        var fixed_buffer = std.io.fixedBufferStream(read_buffer[0..in_size]);

        return Decompressed{
            .stream = try zlib.zlibStream(allocator, fixed_buffer.reader()),
        };
    }

    pub fn deinit(self: *Decompressed) void {
        defer self.stream.deinit();
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
    try compress(hello_txt, out_compressed, allocator);

    // decompress it so we know it works
    var out_decompressed = try temp_dir.createFile("out_decompressed", .{ .read = true });
    defer out_decompressed.close();
    try decompress(allocator, out_compressed, out_decompressed);

    // read the decompressed file into memory and check that it's the same
    var read_buffer = [_]u8{0} ** MAX_FILE_SIZE_BYTES;
    const size = try out_decompressed.pread(&read_buffer, 0);
    try std.testing.expect(std.mem.eql(u8, hello_txt_content, read_buffer[0..size]));

    // decompress purely in memory
    var decompressed = try Decompressed.init(allocator, out_compressed);
    defer decompressed.deinit();
    const buf = try decompressed.stream.reader().readAllAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(buf);
    try std.testing.expect(std.mem.eql(u8, hello_txt_content, buf));
}
