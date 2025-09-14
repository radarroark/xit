/// Deflate is a lossless data compression file format that uses a combination
/// of LZ77 and Huffman coding.
pub const deflate = @import("flate/deflate.zig");

/// Inflate is the decoding process that takes a Deflate bitstream for
/// decompression and correctly produces the original full-size data or file.
pub const inflate = @import("flate/inflate.zig");

/// Decompress compressed data from reader and write plain data to the writer.
pub fn decompress(reader: anytype, writer: anytype) !void {
    try inflate.decompress(.raw, reader, writer);
}

/// Decompressor type
pub fn Decompressor(comptime ReaderType: type) type {
    return inflate.Decompressor(.raw, ReaderType);
}

/// Create Decompressor which will read compressed data from reader.
pub fn decompressor(reader: anytype) Decompressor(@TypeOf(reader)) {
    return inflate.decompressor(.raw, reader);
}

/// Compression level, trades between speed and compression size.
pub const Options = deflate.Options;

/// Compress plain data from reader and write compressed data to the writer.
pub fn compress(reader: anytype, writer: anytype, options: Options) !void {
    try deflate.compress(.raw, reader, writer, options);
}

/// Compressor type
pub fn Compressor(comptime WriterType: type) type {
    return deflate.Compressor(.raw, WriterType);
}

/// Create Compressor which outputs compressed data to the writer.
pub fn compressor(writer: anytype, options: Options) !Compressor(@TypeOf(writer)) {
    return try deflate.compressor(.raw, writer, options);
}

/// Huffman only compression. Without Lempel-Ziv match searching. Faster
/// compression, less memory requirements but bigger compressed sizes.
pub const huffman = struct {
    pub fn compress(reader: anytype, writer: anytype) !void {
        try deflate.huffman.compress(.raw, reader, writer);
    }

    pub fn Compressor(comptime WriterType: type) type {
        return deflate.huffman.Compressor(.raw, WriterType);
    }

    pub fn compressor(writer: anytype) !huffman.Compressor(@TypeOf(writer)) {
        return deflate.huffman.compressor(.raw, writer);
    }
};

// No compression store only. Compressed size is slightly bigger than plain.
pub const store = struct {
    pub fn compress(reader: anytype, writer: anytype) !void {
        try deflate.store.compress(.raw, reader, writer);
    }

    pub fn Compressor(comptime WriterType: type) type {
        return deflate.store.Compressor(.raw, WriterType);
    }

    pub fn compressor(writer: anytype) !store.Compressor(@TypeOf(writer)) {
        return deflate.store.compressor(.raw, writer);
    }
};

/// Container defines header/footer around deflate bit stream. Gzip and zlib
/// compression algorithms are containers around deflate bit stream body.
const Container = @import("flate/container.zig").Container;
const std = @import("std");
const testing = std.testing;
const fixedBufferStream = std.io.fixedBufferStream;
const print = std.debug.print;
const builtin = @import("builtin");
