const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const hfd = @import("huffman_decoder.zig");
const BitReader = @import("bit_reader.zig").BitReader;
const CircularBuffer = @import("CircularBuffer.zig");
const Container = @import("container.zig").Container;
const Token = @import("Token.zig");
const codegen_order = @import("consts.zig").huffman.codegen_order;

/// Decompresses deflate bit stream `reader` and writes uncompressed data to the
/// `writer` stream.
pub fn decompress(comptime container: Container, reader: anytype, writer: anytype) !void {
    var d = decompressor(container, reader);
    try d.decompress(writer);
}

/// Inflate decompressor for the reader type.
pub fn decompressor(comptime container: Container, reader: anytype) Decompressor(container, @TypeOf(reader)) {
    return Decompressor(container, @TypeOf(reader)).init(reader);
}

pub fn Decompressor(comptime container: Container, comptime ReaderType: type) type {
    // zlib has 4 bytes footer, lookahead of 4 bytes ensures that we will not overshoot.
    // gzip has 8 bytes footer so we will not overshoot even with 8 bytes of lookahead.
    // For raw deflate there is always possibility of overshot so we use 8 bytes lookahead.
    const lookahead: type = if (container == .zlib) u32 else u64;
    return Inflate(container, lookahead, ReaderType);
}

/// Inflate decompresses deflate bit stream. Reads compressed data from reader
/// provided in init. Decompressed data are stored in internal hist buffer and
/// can be accesses iterable `next` or reader interface.
///
/// Container defines header/footer wrapper around deflate bit stream. Can be
/// gzip or zlib.
///
/// Deflate bit stream consists of multiple blocks. Block can be one of three types:
///   * stored, non compressed, max 64k in size
///   * fixed, huffman codes are predefined
///   * dynamic, huffman code tables are encoded at the block start
///
/// `step` function runs decoder until internal `hist` buffer is full. Client
/// than needs to read that data in order to proceed with decoding.
///
/// Allocates 74.5K of internal buffers, most important are:
///   * 64K for history (CircularBuffer)
///   * ~10K huffman decoders (Literal and DistanceDecoder)
///
pub fn Inflate(comptime container: Container, comptime LookaheadType: type, comptime ReaderType: type) type {
    assert(LookaheadType == u32 or LookaheadType == u64);
    const BitReaderType = BitReader(LookaheadType, ReaderType);

    return struct {
        //const BitReaderType = BitReader(ReaderType);
        const F = BitReaderType.flag;

        bits: BitReaderType = .{},
        hist: CircularBuffer = .{},
        // Hashes, produces checkusm, of uncompressed data for gzip/zlib footer.
        hasher: container.Hasher() = .{},

        // dynamic block huffman code decoders
        lit_dec: hfd.LiteralDecoder = .{}, // literals
        dst_dec: hfd.DistanceDecoder = .{}, // distances

        // current read state
        bfinal: u1 = 0,
        block_type: u2 = 0b11,
        state: ReadState = .protocol_header,

        const ReadState = enum {
            protocol_header,
            block_header,
            block,
            protocol_footer,
            end,
        };

        const Self = @This();

        pub const Error = BitReaderType.Error || Container.Error || hfd.Error || error{
            InvalidCode,
            InvalidMatch,
            InvalidBlockType,
            WrongStoredBlockNlen,
            InvalidDynamicBlockHeader,
        };

        pub fn init(rt: ReaderType) Self {
            return .{ .bits = BitReaderType.init(rt) };
        }

        fn blockHeader(self: *Self) !void {
            self.bfinal = try self.bits.read(u1);
            self.block_type = try self.bits.read(u2);
        }

        fn storedBlock(self: *Self) !bool {
            self.bits.alignToByte(); // skip padding until byte boundary
            // everything after this is byte aligned in stored block
            var len = try self.bits.read(u16);
            const nlen = try self.bits.read(u16);
            if (len != ~nlen) return error.WrongStoredBlockNlen;

            while (len > 0) {
                const buf = self.hist.getWritable(len);
                try self.bits.readAll(buf);
                len -= @intCast(buf.len);
            }
            return true;
        }

        fn fixedBlock(self: *Self) !bool {
            while (!self.hist.full()) {
                const code = try self.bits.readFixedCode();
                switch (code) {
                    0...255 => self.hist.write(@intCast(code)),
                    256 => return true, // end of block
                    257...285 => try self.fixedDistanceCode(@intCast(code - 257)),
                    else => return error.InvalidCode,
                }
            }
            return false;
        }

        // Handles fixed block non literal (length) code.
        // Length code is followed by 5 bits of distance code.
        fn fixedDistanceCode(self: *Self, code: u8) !void {
            try self.bits.fill(5 + 5 + 13);
            const length = try self.decodeLength(code);
            const distance = try self.decodeDistance(try self.bits.readF(u5, F.buffered | F.reverse));
            try self.hist.writeMatch(length, distance);
        }

        inline fn decodeLength(self: *Self, code: u8) !u16 {
            if (code > 28) return error.InvalidCode;
            const ml = Token.matchLength(code);
            return if (ml.extra_bits == 0) // 0 - 5 extra bits
                ml.base
            else
                ml.base + try self.bits.readN(ml.extra_bits, F.buffered);
        }

        fn decodeDistance(self: *Self, code: u8) !u16 {
            if (code > 29) return error.InvalidCode;
            const md = Token.matchDistance(code);
            return if (md.extra_bits == 0) // 0 - 13 extra bits
                md.base
            else
                md.base + try self.bits.readN(md.extra_bits, F.buffered);
        }

        fn dynamicBlockHeader(self: *Self) !void {
            const hlit: u16 = @as(u16, try self.bits.read(u5)) + 257; // number of ll code entries present - 257
            const hdist: u16 = @as(u16, try self.bits.read(u5)) + 1; // number of distance code entries - 1
            const hclen: u8 = @as(u8, try self.bits.read(u4)) + 4; // hclen + 4 code lengths are encoded

            if (hlit > 286 or hdist > 30)
                return error.InvalidDynamicBlockHeader;

            // lengths for code lengths
            var cl_lens = [_]u4{0} ** 19;
            for (0..hclen) |i| {
                cl_lens[codegen_order[i]] = try self.bits.read(u3);
            }
            var cl_dec: hfd.CodegenDecoder = .{};
            try cl_dec.generate(&cl_lens);

            // decoded code lengths
            var dec_lens = [_]u4{0} ** (286 + 30);
            var pos: usize = 0;
            while (pos < hlit + hdist) {
                const sym = try cl_dec.find(try self.bits.peekF(u7, F.reverse));
                try self.bits.shift(sym.code_bits);
                pos += try self.dynamicCodeLength(sym.symbol, &dec_lens, pos);
            }
            if (pos > hlit + hdist) {
                return error.InvalidDynamicBlockHeader;
            }

            // literal code lengths to literal decoder
            try self.lit_dec.generate(dec_lens[0..hlit]);

            // distance code lengths to distance decoder
            try self.dst_dec.generate(dec_lens[hlit .. hlit + hdist]);
        }

        // Decode code length symbol to code length. Writes decoded length into
        // lens slice starting at position pos. Returns number of positions
        // advanced.
        fn dynamicCodeLength(self: *Self, code: u16, lens: []u4, pos: usize) !usize {
            if (pos >= lens.len)
                return error.InvalidDynamicBlockHeader;

            switch (code) {
                0...15 => {
                    // Represent code lengths of 0 - 15
                    lens[pos] = @intCast(code);
                    return 1;
                },
                16 => {
                    // Copy the previous code length 3 - 6 times.
                    // The next 2 bits indicate repeat length
                    const n: u8 = @as(u8, try self.bits.read(u2)) + 3;
                    if (pos == 0 or pos + n > lens.len)
                        return error.InvalidDynamicBlockHeader;
                    for (0..n) |i| {
                        lens[pos + i] = lens[pos + i - 1];
                    }
                    return n;
                },
                // Repeat a code length of 0 for 3 - 10 times. (3 bits of length)
                17 => return @as(u8, try self.bits.read(u3)) + 3,
                // Repeat a code length of 0 for 11 - 138 times (7 bits of length)
                18 => return @as(u8, try self.bits.read(u7)) + 11,
                else => return error.InvalidDynamicBlockHeader,
            }
        }

        // In larger archives most blocks are usually dynamic, so decompression
        // performance depends on this function.
        fn dynamicBlock(self: *Self) !bool {
            // Hot path loop!
            while (!self.hist.full()) {
                try self.bits.fill(15); // optimization so other bit reads can be buffered (avoiding one `if` in hot path)
                const sym = try self.decodeSymbol(&self.lit_dec);

                switch (sym.kind) {
                    .literal => self.hist.write(sym.symbol),
                    .match => { // Decode match backreference <length, distance>
                        // fill so we can use buffered reads
                        if (LookaheadType == u32)
                            try self.bits.fill(5 + 15)
                        else
                            try self.bits.fill(5 + 15 + 13);
                        const length = try self.decodeLength(sym.symbol);
                        const dsm = try self.decodeSymbol(&self.dst_dec);
                        if (LookaheadType == u32) try self.bits.fill(13);
                        const distance = try self.decodeDistance(dsm.symbol);
                        try self.hist.writeMatch(length, distance);
                    },
                    .end_of_block => return true,
                }
            }
            return false;
        }

        // Peek 15 bits from bits reader (maximum code len is 15 bits). Use
        // decoder to find symbol for that code. We then know how many bits is
        // used. Shift bit reader for that much bits, those bits are used. And
        // return symbol.
        fn decodeSymbol(self: *Self, decoder: anytype) !hfd.Symbol {
            const sym = try decoder.find(try self.bits.peekF(u15, F.buffered | F.reverse));
            try self.bits.shift(sym.code_bits);
            return sym;
        }

        fn step(self: *Self) !void {
            switch (self.state) {
                .protocol_header => {
                    try container.parseHeader(&self.bits);
                    self.state = .block_header;
                },
                .block_header => {
                    try self.blockHeader();
                    self.state = .block;
                    if (self.block_type == 2) try self.dynamicBlockHeader();
                },
                .block => {
                    const done = switch (self.block_type) {
                        0 => try self.storedBlock(),
                        1 => try self.fixedBlock(),
                        2 => try self.dynamicBlock(),
                        else => return error.InvalidBlockType,
                    };
                    if (done) {
                        self.state = if (self.bfinal == 1) .protocol_footer else .block_header;
                    }
                },
                .protocol_footer => {
                    self.bits.alignToByte();
                    try container.parseFooter(&self.hasher, &self.bits);
                    self.state = .end;
                },
                .end => {},
            }
        }

        /// Replaces the inner reader with new reader.
        pub fn setReader(self: *Self, new_reader: ReaderType) void {
            self.bits.forward_reader = new_reader;
            if (self.state == .end or self.state == .protocol_footer) {
                self.state = .protocol_header;
            }
        }

        // Reads all compressed data from the internal reader and outputs plain
        // (uncompressed) data to the provided writer.
        pub fn decompress(self: *Self, writer: anytype) !void {
            while (try self.next()) |buf| {
                try writer.writeAll(buf);
            }
        }

        /// Returns the number of bytes that have been read from the internal
        /// reader but not yet consumed by the decompressor.
        pub fn unreadBytes(self: Self) usize {
            // There can be no error here: the denominator is not zero, and
            // overflow is not possible since the type is unsigned.
            return std.math.divCeil(usize, self.bits.nbits, 8) catch unreachable;
        }

        // Iterator interface

        /// Can be used in iterator like loop without memcpy to another buffer:
        ///   while (try inflate.next()) |buf| { ... }
        pub fn next(self: *Self) Error!?[]const u8 {
            const out = try self.get(0);
            if (out.len == 0) return null;
            return out;
        }

        /// Returns decompressed data from internal sliding window buffer.
        /// Returned buffer can be any length between 0 and `limit` bytes. 0
        /// returned bytes means end of stream reached. With limit=0 returns as
        /// much data it can. It newer will be more than 65536 bytes, which is
        /// size of internal buffer.
        pub fn get(self: *Self, limit: usize) Error![]const u8 {
            while (true) {
                const out = self.hist.readAtMost(limit);
                if (out.len > 0) {
                    self.hasher.update(out);
                    return out;
                }
                if (self.state == .end) return out;
                try self.step();
            }
        }

        // Reader interface

        pub const Reader = std.io.GenericReader(*Self, Error, read);

        /// Returns the number of bytes read. It may be less than buffer.len.
        /// If the number of bytes read is 0, it means end of stream.
        /// End of stream is not an error condition.
        pub fn read(self: *Self, buffer: []u8) Error!usize {
            if (buffer.len == 0) return 0;
            const out = try self.get(buffer.len);
            @memcpy(buffer[0..out.len], out);
            return out.len;
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }
    };
}
