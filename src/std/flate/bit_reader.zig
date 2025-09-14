const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

pub fn bitReader(comptime T: type, reader: anytype) BitReader(T, @TypeOf(reader)) {
    return BitReader(T, @TypeOf(reader)).init(reader);
}

pub fn BitReader64(comptime ReaderType: type) type {
    return BitReader(u64, ReaderType);
}

pub fn BitReader32(comptime ReaderType: type) type {
    return BitReader(u32, ReaderType);
}

/// Bit reader used during inflate (decompression). Has internal buffer of 64
/// bits which shifts right after bits are consumed. Uses forward_reader to fill
/// that internal buffer when needed.
///
/// readF is the core function. Supports few different ways of getting bits
/// controlled by flags. In hot path we try to avoid checking whether we need to
/// fill buffer from forward_reader by calling fill in advance and readF with
/// buffered flag set.
///
pub fn BitReader(comptime T: type, comptime ReaderType: type) type {
    assert(T == u32 or T == u64);
    const t_bytes: usize = @sizeOf(T);
    const Tshift = if (T == u64) u6 else u5;

    return struct {
        // Underlying reader used for filling internal bits buffer
        forward_reader: ReaderType = undefined,
        // Internal buffer of 64 bits
        bits: T = 0,
        // Number of bits in the buffer
        nbits: u32 = 0,

        const Self = @This();

        pub const Error = ReaderType.Error || error{EndOfStream};

        pub fn init(rdr: ReaderType) Self {
            var self = Self{ .forward_reader = rdr };
            self.fill(1) catch {};
            return self;
        }

        /// Try to have `nice` bits are available in buffer. Reads from
        /// forward reader if there is no `nice` bits in buffer. Returns error
        /// if end of forward stream is reached and internal buffer is empty.
        /// It will not error if less than `nice` bits are in buffer, only when
        /// all bits are exhausted. During inflate we usually know what is the
        /// maximum bits for the next step but usually that step will need less
        /// bits to decode. So `nice` is not hard limit, it will just try to have
        /// that number of bits available. If end of forward stream is reached
        /// it may be some extra zero bits in buffer.
        pub inline fn fill(self: *Self, nice: u6) !void {
            if (self.nbits >= nice and nice != 0) {
                return; // We have enough bits
            }
            // Read more bits from forward reader

            // Number of empty bytes in bits, round nbits to whole bytes.
            const empty_bytes =
                @as(u8, if (self.nbits & 0x7 == 0) t_bytes else t_bytes - 1) - // 8 for 8, 16, 24..., 7 otherwise
                (self.nbits >> 3); // 0 for 0-7, 1 for 8-16, ... same as / 8

            var buf: [t_bytes]u8 = [_]u8{0} ** t_bytes;
            const bytes_read = self.forward_reader.readAll(buf[0..empty_bytes]) catch 0;
            if (bytes_read > 0) {
                const u: T = std.mem.readInt(T, buf[0..t_bytes], .little);
                self.bits |= u << @as(Tshift, @intCast(self.nbits));
                self.nbits += 8 * @as(u8, @intCast(bytes_read));
                return;
            }

            if (self.nbits == 0)
                return error.EndOfStream;
        }

        /// Read exactly buf.len bytes into buf.
        pub fn readAll(self: *Self, buf: []u8) !void {
            assert(self.alignBits() == 0); // internal bits must be at byte boundary

            // First read from internal bits buffer.
            var n: usize = 0;
            while (self.nbits > 0 and n < buf.len) {
                buf[n] = try self.readF(u8, flag.buffered);
                n += 1;
            }
            // Then use forward reader for all other bytes.
            try self.forward_reader.readNoEof(buf[n..]);
        }

        pub const flag = struct {
            pub const peek: u3 = 0b001; // dont advance internal buffer, just get bits, leave them in buffer
            pub const buffered: u3 = 0b010; // assume that there is no need to fill, fill should be called before
            pub const reverse: u3 = 0b100; // bit reverse read bits
        };

        /// Alias for readF(U, 0).
        pub fn read(self: *Self, comptime U: type) !U {
            return self.readF(U, 0);
        }

        /// Alias for readF with flag.peak set.
        pub inline fn peekF(self: *Self, comptime U: type, comptime how: u3) !U {
            return self.readF(U, how | flag.peek);
        }

        /// Read with flags provided.
        pub fn readF(self: *Self, comptime U: type, comptime how: u3) !U {
            if (U == T) {
                assert(how == 0);
                assert(self.alignBits() == 0);
                try self.fill(@bitSizeOf(T));
                if (self.nbits != @bitSizeOf(T)) return error.EndOfStream;
                const v = self.bits;
                self.nbits = 0;
                self.bits = 0;
                return v;
            }
            const n: Tshift = @bitSizeOf(U);
            switch (how) {
                0 => { // `normal` read
                    try self.fill(n); // ensure that there are n bits in the buffer
                    const u: U = @truncate(self.bits); // get n bits
                    try self.shift(n); // advance buffer for n
                    return u;
                },
                (flag.peek) => { // no shift, leave bits in the buffer
                    try self.fill(n);
                    return @truncate(self.bits);
                },
                flag.buffered => { // no fill, assume that buffer has enough bits
                    const u: U = @truncate(self.bits);
                    try self.shift(n);
                    return u;
                },
                (flag.reverse) => { // same as 0 with bit reverse
                    try self.fill(n);
                    const u: U = @truncate(self.bits);
                    try self.shift(n);
                    return @bitReverse(u);
                },
                (flag.peek | flag.reverse) => {
                    try self.fill(n);
                    return @bitReverse(@as(U, @truncate(self.bits)));
                },
                (flag.buffered | flag.reverse) => {
                    const u: U = @truncate(self.bits);
                    try self.shift(n);
                    return @bitReverse(u);
                },
                (flag.peek | flag.buffered) => {
                    return @truncate(self.bits);
                },
                (flag.peek | flag.buffered | flag.reverse) => {
                    return @bitReverse(@as(U, @truncate(self.bits)));
                },
            }
        }

        /// Read n number of bits.
        /// Only buffered flag can be used in how.
        pub fn readN(self: *Self, n: u4, comptime how: u3) !u16 {
            switch (how) {
                0 => {
                    try self.fill(n);
                },
                flag.buffered => {},
                else => unreachable,
            }
            const mask: u16 = (@as(u16, 1) << n) - 1;
            const u: u16 = @as(u16, @truncate(self.bits)) & mask;
            try self.shift(n);
            return u;
        }

        /// Advance buffer for n bits.
        pub fn shift(self: *Self, n: Tshift) !void {
            if (n > self.nbits) return error.EndOfStream;
            self.bits >>= n;
            self.nbits -= n;
        }

        /// Skip n bytes.
        pub fn skipBytes(self: *Self, n: u16) !void {
            for (0..n) |_| {
                try self.fill(8);
                try self.shift(8);
            }
        }

        // Number of bits to align stream to the byte boundary.
        fn alignBits(self: *Self) u3 {
            return @intCast(self.nbits & 0x7);
        }

        /// Align stream to the byte boundary.
        pub fn alignToByte(self: *Self) void {
            const ab = self.alignBits();
            if (ab > 0) self.shift(ab) catch unreachable;
        }

        /// Skip zero terminated string.
        pub fn skipStringZ(self: *Self) !void {
            while (true) {
                if (try self.readF(u8, 0) == 0) break;
            }
        }

        /// Read deflate fixed fixed code.
        /// Reads first 7 bits, and then maybe 1 or 2 more to get full 7,8 or 9 bit code.
        /// ref: https://datatracker.ietf.org/doc/html/rfc1951#page-12
        ///         Lit Value    Bits        Codes
        ///          ---------    ----        -----
        ///            0 - 143     8          00110000 through
        ///                                   10111111
        ///          144 - 255     9          110010000 through
        ///                                   111111111
        ///          256 - 279     7          0000000 through
        ///                                   0010111
        ///          280 - 287     8          11000000 through
        ///                                   11000111
        pub fn readFixedCode(self: *Self) !u16 {
            try self.fill(7 + 2);
            const code7 = try self.readF(u7, flag.buffered | flag.reverse);
            if (code7 <= 0b0010_111) { // 7 bits, 256-279, codes 0000_000 - 0010_111
                return @as(u16, code7) + 256;
            } else if (code7 <= 0b1011_111) { // 8 bits, 0-143, codes 0011_0000 through 1011_1111
                return (@as(u16, code7) << 1) + @as(u16, try self.readF(u1, flag.buffered)) - 0b0011_0000;
            } else if (code7 <= 0b1100_011) { // 8 bit, 280-287, codes 1100_0000 - 1100_0111
                return (@as(u16, code7 - 0b1100000) << 1) + try self.readF(u1, flag.buffered) + 280;
            } else { // 9 bit, 144-255, codes 1_1001_0000 - 1_1111_1111
                return (@as(u16, code7 - 0b1100_100) << 2) + @as(u16, try self.readF(u2, flag.buffered | flag.reverse)) + 144;
            }
        }
    };
}
