//! 64K buffer of uncompressed data created in inflate (decompression). Has enough
//! history to support writing match<length, distance>; copying length of bytes
//! from the position distance backward from current.
//!
//! Reads can return less than available bytes if they are spread across
//! different circles. So reads should repeat until get required number of bytes
//! or until returned slice is zero length.
//!
//! Note on deflate limits:
//!  * non-compressible block is limited to 65,535 bytes.
//!  * backward pointer is limited in distance to 32K bytes and in length to 258 bytes.
//!
//! Whole non-compressed block can be written without overlap. We always have
//! history of up to 64K, more then 32K needed.
//!
const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const consts = @import("consts.zig").match;

const mask = 0xffff; // 64K - 1
const buffer_len = mask + 1; // 64K buffer

const Self = @This();

buffer: [buffer_len]u8 = undefined,
wp: usize = 0, // write position
rp: usize = 0, // read position

fn writeAll(self: *Self, buf: []const u8) void {
    for (buf) |c| self.write(c);
}

/// Write literal.
pub fn write(self: *Self, b: u8) void {
    assert(self.wp - self.rp < mask);
    self.buffer[self.wp & mask] = b;
    self.wp += 1;
}

/// Write match (back-reference to the same data slice) starting at `distance`
/// back from current write position, and `length` of bytes.
pub fn writeMatch(self: *Self, length: u16, distance: u16) !void {
    if (self.wp < distance or
        length < consts.base_length or length > consts.max_length or
        distance < consts.min_distance or distance > consts.max_distance)
    {
        return error.InvalidMatch;
    }
    assert(self.wp - self.rp < mask);

    var from: usize = self.wp - distance & mask;
    const from_end: usize = from + length;
    var to: usize = self.wp & mask;
    const to_end: usize = to + length;

    self.wp += length;

    // Fast path using memcpy
    if (from_end < buffer_len and to_end < buffer_len) // start and end at the same circle
    {
        var cur_len = distance;
        var remaining_len = length;
        while (cur_len < remaining_len) {
            @memcpy(self.buffer[to..][0..cur_len], self.buffer[from..][0..cur_len]);
            to += cur_len;
            remaining_len -= cur_len;
            cur_len = cur_len * 2;
        }
        @memcpy(self.buffer[to..][0..remaining_len], self.buffer[from..][0..remaining_len]);
        return;
    }

    // Slow byte by byte
    while (to < to_end) {
        self.buffer[to & mask] = self.buffer[from & mask];
        to += 1;
        from += 1;
    }
}

/// Returns writable part of the internal buffer of size `n` at most. Advances
/// write pointer, assumes that returned buffer will be filled with data.
pub fn getWritable(self: *Self, n: usize) []u8 {
    const wp = self.wp & mask;
    const len = @min(n, buffer_len - wp);
    self.wp += len;
    return self.buffer[wp .. wp + len];
}

/// Read available data. Can return part of the available data if it is
/// spread across two circles. So read until this returns zero length.
pub fn read(self: *Self) []const u8 {
    return self.readAtMost(buffer_len);
}

/// Read part of available data. Can return less than max even if there are
/// more than max decoded data.
pub fn readAtMost(self: *Self, limit: usize) []const u8 {
    const rb = self.readBlock(if (limit == 0) buffer_len else limit);
    defer self.rp += rb.len;
    return self.buffer[rb.head..rb.tail];
}

const ReadBlock = struct {
    head: usize,
    tail: usize,
    len: usize,
};

/// Returns position of continuous read block data.
fn readBlock(self: *Self, max: usize) ReadBlock {
    const r = self.rp & mask;
    const w = self.wp & mask;
    const n = @min(
        max,
        if (w >= r) w - r else buffer_len - r,
    );
    return .{
        .head = r,
        .tail = r + n,
        .len = n,
    };
}

/// Number of free bytes for write.
pub fn free(self: *Self) usize {
    return buffer_len - (self.wp - self.rp);
}

/// Full if largest match can't fit. 258 is largest match length. That much
/// bytes can be produced in single decode step.
pub fn full(self: *Self) bool {
    return self.free() < 258 + 1;
}
