//! why are we still using sha1? well, we're stuck with it.
//! git added support for sha256 but nobody is using it. sha1
//! collisions have apparently been found, which means people can
//! theoretically make different commits that have the same hash.
//! to be fair, the attacks are pretty hard to pull off.
//! a lot of this is just a social problem...you need
//! to trust the people you are collabing with, and actually
//! read the code they share with you. i really don't think it's
//! a big deal. holy shit, i think i just changed my mind over
//! the course of writing this comment.

const std = @import("std");

const MAX_READ_BYTES = 1024;
pub const SHA1_BYTES_LEN = std.crypto.hash.Sha1.digest_length;
pub const SHA1_HEX_LEN = SHA1_BYTES_LEN * 2;

pub fn sha1_file(file: std.fs.File, out: *[SHA1_BYTES_LEN]u8) !void {
    var h = std.crypto.hash.Sha1.init(.{});
    var buffer = [_]u8{0} ** MAX_READ_BYTES;
    var offset: u64 = 0;
    while (true) {
        const size = try file.pread(&buffer, offset);
        offset += size;
        if (size == 0) {
            break;
        }
        h.update(buffer[0..size]);
    }
    h.final(out);
}

pub fn sha1_buffer(buffer: []const u8, out: *[SHA1_BYTES_LEN]u8) !void {
    var h = std.crypto.hash.Sha1.init(.{});
    h.update(buffer);
    h.final(out);
}
