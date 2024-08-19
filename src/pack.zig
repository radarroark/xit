const std = @import("std");
const hash = @import("./hash.zig");
const rp = @import("./repo.zig");

fn findOid(idx_file: std.fs.File, oid_list_pos: u64, index: usize) ![hash.SHA1_BYTES_LEN]u8 {
    const reader = idx_file.reader();
    const oid_pos = oid_list_pos + (index * hash.SHA1_BYTES_LEN);
    try idx_file.seekTo(oid_pos);
    return try reader.readBytesNoEof(hash.SHA1_BYTES_LEN);
}

fn findObjectIndex(idx_file: std.fs.File, fanout_table: [256]u32, oid_list_pos: u64, oid_bytes: [hash.SHA1_BYTES_LEN]u8) !?usize {
    var left: u32 = 0;
    var right = fanout_table[oid_bytes[0]];

    // binary search for the oid
    while (left < right) {
        const mid = left + ((right - left) / 2);
        const mid_oid_bytes = try findOid(idx_file, oid_list_pos, mid);
        if (std.mem.eql(u8, &oid_bytes, &mid_oid_bytes)) {
            return mid;
        } else if (std.mem.lessThan(u8, &oid_bytes, &mid_oid_bytes)) {
            if (mid == 0) {
                break;
            } else {
                right = mid - 1;
            }
        } else {
            if (left == fanout_table[oid_bytes[0]]) {
                break;
            } else {
                left = mid + 1;
            }
        }
    }

    const right_oid_bytes = try findOid(idx_file, oid_list_pos, right);
    if (std.mem.eql(u8, &oid_bytes, &right_oid_bytes)) {
        return right;
    }

    return null;
}

fn findOffset(idx_file: std.fs.File, fanout_table: [256]u32, oid_list_pos: u64, index: usize) !u64 {
    const reader = idx_file.reader();

    const entry_count = fanout_table[fanout_table.len - 1];
    const crc_size: u64 = 4;
    const offset_size: u64 = 4;
    const crc_list_pos = oid_list_pos + (entry_count * hash.SHA1_BYTES_LEN);
    const offset_list_pos = crc_list_pos + (entry_count * crc_size);
    const offset_pos = offset_list_pos + (index * offset_size);

    try idx_file.seekTo(offset_pos);
    const offset: packed struct {
        value: u31,
        high_bit: u1,
    } = @bitCast(try reader.readInt(u32, .big));
    if (offset.high_bit == 0) {
        return offset.value;
    }

    const offset64_size: u64 = 8;
    const offset64_list_pos = offset_list_pos + (entry_count * offset_size);
    const offset64_pos = offset64_list_pos + (offset.value * offset64_size);

    try idx_file.seekTo(offset64_pos);
    return try reader.readInt(u64, .big);
}

fn searchPackIndex(idx_file: std.fs.File, oid_bytes: [hash.SHA1_BYTES_LEN]u8) !?u64 {
    const reader = idx_file.reader();

    const header = try reader.readBytesNoEof(4);
    const version = if (!std.mem.eql(u8, &[_]u8{ 255, 116, 79, 99 }, &header)) 1 else try reader.readInt(u32, .big);
    if (version != 2) {
        return error.NotImplemented;
    }

    var fanout_table = [_]u32{0} ** 256;
    for (&fanout_table) |*entry| {
        entry.* = try reader.readInt(u32, .big);
    }
    const oid_list_pos = try idx_file.getPos();

    if (try findObjectIndex(idx_file, fanout_table, oid_list_pos, oid_bytes)) |index| {
        return try findOffset(idx_file, fanout_table, oid_list_pos, index);
    }

    return null;
}

const PackOffset = struct {
    pack_id: [hash.SHA1_HEX_LEN]u8,
    value: u64,
};

fn searchPackIndexes(core: rp.Repo(.git).Core, oid_hex: [hash.SHA1_HEX_LEN]u8) !PackOffset {
    const oid_bytes = try hash.hexToBytes(oid_hex);

    var pack_dir = try core.git_dir.openDir("objects/pack", .{ .iterate = true });
    defer pack_dir.close();

    const prefix = "pack-";
    const suffix = ".idx";

    var iter = pack_dir.iterate();
    while (try iter.next()) |entry| {
        switch (entry.kind) {
            .file => {
                if (std.mem.startsWith(u8, entry.name, prefix) and std.mem.endsWith(u8, entry.name, suffix)) {
                    const pack_id = entry.name[prefix.len .. entry.name.len - suffix.len];

                    if (pack_id.len == hash.SHA1_HEX_LEN) {
                        var idx_file = try pack_dir.openFile(entry.name, .{ .mode = .read_only });
                        defer idx_file.close();

                        if (try searchPackIndex(idx_file, oid_bytes)) |offset| {
                            return .{
                                .pack_id = pack_id[0..hash.SHA1_HEX_LEN].*,
                                .value = offset,
                            };
                        }
                    }
                }
            },
            else => {},
        }
    }

    return error.PackObjectNotFound;
}
