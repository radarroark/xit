const std = @import("std");
const hash = @import("./hash.zig");
const rp = @import("./repo.zig");
const compress = @import("./compress.zig");

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

fn searchPackIndexes(pack_dir: std.fs.Dir, oid_hex: [hash.SHA1_HEX_LEN]u8) !PackOffset {
    const oid_bytes = try hash.hexToBytes(oid_hex);

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

pub const PackObjectReader = struct {
    pack_file: std.fs.File,
    stream: compress.ZlibStream,
    position: u64,
    size: u64,

    pub fn init(core: *rp.Repo(.git).Core, oid_hex: [hash.SHA1_HEX_LEN]u8) !PackObjectReader {
        var pack_dir = try core.git_dir.openDir("objects/pack", .{ .iterate = true });
        defer pack_dir.close();

        const pack_offset = try searchPackIndexes(pack_dir, oid_hex);

        const prefix = "pack-";
        const suffix = ".pack";

        var file_name_buf = [_]u8{0} ** (prefix.len + hash.SHA1_HEX_LEN + suffix.len);
        const file_name = try std.fmt.bufPrint(&file_name_buf, "{s}{s}{s}", .{ prefix, pack_offset.pack_id, suffix });

        var pack_file = try pack_dir.openFile(file_name, .{ .mode = .read_only });
        errdefer pack_file.close();
        const reader = pack_file.reader();

        // parse header
        const sig = try reader.readBytesNoEof(4);
        if (!std.mem.eql(u8, "PACK", &sig)) {
            return error.InvalidPackFileSig;
        }
        const version = try reader.readInt(u32, .big);
        if (version != 2) {
            return error.InvalidPackFileVersion;
        }
        _ = try reader.readInt(u32, .big); // number of objects

        try pack_file.seekTo(pack_offset.value);

        // parse object header
        const PackObjectKind = enum(u3) {
            commit = 1,
            tree = 2,
            blob = 3,
            tag = 4,
            ofs_delta = 6,
            ref_delta = 7,
        };
        const obj_header: packed struct {
            size: u4,
            kind: PackObjectKind,
            high_bit: u1,
        } = @bitCast(try reader.readByte());

        // get size of object (variable length format)
        var size: u64 = obj_header.size;
        var size_shift: u6 = @bitSizeOf(@TypeOf(obj_header.size));
        var cont = obj_header.high_bit == 1;
        while (cont) {
            const next_byte: packed struct {
                value: u7,
                high_bit: u1,
            } = @bitCast(try reader.readByte());
            cont = next_byte.high_bit == 1;
            const value: u64 = next_byte.value;
            size += (value << size_shift);
            size_shift += @bitSizeOf(@TypeOf(next_byte.value));
        }

        switch (obj_header.kind) {
            .commit, .tree, .blob, .tag => {},
            .ofs_delta => return error.UnsupportedPackObjectKind,
            .ref_delta => {
                const base_oid = try reader.readBytesNoEof(hash.SHA1_BYTES_LEN);
                const new_pack_reader = try PackObjectReader.init(core, std.fmt.bytesToHex(base_oid, .lower));
                pack_file.close();
                return new_pack_reader;
            },
        }

        return .{
            .pack_file = pack_file,
            .stream = std.compress.zlib.decompressor(reader),
            .position = 0,
            .size = size,
        };
    }

    pub fn deinit(self: *PackObjectReader) void {
        self.pack_file.close();
    }

    pub fn reset(self: *PackObjectReader) !void {
        _ = self;
        return error.NotImplemented;
    }

    pub fn skipBytes(self: *PackObjectReader, num_bytes: u64) !void {
        _ = self;
        _ = num_bytes;
        return error.NotImplemented;
    }

    pub fn read(self: *PackObjectReader, dest: []u8) !usize {
        const size = @min(dest.len, self.size - self.position);
        if (size == 0) {
            return 0;
        }
        const read_size = try self.stream.reader().read(dest[0..size]);
        self.position += size;
        return read_size;
    }

    pub fn readNoEof(self: *PackObjectReader, dest: []u8) !void {
        _ = self;
        _ = dest;
        return error.NotImplemented;
    }

    pub fn readUntilDelimiter(self: *PackObjectReader, dest: []u8, delimiter: u8) ![]u8 {
        _ = self;
        _ = dest;
        _ = delimiter;
        return error.NotImplemented;
    }

    pub fn readUntilDelimiterAlloc(self: *PackObjectReader, allocator: std.mem.Allocator, delimiter: u8, max_size: usize) ![]u8 {
        _ = self;
        _ = allocator;
        _ = delimiter;
        _ = max_size;
        return error.NotImplemented;
    }

    pub fn readAllAlloc(self: *PackObjectReader, allocator: std.mem.Allocator, max_size: usize) ![]u8 {
        _ = self;
        _ = allocator;
        _ = max_size;
        return error.NotImplemented;
    }
};

pub const LooseOrPackObjectReader = union(enum) {
    loose: struct {
        file: std.fs.File,
        skip_header: bool,
        stream: compress.ZlibStream,
    },
    pack: PackObjectReader,

    pub const Error = compress.ZlibStream.Reader.Error;

    pub fn init(core: *rp.Repo(.git).Core, oid_hex: [hash.SHA1_HEX_LEN]u8, skip_header: bool) !LooseOrPackObjectReader {
        // open the objects dir
        var objects_dir = try core.git_dir.openDir("objects", .{});
        defer objects_dir.close();

        // open the object file
        var path_buf = [_]u8{0} ** (hash.SHA1_HEX_LEN + 1);
        const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ oid_hex[0..2], oid_hex[2..] });
        var object_file = objects_dir.openFile(path, .{ .mode = .read_only }) catch |err| switch (err) {
            error.FileNotFound => return .{
                .pack = PackObjectReader.init(core, oid_hex) catch return error.ObjectNotFound,
            },
            else => return err,
        };
        errdefer object_file.close();

        return .{
            .loose = .{
                .file = object_file,
                .skip_header = skip_header,
                .stream = try compress.decompressStream(object_file, skip_header),
            },
        };
    }

    pub fn deinit(self: *LooseOrPackObjectReader) void {
        switch (self.*) {
            .loose => self.loose.file.close(),
            .pack => self.pack.deinit(),
        }
    }

    pub fn reset(self: *LooseOrPackObjectReader) !void {
        switch (self.*) {
            .loose => self.loose.stream = try compress.decompressStream(self.loose.file, self.loose.skip_header),
            .pack => try self.pack.reset(),
        }
    }

    pub fn skipBytes(self: *LooseOrPackObjectReader, num_bytes: u64) !void {
        switch (self.*) {
            .loose => try self.loose.stream.reader().skipBytes(num_bytes, .{}),
            .pack => try self.pack.skipBytes(num_bytes),
        }
    }

    pub fn read(self: *LooseOrPackObjectReader, dest: []u8) !usize {
        switch (self.*) {
            .loose => return try self.loose.stream.reader().read(dest),
            .pack => return try self.pack.read(dest),
        }
    }

    pub fn readNoEof(self: *LooseOrPackObjectReader, dest: []u8) !void {
        switch (self.*) {
            .loose => try self.loose.stream.reader().readNoEof(dest),
            .pack => try self.pack.readNoEof(dest),
        }
    }

    pub fn readUntilDelimiter(self: *LooseOrPackObjectReader, dest: []u8, delimiter: u8) ![]u8 {
        switch (self.*) {
            .loose => return try self.loose.stream.reader().readUntilDelimiter(dest, delimiter),
            .pack => return try self.pack.readUntilDelimiter(dest, delimiter),
        }
    }

    pub fn readUntilDelimiterAlloc(self: *LooseOrPackObjectReader, allocator: std.mem.Allocator, delimiter: u8, max_size: usize) ![]u8 {
        switch (self.*) {
            .loose => return try self.loose.stream.reader().readUntilDelimiterAlloc(allocator, delimiter, max_size),
            .pack => return try self.pack.readUntilDelimiterAlloc(allocator, delimiter, max_size),
        }
    }

    pub fn readAllAlloc(self: *LooseOrPackObjectReader, allocator: std.mem.Allocator, max_size: usize) ![]u8 {
        switch (self.*) {
            .loose => return try self.loose.stream.reader().readAllAlloc(allocator, max_size),
            .pack => return try self.pack.readAllAlloc(allocator, max_size),
        }
    }
};
