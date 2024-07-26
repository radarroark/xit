const std = @import("std");
const xitdb = @import("xitdb");
const rp = @import("./repo.zig");
const hash = @import("./hash.zig");
const st = @import("./status.zig");
const df = @import("./diff.zig");

const NodeIdInt = u224;
const NodeId = packed struct {
    node: u64,
    patch_id: xitdb.Hash,
};

const ChangeKind = enum(u8) {
    new_node = 0,
    delete_node = 1,
    new_edge = 2,
};

const Change = union(ChangeKind) {
    new_node: struct {
        id: NodeId,
        contents: []const u8,
    },
    delete_node: struct {
        id: NodeId,
    },
    new_edge: struct {
        src: NodeId,
        dest: NodeId,
    },
};

pub fn patchHash(comptime repo_kind: rp.RepoKind, allocator: std.mem.Allocator, myers_diff_iter: *df.MyersDiffIterator(repo_kind)) !xitdb.Hash {
    var h = std.crypto.hash.Sha1.init(.{});
    while (try myers_diff_iter.next()) |edit| {
        defer edit.deinit(allocator);

        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();
        var writer = buffer.writer();

        switch (edit) {
            .eql => {},
            .ins => {
                try writer.writeInt(u8, @intFromEnum(ChangeKind.new_node), .big);
                try writer.writeInt(u64, edit.ins.new_line.num, .big);
                try writer.writeInt(u64, edit.ins.new_line.text.len, .big);
                try writer.writeAll(edit.ins.new_line.text);
            },
            .del => {
                try writer.writeInt(u8, @intFromEnum(ChangeKind.delete_node), .big);
                try writer.writeInt(u64, edit.del.old_line.num, .big);
            },
        }

        h.update(buffer.items);
    }
    try myers_diff_iter.reset();

    var patch_hash = [_]u8{0} ** hash.SHA1_BYTES_LEN;
    h.final(&patch_hash);
    return hash.hashBuffer(&patch_hash);
}

pub fn writePatchesForFile(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator, line_iter_pair: *df.LineIteratorPair(repo_kind)) !void {
    var myers_diff_iter = try df.MyersDiffIterator(repo_kind).init(allocator, &line_iter_pair.a, &line_iter_pair.b);
    defer myers_diff_iter.deinit();

    const patch_hash = try patchHash(repo_kind, allocator, &myers_diff_iter);

    // exit early if patch already exists
    if (try core_cursor.cursor.readPath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("patches") } },
        .{ .hash_map_get = .{ .key = patch_hash } },
    })) |_| {
        return;
    }

    // init node-sets
    const path_hash = hash.hashBuffer(line_iter_pair.path);
    var path_cursor = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("path-set") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = path_hash } },
    });
    try path_cursor.writeBytes(line_iter_pair.path, .once);
    _ = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
        .{ .hash_map_get = .{ .value = hash.hashBuffer("node-sets") } },
        .hash_map_init,
        .{ .hash_map_get = .{ .key = path_hash } },
        .{ .write = .{ .slot = path_cursor.slot_ptr.slot } },
    });

    var new_node_count: u64 = 0;

    while (try myers_diff_iter.next()) |edit| {
        defer edit.deinit(allocator);

        var patch_entries = std.ArrayList([]const u8).init(allocator);
        defer patch_entries.deinit();

        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();
        var writer = buffer.writer();

        switch (edit) {
            .eql => {},
            .ins => {
                try writer.writeInt(u8, @intFromEnum(ChangeKind.new_node), .big);
                try writer.writeInt(u64, new_node_count, .big);
                try patch_entries.append(buffer.items);
            },
            .del => {
                try writer.writeInt(u8, @intFromEnum(ChangeKind.delete_node), .big);
                try writer.writeInt(u64, edit.del.old_line.num, .big);
                try patch_entries.append(buffer.items);
            },
        }

        // put changes in the key
        for (patch_entries.items) |entry| {
            _ = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
                .{ .hash_map_get = .{ .value = hash.hashBuffer("patches") } },
                .hash_map_init,
                .{ .hash_map_get = .{ .key = patch_hash } },
                .array_list_init,
                .{ .array_list_get = .append },
                .{ .write = .{ .bytes = entry } },
            });
        }

        if (edit == .ins) {
            // put content from new node in the value
            _ = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
                .{ .hash_map_get = .{ .value = hash.hashBuffer("patches") } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = patch_hash } },
                .array_list_init,
                .{ .array_list_get = .append },
                .{ .write = .{ .bytes = edit.ins.new_line.text } },
            });

            // add node id to node-sets
            var node_id_buffer = std.ArrayList(u8).init(allocator);
            defer node_id_buffer.deinit();
            var node_id_writer = node_id_buffer.writer();
            try node_id_writer.writeInt(NodeIdInt, @bitCast(NodeId{ .patch_id = patch_hash, .node = new_node_count }), .big);
            const node_id_hash = hash.hashBuffer(node_id_buffer.items);
            _ = try core_cursor.cursor.writePath(void, &[_]xitdb.PathPart(void){
                .{ .hash_map_get = .{ .value = hash.hashBuffer("node-sets") } },
                .hash_map_init,
                .{ .hash_map_get = .{ .value = path_hash } },
                .hash_map_init,
                .{ .hash_map_get = .{ .key = node_id_hash } },
                .{ .write = .{ .bytes = node_id_buffer.items } },
            });

            new_node_count += 1;
        }
    }
}

pub fn writePatches(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator) !void {
    comptime std.debug.assert(repo_kind == .xit);

    var file_iter = blk: {
        var stat = try st.Status(repo_kind).init(allocator, core_cursor);
        errdefer stat.deinit();
        break :blk try df.FileIterator(repo_kind).init(allocator, core_cursor.core, .index, stat);
    };
    defer file_iter.deinit();

    while (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();
        try writePatchesForFile(repo_kind, core_cursor, allocator, &line_iter_pair);
    }
}
