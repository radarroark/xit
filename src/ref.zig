const std = @import("std");
const hash = @import("./hash.zig");
const io = @import("./io.zig");
const rp = @import("./repo.zig");

const MAX_READ_BYTES = 1024; // FIXME: this is arbitrary...
const REF_START_STR = "ref: refs/heads/";

pub const Ref = struct {
    allocator: std.mem.Allocator,
    name: []const u8,
    oid_hex: ?[hash.SHA1_HEX_LEN]u8,

    pub fn initWithName(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator, dir_name: []const u8, name: []const u8) !Ref {
        const path = try io.joinPath(allocator, &.{ "refs", dir_name, name });
        defer allocator.free(path);
        const content = try std.fmt.allocPrint(allocator, "ref: {s}", .{path});
        defer allocator.free(content);

        return .{
            .allocator = allocator,
            .name = name,
            .oid_hex = try resolve(repo_kind, core_cursor, content),
        };
    }

    pub fn initFromLink(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator, path: []const u8) !?Ref {
        var buffer = [_]u8{0} ** MAX_READ_BYTES;
        const content = try read(repo_kind, core_cursor, path, &buffer);

        if (std.mem.startsWith(u8, content, REF_START_STR) and content.len > REF_START_STR.len) {
            const name_len = content.len - REF_START_STR.len;
            const name = try allocator.alloc(u8, name_len);
            errdefer allocator.free(name);
            @memcpy(name, content[REF_START_STR.len..]);

            return .{
                .allocator = allocator,
                .name = name,
                .oid_hex = try resolve(repo_kind, core_cursor, content),
            };
        } else {
            return null;
        }
    }

    pub fn deinit(self: *Ref) void {
        self.allocator.free(self.name);
    }
};

pub const RefList = struct {
    refs: std.ArrayList(Ref),
    arena: *std.heap.ArenaAllocator,
    allocator: std.mem.Allocator,

    pub fn init(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator, dir_name: []const u8) !RefList {
        const arena = try allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        var ref_list = RefList{
            .refs = std.ArrayList(Ref).init(allocator),
            .arena = arena,
            .allocator = allocator,
        };
        errdefer ref_list.deinit();

        switch (repo_kind) {
            .git => {
                var refs_dir = try core_cursor.core.git_dir.openDir("refs", .{});
                defer refs_dir.close();
                var heads_dir = try refs_dir.openDir("heads", .{});
                defer heads_dir.close();

                var path = std.ArrayList([]const u8).init(allocator);
                defer path.deinit();
                try ref_list.addRefs(repo_kind, core_cursor, dir_name, heads_dir, &path);
            },
            .xit => {
                if (try core_cursor.cursor.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hash.hashBuffer("refs") } },
                    .{ .hash_map_get = .{ .value = hash.hashBuffer("heads") } },
                })) |heads_cursor| {
                    var iter = try heads_cursor.iter();
                    defer iter.deinit();
                    while (try iter.next()) |*next_cursor| {
                        const kv_pair = try next_cursor.readKeyValuePair();
                        const name = try kv_pair.key_cursor.readBytesAlloc(ref_list.arena.allocator(), MAX_READ_BYTES);
                        const ref = try Ref.initWithName(repo_kind, core_cursor, ref_list.arena.allocator(), dir_name, name);
                        try ref_list.refs.append(ref);
                    }
                }
            },
        }

        return ref_list;
    }

    pub fn deinit(self: *RefList) void {
        self.refs.deinit();
        self.arena.deinit();
        self.allocator.destroy(self.arena);
    }

    fn addRefs(self: *RefList, comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, dir_name: []const u8, dir: std.fs.Dir, path: *std.ArrayList([]const u8)) !void {
        var iter_dir = try dir.openDir(".", .{ .iterate = true });
        defer iter_dir.close();
        var iter = iter_dir.iterate();
        while (try iter.next()) |entry| {
            var next_path = try path.clone();
            defer next_path.deinit();
            try next_path.append(entry.name);
            switch (entry.kind) {
                .file => {
                    const name = try io.joinPath(self.arena.allocator(), next_path.items);
                    const ref = try Ref.initWithName(repo_kind, core_cursor, self.arena.allocator(), dir_name, name);
                    try self.refs.append(ref);
                },
                .directory => {
                    var next_dir = try dir.openDir(entry.name, .{});
                    defer next_dir.close();
                    try self.addRefs(repo_kind, core_cursor, dir_name, next_dir, &next_path);
                },
                else => {},
            }
        }
    }
};

pub fn resolve(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, content: []const u8) !?[hash.SHA1_HEX_LEN]u8 {
    if (std.mem.startsWith(u8, content, REF_START_STR) and content.len > REF_START_STR.len) {
        return try resolve(repo_kind, core_cursor, content[REF_START_STR.len..]);
    }

    switch (repo_kind) {
        .git => {
            var refs_dir = try core_cursor.core.git_dir.openDir("refs", .{});
            defer refs_dir.close();
            var heads_dir = try refs_dir.openDir("heads", .{});
            defer heads_dir.close();

            blk: {
                var ref_file = heads_dir.openFile(content, .{ .mode = .read_only }) catch break :blk;
                defer ref_file.close();
                var buffer = [_]u8{0} ** MAX_READ_BYTES;
                const size = try ref_file.reader().readAll(&buffer);
                return try resolve(repo_kind, core_cursor, std.mem.sliceTo(buffer[0..size], '\n'));
            }

            if (content.len == hash.SHA1_HEX_LEN) {
                var buffer = [_]u8{0} ** hash.SHA1_HEX_LEN;
                @memcpy(&buffer, content[0..hash.SHA1_HEX_LEN]);
                return buffer;
            } else {
                return null;
            }
        },
        .xit => {
            var db_buffer = [_]u8{0} ** MAX_READ_BYTES;
            if (try core_cursor.cursor.readPath(void, &.{
                .{ .hash_map_get = .{ .value = hash.hashBuffer("refs") } },
                .{ .hash_map_get = .{ .value = hash.hashBuffer("heads") } },
                .{ .hash_map_get = .{ .value = hash.hashBuffer(content) } },
            })) |bytes_cursor| {
                const bytes = try bytes_cursor.readBytes(&db_buffer);
                return try resolve(repo_kind, core_cursor, bytes);
            } else {
                if (content.len == hash.SHA1_HEX_LEN) {
                    var buffer = [_]u8{0} ** hash.SHA1_HEX_LEN;
                    @memcpy(&buffer, content[0..hash.SHA1_HEX_LEN]);
                    return buffer;
                } else {
                    return null;
                }
            }
        },
    }
}

pub fn read(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, path: []const u8, buffer: *[MAX_READ_BYTES]u8) ![]u8 {
    switch (repo_kind) {
        .git => {
            const head_file = try core_cursor.core.git_dir.openFile(path, .{ .mode = .read_only });
            defer head_file.close();
            const size = try head_file.reader().readAll(buffer);
            return std.mem.sliceTo(buffer[0..size], '\n');
        },
        .xit => {
            if (try core_cursor.cursor.readPath(void, &.{
                .{ .hash_map_get = .{ .value = hash.hashBuffer(path) } },
            })) |target_bytes_cursor| {
                return try target_bytes_cursor.readBytes(buffer);
            } else {
                return error.KeyNotFound;
            }
        },
    }
}

pub fn readHeadMaybe(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor) !?[hash.SHA1_HEX_LEN]u8 {
    var buffer = [_]u8{0} ** MAX_READ_BYTES;
    return try resolve(repo_kind, core_cursor, try read(repo_kind, core_cursor, "HEAD", &buffer));
}

pub fn readHead(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor) ![hash.SHA1_HEX_LEN]u8 {
    if (try readHeadMaybe(repo_kind, core_cursor)) |buffer| {
        return buffer;
    } else {
        return error.RefInvalidHash;
    }
}

pub fn readHeadName(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator) ![]u8 {
    var buffer = [_]u8{0} ** MAX_READ_BYTES;
    const content = try read(repo_kind, core_cursor, "HEAD", &buffer);
    if (std.mem.startsWith(u8, content, REF_START_STR) and content.len > REF_START_STR.len) {
        const ref_name = content[REF_START_STR.len..];
        const buf = try allocator.alloc(u8, ref_name.len);
        @memcpy(buf, ref_name);
        return buf;
    } else {
        const buf = try allocator.alloc(u8, content.len);
        @memcpy(buf, content);
        return buf;
    }
}

/// makes HEAD point to a new ref
pub fn writeHead(comptime repo_kind: rp.RepoKind, core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator, target: []const u8, oid_hex_maybe: ?[hash.SHA1_HEX_LEN]u8) !void {
    switch (repo_kind) {
        .git => {
            var lock = try io.LockFile.init(allocator, core_cursor.core.git_dir, "HEAD");
            defer lock.deinit();

            // if the target is a ref, just update HEAD to point to it
            var refs_dir = try core_cursor.core.git_dir.openDir("refs", .{});
            defer refs_dir.close();
            var heads_dir = try refs_dir.openDir("heads", .{});
            defer heads_dir.close();
            var ref_file = heads_dir.openFile(target, .{ .mode = .read_only }) catch |err| switch (err) {
                error.FileNotFound => {
                    if (oid_hex_maybe) |oid_hex| {
                        // the HEAD is detached, so just update it with the oid
                        try lock.lock_file.writeAll(&oid_hex);
                    } else {
                        // point HEAD at the ref, even though the ref doesn't exist
                        var write_buffer = [_]u8{0} ** MAX_READ_BYTES;
                        const content = try std.fmt.bufPrint(&write_buffer, "ref: refs/heads/{s}", .{target});
                        try lock.lock_file.writeAll(content);
                    }
                    lock.success = true;
                    return;
                },
                else => return err,
            };
            defer ref_file.close();

            // point HEAD at the ref
            var write_buffer = [_]u8{0} ** MAX_READ_BYTES;
            const content = try std.fmt.bufPrint(&write_buffer, "ref: refs/heads/{s}", .{target});
            try lock.lock_file.writeAll(content);
            lock.success = true;
        },
        .xit => {
            if (try core_cursor.cursor.readPath(void, &.{
                .{ .hash_map_get = .{ .value = hash.hashBuffer("refs") } },
                .{ .hash_map_get = .{ .value = hash.hashBuffer("heads") } },
                .{ .hash_map_get = .{ .value = hash.hashBuffer(target) } },
            })) |_| {
                // point HEAD at the ref
                var write_buffer = [_]u8{0} ** MAX_READ_BYTES;
                const content = try std.fmt.bufPrint(&write_buffer, "ref: refs/heads/{s}", .{target});
                var ref_content_cursor = try core_cursor.cursor.writePath(void, &.{
                    .{ .hash_map_get = .{ .value = hash.hashBuffer("ref-content-set") } },
                    .hash_map_init,
                    .{ .hash_map_get = .{ .key = hash.hashBuffer(content) } },
                });
                try ref_content_cursor.writeBytes(content, .once);
                _ = try core_cursor.cursor.writePath(void, &.{
                    .{ .hash_map_get = .{ .value = hash.hashBuffer("HEAD") } },
                    .{ .write = .{ .slot = ref_content_cursor.slot_ptr.slot } },
                });
            } else {
                if (oid_hex_maybe) |oid_hex| {
                    // the HEAD is detached, so just update it with the oid
                    var ref_content_cursor = try core_cursor.cursor.writePath(void, &.{
                        .{ .hash_map_get = .{ .value = hash.hashBuffer("ref-content-set") } },
                        .hash_map_init,
                        .{ .hash_map_get = .{ .key = try hash.hexToHash(&oid_hex) } },
                    });
                    try ref_content_cursor.writeBytes(&oid_hex, .once);
                    _ = try core_cursor.cursor.writePath(void, &.{
                        .{ .hash_map_get = .{ .value = hash.hashBuffer("HEAD") } },
                        .{ .write = .{ .slot = ref_content_cursor.slot_ptr.slot } },
                    });
                } else {
                    // point HEAD at the ref, even though the ref doesn't exist
                    var write_buffer = [_]u8{0} ** MAX_READ_BYTES;
                    const content = try std.fmt.bufPrint(&write_buffer, "ref: refs/heads/{s}", .{target});
                    var ref_content_cursor = try core_cursor.cursor.writePath(void, &.{
                        .{ .hash_map_get = .{ .value = hash.hashBuffer("ref-content-set") } },
                        .hash_map_init,
                        .{ .hash_map_get = .{ .key = hash.hashBuffer(content) } },
                    });
                    try ref_content_cursor.writeBytes(content, .once);
                    _ = try core_cursor.cursor.writePath(void, &.{
                        .{ .hash_map_get = .{ .value = hash.hashBuffer("HEAD") } },
                        .{ .write = .{ .slot = ref_content_cursor.slot_ptr.slot } },
                    });
                }
            }
        },
    }
}

/// update the given file with the given oid,
/// following refs recursively if necessary.
/// used after a commit is made.
pub fn updateRecur(
    comptime repo_kind: rp.RepoKind,
    core_cursor: rp.Repo(repo_kind).CoreCursor,
    allocator: std.mem.Allocator,
    path_parts: []const []const u8,
    oid_hex: *const [hash.SHA1_HEX_LEN]u8,
) anyerror!void {
    switch (repo_kind) {
        .git => {
            const path = try io.joinPath(allocator, path_parts);
            defer allocator.free(path);

            var lock = try io.LockFile.init(allocator, core_cursor.core.git_dir, path);
            defer lock.deinit();

            // read file and get ref name if necessary
            var buffer = [_]u8{0} ** MAX_READ_BYTES;
            const ref_name_maybe = blk: {
                const old_content = read(repo_kind, core_cursor, path, &buffer) catch |err| switch (err) {
                    error.FileNotFound => break :blk null,
                    else => return err,
                };
                if (std.mem.startsWith(u8, old_content, REF_START_STR) and old_content.len > REF_START_STR.len) {
                    break :blk old_content[REF_START_STR.len..];
                } else {
                    break :blk null;
                }
            };

            // if it's a ref, update it recursively
            if (ref_name_maybe) |ref_name| {
                try updateRecur(repo_kind, core_cursor, allocator, &.{ "refs", "heads", ref_name }, oid_hex);
            }
            // otherwise, update it with the oid
            else {
                try lock.lock_file.writeAll(oid_hex);
                try lock.lock_file.writeAll("\n");
                lock.success = true;
            }
        },
        .xit => {
            const Ctx = struct {
                core_cursor: rp.Repo(repo_kind).CoreCursor,
                allocator: std.mem.Allocator,
                oid_hex: *const [hash.SHA1_HEX_LEN]u8,
                file_name: []const u8,

                pub fn run(ctx: @This(), cursor: *rp.Repo(repo_kind).DB.Cursor(.read_write)) !void {
                    const file_name_hash = hash.hashBuffer(ctx.file_name);

                    var buffer = [_]u8{0} ** MAX_READ_BYTES;
                    if (try cursor.readPath(void, &.{
                        .{ .hash_map_get = .{ .value = file_name_hash } },
                    })) |old_content_cursor| {
                        const old_content = try old_content_cursor.readBytes(&buffer);
                        // if it's a ref, update it recursively
                        if (std.mem.startsWith(u8, old_content, REF_START_STR) and old_content.len > REF_START_STR.len) {
                            const ref_name = old_content[REF_START_STR.len..];
                            try updateRecur(repo_kind, ctx.core_cursor, ctx.allocator, &.{ "refs", "heads", ref_name }, ctx.oid_hex);
                            return;
                        }
                    }

                    // otherwise, update with the oid
                    var ref_name_cursor = try ctx.core_cursor.cursor.writePath(void, &.{
                        .{ .hash_map_get = .{ .value = hash.hashBuffer("ref-name-set") } },
                        .hash_map_init,
                        .{ .hash_map_get = .{ .key = file_name_hash } },
                    });
                    try ref_name_cursor.writeBytes(ctx.file_name, .once);
                    _ = try cursor.writePath(void, &.{
                        .{ .hash_map_get = .{ .key = file_name_hash } },
                        .{ .write = .{ .slot = ref_name_cursor.slot_ptr.slot } },
                    });
                    var ref_content_cursor = try ctx.core_cursor.cursor.writePath(void, &.{
                        .{ .hash_map_get = .{ .value = hash.hashBuffer("ref-content-set") } },
                        .hash_map_init,
                        .{ .hash_map_get = .{ .key = try hash.hexToHash(ctx.oid_hex) } },
                    });
                    try ref_content_cursor.writeBytes(ctx.oid_hex, .once);
                    _ = try cursor.writePath(void, &.{
                        .{ .hash_map_get = .{ .value = file_name_hash } },
                        .{ .write = .{ .slot = ref_content_cursor.slot_ptr.slot } },
                    });
                }
            };
            var db_path_parts = std.ArrayList(rp.Repo(repo_kind).DB.PathPart(Ctx)).init(allocator);
            defer db_path_parts.deinit();
            for (path_parts[0 .. path_parts.len - 1]) |part_name| {
                try db_path_parts.append(.{ .hash_map_get = .{ .value = hash.hashBuffer(part_name) } });
                try db_path_parts.append(.hash_map_init);
            }
            try db_path_parts.append(.{ .ctx = Ctx{
                .core_cursor = core_cursor,
                .allocator = allocator,
                .oid_hex = oid_hex,
                .file_name = path_parts[path_parts.len - 1],
            } });
            _ = try core_cursor.cursor.writePath(Ctx, db_path_parts.items);
        },
    }
}
