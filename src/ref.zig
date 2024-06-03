const std = @import("std");
const xitdb = @import("xitdb");
const hash = @import("./hash.zig");
const io = @import("./io.zig");
const rp = @import("./repo.zig");

const MAX_READ_BYTES = 1024;
const REF_START_STR = "ref: refs/heads/";

pub const Ref = struct {
    allocator: std.mem.Allocator,
    name: []const u8,
    oid_hex: ?[hash.SHA1_HEX_LEN]u8,

    pub fn initWithName(comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core, allocator: std.mem.Allocator, dir_name: []const u8, name: []const u8) !Ref {
        const path = try std.fs.path.join(allocator, &[_][]const u8{ "refs", dir_name, name });
        defer allocator.free(path);
        const content = try std.fmt.allocPrint(allocator, "ref: {s}", .{path});
        defer allocator.free(content);

        return .{
            .allocator = allocator,
            .name = name,
            .oid_hex = try resolve(repo_kind, core, content),
        };
    }

    pub fn initFromLink(comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core, allocator: std.mem.Allocator, path: []const u8) !?Ref {
        var buffer = [_]u8{0} ** MAX_READ_BYTES;
        const content = try read(repo_kind, core, path, &buffer);

        if (std.mem.startsWith(u8, content, REF_START_STR) and content.len > REF_START_STR.len) {
            const name_len = content.len - REF_START_STR.len;
            const name = try allocator.alloc(u8, name_len);
            errdefer allocator.free(name);
            @memcpy(name, content[REF_START_STR.len..]);

            return .{
                .allocator = allocator,
                .name = name,
                .oid_hex = try resolve(repo_kind, core, content),
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
    arena: std.heap.ArenaAllocator,

    pub fn init(comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core, allocator: std.mem.Allocator, dir_name: []const u8) !RefList {
        var refs = std.ArrayList(Ref).init(allocator);
        errdefer refs.deinit();

        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        var ref_list = RefList{
            .refs = refs,
            .arena = arena,
        };

        switch (repo_kind) {
            .git => {
                var refs_dir = try core.git_dir.openDir("refs", .{});
                defer refs_dir.close();
                var heads_dir = try refs_dir.openDir("heads", .{});
                defer heads_dir.close();

                var path = std.ArrayList([]const u8).init(allocator);
                defer path.deinit();
                try ref_list.addRefs(repo_kind, core, dir_name, heads_dir, &path);
            },
            .xit => {
                const Ctx = struct {
                    ref_list: *RefList,
                    core: *rp.Repo(repo_kind).Core,
                    dir_name: []const u8,

                    pub fn run(self: @This(), cursor: *xitdb.Database(.file).Cursor) !void {
                        if (try cursor.readCursor(void, &[_]xitdb.PathPart(void){
                            .{ .hash_map_get = hash.hashBuffer("refs") },
                            .{ .hash_map_get = hash.hashBuffer("heads") },
                        })) |heads_cursor| {
                            var iter = try heads_cursor.iter(.hash_map);
                            defer iter.deinit();
                            while (try iter.next()) |*next_cursor| {
                                if (try next_cursor.readHash(void, &[_]xitdb.PathPart(void){})) |name_hash| {
                                    if (try cursor.readBytesAlloc(self.ref_list.arena.allocator(), void, &[_]xitdb.PathPart(void){
                                        .{ .hash_map_get = hash.hashBuffer("names") },
                                        .{ .hash_map_get = name_hash },
                                    })) |name| {
                                        const ref = try Ref.initWithName(repo_kind, self.core, self.ref_list.arena.allocator(), self.dir_name, name);
                                        try self.ref_list.refs.append(ref);
                                    } else {
                                        return error.ValueNotFound;
                                    }
                                }
                            }
                        }
                    }
                };
                _ = try core.db.rootCursor().execute(Ctx, &[_]xitdb.PathPart(Ctx){
                    .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                    .{ .ctx = Ctx{ .ref_list = &ref_list, .core = core, .dir_name = dir_name } },
                });
            },
        }

        return ref_list;
    }

    pub fn deinit(self: *RefList) void {
        self.refs.deinit();
        self.arena.deinit();
    }

    fn addRefs(self: *RefList, comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core, dir_name: []const u8, dir: std.fs.Dir, path: *std.ArrayList([]const u8)) !void {
        var iter_dir = try dir.openDir(".", .{ .iterate = true });
        defer iter_dir.close();
        var iter = iter_dir.iterate();
        while (try iter.next()) |entry| {
            var next_path = try path.clone();
            defer next_path.deinit();
            try next_path.append(entry.name);
            switch (entry.kind) {
                .file => {
                    const name = try std.mem.join(self.arena.allocator(), "/", next_path.items);
                    const ref = try Ref.initWithName(repo_kind, core, self.arena.allocator(), dir_name, name);
                    try self.refs.append(ref);
                },
                .directory => {
                    var next_dir = try dir.openDir(entry.name, .{});
                    defer next_dir.close();
                    try self.addRefs(repo_kind, core, dir_name, next_dir, &next_path);
                },
                else => {},
            }
        }
    }
};

pub fn resolve(comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core, content: []const u8) !?[hash.SHA1_HEX_LEN]u8 {
    if (std.mem.startsWith(u8, content, REF_START_STR) and content.len > REF_START_STR.len) {
        return try resolve(repo_kind, core, content[REF_START_STR.len..]);
    }

    switch (repo_kind) {
        .git => {
            var refs_dir = try core.git_dir.openDir("refs", .{});
            defer refs_dir.close();
            var heads_dir = try refs_dir.openDir("heads", .{});
            defer heads_dir.close();

            blk: {
                var ref_file = heads_dir.openFile(content, .{ .mode = .read_only }) catch break :blk;
                defer ref_file.close();
                var buffer = [_]u8{0} ** MAX_READ_BYTES;
                const size = try ref_file.reader().readAll(&buffer);
                return try resolve(repo_kind, core, buffer[0..size]);
            }

            if (content.len >= hash.SHA1_HEX_LEN) {
                var buffer = [_]u8{0} ** hash.SHA1_HEX_LEN;
                @memcpy(&buffer, content[0..hash.SHA1_HEX_LEN]);
                return buffer;
            } else {
                return null;
            }
        },
        .xit => {
            var db_buffer = [_]u8{0} ** MAX_READ_BYTES;
            if (try core.db.rootCursor().readBytes(&db_buffer, void, &[_]xitdb.PathPart(void){
                .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                .{ .hash_map_get = hash.hashBuffer("refs") },
                .{ .hash_map_get = hash.hashBuffer("heads") },
                .{ .hash_map_get = hash.hashBuffer(content) },
            })) |bytes| {
                return try resolve(repo_kind, core, bytes);
            } else {
                if (content.len >= hash.SHA1_HEX_LEN) {
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

pub fn read(comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core, path: []const u8, buffer: *[MAX_READ_BYTES]u8) ![]u8 {
    switch (repo_kind) {
        .git => {
            const head_file = try core.git_dir.openFile(path, .{ .mode = .read_only });
            defer head_file.close();
            const size = try head_file.reader().readAll(buffer);
            return buffer[0..size];
        },
        .xit => {
            if (try core.db.rootCursor().readBytes(buffer, void, &[_]xitdb.PathPart(void){
                .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                .{ .hash_map_get = hash.hashBuffer(path) },
            })) |target_bytes| {
                return target_bytes;
            } else {
                return error.KeyNotFound;
            }
        },
    }
}

pub fn readHeadMaybe(comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core) !?[hash.SHA1_HEX_LEN]u8 {
    var buffer = [_]u8{0} ** MAX_READ_BYTES;
    return try resolve(repo_kind, core, try read(repo_kind, core, "HEAD", &buffer));
}

pub fn readHead(comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core) ![hash.SHA1_HEX_LEN]u8 {
    if (try readHeadMaybe(repo_kind, core)) |buffer| {
        return buffer;
    } else {
        return error.RefInvalidHash;
    }
}

pub fn readHeadName(comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core, allocator: std.mem.Allocator) ![]u8 {
    var buffer = [_]u8{0} ** MAX_READ_BYTES;
    const content = try read(repo_kind, core, "HEAD", &buffer);
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

pub fn writeHead(comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core, allocator: std.mem.Allocator, target: []const u8, oid_hex_maybe: ?[hash.SHA1_HEX_LEN]u8) !void {
    switch (repo_kind) {
        .git => {
            var lock = try io.LockFile.init(allocator, core.git_dir, "HEAD");
            defer lock.deinit();

            // if the target is a ref, just update HEAD to point to it
            var refs_dir = try core.git_dir.openDir("refs", .{});
            defer refs_dir.close();
            var heads_dir = try refs_dir.openDir("heads", .{});
            defer heads_dir.close();
            var ref_file = heads_dir.openFile(target, .{ .mode = .read_only }) catch |err| {
                switch (err) {
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
                }
            };
            defer ref_file.close();

            // point HEAD at the ref
            var write_buffer = [_]u8{0} ** MAX_READ_BYTES;
            const content = try std.fmt.bufPrint(&write_buffer, "ref: refs/heads/{s}", .{target});
            try lock.lock_file.writeAll(content);
            lock.success = true;
        },
        .xit => {
            const Ctx = struct {
                allocator: std.mem.Allocator,
                target: []const u8,
                oid_hex_maybe: ?[hash.SHA1_HEX_LEN]u8,

                pub fn run(self: @This(), cursor: *xitdb.Database(.file).Cursor) !void {
                    var path_parts = std.ArrayList(xitdb.PathPart(void)).init(self.allocator);
                    defer path_parts.deinit();
                    try path_parts.appendSlice(&[_]xitdb.PathPart(void){
                        .{ .hash_map_get = hash.hashBuffer("HEAD") },
                    });

                    if (try cursor.readBytesAlloc(self.allocator, void, &[_]xitdb.PathPart(void){
                        .{ .hash_map_get = hash.hashBuffer("refs") },
                        .{ .hash_map_get = hash.hashBuffer("heads") },
                        .{ .hash_map_get = hash.hashBuffer(self.target) },
                    })) |target_bytes| {
                        self.allocator.free(target_bytes);

                        // point HEAD at the ref
                        var write_buffer = [_]u8{0} ** MAX_READ_BYTES;
                        const content = try std.fmt.bufPrint(&write_buffer, "ref: refs/heads/{s}", .{self.target});
                        const content_hash = hash.hashBuffer(content);
                        const content_ptr = try cursor.writeBytes(content, .once, void, &[_]xitdb.PathPart(void){
                            .{ .hash_map_get = hash.hashBuffer("ref-values") },
                            .hash_map_create,
                            .{ .hash_map_get = content_hash },
                        });
                        try path_parts.append(.{ .value = .{ .bytes_ptr = content_ptr } });
                        _ = try cursor.execute(void, path_parts.items);
                    } else {
                        if (self.oid_hex_maybe) |oid_hex| {
                            // the HEAD is detached, so just update it with the oid
                            const content_ptr = try cursor.writeBytes(&oid_hex, .once, void, &[_]xitdb.PathPart(void){
                                .{ .hash_map_get = hash.hashBuffer("ref-values") },
                                .hash_map_create,
                                .{ .hash_map_get = try hash.hexToHash(&oid_hex) },
                            });
                            try path_parts.append(.{ .value = .{ .bytes_ptr = content_ptr } });
                            _ = try cursor.execute(void, path_parts.items);
                        } else {
                            // point HEAD at the ref, even though the ref doesn't exist
                            var write_buffer = [_]u8{0} ** MAX_READ_BYTES;
                            const content = try std.fmt.bufPrint(&write_buffer, "ref: refs/heads/{s}", .{self.target});
                            const content_hash = hash.hashBuffer(content);
                            const content_ptr = try cursor.writeBytes(content, .once, void, &[_]xitdb.PathPart(void){
                                .{ .hash_map_get = hash.hashBuffer("ref-values") },
                                .hash_map_create,
                                .{ .hash_map_get = content_hash },
                            });
                            try path_parts.append(.{ .value = .{ .bytes_ptr = content_ptr } });
                            _ = try cursor.execute(void, path_parts.items);
                        }
                    }
                }
            };
            _ = try core.db.rootCursor().execute(Ctx, &[_]xitdb.PathPart(Ctx){
                .{ .array_list_get = .append_copy },
                .hash_map_create,
                .{ .ctx = Ctx{ .allocator = allocator, .target = target, .oid_hex_maybe = oid_hex_maybe } },
            });
        },
    }
}

pub fn UpdateOpts(comptime repo_kind: rp.RepoKind) type {
    return switch (repo_kind) {
        .git => struct {
            dir: std.fs.Dir,
        },
        .xit => struct {
            root_cursor: *xitdb.Database(.file).Cursor,
        },
    };
}

/// update the given file with the given oid,
/// following refs recursively if necessary.
/// used after a commit is made.
pub fn updateRecur(comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core, opts: UpdateOpts(repo_kind), allocator: std.mem.Allocator, file_name: []const u8, oid_hex: *const [hash.SHA1_HEX_LEN]u8) anyerror!void {
    switch (repo_kind) {
        .git => {
            var lock = try io.LockFile.init(allocator, opts.dir, file_name);
            defer lock.deinit();

            // read file and get ref name if necessary
            var buffer = [_]u8{0} ** MAX_READ_BYTES;
            const ref_name_maybe = blk: {
                const old_content = read(repo_kind, core, file_name, &buffer) catch |err| {
                    switch (err) {
                        error.FileNotFound => break :blk null,
                        else => return err,
                    }
                };
                if (std.mem.startsWith(u8, old_content, REF_START_STR) and old_content.len > REF_START_STR.len) {
                    break :blk old_content[REF_START_STR.len..];
                } else {
                    break :blk null;
                }
            };

            // if it's a ref, update it recursively
            if (ref_name_maybe) |ref_name| {
                var refs_dir = try core.git_dir.openDir("refs", .{});
                defer refs_dir.close();
                var heads_dir = try refs_dir.openDir("heads", .{});
                defer heads_dir.close();
                try updateRecur(repo_kind, core, .{ .dir = heads_dir }, allocator, ref_name, oid_hex);
            }
            // otherwise, update it with the oid
            else {
                try lock.lock_file.writeAll(oid_hex);
                try lock.lock_file.writeAll("\n");
                lock.success = true;
            }
        },
        .xit => {
            // read file and get ref name if necessary
            var buffer = [_]u8{0} ** MAX_READ_BYTES;
            const ref_name_maybe = blk: {
                // TODO: make `read` use root cursor for tx safety
                const old_content = read(repo_kind, core, file_name, &buffer) catch |err| {
                    switch (err) {
                        error.KeyNotFound => break :blk null,
                        else => return err,
                    }
                };
                if (std.mem.startsWith(u8, old_content, REF_START_STR) and old_content.len > REF_START_STR.len) {
                    break :blk old_content[REF_START_STR.len..];
                } else {
                    break :blk null;
                }
            };

            // if it's a ref, update it recursively
            if (ref_name_maybe) |ref_name| {
                try updateRecur(repo_kind, core, opts, allocator, ref_name, oid_hex);
            }
            // otherwise, update it with the oid
            else {
                const file_name_hash = hash.hashBuffer(file_name);
                _ = try opts.root_cursor.writeBytes(file_name, .once, void, &[_]xitdb.PathPart(void){
                    .{ .hash_map_get = hash.hashBuffer("names") },
                    .hash_map_create,
                    .{ .hash_map_get = file_name_hash },
                });
                const oid_ptr = try opts.root_cursor.writeBytes(oid_hex, .once, void, &[_]xitdb.PathPart(void){
                    .{ .hash_map_get = hash.hashBuffer("ref-values") },
                    .hash_map_create,
                    .{ .hash_map_get = try hash.hexToHash(oid_hex) },
                });
                _ = try opts.root_cursor.execute(void, &[_]xitdb.PathPart(void){
                    .{ .hash_map_get = hash.hashBuffer("refs") },
                    .hash_map_create,
                    .{ .hash_map_get = hash.hashBuffer("heads") },
                    .hash_map_create,
                    .{ .hash_map_get = file_name_hash },
                    .{ .value = .{ .bytes_ptr = oid_ptr } },
                });
            }
        },
    }
}
