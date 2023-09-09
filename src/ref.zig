const std = @import("std");
const xitdb = @import("xitdb");
const hash = @import("./hash.zig");
const io = @import("./io.zig");
const rp = @import("./repo.zig");

const MAX_READ_BYTES = 1024;
const REF_START_STR = "ref: refs/heads/";

pub const RefError = error{
    RefInvalidHash,
};

pub const Ref = struct {
    allocator: std.mem.Allocator,
    name: []const u8,
    oid: ?[hash.SHA1_HEX_LEN]u8,

    pub fn init(comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core, allocator: std.mem.Allocator, dir_name: []const u8, relative_path: []const []const u8) !Ref {
        const name = try std.mem.join(allocator, "/", relative_path);
        errdefer allocator.free(name);

        const path = try std.fs.path.join(allocator, &[_][]const u8{ "refs", dir_name, name });
        defer allocator.free(path);
        const content = try std.fmt.allocPrint(allocator, "ref: {s}", .{path});
        defer allocator.free(content);

        return .{
            .allocator = allocator,
            .name = name,
            .oid = try resolve(repo_kind, core, content),
        };
    }

    pub fn initWithPath(comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core, allocator: std.mem.Allocator, path: []const u8) !?Ref {
        var buffer = [_]u8{0} ** MAX_READ_BYTES;
        const content = try read(repo_kind, core, path, &buffer);

        if (std.mem.startsWith(u8, content, REF_START_STR) and content.len > REF_START_STR.len) {
            const name_len = content.len - REF_START_STR.len;
            var name = try allocator.alloc(u8, name_len);
            errdefer allocator.free(name);
            @memcpy(name, content[REF_START_STR.len..]);

            return .{
                .allocator = allocator,
                .name = name,
                .oid = try resolve(repo_kind, core, content),
            };
        } else {
            return null;
        }
    }

    pub fn deinit(self: *Ref) void {
        self.allocator.free(self.name);
    }
};

fn addRefs(comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core, allocator: std.mem.Allocator, dir_name: []const u8, dir: std.fs.Dir, refs: *std.ArrayList(Ref), path: *std.ArrayList([]const u8)) !void {
    var iter_dir = try dir.openIterableDir(".", .{});
    defer iter_dir.close();
    var iter = iter_dir.iterate();
    while (try iter.next()) |entry| {
        var next_path = try path.clone();
        defer next_path.deinit();
        try next_path.append(entry.name);
        switch (entry.kind) {
            .file => {
                var ref = try Ref.init(repo_kind, core, allocator, dir_name, next_path.items);
                errdefer ref.deinit();
                try refs.append(ref);
            },
            .directory => {
                var next_dir = try dir.openDir(entry.name, .{});
                defer next_dir.close();
                try addRefs(repo_kind, core, allocator, dir_name, next_dir, refs, &next_path);
            },
            else => {},
        }
    }
}

pub const RefList = struct {
    refs: std.ArrayList(Ref),

    pub fn init(comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core, allocator: std.mem.Allocator, dir_name: []const u8) !RefList {
        var refs = std.ArrayList(Ref).init(allocator);
        errdefer {
            for (refs.items) |*ref| {
                ref.deinit();
            }
            refs.deinit();
        }

        var refs_dir = try core.git_dir.openDir("refs", .{});
        defer refs_dir.close();
        var heads_dir = try refs_dir.openDir("heads", .{});
        defer heads_dir.close();

        var path = std.ArrayList([]const u8).init(allocator);
        defer path.deinit();
        try addRefs(repo_kind, core, allocator, dir_name, heads_dir, &refs, &path);

        return .{
            .refs = refs,
        };
    }

    pub fn deinit(self: *RefList) void {
        for (self.refs.items) |*ref| {
            ref.deinit();
        }
        self.refs.deinit();
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
                std.mem.copy(u8, &buffer, content[0..hash.SHA1_HEX_LEN]);
                return buffer;
            } else {
                return null;
            }
        },
        .xit => {
            var db_buffer = [_]u8{0} ** MAX_READ_BYTES;
            if (try core.db.rootCursor().readBytes(&db_buffer, void, &[_]xitdb.PathPart(void){
                .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                .{ .map_get = .{ .bytes = "refs" } },
                .{ .map_get = .{ .bytes = "heads" } },
                .{ .map_get = .{ .bytes = content } },
            })) |bytes| {
                return try resolve(repo_kind, core, bytes);
            } else {
                if (content.len >= hash.SHA1_HEX_LEN) {
                    var buffer = [_]u8{0} ** hash.SHA1_HEX_LEN;
                    std.mem.copy(u8, &buffer, content[0..hash.SHA1_HEX_LEN]);
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
                .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                .{ .map_get = .{ .bytes = path } },
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

pub fn writeHead(comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core, allocator: std.mem.Allocator, target: []const u8, oid_maybe: ?[hash.SHA1_HEX_LEN]u8) !void {
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
                        if (oid_maybe) |oid| {
                            // the HEAD is detached, so just update it with the oid
                            try lock.lock_file.writeAll(&oid);
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
            var path_parts = std.ArrayList(xitdb.PathPart(void)).init(allocator);
            defer path_parts.deinit();
            try path_parts.appendSlice(&[_]xitdb.PathPart(void){
                .{ .list_get = .append_copy },
                .map_create,
                .{ .map_get = .{ .bytes = "HEAD" } },
            });

            if (try core.db.rootCursor().readBytesAlloc(allocator, void, &[_]xitdb.PathPart(void){
                .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                .{ .map_get = .{ .bytes = "refs" } },
                .{ .map_get = .{ .bytes = "heads" } },
                .{ .map_get = .{ .bytes = target } },
            })) |target_bytes| {
                allocator.free(target_bytes);

                // point HEAD at the ref
                var write_buffer = [_]u8{0} ** MAX_READ_BYTES;
                const content = try std.fmt.bufPrint(&write_buffer, "ref: refs/heads/{s}", .{target});
                try path_parts.append(.{ .value = .{ .bytes = content } });
                try core.db.rootCursor().execute(void, path_parts.items);
            } else {
                if (oid_maybe) |oid| {
                    // the HEAD is detached, so just update it with the oid
                    try path_parts.append(.{ .value = .{ .bytes = &oid } });
                    try core.db.rootCursor().execute(void, path_parts.items);
                } else {
                    // point HEAD at the ref, even though the ref doesn't exist
                    var write_buffer = [_]u8{0} ** MAX_READ_BYTES;
                    const content = try std.fmt.bufPrint(&write_buffer, "ref: refs/heads/{s}", .{target});
                    try path_parts.append(.{ .value = .{ .bytes = content } });
                    try core.db.rootCursor().execute(void, path_parts.items);
                }
            }
        },
    }
}

pub fn UpdateOpts(comptime repo_kind: rp.RepoKind) type {
    return switch (repo_kind) {
        .git => struct {
            dir: std.fs.Dir,
        },
        .xit => struct {
            root_cursor: xitdb.Database(.file).Cursor,
            cursor: xitdb.Database(.file).Cursor,
        },
    };
}

/// update the given file with the given oid,
/// following refs recursively if necessary.
/// used after a commit is made.
pub fn updateRecur(comptime repo_kind: rp.RepoKind, core: *rp.Repo(repo_kind).Core, opts: UpdateOpts(repo_kind), allocator: std.mem.Allocator, file_name: []const u8, oid: [hash.SHA1_HEX_LEN]u8) anyerror!void {
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
                try updateRecur(repo_kind, core, .{ .dir = heads_dir }, allocator, ref_name, oid);
            }
            // otherwise, update it with the oid
            else {
                try lock.lock_file.writeAll(&oid);
                try lock.lock_file.writeAll("\n");
                lock.success = true;
            }
        },
        .xit => {
            // read file and get ref name if necessary
            var buffer = [_]u8{0} ** MAX_READ_BYTES;
            const ref_name_maybe = blk: {
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
                const UpdateCtx = struct {
                    core: *rp.Repo(repo_kind).Core,
                    allocator: std.mem.Allocator,
                    file_name: []const u8,
                    oid: [hash.SHA1_HEX_LEN]u8,
                    root_cursor: xitdb.Database(.file).Cursor,

                    pub fn update(ctx_self: @This(), cursor: xitdb.Database(.file).Cursor, _: bool) !void {
                        try updateRecur(repo_kind, ctx_self.core, .{ .root_cursor = ctx_self.root_cursor, .cursor = cursor }, ctx_self.allocator, ctx_self.file_name, ctx_self.oid);
                    }
                };
                try opts.root_cursor.execute(UpdateCtx, &[_]xitdb.PathPart(UpdateCtx){
                    .{ .map_get = .{ .bytes = "refs" } },
                    .map_create,
                    .{ .map_get = .{ .bytes = "heads" } },
                    .map_create,
                    .{ .update = UpdateCtx{ .core = core, .allocator = allocator, .file_name = ref_name, .oid = oid, .root_cursor = opts.root_cursor } },
                });
            }
            // otherwise, update it with the oid
            else {
                try opts.cursor.execute(void, &[_]xitdb.PathPart(void){
                    .{ .map_get = .{ .bytes = file_name } },
                    .{ .value = .{ .bytes = &oid } },
                });
            }
        },
    }
}
