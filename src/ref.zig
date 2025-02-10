const std = @import("std");
const hash = @import("./hash.zig");
const fs = @import("./fs.zig");
const rp = @import("./repo.zig");

pub const MAX_REF_CONTENT_SIZE = 512;
const REF_START_STR = "ref: ";

/// validates ref name with mostly the same rules as in:
/// git check-ref-format --help
pub fn validateName(name: []const u8) bool {
    if (name.len == 0 or
        name.len > 255 or // apparently git's max ref name size
        name[0] == '-' or
        name[name.len - 1] == '.' or
        std.mem.indexOf(u8, name, "..") != null or
        std.mem.indexOf(u8, name, "@{") != null)
    {
        return false;
    }

    // can't contain ASCII control chars or certain special chars
    for (name) |char| {
        switch (char) {
            0...0o37, 0o177, ' ', '~', '^', ':', '?', '*', '[', '\\' => return false,
            else => {},
        }
    }

    // restrictions on each path part
    var split_iter = std.mem.splitScalar(u8, name, '/');
    while (split_iter.next()) |path_part| {
        if (path_part.len == 0 or
            path_part[0] == '.' or
            std.mem.endsWith(u8, name, ".lock"))
        {
            return false;
        }
    }

    return true;
}

pub const RefKind = union(enum) {
    head,
    tag,
    remote: []const u8,
};

pub const Ref = struct {
    kind: RefKind,
    name: []const u8,

    pub fn initFromPath(ref_path: []const u8) ?Ref {
        var split_iter = std.mem.splitScalar(u8, ref_path, '/');

        const refs_str = split_iter.next() orelse return null;
        if (!std.mem.eql(u8, "refs", refs_str)) return null;

        const ref_kind = split_iter.next() orelse return null;
        const ref_name = ref_path[refs_str.len + 1 + ref_kind.len + 1 ..];

        if (std.mem.eql(u8, "heads", ref_kind)) {
            return .{ .kind = .head, .name = ref_name };
        } else if (std.mem.eql(u8, "tags", ref_kind)) {
            return .{ .kind = .tag, .name = ref_name };
        } else if (std.mem.eql(u8, "remotes", ref_kind)) {
            const remote_name = split_iter.next() orelse return null;
            const remote_ref_name = ref_name[remote_name.len + 1 ..];
            return .{ .kind = .{ .remote = remote_name }, .name = remote_ref_name };
        } else {
            return null;
        }
    }

    pub fn toPath(self: Ref, buffer: []u8) ![]const u8 {
        return switch (self.kind) {
            .head => try std.fmt.bufPrint(buffer, "refs/heads/{s}", .{self.name}),
            .tag => try std.fmt.bufPrint(buffer, "refs/tags/{s}", .{self.name}),
            .remote => |remote| try std.fmt.bufPrint(buffer, "refs/remotes/{s}/{s}", .{ remote, self.name }),
        };
    }
};

fn isOid(comptime hash_kind: hash.HashKind, content: []const u8) bool {
    if (content.len != hash.hexLen(hash_kind)) {
        return false;
    }
    for (content) |ch| {
        if (!std.ascii.isHex(ch)) {
            return false;
        }
    }
    return true;
}

pub fn RefOrOid(comptime hash_kind: hash.HashKind) type {
    return union(enum) {
        ref: Ref,
        oid: *const [hash.hexLen(hash_kind)]u8,

        pub fn initFromDb(content: []const u8) ?RefOrOid(hash_kind) {
            if (std.mem.startsWith(u8, content, REF_START_STR)) {
                if (Ref.initFromPath(content[REF_START_STR.len..])) |ref| {
                    return .{ .ref = ref };
                } else {
                    return null;
                }
            } else if (isOid(hash_kind, content)) {
                return .{ .oid = content[0..comptime hash.hexLen(hash_kind)] };
            } else {
                return null;
            }
        }

        pub fn initFromUser(content: []const u8) ?RefOrOid(hash_kind) {
            if (isOid(hash_kind, content)) {
                return .{ .oid = content[0..comptime hash.hexLen(hash_kind)] };
            } else {
                return .{ .ref = .{ .kind = .head, .name = content } };
            }
        }
    };
}

pub const RefList = struct {
    refs: std.StringArrayHashMap(Ref),
    arena: *std.heap.ArenaAllocator,
    allocator: std.mem.Allocator,

    pub fn init(
        comptime repo_kind: rp.RepoKind,
        comptime repo_opts: rp.RepoOpts(repo_kind),
        state: rp.Repo(repo_kind, repo_opts).State(.read_only),
        allocator: std.mem.Allocator,
        ref_kind: RefKind,
    ) !RefList {
        const arena = try allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        var ref_list = RefList{
            .refs = std.StringArrayHashMap(Ref).init(allocator),
            .arena = arena,
            .allocator = allocator,
        };
        errdefer ref_list.deinit();

        const dir_name = switch (ref_kind) {
            .head => "heads",
            .tag => "tags",
            .remote => return error.NotImplemented,
        };

        switch (repo_kind) {
            .git => {
                var refs_dir = try state.core.git_dir.openDir("refs", .{});
                defer refs_dir.close();
                var heads_dir = try refs_dir.openDir(dir_name, .{ .iterate = true });
                defer heads_dir.close();

                var path = std.ArrayList([]const u8).init(allocator);
                defer path.deinit();
                try ref_list.addRefs(repo_opts, state, ref_kind, heads_dir, &path);
            },
            .xit => {
                if (try state.extra.moment.cursor.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hash.hashInt(repo_opts.hash, "refs") } },
                    .{ .hash_map_get = .{ .value = hash.hashInt(repo_opts.hash, dir_name) } },
                })) |heads_cursor| {
                    var iter = try heads_cursor.iterator();
                    defer iter.deinit();
                    while (try iter.next()) |*next_cursor| {
                        const kv_pair = try next_cursor.readKeyValuePair();
                        const name = try kv_pair.key_cursor.readBytesAlloc(ref_list.arena.allocator(), MAX_REF_CONTENT_SIZE);
                        try ref_list.refs.put(name, .{ .kind = ref_kind, .name = name });
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

    fn addRefs(
        self: *RefList,
        comptime repo_opts: rp.RepoOpts(.git),
        state: rp.Repo(.git, repo_opts).State(.read_only),
        ref_kind: RefKind,
        dir: std.fs.Dir,
        path: *std.ArrayList([]const u8),
    ) !void {
        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            var next_path = try path.clone();
            defer next_path.deinit();
            try next_path.append(entry.name);
            switch (entry.kind) {
                .file => {
                    const name = try fs.joinPath(self.arena.allocator(), next_path.items);
                    try self.refs.put(name, .{ .kind = ref_kind, .name = name });
                },
                .directory => {
                    var next_dir = try dir.openDir(entry.name, .{ .iterate = true });
                    defer next_dir.close();
                    try self.addRefs(repo_opts, state, ref_kind, next_dir, &next_path);
                },
                else => {},
            }
        }
    }
};

pub fn readRecur(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    input: RefOrOid(repo_opts.hash),
) !?[hash.hexLen(repo_opts.hash)]u8 {
    switch (input) {
        .ref => |ref| {
            var ref_path_buffer = [_]u8{0} ** MAX_REF_CONTENT_SIZE;
            const ref_path = try ref.toPath(&ref_path_buffer);

            var read_buffer = [_]u8{0} ** MAX_REF_CONTENT_SIZE;
            const content = read(repo_kind, repo_opts, state, ref_path, &read_buffer) catch |err| switch (err) {
                error.RefNotFound => return null,
                else => |e| return e,
            };

            if (RefOrOid(repo_opts.hash).initFromDb(content)) |next_input| {
                return try readRecur(repo_kind, repo_opts, state, next_input);
            } else {
                return null;
            }
        },
        .oid => |oid| return oid.*,
    }
}

pub fn read(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    ref_path: []const u8,
    buffer: []u8,
) ![]u8 {
    switch (repo_kind) {
        .git => {
            // look for loose ref
            if (state.core.git_dir.openFile(ref_path, .{ .mode = .read_only })) |ref_file| {
                defer ref_file.close();
                const size = try ref_file.reader().readAll(buffer);
                return std.mem.sliceTo(buffer[0..size], '\n');
            } else |err| switch (err) {
                error.FileNotFound => {},
                else => |e| return e,
            }

            // look for packed ref
            if (state.core.git_dir.openFile("packed-refs", .{ .mode = .read_only })) |packed_refs_file| {
                defer packed_refs_file.close();

                var buffered_reader = std.io.bufferedReaderSize(repo_opts.read_size, packed_refs_file.reader());
                const reader = buffered_reader.reader();

                var read_buffer = [_]u8{0} ** repo_opts.max_read_size;
                while (try reader.readUntilDelimiterOrEof(&read_buffer, '\n')) |line| {
                    const trimmed_line = std.mem.trim(u8, line, " ");
                    if (std.mem.startsWith(u8, trimmed_line, "#")) {
                        continue;
                    }

                    var split_iter = std.mem.splitScalar(u8, trimmed_line, ' ');
                    const oid_hex = split_iter.next() orelse continue;
                    const path = split_iter.next() orelse continue;

                    if (isOid(repo_opts.hash, oid_hex) and std.mem.eql(u8, ref_path, path)) {
                        @memcpy(buffer[0..oid_hex.len], oid_hex);
                        return buffer[0..oid_hex.len];
                    }
                }
            } else |err| switch (err) {
                error.FileNotFound => {},
                else => |e| return e,
            }

            return error.RefNotFound;
        },
        .xit => {
            var map = state.extra.moment.*;
            var ref_name = ref_path;

            if (Ref.initFromPath(ref_path)) |ref| {
                const refs_cursor = (try map.getCursor(hash.hashInt(repo_opts.hash, "refs"))) orelse return error.RefNotFound;
                const refs = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_only).init(refs_cursor);
                switch (ref.kind) {
                    .head => {
                        const heads_cursor = (try refs.getCursor(hash.hashInt(repo_opts.hash, "heads"))) orelse return error.RefNotFound;
                        map = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_only).init(heads_cursor);
                    },
                    .tag => {
                        const tags_cursor = (try refs.getCursor(hash.hashInt(repo_opts.hash, "tags"))) orelse return error.RefNotFound;
                        map = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_only).init(tags_cursor);
                    },
                    .remote => |remote| {
                        const remotes_cursor = (try refs.getCursor(hash.hashInt(repo_opts.hash, "remotes"))) orelse return error.RefNotFound;
                        const remotes = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_only).init(remotes_cursor);
                        const remote_cursor = (try remotes.getCursor(hash.hashInt(repo_opts.hash, remote))) orelse return error.RefNotFound;
                        map = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_only).init(remote_cursor);
                    },
                }
                ref_name = ref.name;
            }

            const ref_cursor = (try map.getCursor(hash.hashInt(repo_opts.hash, ref_name))) orelse return error.RefNotFound;
            return try ref_cursor.readBytes(buffer);
        },
    }
}

pub fn readHeadMaybe(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
) !?[hash.hexLen(repo_opts.hash)]u8 {
    var buffer = [_]u8{0} ** MAX_REF_CONTENT_SIZE;
    const content = try read(repo_kind, repo_opts, state, "HEAD", &buffer);
    if (RefOrOid(repo_opts.hash).initFromDb(content)) |input| {
        return try readRecur(repo_kind, repo_opts, state, input);
    } else {
        return null;
    }
}

pub fn readHead(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
) ![hash.hexLen(repo_opts.hash)]u8 {
    if (try readHeadMaybe(repo_kind, repo_opts, state)) |buffer| {
        return buffer;
    } else {
        return error.RefInvalidHash;
    }
}

pub fn readHeadName(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    buffer: []u8,
) ![]u8 {
    const content = try read(repo_kind, repo_opts, state, "HEAD", buffer);
    const ref_heads_start_str = "ref: refs/heads/";
    if (std.mem.startsWith(u8, content, ref_heads_start_str) and content.len > ref_heads_start_str.len) {
        return content[ref_heads_start_str.len..];
    } else {
        return content;
    }
}

pub fn readHeadNameAlloc(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_only),
    allocator: std.mem.Allocator,
) ![]u8 {
    var buffer = [_]u8{0} ** MAX_REF_CONTENT_SIZE;
    return try allocator.dupe(u8, try readHeadName(repo_kind, repo_opts, state, &buffer));
}

pub fn write(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    ref_path: []const u8,
    content: []const u8,
) !void {
    switch (repo_kind) {
        .git => {
            if (std.fs.path.dirname(ref_path)) |ref_parent_path| {
                try state.core.git_dir.makePath(ref_parent_path);
            }
            var lock = try fs.LockFile.init(state.core.git_dir, ref_path);
            defer lock.deinit();
            try lock.lock_file.writeAll(content);
            try lock.lock_file.writeAll("\n");
            lock.success = true;
        },
        .xit => {
            var map = state.extra.moment.*;
            var ref_name = ref_path;

            if (Ref.initFromPath(ref_path)) |ref| {
                const refs_cursor = try map.putCursor(hash.hashInt(repo_opts.hash, "refs"));
                const refs = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(refs_cursor);
                switch (ref.kind) {
                    .head => {
                        const heads_cursor = try refs.putCursor(hash.hashInt(repo_opts.hash, "heads"));
                        map = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(heads_cursor);
                    },
                    .tag => {
                        const tags_cursor = try refs.putCursor(hash.hashInt(repo_opts.hash, "tags"));
                        map = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(tags_cursor);
                    },
                    .remote => |remote_name| {
                        const remotes_cursor = try refs.putCursor(hash.hashInt(repo_opts.hash, "remotes"));
                        const remotes = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(remotes_cursor);
                        const remote_cursor = try remotes.putCursor(hash.hashInt(repo_opts.hash, remote_name));
                        map = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(remote_cursor);
                    },
                }
                ref_name = ref.name;
            }

            const ref_name_hash = hash.hashInt(repo_opts.hash, ref_name);
            const ref_name_set_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "ref-name-set"));
            const ref_name_set = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(ref_name_set_cursor);
            var ref_name_cursor = try ref_name_set.putKeyCursor(ref_name_hash);
            try ref_name_cursor.writeIfEmpty(.{ .bytes = ref_name });
            try map.putKey(ref_name_hash, .{ .slot = ref_name_cursor.slot() });
            const ref_content_set_cursor = try state.extra.moment.putCursor(hash.hashInt(repo_opts.hash, "ref-content-set"));
            const ref_content_set = try rp.Repo(repo_kind, repo_opts).DB.HashMap(.read_write).init(ref_content_set_cursor);
            var ref_content_cursor = try ref_content_set.putKeyCursor(hash.hashInt(repo_opts.hash, content));
            try ref_content_cursor.writeIfEmpty(.{ .bytes = content });
            try map.put(ref_name_hash, .{ .slot = ref_content_cursor.slot() });
        },
    }
}

pub fn writeRecur(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    ref_path: []const u8,
    oid_hex: *const [hash.hexLen(repo_opts.hash)]u8,
) !void {
    var buffer = [_]u8{0} ** MAX_REF_CONTENT_SIZE;
    const existing_content = read(repo_kind, repo_opts, state.readOnly(), ref_path, &buffer) catch |err| switch (err) {
        error.RefNotFound => {
            try write(repo_kind, repo_opts, state, ref_path, oid_hex);
            return;
        },
        else => |e| return e,
    };
    if (RefOrOid(repo_opts.hash).initFromDb(existing_content)) |input| {
        switch (input) {
            .ref => |ref| {
                var ref_path_buffer = [_]u8{0} ** MAX_REF_CONTENT_SIZE;
                const next_ref_path = try ref.toPath(&ref_path_buffer);
                try writeRecur(repo_kind, repo_opts, state, next_ref_path, oid_hex);
            },
            .oid => try write(repo_kind, repo_opts, state, ref_path, oid_hex),
        }
    } else {
        try write(repo_kind, repo_opts, state, ref_path, oid_hex);
    }
}

pub fn replaceHead(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    ref_or_oid: RefOrOid(repo_opts.hash),
) !void {
    var buffer = [_]u8{0} ** MAX_REF_CONTENT_SIZE;
    const content = switch (ref_or_oid) {
        .oid => |oid| oid,
        .ref => |ref| blk: {
            var path_buffer = [_]u8{0} ** MAX_REF_CONTENT_SIZE;
            const path = try ref.toPath(&path_buffer);
            break :blk try std.fmt.bufPrint(&buffer, "ref: {s}", .{path});
        },
    };
    try write(repo_kind, repo_opts, state, "HEAD", content);
}

pub fn updateHead(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    oid: *const [hash.hexLen(repo_opts.hash)]u8,
) !void {
    try writeRecur(repo_kind, repo_opts, state, "HEAD", oid);
}
