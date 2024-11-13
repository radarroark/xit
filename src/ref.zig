const std = @import("std");
const hash = @import("./hash.zig");
const io = @import("./io.zig");
const rp = @import("./repo.zig");

const MAX_REF_CONTENT_SIZE = 512;
const REF_START_STR = "ref: ";

pub const Ref = struct {
    kind: union(enum) {
        local,
        remote: []const u8,
    },
    name: []const u8,

    pub fn initFromPath(ref_path: []const u8) ?Ref {
        var split_iter = std.mem.splitScalar(u8, ref_path, '/');

        const refs_str = split_iter.next() orelse return null;
        if (!std.mem.eql(u8, "refs", refs_str)) return null;

        const ref_kind = split_iter.next() orelse return null;
        const ref_name = ref_path[refs_str.len + 1 + ref_kind.len + 1 ..];

        if (std.mem.eql(u8, "heads", ref_kind)) {
            return .{ .kind = .local, .name = ref_name };
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
            .local => try std.fmt.bufPrint(buffer, "refs/heads/{s}", .{self.name}),
            .remote => |remote| try std.fmt.bufPrint(buffer, "refs/remotes/{s}/{s}", .{ remote, self.name }),
        };
    }
};

pub const RefOrOid = union(enum) {
    ref: Ref,
    oid: *const [hash.SHA1_HEX_LEN]u8,

    pub fn initFromDb(content: []const u8) ?RefOrOid {
        if (std.mem.startsWith(u8, content, REF_START_STR)) {
            if (Ref.initFromPath(content[REF_START_STR.len..])) |ref| {
                return .{ .ref = ref };
            } else {
                return null;
            }
        } else if (content.len == hash.SHA1_HEX_LEN) {
            return .{ .oid = content[0..hash.SHA1_HEX_LEN] };
        } else {
            return null;
        }
    }

    pub fn initFromUser(content: []const u8) RefOrOid {
        if (content.len == hash.SHA1_HEX_LEN) {
            return .{ .oid = content[0..hash.SHA1_HEX_LEN] };
        } else {
            return .{ .ref = .{ .kind = .local, .name = content } };
        }
    }
};

pub const LoadedRef = struct {
    allocator: std.mem.Allocator,
    path: []const u8,
    name: []const u8,
    oid_hex: ?[hash.SHA1_HEX_LEN]u8,

    pub fn initWithName(comptime repo_kind: rp.RepoKind, state: rp.Repo(repo_kind).State(.read_only), allocator: std.mem.Allocator, dir_name: []const u8, name: []const u8) !LoadedRef {
        const path = try io.joinPath(allocator, &.{ "refs", dir_name, name });
        errdefer allocator.free(path);
        return .{
            .allocator = allocator,
            .path = path,
            .name = name,
            .oid_hex = try readRecur(repo_kind, state, .{ .ref = Ref.initFromPath(path) orelse return error.InvalidRefPath }),
        };
    }

    pub fn initWithPath(comptime repo_kind: rp.RepoKind, state: rp.Repo(repo_kind).State(.read_only), allocator: std.mem.Allocator, ref_path: []const u8) !LoadedRef {
        const path = try allocator.dupe(u8, ref_path);
        errdefer allocator.free(path);
        return .{
            .allocator = allocator,
            .path = path,
            .name = (Ref.initFromPath(path) orelse return error.InvalidRefPath).name,
            .oid_hex = try readRecur(repo_kind, state, .{ .ref = Ref.initFromPath(path) orelse return error.InvalidRefPath }),
        };
    }

    pub fn initWithPathRecur(comptime repo_kind: rp.RepoKind, state: rp.Repo(repo_kind).State(.read_only), allocator: std.mem.Allocator, ref_path: []const u8) !?LoadedRef {
        var buffer = [_]u8{0} ** MAX_REF_CONTENT_SIZE;
        const content = try read(repo_kind, state, ref_path, &buffer);

        if (std.mem.startsWith(u8, content, REF_START_STR) and content.len > REF_START_STR.len) {
            return try initWithPath(repo_kind, state, allocator, content[REF_START_STR.len..]);
        } else {
            return null;
        }
    }

    pub fn deinit(self: *LoadedRef) void {
        self.allocator.free(self.path);
    }
};

pub const RefList = struct {
    refs: std.ArrayList(LoadedRef),
    arena: *std.heap.ArenaAllocator,
    allocator: std.mem.Allocator,

    pub fn init(comptime repo_kind: rp.RepoKind, state: rp.Repo(repo_kind).State(.read_only), allocator: std.mem.Allocator, dir_name: []const u8) !RefList {
        const arena = try allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        var ref_list = RefList{
            .refs = std.ArrayList(LoadedRef).init(allocator),
            .arena = arena,
            .allocator = allocator,
        };
        errdefer ref_list.deinit();

        switch (repo_kind) {
            .git => {
                var refs_dir = try state.core.git_dir.openDir("refs", .{});
                defer refs_dir.close();
                var heads_dir = try refs_dir.openDir("heads", .{});
                defer heads_dir.close();

                var path = std.ArrayList([]const u8).init(allocator);
                defer path.deinit();
                try ref_list.addRefs(repo_kind, state, dir_name, heads_dir, &path);
            },
            .xit => {
                if (try state.extra.moment.cursor.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hash.hashBuffer("refs") } },
                    .{ .hash_map_get = .{ .value = hash.hashBuffer("heads") } },
                })) |heads_cursor| {
                    var iter = try heads_cursor.iterator();
                    defer iter.deinit();
                    while (try iter.next()) |*next_cursor| {
                        const kv_pair = try next_cursor.readKeyValuePair();
                        const name = try kv_pair.key_cursor.readBytesAlloc(ref_list.arena.allocator(), MAX_REF_CONTENT_SIZE);
                        const ref = try LoadedRef.initWithName(repo_kind, state, ref_list.arena.allocator(), dir_name, name);
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

    fn addRefs(self: *RefList, comptime repo_kind: rp.RepoKind, state: rp.Repo(repo_kind).State(.read_only), dir_name: []const u8, dir: std.fs.Dir, path: *std.ArrayList([]const u8)) !void {
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
                    const ref = try LoadedRef.initWithName(repo_kind, state, self.arena.allocator(), dir_name, name);
                    try self.refs.append(ref);
                },
                .directory => {
                    var next_dir = try dir.openDir(entry.name, .{});
                    defer next_dir.close();
                    try self.addRefs(repo_kind, state, dir_name, next_dir, &next_path);
                },
                else => {},
            }
        }
    }
};

pub fn readRecur(comptime repo_kind: rp.RepoKind, state: rp.Repo(repo_kind).State(.read_only), input: RefOrOid) !?[hash.SHA1_HEX_LEN]u8 {
    switch (input) {
        .ref => |ref| {
            var ref_path_buffer = [_]u8{0} ** MAX_REF_CONTENT_SIZE;
            const ref_path = try ref.toPath(&ref_path_buffer);

            var read_buffer = [_]u8{0} ** MAX_REF_CONTENT_SIZE;
            const content = read(repo_kind, state, ref_path, &read_buffer) catch |err| switch (err) {
                error.RefNotFound => return null,
                else => return err,
            };

            if (RefOrOid.initFromDb(content)) |next_input| {
                return try readRecur(repo_kind, state, next_input);
            } else {
                return null;
            }
        },
        .oid => |oid| return oid.*,
    }
}

pub fn read(comptime repo_kind: rp.RepoKind, state: rp.Repo(repo_kind).State(.read_only), ref_path: []const u8, buffer: []u8) ![]u8 {
    switch (repo_kind) {
        .git => {
            const ref_file = state.core.git_dir.openFile(ref_path, .{ .mode = .read_only }) catch |err| switch (err) {
                error.FileNotFound => return error.RefNotFound,
                else => return err,
            };
            defer ref_file.close();
            const size = try ref_file.reader().readAll(buffer);
            return std.mem.sliceTo(buffer[0..size], '\n');
        },
        .xit => {
            var map = state.extra.moment.*;
            var ref_name = ref_path;

            if (Ref.initFromPath(ref_path)) |ref| {
                const refs_cursor = (try map.getCursor(hash.hashBuffer("refs"))) orelse return error.RefNotFound;
                const refs = try rp.Repo(repo_kind).DB.HashMap(.read_only).init(refs_cursor);
                switch (ref.kind) {
                    .local => {
                        const heads_cursor = (try refs.getCursor(hash.hashBuffer("heads"))) orelse return error.RefNotFound;
                        map = try rp.Repo(repo_kind).DB.HashMap(.read_only).init(heads_cursor);
                    },
                    .remote => |remote| {
                        const remotes_cursor = (try refs.getCursor(hash.hashBuffer("remotes"))) orelse return error.RefNotFound;
                        const remotes = try rp.Repo(repo_kind).DB.HashMap(.read_only).init(remotes_cursor);
                        const remote_cursor = (try remotes.getCursor(hash.hashBuffer(remote))) orelse return error.RefNotFound;
                        map = try rp.Repo(repo_kind).DB.HashMap(.read_only).init(remote_cursor);
                    },
                }
                ref_name = ref.name;
            }

            const ref_cursor = (try map.getCursor(hash.hashBuffer(ref_name))) orelse return error.RefNotFound;
            return try ref_cursor.readBytes(buffer);
        },
    }
}

pub fn readHeadMaybe(comptime repo_kind: rp.RepoKind, state: rp.Repo(repo_kind).State(.read_only)) !?[hash.SHA1_HEX_LEN]u8 {
    var buffer = [_]u8{0} ** MAX_REF_CONTENT_SIZE;
    const content = try read(repo_kind, state, "HEAD", &buffer);
    if (RefOrOid.initFromDb(content)) |input| {
        return try readRecur(repo_kind, state, input);
    } else {
        return null;
    }
}

pub fn readHead(comptime repo_kind: rp.RepoKind, state: rp.Repo(repo_kind).State(.read_only)) ![hash.SHA1_HEX_LEN]u8 {
    if (try readHeadMaybe(repo_kind, state)) |buffer| {
        return buffer;
    } else {
        return error.RefInvalidHash;
    }
}

pub fn readHeadName(comptime repo_kind: rp.RepoKind, state: rp.Repo(repo_kind).State(.read_only), allocator: std.mem.Allocator) ![]u8 {
    var buffer = [_]u8{0} ** MAX_REF_CONTENT_SIZE;
    const content = try read(repo_kind, state, "HEAD", &buffer);
    const ref_heads_start_str = "ref: refs/heads/";
    if (std.mem.startsWith(u8, content, ref_heads_start_str) and content.len > ref_heads_start_str.len) {
        const ref_name = content[ref_heads_start_str.len..];
        return try allocator.dupe(u8, ref_name);
    } else {
        return try allocator.dupe(u8, content);
    }
}

pub fn write(
    comptime repo_kind: rp.RepoKind,
    state: rp.Repo(repo_kind).State(.read_write),
    ref_path: []const u8,
    content: []const u8,
) !void {
    switch (repo_kind) {
        .git => {
            if (std.fs.path.dirname(ref_path)) |ref_parent_path| {
                try state.core.git_dir.makePath(ref_parent_path);
            }
            var lock = try io.LockFile.init(state.core.git_dir, ref_path);
            defer lock.deinit();
            try lock.lock_file.writeAll(content);
            try lock.lock_file.writeAll("\n");
            lock.success = true;
        },
        .xit => {
            var map = state.extra.moment.*;
            var ref_name = ref_path;

            if (Ref.initFromPath(ref_path)) |ref| {
                const refs_cursor = try map.putCursor(hash.hashBuffer("refs"));
                const refs = try rp.Repo(repo_kind).DB.HashMap(.read_write).init(refs_cursor);
                switch (ref.kind) {
                    .local => {
                        const heads_cursor = try refs.putCursor(hash.hashBuffer("heads"));
                        map = try rp.Repo(repo_kind).DB.HashMap(.read_write).init(heads_cursor);
                    },
                    .remote => |remote_name| {
                        const remotes_cursor = try refs.putCursor(hash.hashBuffer("remotes"));
                        const remotes = try rp.Repo(repo_kind).DB.HashMap(.read_write).init(remotes_cursor);
                        const remote_cursor = try remotes.putCursor(hash.hashBuffer(remote_name));
                        map = try rp.Repo(repo_kind).DB.HashMap(.read_write).init(remote_cursor);
                    },
                }
                ref_name = ref.name;
            }

            const ref_name_hash = hash.hashBuffer(ref_name);
            const ref_name_set_cursor = try state.extra.moment.putCursor(hash.hashBuffer("ref-name-set"));
            const ref_name_set = try rp.Repo(repo_kind).DB.HashMap(.read_write).init(ref_name_set_cursor);
            var ref_name_cursor = try ref_name_set.putKeyCursor(ref_name_hash);
            try ref_name_cursor.writeIfEmpty(.{ .bytes = ref_name });
            try map.putKey(ref_name_hash, .{ .slot = ref_name_cursor.slot() });
            const ref_content_set_cursor = try state.extra.moment.putCursor(hash.hashBuffer("ref-content-set"));
            const ref_content_set = try rp.Repo(repo_kind).DB.HashMap(.read_write).init(ref_content_set_cursor);
            var ref_content_cursor = try ref_content_set.putKeyCursor(hash.hashBuffer(content));
            try ref_content_cursor.writeIfEmpty(.{ .bytes = content });
            try map.put(ref_name_hash, .{ .slot = ref_content_cursor.slot() });
        },
    }
}

pub fn writeRecur(
    comptime repo_kind: rp.RepoKind,
    state: rp.Repo(repo_kind).State(.read_write),
    ref_path: []const u8,
    oid_hex: *const [hash.SHA1_HEX_LEN]u8,
) !void {
    var buffer = [_]u8{0} ** MAX_REF_CONTENT_SIZE;
    const existing_content = read(repo_kind, state.readOnly(), ref_path, &buffer) catch |err| switch (err) {
        error.RefNotFound => {
            try write(repo_kind, state, ref_path, oid_hex);
            return;
        },
        else => return err,
    };
    if (RefOrOid.initFromDb(existing_content)) |input| {
        switch (input) {
            .ref => |ref| {
                var ref_path_buffer = [_]u8{0} ** MAX_REF_CONTENT_SIZE;
                const next_ref_path = try ref.toPath(&ref_path_buffer);
                try writeRecur(repo_kind, state, next_ref_path, oid_hex);
            },
            .oid => try write(repo_kind, state, ref_path, oid_hex),
        }
    } else {
        try write(repo_kind, state, ref_path, oid_hex);
    }
}

pub fn writeHead(comptime repo_kind: rp.RepoKind, state: rp.Repo(repo_kind).State(.read_write), target: []const u8, oid_hex_maybe: ?[hash.SHA1_HEX_LEN]u8) !void {
    var buffer = [_]u8{0} ** MAX_REF_CONTENT_SIZE;
    const content =
        // target is a ref, so make HEAD point to it
        if (try readRecur(repo_kind, state.readOnly(), .{ .ref = .{ .kind = .local, .name = target } }) != null)
        try std.fmt.bufPrint(&buffer, "ref: refs/heads/{s}", .{target})
        // the HEAD is detached, so just update it with the oid
    else if (oid_hex_maybe) |oid_hex|
        &oid_hex
        // point HEAD at the ref, even though the ref doesn't exist
    else
        try std.fmt.bufPrint(&buffer, "ref: refs/heads/{s}", .{target});
    try write(repo_kind, state, "HEAD", content);
}
