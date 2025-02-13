const std = @import("std");
const hash = @import("./hash.zig");
const obj = @import("./object.zig");
const cmd = @import("./command.zig");
const idx = @import("./index.zig");
const st = @import("./status.zig");
const bch = @import("./branch.zig");
const mnt = @import("./mount.zig");
const rf = @import("./ref.zig");
const fs = @import("./fs.zig");
const df = @import("./diff.zig");
const mrg = @import("./merge.zig");
const cfg = @import("./config.zig");
const net = @import("./net.zig");
const chunk = @import("./chunk.zig");
const tag = @import("./tag.zig");

pub const RepoKind = enum {
    git,
    xit,
};

pub fn RepoOpts(comptime repo_kind: RepoKind) type {
    return struct {
        hash: hash.HashKind = .sha1,
        read_size: usize = 1024,
        max_read_size: usize = 2048,
        max_line_size: usize = 10_000,
        max_line_count: usize = 10_000_000,
        is_test: bool = false,
        extra: Extra = .{},

        pub const Extra = switch (repo_kind) {
            .git => struct {},
            .xit => struct {
                chunk_opts: chunk.FastCdcOpts = .{
                    .min_size = 1024,
                    .avg_size = 2048,
                    .max_size = 4096,
                    .normalization = .level1,
                },
            },
        };

        pub fn withHash(self: RepoOpts(repo_kind), hash_kind: hash.HashKind) RepoOpts(repo_kind) {
            var new_self = self;
            new_self.hash = hash_kind;
            return new_self;
        }
    };
}

pub const InitOpts = struct {
    cwd: std.fs.Dir,
};

pub fn Repo(comptime repo_kind: RepoKind, comptime repo_opts: RepoOpts(repo_kind)) type {
    return struct {
        core: Core,
        init_opts: InitOpts,

        pub const Core = switch (repo_kind) {
            .git => struct {
                repo_dir: std.fs.Dir,
                git_dir: std.fs.Dir,

                pub fn latestMoment(_: *@This()) !void {}
            },
            .xit => struct {
                repo_dir: std.fs.Dir,
                xit_dir: std.fs.Dir,
                db_file: std.fs.File,
                db: DB,

                /// used by read-only fns to get a moment without starting a transaction
                pub fn latestMoment(self: *@This()) !DB.HashMap(.read_only) {
                    if (self.db.tx_start != null) return error.NotMeantToRunInTransaction;
                    const history = try DB.ArrayList(.read_only).init(self.db.rootCursor().readOnly());
                    if (try history.getCursor(-1)) |cursor| {
                        return try DB.HashMap(.read_only).init(cursor);
                    } else {
                        return error.DatabaseIsEmpty;
                    }
                }
            },
        };

        pub const DB = switch (repo_kind) {
            .git => void,
            .xit => switch (repo_opts.hash) {
                .none => void,
                else => @import("xitdb").Database(.file, hash.HashInt(repo_opts.hash)),
            },
        };

        pub const WriteMode = switch (repo_kind) {
            .git => enum { read_only, read_write },
            .xit => @import("xitdb").WriteMode,
        };

        // the data representing a moment in time in xitdb.
        // not used at all on the git side.
        pub fn Moment(comptime write_mode: WriteMode) type {
            return switch (repo_kind) {
                .git => void,
                .xit => DB.HashMap(write_mode),
            };
        }

        // bundle of the repo's state that is passed to internal functions
        pub fn State(comptime write_mode: WriteMode) type {
            return struct {
                core: *Core,
                extra: Extra,

                pub const Extra = switch (repo_kind) {
                    .git => switch (write_mode) {
                        .read_only => struct {
                            moment: *void = undefined, // does nothing, but allows `{ .moment = &moment }` to compile
                        },
                        .read_write => struct {
                            lock_file_maybe: ?std.fs.File = null,
                        },
                    },
                    .xit => struct {
                        moment: *DB.HashMap(write_mode),
                    },
                };

                pub fn readOnly(self: State(.read_write)) State(.read_only) {
                    return switch (repo_kind) {
                        .git => .{ .core = self.core, .extra = .{} },
                        .xit => .{ .core = self.core, .extra = .{ .moment = @ptrCast(self.extra.moment) } },
                    };
                }
            };
        }

        pub fn init(allocator: std.mem.Allocator, opts: InitOpts, sub_path: []const u8) !Repo(repo_kind, repo_opts) {
            // get the root dir. if no path was given to the init command, this
            // should just be the current working directory (cwd). if a path was
            // given, it should either append it to the cwd or, if it is absolute,
            // it should just use that path alone. IT'S MAGIC!
            var repo_dir = try opts.cwd.makeOpenPath(sub_path, .{});
            errdefer repo_dir.close();

            switch (repo_kind) {
                .git => {
                    // return if dir already exists
                    {
                        var git_dir_or_err = repo_dir.openDir(".git", .{});
                        if (git_dir_or_err) |*git_dir| {
                            git_dir.close();
                            return error.RepoAlreadyExists;
                        } else |_| {}
                    }

                    // make the .git dir
                    var git_dir = try repo_dir.makeOpenPath(".git", .{});
                    errdefer git_dir.close();

                    // make a few dirs inside of .git
                    try git_dir.makePath("objects");
                    try git_dir.makePath("objects/pack");
                    try git_dir.makePath("refs");
                    try git_dir.makePath("refs/heads");

                    var self = Repo(repo_kind, repo_opts){
                        .core = .{
                            .repo_dir = repo_dir,
                            .git_dir = git_dir,
                        },
                        .init_opts = opts,
                    };

                    // update HEAD
                    const state = State(.read_write){ .core = &self.core, .extra = .{} };
                    try rf.replaceHead(repo_kind, repo_opts, state, .{ .ref = .{ .kind = .head, .name = "master" } });

                    return self;
                },
                .xit => {
                    // return if dir already exists
                    {
                        var xit_dir_or_err = repo_dir.openDir(".xit", .{});
                        if (xit_dir_or_err) |*xit_dir| {
                            xit_dir.close();
                            return error.RepoAlreadyExists;
                        } else |_| {}
                    }

                    // make the .xit dir
                    var xit_dir = try repo_dir.makeOpenPath(".xit", .{});
                    errdefer xit_dir.close();

                    // create the db file
                    const db_file = try xit_dir.createFile("db", .{ .exclusive = true, .lock = .exclusive, .read = true });
                    errdefer db_file.close();

                    // make the db
                    var self = Repo(repo_kind, repo_opts){
                        .core = .{
                            .repo_dir = repo_dir,
                            .xit_dir = xit_dir,
                            .db_file = db_file,
                            .db = try DB.init(allocator, .{ .file = db_file, .hash_id = .{ .id = hash.hashId(repo_opts.hash) } }),
                        },
                        .init_opts = opts,
                    };

                    // update HEAD
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            try rf.replaceHead(repo_kind, repo_opts, state, .{ .ref = .{ .kind = .head, .name = "master" } });
                        }
                    };
                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core },
                    );

                    return self;
                },
            }
        }

        pub fn open(allocator: std.mem.Allocator, opts: InitOpts) !Repo(repo_kind, repo_opts) {
            const cwd_path = try opts.cwd.realpathAlloc(allocator, ".");
            defer allocator.free(cwd_path);

            // search all parent dirs for one containing the internal dir
            var dir_path_maybe: ?[]const u8 = cwd_path;
            while (dir_path_maybe) |dir_path| {
                var repo_dir = try std.fs.openDirAbsolute(dir_path, .{});
                defer repo_dir.close();

                const internal_dir_name = switch (repo_kind) {
                    .git => ".git",
                    .xit => ".xit",
                };
                var internal_dir = repo_dir.openDir(internal_dir_name, .{}) catch |err| switch (err) {
                    error.FileNotFound => {
                        dir_path_maybe = std.fs.path.dirname(dir_path);
                        continue;
                    },
                    else => |e| return e,
                };
                defer internal_dir.close();

                break;
            }

            const dir_path = dir_path_maybe orelse return error.RepoNotFound;
            var repo_dir = try std.fs.openDirAbsolute(dir_path, .{});
            errdefer repo_dir.close();

            switch (repo_kind) {
                .git => {
                    var git_dir = try repo_dir.openDir(".git", .{});
                    errdefer git_dir.close();

                    return .{
                        .core = .{
                            .repo_dir = repo_dir,
                            .git_dir = git_dir,
                        },
                        .init_opts = opts,
                    };
                },
                .xit => {
                    var xit_dir = try repo_dir.openDir(".xit", .{});
                    errdefer xit_dir.close();

                    var db_file = xit_dir.openFile("db", .{ .mode = .read_write, .lock = .exclusive }) catch |err| switch (err) {
                        error.FileNotFound => return error.RepoNotFound,
                        else => |e| return e,
                    };
                    errdefer db_file.close();

                    return .{
                        .core = .{
                            .repo_dir = repo_dir,
                            .xit_dir = xit_dir,
                            .db_file = db_file,
                            .db = switch (repo_opts.hash) {
                                .none => {},
                                else => blk: {
                                    const hash_id = hash.hashId(repo_opts.hash);
                                    const db = try DB.init(allocator, .{ .file = db_file, .hash_id = .{ .id = hash_id } });
                                    if (db.header.hash_id.id != hash_id) return error.UnexpectedHashKind;
                                    break :blk db;
                                },
                            },
                        },
                        .init_opts = opts,
                    };
                },
            }
        }

        pub fn deinit(self: *Repo(repo_kind, repo_opts)) void {
            switch (repo_kind) {
                .git => {
                    self.core.git_dir.close();
                    self.core.repo_dir.close();
                },
                .xit => {
                    self.core.xit_dir.close();
                    self.core.db_file.close();
                    self.core.repo_dir.close();
                },
            }
        }

        pub fn hashKind(self: *Repo(repo_kind, repo_opts)) !hash.HashKind {
            switch (repo_kind) {
                .git => return .sha1,
                .xit => switch (repo_opts.hash) {
                    .none => {
                        const xitdb = @import("xitdb");

                        try self.core.db_file.seekTo(0);
                        const header = try xitdb.DatabaseHeader.read(self.core.db_file.reader());
                        try header.validate();

                        return hash.hashKind(header.hash_id.id, header.hash_size) orelse error.InvalidHashKind;
                    },
                    else => return self.core.db.header.hash_id.id,
                },
            }
        }

        pub fn commit(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, metadata: obj.CommitMetadata(repo_opts.hash)) ![hash.hexLen(repo_opts.hash)]u8 {
            switch (repo_kind) {
                .git => return try obj.writeCommit(repo_kind, repo_opts, .{ .core = &self.core, .extra = .{} }, allocator, metadata),
                .xit => {
                    const patch = @import("./patch.zig");

                    var result: [hash.hexLen(repo_opts.hash)]u8 = undefined;

                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        allocator: std.mem.Allocator,
                        metadata: obj.CommitMetadata(repo_opts.hash),
                        result: *[hash.hexLen(repo_opts.hash)]u8,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            var stat = try st.Status(repo_kind, repo_opts).init(ctx.allocator, state.readOnly());
                            defer stat.deinit();
                            ctx.result.* = try obj.writeCommit(repo_kind, repo_opts, state, ctx.allocator, ctx.metadata);
                            try patch.writeAndApplyPatches(repo_opts, state, ctx.allocator, &stat, ctx.result);
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .allocator = allocator, .metadata = metadata, .result = &result },
                    );

                    return result;
                },
            }
        }

        pub fn listTags(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator) !rf.RefList {
            var moment = try self.core.latestMoment();
            const state = State(.read_only){ .core = &self.core, .extra = .{ .moment = &moment } };
            return try rf.RefList.init(repo_kind, repo_opts, state, allocator, .tag);
        }

        pub fn addTag(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, input: tag.AddTagInput) ![hash.hexLen(repo_opts.hash)]u8 {
            switch (repo_kind) {
                .git => return try tag.add(repo_kind, repo_opts, .{ .core = &self.core, .extra = .{} }, allocator, input),
                .xit => {
                    var result: [hash.hexLen(repo_opts.hash)]u8 = undefined;

                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        allocator: std.mem.Allocator,
                        input: tag.AddTagInput,
                        result: *[hash.hexLen(repo_opts.hash)]u8,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            ctx.result.* = try tag.add(repo_kind, repo_opts, state, ctx.allocator, ctx.input);
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .allocator = allocator, .input = input, .result = &result },
                    );

                    return result;
                },
            }
        }

        pub fn removeTag(self: *Repo(repo_kind, repo_opts), input: tag.RemoveTagInput) !void {
            switch (repo_kind) {
                .git => try tag.remove(repo_kind, repo_opts, .{ .core = &self.core, .extra = .{} }, input),
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        input: tag.RemoveTagInput,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            try tag.remove(repo_kind, repo_opts, state, ctx.input);
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .input = input },
                    );
                },
            }
        }

        pub fn add(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, paths: []const []const u8) !void {
            switch (repo_kind) {
                .git => {
                    var lock = try fs.LockFile.init(self.core.git_dir, "index");
                    defer lock.deinit();

                    var index = try idx.Index(repo_kind, repo_opts).init(allocator, .{ .core = &self.core, .extra = .{} });
                    defer index.deinit();

                    for (paths) |path| {
                        const rel_path = try fs.relativePath(allocator, self.core.repo_dir, self.init_opts.cwd, path);
                        defer allocator.free(rel_path);
                        const path_parts = try fs.splitPath(allocator, rel_path);
                        defer allocator.free(path_parts);
                        try index.addOrRemovePath(.{ .core = &self.core, .extra = .{} }, path_parts, .add);
                    }

                    try index.write(allocator, .{ .core = &self.core, .extra = .{ .lock_file_maybe = lock.lock_file } });

                    lock.success = true;
                },
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        allocator: std.mem.Allocator,
                        cwd: std.fs.Dir,
                        paths: []const []const u8,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };

                            var index = try idx.Index(repo_kind, repo_opts).init(ctx.allocator, state.readOnly());
                            defer index.deinit();

                            for (ctx.paths) |path| {
                                const rel_path = try fs.relativePath(ctx.allocator, ctx.core.repo_dir, ctx.cwd, path);
                                defer ctx.allocator.free(rel_path);
                                const path_parts = try fs.splitPath(ctx.allocator, rel_path);
                                defer ctx.allocator.free(path_parts);
                                try index.addOrRemovePath(state, path_parts, .add);
                            }

                            try index.write(ctx.allocator, state);
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .allocator = allocator, .cwd = self.init_opts.cwd, .paths = paths },
                    );
                },
            }
        }

        pub fn unadd(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, paths: []const []const u8) !void {
            switch (repo_kind) {
                .git => {
                    var lock = try fs.LockFile.init(self.core.git_dir, "index");
                    defer lock.deinit();

                    var index = try idx.Index(repo_kind, repo_opts).init(allocator, .{ .core = &self.core, .extra = .{} });
                    defer index.deinit();

                    for (paths) |path| {
                        const rel_path = try fs.relativePath(allocator, self.core.repo_dir, self.init_opts.cwd, path);
                        defer allocator.free(rel_path);
                        const path_parts = try fs.splitPath(allocator, rel_path);
                        defer allocator.free(path_parts);

                        try index.addOrRemovePath(.{ .core = &self.core, .extra = .{} }, path_parts, .rm);

                        // iterate over the HEAD entries and add them to the index
                        if (try mnt.headTreeEntry(repo_kind, repo_opts, .{ .core = &self.core, .extra = .{} }, allocator, path_parts)) |*tree_entry| {
                            try index.addTreeEntry(.{ .core = &self.core, .extra = .{} }, allocator, tree_entry, path_parts);
                        }
                    }

                    try index.write(allocator, .{ .core = &self.core, .extra = .{ .lock_file_maybe = lock.lock_file } });

                    lock.success = true;
                },
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        allocator: std.mem.Allocator,
                        cwd: std.fs.Dir,
                        paths: []const []const u8,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };

                            var index = try idx.Index(repo_kind, repo_opts).init(ctx.allocator, state.readOnly());
                            defer index.deinit();

                            for (ctx.paths) |path| {
                                const rel_path = try fs.relativePath(ctx.allocator, ctx.core.repo_dir, ctx.cwd, path);
                                defer ctx.allocator.free(rel_path);
                                const path_parts = try fs.splitPath(ctx.allocator, rel_path);
                                defer ctx.allocator.free(path_parts);

                                try index.addOrRemovePath(state, path_parts, .rm);

                                // iterate over the HEAD entries and add them to the index
                                if (try mnt.headTreeEntry(repo_kind, repo_opts, state.readOnly(), ctx.allocator, path_parts)) |*tree_entry| {
                                    try index.addTreeEntry(state.readOnly(), ctx.allocator, tree_entry, path_parts);
                                }
                            }

                            try index.write(ctx.allocator, state);
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .allocator = allocator, .cwd = self.init_opts.cwd, .paths = paths },
                    );
                },
            }
        }

        pub fn untrack(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, paths: []const []const u8, opts: mnt.UntrackOptions) !void {
            try self.rm(allocator, paths, .{
                .force = opts.force,
                .remove_from_mount = false,
            });
        }

        pub fn rm(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, paths: []const []const u8, opts: mnt.RemoveOptions) !void {
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();

            var normalized_paths = std.ArrayList([]const u8).init(arena.allocator());
            for (paths) |path| {
                const rel_path = try fs.relativePath(allocator, self.core.repo_dir, self.init_opts.cwd, path);
                defer allocator.free(rel_path);
                const path_parts = try fs.splitPath(allocator, rel_path);
                defer allocator.free(path_parts);
                const normalized_path = try fs.joinPath(arena.allocator(), path_parts);
                try normalized_paths.append(normalized_path);
            }

            switch (repo_kind) {
                .git => {
                    var lock = try fs.LockFile.init(self.core.git_dir, "index");
                    defer lock.deinit();

                    const state = State(.read_write){ .core = &self.core, .extra = .{ .lock_file_maybe = lock.lock_file } };
                    try mnt.removePaths(repo_kind, repo_opts, state, allocator, normalized_paths.items, opts);

                    lock.success = true;
                },
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        allocator: std.mem.Allocator,
                        paths: []const []const u8,
                        opts: mnt.RemoveOptions,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            try mnt.removePaths(repo_kind, repo_opts, state, ctx.allocator, ctx.paths, ctx.opts);
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .allocator = allocator, .paths = normalized_paths.items, .opts = opts },
                    );
                },
            }
        }

        pub fn status(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator) !st.Status(repo_kind, repo_opts) {
            var moment = try self.core.latestMoment();
            const state = State(.read_only){ .core = &self.core, .extra = .{ .moment = &moment } };
            return try st.Status(repo_kind, repo_opts).init(allocator, state);
        }

        pub fn filePair(
            self: *Repo(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
            path: []const u8,
            status_kind: st.StatusKind,
            stat: *st.Status(repo_kind, repo_opts),
        ) !df.LineIteratorPair(repo_kind, repo_opts) {
            var moment = try self.core.latestMoment();
            const state = State(.read_only){ .core = &self.core, .extra = .{ .moment = &moment } };
            return try df.LineIteratorPair(repo_kind, repo_opts).init(allocator, state, path, status_kind, stat);
        }

        pub fn filePairs(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, diff_opts: df.DiffOptions(repo_kind, repo_opts)) !df.FileIterator(repo_kind, repo_opts) {
            var moment = try self.core.latestMoment();
            const state = State(.read_only){ .core = &self.core, .extra = .{ .moment = &moment } };
            return try df.FileIterator(repo_kind, repo_opts).init(allocator, state, diff_opts);
        }

        pub fn treeDiff(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, old_oid_maybe: ?[hash.hexLen(repo_opts.hash)]u8, new_oid_maybe: ?[hash.hexLen(repo_opts.hash)]u8) !obj.TreeDiff(repo_kind, repo_opts) {
            var moment = try self.core.latestMoment();
            const state = State(.read_only){ .core = &self.core, .extra = .{ .moment = &moment } };
            var tree_diff = obj.TreeDiff(repo_kind, repo_opts).init(allocator);
            errdefer tree_diff.deinit();
            try tree_diff.compare(state, old_oid_maybe, new_oid_maybe, null);
            return tree_diff;
        }

        pub fn currentBranch(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator) ![]const u8 {
            var moment = try self.core.latestMoment();
            const state = State(.read_only){ .core = &self.core, .extra = .{ .moment = &moment } };
            return try rf.readHeadNameAlloc(repo_kind, repo_opts, state, allocator);
        }

        pub fn listBranches(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator) !rf.RefList {
            var moment = try self.core.latestMoment();
            const state = State(.read_only){ .core = &self.core, .extra = .{ .moment = &moment } };
            return try rf.RefList.init(repo_kind, repo_opts, state, allocator, .head);
        }

        pub fn addBranch(self: *Repo(repo_kind, repo_opts), input: bch.AddBranchInput) !void {
            switch (repo_kind) {
                .git => try bch.add(repo_kind, repo_opts, .{ .core = &self.core, .extra = .{} }, input),
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        input: bch.AddBranchInput,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            try bch.add(repo_kind, repo_opts, state, ctx.input);
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .input = input },
                    );
                },
            }
        }

        pub fn removeBranch(self: *Repo(repo_kind, repo_opts), input: bch.RemoveBranchInput) !void {
            switch (repo_kind) {
                .git => try bch.remove(repo_kind, repo_opts, .{ .core = &self.core, .extra = .{} }, input),
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        input: bch.RemoveBranchInput,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            try bch.remove(repo_kind, repo_opts, state, ctx.input);
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .input = input },
                    );
                },
            }
        }

        pub fn switchHead(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, input: mnt.SwitchInput(repo_opts.hash)) !mnt.Switch(repo_kind, repo_opts) {
            switch (repo_kind) {
                .git => return try mnt.Switch(repo_kind, repo_opts).init(.{ .core = &self.core, .extra = .{} }, allocator, input),
                .xit => {
                    var result: mnt.Switch(repo_kind, repo_opts) = undefined;

                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        allocator: std.mem.Allocator,
                        input: mnt.SwitchInput(repo_opts.hash),
                        result: *mnt.Switch(repo_kind, repo_opts),

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            ctx.result.* = try mnt.Switch(repo_kind, repo_opts).init(state, ctx.allocator, ctx.input);
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .allocator = allocator, .input = input, .result = &result },
                    );

                    return result;
                },
            }
        }

        pub fn restore(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, path: []const u8) !void {
            var moment = try self.core.latestMoment();
            const state = State(.read_only){ .core = &self.core, .extra = .{ .moment = &moment } };

            const rel_path = try fs.relativePath(allocator, self.core.repo_dir, self.init_opts.cwd, path);
            defer allocator.free(rel_path);
            const path_parts = try fs.splitPath(allocator, rel_path);
            defer allocator.free(path_parts);

            try mnt.restore(repo_kind, repo_opts, state, allocator, path_parts);
        }

        pub fn log(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, start_oids_maybe: ?[]const [hash.hexLen(repo_opts.hash)]u8) !obj.ObjectIterator(repo_kind, repo_opts, .full) {
            var moment = try self.core.latestMoment();
            const state = State(.read_only){ .core = &self.core, .extra = .{ .moment = &moment } };
            var iter = try obj.ObjectIterator(repo_kind, repo_opts, .full).init(allocator, state, .{ .recursive = false });
            errdefer iter.deinit();

            const start_oids = start_oids_maybe orelse if (try rf.readHeadMaybe(repo_kind, repo_opts, state)) |head_oid| &.{head_oid} else &.{};
            for (start_oids) |*start_oid| {
                try iter.include(start_oid);
            }

            return iter;
        }

        pub fn merge(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, input: mrg.MergeInput(repo_kind, repo_opts.hash)) !mrg.Merge(repo_kind, repo_opts) {
            switch (repo_kind) {
                .git => return try mrg.Merge(repo_kind, repo_opts).init(.{ .core = &self.core, .extra = .{} }, allocator, input),
                .xit => {
                    var merge_result: mrg.Merge(repo_kind, repo_opts) = undefined;

                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        allocator: std.mem.Allocator,
                        input: mrg.MergeInput(repo_kind, repo_opts.hash),
                        merge_result: *mrg.Merge(repo_kind, repo_opts),

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            ctx.merge_result.* = try mrg.Merge(repo_kind, repo_opts).init(state, ctx.allocator, ctx.input);
                            // no need to make a new transaction if nothing was done
                            if (.nothing == ctx.merge_result.result) {
                                return error.CancelTransaction;
                            }
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .allocator = allocator, .input = input, .merge_result = &merge_result },
                    ) catch |err| switch (err) {
                        error.CancelTransaction => {},
                        else => |e| return e,
                    };

                    return merge_result;
                },
            }
        }

        pub fn config(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator) !cfg.Config(repo_kind, repo_opts) {
            var moment = try self.core.latestMoment();
            const state = State(.read_only){ .core = &self.core, .extra = .{ .moment = &moment } };
            return try cfg.Config(repo_kind, repo_opts).init(state, allocator);
        }

        pub fn addConfig(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, input: cfg.AddConfigInput) !void {
            var conf = try self.config(allocator);
            defer conf.deinit();
            switch (repo_kind) {
                .git => {
                    var lock = try fs.LockFile.init(self.core.git_dir, "config");
                    defer lock.deinit();

                    try conf.add(.{ .core = &self.core, .extra = .{ .lock_file_maybe = lock.lock_file } }, input);

                    lock.success = true;
                },
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        conf: *cfg.Config(repo_kind, repo_opts),
                        input: cfg.AddConfigInput,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            try ctx.conf.add(state, ctx.input);
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .conf = &conf, .input = input },
                    );
                },
            }
        }

        pub fn removeConfig(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, input: cfg.RemoveConfigInput) !void {
            var conf = try self.config(allocator);
            defer conf.deinit();
            switch (repo_kind) {
                .git => {
                    var lock = try fs.LockFile.init(self.core.git_dir, "config");
                    defer lock.deinit();

                    try conf.remove(.{ .core = &self.core, .extra = .{ .lock_file_maybe = lock.lock_file } }, input);

                    lock.success = true;
                },
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        conf: *cfg.Config(repo_kind, repo_opts),
                        input: cfg.RemoveConfigInput,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            try ctx.conf.remove(state, ctx.input);
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .conf = &conf, .input = input },
                    );
                },
            }
        }

        pub fn remote(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator) !cfg.RemoteConfig {
            var conf = try self.config(allocator);
            defer conf.deinit();
            return try cfg.RemoteConfig.init(repo_kind, repo_opts, &conf, allocator);
        }

        pub fn addRemote(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, input: cfg.AddConfigInput) !void {
            const new_name = try std.fmt.allocPrint(allocator, "remote.{s}.url", .{input.name});
            defer allocator.free(new_name);
            _ = try std.Uri.parse(input.value); // validate url
            const new_input = cfg.AddConfigInput{
                .name = new_name,
                .value = input.value,
            };

            var conf = try self.config(allocator);
            defer conf.deinit();
            switch (repo_kind) {
                .git => {
                    var lock = try fs.LockFile.init(self.core.git_dir, "config");
                    defer lock.deinit();

                    try conf.add(.{ .core = &self.core, .extra = .{ .lock_file_maybe = lock.lock_file } }, new_input);

                    lock.success = true;
                },
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        conf: *cfg.Config(repo_kind, repo_opts),
                        input: cfg.AddConfigInput,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            try ctx.conf.add(state, ctx.input);
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .conf = &conf, .input = new_input },
                    );
                },
            }
        }

        pub fn removeRemote(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, input: cfg.RemoveConfigInput) !void {
            const new_name = try std.fmt.allocPrint(allocator, "remote.{s}.url", .{input.name});
            defer allocator.free(new_name);
            const new_input = cfg.RemoveConfigInput{
                .name = new_name,
            };

            var conf = try self.config(allocator);
            defer conf.deinit();
            switch (repo_kind) {
                .git => {
                    var lock = try fs.LockFile.init(self.core.git_dir, "config");
                    defer lock.deinit();

                    try conf.remove(.{ .core = &self.core, .extra = .{ .lock_file_maybe = lock.lock_file } }, new_input);

                    lock.success = true;
                },
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        conf: *cfg.Config(repo_kind, repo_opts),
                        input: cfg.RemoveConfigInput,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            try ctx.conf.remove(state, ctx.input);
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .conf = &conf, .input = new_input },
                    );
                },
            }
        }

        pub fn fetch(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, remote_name: []const u8) !net.FetchResult {
            var rem = try self.remote(allocator);
            defer rem.deinit();

            const remote_section = rem.sections.get(remote_name) orelse return error.RemoteNotFound;
            const remote_url = remote_section.get("url") orelse return error.RemoteNotFound;
            const parsed_uri = try std.Uri.parse(remote_url);

            switch (repo_kind) {
                .git => {
                    return try net.fetch(repo_kind, repo_opts, .{ .core = &self.core, .extra = .{} }, allocator, remote_name, parsed_uri);
                },
                .xit => {
                    var fetch_result: net.FetchResult = undefined;
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        allocator: std.mem.Allocator,
                        remote_name: []const u8,
                        parsed_uri: std.Uri,
                        fetch_result: *net.FetchResult,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            ctx.fetch_result.* = try net.fetch(repo_kind, repo_opts, state, ctx.allocator, ctx.remote_name, ctx.parsed_uri);
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .allocator = allocator, .remote_name = remote_name, .parsed_uri = parsed_uri, .fetch_result = &fetch_result },
                    );
                    return fetch_result;
                },
            }
        }

        pub const PullResult = struct {
            fetch: net.FetchResult,
            merge: mrg.Merge(repo_kind, repo_opts),

            pub fn deinit(self: *PullResult) void {
                self.merge.deinit();
            }
        };

        pub fn pull(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, remote_name: []const u8, remote_ref_name: []const u8) !PullResult {
            var rem = try self.remote(allocator);
            defer rem.deinit();

            const remote_section = rem.sections.get(remote_name) orelse return error.RemoteNotFound;
            const remote_url = remote_section.get("url") orelse return error.RemoteNotFound;
            const parsed_uri = try std.Uri.parse(remote_url);

            switch (repo_kind) {
                .git => {
                    const fetch_result = try net.fetch(repo_kind, repo_opts, .{ .core = &self.core, .extra = .{} }, allocator, remote_name, parsed_uri);
                    const remote_ref = rf.Ref{ .kind = .{ .remote = remote_name }, .name = remote_ref_name };
                    var merge_result = try mrg.Merge(repo_kind, repo_opts).init(.{ .core = &self.core, .extra = .{} }, allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = remote_ref }} } } });
                    errdefer merge_result.deinit();

                    return .{
                        .fetch = fetch_result,
                        .merge = merge_result,
                    };
                },
                .xit => {
                    var pull_result: PullResult = undefined;
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        allocator: std.mem.Allocator,
                        remote_name: []const u8,
                        remote_ref_name: []const u8,
                        parsed_uri: std.Uri,
                        pull_result: *PullResult,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };

                            const fetch_result = try net.fetch(repo_kind, repo_opts, state, ctx.allocator, ctx.remote_name, ctx.parsed_uri);
                            const remote_ref = rf.Ref{ .kind = .{ .remote = ctx.remote_name }, .name = ctx.remote_ref_name };
                            var merge_result = try mrg.Merge(repo_kind, repo_opts).init(state, ctx.allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = remote_ref }} } } });
                            errdefer merge_result.deinit();

                            ctx.pull_result.* = .{
                                .fetch = fetch_result,
                                .merge = merge_result,
                            };
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .allocator = allocator, .remote_name = remote_name, .remote_ref_name = remote_ref_name, .parsed_uri = parsed_uri, .pull_result = &pull_result },
                    );
                    return pull_result;
                },
            }
        }

        pub fn copyObjects(
            self: *Repo(repo_kind, repo_opts),
            comptime source_repo_kind: RepoKind,
            comptime source_repo_opts: RepoOpts(source_repo_kind),
            obj_iter: *obj.ObjectIterator(source_repo_kind, source_repo_opts, .raw),
        ) !void {
            switch (repo_kind) {
                .git => {
                    while (try obj_iter.next()) |object| {
                        defer object.deinit();
                        var oid = [_]u8{0} ** hash.byteLen(repo_opts.hash);
                        try obj.writeObject(repo_kind, repo_opts, .{ .core = &self.core, .extra = .{} }, &object.object_reader, object.object_reader.reader.reader(), object.object_reader.header, &oid);
                    }
                },
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        obj_iter: *obj.ObjectIterator(source_repo_kind, source_repo_opts, .raw),

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            while (try ctx.obj_iter.next()) |object| {
                                defer object.deinit();
                                var oid = [_]u8{0} ** hash.byteLen(repo_opts.hash);
                                try obj.writeObject(repo_kind, repo_opts, state, &object.object_reader, object.object_reader.reader.reader(), object.object_reader.header, &oid);
                            }
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .obj_iter = obj_iter },
                    );
                },
            }
        }
    };
}

/// auto-detects the hash used by an existing repo
pub fn AnyRepo(comptime repo_kind: RepoKind, comptime repo_opts: RepoOpts(repo_kind)) type {
    return union(hash.HashKind) {
        none,
        sha1: Repo(repo_kind, repo_opts.withHash(.sha1)),
        sha256: Repo(repo_kind, repo_opts.withHash(.sha256)),

        pub fn open(allocator: std.mem.Allocator, init_opts: InitOpts) !AnyRepo(repo_kind, repo_opts) {
            switch (repo_opts.hash) {
                .none => {
                    const hash_kind = blk: {
                        var repo = try Repo(repo_kind, repo_opts).open(allocator, init_opts);
                        defer repo.deinit();
                        break :blk try repo.hashKind();
                    };
                    return switch (hash_kind) {
                        .none => .none,
                        .sha1 => .{ .sha1 = try Repo(repo_kind, repo_opts.withHash(.sha1)).open(allocator, init_opts) },
                        .sha256 => .{ .sha256 = try Repo(repo_kind, repo_opts.withHash(.sha256)).open(allocator, init_opts) },
                    };
                },
                .sha1 => return .{ .sha1 = try Repo(repo_kind, repo_opts).open(allocator, init_opts) },
                .sha256 => return .{ .sha256 = try Repo(repo_kind, repo_opts).open(allocator, init_opts) },
            }
        }

        pub fn deinit(self: *AnyRepo(repo_kind, repo_opts)) void {
            switch (self.*) {
                .none => {},
                inline else => |*case| case.deinit(),
            }
        }
    };
}
