const std = @import("std");
const hash = @import("./hash.zig");
const obj = @import("./object.zig");
const cmd = @import("./command.zig");
const idx = @import("./index.zig");
const bch = @import("./branch.zig");
const work = @import("./workdir.zig");
const rf = @import("./ref.zig");
const fs = @import("./fs.zig");
const df = @import("./diff.zig");
const mrg = @import("./merge.zig");
const cfg = @import("./config.zig");
const chunk = @import("./chunk.zig");
const tg = @import("./tag.zig");
const tr = @import("./tree.zig");
const net = @import("./net.zig");
const net_refspec = @import("./net/refspec.zig");
const un = @import("./undo.zig");

pub const ProgressKind = enum {
    writing_object_from_pack,
    writing_object,
    writing_patch,
    sending_bytes,
};

pub const ProgressEvent = union(enum) {
    start: struct {
        kind: ProgressKind,
        estimated_total_items: usize,
    },
    complete_one: ProgressKind,
    complete_total: struct {
        kind: ProgressKind,
        count: usize,
    },
    end: ProgressKind,
    text: []const u8,
};

pub const RepoKind = enum {
    git,
    xit,
};

pub fn RepoOpts(comptime repo_kind: RepoKind) type {
    return struct {
        hash: hash.HashKind = .sha1,
        read_size: usize = 2048,
        max_read_size: usize = 4096,
        max_line_size: usize = 10_000,
        max_line_count: usize = 10_000_000,
        net_read_size: usize = 65536,
        is_test: bool = false,
        ProgressCtx: type = void,
        extra: Extra = .{},

        pub const Extra = switch (repo_kind) {
            .git => struct {},
            .xit => struct {
                compress_chunks: bool = true,
                chunk_opts: chunk.FastCdcOpts = .{
                    .min_size = 2048,
                    .avg_size = 4096,
                    .max_size = 8192,
                    .normalization = .level1,
                },
                enable_patches: bool = false,
            },
        };

        pub fn withHash(self: RepoOpts(repo_kind), hash_kind: hash.HashKind) RepoOpts(repo_kind) {
            var new_self = self;
            new_self.hash = hash_kind;
            return new_self;
        }

        pub fn withProgressCtx(self: RepoOpts(repo_kind), ProgressCtx: type) RepoOpts(repo_kind) {
            var new_self = self;
            new_self.ProgressCtx = ProgressCtx;
            return new_self;
        }
    };
}

pub const InitOpts = struct {
    cwd: std.fs.Dir,
    create_default_branch: ?[]const u8 = "master",
};

pub fn Repo(comptime repo_kind: RepoKind, comptime repo_opts: RepoOpts(repo_kind)) type {
    return struct {
        comptime self_repo_kind: RepoKind = repo_kind,
        comptime self_repo_opts: RepoOpts(repo_kind) = repo_opts,

        core: Core,

        pub const Core = switch (repo_kind) {
            .git => struct {
                init_opts: InitOpts,
                work_dir: std.fs.Dir,
                repo_dir: std.fs.Dir,

                pub fn latestMoment(_: *@This()) !void {}
            },
            .xit => struct {
                init_opts: InitOpts,
                work_dir: std.fs.Dir,
                repo_dir: std.fs.Dir,
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
            var work_dir = try opts.cwd.makeOpenPath(sub_path, .{});
            errdefer work_dir.close();

            const repo_dir_name = switch (repo_kind) {
                .git => ".git",
                .xit => ".xit",
            };

            // return if dir already exists
            {
                var repo_dir_or_err = work_dir.openDir(repo_dir_name, .{});
                if (repo_dir_or_err) |*repo_dir| {
                    repo_dir.close();
                    return error.RepoAlreadyExists;
                } else |_| {}
            }

            // make the repo dir
            var repo_dir = try work_dir.makeOpenPath(repo_dir_name, .{});
            errdefer repo_dir.close();

            switch (repo_kind) {
                .git => {
                    // make a few dirs inside of .git
                    try repo_dir.makePath("objects");
                    try repo_dir.makePath("objects/pack");
                    try repo_dir.makePath("refs");
                    try repo_dir.makePath("refs/heads");

                    var self = Repo(repo_kind, repo_opts){
                        .core = .{
                            .init_opts = opts,
                            .work_dir = work_dir,
                            .repo_dir = repo_dir,
                        },
                    };

                    if (opts.create_default_branch) |default_branch_name| {
                        try self.addBranch(.{ .name = default_branch_name });
                        try self.resetAdd(.{ .ref = .{ .kind = .head, .name = default_branch_name } });
                    }

                    return self;
                },
                .xit => {
                    // create the db file
                    const db_file = try repo_dir.createFile("db", .{ .exclusive = true, .lock = .exclusive, .read = true });
                    errdefer db_file.close();

                    // make the db
                    var self = Repo(repo_kind, repo_opts){
                        .core = .{
                            .init_opts = opts,
                            .work_dir = work_dir,
                            .repo_dir = repo_dir,
                            .db_file = db_file,
                            .db = try DB.init(allocator, .{ .file = db_file, .hash_id = .{ .id = hash.hashId(repo_opts.hash) } }),
                        },
                    };

                    if (opts.create_default_branch) |default_branch_name| {
                        try self.addBranch(.{ .name = default_branch_name });
                        try self.resetAdd(.{ .ref = .{ .kind = .head, .name = default_branch_name } });
                    }

                    if (repo_opts.extra.enable_patches) {
                        try self.setMergeAlgorithm(allocator, .patch);
                    }

                    return self;
                },
            }
        }

        pub fn open(allocator: std.mem.Allocator, opts: InitOpts) !Repo(repo_kind, repo_opts) {
            const cwd_path = try opts.cwd.realpathAlloc(allocator, ".");
            defer allocator.free(cwd_path);

            const repo_dir_name = switch (repo_kind) {
                .git => ".git",
                .xit => ".xit",
            };

            // search all parent dirs for one containing the repo dir
            var dir_path_maybe: ?[]const u8 = cwd_path;
            while (dir_path_maybe) |dir_path| {
                var work_dir = try std.fs.openDirAbsolute(dir_path, .{});
                defer work_dir.close();

                var repo_dir = work_dir.openDir(repo_dir_name, .{}) catch |err| switch (err) {
                    error.FileNotFound => {
                        dir_path_maybe = std.fs.path.dirname(dir_path);
                        continue;
                    },
                    else => |e| return e,
                };
                defer repo_dir.close();

                break;
            }

            const dir_path = dir_path_maybe orelse return error.RepoNotFound;
            var work_dir = try std.fs.openDirAbsolute(dir_path, .{});
            errdefer work_dir.close();

            var repo_dir = try work_dir.openDir(repo_dir_name, .{});
            errdefer repo_dir.close();

            switch (repo_kind) {
                .git => {
                    return .{
                        .core = .{
                            .init_opts = opts,
                            .work_dir = work_dir,
                            .repo_dir = repo_dir,
                        },
                    };
                },
                .xit => {
                    var db_file = repo_dir.openFile("db", .{ .mode = .read_write, .lock = .exclusive }) catch |err| switch (err) {
                        error.FileNotFound => return error.RepoNotFound,
                        else => |e| return e,
                    };
                    errdefer db_file.close();

                    var self = Repo(repo_kind, repo_opts){
                        .core = .{
                            .init_opts = opts,
                            .work_dir = work_dir,
                            .repo_dir = repo_dir,
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
                    };

                    if (repo_opts.extra.enable_patches) {
                        try self.setMergeAlgorithm(allocator, .patch);
                    }

                    return self;
                },
            }
        }

        pub fn deinit(self: *Repo(repo_kind, repo_opts)) void {
            switch (repo_kind) {
                .git => {
                    self.core.work_dir.close();
                    self.core.repo_dir.close();
                },
                .xit => {
                    self.core.work_dir.close();
                    self.core.repo_dir.close();
                    self.core.db_file.close();
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
                    var result: [hash.hexLen(repo_opts.hash)]u8 = undefined;

                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        allocator: std.mem.Allocator,
                        metadata: obj.CommitMetadata(repo_opts.hash),
                        result: *[hash.hexLen(repo_opts.hash)]u8,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            ctx.result.* = try obj.writeCommit(repo_kind, repo_opts, state, ctx.allocator, ctx.metadata);
                            try un.writeMessage(repo_opts, state, .{ .commit = ctx.metadata });
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

        pub fn addTag(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, input: tg.AddTagInput) ![hash.hexLen(repo_opts.hash)]u8 {
            switch (repo_kind) {
                .git => return try tg.add(repo_kind, repo_opts, .{ .core = &self.core, .extra = .{} }, allocator, input),
                .xit => {
                    var result: [hash.hexLen(repo_opts.hash)]u8 = undefined;

                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        allocator: std.mem.Allocator,
                        input: tg.AddTagInput,
                        result: *[hash.hexLen(repo_opts.hash)]u8,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            ctx.result.* = try tg.add(repo_kind, repo_opts, state, ctx.allocator, ctx.input);
                            try un.writeMessage(repo_opts, state, .{ .tag = .{ .add = ctx.input } });
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

        pub fn removeTag(self: *Repo(repo_kind, repo_opts), input: tg.RemoveTagInput) !void {
            switch (repo_kind) {
                .git => try tg.remove(repo_kind, repo_opts, .{ .core = &self.core, .extra = .{} }, input),
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        input: tg.RemoveTagInput,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            try tg.remove(repo_kind, repo_opts, state, ctx.input);
                            try un.writeMessage(repo_opts, state, .{ .tag = .{ .remove = ctx.input } });
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
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();

            var normalized_paths = std.ArrayList([]const u8).init(arena.allocator());
            for (paths) |path| {
                const rel_path = try fs.relativePath(allocator, self.core.work_dir, self.core.init_opts.cwd, path);
                defer allocator.free(rel_path);
                const path_parts = try fs.splitPath(allocator, rel_path);
                defer allocator.free(path_parts);
                const normalized_path = try fs.joinPath(arena.allocator(), path_parts);
                try normalized_paths.append(normalized_path);
            }

            switch (repo_kind) {
                .git => {
                    var lock = try fs.LockFile.init(self.core.repo_dir, "index");
                    defer lock.deinit();

                    const state = State(.read_write){ .core = &self.core, .extra = .{ .lock_file_maybe = lock.lock_file } };
                    try work.addPaths(repo_kind, repo_opts, state, allocator, normalized_paths.items);

                    lock.success = true;
                },
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        allocator: std.mem.Allocator,
                        paths: []const []const u8,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            try work.addPaths(repo_kind, repo_opts, state, ctx.allocator, ctx.paths);

                            const joined_paths = try std.mem.join(ctx.allocator, " ", ctx.paths);
                            defer ctx.allocator.free(joined_paths);
                            try un.writeMessage(repo_opts, state, .{ .add = .{ .paths = joined_paths } });
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .allocator = allocator, .paths = normalized_paths.items },
                    );
                },
            }
        }

        pub fn unadd(
            self: *Repo(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
            paths: []const []const u8,
            opts: work.UnaddOptions,
        ) !void {
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();

            var normalized_paths = std.ArrayList([]const u8).init(arena.allocator());
            for (paths) |path| {
                const rel_path = try fs.relativePath(allocator, self.core.work_dir, self.core.init_opts.cwd, path);
                defer allocator.free(rel_path);
                const path_parts = try fs.splitPath(allocator, rel_path);
                defer allocator.free(path_parts);
                const normalized_path = try fs.joinPath(arena.allocator(), path_parts);
                try normalized_paths.append(normalized_path);
            }

            switch (repo_kind) {
                .git => {
                    var lock = try fs.LockFile.init(self.core.repo_dir, "index");
                    defer lock.deinit();

                    const state = State(.read_write){ .core = &self.core, .extra = .{ .lock_file_maybe = lock.lock_file } };
                    try work.unaddPaths(repo_kind, repo_opts, state, allocator, normalized_paths.items, opts);

                    lock.success = true;
                },
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        allocator: std.mem.Allocator,
                        paths: []const []const u8,
                        opts: work.UnaddOptions,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            try work.unaddPaths(repo_kind, repo_opts, state, ctx.allocator, ctx.paths, ctx.opts);

                            const joined_paths = try std.mem.join(ctx.allocator, " ", ctx.paths);
                            defer ctx.allocator.free(joined_paths);
                            try un.writeMessage(repo_opts, state, .{ .unadd = .{ .paths = joined_paths } });
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

        pub fn untrack(
            self: *Repo(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
            paths: []const []const u8,
            opts: work.UntrackOptions,
        ) !void {
            try self.remove(allocator, paths, .{
                .force = opts.force,
                .recursive = opts.recursive,
                .update_work_dir = false,
            });
        }

        pub fn remove(
            self: *Repo(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
            paths: []const []const u8,
            opts: work.RemoveOptions,
        ) !void {
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();

            var normalized_paths = std.ArrayList([]const u8).init(arena.allocator());
            for (paths) |path| {
                const rel_path = try fs.relativePath(allocator, self.core.work_dir, self.core.init_opts.cwd, path);
                defer allocator.free(rel_path);
                const path_parts = try fs.splitPath(allocator, rel_path);
                defer allocator.free(path_parts);
                const normalized_path = try fs.joinPath(arena.allocator(), path_parts);
                try normalized_paths.append(normalized_path);
            }

            switch (repo_kind) {
                .git => {
                    var lock = try fs.LockFile.init(self.core.repo_dir, "index");
                    defer lock.deinit();

                    const state = State(.read_write){ .core = &self.core, .extra = .{ .lock_file_maybe = lock.lock_file } };
                    try work.removePaths(repo_kind, repo_opts, state, allocator, normalized_paths.items, opts);

                    lock.success = true;
                },
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        allocator: std.mem.Allocator,
                        paths: []const []const u8,
                        opts: work.RemoveOptions,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            try work.removePaths(repo_kind, repo_opts, state, ctx.allocator, ctx.paths, ctx.opts);

                            const joined_paths = try std.mem.join(ctx.allocator, " ", ctx.paths);
                            defer ctx.allocator.free(joined_paths);
                            if (ctx.opts.update_work_dir) {
                                try un.writeMessage(repo_opts, state, .{ .rm = .{ .paths = joined_paths } });
                            } else {
                                try un.writeMessage(repo_opts, state, .{ .untrack = .{ .paths = joined_paths } });
                            }
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

        pub fn status(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator) !work.Status(repo_kind, repo_opts) {
            var moment = try self.core.latestMoment();
            const state = State(.read_only){ .core = &self.core, .extra = .{ .moment = &moment } };
            return try work.Status(repo_kind, repo_opts).init(allocator, state);
        }

        pub fn filePair(
            self: *Repo(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
            path: []const u8,
            status_kind: work.StatusKind,
            stat: *work.Status(repo_kind, repo_opts),
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

        pub fn treeDiff(
            self: *Repo(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
            old_oid_maybe: ?*const [hash.hexLen(repo_opts.hash)]u8,
            new_oid_maybe: ?*const [hash.hexLen(repo_opts.hash)]u8,
        ) !tr.TreeDiff(repo_kind, repo_opts) {
            var moment = try self.core.latestMoment();
            const state = State(.read_only){ .core = &self.core, .extra = .{ .moment = &moment } };
            var tree_diff = tr.TreeDiff(repo_kind, repo_opts).init(allocator);
            errdefer tree_diff.deinit();
            try tree_diff.compare(state, old_oid_maybe, new_oid_maybe, null);
            return tree_diff;
        }

        pub fn head(self: *Repo(repo_kind, repo_opts), buffer: []u8) !rf.RefOrOid(repo_opts.hash) {
            var moment = try self.core.latestMoment();
            const state = State(.read_only){ .core = &self.core, .extra = .{ .moment = &moment } };
            return try rf.readHead(repo_kind, repo_opts, state, buffer) orelse return error.HeadNotFound;
        }

        pub fn readRef(self: *Repo(repo_kind, repo_opts), ref: rf.Ref) !?[hash.hexLen(repo_opts.hash)]u8 {
            var moment = try self.core.latestMoment();
            const state = State(.read_only){ .core = &self.core, .extra = .{ .moment = &moment } };
            return try rf.readRecur(repo_kind, repo_opts, state, .{ .ref = ref });
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
                            try un.writeMessage(repo_opts, state, .{ .branch = .{ .add = ctx.input } });
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
                            try un.writeMessage(repo_opts, state, .{ .branch = .{ .remove = ctx.input } });
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

        pub fn switchDir(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, input: work.SwitchInput(repo_opts.hash)) !work.Switch(repo_kind, repo_opts) {
            switch (repo_kind) {
                .git => return try work.Switch(repo_kind, repo_opts).init(.{ .core = &self.core, .extra = .{} }, allocator, input),
                .xit => {
                    var result: work.Switch(repo_kind, repo_opts) = undefined;

                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        allocator: std.mem.Allocator,
                        input: work.SwitchInput(repo_opts.hash),
                        result: *work.Switch(repo_kind, repo_opts),

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            ctx.result.* = try work.Switch(repo_kind, repo_opts).init(state, ctx.allocator, ctx.input);
                            try un.writeMessage(repo_opts, state, .{ .switch_dir = ctx.input });
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

        pub fn reset(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, input: work.ResetInput(repo_opts.hash)) !work.Switch(repo_kind, repo_opts) {
            return try self.switchDir(allocator, .{
                .kind = .reset,
                .target = input.target,
                .update_work_dir = false,
                .force = input.force,
            });
        }

        pub fn resetDir(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, input: work.ResetInput(repo_opts.hash)) !work.Switch(repo_kind, repo_opts) {
            return try self.switchDir(allocator, .{
                .kind = .reset,
                .target = input.target,
                .update_work_dir = true,
                .force = input.force,
            });
        }

        pub fn resetAdd(self: *Repo(repo_kind, repo_opts), target: rf.RefOrOid(repo_opts.hash)) !void {
            switch (repo_kind) {
                .git => switch (target) {
                    .ref => try rf.replaceHead(repo_kind, repo_opts, .{ .core = &self.core, .extra = .{} }, target),
                    .oid => |oid| try rf.updateHead(repo_kind, repo_opts, .{ .core = &self.core, .extra = .{} }, oid),
                },
                .xit => {
                    // update HEAD
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        target: rf.RefOrOid(repo_opts.hash),

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            switch (ctx.target) {
                                .ref => try rf.replaceHead(repo_kind, repo_opts, state, ctx.target),
                                .oid => |oid| try rf.updateHead(repo_kind, repo_opts, state, oid),
                            }
                            try un.writeMessage(repo_opts, state, .{ .reset_add = ctx.target });
                        }
                    };
                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .target = target },
                    );
                },
            }
        }

        pub fn restore(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, path: []const u8) !void {
            var moment = try self.core.latestMoment();
            const state = State(.read_only){ .core = &self.core, .extra = .{ .moment = &moment } };
            const rel_path = try fs.relativePath(allocator, self.core.work_dir, self.core.init_opts.cwd, path);
            defer allocator.free(rel_path);
            const path_parts = try fs.splitPath(allocator, rel_path);
            defer allocator.free(path_parts);
            try work.restore(repo_kind, repo_opts, state, allocator, path_parts);
        }

        pub fn log(
            self: *Repo(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
            start_oids_maybe: ?[]const [hash.hexLen(repo_opts.hash)]u8,
        ) !obj.ObjectIterator(repo_kind, repo_opts, .full) {
            var moment = try self.core.latestMoment();
            const state = State(.read_only){ .core = &self.core, .extra = .{ .moment = &moment } };
            var iter = try obj.ObjectIterator(repo_kind, repo_opts, .full).init(allocator, state, .{ .kind = .commit });
            errdefer iter.deinit();

            const start_oids = start_oids_maybe orelse if (try rf.readHeadRecurMaybe(repo_kind, repo_opts, state)) |head_oid| &.{head_oid} else &.{};
            for (start_oids) |*start_oid| {
                try iter.include(start_oid);
            }

            return iter;
        }

        pub fn logRaw(
            self: *Repo(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
            opts: obj.ObjectIteratorOptions,
        ) !obj.ObjectIterator(repo_kind, repo_opts, .raw) {
            var moment = try self.core.latestMoment();
            const state = State(.read_only){ .core = &self.core, .extra = .{ .moment = &moment } };
            return try obj.ObjectIterator(repo_kind, repo_opts, .raw).init(allocator, state, opts);
        }

        pub fn merge(
            self: *Repo(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
            input: mrg.MergeInput(repo_opts.hash),
            progress_ctx_maybe: ?repo_opts.ProgressCtx,
        ) !mrg.Merge(repo_kind, repo_opts) {
            switch (repo_kind) {
                .git => return try mrg.Merge(repo_kind, repo_opts).init(.{ .core = &self.core, .extra = .{} }, allocator, input, progress_ctx_maybe),
                .xit => {
                    var merge_result: mrg.Merge(repo_kind, repo_opts) = undefined;

                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        allocator: std.mem.Allocator,
                        input: mrg.MergeInput(repo_opts.hash),
                        merge_result: *mrg.Merge(repo_kind, repo_opts),
                        progress_ctx_maybe: ?repo_opts.ProgressCtx,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };

                            ctx.merge_result.* = try mrg.Merge(repo_kind, repo_opts).init(state, ctx.allocator, ctx.input, ctx.progress_ctx_maybe);

                            switch (ctx.merge_result.result) {
                                .success => {},
                                // no need to make a new transaction if nothing was done
                                .nothing => return error.CancelTransaction,
                                .fast_forward, .conflict => {},
                            }

                            try un.writeMessage(repo_opts, state, .{ .merge = ctx.input });
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .allocator = allocator, .input = input, .progress_ctx_maybe = progress_ctx_maybe, .merge_result = &merge_result },
                    ) catch |err| switch (err) {
                        error.CancelTransaction => {},
                        else => |e| return e,
                    };

                    return merge_result;
                },
            }
        }

        pub fn listConfig(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator) !cfg.Config(repo_kind, repo_opts) {
            var moment = try self.core.latestMoment();
            const state = State(.read_only){ .core = &self.core, .extra = .{ .moment = &moment } };
            return try cfg.Config(repo_kind, repo_opts).init(state, allocator);
        }

        pub fn addConfig(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, input: cfg.AddConfigInput) !void {
            var config = try self.listConfig(allocator);
            defer config.deinit();

            switch (repo_kind) {
                .git => {
                    var lock = try fs.LockFile.init(self.core.repo_dir, "config");
                    defer lock.deinit();

                    try config.add(.{ .core = &self.core, .extra = .{ .lock_file_maybe = lock.lock_file } }, input);

                    lock.success = true;
                },
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        config: *cfg.Config(repo_kind, repo_opts),
                        input: cfg.AddConfigInput,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            try ctx.config.add(state, ctx.input);
                            try un.writeMessage(repo_opts, state, .{ .config = .{ .add = ctx.input } });
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .config = &config, .input = input },
                    );
                },
            }
        }

        pub fn removeConfig(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, input: cfg.RemoveConfigInput) !void {
            var config = try self.listConfig(allocator);
            defer config.deinit();

            switch (repo_kind) {
                .git => {
                    var lock = try fs.LockFile.init(self.core.repo_dir, "config");
                    defer lock.deinit();

                    try config.remove(.{ .core = &self.core, .extra = .{ .lock_file_maybe = lock.lock_file } }, input);

                    lock.success = true;
                },
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        config: *cfg.Config(repo_kind, repo_opts),
                        input: cfg.RemoveConfigInput,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            try ctx.config.remove(state, ctx.input);
                            try un.writeMessage(repo_opts, state, .{ .config = .{ .remove = ctx.input } });
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .config = &config, .input = input },
                    );
                },
            }
        }

        pub fn setMergeAlgorithm(
            self: *Repo(.xit, repo_opts),
            allocator: std.mem.Allocator,
            merge_algo: mrg.MergeAlgorithm,
        ) !void {
            const Ctx = struct {
                core: *Repo(repo_kind, repo_opts).Core,
                allocator: std.mem.Allocator,
                merge_algo: mrg.MergeAlgorithm,

                pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                    var moment = try DB.HashMap(.read_write).init(cursor.*);
                    const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };

                    var config = try cfg.Config(.xit, repo_opts).init(state.readOnly(), ctx.allocator);
                    defer config.deinit();

                    const merge_algo_str = switch (ctx.merge_algo) {
                        .diff3 => "diff3",
                        .patch => "patch",
                    };

                    if (config.sections.get("merge")) |merge_section| {
                        if (merge_section.get("algorithm")) |algo| {
                            if (std.mem.eql(u8, merge_algo_str, algo)) {
                                return error.CancelTransaction;
                            }
                        }
                    }

                    try config.add(state, .{ .name = "merge.algorithm", .value = merge_algo_str });

                    switch (ctx.merge_algo) {
                        .diff3 => try un.writeMessage(repo_opts, state, .{ .patch = .off }),
                        .patch => try un.writeMessage(repo_opts, state, .{ .patch = .on }),
                    }
                }
            };

            const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
            history.appendContext(
                .{ .slot = try history.getSlot(-1) },
                Ctx{ .core = &self.core, .allocator = allocator, .merge_algo = merge_algo },
            ) catch |err| switch (err) {
                error.CancelTransaction => {},
                else => |e| return e,
            };
        }

        pub fn patchAll(
            self: *Repo(.xit, repo_opts),
            allocator: std.mem.Allocator,
            progress_ctx_maybe: ?repo_opts.ProgressCtx,
        ) !void {
            const Ctx = struct {
                core: *Repo(repo_kind, repo_opts).Core,
                allocator: std.mem.Allocator,
                progress_ctx_maybe: ?repo_opts.ProgressCtx,

                pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                    var moment = try DB.HashMap(.read_write).init(cursor.*);
                    const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };

                    {
                        var config = try cfg.Config(.xit, repo_opts).init(state.readOnly(), ctx.allocator);
                        defer config.deinit();
                        try config.add(state, .{ .name = "merge.algorithm", .value = "patch" });
                    }

                    var obj_iter = try obj.ObjectIterator(repo_kind, repo_opts, .full).init(ctx.allocator, state.readOnly(), .{ .kind = .commit });
                    defer obj_iter.deinit();

                    // add heads
                    {
                        var ref_list = try rf.RefList.init(repo_kind, repo_opts, state.readOnly(), ctx.allocator, .head);
                        defer ref_list.deinit();

                        for (ref_list.refs.values()) |ref| {
                            if (try rf.readRecur(repo_kind, repo_opts, state.readOnly(), .{ .ref = ref })) |oid| {
                                try obj_iter.include(&oid);
                            }
                        }
                    }

                    // add tags
                    {
                        var ref_list = try rf.RefList.init(repo_kind, repo_opts, state.readOnly(), ctx.allocator, .tag);
                        defer ref_list.deinit();

                        for (ref_list.refs.values()) |ref| {
                            if (try rf.readRecur(repo_kind, repo_opts, state.readOnly(), .{ .ref = ref })) |oid| {
                                try obj_iter.include(&oid);
                            }
                        }
                    }

                    const patch = @import("./patch.zig");

                    var patch_writer = try patch.PatchWriter(repo_opts).init(state.readOnly(), ctx.allocator);
                    defer patch_writer.deinit(ctx.allocator);

                    while (try obj_iter.next()) |commit_object| {
                        defer commit_object.deinit();
                        const oid = try hash.hexToBytes(repo_opts.hash, commit_object.oid);
                        try patch_writer.add(state.readOnly(), ctx.allocator, &oid);
                    }

                    try patch_writer.write(state, ctx.allocator, ctx.progress_ctx_maybe);

                    try un.writeMessage(repo_opts, state, .{ .patch = .all });
                }
            };

            const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
            try history.appendContext(
                .{ .slot = try history.getSlot(-1) },
                Ctx{ .core = &self.core, .allocator = allocator, .progress_ctx_maybe = progress_ctx_maybe },
            );
        }

        pub fn listRemotes(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator) !cfg.RemoteConfig {
            var config = try self.listConfig(allocator);
            defer config.deinit();
            return try cfg.RemoteConfig.init(repo_kind, repo_opts, &config, allocator);
        }

        pub fn addRemote(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, input: cfg.AddConfigInput) !void {
            if (!net.validateUrl(self.core.init_opts.cwd, input.value)) {
                return error.InvalidRemoteUrl;
            }

            switch (repo_kind) {
                .git => {
                    var lock = try fs.LockFile.init(self.core.repo_dir, "config");
                    defer lock.deinit();

                    try net.Remote(repo_kind, repo_opts).addConfig(
                        .{ .core = &self.core, .extra = .{ .lock_file_maybe = lock.lock_file } },
                        allocator,
                        input.name,
                        input.value,
                    );

                    lock.success = true;
                },
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        allocator: std.mem.Allocator,
                        input: cfg.AddConfigInput,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            try net.Remote(repo_kind, repo_opts).addConfig(state, ctx.allocator, ctx.input.name, ctx.input.value);
                            try un.writeMessage(repo_opts, state, .{ .remote = .{ .add = ctx.input } });
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .allocator = allocator, .input = input },
                    );
                },
            }
        }

        pub fn removeRemote(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, input: cfg.RemoveConfigInput) !void {
            switch (repo_kind) {
                .git => {
                    var lock = try fs.LockFile.init(self.core.repo_dir, "config");
                    defer lock.deinit();

                    try net.Remote(repo_kind, repo_opts).removeConfig(
                        .{ .core = &self.core, .extra = .{ .lock_file_maybe = lock.lock_file } },
                        allocator,
                        input.name,
                    );

                    lock.success = true;
                },
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        allocator: std.mem.Allocator,
                        input: cfg.RemoveConfigInput,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            try net.Remote(repo_kind, repo_opts).removeConfig(state, ctx.allocator, ctx.input.name);
                            try un.writeMessage(repo_opts, state, .{ .remote = .{ .remove = ctx.input } });
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .allocator = allocator, .input = input },
                    );
                },
            }
        }

        pub fn copyObjects(
            self: *Repo(repo_kind, repo_opts),
            comptime source_repo_kind: RepoKind,
            comptime source_repo_opts: RepoOpts(source_repo_kind),
            obj_iter: *obj.ObjectIterator(source_repo_kind, source_repo_opts, .raw),
            progress_ctx_maybe: ?repo_opts.ProgressCtx,
        ) !void {
            switch (repo_kind) {
                .git => {
                    try obj.copyFromObjectIterator(
                        repo_kind,
                        repo_opts,
                        .{ .core = &self.core, .extra = .{} },
                        source_repo_kind,
                        source_repo_opts,
                        obj_iter,
                        progress_ctx_maybe,
                    );
                },
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        obj_iter: *obj.ObjectIterator(source_repo_kind, source_repo_opts, .raw),
                        progress_ctx_maybe: ?repo_opts.ProgressCtx,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            try obj.copyFromObjectIterator(
                                repo_kind,
                                repo_opts,
                                state,
                                source_repo_kind,
                                source_repo_opts,
                                ctx.obj_iter,
                                ctx.progress_ctx_maybe,
                            );
                            try un.writeMessage(repo_opts, state, .copy_objects);
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .obj_iter = obj_iter, .progress_ctx_maybe = progress_ctx_maybe },
                    );
                },
            }
        }

        pub fn clone(
            allocator: std.mem.Allocator,
            url: []const u8,
            cwd: std.fs.Dir,
            local_path: []const u8,
            opts: net.Opts(repo_opts.ProgressCtx),
        ) !Repo(repo_kind, repo_opts) {
            if (repo_opts.hash == .none) return error.UnsupportedHashKind;
            return net.clone(repo_kind, repo_opts, allocator, url, cwd, local_path, opts);
        }

        pub fn fetch(
            self: *Repo(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
            remote_name: []const u8,
            opts: net.Opts(repo_opts.ProgressCtx),
        ) !void {
            switch (repo_kind) {
                .git => {
                    const state = State(.read_write){ .core = &self.core, .extra = .{} };
                    var remote = try net.Remote(repo_kind, repo_opts).open(state.readOnly(), allocator, remote_name);
                    defer remote.deinit(allocator);
                    try net.fetch(repo_kind, repo_opts, state, allocator, &remote, opts);
                },
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        allocator: std.mem.Allocator,
                        remote_name: []const u8,
                        opts: net.Opts(repo_opts.ProgressCtx),

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            var remote = try net.Remote(repo_kind, repo_opts).open(state.readOnly(), ctx.allocator, ctx.remote_name);
                            defer remote.deinit(ctx.allocator);
                            try net.fetch(repo_kind, repo_opts, state, ctx.allocator, &remote, ctx.opts);
                            try un.writeMessage(repo_opts, state, .{ .fetch = .{ .remote_name = ctx.remote_name } });
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .allocator = allocator, .remote_name = remote_name, .opts = opts },
                    );
                },
            }
        }

        pub fn push(
            self: *Repo(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
            remote_name: []const u8,
            refspec_str: []const u8,
            force: bool,
            opts: net.Opts(repo_opts.ProgressCtx),
        ) !void {
            var refspecs = std.ArrayList([]const u8).init(allocator);
            defer refspecs.deinit();
            if (opts.refspecs) |opts_refspecs| {
                try refspecs.appendSlice(opts_refspecs);
            }

            var refspec = try net_refspec.RefSpec.init(allocator, refspec_str, .push);
            defer refspec.deinit(allocator);

            if (force) {
                refspec.is_force = true;
            }

            const refspec_normalized = try refspec.normalize(allocator);
            defer allocator.free(refspec_normalized);

            try refspecs.append(refspec_normalized);

            var new_opts = opts;
            new_opts.refspecs = refspecs.items;

            switch (repo_kind) {
                .git => {
                    const state = State(.read_write){ .core = &self.core, .extra = .{} };
                    var remote = try net.Remote(repo_kind, repo_opts).open(state.readOnly(), allocator, remote_name);
                    defer remote.deinit(allocator);
                    try net.push(repo_kind, repo_opts, state, allocator, &remote, new_opts);
                },
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        allocator: std.mem.Allocator,
                        remote_name: []const u8,
                        opts: net.Opts(repo_opts.ProgressCtx),

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            var remote = try net.Remote(repo_kind, repo_opts).open(state.readOnly(), ctx.allocator, ctx.remote_name);
                            defer remote.deinit(ctx.allocator);
                            try net.push(repo_kind, repo_opts, state, ctx.allocator, &remote, ctx.opts);

                            const joined_refspecs = try std.mem.join(ctx.allocator, " ", ctx.opts.refspecs orelse return error.RefspecsNotFound);
                            defer ctx.allocator.free(joined_refspecs);
                            try un.writeMessage(repo_opts, state, .{ .push = .{ .remote_name = ctx.remote_name, .refspecs = joined_refspecs } });
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .allocator = allocator, .remote_name = remote_name, .opts = new_opts },
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
