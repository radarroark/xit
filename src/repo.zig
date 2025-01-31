const std = @import("std");
const hash = @import("./hash.zig");
const obj = @import("./object.zig");
const cmd = @import("./command.zig");
const idx = @import("./index.zig");
const st = @import("./status.zig");
const bch = @import("./branch.zig");
const res = @import("./restore.zig");
const rf = @import("./ref.zig");
const fs = @import("./fs.zig");
const df = @import("./diff.zig");
const mrg = @import("./merge.zig");
const cfg = @import("./config.zig");
const net = @import("./net.zig");
const chunk = @import("./chunk.zig");

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

pub const Writers = struct {
    out: std.io.AnyWriter = std.io.null_writer.any(),
    err: std.io.AnyWriter = std.io.null_writer.any(),
};

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
                    try rf.replaceHead(repo_kind, repo_opts, state, .{ .ref = .{ .kind = .local, .name = "master" } });

                    // add default user config
                    try self.addConfig(allocator, .{ .name = "user.name", .value = "fixme" });
                    try self.addConfig(allocator, .{ .name = "user.email", .value = "fix@me" });

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
                            try rf.replaceHead(repo_kind, repo_opts, state, .{ .ref = .{ .kind = .local, .name = "master" } });
                        }
                    };
                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core },
                    );

                    // add default user config
                    try self.addConfig(allocator, .{ .name = "user.name", .value = "fixme" });
                    try self.addConfig(allocator, .{ .name = "user.email", .value = "fix@me" });

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

        pub fn runCommand(
            self: *Repo(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
            command: cmd.Command(repo_kind, repo_opts.hash),
            writers: Writers,
        ) !void {
            switch (command) {
                .init => {},
                .add => |add_cmd| {
                    try self.add(allocator, add_cmd.paths);
                },
                .unadd => |unadd_cmd| {
                    try self.unadd(allocator, unadd_cmd.paths, unadd_cmd.opts);
                },
                .rm => |rm_cmd| {
                    try self.rm(allocator, rm_cmd.paths, rm_cmd.opts);
                },
                .reset => |reset_cmd| {
                    try self.reset(allocator, reset_cmd.path);
                },
                .commit => |commit_cmd| {
                    _ = try self.commit(allocator, commit_cmd);
                },
                .status => {
                    var stat = try self.status(allocator);
                    defer stat.deinit();

                    for (stat.untracked.values()) |entry| {
                        try writers.out.print("?? {s}\n", .{entry.path});
                    }

                    for (stat.workspace_modified.values()) |entry| {
                        try writers.out.print(" M {s}\n", .{entry.path});
                    }

                    for (stat.workspace_deleted.keys()) |path| {
                        try writers.out.print(" D {s}\n", .{path});
                    }

                    for (stat.index_added.keys()) |path| {
                        try writers.out.print("A  {s}\n", .{path});
                    }

                    for (stat.index_modified.keys()) |path| {
                        try writers.out.print("M  {s}\n", .{path});
                    }

                    for (stat.index_deleted.keys()) |path| {
                        try writers.out.print("D  {s}\n", .{path});
                    }

                    for (stat.conflicts.keys(), stat.conflicts.values()) |path, conflict| {
                        if (conflict.base) {
                            if (conflict.target) {
                                if (conflict.source) {
                                    try writers.out.print("UU {s}\n", .{path}); // both modified
                                } else {
                                    try writers.out.print("UD {s}\n", .{path}); // deleted by them
                                }
                            } else {
                                if (conflict.source) {
                                    try writers.out.print("DU {s}\n", .{path}); // deleted by us
                                } else {
                                    return error.NoCurrentOrSource;
                                }
                            }
                        } else {
                            if (conflict.target) {
                                if (conflict.source) {
                                    try writers.out.print("AA {s}\n", .{path}); // both added
                                } else {
                                    try writers.out.print("AU {s}\n", .{path}); // added by us
                                }
                            } else {
                                if (conflict.source) {
                                    try writers.out.print("UA {s}\n", .{path}); // added by them
                                } else {
                                    return error.NoCurrentOrSource;
                                }
                            }
                        }
                    }
                },
                .diff => |diff_cmd| {
                    const DiffState = union(df.DiffKind) {
                        workspace: st.Status(repo_kind, repo_opts),
                        index: st.Status(repo_kind, repo_opts),
                        tree: obj.TreeDiff(repo_kind, repo_opts),

                        fn deinit(diff_state: *@This()) void {
                            switch (diff_state.*) {
                                .workspace => diff_state.workspace.deinit(),
                                .index => diff_state.index.deinit(),
                                .tree => diff_state.tree.deinit(),
                            }
                        }
                    };
                    const diff_opts = diff_cmd.diff_opts;
                    var diff_state: DiffState = switch (diff_opts) {
                        .workspace => .{ .workspace = try self.status(allocator) },
                        .index => .{ .index = try self.status(allocator) },
                        .tree => |tree| .{ .tree = try self.treeDiff(allocator, tree.old, tree.new) },
                    };
                    defer diff_state.deinit();
                    var diff_iter = try self.filePairs(allocator, switch (diff_opts) {
                        .workspace => |workspace| .{
                            .workspace = .{
                                .conflict_diff_kind = workspace.conflict_diff_kind,
                                .status = &diff_state.workspace,
                            },
                        },
                        .index => .{
                            .index = .{ .status = &diff_state.index },
                        },
                        .tree => .{
                            .tree = .{ .tree_diff = &diff_state.tree },
                        },
                    });

                    while (try diff_iter.next()) |*line_iter_pair_ptr| {
                        var line_iter_pair = line_iter_pair_ptr.*;
                        defer line_iter_pair.deinit();
                        var hunk_iter = try df.HunkIterator(repo_kind, repo_opts).init(allocator, &line_iter_pair.a, &line_iter_pair.b);
                        defer hunk_iter.deinit();
                        for (hunk_iter.header_lines.items) |header_line| {
                            try writers.out.print("{s}\n", .{header_line});
                        }
                        while (try hunk_iter.next()) |*hunk_ptr| {
                            var hunk = hunk_ptr.*;
                            defer hunk.deinit();
                            const offsets = hunk.offsets();
                            try writers.out.print("@@ -{},{} +{},{} @@\n", .{
                                offsets.del_start,
                                offsets.del_count,
                                offsets.ins_start,
                                offsets.ins_count,
                            });
                            for (hunk.edits.items) |edit| {
                                try writers.out.print("{s} {s}\n", .{
                                    switch (edit) {
                                        .eql => " ",
                                        .ins => "+",
                                        .del => "-",
                                    },
                                    switch (edit) {
                                        .eql => |eql| eql.new_line.text,
                                        .ins => |ins| ins.new_line.text,
                                        .del => |del| del.old_line.text,
                                    },
                                });
                            }
                        }
                    }
                },
                .branch => |branch_cmd| {
                    switch (branch_cmd) {
                        .list => {
                            const current_branch = try self.currentBranch(allocator);
                            defer allocator.free(current_branch);

                            var ref_list = try self.listBranches(allocator);
                            defer ref_list.deinit();

                            for (ref_list.refs.values()) |ref| {
                                const prefix = if (std.mem.eql(u8, current_branch, ref.name)) "*" else " ";
                                try writers.out.print("{s} {s}\n", .{ prefix, ref.name });
                            }
                        },
                        .add => try self.addBranch(branch_cmd.add),
                        .remove => try self.removeBranch(branch_cmd.remove),
                    }
                },
                .switch_head => |switch_head_cmd| {
                    var result = try self.switchHead(allocator, switch_head_cmd);
                    defer result.deinit();
                },
                .restore => |restore_cmd| {
                    try self.restore(allocator, restore_cmd.path);
                },
                .log => {
                    var commit_iter = try self.log(allocator, null);
                    defer commit_iter.deinit();
                    while (try commit_iter.next()) |commit_object| {
                        defer commit_object.deinit();
                        try writers.out.print("commit {s}\n", .{commit_object.oid});
                        if (commit_object.content.commit.metadata.author) |author| {
                            try writers.out.print("Author {s}\n", .{author});
                        }
                        try writers.out.print("\n", .{});
                        var split_iter = std.mem.split(u8, commit_object.content.commit.metadata.message, "\n");
                        while (split_iter.next()) |line| {
                            try writers.out.print("    {s}\n", .{line});
                        }
                        try writers.out.print("\n", .{});
                    }
                },
                .merge => |merge_cmd| {
                    var result = try self.merge(allocator, merge_cmd);
                    defer result.deinit();
                    try printMergeResult(&result, writers);
                },
                .config => |config_cmd| {
                    switch (config_cmd) {
                        .list => {
                            var conf = try self.config(allocator);
                            defer conf.deinit();

                            for (conf.sections.keys(), conf.sections.values()) |section_name, variables| {
                                for (variables.keys(), variables.values()) |name, value| {
                                    try writers.out.print("{s}.{s}={s}\n", .{ section_name, name, value });
                                }
                            }
                        },
                        .add => |config_add_cmd| try self.addConfig(allocator, config_add_cmd),
                        .remove => |config_remove_cmd| try self.removeConfig(allocator, config_remove_cmd),
                    }
                },
                .remote => |remote_cmd| {
                    switch (remote_cmd) {
                        .list => {
                            var rem = try self.remote(allocator);
                            defer rem.deinit();

                            for (rem.sections.keys(), rem.sections.values()) |section_name, variables| {
                                for (variables.keys(), variables.values()) |name, value| {
                                    try writers.out.print("{s}.{s}={s}\n", .{ section_name, name, value });
                                }
                            }
                        },
                        .add => |remote_add_cmd| try self.addRemote(allocator, remote_add_cmd),
                        .remove => |remote_remove_cmd| try self.removeRemote(allocator, remote_remove_cmd),
                    }
                },
                .fetch => |fetch_cmd| {
                    _ = try self.fetch(allocator, fetch_cmd.remote_name);
                },
                .pull => |pull_cmd| {
                    var result = try self.pull(allocator, pull_cmd.remote_name, pull_cmd.remote_ref_name);
                    defer result.deinit();
                    try printMergeResult(&result.merge, writers);
                },
            }
        }

        fn printMergeResult(merge_result: *const mrg.Merge(repo_kind, repo_opts), writers: anytype) !void {
            for (merge_result.auto_resolved_conflicts.keys()) |path| {
                if (merge_result.changes.contains(path)) {
                    try writers.out.print("Auto-merging {s}\n", .{path});
                }
            }
            switch (merge_result.result) {
                .success => {},
                .nothing => {
                    try writers.out.print("Already up to date.\n", .{});
                },
                .fast_forward => {
                    try writers.out.print("Fast-forward\n", .{});
                },
                .conflict => |result_conflict| {
                    for (result_conflict.conflicts.keys(), result_conflict.conflicts.values()) |path, conflict| {
                        if (conflict.renamed) |renamed| {
                            const conflict_type = if (conflict.target != null)
                                "file/directory"
                            else
                                "directory/file";
                            const dir_branch_name = if (conflict.target != null)
                                merge_result.source_name
                            else
                                merge_result.target_name;
                            try writers.err.print("CONFLICT ({s}): There is a directory with name {s} in {s}. Adding {s} as {s}\n", .{ conflict_type, path, dir_branch_name, path, renamed.path });
                        } else {
                            if (merge_result.changes.contains(path)) {
                                try writers.out.print("Auto-merging {s}\n", .{path});
                            }
                            if (conflict.target != null and conflict.source != null) {
                                const conflict_type = if (conflict.base != null)
                                    "content"
                                else
                                    "add/add";
                                try writers.err.print("CONFLICT ({s}): Merge conflict in {s}\n", .{ conflict_type, path });
                            } else {
                                const conflict_type = if (conflict.target != null)
                                    "modify/delete"
                                else
                                    "delete/modify";
                                const deleted_branch_name, const modified_branch_name = if (conflict.target != null)
                                    .{ merge_result.source_name, merge_result.target_name }
                                else
                                    .{ merge_result.target_name, merge_result.source_name };
                                try writers.err.print("CONFLICT ({s}): {s} deleted in {s} and modified in {s}\n", .{ conflict_type, path, deleted_branch_name, modified_branch_name });
                            }
                        }
                    }
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

        pub fn add(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, paths: []const []const u8) !void {
            switch (repo_kind) {
                .git => {
                    var lock = try fs.LockFile.init(self.core.git_dir, "index");
                    defer lock.deinit();

                    var index = try idx.Index(repo_kind, repo_opts).init(allocator, .{ .core = &self.core, .extra = .{} });
                    defer index.deinit();

                    for (paths) |path| {
                        try index.addOrRemovePath(.{ .core = &self.core, .extra = .{} }, self.init_opts.cwd, path, .add);
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
                                try index.addOrRemovePath(state, ctx.cwd, path, .add);
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

        pub fn unadd(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, paths: []const []const u8, opts: idx.IndexUnaddOptions) !void {
            try self.rm(allocator, paths, .{
                .force = opts.force,
                .remove_from_workspace = false,
            });
        }

        pub fn rm(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, paths: []const []const u8, opts: idx.IndexRemoveOptions) !void {
            // TODO: add support for -r (removing dirs)
            switch (repo_kind) {
                .git => {
                    var lock = try fs.LockFile.init(self.core.git_dir, "index");
                    defer lock.deinit();

                    var index = try idx.Index(repo_kind, repo_opts).init(allocator, .{ .core = &self.core, .extra = .{} });
                    defer index.deinit();

                    var head_tree = try st.HeadTree(repo_kind, repo_opts).init(allocator, .{ .core = &self.core, .extra = .{} });
                    defer head_tree.deinit();

                    for (paths) |path| {
                        const meta = try fs.getMetadata(self.core.repo_dir, path);
                        switch (meta.kind()) {
                            .file => {
                                if (!opts.force) {
                                    const differs_from = try idx.indexDiffersFrom(repo_kind, repo_opts, &self.core, index, head_tree, path, meta);
                                    if (differs_from.head and differs_from.workspace) {
                                        return error.CannotRemoveFileWithStagedAndUnstagedChanges;
                                    } else if (differs_from.head and opts.remove_from_workspace) {
                                        return error.CannotRemoveFileWithStagedChanges;
                                    } else if (differs_from.workspace and opts.remove_from_workspace) {
                                        return error.CannotRemoveFileWithUnstagedChanges;
                                    }
                                }
                                try index.addOrRemovePath(.{ .core = &self.core, .extra = .{} }, self.init_opts.cwd, path, .rm);
                            },
                            else => return error.UnexpectedPathType,
                        }
                    }

                    if (opts.remove_from_workspace) {
                        for (paths) |path| {
                            const meta = try fs.getMetadata(self.core.repo_dir, path);
                            switch (meta.kind()) {
                                .file => try self.core.repo_dir.deleteFile(path),
                                else => return error.UnexpectedPathType,
                            }
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
                        opts: idx.IndexRemoveOptions,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };

                            var index = try idx.Index(repo_kind, repo_opts).init(ctx.allocator, state.readOnly());
                            defer index.deinit();

                            var head_tree = try st.HeadTree(repo_kind, repo_opts).init(ctx.allocator, state.readOnly());
                            defer head_tree.deinit();

                            for (ctx.paths) |path| {
                                const meta = try fs.getMetadata(ctx.core.repo_dir, path);
                                switch (meta.kind()) {
                                    .file => {
                                        if (!ctx.opts.force) {
                                            const differs_from = try idx.indexDiffersFrom(repo_kind, repo_opts, ctx.core, index, head_tree, path, meta);
                                            if (differs_from.head and differs_from.workspace) {
                                                return error.CannotRemoveFileWithStagedAndUnstagedChanges;
                                            } else if (differs_from.head and ctx.opts.remove_from_workspace) {
                                                return error.CannotRemoveFileWithStagedChanges;
                                            } else if (differs_from.workspace and ctx.opts.remove_from_workspace) {
                                                return error.CannotRemoveFileWithUnstagedChanges;
                                            }
                                        }
                                        try index.addOrRemovePath(state, ctx.cwd, path, .rm);
                                    },
                                    else => return error.UnexpectedPathType,
                                }
                            }

                            if (ctx.opts.remove_from_workspace) {
                                for (ctx.paths) |path| {
                                    const meta = try fs.getMetadata(ctx.core.repo_dir, path);
                                    switch (meta.kind()) {
                                        .file => try ctx.core.repo_dir.deleteFile(path),
                                        .directory => return error.CannotDeleteDir,
                                        else => return error.UnexpectedPathType,
                                    }
                                }
                            }

                            try index.write(ctx.allocator, .{ .core = ctx.core, .extra = .{ .moment = &moment } });
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .allocator = allocator, .cwd = self.init_opts.cwd, .paths = paths, .opts = opts },
                    );
                },
            }
        }

        pub fn reset(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, path: []const u8) !void {
            var stat = try self.status(allocator);
            defer stat.deinit();

            if (stat.index_added.contains(path) or stat.index_modified.contains(path)) {
                try self.unadd(allocator, &.{path}, .{});
            } else if (stat.index_deleted.contains(path)) {
                try self.add(allocator, &.{path});
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
            switch (status_kind) {
                .added => |added| {
                    switch (added) {
                        .created => {
                            var a = try df.LineIterator(repo_kind, repo_opts).initFromNothing(allocator, path);
                            errdefer a.deinit();
                            const index_entries_for_path = stat.index.entries.get(path) orelse return error.EntryNotFound;
                            var b = try df.LineIterator(repo_kind, repo_opts).initFromIndex(state, allocator, index_entries_for_path[0] orelse return error.NullEntry);
                            errdefer b.deinit();
                            return .{ .path = path, .a = a, .b = b };
                        },
                        .modified => {
                            var a = try df.LineIterator(repo_kind, repo_opts).initFromHead(state, allocator, path, stat.head_tree.entries.get(path) orelse return error.EntryNotFound);
                            errdefer a.deinit();
                            const index_entries_for_path = stat.index.entries.get(path) orelse return error.EntryNotFound;
                            var b = try df.LineIterator(repo_kind, repo_opts).initFromIndex(state, allocator, index_entries_for_path[0] orelse return error.NullEntry);
                            errdefer b.deinit();
                            return .{ .path = path, .a = a, .b = b };
                        },
                        .deleted => {
                            var a = try df.LineIterator(repo_kind, repo_opts).initFromHead(state, allocator, path, stat.head_tree.entries.get(path) orelse return error.EntryNotFound);
                            errdefer a.deinit();
                            var b = try df.LineIterator(repo_kind, repo_opts).initFromNothing(allocator, path);
                            errdefer b.deinit();
                            return .{ .path = path, .a = a, .b = b };
                        },
                    }
                },
                .not_added => |not_added| {
                    switch (not_added) {
                        .modified => {
                            const meta = try fs.getMetadata(self.core.repo_dir, path);
                            const mode = fs.getMode(meta);

                            const index_entries_for_path = stat.index.entries.get(path) orelse return error.EntryNotFound;
                            var a = try df.LineIterator(repo_kind, repo_opts).initFromIndex(state, allocator, index_entries_for_path[0] orelse return error.NullEntry);
                            errdefer a.deinit();
                            var b = try df.LineIterator(repo_kind, repo_opts).initFromWorkspace(state, allocator, path, mode);
                            errdefer b.deinit();
                            return .{ .path = path, .a = a, .b = b };
                        },
                        .deleted => {
                            const index_entries_for_path = stat.index.entries.get(path) orelse return error.EntryNotFound;
                            var a = try df.LineIterator(repo_kind, repo_opts).initFromIndex(state, allocator, index_entries_for_path[0] orelse return error.NullEntry);
                            errdefer a.deinit();
                            var b = try df.LineIterator(repo_kind, repo_opts).initFromNothing(allocator, path);
                            errdefer b.deinit();
                            return .{ .path = path, .a = a, .b = b };
                        },
                    }
                },
                .not_tracked => {
                    const meta = try fs.getMetadata(self.core.repo_dir, path);
                    const mode = fs.getMode(meta);

                    var a = try df.LineIterator(repo_kind, repo_opts).initFromNothing(allocator, path);
                    errdefer a.deinit();
                    var b = try df.LineIterator(repo_kind, repo_opts).initFromWorkspace(state, allocator, path, mode);
                    errdefer b.deinit();
                    return .{ .path = path, .a = a, .b = b };
                },
            }
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
            return try rf.RefList.init(repo_kind, repo_opts, state, allocator);
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

        pub fn switchHead(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, input: res.SwitchInput(repo_opts.hash)) !res.Switch(repo_kind, repo_opts) {
            switch (repo_kind) {
                .git => return try res.Switch(repo_kind, repo_opts).init(.{ .core = &self.core, .extra = .{} }, allocator, input),
                .xit => {
                    var result: res.Switch(repo_kind, repo_opts) = undefined;

                    const Ctx = struct {
                        core: *Repo(repo_kind, repo_opts).Core,
                        allocator: std.mem.Allocator,
                        input: res.SwitchInput(repo_opts.hash),
                        result: *res.Switch(repo_kind, repo_opts),

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            ctx.result.* = try res.Switch(repo_kind, repo_opts).init(state, ctx.allocator, ctx.input);
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
            try res.restore(repo_kind, repo_opts, state, allocator, path);
        }

        pub fn log(self: *Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, start_oids_maybe: ?[]const [hash.hexLen(repo_opts.hash)]u8) !obj.ObjectIterator(repo_kind, repo_opts, .full) {
            const options = .{ .recursive = false };
            var moment = try self.core.latestMoment();
            const state = State(.read_only){ .core = &self.core, .extra = .{ .moment = &moment } };
            if (start_oids_maybe) |start_oids| {
                return try obj.ObjectIterator(repo_kind, repo_opts, .full).init(allocator, state, start_oids, options);
            } else {
                const start_oids = if (try rf.readHeadMaybe(repo_kind, repo_opts, state)) |head_oid| &.{head_oid} else &.{};
                return try obj.ObjectIterator(repo_kind, repo_opts, .full).init(allocator, state, start_oids, options);
            }
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
