const std = @import("std");
const hash = @import("./hash.zig");
const obj = @import("./object.zig");
const cmd = @import("./command.zig");
const idx = @import("./index.zig");
const st = @import("./status.zig");
const bch = @import("./branch.zig");
const chk = @import("./checkout.zig");
const ref = @import("./ref.zig");
const io = @import("./io.zig");
const df = @import("./diff.zig");
const mrg = @import("./merge.zig");
const cfg = @import("./config.zig");

pub const RepoKind = enum {
    git,
    xit,
};

pub fn Repo(comptime repo_kind: RepoKind) type {
    return struct {
        allocator: std.mem.Allocator,
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
            .xit => @import("xitdb").Database(.file, hash.Hash),
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

        pub const InitOpts = struct {
            cwd: std.fs.Dir,
        };

        pub fn init(allocator: std.mem.Allocator, opts: InitOpts) !Repo(repo_kind) {
            switch (repo_kind) {
                .git => {
                    var repo_dir = try opts.cwd.openDir(".", .{});
                    errdefer repo_dir.close();

                    var git_dir = repo_dir.openDir(".git", .{}) catch return error.RepoDoesNotExist;
                    errdefer git_dir.close();

                    return .{
                        .allocator = allocator,
                        .core = .{
                            .repo_dir = repo_dir,
                            .git_dir = git_dir,
                        },
                        .init_opts = opts,
                    };
                },
                .xit => {
                    var repo_dir = try opts.cwd.openDir(".", .{});
                    errdefer repo_dir.close();

                    var xit_dir = repo_dir.openDir(".xit", .{}) catch return error.RepoDoesNotExist;
                    errdefer xit_dir.close();

                    var db_file = xit_dir.openFile("db", .{ .mode = .read_write, .lock = .exclusive }) catch return error.RepoDoesNotExist;
                    errdefer db_file.close();

                    return .{
                        .allocator = allocator,
                        .core = .{
                            .repo_dir = repo_dir,
                            .xit_dir = xit_dir,
                            .db_file = db_file,
                            .db = try DB.init(allocator, .{ .file = db_file }),
                        },
                        .init_opts = opts,
                    };
                },
            }
        }

        pub fn initWithCommand(allocator: std.mem.Allocator, opts: InitOpts, sub_command: cmd.SubCommand, writers: anytype) !Repo(repo_kind) {
            var repo = Repo(repo_kind).init(allocator, opts) catch |err| switch (err) {
                error.RepoDoesNotExist => {
                    if (sub_command == .init) {
                        var repo = switch (repo_kind) {
                            .git => Repo(repo_kind){ .allocator = allocator, .core = undefined, .init_opts = opts },
                            .xit => Repo(repo_kind){ .allocator = allocator, .core = undefined, .init_opts = opts },
                        };
                        try repo.runCommand(sub_command, writers);
                        return repo;
                    } else {
                        return error.NotARepo;
                    }
                },
                else => return err,
            };
            errdefer repo.deinit();
            try repo.runCommand(sub_command, writers);
            return repo;
        }

        pub fn initNew(allocator: std.mem.Allocator, dir: std.fs.Dir, sub_path: []const u8) !Repo(repo_kind) {
            // get the root dir. if no path was given to the init command, this
            // should just be the current working directory (cwd). if a path was
            // given, it should either append it to the cwd or, if it is absolute,
            // it should just use that path alone. IT'S MAGIC!
            var repo_dir = try dir.makeOpenPath(sub_path, .{});
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
                    var objects_dir = try git_dir.makeOpenPath("objects", .{});
                    defer objects_dir.close();
                    var refs_dir = try git_dir.makeOpenPath("refs", .{});
                    defer refs_dir.close();
                    var heads_dir = try refs_dir.makeOpenPath("heads", .{});
                    defer heads_dir.close();

                    var self = Repo(repo_kind){
                        .allocator = allocator,
                        .core = .{
                            .repo_dir = repo_dir,
                            .git_dir = git_dir,
                        },
                        .init_opts = .{ .cwd = dir },
                    };

                    // update HEAD
                    const state = State(.read_write){ .core = &self.core, .extra = .{} };
                    try ref.writeHead(repo_kind, state, allocator, "master", null);

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
                    var self = Repo(repo_kind){
                        .allocator = allocator,
                        .core = .{
                            .repo_dir = repo_dir,
                            .xit_dir = xit_dir,
                            .db_file = db_file,
                            .db = try DB.init(allocator, .{ .file = db_file }),
                        },
                        .init_opts = .{ .cwd = dir },
                    };

                    // update HEAD
                    const Ctx = struct {
                        core: *Repo(repo_kind).Core,
                        allocator: std.mem.Allocator,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            try ref.writeHead(repo_kind, state, ctx.allocator, "master", null);
                        }
                    };
                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .allocator = self.allocator },
                    );

                    return self;
                },
            }
        }

        pub fn deinit(self: *Repo(repo_kind)) void {
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

        fn runCommand(self: *Repo(repo_kind), sub_command: cmd.SubCommand, writers: anytype) !void {
            switch (sub_command) {
                .init => |init_cmd| {
                    self.* = Repo(repo_kind).initNew(self.allocator, self.init_opts.cwd, init_cmd.dir) catch |err| switch (err) {
                        error.RepoAlreadyExists => {
                            try writers.err.print("{s} is already a repository\n", .{init_cmd.dir});
                            return;
                        },
                        else => return err,
                    };
                },
                .add => |add_cmd| {
                    try self.add(add_cmd.paths.items);
                },
                .unadd => |unadd_cmd| {
                    try self.unadd(unadd_cmd.paths.items, unadd_cmd.opts);
                },
                .rm => |rm_cmd| {
                    try self.rm(rm_cmd.paths.items, rm_cmd.opts);
                },
                .reset => |reset_cmd| {
                    try self.reset(reset_cmd.path);
                },
                .commit => |commit_cmd| {
                    _ = try self.commit(null, commit_cmd);
                },
                .status => {
                    var stat = try self.status();
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
                        workspace: st.Status(repo_kind),
                        index: st.Status(repo_kind),
                        tree: obj.TreeDiff(repo_kind),

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
                        .workspace => .{ .workspace = try self.status() },
                        .index => .{ .index = try self.status() },
                        .tree => |tree| .{ .tree = try self.treeDiff(tree.old, tree.new) },
                    };
                    defer diff_state.deinit();
                    var diff_iter = try self.filePairs(switch (diff_opts) {
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
                        var hunk_iter = try df.HunkIterator(repo_kind).init(self.allocator, &line_iter_pair.a, &line_iter_pair.b);
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
                            var moment = try self.core.latestMoment();
                            const state = .{ .core = &self.core, .extra = .{ .moment = &moment } };

                            var current_branch_maybe = try ref.Ref.initFromLink(repo_kind, state, self.allocator, "HEAD");
                            defer if (current_branch_maybe) |*current_branch| current_branch.deinit();

                            var ref_list = try ref.RefList.init(repo_kind, state, self.allocator, "heads");
                            defer ref_list.deinit();

                            for (ref_list.refs.items) |r| {
                                const is_current_branch = if (current_branch_maybe) |current_branch|
                                    std.mem.eql(u8, current_branch.name, r.name)
                                else
                                    false;
                                try writers.out.print("{s} {s}\n", .{ if (is_current_branch) "*" else " ", r.name });
                            }
                        },
                        .add => try self.addBranch(branch_cmd.add),
                        .remove => try self.removeBranch(branch_cmd.remove),
                    }
                },
                .switch_head => |switch_head_cmd| {
                    var result = try self.switchHead(switch_head_cmd.target, .{ .force = false });
                    defer result.deinit();
                },
                .restore => |restore_cmd| {
                    try self.restore(restore_cmd.path);
                },
                .log => {
                    var commit_iter = try self.log(null);
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
                .merge, .cherry_pick => {
                    var result = switch (sub_command) {
                        .merge => |merge_cmd| try self.merge(merge_cmd),
                        .cherry_pick => |cherry_pick_cmd| try self.cherryPick(cherry_pick_cmd),
                        else => unreachable,
                    };
                    defer result.deinit();
                    for (result.auto_resolved_conflicts.keys()) |path| {
                        if (result.changes.contains(path)) {
                            try writers.out.print("Auto-merging {s}\n", .{path});
                        }
                    }
                    switch (result.data) {
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
                                        result.source_name
                                    else
                                        result.target_name;
                                    try writers.err.print("CONFLICT ({s}): There is a directory with name {s} in {s}. Adding {s} as {s}\n", .{ conflict_type, path, dir_branch_name, path, renamed.path });
                                } else {
                                    if (result.changes.contains(path)) {
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
                                            .{ result.source_name, result.target_name }
                                        else
                                            .{ result.target_name, result.source_name };
                                        try writers.err.print("CONFLICT ({s}): {s} deleted in {s} and modified in {s}\n", .{ conflict_type, path, deleted_branch_name, modified_branch_name });
                                    }
                                }
                            }
                        },
                    }
                },
                .config => |config_cmd| {
                    switch (config_cmd) {
                        .list => {
                            var conf = try self.config();
                            defer conf.deinit();

                            for (conf.sections.keys(), conf.sections.values()) |section_name, variables| {
                                for (variables.keys(), variables.values()) |name, value| {
                                    try writers.out.print("{s}.{s}={s}\n", .{ section_name, name, value });
                                }
                            }
                        },
                        .add => |config_add_cmd| try self.addConfig(config_add_cmd),
                        .remove => |config_remove_cmd| try self.removeConfig(config_remove_cmd),
                    }
                },
                .remote => |remote_cmd| {
                    switch (remote_cmd) {
                        .list => {
                            var rem = try self.remote();
                            defer rem.deinit();

                            for (rem.sections.keys(), rem.sections.values()) |section_name, variables| {
                                for (variables.keys(), variables.values()) |name, value| {
                                    try writers.out.print("{s}.{s}={s}\n", .{ section_name, name, value });
                                }
                            }
                        },
                        .add => |remote_add_cmd| try self.addRemote(remote_add_cmd),
                        .remove => |remote_remove_cmd| try self.removeRemote(remote_remove_cmd),
                    }
                },
            }
        }

        pub fn commit(self: *Repo(repo_kind), parent_oids_maybe: ?[]const [hash.SHA1_HEX_LEN]u8, metadata: obj.CommitMetadata) ![hash.SHA1_HEX_LEN]u8 {
            switch (repo_kind) {
                .git => return try obj.writeCommit(repo_kind, .{ .core = &self.core, .extra = .{} }, self.allocator, parent_oids_maybe, metadata),
                .xit => {
                    const pch = @import("./patch.zig");

                    var result: [hash.SHA1_HEX_LEN]u8 = undefined;

                    const Ctx = struct {
                        core: *Repo(repo_kind).Core,
                        allocator: std.mem.Allocator,
                        parent_oids_maybe: ?[]const [hash.SHA1_HEX_LEN]u8,
                        metadata: obj.CommitMetadata,
                        result: *[hash.SHA1_HEX_LEN]u8,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            try pch.writePatch(state, ctx.allocator);
                            ctx.result.* = try obj.writeCommit(repo_kind, state, ctx.allocator, ctx.parent_oids_maybe, ctx.metadata);
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .allocator = self.allocator, .parent_oids_maybe = parent_oids_maybe, .metadata = metadata, .result = &result },
                    );

                    return result;
                },
            }
        }

        pub fn add(self: *Repo(repo_kind), paths: []const []const u8) !void {
            switch (repo_kind) {
                .git => {
                    var lock = try io.LockFile.init(self.allocator, self.core.git_dir, "index");
                    defer lock.deinit();

                    var index = try idx.Index(repo_kind).init(self.allocator, .{ .core = &self.core, .extra = .{} });
                    defer index.deinit();

                    for (paths) |path| {
                        try index.addOrRemovePath(.{ .core = &self.core, .extra = .{} }, path, .add);
                    }

                    try index.write(self.allocator, .{ .core = &self.core, .extra = .{ .lock_file_maybe = lock.lock_file } });

                    lock.success = true;
                },
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind).Core,
                        allocator: std.mem.Allocator,
                        paths: []const []const u8,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };

                            var index = try idx.Index(repo_kind).init(ctx.allocator, state.readOnly());
                            defer index.deinit();

                            for (ctx.paths) |path| {
                                try index.addOrRemovePath(state, path, .add);
                            }

                            try index.write(ctx.allocator, state);
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .allocator = self.allocator, .paths = paths },
                    );
                },
            }
        }

        pub fn unadd(self: *Repo(repo_kind), paths: []const []const u8, opts: idx.IndexUnaddOptions) !void {
            try self.rm(paths, .{
                .force = opts.force,
                .remove_from_workspace = false,
            });
        }

        pub fn rm(self: *Repo(repo_kind), paths: []const []const u8, opts: idx.IndexRemoveOptions) !void {
            // TODO: add support for -r (removing dirs)
            switch (repo_kind) {
                .git => {
                    var lock = try io.LockFile.init(self.allocator, self.core.git_dir, "index");
                    defer lock.deinit();

                    var index = try idx.Index(repo_kind).init(self.allocator, .{ .core = &self.core, .extra = .{} });
                    defer index.deinit();

                    var head_tree = try st.HeadTree(repo_kind).init(self.allocator, .{ .core = &self.core, .extra = .{} });
                    defer head_tree.deinit();

                    for (paths) |path| {
                        const meta = try io.getMetadata(self.core.repo_dir, path);
                        switch (meta.kind()) {
                            .file => {
                                if (!opts.force) {
                                    const differs_from = try idx.indexDiffersFrom(repo_kind, &self.core, index, head_tree, path, meta);
                                    if (differs_from.head and differs_from.workspace) {
                                        return error.CannotRemoveFileWithStagedAndUnstagedChanges;
                                    } else if (differs_from.head and opts.remove_from_workspace) {
                                        return error.CannotRemoveFileWithStagedChanges;
                                    } else if (differs_from.workspace and opts.remove_from_workspace) {
                                        return error.CannotRemoveFileWithUnstagedChanges;
                                    }
                                }
                                try index.addOrRemovePath(.{ .core = &self.core, .extra = .{} }, path, .rm);
                            },
                            else => return error.UnexpectedPathType,
                        }
                    }

                    if (opts.remove_from_workspace) {
                        for (paths) |path| {
                            const meta = try io.getMetadata(self.core.repo_dir, path);
                            switch (meta.kind()) {
                                .file => try self.core.repo_dir.deleteFile(path),
                                else => return error.UnexpectedPathType,
                            }
                        }
                    }

                    try index.write(self.allocator, .{ .core = &self.core, .extra = .{ .lock_file_maybe = lock.lock_file } });

                    lock.success = true;
                },
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind).Core,
                        allocator: std.mem.Allocator,
                        paths: []const []const u8,
                        opts: idx.IndexRemoveOptions,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };

                            var index = try idx.Index(repo_kind).init(ctx.allocator, state.readOnly());
                            defer index.deinit();

                            var head_tree = try st.HeadTree(repo_kind).init(ctx.allocator, state.readOnly());
                            defer head_tree.deinit();

                            for (ctx.paths) |path| {
                                const meta = try io.getMetadata(ctx.core.repo_dir, path);
                                switch (meta.kind()) {
                                    .file => {
                                        if (!ctx.opts.force) {
                                            const differs_from = try idx.indexDiffersFrom(repo_kind, ctx.core, index, head_tree, path, meta);
                                            if (differs_from.head and differs_from.workspace) {
                                                return error.CannotRemoveFileWithStagedAndUnstagedChanges;
                                            } else if (differs_from.head and ctx.opts.remove_from_workspace) {
                                                return error.CannotRemoveFileWithStagedChanges;
                                            } else if (differs_from.workspace and ctx.opts.remove_from_workspace) {
                                                return error.CannotRemoveFileWithUnstagedChanges;
                                            }
                                        }
                                        try index.addOrRemovePath(state, path, .rm);
                                    },
                                    else => return error.UnexpectedPathType,
                                }
                            }

                            if (ctx.opts.remove_from_workspace) {
                                for (ctx.paths) |path| {
                                    const meta = try io.getMetadata(ctx.core.repo_dir, path);
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
                        Ctx{ .core = &self.core, .allocator = self.allocator, .paths = paths, .opts = opts },
                    );
                },
            }
        }

        pub fn reset(self: *Repo(repo_kind), path: []const u8) !void {
            var stat = try self.status();
            defer stat.deinit();

            if (stat.index_added.contains(path) or stat.index_modified.contains(path)) {
                try self.unadd(&.{path}, .{});
            } else if (stat.index_deleted.contains(path)) {
                try self.add(&.{path});
            }
        }

        pub fn status(self: *Repo(repo_kind)) !st.Status(repo_kind) {
            var moment = try self.core.latestMoment();
            const state = .{ .core = &self.core, .extra = .{ .moment = &moment } };
            return try st.Status(repo_kind).init(self.allocator, state);
        }

        pub fn filePair(self: *Repo(repo_kind), path: []const u8, status_kind: st.StatusKind, stat: *st.Status(repo_kind)) !df.LineIteratorPair(repo_kind) {
            var moment = try self.core.latestMoment();
            const state = .{ .core = &self.core, .extra = .{ .moment = &moment } };
            switch (status_kind) {
                .added => |added| {
                    switch (added) {
                        .created => {
                            var a = try df.LineIterator(repo_kind).initFromNothing(self.allocator, path);
                            errdefer a.deinit();
                            const index_entries_for_path = stat.index.entries.get(path) orelse return error.EntryNotFound;
                            var b = try df.LineIterator(repo_kind).initFromIndex(state, self.allocator, index_entries_for_path[0] orelse return error.NullEntry);
                            errdefer b.deinit();
                            return .{ .path = path, .a = a, .b = b };
                        },
                        .modified => {
                            var a = try df.LineIterator(repo_kind).initFromHead(state, self.allocator, path, stat.head_tree.entries.get(path) orelse return error.EntryNotFound);
                            errdefer a.deinit();
                            const index_entries_for_path = stat.index.entries.get(path) orelse return error.EntryNotFound;
                            var b = try df.LineIterator(repo_kind).initFromIndex(state, self.allocator, index_entries_for_path[0] orelse return error.NullEntry);
                            errdefer b.deinit();
                            return .{ .path = path, .a = a, .b = b };
                        },
                        .deleted => {
                            var a = try df.LineIterator(repo_kind).initFromHead(state, self.allocator, path, stat.head_tree.entries.get(path) orelse return error.EntryNotFound);
                            errdefer a.deinit();
                            var b = try df.LineIterator(repo_kind).initFromNothing(self.allocator, path);
                            errdefer b.deinit();
                            return .{ .path = path, .a = a, .b = b };
                        },
                    }
                },
                .not_added => |not_added| {
                    switch (not_added) {
                        .modified => {
                            const meta = try io.getMetadata(self.core.repo_dir, path);
                            const mode = io.getMode(meta);

                            const index_entries_for_path = stat.index.entries.get(path) orelse return error.EntryNotFound;
                            var a = try df.LineIterator(repo_kind).initFromIndex(state, self.allocator, index_entries_for_path[0] orelse return error.NullEntry);
                            errdefer a.deinit();
                            var b = try df.LineIterator(repo_kind).initFromWorkspace(state, self.allocator, path, mode);
                            errdefer b.deinit();
                            return .{ .path = path, .a = a, .b = b };
                        },
                        .deleted => {
                            const index_entries_for_path = stat.index.entries.get(path) orelse return error.EntryNotFound;
                            var a = try df.LineIterator(repo_kind).initFromIndex(state, self.allocator, index_entries_for_path[0] orelse return error.NullEntry);
                            errdefer a.deinit();
                            var b = try df.LineIterator(repo_kind).initFromNothing(self.allocator, path);
                            errdefer b.deinit();
                            return .{ .path = path, .a = a, .b = b };
                        },
                    }
                },
                .not_tracked => {
                    const meta = try io.getMetadata(self.core.repo_dir, path);
                    const mode = io.getMode(meta);

                    var a = try df.LineIterator(repo_kind).initFromNothing(self.allocator, path);
                    errdefer a.deinit();
                    var b = try df.LineIterator(repo_kind).initFromWorkspace(state, self.allocator, path, mode);
                    errdefer b.deinit();
                    return .{ .path = path, .a = a, .b = b };
                },
            }
        }

        pub fn filePairs(self: *Repo(repo_kind), diff_opts: df.DiffOptions(repo_kind)) !df.FileIterator(repo_kind) {
            var moment = try self.core.latestMoment();
            const state = .{ .core = &self.core, .extra = .{ .moment = &moment } };
            return try df.FileIterator(repo_kind).init(self.allocator, state, diff_opts);
        }

        pub fn treeDiff(self: *Repo(repo_kind), old_oid_maybe: ?[hash.SHA1_HEX_LEN]u8, new_oid_maybe: ?[hash.SHA1_HEX_LEN]u8) !obj.TreeDiff(repo_kind) {
            var moment = try self.core.latestMoment();
            const state = .{ .core = &self.core, .extra = .{ .moment = &moment } };
            var tree_diff = obj.TreeDiff(repo_kind).init(self.allocator);
            errdefer tree_diff.deinit();
            try tree_diff.compare(state, old_oid_maybe, new_oid_maybe, null);
            return tree_diff;
        }

        pub fn addBranch(self: *Repo(repo_kind), input: bch.AddBranchInput) !void {
            switch (repo_kind) {
                .git => try bch.add(repo_kind, .{ .core = &self.core, .extra = .{} }, self.allocator, input),
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind).Core,
                        allocator: std.mem.Allocator,
                        input: bch.AddBranchInput,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            try bch.add(repo_kind, state, ctx.allocator, ctx.input);
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .allocator = self.allocator, .input = input },
                    );
                },
            }
        }

        pub fn removeBranch(self: *Repo(repo_kind), input: bch.RemoveBranchInput) !void {
            switch (repo_kind) {
                .git => try bch.remove(repo_kind, .{ .core = &self.core, .extra = .{} }, self.allocator, input),
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind).Core,
                        allocator: std.mem.Allocator,
                        input: bch.RemoveBranchInput,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            try bch.remove(repo_kind, state, ctx.allocator, ctx.input);
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .allocator = self.allocator, .input = input },
                    );
                },
            }
        }

        pub fn switchHead(self: *Repo(repo_kind), target: []const u8, options: chk.Switch.Options) !chk.Switch {
            switch (repo_kind) {
                .git => return try chk.Switch.init(repo_kind, .{ .core = &self.core, .extra = .{} }, self.allocator, target, options),
                .xit => {
                    var result: chk.Switch = undefined;

                    const Ctx = struct {
                        core: *Repo(repo_kind).Core,
                        allocator: std.mem.Allocator,
                        target: []const u8,
                        options: chk.Switch.Options,
                        result: *chk.Switch,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            ctx.result.* = try chk.Switch.init(repo_kind, state, ctx.allocator, ctx.target, ctx.options);
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    try history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .allocator = self.allocator, .target = target, .options = options, .result = &result },
                    );

                    return result;
                },
            }
        }

        pub fn restore(self: *Repo(repo_kind), path: []const u8) !void {
            var moment = try self.core.latestMoment();
            const state = .{ .core = &self.core, .extra = .{ .moment = &moment } };
            try chk.restore(repo_kind, state, self.allocator, path);
        }

        pub fn log(self: *Repo(repo_kind), start_oids_maybe: ?[]const [hash.SHA1_HEX_LEN]u8) !obj.ObjectIterator(repo_kind, .full) {
            const options = .{ .recursive = false };
            var moment = try self.core.latestMoment();
            const state = .{ .core = &self.core, .extra = .{ .moment = &moment } };
            if (start_oids_maybe) |start_oids| {
                return try obj.ObjectIterator(repo_kind, .full).init(self.allocator, state, start_oids, options);
            } else {
                const head_oid = try ref.readHead(repo_kind, state);
                return try obj.ObjectIterator(repo_kind, .full).init(self.allocator, state, &.{head_oid}, options);
            }
        }

        pub fn merge(self: *Repo(repo_kind), input: mrg.MergeInput) !mrg.Merge {
            switch (repo_kind) {
                .git => return try mrg.Merge.init(repo_kind, .{ .core = &self.core, .extra = .{} }, self.allocator, .merge, input, .diff3),
                .xit => {
                    var result: mrg.Merge = undefined;

                    const Ctx = struct {
                        core: *Repo(repo_kind).Core,
                        allocator: std.mem.Allocator,
                        input: mrg.MergeInput,
                        result: *mrg.Merge,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            ctx.result.* = try mrg.Merge.init(repo_kind, state, ctx.allocator, .merge, ctx.input, .diff3);
                            // no need to make a new transaction if nothing was done
                            if (.nothing == ctx.result.data) {
                                return error.CancelTransaction;
                            }
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .allocator = self.allocator, .input = input, .result = &result },
                    ) catch |err| switch (err) {
                        error.CancelTransaction => {},
                        else => return err,
                    };

                    return result;
                },
            }
        }

        pub fn cherryPick(self: *Repo(repo_kind), input: mrg.MergeInput) !mrg.Merge {
            switch (repo_kind) {
                .git => return try mrg.Merge.init(repo_kind, .{ .core = &self.core, .extra = .{} }, self.allocator, .cherry_pick, input, .diff3),
                .xit => {
                    var result: mrg.Merge = undefined;

                    const Ctx = struct {
                        core: *Repo(repo_kind).Core,
                        allocator: std.mem.Allocator,
                        input: mrg.MergeInput,
                        result: *mrg.Merge,

                        pub fn run(ctx: @This(), cursor: *DB.Cursor(.read_write)) !void {
                            var moment = try DB.HashMap(.read_write).init(cursor.*);
                            const state = State(.read_write){ .core = ctx.core, .extra = .{ .moment = &moment } };
                            ctx.result.* = try mrg.Merge.init(repo_kind, state, ctx.allocator, .cherry_pick, ctx.input, .diff3);
                            // no need to make a new transaction if nothing was done
                            if (.nothing == ctx.result.data) {
                                return error.CancelTransaction;
                            }
                        }
                    };

                    const history = try DB.ArrayList(.read_write).init(self.core.db.rootCursor());
                    history.appendContext(
                        .{ .slot = try history.getSlot(-1) },
                        Ctx{ .core = &self.core, .allocator = self.allocator, .input = input, .result = &result },
                    ) catch |err| switch (err) {
                        error.CancelTransaction => {},
                        else => return err,
                    };

                    return result;
                },
            }
        }

        pub fn config(self: *Repo(repo_kind)) !cfg.Config(repo_kind) {
            var moment = try self.core.latestMoment();
            const state = .{ .core = &self.core, .extra = .{ .moment = &moment } };
            return try cfg.Config(repo_kind).init(state, self.allocator);
        }

        pub fn addConfig(self: *Repo(repo_kind), input: cfg.AddConfigInput) !void {
            var conf = try self.config();
            defer conf.deinit();
            switch (repo_kind) {
                .git => {
                    var lock = try io.LockFile.init(self.allocator, self.core.git_dir, "config");
                    defer lock.deinit();

                    try conf.add(.{ .core = &self.core, .extra = .{ .lock_file_maybe = lock.lock_file } }, input);

                    lock.success = true;
                },
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind).Core,
                        conf: *cfg.Config(repo_kind),
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

        pub fn removeConfig(self: *Repo(repo_kind), input: cfg.RemoveConfigInput) !void {
            var conf = try self.config();
            defer conf.deinit();
            switch (repo_kind) {
                .git => {
                    var lock = try io.LockFile.init(self.allocator, self.core.git_dir, "config");
                    defer lock.deinit();

                    try conf.remove(.{ .core = &self.core, .extra = .{ .lock_file_maybe = lock.lock_file } }, input);

                    lock.success = true;
                },
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind).Core,
                        conf: *cfg.Config(repo_kind),
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

        pub fn remote(self: *Repo(repo_kind)) !cfg.RemoteConfig {
            var conf = try self.config();
            defer conf.deinit();
            return try cfg.RemoteConfig.init(repo_kind, &conf, self.allocator);
        }

        pub fn addRemote(self: *Repo(repo_kind), input: cfg.AddConfigInput) !void {
            const new_name = try std.fmt.allocPrint(self.allocator, "remote.{s}.url", .{input.name});
            defer self.allocator.free(new_name);
            const new_input = cfg.AddConfigInput{
                .name = new_name,
                .value = input.value,
            };

            var conf = try self.config();
            defer conf.deinit();
            switch (repo_kind) {
                .git => {
                    var lock = try io.LockFile.init(self.allocator, self.core.git_dir, "config");
                    defer lock.deinit();

                    try conf.add(.{ .core = &self.core, .extra = .{ .lock_file_maybe = lock.lock_file } }, new_input);

                    lock.success = true;
                },
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind).Core,
                        conf: *cfg.Config(repo_kind),
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

        pub fn removeRemote(self: *Repo(repo_kind), input: cfg.RemoveConfigInput) !void {
            const new_name = try std.fmt.allocPrint(self.allocator, "remote.{s}.url", .{input.name});
            defer self.allocator.free(new_name);
            const new_input = cfg.RemoveConfigInput{
                .name = new_name,
            };

            var conf = try self.config();
            defer conf.deinit();
            switch (repo_kind) {
                .git => {
                    var lock = try io.LockFile.init(self.allocator, self.core.git_dir, "config");
                    defer lock.deinit();

                    try conf.remove(.{ .core = &self.core, .extra = .{ .lock_file_maybe = lock.lock_file } }, new_input);

                    lock.success = true;
                },
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind).Core,
                        conf: *cfg.Config(repo_kind),
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
    };
}
