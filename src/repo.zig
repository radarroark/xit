const std = @import("std");
const xitdb = @import("xitdb");
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
const pch = @import("./patch.zig");

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

                pub fn latestCursor(_: *@This()) !void {}
            },
            .xit => struct {
                repo_dir: std.fs.Dir,
                xit_dir: std.fs.Dir,
                db: xitdb.Database(.file),

                pub fn latestCursor(self: *@This()) !xitdb.Database(.file).Cursor {
                    return (try self.db.rootCursor().readPath(void, &[_]xitdb.PathPart(void){
                        .{ .array_list_get = .{ .index = -1 } },
                    })) orelse return error.DatabaseEmpty;
                }
            },
        };

        pub const CoreCursor = switch (repo_kind) {
            .git => struct {
                core: *Core,
                lock_file_maybe: ?std.fs.File = null,
            },
            .xit => struct {
                core: *Core,
                cursor: *xitdb.Database(.file).Cursor,
            },
        };

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
                            .db = try xitdb.Database(.file).init(allocator, .{ .file = db_file }),
                        },
                        .init_opts = opts,
                    };
                },
            }
        }

        pub fn initWithCommand(allocator: std.mem.Allocator, opts: InitOpts, cmd_data: cmd.CommandData, writers: anytype) !Repo(repo_kind) {
            var repo = Repo(repo_kind).init(allocator, opts) catch |err| switch (err) {
                error.RepoDoesNotExist => {
                    if (cmd_data == .init) {
                        var repo = switch (repo_kind) {
                            .git => Repo(repo_kind){ .allocator = allocator, .core = undefined, .init_opts = opts },
                            .xit => Repo(repo_kind){ .allocator = allocator, .core = undefined, .init_opts = opts },
                        };
                        try repo.command(cmd_data, writers);
                        return repo;
                    } else {
                        return error.NotARepo;
                    }
                },
                else => return err,
            };
            errdefer repo.deinit();
            try repo.command(cmd_data, writers);
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
                    try ref.writeHead(repo_kind, .{ .core = &self.core }, allocator, "master", null);

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

                    // make the db
                    var db = blk: {
                        const db_file = try xit_dir.createFile("db", .{ .exclusive = true, .lock = .exclusive, .read = true });
                        errdefer db_file.close();
                        break :blk try xitdb.Database(.file).init(allocator, .{ .file = db_file });
                    };
                    errdefer db.deinit();

                    var self = Repo(repo_kind){
                        .allocator = allocator,
                        .core = .{
                            .repo_dir = repo_dir,
                            .xit_dir = xit_dir,
                            .db = db,
                        },
                        .init_opts = .{ .cwd = dir },
                    };

                    // update HEAD
                    const Ctx = struct {
                        core: *Repo(repo_kind).Core,
                        allocator: std.mem.Allocator,

                        pub fn run(ctx_self: @This(), cursor: *xitdb.Database(.file).Cursor) !void {
                            try ref.writeHead(repo_kind, .{ .core = ctx_self.core, .cursor = cursor }, ctx_self.allocator, "master", null);
                        }
                    };
                    _ = try self.core.db.rootCursor().writePath(Ctx, &[_]xitdb.PathPart(Ctx){
                        .{ .array_list_get = .append_copy },
                        .hash_map_init,
                        .{ .ctx = Ctx{ .core = &self.core, .allocator = self.allocator } },
                    });

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
                    self.core.db.deinit();
                    self.core.xit_dir.close();
                    self.core.repo_dir.close();
                },
            }
        }

        fn command(self: *Repo(repo_kind), cmd_data: cmd.CommandData, writers: anytype) !void {
            switch (cmd_data) {
                cmd.CommandData.invalid => {
                    try writers.err.print("\"{s}\" is not a valid command\n", .{cmd_data.invalid.name});
                    return;
                },
                cmd.CommandData.usage => {
                    try writers.out.print(
                        \\usage: xit
                        \\
                        \\start a working area:
                        \\   init
                        \\
                    , .{});
                },
                cmd.CommandData.init => {
                    self.* = Repo(repo_kind).initNew(self.allocator, self.init_opts.cwd, cmd_data.init.dir) catch |err| {
                        switch (err) {
                            error.RepoAlreadyExists => {
                                try writers.err.print("{s} is already a repository\n", .{cmd_data.init.dir});
                                return;
                            },
                            else => return err,
                        }
                    };
                },
                cmd.CommandData.add => {
                    try self.add(cmd_data.add.paths.items);
                },
                cmd.CommandData.commit => {
                    _ = try self.commit(null, cmd_data.commit.message);
                },
                cmd.CommandData.status => {
                    var stat = try self.status();
                    defer stat.deinit();

                    for (stat.untracked.items) |entry| {
                        try writers.out.print("?? {s}\n", .{entry.path});
                    }

                    for (stat.workspace_modified.items) |entry| {
                        try writers.out.print(" M {s}\n", .{entry.path});
                    }

                    for (stat.workspace_deleted.items) |path| {
                        try writers.out.print(" D {s}\n", .{path});
                    }

                    for (stat.index_added.items) |path| {
                        try writers.out.print("A  {s}\n", .{path});
                    }

                    for (stat.index_modified.items) |path| {
                        try writers.out.print("M  {s}\n", .{path});
                    }

                    for (stat.index_deleted.items) |path| {
                        try writers.out.print("D  {s}\n", .{path});
                    }

                    for (stat.conflicts.keys(), stat.conflicts.values()) |path, conflict| {
                        if (conflict.common) {
                            if (conflict.current) {
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
                            if (conflict.current) {
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
                cmd.CommandData.diff => {
                    var diff_iter = try self.diff(cmd_data.diff.diff_kind);
                    defer diff_iter.deinit();

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
                                        .eql => edit.eql.new_line.text,
                                        .ins => edit.ins.new_line.text,
                                        .del => edit.del.old_line.text,
                                    },
                                });
                            }
                        }
                    }
                },
                cmd.CommandData.branch => {
                    if (cmd_data.branch.name) |name| {
                        try self.create_branch(name);
                    } else {
                        var cursor = try self.core.latestCursor();
                        const core_cursor = switch (repo_kind) {
                            .git => .{ .core = &self.core },
                            .xit => .{ .core = &self.core, .cursor = &cursor },
                        };

                        var current_branch_maybe = try ref.Ref.initFromLink(repo_kind, core_cursor, self.allocator, "HEAD");
                        defer if (current_branch_maybe) |*current_branch| current_branch.deinit();

                        var ref_list = try ref.RefList.init(repo_kind, core_cursor, self.allocator, "heads");
                        defer ref_list.deinit();

                        for (ref_list.refs.items) |r| {
                            const is_current_branch = if (current_branch_maybe) |current_branch|
                                std.mem.eql(u8, current_branch.name, r.name)
                            else
                                false;
                            try writers.out.print("{s} {s}\n", .{ if (is_current_branch) "*" else " ", r.name });
                        }
                    }
                },
                cmd.CommandData.switch_head => {
                    var result = try self.switch_head(cmd_data.switch_head.target);
                    defer result.deinit();
                },
                cmd.CommandData.restore => {
                    try self.restore(cmd_data.restore.path);
                },
                cmd.CommandData.log => {
                    var cursor = try self.core.latestCursor();
                    const core_cursor = switch (repo_kind) {
                        .git => .{ .core = &self.core },
                        .xit => .{ .core = &self.core, .cursor = &cursor },
                    };
                    if (try ref.readHeadMaybe(repo_kind, core_cursor)) |oid| {
                        var commit_iter = try self.log(oid);
                        defer commit_iter.deinit();
                        while (try commit_iter.next()) |commit_object| {
                            defer commit_object.deinit();
                            try writers.out.print("commit {s}\n", .{commit_object.oid});
                            if (commit_object.content.commit.author) |author| {
                                try writers.out.print("Author {s}\n", .{author});
                            }
                            try writers.out.print("\n", .{});
                            var split_iter = std.mem.split(u8, commit_object.content.commit.message, "\n");
                            while (split_iter.next()) |line| {
                                try writers.out.print("    {s}\n", .{line});
                            }
                            try writers.out.print("\n", .{});
                        }
                    }
                },
                cmd.CommandData.merge => {
                    var result = try self.merge(cmd_data.merge);
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
                        .conflict => {
                            for (result.data.conflict.conflicts.keys(), result.data.conflict.conflicts.values()) |path, conflict| {
                                if (conflict.renamed) |renamed| {
                                    const conflict_type = if (conflict.current != null)
                                        "file/directory"
                                    else
                                        "directory/file";
                                    const dir_branch_name = if (conflict.current != null)
                                        result.source_name
                                    else
                                        result.current_name;
                                    try writers.err.print("CONFLICT ({s}): There is a directory with name {s} in {s}. Adding {s} as {s}\n", .{ conflict_type, path, dir_branch_name, path, renamed.path });
                                } else {
                                    if (result.changes.contains(path)) {
                                        try writers.out.print("Auto-merging {s}\n", .{path});
                                    }
                                    if (conflict.current != null and conflict.source != null) {
                                        const conflict_type = if (conflict.common != null)
                                            "content"
                                        else
                                            "add/add";
                                        try writers.err.print("CONFLICT ({s}): Merge conflict in {s}\n", .{ conflict_type, path });
                                    } else {
                                        const conflict_type = if (conflict.current != null)
                                            "modify/delete"
                                        else
                                            "delete/modify";
                                        const deleted_branch_name, const modified_branch_name = if (conflict.current != null)
                                            .{ result.source_name, result.current_name }
                                        else
                                            .{ result.current_name, result.source_name };
                                        try writers.err.print("CONFLICT ({s}): {s} deleted in {s} and modified in {s}\n", .{ conflict_type, path, deleted_branch_name, modified_branch_name });
                                    }
                                }
                            }
                        },
                    }
                },
            }
        }

        pub fn commit(self: *Repo(repo_kind), parent_oids_maybe: ?[]const [hash.SHA1_HEX_LEN]u8, message_maybe: ?[]const u8) ![hash.SHA1_HEX_LEN]u8 {
            switch (repo_kind) {
                .git => return try obj.writeCommit(repo_kind, .{ .core = &self.core }, self.allocator, parent_oids_maybe, message_maybe),
                .xit => {
                    var result: [hash.SHA1_HEX_LEN]u8 = undefined;
                    const Ctx = struct {
                        core: *Repo(repo_kind).Core,
                        allocator: std.mem.Allocator,
                        parent_oids_maybe: ?[]const [hash.SHA1_HEX_LEN]u8,
                        message_maybe: ?[]const u8,
                        result: *[hash.SHA1_HEX_LEN]u8,

                        pub fn run(ctx_self: @This(), cursor: *xitdb.Database(.file).Cursor) !void {
                            try pch.writePatches(repo_kind, .{ .core = ctx_self.core, .cursor = cursor }, ctx_self.allocator);
                            ctx_self.result.* = try obj.writeCommit(repo_kind, .{ .core = ctx_self.core, .cursor = cursor }, ctx_self.allocator, ctx_self.parent_oids_maybe, ctx_self.message_maybe);
                        }
                    };
                    _ = try self.core.db.rootCursor().writePath(Ctx, &[_]xitdb.PathPart(Ctx){
                        .{ .array_list_get = .append_copy },
                        .hash_map_init,
                        .{ .ctx = Ctx{ .core = &self.core, .allocator = self.allocator, .parent_oids_maybe = parent_oids_maybe, .message_maybe = message_maybe, .result = &result } },
                    });
                    return result;
                },
            }
        }

        pub fn add(self: *Repo(repo_kind), paths: []const []const u8) !void {
            switch (repo_kind) {
                .git => {
                    // create lock file
                    var lock = try io.LockFile.init(self.allocator, self.core.git_dir, "index");
                    defer lock.deinit();

                    // read index
                    var index = try idx.Index(.git).init(self.allocator, .{ .core = &self.core });
                    defer index.deinit();

                    // read all the new entries
                    for (paths) |path| {
                        if (self.core.repo_dir.openFile(path, .{ .mode = .read_only })) |file| {
                            file.close();
                        } else |err| {
                            switch (err) {
                                error.IsDir => {}, // only happens on windows
                                error.FileNotFound => {
                                    if (index.entries.contains(path)) {
                                        index.removePath(path);
                                        continue;
                                    } else {
                                        return err;
                                    }
                                },
                                else => return err,
                            }
                        }
                        try index.addPath(.{ .core = &self.core }, path);
                    }

                    try index.write(self.allocator, .{ .core = &self.core, .lock_file_maybe = lock.lock_file });

                    lock.success = true;
                },
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind).Core,
                        allocator: std.mem.Allocator,
                        paths: []const []const u8,

                        pub fn run(ctx_self: @This(), cursor: *xitdb.Database(.file).Cursor) !void {
                            // read index
                            var index = try idx.Index(.xit).init(ctx_self.allocator, .{ .core = ctx_self.core, .cursor = cursor });
                            defer index.deinit();

                            // read all the new entries
                            for (ctx_self.paths) |path| {
                                if (ctx_self.core.repo_dir.openFile(path, .{ .mode = .read_only })) |file| {
                                    file.close();
                                } else |err| {
                                    switch (err) {
                                        error.IsDir => {}, // only happens on windows
                                        error.FileNotFound => {
                                            if (index.entries.contains(path)) {
                                                index.removePath(path);
                                                continue;
                                            } else {
                                                return err;
                                            }
                                        },
                                        else => return err,
                                    }
                                }
                                try index.addPath(.{ .core = ctx_self.core, .cursor = cursor }, path);
                            }

                            // write index
                            try index.write(ctx_self.allocator, .{ .core = ctx_self.core, .cursor = cursor });
                        }
                    };
                    _ = try self.core.db.rootCursor().writePath(Ctx, &[_]xitdb.PathPart(Ctx){
                        .{ .array_list_get = .append_copy },
                        .hash_map_init,
                        .{ .ctx = Ctx{ .core = &self.core, .allocator = self.allocator, .paths = paths } },
                    });
                },
            }
        }

        pub fn status(self: *Repo(repo_kind)) !st.Status(repo_kind) {
            var cursor = try self.core.latestCursor();
            const core_cursor = switch (repo_kind) {
                .git => .{ .core = &self.core },
                .xit => .{ .core = &self.core, .cursor = &cursor },
            };
            return try st.Status(repo_kind).init(self.allocator, core_cursor);
        }

        pub fn diff(self: *Repo(repo_kind), diff_kind: df.DiffKind) !df.FileIterator(repo_kind) {
            var stat = try self.status();
            errdefer stat.deinit();
            return try df.FileIterator(repo_kind).init(self.allocator, &self.core, diff_kind, stat);
        }

        pub fn create_branch(self: *Repo(repo_kind), name: []const u8) !void {
            switch (repo_kind) {
                .git => try bch.create(repo_kind, .{ .core = &self.core }, self.allocator, name),
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind).Core,
                        allocator: std.mem.Allocator,
                        name: []const u8,

                        pub fn run(ctx_self: @This(), cursor: *xitdb.Database(.file).Cursor) !void {
                            try bch.create(repo_kind, .{ .core = ctx_self.core, .cursor = cursor }, ctx_self.allocator, ctx_self.name);
                        }
                    };
                    _ = try self.core.db.rootCursor().writePath(Ctx, &[_]xitdb.PathPart(Ctx){
                        .{ .array_list_get = .append_copy },
                        .hash_map_init,
                        .{ .ctx = Ctx{ .core = &self.core, .allocator = self.allocator, .name = name } },
                    });
                },
            }
        }

        pub fn delete_branch(self: *Repo(repo_kind), name: []const u8) !void {
            switch (repo_kind) {
                .git => try bch.delete(repo_kind, .{ .core = &self.core }, self.allocator, name),
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind).Core,
                        allocator: std.mem.Allocator,
                        name: []const u8,

                        pub fn run(ctx_self: @This(), cursor: *xitdb.Database(.file).Cursor) !void {
                            try bch.delete(repo_kind, .{ .core = ctx_self.core, .cursor = cursor }, ctx_self.allocator, ctx_self.name);
                        }
                    };
                    _ = try self.core.db.rootCursor().writePath(Ctx, &[_]xitdb.PathPart(Ctx){
                        .{ .array_list_get = .append_copy },
                        .hash_map_init,
                        .{ .ctx = Ctx{ .core = &self.core, .allocator = self.allocator, .name = name } },
                    });
                },
            }
        }

        pub fn switch_head(self: *Repo(repo_kind), target: []const u8) !chk.Switch {
            switch (repo_kind) {
                .git => return try chk.Switch.init(repo_kind, .{ .core = &self.core }, self.allocator, target),
                .xit => {
                    var result: chk.Switch = undefined;
                    const Ctx = struct {
                        core: *Repo(repo_kind).Core,
                        allocator: std.mem.Allocator,
                        target: []const u8,
                        result: *chk.Switch,

                        pub fn run(ctx_self: @This(), cursor: *xitdb.Database(.file).Cursor) !void {
                            ctx_self.result.* = try chk.Switch.init(repo_kind, .{ .core = ctx_self.core, .cursor = cursor }, ctx_self.allocator, ctx_self.target);
                        }
                    };
                    _ = try self.core.db.rootCursor().writePath(Ctx, &[_]xitdb.PathPart(Ctx){
                        .{ .array_list_get = .append_copy },
                        .hash_map_init,
                        .{ .ctx = Ctx{ .core = &self.core, .allocator = self.allocator, .target = target, .result = &result } },
                    });
                    return result;
                },
            }
        }

        pub fn restore(self: *Repo(repo_kind), path: []const u8) !void {
            switch (repo_kind) {
                .git => try chk.restore(repo_kind, .{ .core = &self.core }, self.allocator, path),
                .xit => {
                    const Ctx = struct {
                        core: *Repo(repo_kind).Core,
                        allocator: std.mem.Allocator,
                        path: []const u8,

                        pub fn run(ctx_self: @This(), cursor: *xitdb.Database(.file).Cursor) !void {
                            try chk.restore(repo_kind, .{ .core = ctx_self.core, .cursor = cursor }, ctx_self.allocator, ctx_self.path);
                        }
                    };
                    _ = try self.core.db.rootCursor().writePath(Ctx, &[_]xitdb.PathPart(Ctx){
                        .{ .array_list_get = .append_copy },
                        .hash_map_init,
                        .{ .ctx = Ctx{ .core = &self.core, .allocator = self.allocator, .path = path } },
                    });
                },
            }
        }

        pub fn log(self: *Repo(repo_kind), oid: [hash.SHA1_HEX_LEN]u8) !obj.ObjectIterator(repo_kind) {
            return try obj.ObjectIterator(repo_kind).init(self.allocator, &self.core, oid);
        }

        pub fn merge(self: *Repo(repo_kind), input: mrg.MergeInput) !mrg.Merge {
            switch (repo_kind) {
                .git => return try mrg.Merge.init(repo_kind, .{ .core = &self.core }, self.allocator, input),
                .xit => {
                    var result: mrg.Merge = undefined;
                    const Ctx = struct {
                        core: *Repo(repo_kind).Core,
                        allocator: std.mem.Allocator,
                        input: mrg.MergeInput,
                        result: *mrg.Merge,

                        pub fn run(ctx_self: @This(), cursor: *xitdb.Database(.file).Cursor) !void {
                            ctx_self.result.* = try mrg.Merge.init(repo_kind, .{ .core = ctx_self.core, .cursor = cursor }, ctx_self.allocator, ctx_self.input);
                            // no need to make a new transaction if nothing was done
                            if (.nothing == ctx_self.result.data) {
                                return error.CancelTransaction;
                            }
                        }
                    };
                    _ = self.core.db.rootCursor().writePath(Ctx, &[_]xitdb.PathPart(Ctx){
                        .{ .array_list_get = .append_copy },
                        .hash_map_init,
                        .{ .ctx = Ctx{ .core = &self.core, .allocator = self.allocator, .input = input, .result = &result } },
                    }) catch |err| switch (err) {
                        error.CancelTransaction => {},
                        else => return err,
                    };
                    return result;
                },
            }
        }
    };
}
