const std = @import("std");
const xitdb = @import("xitdb");
const hash = @import("./hash.zig");
const obj = @import("./object.zig");
const cmd = @import("./command.zig");
const idx = @import("./index.zig");
const st = @import("./status.zig");
const branch = @import("./branch.zig");
const chk = @import("./checkout.zig");
const ref = @import("./ref.zig");
const io = @import("./io.zig");
const df = @import("./diff.zig");

pub const RepoKind = enum {
    git,
    xit,
};

pub const RepoErrors = error{
    NotARepo,
    RepoAlreadyExists,
};

pub fn Repo(comptime repo_kind: RepoKind) type {
    return struct {
        allocator: std.mem.Allocator,
        core: Core,

        pub const Core = switch (repo_kind) {
            .git => struct {
                repo_dir: std.fs.Dir,
                git_dir: std.fs.Dir,
            },
            .xit => struct {
                repo_dir: std.fs.Dir,
                db: xitdb.Database(.file),
            },
        };

        pub const InitOpts = struct {
            cwd: std.fs.Dir,
        };

        pub fn init(allocator: std.mem.Allocator, opts: InitOpts) !?Repo(repo_kind) {
            switch (repo_kind) {
                .git => {
                    var git_dir_maybe = opts.cwd.openDir(".git", .{}) catch null;
                    if (git_dir_maybe) |*git_dir| {
                        errdefer git_dir.close();

                        var repo_dir = try opts.cwd.openDir(".", .{});
                        errdefer repo_dir.close();

                        return .{
                            .allocator = allocator,
                            .core = .{
                                .repo_dir = repo_dir,
                                .git_dir = git_dir.*,
                            },
                        };
                    } else {
                        return null;
                    }
                },
                .xit => {
                    var xit_file_maybe = opts.cwd.openFile(".xit", .{ .mode = .read_write, .lock = .exclusive }) catch null;
                    if (xit_file_maybe) |*xit_file| {
                        errdefer xit_file.close();

                        var repo_dir = try opts.cwd.openDir(".", .{});
                        errdefer repo_dir.close();

                        return .{
                            .allocator = allocator,
                            .core = .{
                                .repo_dir = repo_dir,
                                .db = try xitdb.Database(.file).init(allocator, .{ .file = xit_file.* }),
                            },
                        };
                    } else {
                        return null;
                    }
                },
            }
        }

        pub fn initWithCommand(allocator: std.mem.Allocator, opts: InitOpts, cmd_data: cmd.CommandData) !Repo(repo_kind) {
            var self_maybe = try Repo(repo_kind).init(allocator, opts);
            if (self_maybe) |*self| {
                errdefer self.deinit();
                try self.command(cmd_data);
                return self.*;
            } else {
                if (cmd_data == .init) {
                    var self = switch (repo_kind) {
                        .git => Repo(repo_kind){ .allocator = allocator, .core = undefined },
                        .xit => Repo(repo_kind){ .allocator = allocator, .core = undefined },
                    };
                    try self.command(cmd_data);
                    return self;
                } else {
                    return error.NotARepo;
                }
            }
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
                    // make the .git dir
                    repo_dir.makeDir(".git") catch |err| {
                        switch (err) {
                            error.PathAlreadyExists => return error.RepoAlreadyExists,
                            else => return err,
                        }
                    };

                    // make a few dirs inside of .git
                    var git_dir = try repo_dir.openDir(".git", .{});
                    errdefer git_dir.close();
                    var objects_dir = try git_dir.makeOpenPath("objects", .{});
                    defer objects_dir.close();
                    var refs_dir = try git_dir.makeOpenPath("refs", .{});
                    defer refs_dir.close();
                    var heads_dir = try refs_dir.makeOpenPath("heads", .{});
                    defer heads_dir.close();

                    var self: Repo(repo_kind) = .{
                        .allocator = allocator,
                        .core = .{
                            .repo_dir = repo_dir,
                            .git_dir = git_dir,
                        },
                    };

                    // update HEAD
                    try ref.writeHead(repo_kind, &self.core, allocator, "master", null);

                    return self;
                },
                .xit => {
                    const file = repo_dir.createFile(".xit", .{ .exclusive = true, .lock = .exclusive, .read = true }) catch |err| {
                        switch (err) {
                            error.PathAlreadyExists => return error.RepoAlreadyExists,
                            else => return err,
                        }
                    };

                    var db = blk: {
                        errdefer file.close();
                        break :blk try xitdb.Database(.file).init(allocator, .{ .file = file });
                    };
                    errdefer db.deinit();

                    var self: Repo(repo_kind) = .{
                        .allocator = allocator,
                        .core = .{
                            .repo_dir = repo_dir,
                            .db = db,
                        },
                    };

                    // update HEAD
                    try ref.writeHead(repo_kind, &self.core, allocator, "master", null);

                    return self;
                },
            }
        }

        pub fn deinit(self: *Repo(repo_kind)) void {
            switch (repo_kind) {
                .git => {
                    self.core.repo_dir.close();
                    self.core.git_dir.close();
                },
                .xit => {
                    self.core.repo_dir.close();
                    self.core.db.deinit();
                },
            }
        }

        fn command(self: *Repo(repo_kind), cmd_data: cmd.CommandData) !void {
            const stdout = std.io.getStdOut().writer();
            const stderr = std.io.getStdErr().writer();

            switch (cmd_data) {
                cmd.CommandData.invalid => {
                    try stderr.print("\"{s}\" is not a valid command\n", .{cmd_data.invalid.name});
                    return;
                },
                cmd.CommandData.usage => {
                    try stdout.print(
                        \\usage: xit
                        \\
                        \\start a working area:
                        \\   init
                        \\
                    , .{});
                },
                cmd.CommandData.init => {
                    self.* = Repo(repo_kind).initNew(self.allocator, std.fs.cwd(), cmd_data.init.dir) catch |err| {
                        switch (err) {
                            error.RepoAlreadyExists => {
                                try stderr.print("{s} is already a repository\n", .{cmd_data.init.dir});
                                return;
                            },
                            else => return err,
                        }
                    };
                },
                cmd.CommandData.add => {
                    try self.add(cmd_data.add.paths);
                },
                cmd.CommandData.commit => {
                    const head_oid_maybe = try ref.readHeadMaybe(repo_kind, &self.core);
                    const parent_oids = if (head_oid_maybe) |head_oid| &[_][hash.SHA1_HEX_LEN]u8{head_oid} else &[_][hash.SHA1_HEX_LEN]u8{};
                    try obj.writeCommit(repo_kind, &self.core, self.allocator, parent_oids, cmd_data.commit.message);
                },
                cmd.CommandData.status => {
                    var stat = try self.status();
                    defer stat.deinit();

                    for (stat.untracked.items) |entry| {
                        try stdout.print("?? {s}\n", .{entry.path});
                    }

                    for (stat.workspace_modified.items) |entry| {
                        try stdout.print(" M {s}\n", .{entry.path});
                    }

                    for (stat.workspace_deleted.items) |path| {
                        try stdout.print(" D {s}\n", .{path});
                    }

                    for (stat.index_added.items) |path| {
                        try stdout.print("A  {s}\n", .{path});
                    }

                    for (stat.index_modified.items) |path| {
                        try stdout.print("M  {s}\n", .{path});
                    }

                    for (stat.index_deleted.items) |path| {
                        try stdout.print("D  {s}\n", .{path});
                    }
                },
                cmd.CommandData.diff => {
                    var diff_iter = try self.diff(cmd_data.diff.kind);
                    defer diff_iter.deinit();

                    while (try diff_iter.next()) |diff_item| {
                        defer diff_item.deinit();
                        for (diff_item.header_lines.items) |header_line| {
                            try stdout.print("{s}\n", .{header_line});
                        }
                        for (diff_item.hunks.items) |hunk| {
                            const offsets = hunk.offsets();
                            try stdout.print("@@ -{},{} +{},{} @@\n", .{
                                offsets.del_start,
                                offsets.del_count,
                                offsets.ins_start,
                                offsets.ins_count,
                            });
                            for (hunk.edits) |edit| {
                                try stdout.print("{s} {s}\n", .{
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
                        try branch.create(repo_kind, &self.core, self.allocator, name);
                    } else {
                        var current_branch_maybe = try ref.Ref.initFromLink(repo_kind, &self.core, self.allocator, "HEAD");
                        defer if (current_branch_maybe) |*current_branch| current_branch.deinit();

                        var ref_list = try ref.RefList.init(repo_kind, &self.core, self.allocator, "heads");
                        defer ref_list.deinit();

                        for (ref_list.refs.items) |r| {
                            const is_current_branch = if (current_branch_maybe) |current_branch|
                                std.mem.eql(u8, current_branch.name, r.name)
                            else
                                false;
                            try stdout.print("{s} {s}\n", .{ if (is_current_branch) "*" else " ", r.name });
                        }
                    }
                },
                cmd.CommandData.switch_head => {
                    var result = chk.SwitchResult.init();
                    defer result.deinit();
                    chk.switch_head(repo_kind, &self.core, self.allocator, cmd_data.switch_head.target, &result) catch |err| {
                        switch (err) {
                            error.SwitchConflict => {},
                            else => return err,
                        }
                    };
                },
                cmd.CommandData.restore => {
                    try chk.restore(repo_kind, &self.core, self.allocator, cmd_data.restore.path);
                },
                cmd.CommandData.log => {
                    if (try ref.readHeadMaybe(repo_kind, &self.core)) |oid| {
                        var commit_iter = try self.log(oid);
                        defer commit_iter.deinit();
                        while (try commit_iter.next()) |commit_object| {
                            defer commit_object.deinit();
                            try stdout.print("commit {s}\n", .{commit_object.oid});
                            if (commit_object.content.commit.author) |author| {
                                try stdout.print("Author {s}\n", .{author});
                            }
                            try stdout.print("\n", .{});
                            var split_iter = std.mem.split(u8, commit_object.content.commit.message, "\n");
                            while (split_iter.next()) |line| {
                                try stdout.print("    {s}\n", .{line});
                            }
                            try stdout.print("\n", .{});
                        }
                    }
                },
            }
        }

        pub fn status(self: *Repo(repo_kind)) !st.Status(repo_kind) {
            return try st.Status(repo_kind).init(self.allocator, &self.core);
        }

        pub fn diff(self: *Repo(repo_kind), diff_kind: df.DiffKind) !df.DiffIterator(repo_kind) {
            return try df.DiffIterator(repo_kind).init(self.allocator, &self.core, diff_kind);
        }

        pub fn add(self: *Repo(repo_kind), paths: std.ArrayList([]const u8)) !void {
            switch (repo_kind) {
                .git => {
                    // create lock file
                    var lock = try io.LockFile.init(self.allocator, self.core.git_dir, "index");
                    defer lock.deinit();

                    // read index
                    var index = try idx.Index(.git).init(self.allocator, &self.core);
                    defer index.deinit();

                    // read all the new entries
                    for (paths.items) |path| {
                        const file = self.core.repo_dir.openFile(path, .{ .mode = .read_only }) catch |err| {
                            if (err == error.FileNotFound and index.entries.contains(path)) {
                                index.removePath(path);
                                continue;
                            } else {
                                return err;
                            }
                        };
                        defer file.close();
                        try index.addPath(&self.core, path);
                    }

                    try index.write(self.allocator, .{ .lock_file = lock.lock_file });

                    lock.success = true;
                },
                .xit => {
                    // read index
                    var index = try idx.Index(.xit).init(self.allocator, &self.core);
                    defer index.deinit();

                    // read all the new entries
                    for (paths.items) |path| {
                        const file = self.core.repo_dir.openFile(path, .{ .mode = .read_only }) catch |err| {
                            if (err == error.FileNotFound and index.entries.contains(path)) {
                                index.removePath(path);
                                continue;
                            } else {
                                return err;
                            }
                        };
                        defer file.close();
                        try index.addPath(&self.core, path);
                    }

                    try index.write(self.allocator, .{ .db = &self.core.db });
                },
            }
        }

        pub fn log(self: *Repo(repo_kind), oid: [hash.SHA1_HEX_LEN]u8) !obj.ObjectIterator(repo_kind) {
            return try obj.ObjectIterator(repo_kind).init(self.allocator, &self.core, oid);
        }
    };
}
