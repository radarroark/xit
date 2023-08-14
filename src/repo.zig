const std = @import("std");
const xitdb = @import("xitdb");
const obj = @import("./object.zig");
const cmd = @import("./command.zig");
const idx = @import("./index.zig");
const st = @import("./status.zig");
const branch = @import("./branch.zig");
const chk = @import("./checkout.zig");
const ref = @import("./ref.zig");
const io = @import("./io.zig");

pub const RepoKind = enum {
    git,
    xit,
};

pub const RepoErrors = error{
    NotARepo,
    RepoAlreadyExists,
};

pub fn Repo(comptime kind: RepoKind) type {
    return struct {
        allocator: std.mem.Allocator,
        core: Core,

        pub const Core = switch (kind) {
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

        pub fn init(allocator: std.mem.Allocator, opts: InitOpts) !?Repo(kind) {
            switch (kind) {
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
                    var xit_file_maybe = opts.cwd.openFile(".xit", .{}) catch null;
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

        pub fn initWithCommand(allocator: std.mem.Allocator, opts: InitOpts, cmd_data: cmd.CommandData) !Repo(kind) {
            var self_maybe = try Repo(kind).init(allocator, opts);
            if (self_maybe) |*self| {
                try self.command(cmd_data);
                return self.*;
            } else {
                if (cmd_data == .init) {
                    var self = switch (kind) {
                        .git => Repo(kind){ .allocator = allocator, .core = .{ .repo_dir = undefined, .git_dir = undefined } },
                        .xit => Repo(kind){ .allocator = allocator, .core = .{ .repo_dir = undefined, .db = undefined } },
                    };
                    try self.command(cmd_data);
                    return self;
                } else {
                    return error.NotARepo;
                }
            }
        }

        pub fn initNew(allocator: std.mem.Allocator, dir: std.fs.Dir, sub_path: []const u8) !Repo(kind) {
            // get the root dir. if no path was given to the init command, this
            // should just be the current working directory (cwd). if a path was
            // given, it should either append it to the cwd or, if it is absolute,
            // it should just use that path alone. IT'S MAGIC!
            var repo_dir = try dir.makeOpenPath(sub_path, .{});
            errdefer repo_dir.close();

            switch (kind) {
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

                    // update HEAD
                    try ref.writeHead(allocator, git_dir, "master", null);

                    return .{
                        .allocator = allocator,
                        .core = .{
                            .repo_dir = repo_dir,
                            .git_dir = git_dir,
                        },
                    };
                },
                .xit => {
                    const file = repo_dir.createFile(".xit", .{ .exclusive = true, .lock = .exclusive }) catch |err| {
                        switch (err) {
                            error.PathAlreadyExists => return error.RepoAlreadyExists,
                            else => return err,
                        }
                    };
                    errdefer file.close();

                    return .{
                        .allocator = allocator,
                        .core = .{
                            .repo_dir = repo_dir,
                            .db = try xitdb.Database(.file).init(allocator, .{ .file = file }),
                        },
                    };
                },
            }
        }

        pub fn deinit(self: *Repo(kind)) void {
            switch (kind) {
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

        fn command(self: *Repo(kind), cmd_data: cmd.CommandData) !void {
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
                    self.* = Repo(kind).initNew(self.allocator, std.fs.cwd(), cmd_data.init.dir) catch |err| {
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
                    try obj.writeCommit(self.allocator, self.core.repo_dir, cmd_data);
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
                cmd.CommandData.branch => {
                    switch (kind) {
                        .git => {
                            if (cmd_data.branch.name) |name| {
                                try branch.create(self.allocator, self.core.git_dir, name);
                            } else {
                                var current_branch_maybe = try ref.Ref.initWithPath(self.allocator, self.core.git_dir, "HEAD");
                                defer if (current_branch_maybe) |*current_branch| current_branch.deinit();

                                var ref_list = try ref.RefList.init(self.allocator, self.core.git_dir, "heads");
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
                        .xit => {},
                    }
                },
                cmd.CommandData.checkout => {
                    switch (kind) {
                        .git => {
                            var result = chk.CheckoutResult.init();
                            defer result.deinit();
                            chk.checkout(self.allocator, self.core.repo_dir, cmd_data.checkout.target, &result) catch |err| {
                                switch (err) {
                                    error.CheckoutConflict => {},
                                    else => return err,
                                }
                            };
                        },
                        .xit => {},
                    }
                },
            }
        }

        pub fn status(self: *Repo(kind)) !st.Status {
            switch (kind) {
                .git => {
                    return try st.Status.init(self.allocator, self.core.repo_dir, self.core.git_dir);
                },
                .xit => {
                    return error.NotARepo;
                },
            }
        }

        pub fn add(self: *Repo(kind), paths: std.ArrayList([]const u8)) !void {
            switch (kind) {
                .git => {
                    // create lock file
                    var lock = try io.LockFile.init(self.allocator, self.core.git_dir, "index");
                    defer lock.deinit();

                    // read index
                    var index = try idx.Index(.git).init(self.allocator, .{ .git_dir = self.core.git_dir });
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
                        try index.addPath(self.core.repo_dir, path);
                    }

                    try index.write(self.allocator, .{ .lock_file = lock.lock_file });

                    lock.success = true;
                },
                .xit => {
                    // read index
                    var index = try idx.Index(.xit).init(self.allocator, .{ .db = &self.core.db });
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
                        try index.addPath(self.core.repo_dir, path);
                    }

                    try index.write(self.allocator, .{ .db = &self.core.db });
                },
            }
        }
    };
}
