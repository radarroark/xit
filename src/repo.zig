const std = @import("std");
const obj = @import("./object.zig");
const cmd = @import("./command.zig");
const idx = @import("./index.zig");
const stat = @import("./status.zig");
const branch = @import("./branch.zig");
const chk = @import("./checkout.zig");
const ref = @import("./ref.zig");

pub const RepoKind = enum {
    git,
};

pub const RepoErrors = error{
    NotARepo,
};

pub fn Repo(comptime kind: RepoKind) type {
    return struct {
        allocator: std.mem.Allocator,
        core: Core,

        pub const Core = switch (kind) {
            .git => struct {
                repo_dir_maybe: ?std.fs.Dir,
                repo_dir_created: bool,
            },
        };

        pub const InitOpts = switch (kind) {
            .git => struct {
                cwd: std.fs.Dir,
            },
        };

        pub fn init(allocator: std.mem.Allocator, opts: InitOpts) !Repo(kind) {
            return .{
                .allocator = allocator,
                .core = switch (kind) {
                    .git => blk: {
                        var git_dir_maybe: ?std.fs.Dir = opts.cwd.openDir(".git", .{}) catch |err| open_dir_blk: {
                            switch (err) {
                                error.FileNotFound => break :open_dir_blk null,
                                else => return err,
                            }
                        };
                        defer if (git_dir_maybe) |*git_dir| git_dir.close();
                        break :blk .{
                            .repo_dir_maybe = if (git_dir_maybe == null) null else opts.cwd,
                            .repo_dir_created = false,
                        };
                    },
                },
            };
        }

        pub fn deinit(self: *Repo(kind)) void {
            switch (kind) {
                .git => {
                    if (self.core.repo_dir_created) {
                        if (self.core.repo_dir_maybe) |*repo_dir| {
                            repo_dir.close();
                        }
                    }
                },
            }
        }

        pub fn command(self: *Repo(kind), cmd_data: cmd.CommandData) !void {
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
                    // get the root dir. no path was given to the init command, this
                    // should just be the current working directory (cwd). if a path was
                    // given, it should either append it to the cwd or, if it is absolute,
                    // it should just use that path alone. IT'S MAGIC!
                    var repo_dir = try std.fs.cwd().makeOpenPath(cmd_data.init.dir, .{});
                    errdefer repo_dir.close();
                    self.core.repo_dir_maybe = repo_dir;
                    self.core.repo_dir_created = true;

                    // make the .git dir. right now we're throwing an error if it already
                    // exists. in git it says "Reinitialized existing Git repository" so
                    // we'll need to do that eventually.
                    repo_dir.makeDir(".git") catch |err| {
                        switch (err) {
                            error.PathAlreadyExists => {
                                try stderr.print("{s} is already a repository\n", .{cmd_data.init.dir});
                                return;
                            },
                            else => return err,
                        }
                    };

                    // make a few dirs inside of .git
                    var git_dir = try repo_dir.openDir(".git", .{});
                    defer git_dir.close();
                    var objects_dir = try git_dir.makeOpenPath("objects", .{});
                    defer objects_dir.close();
                    var refs_dir = try git_dir.makeOpenPath("refs", .{});
                    defer refs_dir.close();
                    var heads_dir = try refs_dir.makeOpenPath("heads", .{});
                    defer heads_dir.close();

                    // update HEAD
                    try ref.writeHead(self.allocator, git_dir, "master", null);
                },
                cmd.CommandData.add => {
                    if (self.core.repo_dir_maybe) |repo_dir| {
                        try idx.writeIndex(self.allocator, repo_dir, cmd_data.add.paths);
                    } else {
                        return error.NotARepo;
                    }
                },
                cmd.CommandData.commit => {
                    if (self.core.repo_dir_maybe) |repo_dir| {
                        try obj.writeCommit(self.allocator, repo_dir, cmd_data);
                    } else {
                        return error.NotARepo;
                    }
                },
                cmd.CommandData.status => {
                    if (self.core.repo_dir_maybe) |repo_dir| {
                        var git_dir = try repo_dir.openDir(".git", .{});
                        defer git_dir.close();

                        var status = try stat.Status.init(self.allocator, repo_dir, git_dir);
                        defer status.deinit();

                        for (status.untracked.items) |entry| {
                            try stdout.print("?? {s}\n", .{entry.path});
                        }

                        for (status.workspace_modified.items) |entry| {
                            try stdout.print(" M {s}\n", .{entry.path});
                        }

                        for (status.workspace_deleted.items) |path| {
                            try stdout.print(" D {s}\n", .{path});
                        }

                        for (status.index_added.items) |path| {
                            try stdout.print("A  {s}\n", .{path});
                        }

                        for (status.index_modified.items) |path| {
                            try stdout.print("M  {s}\n", .{path});
                        }

                        for (status.index_deleted.items) |path| {
                            try stdout.print("D  {s}\n", .{path});
                        }
                    } else {
                        return error.NotARepo;
                    }
                },
                cmd.CommandData.branch => {
                    if (self.core.repo_dir_maybe) |repo_dir| {
                        var git_dir = try repo_dir.openDir(".git", .{});
                        defer git_dir.close();

                        if (cmd_data.branch.name) |name| {
                            try branch.create(self.allocator, git_dir, name);
                        } else {
                            var current_branch_maybe = try ref.Ref.initWithPath(self.allocator, git_dir, "HEAD");
                            defer if (current_branch_maybe) |*current_branch| current_branch.deinit();

                            var ref_list = try ref.RefList.init(self.allocator, git_dir, "heads");
                            defer ref_list.deinit();

                            for (ref_list.refs.items) |r| {
                                const is_current_branch = if (current_branch_maybe) |current_branch|
                                    std.mem.eql(u8, current_branch.name, r.name)
                                else
                                    false;
                                try stdout.print("{s} {s}\n", .{ if (is_current_branch) "*" else " ", r.name });
                            }
                        }
                    } else {
                        return error.NotARepo;
                    }
                },
                cmd.CommandData.checkout => {
                    if (self.core.repo_dir_maybe) |repo_dir| {
                        var result = chk.CheckoutResult.init();
                        defer result.deinit();
                        chk.checkout(self.allocator, repo_dir, cmd_data.checkout.target, &result) catch |err| {
                            switch (err) {
                                error.CheckoutConflict => {},
                                else => return err,
                            }
                        };
                    } else {
                        return error.NotARepo;
                    }
                },
            }
        }
    };
}
