//! you're looking at radar's hopeless attempt to implement
//! the successor to git. behold the three rules of xit:
//!
//! 1. keep the codebase small and stupid.
//! 2. prefer simple 80% solutions over complex 100% solutions.
//! 3. never take yourself too seriously. be a dork, and you'll
//! attract dorks. together, we'll make a glorious pack of strays.
//!
//! "C'mon Alex! You always dreamt about going on a big adventure!
//!  Let this be our first!" -- Lunar: Silver Star Story

const std = @import("std");
const cmd = @import("./command.zig");
const rp = @import("./repo.zig");
const ui = @import("./ui.zig");
const hash = @import("./hash.zig");
const df = @import("./diff.zig");
const mnt = @import("./mount.zig");
const mrg = @import("./merge.zig");
const obj = @import("./object.zig");
const tr = @import("./tree.zig");
const rf = @import("./ref.zig");

pub const Writers = struct {
    out: std.io.AnyWriter = std.io.null_writer.any(),
    err: std.io.AnyWriter = std.io.null_writer.any(),
};

/// this is meant to be the main entry point if you wanted to use xit
/// as a CLI tool. to use xit programmatically, build a Repo struct
/// and call methods on it directly. to use xit subconsciously, just
/// think about it really often and eventually you'll dream about it.
pub fn run(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    allocator: std.mem.Allocator,
    args: []const []const u8,
    cwd: std.fs.Dir,
    writers: Writers,
) !void {
    var cmd_args = try cmd.CommandArgs.init(allocator, args);
    defer cmd_args.deinit();

    switch (try cmd.CommandDispatch(repo_kind, repo_opts.hash).init(&cmd_args)) {
        .invalid => |invalid| switch (invalid) {
            .command => |command| {
                try writers.err.print("\"{s}\" is not a valid command\n\n", .{command});
                try cmd.printHelp(null, writers.err);
                return error.PrintedError;
            },
            .argument => |argument| {
                try writers.err.print("\"{s}\" is not a valid argument\n\n", .{argument.value});
                try cmd.printHelp(argument.command, writers.err);
                return error.PrintedError;
            },
        },
        .help => |cmd_kind_maybe| try cmd.printHelp(cmd_kind_maybe, writers.out),
        .tui => |cmd_kind_maybe| if (.none == repo_opts.hash) {
            // if no hash was specified, use AnyRepo to detect the hash being used
            var any_repo = try rp.AnyRepo(repo_kind, repo_opts).open(allocator, .{ .cwd = cwd });
            defer any_repo.deinit();
            switch (any_repo) {
                .none => return error.HashKindNotFound,
                .sha1 => |*repo| try ui.start(repo_kind, repo_opts.withHash(.sha1), repo, allocator, cmd_kind_maybe),
                .sha256 => |*repo| try ui.start(repo_kind, repo_opts.withHash(.sha256), repo, allocator, cmd_kind_maybe),
            }
        } else {
            var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = cwd });
            defer repo.deinit();
            try ui.start(repo_kind, repo_opts, &repo, allocator, cmd_kind_maybe);
        },
        .cli => |cli_cmd| switch (cli_cmd) {
            .init => |init_cmd| {
                const new_repo_opts = comptime if (.none == repo_opts.hash)
                    // if no hash was specified, just use the default hash
                    repo_opts.withHash((rp.RepoOpts(repo_kind){}).hash)
                else
                    repo_opts;
                var repo = try rp.Repo(repo_kind, new_repo_opts).init(allocator, .{ .cwd = cwd }, init_cmd.dir);
                defer repo.deinit();

                // add default user config
                try repo.addConfig(allocator, .{ .name = "user.name", .value = "fixme" });
                try repo.addConfig(allocator, .{ .name = "user.email", .value = "fix@me" });

                try writers.out.print(
                    \\congrats, you just created a new repo! aren't you special.
                    \\try setting your name and email. if you're too lazy, the
                    \\default ones will be used, and you'll be like one of those
                    \\low-effort people who make slides with times new roman font.
                    \\
                    \\    xit config add user.name foo
                    \\    xit config add user.email foo@bar
                    \\
                , .{});
            },
            else => if (.none == repo_opts.hash) {
                // if no hash was specified, use AnyRepo to detect the hash being used
                var any_repo = try rp.AnyRepo(repo_kind, repo_opts).open(allocator, .{ .cwd = cwd });
                defer any_repo.deinit();
                switch (any_repo) {
                    .none => return error.HashKindNotFound,
                    .sha1 => |*repo| {
                        const cmd_maybe = try cmd.Command(repo_kind, .sha1).init(&cmd_args);
                        try runCommand(repo_kind, repo_opts.withHash(.sha1), repo, allocator, cmd_maybe orelse return error.InvalidCommand, writers);
                    },
                    .sha256 => |*repo| {
                        const cmd_maybe = try cmd.Command(repo_kind, .sha256).init(&cmd_args);
                        try runCommand(repo_kind, repo_opts.withHash(.sha256), repo, allocator, cmd_maybe orelse return error.InvalidCommand, writers);
                    },
                }
            } else {
                var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = cwd });
                defer repo.deinit();
                try runCommand(repo_kind, repo_opts, &repo, allocator, cli_cmd, writers);
            },
        },
    }
}

/// like `run` except it prints user-friendly error messages
pub fn runPrint(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    allocator: std.mem.Allocator,
    args: []const []const u8,
    cwd: std.fs.Dir,
    writers: Writers,
) !void {
    run(repo_kind, repo_opts, allocator, args, cwd, writers) catch |err| switch (err) {
        error.RepoNotFound => {
            try writers.err.print(
                \\repo not found, dummy.
                \\either you're in the wrong place
                \\or you need to make a new one like this:
                \\
                \\
            , .{});
            try cmd.printHelp(.init, writers.err);
            return error.PrintedError;
        },
        error.RepoAlreadyExists => {
            try writers.err.print(
                \\repo already exists, dummy.
                \\two repos in the same directory makes no sense.
                \\think about it.
                \\
            , .{});
            return error.PrintedError;
        },
        error.CannotRemoveFileWithStagedAndUnstagedChanges, error.CannotRemoveFileWithStagedChanges, error.CannotRemoveFileWithUnstagedChanges => {
            try writers.err.print(
                \\a file has uncommitted changes.
                \\if you really want to do it, throw caution
                \\into the wind by adding the -f flag.
                \\
            , .{});
            return error.PrintedError;
        },
        error.EmptyCommit => {
            try writers.err.print(
                \\you haven't added anything to commit yet.
                \\if you really want to commit anyway, add the
                \\--allow-empty flag and no one will judge you.
                \\
            , .{});
            return error.PrintedError;
        },
        error.AddIndexPathNotFound => {
            try writers.err.print(
                \\a path you are adding does not exist.
                \\
            , .{});
            return error.PrintedError;
        },
        error.RemoveIndexPathNotFound => {
            try writers.err.print(
                \\a path you are removing does not exist.
                \\
            , .{});
            return error.PrintedError;
        },
        else => |e| return e,
    };
}

/// executes a command on the given repo
fn runCommand(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    repo: *rp.Repo(repo_kind, repo_opts),
    allocator: std.mem.Allocator,
    command: cmd.Command(repo_kind, repo_opts.hash),
    writers: Writers,
) !void {
    switch (command) {
        .init => {},
        .add => |add_cmd| {
            try repo.add(allocator, add_cmd.paths);
        },
        .unadd => |unadd_cmd| {
            try repo.unadd(allocator, unadd_cmd.paths);
        },
        .untrack => |untrack_cmd| {
            try repo.untrack(allocator, untrack_cmd.paths, untrack_cmd.opts);
        },
        .rm => |rm_cmd| {
            try repo.remove(allocator, rm_cmd.paths, rm_cmd.opts);
        },
        .commit => |commit_cmd| {
            _ = try repo.commit(allocator, commit_cmd);
        },
        .tag => |tag_cmd| switch (tag_cmd) {
            .list => {
                var ref_list = try repo.listTags(allocator);
                defer ref_list.deinit();

                for (ref_list.refs.values()) |ref| {
                    try writers.out.print("{s}\n", .{ref.name});
                }
            },
            .add => |add_tag| _ = try repo.addTag(allocator, add_tag),
            .remove => |rm_tag| try repo.removeTag(rm_tag),
        },
        .status => {
            var head_buffer = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
            switch (try repo.head(&head_buffer)) {
                .ref => |ref| try writers.out.print("on branch {s}\n\n", .{ref.name}),
                .oid => |oid| try writers.out.print("HEAD detached at {s}\n\n", .{oid}),
            }

            var stat = try repo.status(allocator);
            defer stat.deinit();

            for (stat.untracked.values()) |entry| {
                try writers.out.print("?? {s}\n", .{entry.path});
            }

            for (stat.mount_modified.values()) |entry| {
                try writers.out.print(" M {s}\n", .{entry.path});
            }

            for (stat.mount_deleted.keys()) |path| {
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
                            return error.InvalidConflict;
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
                            return error.InvalidConflict;
                        }
                    }
                }
            }
        },
        .diff_mount, .diff_added => |diff_cmd| {
            const DiffState = union(df.DiffKind) {
                mount: mnt.Status(repo_kind, repo_opts),
                index: mnt.Status(repo_kind, repo_opts),
                tree: tr.TreeDiff(repo_kind, repo_opts),

                fn deinit(diff_state: *@This()) void {
                    switch (diff_state.*) {
                        .mount => diff_state.mount.deinit(),
                        .index => diff_state.index.deinit(),
                        .tree => diff_state.tree.deinit(),
                    }
                }
            };
            var diff_state: DiffState = switch (diff_cmd) {
                .mount => .{ .mount = try repo.status(allocator) },
                .index => .{ .index = try repo.status(allocator) },
                .tree => |tree| .{
                    .tree = try repo.treeDiff(allocator, if (tree.old) |old| &old else null, if (tree.new) |new| &new else null),
                },
            };
            defer diff_state.deinit();
            var diff_iter = try repo.filePairs(allocator, switch (diff_cmd) {
                .mount => |mount| .{
                    .mount = .{
                        .conflict_diff_kind = mount.conflict_diff_kind,
                        .status = &diff_state.mount,
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
                        const line = switch (edit) {
                            .eql => |eql| try hunk_iter.line_iter_b.get(eql.new_line.num),
                            .ins => |ins| try hunk_iter.line_iter_b.get(ins.new_line.num),
                            .del => |del| try hunk_iter.line_iter_a.get(del.old_line.num),
                        };
                        defer hunk_iter.allocator.free(line);
                        try writers.out.print("{s} {s}\n", .{
                            switch (edit) {
                                .eql => " ",
                                .ins => "+",
                                .del => "-",
                            },
                            line,
                        });
                    }
                }
            }
        },
        .branch => |branch_cmd| {
            switch (branch_cmd) {
                .list => {
                    var head_buffer = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
                    const current_branch_name = switch (try repo.head(&head_buffer)) {
                        .ref => |ref| ref.name,
                        .oid => "",
                    };

                    var ref_list = try repo.listBranches(allocator);
                    defer ref_list.deinit();

                    for (ref_list.refs.values()) |ref| {
                        const prefix = if (std.mem.eql(u8, current_branch_name, ref.name)) "*" else " ";
                        try writers.out.print("{s} {s}\n", .{ prefix, ref.name });
                    }
                },
                .add => |add_branch| try repo.addBranch(add_branch),
                .remove => |rm_branch| try repo.removeBranch(rm_branch),
            }
        },
        .switch_mount, .reset_mount, .reset_added => |switch_mount_cmd| {
            var switch_result = try repo.switchMount(allocator, switch_mount_cmd);
            defer switch_result.deinit();
            switch (switch_result.result) {
                .success => {},
                .conflict => |conflict| {
                    try writers.err.print(
                        \\conflicts detected in the following file paths:
                        \\
                    , .{});
                    for (conflict.stale_files.keys()) |path| {
                        try writers.err.print("  {s}\n", .{path});
                    }
                    for (conflict.stale_dirs.keys()) |path| {
                        try writers.err.print("  {s}\n", .{path});
                    }
                    for (conflict.untracked_overwritten.keys()) |path| {
                        try writers.err.print("  {s}\n", .{path});
                    }
                    for (conflict.untracked_removed.keys()) |path| {
                        try writers.err.print("  {s}\n", .{path});
                    }
                    try writers.err.print(
                        \\if you really want to continue, throw caution
                        \\into the wind by adding the -f flag.
                        \\
                    , .{});
                    return error.PrintedError;
                },
            }
        },
        .reset_head => |reset_head_cmd| {
            if (!try repo.checkExists(allocator, reset_head_cmd)) {
                try writers.err.print("ref or oid does not exist", .{});
                return error.PrintedError;
            }
            try repo.resetHead(reset_head_cmd);
        },
        .restore => |restore_cmd| try repo.restore(allocator, restore_cmd.path),
        .log => {
            var commit_iter = try repo.log(allocator, null);
            defer commit_iter.deinit();
            while (try commit_iter.next()) |commit_object| {
                defer commit_object.deinit();
                try writers.out.print("commit {s}\n", .{commit_object.oid});
                if (commit_object.content.commit.metadata.author) |author| {
                    try writers.out.print("Author {s}\n", .{author});
                }
                try writers.out.print("\n", .{});

                try commit_object.object_reader.seekTo(commit_object.content.commit.message_position);
                while (try commit_object.object_reader.reader.reader().readUntilDelimiterOrEofAlloc(allocator, '\n', repo_opts.max_read_size)) |line| {
                    defer allocator.free(line);
                    try writers.out.print("    {s}\n", .{line});
                }
                try writers.out.print("\n", .{});
            }
        },
        .merge => |merge_cmd| {
            var result = try repo.merge(allocator, merge_cmd);
            defer result.deinit();
            try printMergeResult(repo_kind, repo_opts, &result, writers);
        },
        .cherry_pick => |cherry_pick_cmd| {
            var result = try repo.merge(allocator, cherry_pick_cmd);
            defer result.deinit();
            try printMergeResult(repo_kind, repo_opts, &result, writers);
        },
        .config => |config_cmd| {
            switch (config_cmd) {
                .list => {
                    var conf = try repo.config(allocator);
                    defer conf.deinit();

                    for (conf.sections.keys(), conf.sections.values()) |section_name, variables| {
                        for (variables.keys(), variables.values()) |name, value| {
                            try writers.out.print("{s}.{s}={s}\n", .{ section_name, name, value });
                        }
                    }
                },
                .add => |config_add_cmd| try repo.addConfig(allocator, config_add_cmd),
                .remove => |config_remove_cmd| try repo.removeConfig(allocator, config_remove_cmd),
            }
        },
        .remote => |remote_cmd| {
            switch (remote_cmd) {
                .list => {
                    var rem = try repo.remote(allocator);
                    defer rem.deinit();

                    for (rem.sections.keys(), rem.sections.values()) |section_name, variables| {
                        for (variables.keys(), variables.values()) |name, value| {
                            try writers.out.print("{s}.{s}={s}\n", .{ section_name, name, value });
                        }
                    }
                },
                .add => |remote_add_cmd| try repo.addRemote(allocator, remote_add_cmd),
                .remove => |remote_remove_cmd| try repo.removeRemote(allocator, remote_remove_cmd),
            }
        },
        .fetch => |fetch_cmd| {
            _ = try repo.fetch(allocator, fetch_cmd.remote_name);
        },
        .pull => |pull_cmd| {
            var result = try repo.pull(allocator, pull_cmd.remote_name, pull_cmd.remote_ref_name);
            defer result.deinit();
            try printMergeResult(repo_kind, repo_opts, &result.merge, writers);
        },
    }
}

fn printMergeResult(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    merge_result: *const mrg.Merge(repo_kind, repo_opts),
    writers: Writers,
) !void {
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
            return error.PrintedError;
        },
    }
}

/// this is the main "main". it's even mainier than "run".
/// this is the real deal. there is no main more main than this.
/// at least, not that i know of. i guess internally zig probably
/// has an earlier entrypoint which is even mainier than this.
pub fn main() !u8 {
    const allocator = std.heap.page_allocator;
    var args = std.ArrayList([]const u8).init(allocator);
    defer args.deinit();

    var arg_it = try std.process.argsWithAllocator(allocator);
    defer arg_it.deinit();
    _ = arg_it.skip();
    while (arg_it.next()) |arg| {
        try args.append(arg);
    }

    const writers = Writers{ .out = std.io.getStdOut().writer().any(), .err = std.io.getStdErr().writer().any() };
    runPrint(.xit, .{}, allocator, args.items, std.fs.cwd(), writers) catch |err| switch (err) {
        error.PrintedError => return 1,
        else => |e| return e,
    };

    return 0;
}
