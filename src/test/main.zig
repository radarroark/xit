//! end-to-end test using the main entrypoint: `main.run`.
//! runs with both git and xit modes, using libgit2 to
//! validate git mode.

const std = @import("std");
const builtin = @import("builtin");
const xit = @import("xit");
const main = xit.main;
const hash = xit.hash;
const idx = xit.index;
const obj = xit.object;
const rf = xit.ref;
const rp = xit.repo;
const df = xit.diff;
const mrg = xit.merge;

const c = @cImport({
    @cInclude("git2.h");
});

test "main" {
    // read and write objects in small increments to help uncover bugs
    const last_hash_git = try testMain(.git, .{ .read_size = 1, .is_test = true });
    const last_hash_xit = try testMain(.xit, .{ .read_size = 1, .is_test = true, .extra = .{
        .chunk_opts = .{ .min_size = 1, .avg_size = 2, .max_size = 4, .normalization = .level1 },
    } });
    try std.testing.expectEqualStrings(&last_hash_git, &last_hash_xit);

    // make sure sha256 works on the xit side
    _ = try testMain(.xit, .{ .hash = .sha256, .is_test = true });
}

fn testMain(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) ![hash.hexLen(repo_opts.hash)]u8 {
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-main";

    // start libgit
    if (repo_kind == .git) _ = c.git_libgit2_init();
    defer _ = if (repo_kind == .git) c.git_libgit2_shutdown();

    // create the temp dir
    const cwd = std.fs.cwd();
    var temp_dir_or_err = cwd.openDir(temp_dir_name, .{});
    if (temp_dir_or_err) |*temp_dir| {
        temp_dir.close();
        try cwd.deleteTree(temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.makeOpenPath(temp_dir_name, .{});
    defer cwd.deleteTree(temp_dir_name) catch {};
    defer temp_dir.close();

    // init repo
    try main.run(repo_kind, repo_opts, allocator, &.{ "init", "repo" }, temp_dir, .{});

    // get the main dir
    var repo_dir = try temp_dir.openDir("repo", .{});
    defer repo_dir.close();

    // init repo-specific state
    const TestState = switch (repo_kind) {
        .git => struct {
            git_dir: std.fs.Dir,
        },
        .xit => struct {
            xit_dir: std.fs.Dir,
            db_file: std.fs.File,
        },
    };
    var test_state: TestState = switch (repo_kind) {
        .git => .{
            .git_dir = try repo_dir.openDir(".git", .{}),
        },
        .xit => blk: {
            const xit_dir = try repo_dir.openDir(".xit", .{});
            break :blk .{
                .xit_dir = xit_dir,
                .db_file = try xit_dir.openFile("db", .{ .mode = .read_write }),
            };
        },
    };
    defer switch (repo_kind) {
        .git => test_state.git_dir.close(),
        .xit => {
            test_state.db_file.close();
            test_state.xit_dir.close();
        },
    };

    // get repo path for libgit
    var repo_path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
    const repo_path: [*c]const u8 = @ptrCast(try repo_dir.realpath(".", &repo_path_buffer));

    // make sure we can get status before first commit
    {
        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var status = try repo.status(allocator);
        defer status.deinit();
    }

    const hello_txt_content =
        \\1
        \\2
        \\3
        \\4
        \\5
        \\6
        \\7
        \\8
        \\9
        \\10
        \\11
        \\12
        \\13
        \\14
        \\15
        \\16
        \\17
        \\18
        \\19
    ;

    // add and commit
    {
        // make file
        var hello_txt = try repo_dir.createFile("hello.txt", .{});
        defer hello_txt.close();
        try hello_txt.writeAll(hello_txt_content);

        // make file
        var readme = try repo_dir.createFile("README", .{ .read = true });
        defer readme.close();
        try readme.writeAll("My cool project");

        // make file
        var license = try repo_dir.createFile("LICENSE", .{});
        defer license.close();
        try license.writeAll("do whatever you want");

        // make file
        var tests = try repo_dir.createFile("tests", .{});
        defer tests.close();
        try tests.writeAll("testing...");

        // make file
        var run_sh = try repo_dir.createFile("run.sh", .{});
        defer run_sh.close();
        try run_sh.writeAll("#!/bin/sh");

        // make file in a dir
        var docs_dir = try repo_dir.makeOpenPath("docs", .{});
        defer docs_dir.close();
        var design_md = try docs_dir.createFile("design.md", .{});
        defer design_md.close();
        try design_md.writeAll("design stuff");

        // add the files
        try main.run(repo_kind, repo_opts, allocator, &.{ "add", "." }, repo_dir, .{});

        // make a commit
        // we're calling this one differently to test a few things:
        // 1. setting the hash to `.none` causes it to autodetect the repo's hash.
        // 2. the cwd is docs_dir, to make sure we can run commands in any sub dir.
        // 3. we're using runPrint instead of run, which prints user-friendly errors
        //    (no difference in the tests but I just want to make sure it works)
        try main.runPrint(repo_kind, repo_opts.withHash(.none), allocator, &.{ "commit", "-m", "first commit" }, docs_dir, .{});

        switch (repo_kind) {
            .git => {
                // check that the commit object was created
                {
                    var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
                    defer repo.deinit();
                    const head_file_buffer = try rf.readHeadRecur(repo_kind, repo_opts, .{ .core = &repo.core, .extra = .{} });
                    var objects_dir = try test_state.git_dir.openDir("objects", .{});
                    defer objects_dir.close();
                    var hash_prefix_dir = try objects_dir.openDir(head_file_buffer[0..2], .{});
                    defer hash_prefix_dir.close();
                    var hash_suffix_file = try hash_prefix_dir.openFile(head_file_buffer[2..], .{});
                    defer hash_suffix_file.close();
                }

                // read the commit with libgit
                {
                    var repo: ?*c.git_repository = null;
                    try std.testing.expectEqual(0, c.git_repository_open(&repo, repo_path));
                    defer c.git_repository_free(repo);
                    var head: ?*c.git_reference = null;
                    try std.testing.expectEqual(0, c.git_repository_head(&head, repo));
                    defer c.git_reference_free(head);
                    const oid = c.git_reference_target(head);
                    try std.testing.expect(null != oid);
                    var commit: ?*c.git_commit = null;
                    try std.testing.expectEqual(0, c.git_commit_lookup(&commit, repo, oid));
                    defer c.git_commit_free(commit);
                    try std.testing.expectEqualStrings("first commit", std.mem.sliceTo(c.git_commit_message(commit), 0));
                }

                // make sure we are hashing files the same way git does
                {
                    try readme.seekTo(0);
                    const meta = try readme.metadata();
                    const file_size = meta.size();
                    const header = try std.fmt.allocPrint(allocator, "blob {}\x00", .{file_size});
                    defer allocator.free(header);

                    var sha1_bytes_buffer = [_]u8{0} ** hash.byteLen(repo_opts.hash);
                    try hash.hashReader(repo_opts.hash, repo_opts.read_size, readme.reader(), header, &sha1_bytes_buffer);
                    const sha1_hex = std.fmt.bytesToHex(&sha1_bytes_buffer, .lower);

                    var oid: c.git_oid = undefined;
                    try std.testing.expectEqual(0, c.git_odb_hashfile(&oid, temp_dir_name ++ "/repo/README", c.GIT_OBJECT_BLOB));
                    const oid_str = c.git_oid_tostr_s(&oid);
                    try std.testing.expect(oid_str != null);

                    try std.testing.expectEqualStrings(&sha1_hex, std.mem.sliceTo(oid_str, 0));
                }
            },
            .xit => {
                // check that the commit object was created
                var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
                defer repo.deinit();
                var moment = try repo.core.latestMoment();
                const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
                const head_file_buffer = try rf.readHeadRecur(repo_kind, repo_opts, state);
                const chunk_info_cursor_maybe = try moment.cursor.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hash.hashInt(repo_opts.hash, "object-id->chunk-info") } },
                    .{ .hash_map_get = .{ .value = try hash.hexToInt(repo_opts.hash, &head_file_buffer) } },
                });
                try std.testing.expect(chunk_info_cursor_maybe != null);
            },
        }
    }

    // get HEAD contents
    const commit1 = blk: {
        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
        break :blk try rf.readHeadRecur(repo_kind, repo_opts, state);
    };

    const new_hello_txt_content =
        \\1
        \\2
        \\3
        \\4
        \\5.0
        \\6
        \\7
        \\8
        \\9.0
        \\10.0
        \\11
        \\12
        \\13
        \\14
        \\15.0
        \\16
        \\17
        \\18
        \\19
    ;

    // make another commit
    {
        // change a file
        const hello_txt = try repo_dir.openFile("hello.txt", .{ .mode = .read_write });
        defer hello_txt.close();
        try hello_txt.writeAll(new_hello_txt_content);
        try hello_txt.setEndPos(try hello_txt.getPos());

        // replace a file with a directory
        try repo_dir.deleteFile("tests");
        var tests_dir = try repo_dir.makeOpenPath("tests", .{});
        defer tests_dir.close();
        var main_test_zig = try tests_dir.createFile("main_test.zig", .{});
        defer main_test_zig.close();

        // make a few dirs
        var src_dir = try repo_dir.makeOpenPath("src", .{});
        defer src_dir.close();
        var src_zig_dir = try src_dir.makeOpenPath("zig", .{});
        defer src_zig_dir.close();

        // make a file in the dir
        var main_zig = try src_zig_dir.createFile("main.zig", .{});
        defer main_zig.close();
        try main_zig.writeAll("pub fn main() !void {}");

        // make file in a nested dir
        var two_dir = try repo_dir.makeOpenPath("one/two", .{});
        defer two_dir.close();
        var three_txt = try two_dir.createFile("three.txt", .{});
        defer three_txt.close();
        try three_txt.writeAll("one, two, three!");

        // change permissions of a file
        if (builtin.os.tag != .windows) {
            const run_sh = try repo_dir.openFile("run.sh", .{ .mode = .read_write });
            defer run_sh.close();
            try run_sh.setPermissions(std.fs.File.Permissions{ .inner = std.fs.File.PermissionsUnix{ .mode = 0o755 } });
        }

        // mount diff
        {
            var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();
            var status = try repo.status(allocator);
            defer status.deinit();
            var file_iter = try repo.filePairs(allocator, .{
                .mount = .{
                    .conflict_diff_kind = .target,
                    .status = &status,
                },
            });

            while (try file_iter.next()) |*line_iter_pair_ptr| {
                var line_iter_pair = line_iter_pair_ptr.*;
                defer line_iter_pair.deinit();
                var hunk_iter = try df.HunkIterator(repo_kind, repo_opts).init(allocator, &line_iter_pair.a, &line_iter_pair.b);
                defer hunk_iter.deinit();
                if (std.mem.eql(u8, "hello.txt", line_iter_pair.path)) {
                    try std.testing.expectEqualStrings("diff --git a/hello.txt b/hello.txt", hunk_iter.header_lines.items[0]);
                    const expected_hunks = &[_][]const df.Edit{
                        &[_]df.Edit{
                            .{ .eql = .{ .old_line = .{ .num = 1 }, .new_line = .{ .num = 1 } } },
                            .{ .eql = .{ .old_line = .{ .num = 2 }, .new_line = .{ .num = 2 } } },
                            .{ .eql = .{ .old_line = .{ .num = 3 }, .new_line = .{ .num = 3 } } },
                            .{ .del = .{ .old_line = .{ .num = 4 } } },
                            .{ .ins = .{ .new_line = .{ .num = 4 } } },
                            .{ .eql = .{ .old_line = .{ .num = 5 }, .new_line = .{ .num = 5 } } },
                            .{ .eql = .{ .old_line = .{ .num = 6 }, .new_line = .{ .num = 6 } } },
                            .{ .eql = .{ .old_line = .{ .num = 7 }, .new_line = .{ .num = 7 } } },
                        },
                        &[_]df.Edit{
                            .{ .del = .{ .old_line = .{ .num = 8 } } },
                            .{ .del = .{ .old_line = .{ .num = 9 } } },
                            .{ .ins = .{ .new_line = .{ .num = 8 } } },
                            .{ .ins = .{ .new_line = .{ .num = 9 } } },
                            .{ .eql = .{ .old_line = .{ .num = 10 }, .new_line = .{ .num = 10 } } },
                            .{ .eql = .{ .old_line = .{ .num = 11 }, .new_line = .{ .num = 11 } } },
                            .{ .eql = .{ .old_line = .{ .num = 12 }, .new_line = .{ .num = 12 } } },
                        },
                        &[_]df.Edit{
                            .{ .eql = .{ .old_line = .{ .num = 13 }, .new_line = .{ .num = 13 } } },
                            .{ .del = .{ .old_line = .{ .num = 14 } } },
                            .{ .ins = .{ .new_line = .{ .num = 14 } } },
                            .{ .eql = .{ .old_line = .{ .num = 15 }, .new_line = .{ .num = 15 } } },
                            .{ .eql = .{ .old_line = .{ .num = 16 }, .new_line = .{ .num = 16 } } },
                            .{ .eql = .{ .old_line = .{ .num = 17 }, .new_line = .{ .num = 17 } } },
                        },
                    };
                    for (expected_hunks) |expected_hunk| {
                        if (try hunk_iter.next()) |*actual_hunk_ptr| {
                            var actual_hunk = actual_hunk_ptr.*;
                            defer actual_hunk.deinit();
                            for (expected_hunk, actual_hunk.edits.items) |expected_edit, actual_edit| {
                                try std.testing.expectEqualDeep(expected_edit, actual_edit.withoutOffset());
                            }
                        } else {
                            return error.NullHunk;
                        }
                    }
                } else if (std.mem.eql(u8, "run.sh", line_iter_pair.path)) {
                    try std.testing.expectEqualStrings("diff --git a/run.sh b/run.sh", hunk_iter.header_lines.items[0]);
                    try std.testing.expectEqualStrings("old mode 100644", hunk_iter.header_lines.items[1]);
                    try std.testing.expectEqualStrings("new mode 100755", hunk_iter.header_lines.items[2]);
                } else if (std.mem.eql(u8, "tests", line_iter_pair.path)) {
                    try std.testing.expectEqualStrings("diff --git a/tests b/tests", hunk_iter.header_lines.items[0]);
                    try std.testing.expectEqualStrings("deleted file mode 100644", hunk_iter.header_lines.items[1]);
                } else {
                    return error.EntryNotExpected;
                }
            }

            if (builtin.os.tag != .windows) {
                try std.testing.expectEqual(3, file_iter.next_index);
            } else {
                try std.testing.expectEqual(2, file_iter.next_index);
            }
        }

        // delete a file
        try repo_dir.deleteFile("LICENSE");
        try main.run(repo_kind, repo_opts, allocator, &.{ "add", "LICENSE" }, repo_dir, .{});

        // delete a file and dir
        try repo_dir.deleteTree("docs");
        try main.run(repo_kind, repo_opts, allocator, &.{ "add", "docs/design.md" }, repo_dir, .{});

        // add new and modified files
        try main.run(repo_kind, repo_opts, allocator, &.{ "add", "hello.txt", "run.sh", "src/zig/main.zig" }, repo_dir, .{});

        // index diff
        {
            var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();
            var status = try repo.status(allocator);
            defer status.deinit();
            var file_iter = try repo.filePairs(allocator, .{
                .index = .{ .status = &status },
            });

            while (try file_iter.next()) |*line_iter_pair_ptr| {
                var line_iter_pair = line_iter_pair_ptr.*;
                defer line_iter_pair.deinit();
                var hunk_iter = try df.HunkIterator(repo_kind, repo_opts).init(allocator, &line_iter_pair.a, &line_iter_pair.b);
                defer hunk_iter.deinit();
                if (std.mem.eql(u8, "LICENSE", line_iter_pair.path)) {
                    try std.testing.expectEqualStrings("diff --git a/LICENSE b/LICENSE", hunk_iter.header_lines.items[0]);
                    try std.testing.expectEqualStrings("deleted file mode 100644", hunk_iter.header_lines.items[1]);
                } else if (std.mem.eql(u8, "docs/design.md", line_iter_pair.path)) {
                    try std.testing.expectEqualStrings("diff --git a/docs/design.md b/docs/design.md", hunk_iter.header_lines.items[0]);
                    try std.testing.expectEqualStrings("deleted file mode 100644", hunk_iter.header_lines.items[1]);
                } else if (std.mem.eql(u8, "hello.txt", line_iter_pair.path)) {
                    try std.testing.expectEqualStrings("diff --git a/hello.txt b/hello.txt", hunk_iter.header_lines.items[0]);
                } else if (std.mem.eql(u8, "run.sh", line_iter_pair.path)) {
                    try std.testing.expectEqualStrings("diff --git a/run.sh b/run.sh", hunk_iter.header_lines.items[0]);
                    try std.testing.expectEqualStrings("old mode 100644", hunk_iter.header_lines.items[1]);
                    try std.testing.expectEqualStrings("new mode 100755", hunk_iter.header_lines.items[2]);
                } else if (std.mem.eql(u8, "src/zig/main.zig", line_iter_pair.path)) {
                    try std.testing.expectEqualStrings("diff --git a/src/zig/main.zig b/src/zig/main.zig", hunk_iter.header_lines.items[0]);
                    try std.testing.expectEqualStrings("new file mode 100644", hunk_iter.header_lines.items[1]);
                } else {
                    return error.EntryNotExpected;
                }
            }

            if (builtin.os.tag != .windows) {
                try std.testing.expectEqual(5, file_iter.next_index);
            } else {
                try std.testing.expectEqual(4, file_iter.next_index);
            }
        }

        // add the remaining files
        try main.run(repo_kind, repo_opts, allocator, &.{ "add", "." }, repo_dir, .{});

        // make another commit
        try main.run(repo_kind, repo_opts, allocator, &.{ "commit", "-m", "second commit" }, repo_dir, .{});

        switch (repo_kind) {
            .git => {
                // check that the commit object was created
                {
                    var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
                    defer repo.deinit();
                    const head_file_buffer = try rf.readHeadRecur(repo_kind, repo_opts, .{ .core = &repo.core, .extra = .{} });
                    var objects_dir = try test_state.git_dir.openDir("objects", .{});
                    defer objects_dir.close();
                    var hash_prefix_dir = try objects_dir.openDir(head_file_buffer[0..2], .{});
                    defer hash_prefix_dir.close();
                    var hash_suffix_file = try hash_prefix_dir.openFile(head_file_buffer[2..], .{});
                    defer hash_suffix_file.close();
                }

                // read the commit with libgit
                {
                    var repo: ?*c.git_repository = null;
                    try std.testing.expectEqual(0, c.git_repository_open(&repo, repo_path));
                    defer c.git_repository_free(repo);
                    var head: ?*c.git_reference = null;
                    try std.testing.expectEqual(0, c.git_repository_head(&head, repo));
                    defer c.git_reference_free(head);
                    const oid = c.git_reference_target(head);
                    try std.testing.expect(null != oid);
                    var commit: ?*c.git_commit = null;
                    try std.testing.expectEqual(0, c.git_commit_lookup(&commit, repo, oid));
                    defer c.git_commit_free(commit);
                    try std.testing.expectEqualStrings("second commit", std.mem.sliceTo(c.git_commit_message(commit), 0));
                }
            },
            .xit => {
                // check that the commit object was created
                var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
                defer repo.deinit();
                var moment = try repo.core.latestMoment();
                const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
                const head_file_buffer = try rf.readHeadRecur(repo_kind, repo_opts, state);
                const chunk_info_cursor_maybe = try moment.cursor.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hash.hashInt(repo_opts.hash, "object-id->chunk-info") } },
                    .{ .hash_map_get = .{ .value = try hash.hexToInt(repo_opts.hash, &head_file_buffer) } },
                });
                try std.testing.expect(chunk_info_cursor_maybe != null);
            },
        }
    }

    // get HEAD contents
    const commit2 = blk: {
        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
        break :blk try rf.readHeadRecur(repo_kind, repo_opts, state);
    };

    // tree diff
    {
        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var tree_diff = try repo.treeDiff(allocator, &commit1, &commit2);
        defer tree_diff.deinit();
        var file_iter = try repo.filePairs(allocator, .{
            .tree = .{ .tree_diff = &tree_diff },
        });

        while (try file_iter.next()) |*line_iter_pair_ptr| {
            var line_iter_pair = line_iter_pair_ptr.*;
            defer line_iter_pair.deinit();
            var hunk_iter = try df.HunkIterator(repo_kind, repo_opts).init(allocator, &line_iter_pair.a, &line_iter_pair.b);
            defer hunk_iter.deinit();
            if (std.mem.eql(u8, "LICENSE", line_iter_pair.path)) {
                try std.testing.expectEqualStrings("diff --git a/LICENSE b/LICENSE", hunk_iter.header_lines.items[0]);
                try std.testing.expectEqualStrings("deleted file mode 100644", hunk_iter.header_lines.items[1]);
            } else if (std.mem.eql(u8, "docs/design.md", line_iter_pair.path)) {
                try std.testing.expectEqualStrings("diff --git a/docs/design.md b/docs/design.md", hunk_iter.header_lines.items[0]);
                try std.testing.expectEqualStrings("deleted file mode 100644", hunk_iter.header_lines.items[1]);
            } else if (std.mem.eql(u8, "hello.txt", line_iter_pair.path)) {
                try std.testing.expectEqualStrings("diff --git a/hello.txt b/hello.txt", hunk_iter.header_lines.items[0]);
            } else if (std.mem.eql(u8, "run.sh", line_iter_pair.path)) {
                try std.testing.expectEqualStrings("diff --git a/run.sh b/run.sh", hunk_iter.header_lines.items[0]);
                try std.testing.expectEqualStrings("old mode 100644", hunk_iter.header_lines.items[1]);
                try std.testing.expectEqualStrings("new mode 100755", hunk_iter.header_lines.items[2]);
            } else if (std.mem.eql(u8, "src/zig/main.zig", line_iter_pair.path)) {
                try std.testing.expectEqualStrings("diff --git a/src/zig/main.zig b/src/zig/main.zig", hunk_iter.header_lines.items[0]);
                try std.testing.expectEqualStrings("new file mode 100644", hunk_iter.header_lines.items[1]);
            } else if (std.mem.eql(u8, "tests/main_test.zig", line_iter_pair.path)) {
                try std.testing.expectEqualStrings("diff --git a/tests/main_test.zig b/tests/main_test.zig", hunk_iter.header_lines.items[0]);
                try std.testing.expectEqualStrings("new file mode 100644", hunk_iter.header_lines.items[1]);
            } else if (std.mem.eql(u8, "tests", line_iter_pair.path)) {
                try std.testing.expectEqualStrings("diff --git a/tests b/tests", hunk_iter.header_lines.items[0]);
                try std.testing.expectEqualStrings("deleted file mode 100644", hunk_iter.header_lines.items[1]);
            } else if (std.mem.eql(u8, "one/two/three.txt", line_iter_pair.path)) {
                try std.testing.expectEqualStrings("diff --git a/one/two/three.txt b/one/two/three.txt", hunk_iter.header_lines.items[0]);
                try std.testing.expectEqualStrings("new file mode 100644", hunk_iter.header_lines.items[1]);
            } else {
                return error.EntryNotExpected;
            }
        }

        if (builtin.os.tag != .windows) {
            try std.testing.expectEqual(8, file_iter.next_index);
        } else {
            try std.testing.expectEqual(7, file_iter.next_index);
        }
    }

    // try to switch to first commit after making conflicting change
    {
        {
            // make a new file (and add it to the index) that conflicts with one from commit1
            {
                var license = try repo_dir.createFile("LICENSE", .{});
                defer license.close();
                try license.writeAll("different license");
                try main.run(repo_kind, repo_opts, allocator, &.{ "add", "LICENSE" }, repo_dir, .{});
            }

            // check out commit1 and make sure the conflict is found
            {
                var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
                defer repo.deinit();
                var switch_result = try repo.switchMount(allocator, .{ .target = .{ .oid = &commit1 } });
                defer switch_result.deinit();
                try std.testing.expect(.conflict == switch_result.result);
                try std.testing.expectEqual(1, switch_result.result.conflict.stale_files.count());
            }

            // delete the file
            {
                try repo_dir.deleteFile("LICENSE");
                try main.run(repo_kind, repo_opts, allocator, &.{ "add", "LICENSE" }, repo_dir, .{});
            }
        }

        {
            // make a new file (only in the mount) that conflicts with the descendent of a file from commit1
            {
                var docs = try repo_dir.createFile("docs", .{});
                defer docs.close();
                try docs.writeAll("i conflict with the docs dir in the first commit");
            }

            // check out commit1 and make sure the conflict is found
            {
                var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
                defer repo.deinit();
                var switch_result = try repo.switchMount(allocator, .{ .target = .{ .oid = &commit1 } });
                defer switch_result.deinit();
                try std.testing.expect(.conflict == switch_result.result);
            }

            // delete the file
            try repo_dir.deleteFile("docs");
        }

        {
            // change a file so it conflicts with the one in commit1
            {
                const hello_txt = try repo_dir.openFile("hello.txt", .{ .mode = .read_write });
                defer hello_txt.close();
                try hello_txt.seekTo(0);
                try hello_txt.writeAll("12345");
                try hello_txt.setEndPos(try hello_txt.getPos());
            }

            // check out commit1 and make sure the conflict is found
            {
                var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
                defer repo.deinit();
                var switch_result = try repo.switchMount(allocator, .{ .target = .{ .oid = &commit1 } });
                defer switch_result.deinit();
                try std.testing.expect(.conflict == switch_result.result);
                try std.testing.expectEqual(1, switch_result.result.conflict.stale_files.count());
            }

            // change the file back
            {
                const hello_txt = try repo_dir.openFile("hello.txt", .{ .mode = .read_write });
                defer hello_txt.close();
                try hello_txt.writeAll(new_hello_txt_content);
                try hello_txt.setEndPos(try hello_txt.getPos());
            }
        }

        {
            // create a dir with a file that conflicts with one in commit1
            {
                var license_dir = try repo_dir.makeOpenPath("LICENSE", .{});
                defer license_dir.close();
                const foo_txt = try license_dir.createFile("foo.txt", .{});
                defer foo_txt.close();
                try foo_txt.writeAll("foo");
            }

            // check out commit1 and make sure the conflict is found
            {
                var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
                defer repo.deinit();
                var switch_result = try repo.switchMount(allocator, .{ .target = .{ .oid = &commit1 } });
                defer switch_result.deinit();
                try std.testing.expect(.conflict == switch_result.result);
                try std.testing.expectEqual(1, switch_result.result.conflict.stale_dirs.count());
            }

            // delete the dir
            try repo_dir.deleteTree("LICENSE");
        }
    }

    // switch to first commit
    try main.run(repo_kind, repo_opts, allocator, &.{ "switch", &commit1 }, repo_dir, .{});

    // the mount was updated
    {
        const hello_txt = try repo_dir.openFile("hello.txt", .{ .mode = .read_only });
        defer hello_txt.close();
        const content = try hello_txt.readToEndAlloc(allocator, 1024);
        defer allocator.free(content);
        try std.testing.expectEqualStrings(hello_txt_content, content);

        const license = try repo_dir.openFile("LICENSE", .{ .mode = .read_only });
        defer license.close();

        var two_dir_or_err = repo_dir.openDir("one/two", .{});
        if (two_dir_or_err) |*dir| {
            dir.close();
            return error.UnexpectedDir;
        } else |_| {}

        var one_dir_or_err = repo_dir.openDir("one", .{});
        if (one_dir_or_err) |*dir| {
            dir.close();
            return error.UnexpectedDir;
        } else |_| {}
    }

    // switch to master
    try main.run(repo_kind, repo_opts, allocator, &.{ "switch", "master" }, repo_dir, .{});

    // the mount was updated
    {
        const hello_txt = try repo_dir.openFile("hello.txt", .{ .mode = .read_only });
        defer hello_txt.close();
        const content = try hello_txt.readToEndAlloc(allocator, 1024);
        defer allocator.free(content);
        try std.testing.expectEqualStrings(new_hello_txt_content, content);

        const license_or_err = repo_dir.openFile("LICENSE", .{ .mode = .read_only });
        try std.testing.expectEqual(error.FileNotFound, license_or_err);
    }

    // replacing file with dir and dir with file
    {
        // replace file with directory
        {
            try repo_dir.deleteFile("hello.txt");
            var hello_txt_dir = try repo_dir.makeOpenPath("hello.txt", .{});
            defer hello_txt_dir.close();
            var nested_txt = try hello_txt_dir.createFile("nested.txt", .{});
            defer nested_txt.close();
            var nested2_txt = try hello_txt_dir.createFile("nested2.txt", .{});
            defer nested2_txt.close();
        }

        // add the new dir
        try main.run(repo_kind, repo_opts, allocator, &.{ "add", "hello.txt" }, repo_dir, .{});

        // read index
        {
            var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();
            var moment = try repo.core.latestMoment();
            const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
            var index = try idx.Index(repo_kind, repo_opts).init(allocator, state);
            defer index.deinit();
            try std.testing.expectEqual(7, index.entries.count());
            try std.testing.expect(index.entries.contains("README"));
            try std.testing.expect(index.entries.contains("src/zig/main.zig"));
            try std.testing.expect(index.entries.contains("tests/main_test.zig"));
            try std.testing.expect(index.entries.contains("hello.txt/nested.txt"));
            try std.testing.expect(index.entries.contains("hello.txt/nested2.txt"));
            try std.testing.expect(index.entries.contains("run.sh"));
            try std.testing.expect(index.entries.contains("one/two/three.txt"));
        }

        switch (repo_kind) {
            .git => {
                // read index with libgit
                var repo: ?*c.git_repository = null;
                try std.testing.expectEqual(0, c.git_repository_open(&repo, repo_path));
                defer c.git_repository_free(repo);
                var index: ?*c.git_index = null;
                try std.testing.expectEqual(0, c.git_repository_index(&index, repo));
                defer c.git_index_free(index);
                try std.testing.expectEqual(7, c.git_index_entrycount(index));
            },
            .xit => {
                // read the index in xitdb
                var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
                defer repo.deinit();
                var count: u32 = 0;
                var moment = try repo.core.latestMoment();
                if (try moment.getCursor(hash.hashInt(repo_opts.hash, "index"))) |index_cursor| {
                    var iter = try index_cursor.iterator();
                    defer iter.deinit();
                    while (try iter.next()) |_| {
                        count += 1;
                    }
                }
                try std.testing.expectEqual(7, count);
            },
        }

        // replace directory with file
        {
            var hello_txt_dir = try repo_dir.openDir("hello.txt", .{});
            defer hello_txt_dir.close();
            try hello_txt_dir.deleteFile("nested.txt");
            try hello_txt_dir.deleteFile("nested2.txt");
        }
        try repo_dir.deleteDir("hello.txt");
        var hello_txt2 = try repo_dir.createFile("hello.txt", .{});
        defer hello_txt2.close();

        // add the new file
        try main.run(repo_kind, repo_opts, allocator, &.{ "add", "hello.txt" }, repo_dir, .{});

        // read index
        {
            var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();
            var moment = try repo.core.latestMoment();
            const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
            var index = try idx.Index(repo_kind, repo_opts).init(allocator, state);
            defer index.deinit();
            try std.testing.expectEqual(6, index.entries.count());
            try std.testing.expect(index.entries.contains("README"));
            try std.testing.expect(index.entries.contains("src/zig/main.zig"));
            try std.testing.expect(index.entries.contains("tests/main_test.zig"));
            try std.testing.expect(index.entries.contains("hello.txt"));
            try std.testing.expect(index.entries.contains("run.sh"));
            try std.testing.expect(index.entries.contains("one/two/three.txt"));
        }

        switch (repo_kind) {
            .git => {
                // read index with libgit
                var repo: ?*c.git_repository = null;
                try std.testing.expectEqual(0, c.git_repository_open(&repo, repo_path));
                defer c.git_repository_free(repo);
                var index: ?*c.git_index = null;
                try std.testing.expectEqual(0, c.git_repository_index(&index, repo));
                defer c.git_index_free(index);
                try std.testing.expectEqual(6, c.git_index_entrycount(index));
            },
            .xit => {
                // read the index in xitdb
                var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
                defer repo.deinit();
                var count: u32 = 0;
                var moment = try repo.core.latestMoment();
                if (try moment.getCursor(hash.hashInt(repo_opts.hash, "index"))) |index_cursor| {
                    var iter = try index_cursor.iterator();
                    defer iter.deinit();
                    while (try iter.next()) |_| {
                        count += 1;
                    }
                }
                try std.testing.expectEqual(6, count);
            },
        }

        // a stale index lock file isn't hanging around
        if (repo_kind == .git) {
            const lock_file_or_err = test_state.git_dir.openFile("index.lock", .{ .mode = .read_only });
            try std.testing.expectEqual(error.FileNotFound, lock_file_or_err);
        }
    }

    // changing the index
    {
        // can't add a non-existent file
        try std.testing.expectEqual(error.AddIndexPathNotFound, main.run(repo_kind, repo_opts, allocator, &.{ "add", "no-such-file" }, repo_dir, .{}));

        // can't remove non-existent file
        try std.testing.expectEqual(error.RemoveIndexPathNotFound, main.run(repo_kind, repo_opts, allocator, &.{ "rm", "no-such-file" }, repo_dir, .{}));

        {
            // modify a file
            {
                const three_txt = try repo_dir.openFile("one/two/three.txt", .{ .mode = .read_write });
                defer three_txt.close();
                try three_txt.seekTo(0);
                try three_txt.writeAll("this is now modified");
                try three_txt.setEndPos(try three_txt.getPos());
            }

            // can't remove a file with unstaged changes
            try std.testing.expectEqual(error.CannotRemoveFileWithUnstagedChanges, main.run(repo_kind, repo_opts, allocator, &.{ "rm", "one/two/three.txt" }, repo_dir, .{}));

            // stage the changes
            try main.run(repo_kind, repo_opts, allocator, &.{ "add", "one/two/three.txt" }, repo_dir, .{});

            // modify it again
            {
                const three_txt = try repo_dir.openFile("one/two/three.txt", .{ .mode = .read_write });
                defer three_txt.close();
                try three_txt.seekTo(0);
                try three_txt.writeAll("this is now modified again");
                try three_txt.setEndPos(try three_txt.getPos());
            }

            // can't untrack a file with staged and unstaged changes
            try std.testing.expectEqual(error.CannotRemoveFileWithStagedAndUnstagedChanges, main.run(repo_kind, repo_opts, allocator, &.{ "untrack", "one/two/three.txt" }, repo_dir, .{}));

            // add, unadd, and then untrack modified file
            try main.run(repo_kind, repo_opts, allocator, &.{ "add", "one" }, repo_dir, .{});
            try main.run(repo_kind, repo_opts, allocator, &.{ "unadd", "one" }, repo_dir, .{});

            // still tracked because unadd just resets it back to the state from HEAD
            {
                var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
                defer repo.deinit();
                var moment = try repo.core.latestMoment();
                const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
                var index = try idx.Index(repo_kind, repo_opts).init(allocator, state);
                defer index.deinit();

                try std.testing.expect(index.entries.contains("one/two/three.txt"));
                try std.testing.expectEqual("one, two, three!".len, index.entries.get("one/two/three.txt").?[0].?.file_size);
            }

            try main.run(repo_kind, repo_opts, allocator, &.{ "untrack", "one/two/three.txt" }, repo_dir, .{});

            // not tracked anymore
            {
                var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
                defer repo.deinit();
                var moment = try repo.core.latestMoment();
                const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
                var index = try idx.Index(repo_kind, repo_opts).init(allocator, state);
                defer index.deinit();

                try std.testing.expect(!index.entries.contains("one/two/three.txt"));
            }

            // stage the changes to the file
            try main.run(repo_kind, repo_opts, allocator, &.{ "add", "one/two/three.txt" }, repo_dir, .{});

            // can't remove a file with staged changes
            try std.testing.expectEqual(error.CannotRemoveFileWithStagedChanges, main.run(repo_kind, repo_opts, allocator, &.{ "rm", "one/two/three.txt" }, repo_dir, .{}));

            // remove file by force
            try main.run(repo_kind, repo_opts, allocator, &.{ "rm", "one/two/three.txt", "-f" }, repo_dir, .{});

            // restore file's original content
            {
                const three_txt = try repo_dir.createFile("one/two/three.txt", .{});
                defer three_txt.close();
                try three_txt.seekTo(0);
                try three_txt.writeAll("one, two, three!");
                try three_txt.setEndPos(try three_txt.getPos());

                try main.run(repo_kind, repo_opts, allocator, &.{ "add", "one/two/three.txt" }, repo_dir, .{});
            }

            // remove a file
            {
                try main.run(repo_kind, repo_opts, allocator, &.{ "rm", "one/two/three.txt" }, repo_dir, .{});

                var file_or_err = repo_dir.openFile("one/two/three.txt", .{ .mode = .read_only });
                if (file_or_err) |*file| {
                    file.close();
                    return error.UnexpectedFile;
                } else |_| {}
            }
        }

        {
            // create a new file
            var new_file_txt = try repo_dir.createFile("new-file.txt", .{});
            defer {
                new_file_txt.close();
                repo_dir.deleteFile("new-file.txt") catch {};
            }
            try new_file_txt.writeAll("this is a new file");

            // can't remove unindexed file
            try std.testing.expectEqual(error.RemoveIndexPathNotFound, main.run(repo_kind, repo_opts, allocator, &.{ "rm", "new-file.txt" }, repo_dir, .{}));

            // add file
            try main.run(repo_kind, repo_opts, allocator, &.{ "add", "new-file.txt" }, repo_dir, .{});

            // unadd the same file so it is untracked again
            try main.run(repo_kind, repo_opts, allocator, &.{ "unadd", "new-file.txt" }, repo_dir, .{});
        }
    }

    // status
    {
        // make file
        var goodbye_txt = try repo_dir.createFile("goodbye.txt", .{});
        defer goodbye_txt.close();
        try goodbye_txt.writeAll("Goodbye");

        // make dirs
        var a_dir = try repo_dir.makeOpenPath("a", .{});
        defer a_dir.close();
        var b_dir = try repo_dir.makeOpenPath("b", .{});
        defer b_dir.close();
        var c_dir = try repo_dir.makeOpenPath("c", .{});
        defer c_dir.close();

        // make file in dir
        var farewell_txt = try a_dir.createFile("farewell.txt", .{});
        defer farewell_txt.close();
        try farewell_txt.writeAll("Farewell");

        // modify indexed files
        {
            const hello_txt = try repo_dir.openFile("hello.txt", .{ .mode = .read_write });
            defer hello_txt.close();
            try hello_txt.writeAll("hello, world again!");

            const readme = try repo_dir.openFile("README", .{ .mode = .read_write });
            defer readme.close();
            try readme.writeAll("My code project"); // size doesn't change

            var src_dir = try repo_dir.openDir("src", .{});
            defer src_dir.close();
            var zig_dir = try src_dir.openDir("zig", .{});
            defer zig_dir.close();
            try zig_dir.deleteFile("main.zig");
        }

        // mount changes
        {
            // get status
            var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();
            var status = try repo.status(allocator);
            defer status.deinit();

            // check the untracked entries
            try std.testing.expectEqual(2, status.untracked.count());
            try std.testing.expect(status.untracked.contains("a"));
            try std.testing.expect(status.untracked.contains("goodbye.txt"));

            // check the mount_modified entries
            try std.testing.expectEqual(2, status.mount_modified.count());
            try std.testing.expect(status.mount_modified.contains("hello.txt"));
            try std.testing.expect(status.mount_modified.contains("README"));

            // check the mount_deleted entries
            try std.testing.expectEqual(1, status.mount_deleted.count());
            try std.testing.expect(status.mount_deleted.contains("src/zig/main.zig"));
        }

        // get status with libgit
        if (repo_kind == .git) {
            var repo: ?*c.git_repository = null;
            try std.testing.expectEqual(0, c.git_repository_open(&repo, repo_path));
            defer c.git_repository_free(repo);
            var status_list: ?*c.git_status_list = null;
            var status_options: c.git_status_options = undefined;
            try std.testing.expectEqual(0, c.git_status_options_init(&status_options, c.GIT_STATUS_OPTIONS_VERSION));
            status_options.show = c.GIT_STATUS_SHOW_WORKDIR_ONLY;
            status_options.flags = c.GIT_STATUS_OPT_INCLUDE_UNTRACKED;
            try std.testing.expectEqual(0, c.git_status_list_new(&status_list, repo, &status_options));
            defer c.git_status_list_free(status_list);
            try std.testing.expectEqual(5, c.git_status_list_entrycount(status_list));
        }

        // index changes
        {
            // add file to index
            var d_txt = try c_dir.createFile("d.txt", .{});
            defer d_txt.close();
            try main.run(repo_kind, repo_opts, allocator, &.{ "add", "c/d.txt" }, repo_dir, .{});

            // remove file from index
            try main.run(repo_kind, repo_opts, allocator, &.{ "add", "src/zig/main.zig" }, repo_dir, .{});

            // get status
            var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();
            var status = try repo.status(allocator);
            defer status.deinit();

            // check the index_added entries
            try std.testing.expectEqual(1, status.index_added.count());
            try std.testing.expect(status.index_added.contains("c/d.txt"));

            // check the index_modified entries
            try std.testing.expectEqual(1, status.index_modified.count());
            try std.testing.expect(status.index_modified.contains("hello.txt"));

            // check the index_deleted entries
            try std.testing.expectEqual(2, status.index_deleted.count());
            try std.testing.expect(status.index_deleted.contains("src/zig/main.zig"));
            try std.testing.expect(status.index_deleted.contains("one/two/three.txt"));
        }
    }

    // restore
    {
        // there are two modified and two deleted files remaining
        {
            var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();
            var status = try repo.status(allocator);
            defer status.deinit();

            try std.testing.expectEqual(2, status.mount_modified.count());
            try std.testing.expectEqual(2, status.index_deleted.count());
        }

        try main.run(repo_kind, repo_opts, allocator, &.{ "restore", "README" }, repo_dir, .{});

        try main.run(repo_kind, repo_opts, allocator, &.{ "restore", "hello.txt" }, repo_dir, .{});

        // directories can be restored
        try main.run(repo_kind, repo_opts, allocator, &.{ "restore", "src" }, repo_dir, .{});

        // nested paths can be restored
        try main.run(repo_kind, repo_opts, allocator, &.{ "restore", "one/two/three.txt" }, repo_dir, .{});

        // remove changes to index
        try main.run(repo_kind, repo_opts, allocator, &.{ "add", "hello.txt", "src", "one" }, repo_dir, .{});

        // there are no modified or deleted files remaining
        {
            var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();
            var status = try repo.status(allocator);
            defer status.deinit();

            try std.testing.expectEqual(0, status.mount_modified.count());
            try std.testing.expectEqual(0, status.index_deleted.count());
        }
    }

    // parse objects
    {
        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };

        // read commit
        var commit_object = try obj.Object(repo_kind, repo_opts, .full).init(allocator, state, &commit2);
        defer commit_object.deinit();
        try std.testing.expectEqualStrings("second commit", commit_object.content.commit.metadata.message.?);

        // read tree
        var tree_object = try obj.Object(repo_kind, repo_opts, .full).init(allocator, state, &commit_object.content.commit.tree);
        defer tree_object.deinit();
        try std.testing.expectEqual(6, tree_object.content.tree.entries.count());
    }

    // create a branch
    try main.run(repo_kind, repo_opts, allocator, &.{ "branch", "add", "stuff" }, repo_dir, .{});

    // switch to the branch
    try main.run(repo_kind, repo_opts, allocator, &.{ "switch", "stuff" }, repo_dir, .{});

    // check the refs
    {
        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
        try std.testing.expectEqual(commit2, try rf.readHeadRecur(repo_kind, repo_opts, state));
        try std.testing.expectEqual(commit2, try rf.readRecur(repo_kind, repo_opts, state, .{ .ref = .{ .kind = .head, .name = "stuff" } }));
    }

    // list all branches
    {
        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var ref_list = try repo.listBranches(allocator);
        defer ref_list.deinit();
        try std.testing.expectEqual(2, ref_list.refs.count());
    }

    // get the current branch
    {
        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var current_branch_buffer = [_]u8{0} ** rf.MAX_REF_CONTENT_SIZE;
        const head = try repo.head(&current_branch_buffer);
        try std.testing.expectEqualStrings("stuff", head.ref.name);
    }

    // get the current branch with libgit
    if (repo_kind == .git) {
        var repo: ?*c.git_repository = null;
        try std.testing.expectEqual(0, c.git_repository_open(&repo, repo_path));
        defer c.git_repository_free(repo);
        var head: ?*c.git_reference = null;
        try std.testing.expectEqual(0, c.git_repository_head(&head, repo));
        defer c.git_reference_free(head);
        const branch_name = c.git_reference_shorthand(head);
        try std.testing.expectEqualStrings("stuff", std.mem.sliceTo(branch_name, 0));
    }

    // can't delete current branch
    {
        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        try std.testing.expectEqual(error.CannotDeleteCurrentBranch, repo.removeBranch(.{ .name = "stuff" }));
    }

    // make a few commits on the stuff branch
    {
        const hello_txt = try repo_dir.openFile("hello.txt", .{ .mode = .read_write });
        defer hello_txt.close();

        try hello_txt.seekTo(0);
        try hello_txt.writeAll("hello, world on the stuff branch, commit 3!");
        try hello_txt.setEndPos(try hello_txt.getPos());

        // add the files
        try main.run(repo_kind, repo_opts, allocator, &.{ "add", "hello.txt" }, repo_dir, .{});

        // make a commit
        try main.run(repo_kind, repo_opts, allocator, &.{ "commit", "-m", "third commit" }, repo_dir, .{});

        try hello_txt.seekTo(0);
        try hello_txt.writeAll("hello, world on the stuff branch, commit 4!");
        try hello_txt.setEndPos(try hello_txt.getPos());

        // add the files
        try main.run(repo_kind, repo_opts, allocator, &.{ "add", "hello.txt" }, repo_dir, .{});

        // make a commit
        try main.run(repo_kind, repo_opts, allocator, &.{ "commit", "-m", "fourth commit" }, repo_dir, .{});
    }

    // get HEAD contents
    const commit4_stuff = blk: {
        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
        break :blk try rf.readHeadRecur(repo_kind, repo_opts, state);
    };

    // create a branch with slashes
    try main.run(repo_kind, repo_opts, allocator, &.{ "branch", "add", "a/b/c" }, repo_dir, .{});

    // make sure the ref is created with subdirs
    if (repo_kind == .git) {
        const ref_file = try test_state.git_dir.openFile("refs/heads/a/b/c", .{});
        defer ref_file.close();
    }

    // list all branches
    {
        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var ref_list = try repo.listBranches(allocator);
        defer ref_list.deinit();
        try std.testing.expectEqual(3, ref_list.refs.count());
        try std.testing.expect(ref_list.refs.contains("a/b/c"));
        try std.testing.expect(ref_list.refs.contains("stuff"));
        try std.testing.expect(ref_list.refs.contains("master"));
    }

    // remove the branch
    try main.run(repo_kind, repo_opts, allocator, &.{ "branch", "rm", "a/b/c" }, repo_dir, .{});

    // make sure the subdirs are deleted
    if (repo_kind == .git) {
        try std.testing.expectEqual(error.FileNotFound, test_state.git_dir.openFile("refs/heads/a/b/c", .{}));
        try std.testing.expectEqual(error.FileNotFound, test_state.git_dir.openDir("refs/heads/a/b", .{}));
        try std.testing.expectEqual(error.FileNotFound, test_state.git_dir.openDir("refs/heads/a", .{}));
    }

    // switch to master
    try main.run(repo_kind, repo_opts, allocator, &.{ "switch", "master" }, repo_dir, .{});

    // modify file and commit
    {
        const goodbye_txt = try repo_dir.openFile("goodbye.txt", .{ .mode = .read_write });
        defer goodbye_txt.close();
        try goodbye_txt.writeAll("goodbye, world once again!");

        // add the files
        try main.run(repo_kind, repo_opts, allocator, &.{ "add", "goodbye.txt" }, repo_dir, .{});

        // make a commit
        try main.run(repo_kind, repo_opts, allocator, &.{ "commit", "-m", "third commit" }, repo_dir, .{});
    }

    // get HEAD contents
    const commit3 = blk: {
        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
        break :blk try rf.readHeadRecur(repo_kind, repo_opts, state);
    };

    // make sure the most recent branch name points to the most recent commit
    {
        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
        try std.testing.expectEqual(commit3, try rf.readRecur(repo_kind, repo_opts, state, .{ .ref = .{ .kind = .head, .name = "master" } }));
    }

    // log
    {
        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var iter = try repo.log(allocator, null);
        defer iter.deinit();

        {
            var object = try iter.next() orelse return error.ExpectedObject;
            defer object.deinit();
            try std.testing.expectEqual(commit3, object.oid);

            try object.object_reader.seekTo(object.content.commit.message_position);
            const message = try object.object_reader.reader.reader().readAllAlloc(allocator, repo_opts.max_read_size);
            defer allocator.free(message);
            try std.testing.expectEqualStrings("third commit", message);
        }

        {
            var object = try iter.next() orelse return error.ExpectedObject;
            defer object.deinit();
            try std.testing.expectEqual(commit2, object.oid);

            try object.object_reader.seekTo(object.content.commit.message_position);
            const message = try object.object_reader.reader.reader().readAllAlloc(allocator, repo_opts.max_read_size);
            defer allocator.free(message);
            try std.testing.expectEqualStrings("second commit", message);
        }

        {
            var object = try iter.next() orelse return error.ExpectedObject;
            defer object.deinit();
            try std.testing.expectEqual(commit1, object.oid);

            try object.object_reader.seekTo(object.content.commit.message_position);
            const message = try object.object_reader.reader.reader().readAllAlloc(allocator, repo_opts.max_read_size);
            defer allocator.free(message);
            try std.testing.expectEqualStrings("first commit", message);
        }

        try std.testing.expectEqual(null, try iter.next());
    }

    // common ancestor
    {
        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
        const ancestor_commit = try mrg.commonAncestor(repo_kind, repo_opts, allocator, state, &commit3, &commit4_stuff);
        try std.testing.expectEqualStrings(&commit2, &ancestor_commit);
    }

    // merge
    {
        try main.run(repo_kind, repo_opts, allocator, &.{ "merge", "stuff" }, repo_dir, .{});

        // change from stuff exists
        {
            const hello_txt = try repo_dir.openFile("hello.txt", .{ .mode = .read_only });
            defer hello_txt.close();
            const content = try hello_txt.readToEndAlloc(allocator, 1024);
            defer allocator.free(content);
            try std.testing.expectEqualStrings("hello, world on the stuff branch, commit 4!", content);
        }

        // change from master still exists
        {
            const goodbye_txt = try repo_dir.openFile("goodbye.txt", .{ .mode = .read_only });
            defer goodbye_txt.close();
            const content = try goodbye_txt.readToEndAlloc(allocator, 1024);
            defer allocator.free(content);
            try std.testing.expectEqualStrings("goodbye, world once again!", content);
        }
    }

    // get HEAD contents
    const commit4 = blk: {
        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
        break :blk try rf.readHeadRecur(repo_kind, repo_opts, state);
    };

    // config
    {
        try main.run(repo_kind, repo_opts, allocator, &.{ "config", "add", "core.editor", "vim" }, repo_dir, .{});
        try main.run(repo_kind, repo_opts, allocator, &.{ "config", "add", "branch.master.remote", "origin" }, repo_dir, .{});
        {
            var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();

            var config = try repo.config(allocator);
            defer config.deinit();

            const core_section = config.sections.get("core").?;
            try std.testing.expectEqual(1, core_section.count());

            const branch_master_section = config.sections.get("branch.master").?;
            try std.testing.expectEqual(1, branch_master_section.count());
            try std.testing.expectEqualStrings("origin", branch_master_section.get("remote").?);
        }

        try main.run(repo_kind, repo_opts, allocator, &.{ "config", "rm", "branch.master.remote" }, repo_dir, .{});
        {
            var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();

            var config = try repo.config(allocator);
            defer config.deinit();

            try std.testing.expectEqual(null, config.sections.get("branch.master"));
        }

        // don't allow invalid names
        try std.testing.expectEqual(error.InvalidConfigName, main.run(repo_kind, repo_opts, allocator, &.{ "config", "add", "core.editor#hi", "vim" }, repo_dir, .{}));

        // do allow values with spaces
        try main.run(repo_kind, repo_opts, allocator, &.{ "config", "add", "user.name", "radar roark" }, repo_dir, .{});
        {
            var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();

            var config = try repo.config(allocator);
            defer config.deinit();

            const user_section = config.sections.get("user").?;
            try std.testing.expectEqualStrings("radar roark", user_section.get("name").?);
        }

        // do allow additional characters in subsection names
        try main.run(repo_kind, repo_opts, allocator, &.{ "config", "add", "branch.\"hello.world\".remote", "radar roark" }, repo_dir, .{});
        {
            var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();

            var config = try repo.config(allocator);
            defer config.deinit();

            const branch_hi_section = config.sections.get("branch.\"hello.world\"").?;
            try std.testing.expectEqual(1, branch_hi_section.count());
        }

        // section and var names are forcibly lower-cased, but not the subsection name
        try main.run(repo_kind, repo_opts, allocator, &.{ "config", "add", "BRANCH.MASTER.REMOTE", "origin" }, repo_dir, .{});
        {
            var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();

            var config = try repo.config(allocator);
            defer config.deinit();

            const branch_master_section = config.sections.get("branch.MASTER").?;
            try std.testing.expectEqual(1, branch_master_section.count());
            try std.testing.expectEqualStrings("origin", branch_master_section.get("remote").?);
        }

        try main.run(repo_kind, repo_opts, allocator, &.{ "config", "list" }, repo_dir, .{});
    }

    // remote
    {
        try main.run(repo_kind, repo_opts, allocator, &.{ "remote", "add", "origin", "http://localhost:3000" }, repo_dir, .{});
        {
            var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();

            var remote = try repo.remote(allocator);
            defer remote.deinit();

            const origin_section = remote.sections.get("origin").?;
            try std.testing.expectEqual(1, origin_section.count());
        }

        try main.run(repo_kind, repo_opts, allocator, &.{ "remote", "rm", "origin" }, repo_dir, .{});
        {
            var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();

            var remote = try repo.remote(allocator);
            defer remote.deinit();

            try std.testing.expectEqual(null, remote.sections.get("origin"));
        }

        try main.run(repo_kind, repo_opts, allocator, &.{ "remote", "list" }, repo_dir, .{});
    }

    // tag
    {
        try main.run(repo_kind, repo_opts, allocator, &.{ "tag", "add", "ann", "-m", "this is an annotated tag" }, repo_dir, .{});

        {
            var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();
            var moment = try repo.core.latestMoment();
            const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };

            const tag_oid = (try rf.readRecur(repo_kind, repo_opts, state, .{ .ref = .{ .kind = .tag, .name = "ann" } })) orelse return error.TagNotFound;
            var tag_object = try obj.Object(repo_kind, repo_opts, .full).init(allocator, state, &tag_oid);
            defer tag_object.deinit();

            try tag_object.object_reader.seekTo(tag_object.content.tag.message_position);
            const message = try tag_object.object_reader.reader.reader().readAllAlloc(allocator, repo_opts.max_read_size);
            defer allocator.free(message);
            try std.testing.expectEqualStrings("this is an annotated tag", message);
        }

        try main.run(repo_kind, repo_opts, allocator, &.{ "tag", "list" }, repo_dir, .{});

        try main.run(repo_kind, repo_opts, allocator, &.{ "tag", "rm", "ann" }, repo_dir, .{});
    }

    return commit4;
}
