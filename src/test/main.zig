//! end-to-end test using the main entrypoint (xitMain).
//! runs with both git and xit modes, using libgit2 to
//! validate git mode.

const std = @import("std");
const xitdb = @import("xitdb");
const builtin = @import("builtin");
const main = @import("../main.zig");
const hash = @import("../hash.zig");
const idx = @import("../index.zig");
const obj = @import("../object.zig");
const ref = @import("../ref.zig");
const rp = @import("../repo.zig");
const df = @import("../diff.zig");
const mrg = @import("../merge.zig");

const c = @cImport({
    @cInclude("git2.h");
});

fn testMain(comptime repo_kind: rp.RepoKind) ![hash.SHA1_HEX_LEN]u8 {
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

    const writers = .{ .out = std.io.null_writer, .err = std.io.null_writer };

    // init repo
    try main.xitMain(repo_kind, allocator, &.{ "init", "repo" }, temp_dir, writers);

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
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var status = try repo.status();
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
        try main.xitMain(repo_kind, allocator, &.{ "add", "." }, repo_dir, writers);

        // make a commit
        try main.xitMain(repo_kind, allocator, &.{ "commit", "-m", "first commit" }, repo_dir, writers);

        switch (repo_kind) {
            .git => {
                // check that the commit object was created
                {
                    var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
                    defer repo.deinit();
                    const head_file_buffer = try ref.readHead(repo_kind, .{ .core = &repo.core });
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

                    var sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
                    try hash.sha1Reader(readme.reader(), header, &sha1_bytes_buffer);
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
                var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
                defer repo.deinit();
                var moment = try repo.core.latestMoment();
                const state = rp.Repo(repo_kind).State(.read_only).init(&repo.core, &moment);
                const head_file_buffer = try ref.readHead(repo_kind, state);
                const bytes_cursor_maybe = try moment.cursor.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hash.hashBuffer("objects") } },
                    .{ .hash_map_get = .{ .value = try hash.hexToHash(&head_file_buffer) } },
                });
                try std.testing.expect(bytes_cursor_maybe != null);
            },
        }
    }

    // get HEAD contents
    const commit1 = blk: {
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind).State(.read_only).init(&repo.core, &moment);
        break :blk try ref.readHead(repo_kind, state);
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

        // workspace diff
        {
            var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();
            var status = try repo.status();
            defer status.deinit();
            var file_iter = try repo.filePairs(.{
                .workspace = .{
                    .conflict_diff_kind = .current,
                    .status = &status,
                },
            });

            while (try file_iter.next()) |*line_iter_pair_ptr| {
                var line_iter_pair = line_iter_pair_ptr.*;
                defer line_iter_pair.deinit();
                var hunk_iter = try df.HunkIterator(repo_kind).init(allocator, &line_iter_pair.a, &line_iter_pair.b);
                defer hunk_iter.deinit();
                if (std.mem.eql(u8, "hello.txt", line_iter_pair.path)) {
                    try std.testing.expectEqualStrings("diff --git a/hello.txt b/hello.txt", hunk_iter.header_lines.items[0]);
                    const expected_hunks = &[_][]const df.MyersDiffIterator(repo_kind).Edit{
                        &[_]df.MyersDiffIterator(repo_kind).Edit{
                            .{ .eql = .{ .old_line = .{ .num = 2, .text = "2" }, .new_line = .{ .num = 2, .text = "2" } } },
                            .{ .eql = .{ .old_line = .{ .num = 3, .text = "3" }, .new_line = .{ .num = 3, .text = "3" } } },
                            .{ .eql = .{ .old_line = .{ .num = 4, .text = "4" }, .new_line = .{ .num = 4, .text = "4" } } },
                            .{ .del = .{ .old_line = .{ .num = 5, .text = "5" } } },
                            .{ .ins = .{ .new_line = .{ .num = 5, .text = "5.0" } } },
                            .{ .eql = .{ .old_line = .{ .num = 6, .text = "6" }, .new_line = .{ .num = 6, .text = "6" } } },
                            .{ .eql = .{ .old_line = .{ .num = 7, .text = "7" }, .new_line = .{ .num = 7, .text = "7" } } },
                            .{ .eql = .{ .old_line = .{ .num = 8, .text = "8" }, .new_line = .{ .num = 8, .text = "8" } } },
                        },
                        &[_]df.MyersDiffIterator(repo_kind).Edit{
                            .{ .del = .{ .old_line = .{ .num = 9, .text = "9" } } },
                            .{ .del = .{ .old_line = .{ .num = 10, .text = "10" } } },
                            .{ .ins = .{ .new_line = .{ .num = 9, .text = "9.0" } } },
                            .{ .ins = .{ .new_line = .{ .num = 10, .text = "10.0" } } },
                            .{ .eql = .{ .old_line = .{ .num = 11, .text = "11" }, .new_line = .{ .num = 11, .text = "11" } } },
                            .{ .eql = .{ .old_line = .{ .num = 12, .text = "12" }, .new_line = .{ .num = 12, .text = "12" } } },
                            .{ .eql = .{ .old_line = .{ .num = 13, .text = "13" }, .new_line = .{ .num = 13, .text = "13" } } },
                        },
                        &[_]df.MyersDiffIterator(repo_kind).Edit{
                            .{ .eql = .{ .old_line = .{ .num = 14, .text = "14" }, .new_line = .{ .num = 14, .text = "14" } } },
                            .{ .del = .{ .old_line = .{ .num = 15, .text = "15" } } },
                            .{ .ins = .{ .new_line = .{ .num = 15, .text = "15.0" } } },
                        },
                    };
                    for (expected_hunks) |expected_hunk| {
                        if (try hunk_iter.next()) |*actual_hunk_ptr| {
                            var actual_hunk = actual_hunk_ptr.*;
                            defer actual_hunk.deinit();
                            for (expected_hunk, actual_hunk.edits.items) |expected_edit, actual_edit| {
                                try std.testing.expectEqualDeep(expected_edit, actual_edit);
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
        try main.xitMain(repo_kind, allocator, &.{ "add", "LICENSE" }, repo_dir, writers);

        // delete a file and dir
        try repo_dir.deleteTree("docs");
        try main.xitMain(repo_kind, allocator, &.{ "add", "docs/design.md" }, repo_dir, writers);

        // add new and modified files
        try main.xitMain(repo_kind, allocator, &.{ "add", "hello.txt", "run.sh", "src/zig/main.zig" }, repo_dir, writers);

        // index diff
        {
            var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();
            var status = try repo.status();
            defer status.deinit();
            var file_iter = try repo.filePairs(.{
                .index = .{ .status = &status },
            });

            while (try file_iter.next()) |*line_iter_pair_ptr| {
                var line_iter_pair = line_iter_pair_ptr.*;
                defer line_iter_pair.deinit();
                var hunk_iter = try df.HunkIterator(repo_kind).init(allocator, &line_iter_pair.a, &line_iter_pair.b);
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
        try main.xitMain(repo_kind, allocator, &.{ "add", "." }, repo_dir, writers);

        // make another commit
        try main.xitMain(repo_kind, allocator, &.{ "commit", "-m", "second commit" }, repo_dir, writers);

        switch (repo_kind) {
            .git => {
                // check that the commit object was created
                {
                    var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
                    defer repo.deinit();
                    const head_file_buffer = try ref.readHead(repo_kind, .{ .core = &repo.core });
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
                var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
                defer repo.deinit();
                var moment = try repo.core.latestMoment();
                const state = rp.Repo(repo_kind).State(.read_only).init(&repo.core, &moment);
                const head_file_buffer = try ref.readHead(repo_kind, state);
                const bytes_cursor_maybe = try moment.cursor.readPath(void, &.{
                    .{ .hash_map_get = .{ .value = hash.hashBuffer("objects") } },
                    .{ .hash_map_get = .{ .value = try hash.hexToHash(&head_file_buffer) } },
                });
                try std.testing.expect(bytes_cursor_maybe != null);
            },
        }
    }

    // get HEAD contents
    const commit2 = blk: {
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind).State(.read_only).init(&repo.core, &moment);
        break :blk try ref.readHead(repo_kind, state);
    };

    // tree diff
    {
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var tree_diff = try repo.treeDiff(commit1, commit2);
        defer tree_diff.deinit();
        var file_iter = try repo.filePairs(.{
            .tree = .{ .tree_diff = &tree_diff },
        });

        while (try file_iter.next()) |*line_iter_pair_ptr| {
            var line_iter_pair = line_iter_pair_ptr.*;
            defer line_iter_pair.deinit();
            var hunk_iter = try df.HunkIterator(repo_kind).init(allocator, &line_iter_pair.a, &line_iter_pair.b);
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
                try main.xitMain(repo_kind, allocator, &.{ "add", "LICENSE" }, repo_dir, writers);
            }

            // check out commit1 and make sure the conflict is found
            {
                var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
                defer repo.deinit();
                var result = try repo.switchHead(&commit1, .{ .force = false });
                defer result.deinit();
                try std.testing.expect(result.data == .conflict);
                try std.testing.expectEqual(1, result.data.conflict.stale_files.count());
            }

            // delete the file
            {
                try repo_dir.deleteFile("LICENSE");
                try main.xitMain(repo_kind, allocator, &.{ "add", "LICENSE" }, repo_dir, writers);
            }
        }

        {
            // make a new file (only in the working dir) that conflicts with the descendent of a file from commit1
            {
                var docs = try repo_dir.createFile("docs", .{});
                defer docs.close();
                try docs.writeAll("i conflict with the docs dir in the first commit");
            }

            // check out commit1 and make sure the conflict is found
            {
                var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
                defer repo.deinit();
                var result = try repo.switchHead(&commit1, .{ .force = false });
                defer result.deinit();
                try std.testing.expect(result.data == .conflict);
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
                var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
                defer repo.deinit();
                var result = try repo.switchHead(&commit1, .{ .force = false });
                defer result.deinit();
                try std.testing.expect(result.data == .conflict);
                try std.testing.expectEqual(1, result.data.conflict.stale_files.count());
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
                var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
                defer repo.deinit();
                var result = try repo.switchHead(&commit1, .{ .force = false });
                defer result.deinit();
                try std.testing.expect(result.data == .conflict);
                try std.testing.expectEqual(1, result.data.conflict.stale_dirs.count());
            }

            // delete the dir
            try repo_dir.deleteTree("LICENSE");
        }
    }

    // switch to first commit
    try main.xitMain(repo_kind, allocator, &.{ "switch", &commit1 }, repo_dir, writers);

    // the working tree was updated
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
    try main.xitMain(repo_kind, allocator, &.{ "switch", "master" }, repo_dir, writers);

    // the working tree was updated
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
        try main.xitMain(repo_kind, allocator, &.{ "add", "hello.txt" }, repo_dir, writers);

        // read index
        {
            var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();
            var moment = try repo.core.latestMoment();
            const state = rp.Repo(repo_kind).State(.read_only).init(&repo.core, &moment);
            var index = try idx.Index(repo_kind).init(allocator, state);
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
                var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
                defer repo.deinit();
                var count: u32 = 0;
                var moment = try repo.core.latestMoment();
                if (try moment.get(hash.hashBuffer("index"))) |index_cursor| {
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
        try main.xitMain(repo_kind, allocator, &.{ "add", "hello.txt" }, repo_dir, writers);

        // read index
        {
            var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();
            var moment = try repo.core.latestMoment();
            const state = rp.Repo(repo_kind).State(.read_only).init(&repo.core, &moment);
            var index = try idx.Index(repo_kind).init(allocator, state);
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
                var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
                defer repo.deinit();
                var count: u32 = 0;
                var moment = try repo.core.latestMoment();
                if (try moment.get(hash.hashBuffer("index"))) |index_cursor| {
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
        try std.testing.expectEqual(error.FileNotFound, main.xitMain(repo_kind, allocator, &.{ "add", "no-such-file" }, repo_dir, writers));

        // can't remove non-existent file
        try std.testing.expectEqual(error.FileNotFound, main.xitMain(repo_kind, allocator, &.{ "rm", "no-such-file" }, repo_dir, writers));

        // create a new file
        var new_file_txt = try repo_dir.createFile("new-file.txt", .{});
        defer {
            new_file_txt.close();
            repo_dir.deleteFile("new-file.txt") catch {};
        }
        try new_file_txt.writeAll("this is a new file");

        // can't remove unindexed file
        try std.testing.expectEqual(error.CannotRemoveUnindexedFile, main.xitMain(repo_kind, allocator, &.{ "rm", "new-file.txt" }, repo_dir, writers));

        // modify a file
        {
            const three_txt = try repo_dir.openFile("one/two/three.txt", .{ .mode = .read_write });
            defer three_txt.close();
            try three_txt.seekTo(0);
            try three_txt.writeAll("this is now modified");
            try three_txt.setEndPos(try three_txt.getPos());
        }

        // can't remove a file with unstaged changes
        try std.testing.expectEqual(error.CannotRemoveFileWithUnstagedChanges, main.xitMain(repo_kind, allocator, &.{ "rm", "one/two/three.txt" }, repo_dir, writers));

        // add file
        try main.xitMain(repo_kind, allocator, &.{ "add", "new-file.txt" }, repo_dir, writers);

        // unadd file
        try main.xitMain(repo_kind, allocator, &.{ "unadd", "one/two/three.txt" }, repo_dir, writers);

        // reset will undo index changes
        {
            try main.xitMain(repo_kind, allocator, &.{ "reset", "new-file.txt" }, repo_dir, writers);
            try main.xitMain(repo_kind, allocator, &.{ "reset", "one/two/three.txt" }, repo_dir, writers);

            var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();
            var moment = try repo.core.latestMoment();
            const state = rp.Repo(repo_kind).State(.read_only).init(&repo.core, &moment);
            var index = try idx.Index(repo_kind).init(allocator, state);
            defer index.deinit();

            try std.testing.expect(!index.entries.contains("new-file.txt"));
            try std.testing.expect(index.entries.contains("one/two/three.txt"));
        }

        // stage the changes to the file
        try main.xitMain(repo_kind, allocator, &.{ "add", "one/two/three.txt" }, repo_dir, writers);

        // can't remove a file with staged changes
        try std.testing.expectEqual(error.CannotRemoveFileWithStagedChanges, main.xitMain(repo_kind, allocator, &.{ "rm", "one/two/three.txt" }, repo_dir, writers));

        // remove file by force
        try main.xitMain(repo_kind, allocator, &.{ "rm", "one/two/three.txt", "-f" }, repo_dir, writers);

        // restore file's original content
        {
            const three_txt = try repo_dir.createFile("one/two/three.txt", .{});
            defer three_txt.close();
            try three_txt.seekTo(0);
            try three_txt.writeAll("one, two, three!");
            try three_txt.setEndPos(try three_txt.getPos());

            try main.xitMain(repo_kind, allocator, &.{ "add", "one/two/three.txt" }, repo_dir, writers);
        }

        // remove a file
        {
            try main.xitMain(repo_kind, allocator, &.{ "rm", "one/two/three.txt" }, repo_dir, writers);

            var file_or_err = repo_dir.openFile("one/two/three.txt", .{ .mode = .read_only });
            if (file_or_err) |*file| {
                file.close();
                return error.UnexpectedFile;
            } else |_| {}
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

        // workspace changes
        {
            // get status
            var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();
            var status = try repo.status();
            defer status.deinit();

            // check the untracked entries
            try std.testing.expectEqual(2, status.untracked.count());
            try std.testing.expect(status.untracked.contains("a"));
            try std.testing.expect(status.untracked.contains("goodbye.txt"));

            // check the workspace_modified entries
            try std.testing.expectEqual(2, status.workspace_modified.count());
            try std.testing.expect(status.workspace_modified.contains("hello.txt"));
            try std.testing.expect(status.workspace_modified.contains("README"));

            // check the workspace_deleted entries
            try std.testing.expectEqual(1, status.workspace_deleted.count());
            try std.testing.expect(status.workspace_deleted.contains("src/zig/main.zig"));
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
            try main.xitMain(repo_kind, allocator, &.{ "add", "c/d.txt" }, repo_dir, writers);

            // remove file from index
            try main.xitMain(repo_kind, allocator, &.{ "add", "src/zig/main.zig" }, repo_dir, writers);

            // get status
            var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();
            var status = try repo.status();
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
            var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();
            var status = try repo.status();
            defer status.deinit();

            try std.testing.expectEqual(2, status.workspace_modified.count());
            try std.testing.expectEqual(2, status.index_deleted.count());
        }

        try main.xitMain(repo_kind, allocator, &.{ "restore", "README" }, repo_dir, writers);

        try main.xitMain(repo_kind, allocator, &.{ "restore", "hello.txt" }, repo_dir, writers);

        // directories can be restored
        try main.xitMain(repo_kind, allocator, &.{ "restore", "src" }, repo_dir, writers);

        // nested paths can be restored
        try main.xitMain(repo_kind, allocator, &.{ "restore", "one/two/three.txt" }, repo_dir, writers);

        // remove changes to index
        try main.xitMain(repo_kind, allocator, &.{ "add", "hello.txt", "src", "one" }, repo_dir, writers);

        // there are no modified or deleted files remaining
        {
            var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();
            var status = try repo.status();
            defer status.deinit();

            try std.testing.expectEqual(0, status.workspace_modified.count());
            try std.testing.expectEqual(0, status.index_deleted.count());
        }
    }

    // parse objects
    {
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind).State(.read_only).init(&repo.core, &moment);

        // read commit
        var commit_object = try obj.Object(repo_kind, .full).init(allocator, state, commit2);
        defer commit_object.deinit();
        try std.testing.expectEqualStrings("second commit", commit_object.content.commit.metadata.message);

        // read tree
        var tree_object = try obj.Object(repo_kind, .full).init(allocator, state, commit_object.content.commit.tree);
        defer tree_object.deinit();
        try std.testing.expectEqual(6, tree_object.content.tree.entries.count());
    }

    // create a branch
    try main.xitMain(repo_kind, allocator, &.{ "branch", "add", "stuff" }, repo_dir, writers);

    // switch to the branch
    try main.xitMain(repo_kind, allocator, &.{ "switch", "stuff" }, repo_dir, writers);

    // check the refs
    {
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind).State(.read_only).init(&repo.core, &moment);
        try std.testing.expectEqual(commit2, try ref.readHead(repo_kind, state));
        try std.testing.expectEqual(commit2, try ref.resolve(repo_kind, state, "stuff"));
    }

    // list all branches
    {
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind).State(.read_only).init(&repo.core, &moment);
        var ref_list = try ref.RefList.init(repo_kind, state, allocator, "heads");
        defer ref_list.deinit();
        try std.testing.expectEqual(2, ref_list.refs.items.len);
    }

    // get the current branch
    {
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind).State(.read_only).init(&repo.core, &moment);
        var current_branch_maybe = try ref.Ref.initFromLink(repo_kind, state, allocator, "HEAD");
        defer if (current_branch_maybe) |*current_branch| current_branch.deinit();
        try std.testing.expectEqualStrings("stuff", current_branch_maybe.?.name);
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
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
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
        try main.xitMain(repo_kind, allocator, &.{ "add", "hello.txt" }, repo_dir, writers);

        // make a commit
        try main.xitMain(repo_kind, allocator, &.{ "commit", "-m", "third commit" }, repo_dir, writers);

        try hello_txt.seekTo(0);
        try hello_txt.writeAll("hello, world on the stuff branch, commit 4!");
        try hello_txt.setEndPos(try hello_txt.getPos());

        // add the files
        try main.xitMain(repo_kind, allocator, &.{ "add", "hello.txt" }, repo_dir, writers);

        // make a commit
        try main.xitMain(repo_kind, allocator, &.{ "commit", "-m", "fourth commit" }, repo_dir, writers);
    }

    // get HEAD contents
    const commit4_stuff = blk: {
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind).State(.read_only).init(&repo.core, &moment);
        break :blk try ref.readHead(repo_kind, state);
    };

    // create a branch with slashes
    try main.xitMain(repo_kind, allocator, &.{ "branch", "add", "a/b/c" }, repo_dir, writers);

    // make sure the ref is created with subdirs
    if (repo_kind == .git) {
        const ref_file = try test_state.git_dir.openFile("refs/heads/a/b/c", .{});
        defer ref_file.close();
    }

    // list all branches
    {
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind).State(.read_only).init(&repo.core, &moment);
        var ref_list = try ref.RefList.init(repo_kind, state, allocator, "heads");
        defer ref_list.deinit();
        try std.testing.expectEqual(3, ref_list.refs.items.len);
        var ref_map = std.StringHashMap(void).init(allocator);
        defer ref_map.deinit();
        for (ref_list.refs.items) |r| {
            try ref_map.put(r.name, {});
        }
        try std.testing.expect(ref_map.contains("a/b/c"));
        try std.testing.expect(ref_map.contains("stuff"));
        try std.testing.expect(ref_map.contains("master"));
    }

    // remove the branch
    try main.xitMain(repo_kind, allocator, &.{ "branch", "rm", "a/b/c" }, repo_dir, writers);

    // make sure the subdirs are deleted
    if (repo_kind == .git) {
        try std.testing.expectEqual(error.FileNotFound, test_state.git_dir.openFile("refs/heads/a/b/c", .{}));
        try std.testing.expectEqual(error.FileNotFound, test_state.git_dir.openDir("refs/heads/a/b", .{}));
        try std.testing.expectEqual(error.FileNotFound, test_state.git_dir.openDir("refs/heads/a", .{}));
    }

    // switch to master
    try main.xitMain(repo_kind, allocator, &.{ "switch", "master" }, repo_dir, writers);

    // modify file and commit
    {
        const goodbye_txt = try repo_dir.openFile("goodbye.txt", .{ .mode = .read_write });
        defer goodbye_txt.close();
        try goodbye_txt.writeAll("goodbye, world once again!");

        // add the files
        try main.xitMain(repo_kind, allocator, &.{ "add", "goodbye.txt" }, repo_dir, writers);

        // make a commit
        try main.xitMain(repo_kind, allocator, &.{ "commit", "-m", "third commit" }, repo_dir, writers);
    }

    // get HEAD contents
    const commit3 = blk: {
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind).State(.read_only).init(&repo.core, &moment);
        break :blk try ref.readHead(repo_kind, state);
    };

    // make sure the most recent branch name points to the most recent commit
    {
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind).State(.read_only).init(&repo.core, &moment);
        try std.testing.expectEqual(commit3, try ref.resolve(repo_kind, state, "master"));
    }

    // log
    {
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var iter = try repo.log(&.{commit3});
        defer iter.deinit();

        var object3 = try iter.next();
        try std.testing.expectEqual(commit3, object3.?.oid);
        object3.?.deinit();

        var object2 = try iter.next();
        try std.testing.expectEqual(commit2, object2.?.oid);
        object2.?.deinit();

        var object1 = try iter.next();
        try std.testing.expectEqual(commit1, object1.?.oid);
        object1.?.deinit();

        try std.testing.expectEqual(null, try iter.next());
    }

    // common ancestor
    {
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind).State(.read_only).init(&repo.core, &moment);
        const ancestor_commit = try mrg.commonAncestor(repo_kind, allocator, state, &commit3, &commit4_stuff);
        try std.testing.expectEqualStrings(&commit2, &ancestor_commit);
    }

    // merge
    {
        try main.xitMain(repo_kind, allocator, &.{ "merge", "stuff" }, repo_dir, writers);

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
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind).State(.read_only).init(&repo.core, &moment);
        break :blk try ref.readHead(repo_kind, state);
    };

    // config
    {
        try main.xitMain(repo_kind, allocator, &.{ "config", "add", "core.editor", "vim" }, repo_dir, writers);
        try main.xitMain(repo_kind, allocator, &.{ "config", "add", "branch.master.remote", "origin" }, repo_dir, writers);

        {
            var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();

            var config = try repo.config();
            defer config.deinit();

            const core_section = config.sections.get("core").?;
            try std.testing.expectEqual(1, core_section.count());

            const branch_master_section = config.sections.get("branch.master").?;
            try std.testing.expectEqual(1, branch_master_section.count());
        }

        try main.xitMain(repo_kind, allocator, &.{ "config", "rm", "branch.master.remote" }, repo_dir, writers);

        {
            var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();

            var config = try repo.config();
            defer config.deinit();

            try std.testing.expectEqual(null, config.sections.get("branch.master"));
        }

        // don't allow invalid names
        try std.testing.expectEqual(error.InvalidConfigName, main.xitMain(repo_kind, allocator, &.{ "config", "add", "core#editor", "vim" }, repo_dir, writers));

        // do allow values with spaces
        try main.xitMain(repo_kind, allocator, &.{ "config", "add", "user.name", "radar roark" }, repo_dir, writers);

        {
            var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();

            var config = try repo.config();
            defer config.deinit();

            const user_section = config.sections.get("user").?;
            try std.testing.expectEqual(1, user_section.count());
            try std.testing.expectEqualStrings("radar roark", user_section.get("name").?);
        }

        try main.xitMain(repo_kind, allocator, &.{ "config", "list" }, repo_dir, writers);
    }

    // remote
    {
        try main.xitMain(repo_kind, allocator, &.{ "remote", "add", "origin", "http://localhost:3000" }, repo_dir, writers);

        {
            var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();

            var remote = try repo.remote();
            defer remote.deinit();

            const origin_section = remote.sections.get("origin").?;
            try std.testing.expectEqual(1, origin_section.count());
        }

        try main.xitMain(repo_kind, allocator, &.{ "remote", "rm", "origin" }, repo_dir, writers);

        {
            var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
            defer repo.deinit();

            var remote = try repo.remote();
            defer remote.deinit();

            try std.testing.expectEqual(null, remote.sections.get("origin"));
        }

        try main.xitMain(repo_kind, allocator, &.{ "remote", "list" }, repo_dir, writers);
    }

    return commit4;
}

test "main" {
    const last_hash_git = try testMain(.git);
    const last_hash_xit = try testMain(.xit);
    try std.testing.expectEqualStrings(&last_hash_git, &last_hash_xit);
}
