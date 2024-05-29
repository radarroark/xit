//! end-to-end test using the main entrypoint (xitMain).
//! tests both xit and git modes, using libgit2 to
//! validate git mode.

const std = @import("std");
const xitdb = @import("xitdb");
const builtin = @import("builtin");
const main = @import("../main.zig");
const hash = @import("../hash.zig");
const idx = @import("../index.zig");
const obj = @import("../object.zig");
const ref = @import("../ref.zig");
const chk = @import("../checkout.zig");
const bch = @import("../branch.zig");
const rp = @import("../repo.zig");
const df = @import("../diff.zig");

const c = @cImport({
    @cInclude("git2.h");
});

fn expectEqual(expected: anytype, actual: anytype) !void {
    try std.testing.expectEqual(@as(@TypeOf(actual), expected), actual);
}

fn testMain(allocator: std.mem.Allocator, comptime repo_kind: rp.RepoKind) ![hash.SHA1_HEX_LEN]u8 {
    const temp_dir_name = "temp-test-main";

    var args = std.ArrayList([]const u8).init(allocator);
    defer args.deinit();

    // start libgit
    if (repo_kind == .git) _ = c.git_libgit2_init();
    defer _ = if (repo_kind == .git) c.git_libgit2_shutdown();

    // get the current working directory path.
    // we can't just call std.fs.cwd() all the time because we're
    // gonna change it later. and since defers run at the end,
    // if you call std.fs.cwd() in them you're gonna have a bad time.
    var cwd_path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
    const cwd_path = try std.fs.cwd().realpath(".", &cwd_path_buffer);
    var cwd = try std.fs.openDirAbsolute(cwd_path, .{});
    defer cwd.close();

    // create the temp dir
    if (cwd.openFile(temp_dir_name, .{})) |file| {
        file.close();
        try cwd.deleteTree(temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.makeOpenPath(temp_dir_name, .{});
    defer cwd.deleteTree(temp_dir_name) catch {};
    defer temp_dir.close();

    // init repo
    args.clearAndFree();
    try args.append("init");
    try args.append(temp_dir_name ++ "/repo");
    try main.xitMain(repo_kind, allocator, &args);

    // get the main dir
    var repo_dir = try temp_dir.openDir("repo", .{});
    defer repo_dir.close();

    // init repo_kind-specific state
    const State = switch (repo_kind) {
        .git => struct {
            git_dir: std.fs.Dir,
        },
        .xit => struct {
            xit_file: std.fs.File,
        },
    };
    var state: State = switch (repo_kind) {
        .git => .{
            .git_dir = try repo_dir.openDir(".git", .{}),
        },
        .xit => .{
            .xit_file = try repo_dir.openFile(".xit", .{ .mode = .read_write }),
        },
    };
    defer switch (repo_kind) {
        .git => state.git_dir.close(),
        .xit => state.xit_file.close(),
    };

    // change the cwd
    try repo_dir.setAsCwd();
    defer cwd.setAsCwd() catch {};

    // get repo path for libgit
    var repo_path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
    const repo_path: [*c]const u8 = @ptrCast(try repo_dir.realpath(".", &repo_path_buffer));

    // make sure we can get status before first commit
    {
        var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
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
        args.clearAndFree();
        try args.append("add");
        try args.append(".");
        try main.xitMain(repo_kind, allocator, &args);

        // make a commit
        args.clearAndFree();
        try args.append("commit");
        try args.append("-m");
        try args.append("first commit");
        try main.xitMain(repo_kind, allocator, &args);

        switch (repo_kind) {
            .git => {
                // check that the commit object was created
                {
                    var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
                    defer repo.deinit();
                    const head_file_buffer = try ref.readHead(repo_kind, &repo.core);
                    var objects_dir = try state.git_dir.openDir("objects", .{});
                    defer objects_dir.close();
                    var hash_prefix_dir = try objects_dir.openDir(head_file_buffer[0..2], .{});
                    defer hash_prefix_dir.close();
                    var hash_suffix_file = try hash_prefix_dir.openFile(head_file_buffer[2..], .{});
                    defer hash_suffix_file.close();
                }

                // read the commit with libgit
                {
                    var repo: ?*c.git_repository = null;
                    try expectEqual(0, c.git_repository_open(&repo, repo_path));
                    defer c.git_repository_free(repo);
                    var head: ?*c.git_reference = null;
                    try expectEqual(0, c.git_repository_head(&head, repo));
                    defer c.git_reference_free(head);
                    const oid = c.git_reference_target(head);
                    try std.testing.expect(null != oid);
                    var commit: ?*c.git_commit = null;
                    try expectEqual(0, c.git_commit_lookup(&commit, repo, oid));
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
                    try hash.sha1File(readme, header, &sha1_bytes_buffer);
                    const sha1_hex = std.fmt.bytesToHex(&sha1_bytes_buffer, .lower);

                    var oid: c.git_oid = undefined;
                    try expectEqual(0, c.git_odb_hashfile(&oid, "README", c.GIT_OBJECT_BLOB));
                    const oid_str = c.git_oid_tostr_s(&oid);
                    try std.testing.expect(oid_str != null);

                    try std.testing.expectEqualStrings(&sha1_hex, std.mem.sliceTo(oid_str, 0));
                }
            },
            .xit => {
                // check that the commit object was created
                var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
                defer repo.deinit();
                const head_file_buffer = try ref.readHead(repo_kind, &repo.core);
                var db_buffer = [_]u8{0} ** 1024;
                const bytes_maybe = try repo.core.db.rootCursor().readBytes(&db_buffer, void, &[_]xitdb.PathPart(void){
                    .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                    .{ .hash_map_get = hash.hashBuffer("objects") },
                    .{ .hash_map_get = try hash.hexToHash(&head_file_buffer) },
                });
                try std.testing.expect(bytes_maybe != null);
            },
        }
    }

    // get HEAD contents
    const commit1 = blk: {
        var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
        defer repo.deinit();
        break :blk try ref.readHead(repo_kind, &repo.core);
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

        // change permissions of a file
        if (builtin.os.tag != .windows) {
            const run_sh = try repo_dir.openFile("run.sh", .{ .mode = .read_write });
            defer run_sh.close();
            try run_sh.setPermissions(std.fs.File.Permissions{ .inner = std.fs.File.PermissionsUnix{ .mode = 0o755 } });
        }

        // workspace diff
        {
            var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
            defer repo.deinit();
            var diff_iter = try repo.diff(.workspace);
            defer diff_iter.deinit();

            while (try diff_iter.next()) |diff_item| {
                defer diff_item.deinit();
                if (std.mem.eql(u8, "hello.txt", diff_item.path)) {
                    try std.testing.expectEqualStrings("diff --git a/hello.txt b/hello.txt", diff_item.header_lines.items[0]);
                    const expected_hunks = [_][]const df.MyersDiff.Edit{
                        &[_]df.MyersDiff.Edit{
                            .{ .eql = .{ .old_line = .{ .num = 2, .text = "2" }, .new_line = .{ .num = 2, .text = "2" } } },
                            .{ .eql = .{ .old_line = .{ .num = 3, .text = "3" }, .new_line = .{ .num = 3, .text = "3" } } },
                            .{ .eql = .{ .old_line = .{ .num = 4, .text = "4" }, .new_line = .{ .num = 4, .text = "4" } } },
                            .{ .del = .{ .old_line = .{ .num = 5, .text = "5" } } },
                            .{ .ins = .{ .new_line = .{ .num = 5, .text = "5.0" } } },
                            .{ .eql = .{ .old_line = .{ .num = 6, .text = "6" }, .new_line = .{ .num = 6, .text = "6" } } },
                            .{ .eql = .{ .old_line = .{ .num = 7, .text = "7" }, .new_line = .{ .num = 7, .text = "7" } } },
                            .{ .eql = .{ .old_line = .{ .num = 8, .text = "8" }, .new_line = .{ .num = 8, .text = "8" } } },
                        },
                        &[_]df.MyersDiff.Edit{
                            .{ .del = .{ .old_line = .{ .num = 9, .text = "9" } } },
                            .{ .del = .{ .old_line = .{ .num = 10, .text = "10" } } },
                            .{ .ins = .{ .new_line = .{ .num = 9, .text = "9.0" } } },
                            .{ .ins = .{ .new_line = .{ .num = 10, .text = "10.0" } } },
                            .{ .eql = .{ .old_line = .{ .num = 11, .text = "11" }, .new_line = .{ .num = 11, .text = "11" } } },
                            .{ .eql = .{ .old_line = .{ .num = 12, .text = "12" }, .new_line = .{ .num = 12, .text = "12" } } },
                            .{ .eql = .{ .old_line = .{ .num = 13, .text = "13" }, .new_line = .{ .num = 13, .text = "13" } } },
                        },
                        &[_]df.MyersDiff.Edit{
                            .{ .eql = .{ .old_line = .{ .num = 14, .text = "14" }, .new_line = .{ .num = 14, .text = "14" } } },
                            .{ .del = .{ .old_line = .{ .num = 15, .text = "15" } } },
                            .{ .ins = .{ .new_line = .{ .num = 15, .text = "15.0" } } },
                        },
                    };
                    for (expected_hunks, diff_item.hunks.items) |expected_hunk, actual_hunk| {
                        for (expected_hunk, actual_hunk.edits) |expected_edit, actual_edit| {
                            try std.testing.expectEqualDeep(expected_edit, actual_edit);
                        }
                    }
                } else if (std.mem.eql(u8, "run.sh", diff_item.path)) {
                    try std.testing.expectEqualStrings("diff --git a/run.sh b/run.sh", diff_item.header_lines.items[0]);
                    try std.testing.expectEqualStrings("old mode 100644", diff_item.header_lines.items[1]);
                    try std.testing.expectEqualStrings("new mode 100755", diff_item.header_lines.items[2]);
                } else if (std.mem.eql(u8, "tests", diff_item.path)) {
                    try std.testing.expectEqualStrings("diff --git a/tests b/tests", diff_item.header_lines.items[0]);
                    try std.testing.expectEqualStrings("deleted file mode 100644", diff_item.header_lines.items[1]);
                } else {
                    return error.EntryNotExpected;
                }
            }

            if (builtin.os.tag != .windows) {
                try expectEqual(3, diff_iter.next_index);
            } else {
                try expectEqual(2, diff_iter.next_index);
            }
        }

        // delete a file
        try repo_dir.deleteFile("LICENSE");
        args.clearAndFree();
        try args.append("add");
        try args.append("LICENSE");
        try main.xitMain(repo_kind, allocator, &args);

        // delete a file and dir
        try repo_dir.deleteTree("docs");
        args.clearAndFree();
        try args.append("add");
        try args.append("docs/design.md");
        try main.xitMain(repo_kind, allocator, &args);

        // add new and modified files
        args.clearAndFree();
        try args.append("add");
        try args.append("hello.txt");
        try args.append("run.sh");
        try args.append("src/zig/main.zig");
        try main.xitMain(repo_kind, allocator, &args);

        // index diff
        {
            var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
            defer repo.deinit();
            var diff_iter = try repo.diff(.index);
            defer diff_iter.deinit();

            while (try diff_iter.next()) |diff_item| {
                defer diff_item.deinit();
                if (std.mem.eql(u8, "LICENSE", diff_item.path)) {
                    try std.testing.expectEqualStrings("diff --git a/LICENSE b/LICENSE", diff_item.header_lines.items[0]);
                    try std.testing.expectEqualStrings("deleted file mode 100644", diff_item.header_lines.items[1]);
                } else if (std.mem.eql(u8, "docs/design.md", diff_item.path)) {
                    try std.testing.expectEqualStrings("diff --git a/docs/design.md b/docs/design.md", diff_item.header_lines.items[0]);
                    try std.testing.expectEqualStrings("deleted file mode 100644", diff_item.header_lines.items[1]);
                } else if (std.mem.eql(u8, "hello.txt", diff_item.path)) {
                    try std.testing.expectEqualStrings("diff --git a/hello.txt b/hello.txt", diff_item.header_lines.items[0]);
                } else if (std.mem.eql(u8, "run.sh", diff_item.path)) {
                    try std.testing.expectEqualStrings("diff --git a/run.sh b/run.sh", diff_item.header_lines.items[0]);
                    try std.testing.expectEqualStrings("old mode 100644", diff_item.header_lines.items[1]);
                    try std.testing.expectEqualStrings("new mode 100755", diff_item.header_lines.items[2]);
                } else if (std.mem.eql(u8, "src/zig/main.zig", diff_item.path)) {
                    try std.testing.expectEqualStrings("diff --git a/src/zig/main.zig b/src/zig/main.zig", diff_item.header_lines.items[0]);
                    try std.testing.expectEqualStrings("new file mode 100644", diff_item.header_lines.items[1]);
                } else {
                    return error.EntryNotExpected;
                }
            }

            if (builtin.os.tag != .windows) {
                try expectEqual(5, diff_iter.next_index);
            } else {
                try expectEqual(4, diff_iter.next_index);
            }
        }

        // add the remaining files
        args.clearAndFree();
        try args.append("add");
        try args.append(".");
        try main.xitMain(repo_kind, allocator, &args);

        // make another commit
        args.clearAndFree();
        try args.append("commit");
        try args.append("-m");
        try args.append("second commit");
        try main.xitMain(repo_kind, allocator, &args);

        switch (repo_kind) {
            .git => {
                // check that the commit object was created
                {
                    var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
                    defer repo.deinit();
                    const head_file_buffer = try ref.readHead(repo_kind, &repo.core);
                    var objects_dir = try state.git_dir.openDir("objects", .{});
                    defer objects_dir.close();
                    var hash_prefix_dir = try objects_dir.openDir(head_file_buffer[0..2], .{});
                    defer hash_prefix_dir.close();
                    var hash_suffix_file = try hash_prefix_dir.openFile(head_file_buffer[2..], .{});
                    defer hash_suffix_file.close();
                }

                // read the commit with libgit
                {
                    var repo: ?*c.git_repository = null;
                    try expectEqual(0, c.git_repository_open(&repo, repo_path));
                    defer c.git_repository_free(repo);
                    var head: ?*c.git_reference = null;
                    try expectEqual(0, c.git_repository_head(&head, repo));
                    defer c.git_reference_free(head);
                    const oid = c.git_reference_target(head);
                    try std.testing.expect(null != oid);
                    var commit: ?*c.git_commit = null;
                    try expectEqual(0, c.git_commit_lookup(&commit, repo, oid));
                    defer c.git_commit_free(commit);
                    try std.testing.expectEqualStrings("second commit", std.mem.sliceTo(c.git_commit_message(commit), 0));
                }
            },
            .xit => {
                // check that the commit object was created
                var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
                defer repo.deinit();
                const head_file_buffer = try ref.readHead(repo_kind, &repo.core);
                var db_buffer = [_]u8{0} ** 1024;
                const bytes_maybe = try repo.core.db.rootCursor().readBytes(&db_buffer, void, &[_]xitdb.PathPart(void){
                    .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                    .{ .hash_map_get = hash.hashBuffer("objects") },
                    .{ .hash_map_get = try hash.hexToHash(&head_file_buffer) },
                });
                try std.testing.expect(bytes_maybe != null);
            },
        }
    }

    // get HEAD contents
    const commit2 = blk: {
        var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
        defer repo.deinit();
        break :blk try ref.readHead(repo_kind, &repo.core);
    };

    // try to switch to first commit after making conflicting change
    {
        {
            // make a new file (and add it to the index) that conflicts with one from commit1
            {
                var license = try repo_dir.createFile("LICENSE", .{});
                defer license.close();
                try license.writeAll("different license");
                args.clearAndFree();
                try args.append("add");
                try args.append("LICENSE");
                try main.xitMain(repo_kind, allocator, &args);
            }

            // check out commit1 and make sure the conflict is found
            {
                var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
                defer repo.deinit();
                var result = chk.SwitchResult.init();
                defer result.deinit();
                chk.switch_head(repo_kind, &repo.core, allocator, &commit1, &result) catch |err| {
                    switch (err) {
                        error.SwitchConflict => {},
                        else => return err,
                    }
                };
                try std.testing.expect(result.data == .conflict);
                try expectEqual(1, result.data.conflict.stale_files.count());
            }

            // delete the file
            {
                try repo_dir.deleteFile("LICENSE");
                args.clearAndFree();
                try args.append("add");
                try args.append("LICENSE");
                try main.xitMain(repo_kind, allocator, &args);
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
                var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
                defer repo.deinit();
                var result = chk.SwitchResult.init();
                defer result.deinit();
                chk.switch_head(repo_kind, &repo.core, allocator, &commit1, &result) catch |err| {
                    switch (err) {
                        error.SwitchConflict => {},
                        else => return err,
                    }
                };
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
                var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
                defer repo.deinit();
                var result = chk.SwitchResult.init();
                defer result.deinit();
                chk.switch_head(repo_kind, &repo.core, allocator, &commit1, &result) catch |err| {
                    switch (err) {
                        error.SwitchConflict => {},
                        else => return err,
                    }
                };
                try std.testing.expect(result.data == .conflict);
                try expectEqual(1, result.data.conflict.stale_files.count());
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
                var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
                defer repo.deinit();
                var result = chk.SwitchResult.init();
                defer result.deinit();
                chk.switch_head(repo_kind, &repo.core, allocator, &commit1, &result) catch |err| {
                    switch (err) {
                        error.SwitchConflict => {},
                        else => return err,
                    }
                };
                try std.testing.expect(result.data == .conflict);
                try expectEqual(1, result.data.conflict.stale_dirs.count());
            }

            // delete the dir
            try repo_dir.deleteTree("LICENSE");
        }
    }

    // switch to first commit
    args.clearAndFree();
    try args.append("switch");
    try args.append(&commit1);
    try main.xitMain(repo_kind, allocator, &args);

    // the working tree was updated
    {
        const hello_txt = try repo_dir.openFile("hello.txt", .{ .mode = .read_only });
        defer hello_txt.close();
        const content = try hello_txt.readToEndAlloc(allocator, 1024);
        defer allocator.free(content);
        try std.testing.expectEqualStrings(hello_txt_content, content);

        const license = try repo_dir.openFile("LICENSE", .{ .mode = .read_only });
        defer license.close();
    }

    // switch to master
    args.clearAndFree();
    try args.append("switch");
    try args.append("master");
    try main.xitMain(repo_kind, allocator, &args);

    // the working tree was updated
    {
        const hello_txt = try repo_dir.openFile("hello.txt", .{ .mode = .read_only });
        defer hello_txt.close();
        const content = try hello_txt.readToEndAlloc(allocator, 1024);
        defer allocator.free(content);
        try std.testing.expectEqualStrings(new_hello_txt_content, content);

        const license_or_err = repo_dir.openFile("LICENSE", .{ .mode = .read_only });
        try expectEqual(error.FileNotFound, license_or_err);
    }

    // replacing file with dir and dir with file
    {
        // replace file with directory
        try repo_dir.deleteFile("hello.txt");
        var hello_txt_dir = try repo_dir.makeOpenPath("hello.txt", .{});
        defer hello_txt_dir.close();
        var nested_txt = try hello_txt_dir.createFile("nested.txt", .{});
        defer nested_txt.close();
        var nested2_txt = try hello_txt_dir.createFile("nested2.txt", .{});
        defer nested2_txt.close();

        // add the new file
        args.clearAndFree();
        try args.append("add");
        try args.append(".");
        try main.xitMain(repo_kind, allocator, &args);

        // read index
        {
            var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
            defer repo.deinit();
            var index = try idx.Index(repo_kind).init(allocator, &repo.core);
            defer index.deinit();
            try expectEqual(6, index.entries.count());
            try std.testing.expect(index.entries.contains("README"));
            try std.testing.expect(index.entries.contains("src/zig/main.zig"));
            try std.testing.expect(index.entries.contains("tests/main_test.zig"));
            try std.testing.expect(index.entries.contains("hello.txt/nested.txt"));
            try std.testing.expect(index.entries.contains("hello.txt/nested2.txt"));
            try std.testing.expect(index.entries.contains("run.sh"));
        }

        switch (repo_kind) {
            .git => {
                // read index with libgit
                var repo: ?*c.git_repository = null;
                try expectEqual(0, c.git_repository_open(&repo, repo_path));
                defer c.git_repository_free(repo);
                var index: ?*c.git_index = null;
                try expectEqual(0, c.git_repository_index(&index, repo));
                defer c.git_index_free(index);
                try expectEqual(6, c.git_index_entrycount(index));
            },
            .xit => {
                // read the index in xitdb
                // TODO: use more efficient way to get map size
                var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
                defer repo.deinit();
                var count: u32 = 0;
                if (try repo.core.db.rootCursor().readCursor(void, &[_]xitdb.PathPart(void){
                    .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                    .{ .hash_map_get = hash.hashBuffer("index") },
                })) |cursor| {
                    var iter = try cursor.iter(.hash_map);
                    defer iter.deinit();
                    while (try iter.next()) |_| {
                        count += 1;
                    }
                }
                try expectEqual(6, count);
            },
        }

        // replace directory with file
        try hello_txt_dir.deleteFile("nested.txt");
        try hello_txt_dir.deleteFile("nested2.txt");
        try repo_dir.deleteDir("hello.txt");
        var hello_txt2 = try repo_dir.createFile("hello.txt", .{});
        defer hello_txt2.close();

        // add the new file
        args.clearAndFree();
        try args.append("add");
        try args.append(".");
        try main.xitMain(repo_kind, allocator, &args);

        // read index
        {
            var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
            defer repo.deinit();
            var index = try idx.Index(repo_kind).init(allocator, &repo.core);
            defer index.deinit();
            try expectEqual(5, index.entries.count());
            try std.testing.expect(index.entries.contains("README"));
            try std.testing.expect(index.entries.contains("src/zig/main.zig"));
            try std.testing.expect(index.entries.contains("tests/main_test.zig"));
            try std.testing.expect(index.entries.contains("hello.txt"));
            try std.testing.expect(index.entries.contains("run.sh"));
        }

        switch (repo_kind) {
            .git => {
                // read index with libgit
                var repo: ?*c.git_repository = null;
                try expectEqual(0, c.git_repository_open(&repo, repo_path));
                defer c.git_repository_free(repo);
                var index: ?*c.git_index = null;
                try expectEqual(0, c.git_repository_index(&index, repo));
                defer c.git_index_free(index);
                try expectEqual(5, c.git_index_entrycount(index));
            },
            .xit => {
                // read the index in xitdb
                // TODO: use more efficient way to get map size
                var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
                defer repo.deinit();
                var count: u32 = 0;
                if (try repo.core.db.rootCursor().readCursor(void, &[_]xitdb.PathPart(void){
                    .{ .array_list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                    .{ .hash_map_get = hash.hashBuffer("index") },
                })) |cursor| {
                    var iter = try cursor.iter(.hash_map);
                    defer iter.deinit();
                    while (try iter.next()) |_| {
                        count += 1;
                    }
                }
                try expectEqual(5, count);
            },
        }

        // can't add a non-existent file
        args.clearAndFree();
        try args.append("add");
        try args.append("no-such-file");
        try expectEqual(error.FileNotFound, main.xitMain(repo_kind, allocator, &args));

        // a stale index lock file isn't hanging around
        if (repo_kind == .git) {
            const lock_file_or_err = state.git_dir.openFile("index.lock", .{ .mode = .read_only });
            try expectEqual(error.FileNotFound, lock_file_or_err);
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
            var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
            defer repo.deinit();
            var status = try repo.status();
            defer status.deinit();

            // check the untracked entries
            var untracked_map = std.StringHashMap(void).init(allocator);
            defer untracked_map.deinit();
            try expectEqual(2, status.untracked.items.len);
            for (status.untracked.items) |entry| {
                try untracked_map.put(entry.path, {});
            }
            try std.testing.expect(untracked_map.contains("a"));
            try std.testing.expect(untracked_map.contains("goodbye.txt"));

            // check the workspace_modified entries
            var workspace_modified_map = std.StringHashMap(void).init(allocator);
            defer workspace_modified_map.deinit();
            try expectEqual(2, status.workspace_modified.items.len);
            for (status.workspace_modified.items) |entry| {
                try workspace_modified_map.put(entry.path, {});
            }
            try std.testing.expect(workspace_modified_map.contains("hello.txt"));
            try std.testing.expect(workspace_modified_map.contains("README"));

            // check the workspace_deleted entries
            var workspace_deleted_map = std.StringHashMap(void).init(allocator);
            defer workspace_deleted_map.deinit();
            try expectEqual(1, status.workspace_deleted.items.len);
            for (status.workspace_deleted.items) |path| {
                try workspace_deleted_map.put(path, {});
            }
            try std.testing.expect(workspace_deleted_map.contains("src/zig/main.zig"));
        }

        // get status with libgit
        if (repo_kind == .git) {
            var repo: ?*c.git_repository = null;
            try expectEqual(0, c.git_repository_open(&repo, repo_path));
            defer c.git_repository_free(repo);
            var status_list: ?*c.git_status_list = null;
            var status_options: c.git_status_options = undefined;
            try expectEqual(0, c.git_status_options_init(&status_options, c.GIT_STATUS_OPTIONS_VERSION));
            status_options.show = c.GIT_STATUS_SHOW_WORKDIR_ONLY;
            status_options.flags = c.GIT_STATUS_OPT_INCLUDE_UNTRACKED;
            try expectEqual(0, c.git_status_list_new(&status_list, repo, &status_options));
            defer c.git_status_list_free(status_list);
            try expectEqual(5, c.git_status_list_entrycount(status_list));
        }

        // index changes
        {
            // add file to index
            var d_txt = try c_dir.createFile("d.txt", .{});
            defer d_txt.close();
            args.clearAndFree();
            try args.append("add");
            try args.append("c/d.txt");
            try main.xitMain(repo_kind, allocator, &args);

            // remove file from index
            args.clearAndFree();
            try args.append("add");
            try args.append("src/zig/main.zig");
            try main.xitMain(repo_kind, allocator, &args);

            // get status
            var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
            defer repo.deinit();
            var status = try repo.status();
            defer status.deinit();

            // check the index_added entries
            var index_added_map = std.StringHashMap(void).init(allocator);
            defer index_added_map.deinit();
            try expectEqual(1, status.index_added.items.len);
            for (status.index_added.items) |path| {
                try index_added_map.put(path, {});
            }
            try std.testing.expect(index_added_map.contains("c/d.txt"));

            // check the index_modified entries
            var index_modified_map = std.StringHashMap(void).init(allocator);
            defer index_modified_map.deinit();
            try expectEqual(1, status.index_modified.items.len);
            for (status.index_modified.items) |path| {
                try index_modified_map.put(path, {});
            }
            try std.testing.expect(index_modified_map.contains("hello.txt"));

            // check the index_deleted entries
            var index_deleted_map = std.StringHashMap(void).init(allocator);
            defer index_deleted_map.deinit();
            try expectEqual(1, status.index_deleted.items.len);
            for (status.index_deleted.items) |path| {
                try index_deleted_map.put(path, {});
            }
        }
    }

    // restore
    {
        // there are two modified and one deleted files remaining
        {
            var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
            defer repo.deinit();
            var status = try repo.status();
            defer status.deinit();

            var workspace_modified_map = std.StringHashMap(void).init(allocator);
            defer workspace_modified_map.deinit();
            try expectEqual(2, status.workspace_modified.items.len);

            var index_deleted_map = std.StringHashMap(void).init(allocator);
            defer index_deleted_map.deinit();
            try expectEqual(1, status.index_deleted.items.len);
        }

        args.clearAndFree();
        try args.append("restore");
        try args.append("README");
        try main.xitMain(repo_kind, allocator, &args);

        args.clearAndFree();
        try args.append("restore");
        try args.append("hello.txt");
        try main.xitMain(repo_kind, allocator, &args);

        // directories can be restored
        args.clearAndFree();
        try args.append("restore");
        try args.append("src");
        try main.xitMain(repo_kind, allocator, &args);

        // nested paths can be restored
        try repo_dir.deleteTree("src");
        args.clearAndFree();
        try args.append("restore");
        try args.append("src/zig/main.zig");
        try main.xitMain(repo_kind, allocator, &args);

        // remove changes to index
        args.clearAndFree();
        try args.append("add");
        try args.append("hello.txt");
        try args.append("src");
        try main.xitMain(repo_kind, allocator, &args);

        // there are no modified or deleted files remaining
        {
            var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
            defer repo.deinit();
            var status = try repo.status();
            defer status.deinit();

            var workspace_modified_map = std.StringHashMap(void).init(allocator);
            defer workspace_modified_map.deinit();
            try expectEqual(0, status.workspace_modified.items.len);

            var index_deleted_map = std.StringHashMap(void).init(allocator);
            defer index_deleted_map.deinit();
            try expectEqual(0, status.index_deleted.items.len);
        }
    }

    // parse objects
    {
        var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
        defer repo.deinit();
        // read commit
        var commit_object = try obj.Object(repo_kind).init(allocator, &repo.core, commit2);
        defer commit_object.deinit();
        try std.testing.expectEqualStrings("second commit", commit_object.content.commit.message);

        // read tree
        var tree_object = try obj.Object(repo_kind).init(allocator, &repo.core, commit_object.content.commit.tree);
        defer tree_object.deinit();
        try expectEqual(5, tree_object.content.tree.entries.count());
    }

    // create a branch
    args.clearAndFree();
    try args.append("branch");
    try args.append("stuff");
    try main.xitMain(repo_kind, allocator, &args);

    // switch to the branch
    args.clearAndFree();
    try args.append("switch");
    try args.append("stuff");
    try main.xitMain(repo_kind, allocator, &args);

    // check the refs
    {
        var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
        defer repo.deinit();
        try expectEqual(commit2, try ref.readHead(repo_kind, &repo.core));
        try expectEqual(commit2, try ref.resolve(repo_kind, &repo.core, "stuff"));
    }

    // list all branches
    {
        var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
        defer repo.deinit();
        var ref_list = try ref.RefList.init(repo_kind, &repo.core, allocator, "heads");
        defer ref_list.deinit();
        try expectEqual(2, ref_list.refs.items.len);
    }

    // get the current branch
    {
        var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
        defer repo.deinit();
        var current_branch_maybe = try ref.Ref.initFromLink(repo_kind, &repo.core, allocator, "HEAD");
        defer if (current_branch_maybe) |*current_branch| current_branch.deinit();
        try std.testing.expectEqualStrings("stuff", current_branch_maybe.?.name);
    }

    // get the current branch with libgit
    if (repo_kind == .git) {
        var repo: ?*c.git_repository = null;
        try expectEqual(0, c.git_repository_open(&repo, repo_path));
        defer c.git_repository_free(repo);
        var head: ?*c.git_reference = null;
        try expectEqual(0, c.git_repository_head(&head, repo));
        defer c.git_reference_free(head);
        const branch_name = c.git_reference_shorthand(head);
        try std.testing.expectEqualStrings("stuff", std.mem.sliceTo(branch_name, 0));
    }

    // can't delete current branch
    {
        var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
        defer repo.deinit();
        try expectEqual(error.CannotDeleteCurrentBranch, bch.delete(repo_kind, &repo.core, allocator, "stuff"));
    }

    // make a few commits on the stuff branch
    {
        const hello_txt = try repo_dir.openFile("hello.txt", .{ .mode = .read_write });
        defer hello_txt.close();

        try hello_txt.seekTo(0);
        try hello_txt.writeAll("hello, world on the stuff branch, commit 3!");
        try hello_txt.setEndPos(try hello_txt.getPos());

        // add the files
        args.clearAndFree();
        try args.append("add");
        try args.append("hello.txt");
        try main.xitMain(repo_kind, allocator, &args);

        // make a commit
        args.clearAndFree();
        try args.append("commit");
        try args.append("-m");
        try args.append("third commit");
        try main.xitMain(repo_kind, allocator, &args);

        try hello_txt.seekTo(0);
        try hello_txt.writeAll("hello, world on the stuff branch, commit 4!");
        try hello_txt.setEndPos(try hello_txt.getPos());

        // add the files
        args.clearAndFree();
        try args.append("add");
        try args.append("hello.txt");
        try main.xitMain(repo_kind, allocator, &args);

        // make a commit
        args.clearAndFree();
        try args.append("commit");
        try args.append("-m");
        try args.append("fourth commit");
        try main.xitMain(repo_kind, allocator, &args);
    }

    // get HEAD contents
    const commit4_stuff = blk: {
        var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
        defer repo.deinit();
        break :blk try ref.readHead(repo_kind, &repo.core);
    };

    // create a branch with slashes
    args.clearAndFree();
    try args.append("branch");
    try args.append("a/b/c");
    try main.xitMain(repo_kind, allocator, &args);

    // make sure the ref is created with subdirs
    if (repo_kind == .git) {
        const ref_file = try state.git_dir.openFile("refs/heads/a/b/c", .{});
        defer ref_file.close();
    }

    // list all branches
    {
        var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
        defer repo.deinit();
        var ref_list = try ref.RefList.init(repo_kind, &repo.core, allocator, "heads");
        defer ref_list.deinit();
        try expectEqual(3, ref_list.refs.items.len);
        var ref_map = std.StringHashMap(void).init(allocator);
        defer ref_map.deinit();
        for (ref_list.refs.items) |r| {
            try ref_map.put(r.name, {});
        }
        try std.testing.expect(ref_map.contains("a/b/c"));
        try std.testing.expect(ref_map.contains("stuff"));
        try std.testing.expect(ref_map.contains("master"));
    }

    // delete the branch
    {
        var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
        defer repo.deinit();
        try bch.delete(repo_kind, &repo.core, allocator, "a/b/c");
    }

    // make sure the subdirs are deleted
    if (repo_kind == .git) {
        try expectEqual(error.FileNotFound, state.git_dir.openFile("refs/heads/a/b/c", .{}));
        try expectEqual(error.FileNotFound, state.git_dir.openDir("refs/heads/a/b", .{}));
        try expectEqual(error.FileNotFound, state.git_dir.openDir("refs/heads/a", .{}));
    }

    // switch to master
    args.clearAndFree();
    try args.append("switch");
    try args.append("master");
    try main.xitMain(repo_kind, allocator, &args);

    // modify file and commit
    {
        const goodbye_txt = try repo_dir.openFile("goodbye.txt", .{ .mode = .read_write });
        defer goodbye_txt.close();
        try goodbye_txt.writeAll("goodbye, world once again!");

        // add the files
        args.clearAndFree();
        try args.append("add");
        try args.append("goodbye.txt");
        try main.xitMain(repo_kind, allocator, &args);

        // make a commit
        args.clearAndFree();
        try args.append("commit");
        try args.append("-m");
        try args.append("third commit");
        try main.xitMain(repo_kind, allocator, &args);
    }

    // get HEAD contents
    const commit3 = blk: {
        var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
        defer repo.deinit();
        break :blk try ref.readHead(repo_kind, &repo.core);
    };

    // make sure the most recent branch name points to the most recent commit
    {
        var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
        defer repo.deinit();
        try expectEqual(commit3, try ref.resolve(repo_kind, &repo.core, "master"));
    }

    // log
    {
        var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
        defer repo.deinit();
        var iter = try repo.log(commit3);
        defer iter.deinit();

        var object3 = try iter.next();
        try expectEqual(commit3, object3.?.oid);
        object3.?.deinit();

        var object2 = try iter.next();
        try expectEqual(commit2, object2.?.oid);
        object2.?.deinit();

        var object1 = try iter.next();
        try expectEqual(commit1, object1.?.oid);
        object1.?.deinit();

        try expectEqual(null, try iter.next());
    }

    // common ancestor
    {
        var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
        defer repo.deinit();

        const ancestor_commit = try obj.commonAncestor(repo_kind, allocator, &repo.core, &commit3, &commit4_stuff);
        try std.testing.expectEqualStrings(&ancestor_commit, &commit2);
    }

    // merge
    {
        args.clearAndFree();
        try args.append("merge");
        try args.append("stuff");
        try main.xitMain(repo_kind, allocator, &args);

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
        var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
        defer repo.deinit();
        break :blk try ref.readHead(repo_kind, &repo.core);
    };

    return commit4;
}

test "main" {
    const allocator = std.testing.allocator;
    const last_hash_git = try testMain(allocator, .git);
    const last_hash_xit = try testMain(allocator, .xit);
    try std.testing.expectEqualStrings(&last_hash_git, &last_hash_xit);
}