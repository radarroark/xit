const std = @import("std");
const main = @import("./main.zig");
const hash = @import("./hash.zig");
const idx = @import("./index.zig");
const stat = @import("./status.zig");
const obj = @import("./object.zig");
const ref = @import("./ref.zig");
const chk = @import("./checkout.zig");

const c = @cImport({
    @cInclude("git2.h");
});

pub fn expectEqual(expected: anytype, actual: anytype) !void {
    try std.testing.expectEqual(@as(@TypeOf(actual), expected), actual);
}

test "end to end" {
    const temp_dir_name = "temp-test-end-to-end";

    const allocator = std.testing.allocator;
    var args = std.ArrayList([]const u8).init(allocator);
    defer args.deinit();

    // start libgit
    _ = c.git_libgit2_init();
    defer _ = c.git_libgit2_shutdown();

    // get the current working directory path.
    // we can't just call std.fs.cwd() all the time because we're
    // gonna change it later. and since defers run at the end,
    // if you call std.fs.cwd() in them you're gonna have a bad time.
    var cwd_path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
    const cwd_path = try std.fs.cwd().realpath(".", &cwd_path_buffer);
    var cwd = try std.fs.openDirAbsolute(cwd_path, .{});
    defer cwd.close();

    // create the temp dir
    var temp_dir = try cwd.makeOpenPath(temp_dir_name, .{});
    defer cwd.deleteTree(temp_dir_name) catch {};
    defer temp_dir.close();

    // init repo
    args.clearAndFree();
    try args.append("init");
    try args.append(temp_dir_name ++ "/repo");
    try main.zitMain(allocator, &args);

    // make sure the dirs were created
    var repo_dir = try temp_dir.openDir("repo", .{});
    defer repo_dir.close();
    var git_dir = try repo_dir.openDir(".git", .{});
    defer git_dir.close();

    // change the cwd
    try repo_dir.setAsCwd();
    defer cwd.setAsCwd() catch {};

    // get repo path for libgit
    var repo_path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
    const repo_path = @ptrCast([*c]const u8, try repo_dir.realpath(".", &repo_path_buffer));
    var repo: ?*c.git_repository = null;

    // add and commit
    {
        // make file
        var hello_txt = try repo_dir.createFile("hello.txt", .{});
        defer hello_txt.close();
        try hello_txt.writeAll("hello, world!");

        // make file
        var readme = try repo_dir.createFile("README", .{});
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
        try main.zitMain(allocator, &args);

        // make a commit
        args.clearAndFree();
        try args.append("commit");
        try args.append("-m");
        try args.append("first commit");
        try main.zitMain(allocator, &args);

        // check that the commit object was created
        {
            const head_file_buffer = try ref.readHead(git_dir);
            var objects_dir = try git_dir.openDir("objects", .{});
            defer objects_dir.close();
            var hash_prefix_dir = try objects_dir.openDir(head_file_buffer[0..2], .{});
            defer hash_prefix_dir.close();
            var hash_suffix_file = try hash_prefix_dir.openFile(head_file_buffer[2..], .{});
            defer hash_suffix_file.close();
        }

        // read the commit with libgit
        {
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
    }

    // get HEAD contents
    const commit1 = try ref.readHead(git_dir);

    // make another commit
    {
        // can't commit again because nothing has changed
        args.clearAndFree();
        try args.append("commit");
        try args.append("-m");
        try args.append("pointless commit");
        try expectEqual(error.ObjectAlreadyExists, main.zitMain(allocator, &args));

        // delete a file
        try repo_dir.deleteFile("LICENSE");
        args.clearAndFree();
        try args.append("add");
        try args.append("LICENSE");
        try main.zitMain(allocator, &args);

        // delete a file and dir
        {
            try repo_dir.deleteTree("docs");
            args.clearAndFree();
            try args.append("add");
            try args.append("docs/design.md");
            try main.zitMain(allocator, &args);
        }

        // replace a file with a directory
        try repo_dir.deleteFile("tests");
        var tests_dir = try repo_dir.makeOpenPath("tests", .{});
        defer tests_dir.close();
        var main_test_zig = try tests_dir.createFile("main_test.zig", .{});
        defer main_test_zig.close();

        // change a file
        const hello_txt = try repo_dir.openFile("hello.txt", .{ .mode = .read_write });
        defer hello_txt.close();
        try hello_txt.writeAll("goodbye, world!");
        try hello_txt.setEndPos(try hello_txt.getPos());

        // make a few dirs
        var src_dir = try repo_dir.makeOpenPath("src", .{});
        defer src_dir.close();
        var src_zig_dir = try src_dir.makeOpenPath("zig", .{});
        defer src_zig_dir.close();

        // make a file in the dir
        var main_zig = try src_zig_dir.createFile("main.zig", .{});
        defer main_zig.close();
        try main_zig.writeAll("pub fn main() !void {}");

        // add the files
        args.clearAndFree();
        try args.append("add");
        try args.append(".");
        try main.zitMain(allocator, &args);

        // make another commit
        args.clearAndFree();
        try args.append("commit");
        try args.append("-m");
        try args.append("second commit");
        try main.zitMain(allocator, &args);

        // check that the commit object was created
        {
            const head_file_buffer = try ref.readHead(git_dir);
            var objects_dir = try git_dir.openDir("objects", .{});
            defer objects_dir.close();
            var hash_prefix_dir = try objects_dir.openDir(head_file_buffer[0..2], .{});
            defer hash_prefix_dir.close();
            var hash_suffix_file = try hash_prefix_dir.openFile(head_file_buffer[2..], .{});
            defer hash_suffix_file.close();
        }

        // read the commit with libgit
        {
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
    }

    // get HEAD contents
    const commit2 = try ref.readHead(git_dir);

    // try to checkout first commit after making conflicting change
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
                try main.zitMain(allocator, &args);
            }

            // check out commit1 and make sure the conflict is found
            {
                var result = chk.CheckoutResult.init();
                defer result.deinit();
                chk.checkout(allocator, repo_dir, &commit1, &result) catch |err| {
                    switch (err) {
                        error.CheckoutConflict => {},
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
                try main.zitMain(allocator, &args);
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
                var result = chk.CheckoutResult.init();
                defer result.deinit();
                chk.checkout(allocator, repo_dir, &commit1, &result) catch |err| {
                    switch (err) {
                        error.CheckoutConflict => {},
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
                try hello_txt.writeAll("howdy, world!");
                try hello_txt.setEndPos(try hello_txt.getPos());
            }

            // check out commit1 and make sure the conflict is found
            {
                var result = chk.CheckoutResult.init();
                defer result.deinit();
                chk.checkout(allocator, repo_dir, &commit1, &result) catch |err| {
                    switch (err) {
                        error.CheckoutConflict => {},
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
                try hello_txt.writeAll("goodbye, world!");
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
                var result = chk.CheckoutResult.init();
                defer result.deinit();
                chk.checkout(allocator, repo_dir, &commit1, &result) catch |err| {
                    switch (err) {
                        error.CheckoutConflict => {},
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

    // checkout first commit
    args.clearAndFree();
    try args.append("checkout");
    try args.append(&commit1);
    try main.zitMain(allocator, &args);

    // the working tree was updated
    {
        const hello_txt = try repo_dir.openFile("hello.txt", .{ .mode = .read_only });
        defer hello_txt.close();
        const content = try hello_txt.readToEndAlloc(allocator, 1024);
        defer allocator.free(content);
        try std.testing.expectEqualStrings("hello, world!", content);

        const license = try repo_dir.openFile("LICENSE", .{ .mode = .read_only });
        defer license.close();
    }

    // checkout second commit
    args.clearAndFree();
    try args.append("checkout");
    try args.append(&commit2);
    try main.zitMain(allocator, &args);

    // the working tree was updated
    {
        const hello_txt = try repo_dir.openFile("hello.txt", .{ .mode = .read_only });
        defer hello_txt.close();
        const content = try hello_txt.readToEndAlloc(allocator, 1024);
        defer allocator.free(content);
        try std.testing.expectEqualStrings("goodbye, world!", content);

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
        try main.zitMain(allocator, &args);

        // read index
        {
            var index = try idx.Index.init(allocator, git_dir);
            defer index.deinit();
            try expectEqual(5, index.entries.count());
            try std.testing.expect(index.entries.contains("README"));
            try std.testing.expect(index.entries.contains("src/zig/main.zig"));
            try std.testing.expect(index.entries.contains("hello.txt/nested.txt"));
            try std.testing.expect(index.entries.contains("hello.txt/nested2.txt"));
        }

        // read index with libgit
        {
            try expectEqual(0, c.git_repository_open(&repo, repo_path));
            defer c.git_repository_free(repo);

            var index: ?*c.git_index = null;
            try expectEqual(0, c.git_repository_index(&index, repo));
            defer c.git_index_free(index);
            try expectEqual(5, c.git_index_entrycount(index));
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
        try main.zitMain(allocator, &args);

        // read index
        {
            var index = try idx.Index.init(allocator, git_dir);
            defer index.deinit();
            try expectEqual(4, index.entries.count());
            try std.testing.expect(index.entries.contains("README"));
            try std.testing.expect(index.entries.contains("src/zig/main.zig"));
            try std.testing.expect(index.entries.contains("hello.txt"));
        }

        // read index with libgit
        {
            try expectEqual(0, c.git_repository_open(&repo, repo_path));
            defer c.git_repository_free(repo);

            var index: ?*c.git_index = null;
            try expectEqual(0, c.git_repository_index(&index, repo));
            defer c.git_index_free(index);
            try expectEqual(4, c.git_index_entrycount(index));
        }

        // can't add a non-existent file
        args.clearAndFree();
        try args.append("add");
        try args.append("no-such-file");
        try expectEqual(error.FileNotFound, main.zitMain(allocator, &args));

        // a stale index lock file isn't hanging around
        {
            const lock_file_or_err = git_dir.openFile("index.lock", .{ .mode = .read_only });
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
            var status = try stat.Status.init(allocator, repo_dir, git_dir);
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
        {
            try expectEqual(0, c.git_repository_open(&repo, repo_path));
            defer c.git_repository_free(repo);

            var status_list: ?*c.git_status_list = null;
            var status_options: c.git_status_options = undefined;
            try expectEqual(0, c.git_status_options_init(&status_options, c.GIT_STATUS_OPTIONS_VERSION));
            status_options.show = c.GIT_STATUS_SHOW_WORKDIR_ONLY;
            status_options.flags = c.GIT_STATUS_OPT_INCLUDE_UNTRACKED;
            try expectEqual(0, c.git_status_list_new(&status_list, repo, &status_options));
            defer c.git_status_list_free(status_list);
            // libgit is currently including indexed files, most likely
            // because the repo itself is not completely valid right now
            try expectEqual(6, c.git_status_list_entrycount(status_list));
        }

        // index changes
        {
            // add file to index
            var d_txt = try c_dir.createFile("d.txt", .{});
            defer d_txt.close();
            args.clearAndFree();
            try args.append("add");
            try args.append("c/d.txt");
            try main.zitMain(allocator, &args);

            // remove file from index
            args.clearAndFree();
            try args.append("add");
            try args.append("src/zig/main.zig");
            try main.zitMain(allocator, &args);

            // get status
            var status = try stat.Status.init(allocator, repo_dir, git_dir);
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

    // parse objects
    {
        // read commit
        var commit_object = try obj.Object.init(allocator, repo_dir, commit2);
        defer commit_object.deinit();
        try std.testing.expectEqualStrings("second commit", commit_object.content.commit.message);

        // read tree
        var tree_object = try obj.Object.init(allocator, repo_dir, commit_object.content.commit.tree);
        defer tree_object.deinit();
        try expectEqual(4, tree_object.content.tree.entries.count());
    }

    // create a branch
    args.clearAndFree();
    try args.append("branch");
    try args.append("stuff");
    try main.zitMain(allocator, &args);

    // update HEAD
    // have to do this manually for now
    try ref.writeHead(git_dir, "ref: refs/heads/stuff");
    try expectEqual(commit2, try ref.readHead(git_dir));
    try expectEqual(commit2, try ref.resolve(git_dir, "stuff"));

    // check branch with libgit
    {
        try expectEqual(0, c.git_repository_open(&repo, repo_path));
        defer c.git_repository_free(repo);

        var head: ?*c.git_reference = null;
        try expectEqual(0, c.git_repository_head(&head, repo));
        defer c.git_reference_free(head);
        const branch_name = c.git_reference_shorthand(head);
        try std.testing.expectEqualStrings("stuff", std.mem.sliceTo(branch_name, 0));
    }
}
