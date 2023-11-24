const std = @import("std");
const xitdb = @import("xitdb");
const main = @import("./main.zig");
const hash = @import("./hash.zig");
const idx = @import("./index.zig");
const obj = @import("./object.zig");
const ref = @import("./ref.zig");
const chk = @import("./checkout.zig");
const branch = @import("./branch.zig");
const rp = @import("./repo.zig");
const diff = @import("./diff.zig");

const c = @cImport({
    @cInclude("git2.h");
});

pub fn expectEqual(expected: anytype, actual: anytype) !void {
    try std.testing.expectEqual(@as(@TypeOf(actual), expected), actual);
}

fn testMain(allocator: std.mem.Allocator, comptime repo_kind: rp.RepoKind) !void {
    const temp_dir_name = "temp-test-end-to-end";

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

    // add and commit
    {
        // make file
        var hello_txt = try repo_dir.createFile("hello.txt", .{});
        defer hello_txt.close();
        try hello_txt.writeAll("hello, world!");

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
                    try hash.sha1_file(readme, header, &sha1_bytes_buffer);
                    const sha1_hex = std.fmt.bytesToHex(&sha1_bytes_buffer, .lower);

                    var oid: c.git_oid = undefined;
                    try expectEqual(0, c.git_odb_hashfile(&oid, "README", c.GIT_OBJECT_BLOB));
                    var oid_str = c.git_oid_tostr_s(&oid);
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
                    .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                    .{ .map_get = xitdb.hash_buffer("objects") },
                    .{ .map_get = xitdb.hash_buffer(&head_file_buffer) },
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

    // make another commit
    {
        // can't commit again because nothing has changed
        args.clearAndFree();
        try args.append("commit");
        try args.append("-m");
        try args.append("pointless commit");
        try expectEqual(error.ObjectAlreadyExists, main.xitMain(repo_kind, allocator, &args));

        // delete a file
        try repo_dir.deleteFile("LICENSE");
        args.clearAndFree();
        try args.append("add");
        try args.append("LICENSE");
        try main.xitMain(repo_kind, allocator, &args);

        // delete a file and dir
        {
            try repo_dir.deleteTree("docs");
            args.clearAndFree();
            try args.append("add");
            try args.append("docs/design.md");
            try main.xitMain(repo_kind, allocator, &args);
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
                    .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                    .{ .map_get = xitdb.hash_buffer("objects") },
                    .{ .map_get = xitdb.hash_buffer(&head_file_buffer) },
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
                try main.xitMain(repo_kind, allocator, &args);
            }

            // check out commit1 and make sure the conflict is found
            {
                var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
                defer repo.deinit();
                var result = chk.CheckoutResult.init();
                defer result.deinit();
                chk.checkout(repo_kind, &repo.core, allocator, &commit1, &result) catch |err| {
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
                var result = chk.CheckoutResult.init();
                defer result.deinit();
                chk.checkout(repo_kind, &repo.core, allocator, &commit1, &result) catch |err| {
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
                var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
                defer repo.deinit();
                var result = chk.CheckoutResult.init();
                defer result.deinit();
                chk.checkout(repo_kind, &repo.core, allocator, &commit1, &result) catch |err| {
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
                var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
                defer repo.deinit();
                var result = chk.CheckoutResult.init();
                defer result.deinit();
                chk.checkout(repo_kind, &repo.core, allocator, &commit1, &result) catch |err| {
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
    try main.xitMain(repo_kind, allocator, &args);

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

    // checkout master
    args.clearAndFree();
    try args.append("checkout");
    try args.append("master");
    try main.xitMain(repo_kind, allocator, &args);

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
            try std.testing.expect(index.entries.contains("hello.txt/nested.txt"));
            try std.testing.expect(index.entries.contains("hello.txt/nested2.txt"));
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
                    .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                    .{ .map_get = xitdb.hash_buffer("index") },
                })) |cursor| {
                    var iter = try cursor.iter(.map);
                    defer iter.deinit();
                    while (try iter.next()) |_| {
                        count += 1;
                    }
                }
                try expectEqual(5, count);
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
            try expectEqual(4, index.entries.count());
            try std.testing.expect(index.entries.contains("README"));
            try std.testing.expect(index.entries.contains("src/zig/main.zig"));
            try std.testing.expect(index.entries.contains("tests/main_test.zig"));
            try std.testing.expect(index.entries.contains("hello.txt"));
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
                try expectEqual(4, c.git_index_entrycount(index));
            },
            .xit => {
                // read the index in xitdb
                // TODO: use more efficient way to get map size
                var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
                defer repo.deinit();
                var count: u32 = 0;
                if (try repo.core.db.rootCursor().readCursor(void, &[_]xitdb.PathPart(void){
                    .{ .list_get = .{ .index = .{ .index = 0, .reverse = true } } },
                    .{ .map_get = xitdb.hash_buffer("index") },
                })) |cursor| {
                    var iter = try cursor.iter(.map);
                    defer iter.deinit();
                    while (try iter.next()) |_| {
                        count += 1;
                    }
                }
                try expectEqual(4, count);
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
        try expectEqual(4, tree_object.content.tree.entries.count());
    }

    // create a branch
    args.clearAndFree();
    try args.append("branch");
    try args.append("stuff");
    try main.xitMain(repo_kind, allocator, &args);

    // checkout the branch
    args.clearAndFree();
    try args.append("checkout");
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
        try expectEqual(error.CannotDeleteCurrentBranch, branch.delete(repo_kind, &repo.core, allocator, "stuff"));
    }

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
        try branch.delete(repo_kind, &repo.core, allocator, "a/b/c");
    }

    // make sure the subdirs are deleted
    if (repo_kind == .git) {
        try expectEqual(error.FileNotFound, state.git_dir.openFile("refs/heads/a/b/c", .{}));
        try expectEqual(error.FileNotFound, state.git_dir.openDir("refs/heads/a/b", .{}));
        try expectEqual(error.FileNotFound, state.git_dir.openDir("refs/heads/a", .{}));
    }

    // modify file and commit
    {
        const hello_txt = try repo_dir.openFile("hello.txt", .{ .mode = .read_write });
        defer hello_txt.close();
        try hello_txt.writeAll("hello, world once again!");

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
        try expectEqual(commit3, try ref.resolve(repo_kind, &repo.core, "stuff"));
    }

    // restore
    {
        // there is one modified file remaining
        {
            var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
            defer repo.deinit();
            var status = try repo.status();
            defer status.deinit();
            var workspace_modified_map = std.StringHashMap(void).init(allocator);
            defer workspace_modified_map.deinit();
            try expectEqual(1, status.workspace_modified.items.len);
        }

        args.clearAndFree();
        try args.append("restore");
        try args.append("README");
        try main.xitMain(repo_kind, allocator, &args);

        // there are no modified files remaining
        {
            var repo = (try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir })).?;
            defer repo.deinit();
            var status = try repo.status();
            defer status.deinit();
            var workspace_modified_map = std.StringHashMap(void).init(allocator);
            defer workspace_modified_map.deinit();
            try expectEqual(0, status.workspace_modified.items.len);
        }
    }
}

test "end to end" {
    const allocator = std.testing.allocator;
    try testMain(allocator, .git);
    try testMain(allocator, .xit);
}

test "diff" {
    const allocator = std.testing.allocator;
    const lines1 = [_][]const u8{ "A", "B", "C", "A", "B", "B", "A" };
    const lines2 = [_][]const u8{ "C", "B", "A", "B", "A", "C" };
    const expected_diff = [_][]const u8{};
    var actual_diff = try diff.Diff.init(allocator, &lines1, &lines2);
    defer actual_diff.deinit();
    try expectEqual(expected_diff.len, actual_diff.result.items.len);
    for (expected_diff, actual_diff.result.items) |expected, actual| {
        try std.testing.expectEqualStrings(expected, actual);
    }
}
