//! tests that create repos via the Repo struct.
//! runs with both git and xit modes.

const std = @import("std");
const xit = @import("xit");
const hash = xit.hash;
const rp = xit.repo;
const rf = xit.ref;
const obj = xit.object;
const mrg = xit.merge;
const df = xit.diff;
const ui = xit.ui;

fn addFile(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind), repo: *rp.Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, path: []const u8, content: []const u8) !void {
    if (std.fs.path.dirname(path)) |parent_path| {
        try repo.core.work_dir.makePath(parent_path);
    }
    const file = try repo.core.work_dir.createFile(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(content);
    try repo.add(allocator, &.{path});
}

test "simple" {
    try testSimple(.git, .{ .is_test = true });
    try testSimple(.xit, .{ .is_test = true });
    try testSimple(.xit, .{ .is_test = true, .extra = .{ .enable_patches = true } });
}

fn testSimple(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-simple";

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

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "repo");
        defer repo.deinit();
    }

    var work_dir = try temp_dir.openDir("repo", .{});
    defer work_dir.close();

    var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = work_dir });
    defer repo.deinit();

    try addFile(repo_kind, repo_opts, &repo, allocator, "README.md", "Hello, world!");
    const commit_a = try repo.commit(allocator, .{ .message = "a" });
    try addFile(repo_kind, repo_opts, &repo, allocator, "README.md", "Goodbye, world!");
    const commit_b = try repo.commit(allocator, .{ .message = "b" });
    try repo.remove(allocator, &.{"README.md"}, .{});
    const commit_c = try repo.commit(allocator, .{ .message = "c" });

    {
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, allocator, .log);
        defer root.deinit();

        const grid = try root.getGrid().?.toString(allocator);
        defer allocator.free(grid);

        var grid_without_tabs = grid;
        for (0..3) |_| {
            grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
        }

        try std.testing.expectEqualStrings(
            \\┌─┐                           ┌──────────────────────────────────────────────────────────┐
            \\│c│                           │                                                          │
            \\└─┘                           │ diff --git a/README.md b/README.md                       │
            \\                              │ deleted file mode 100644                                 │
            \\ b                            │ index 6b49ab7..0000000                                   │
            \\                              │ --- a/README.md                                          │
            \\                              │ +++ /dev/null                                            │
            \\ a                            │                                                          │
            \\                              │                                                          │
            \\                              │                                                          │
            \\                              │ @@ -0,1 +0,0 @@                                          │
            \\                              │ - Goodbye, world!                                        │
            \\                              │                                                          │
            \\                              │                                                          │
            \\                              └──────────────────────────────────────────────────────────┘
        , grid_without_tabs);
    }

    // can't add path that is outside repo
    try std.testing.expectError(error.PathIsOutsideRepo, repo.add(allocator, &.{"../README.md"}));

    // commits that haven't changed content are an error
    try std.testing.expectError(error.EmptyCommit, repo.commit(allocator, .{ .message = "d" }));

    // put oids in a set
    var oid_set = std.StringArrayHashMap(void).init(allocator);
    defer oid_set.deinit();
    try oid_set.put(&commit_a, {});
    try oid_set.put(&commit_b, {});
    try oid_set.put(&commit_c, {});

    // assert that all commits have been found in the log
    {
        var commit_iter = try repo.log(allocator, null);
        defer commit_iter.deinit();
        while (try commit_iter.next()) |commit_object| {
            defer commit_object.deinit();
            _ = oid_set.swapRemove(&commit_object.oid);
        }
        try std.testing.expectEqual(0, oid_set.count());
    }

    {
        var result = try repo.resetDir(allocator, .{ .target = .{ .oid = &commit_b } });
        defer result.deinit();
    }

    {
        const readme = try repo.core.work_dir.openFile("README.md", .{ .mode = .read_only });
        defer readme.close();
        const readme_content = try readme.readToEndAlloc(allocator, 1024);
        defer allocator.free(readme_content);
        try std.testing.expectEqualStrings("Goodbye, world!", readme_content);
    }

    {
        var result = try repo.resetDir(allocator, .{ .target = .{ .oid = &commit_a } });
        defer result.deinit();
    }

    {
        const readme = try repo.core.work_dir.openFile("README.md", .{ .mode = .read_only });
        defer readme.close();
        const readme_content = try readme.readToEndAlloc(allocator, 1024);
        defer allocator.free(readme_content);
        try std.testing.expectEqualStrings("Hello, world!", readme_content);
    }

    {
        var result = try repo.resetDir(allocator, .{ .target = .{ .oid = &commit_c } });
        defer result.deinit();
    }

    if (repo.core.work_dir.openFile("README.md", .{ .mode = .read_only })) |readme| {
        readme.close();
        return error.FileNotExpected;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => |e| return e,
    }

    _ = try repo.addTag(allocator, .{ .name = "1.0.0", .message = "hi" });

    // we can enable patches after adding a tag
    if (repo_kind == .xit) {
        try repo.patchAll(allocator, null);
    }

    {
        // we can set the tag to HEAD
        var result = try repo.resetDir(allocator, .{ .target = .{ .ref = .{ .kind = .tag, .name = "1.0.0" } } });
        defer result.deinit();

        // status works when HEAD points to a tag
        var status = try repo.status(allocator);
        defer status.deinit(allocator);
    }
}

test "merge" {
    try testMerge(.git, .{ .is_test = true });
    try testMerge(.xit, .{ .is_test = true });
    try testMerge(.xit, .{ .is_test = true, .extra = .{ .enable_patches = true } });
}

fn testMerge(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-merge";

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

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "repo");
        defer repo.deinit();
    }

    var work_dir = try temp_dir.openDir("repo", .{});
    defer work_dir.close();

    var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = work_dir });
    defer repo.deinit();

    // A --- B --- C --------- J --- K [master]
    //        \               /
    //         \             /
    //          D --- E --- F [foo]
    //           \
    //            \
    //             G --- H [bar]

    try addFile(repo_kind, repo_opts, &repo, allocator, "master.md", "a");
    _ = try repo.commit(allocator, .{ .message = "a" });
    try addFile(repo_kind, repo_opts, &repo, allocator, "master.md", "b");
    _ = try repo.commit(allocator, .{ .message = "b" });
    try repo.addBranch(.{ .name = "foo" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, allocator, "foo.md", "d");
    const commit_d = try repo.commit(allocator, .{ .message = "d" });
    try repo.addBranch(.{ .name = "bar" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "bar" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, allocator, "bar.md", "g");
    _ = try repo.commit(allocator, .{ .message = "g" });
    try addFile(repo_kind, repo_opts, &repo, allocator, "bar.md", "h");
    const commit_h = try repo.commit(allocator, .{ .message = "h" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, allocator, "master.md", "c");
    _ = try repo.commit(allocator, .{ .message = "c" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, allocator, "foo.md", "e");
    _ = try repo.commit(allocator, .{ .message = "e" });
    try addFile(repo_kind, repo_opts, &repo, allocator, "foo.md", "f");
    _ = try repo.commit(allocator, .{ .message = "f" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    const commit_j = blk: {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
        break :blk merge.result.success.oid;
    };
    try addFile(repo_kind, repo_opts, &repo, allocator, "master.md", "k");
    const commit_k = try repo.commit(allocator, .{ .message = "k" });

    var moment = try repo.core.latestMoment();
    const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };

    // there are multiple common ancestors, b and d,
    // but d is the best one because it is a descendent of b
    const ancestor_k_h = try mrg.commonAncestor(repo_kind, repo_opts, allocator, state, &commit_k, &commit_h);
    try std.testing.expectEqualStrings(&commit_d, &ancestor_k_h);

    // if one commit is an ancestor of the other, it is the best common ancestor
    const ancestor_k_j = try mrg.commonAncestor(repo_kind, repo_opts, allocator, state, &commit_k, &commit_j);
    try std.testing.expectEqualStrings(&commit_j, &ancestor_k_j);

    // if we try merging foo again, it does nothing
    {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.nothing == merge.result);
    }

    // if we try merging master into foo, it fast forwards
    {
        var switch_result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer switch_result.deinit();
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "master" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.fast_forward == merge.result);

        const head_oid = try rf.readHeadRecur(repo_kind, repo_opts, state);
        try std.testing.expectEqual(commit_k, head_oid);

        // make sure file from commit k exists
        var master_md = try repo.core.work_dir.openFile("master.md", .{});
        defer master_md.close();
        const master_md_content = try master_md.readToEndAlloc(allocator, 1024);
        defer allocator.free(master_md_content);
        try std.testing.expectEqualStrings("k", master_md_content);
    }

    // copy all objects to a new repo.
    // this will fail if we are not correctly resetting tx_start
    // in `writeAndApplyPatches`, because we'll end up mutating
    // the snapshot of the base commit due to the fact that it has
    // more than one child commits. if that explanation doesn't
    // make sense to you, you're not alone...my future self won't
    // know what it means either probably.
    {
        var obj_iter = try obj.ObjectIterator(repo_kind, repo_opts, .raw).init(allocator, state, .{ .kind = .all });
        defer obj_iter.deinit();
        try obj_iter.include(&commit_k);

        var dest_repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "dest_repo");
        defer dest_repo.deinit();
        try dest_repo.copyObjects(repo_kind, repo_opts, &obj_iter, null);

        var dest_obj_iter = try dest_repo.log(allocator, &.{commit_k});
        defer dest_obj_iter.deinit();
        const dest_commit_k = (try dest_obj_iter.next()) orelse return error.ExpectedObject;
        defer dest_commit_k.deinit();
    }
}

test "merge side branch" {
    try testMergeSideBranch(.git, .{ .is_test = true });
    try testMergeSideBranch(.xit, .{ .is_test = true });
    try testMergeSideBranch(.xit, .{ .is_test = true, .extra = .{ .enable_patches = true } });
}

fn testMergeSideBranch(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-merge-side-branch";

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

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "repo");
        defer repo.deinit();
    }

    var work_dir = try temp_dir.openDir("repo", .{});
    defer work_dir.close();

    var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = work_dir });
    defer repo.deinit();

    //           C <------ D [side]
    //          /           \
    //         /             \
    // A <--- B <---- E <---- F <---- G [master]
    //                 \
    //                  \
    //                   \
    //                    H <---- I <---- J [topic]

    try addFile(repo_kind, repo_opts, &repo, allocator, "master.md", "a");
    _ = try repo.commit(allocator, .{ .message = "a" });

    try addFile(repo_kind, repo_opts, &repo, allocator, "master.md", "b");
    _ = try repo.commit(allocator, .{ .message = "b" });

    try repo.addBranch(.{ .name = "side" });

    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "side" } } });
        defer result.deinit();
    }

    try addFile(repo_kind, repo_opts, &repo, allocator, "side.md", "c");
    _ = try repo.commit(allocator, .{ .message = "c" });

    try addFile(repo_kind, repo_opts, &repo, allocator, "side.md", "d");
    _ = try repo.commit(allocator, .{ .message = "d" });

    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }

    try addFile(repo_kind, repo_opts, &repo, allocator, "master.md", "e");
    const commit_e = try repo.commit(allocator, .{ .message = "e" });

    try repo.addBranch(.{ .name = "topic" });

    // commit f
    _ = blk: {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "side" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
        break :blk merge.result.success.oid;
    };

    try addFile(repo_kind, repo_opts, &repo, allocator, "master.md", "g");
    const commit_g = try repo.commit(allocator, .{ .message = "g" });

    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "topic" } } });
        defer result.deinit();
    }

    try addFile(repo_kind, repo_opts, &repo, allocator, "topic.md", "h");
    _ = try repo.commit(allocator, .{ .message = "h" });

    try addFile(repo_kind, repo_opts, &repo, allocator, "topic.md", "i");
    _ = try repo.commit(allocator, .{ .message = "i" });

    try addFile(repo_kind, repo_opts, &repo, allocator, "topic.md", "j");
    const commit_j = try repo.commit(allocator, .{ .message = "j" });

    var moment = try repo.core.latestMoment();
    const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };

    const ancestor_g_j = try mrg.commonAncestor(repo_kind, repo_opts, allocator, state, &commit_g, &commit_j);
    try std.testing.expectEqualStrings(&commit_e, &ancestor_g_j);
}

test "merge conflict" {
    // read and write objects in small increments to help uncover bugs

    // same file conflict
    try testMergeConflictSameFile(.git, .{ .read_size = 1, .is_test = true });
    try testMergeConflictSameFile(.xit, .{ .read_size = 1, .is_test = true, .extra = .{
        .chunk_opts = .{ .min_size = 1, .avg_size = 2, .max_size = 4, .normalization = .level1 },
    } });
    try testMergeConflictSameFile(.xit, .{ .is_test = true, .extra = .{
        .chunk_opts = .{ .min_size = 1, .avg_size = 2, .max_size = 4, .normalization = .level1 },
        .enable_patches = true,
    } });

    // same file conflict with an empty base
    try testMergeConflictSameFileEmptyBase(.git, .{ .read_size = 1, .is_test = true });
    try testMergeConflictSameFileEmptyBase(.xit, .{ .read_size = 1, .is_test = true, .extra = .{
        .chunk_opts = .{ .min_size = 1, .avg_size = 2, .max_size = 4, .normalization = .level1 },
    } });
    try testMergeConflictSameFileEmptyBase(.xit, .{ .is_test = true, .extra = .{
        .chunk_opts = .{ .min_size = 1, .avg_size = 2, .max_size = 4, .normalization = .level1 },
        .enable_patches = true,
    } });

    // same file conflict that is autoresolved
    try testMergeConflictSameFileAutoresolved(.git, .{ .read_size = 1, .is_test = true });
    try testMergeConflictSameFileAutoresolved(.xit, .{ .read_size = 1, .is_test = true, .extra = .{
        .chunk_opts = .{ .min_size = 1, .avg_size = 2, .max_size = 4, .normalization = .level1 },
    } });
    try testMergeConflictSameFileAutoresolved(.xit, .{ .is_test = true, .extra = .{
        .chunk_opts = .{ .min_size = 1, .avg_size = 2, .max_size = 4, .normalization = .level1 },
        .enable_patches = true,
    } });

    // delete/modify conflict (target deletes, source modifies)
    try testMergeConflictModifyDelete(.git, .{ .read_size = 1, .is_test = true });
    try testMergeConflictModifyDelete(.xit, .{ .read_size = 1, .is_test = true, .extra = .{
        .chunk_opts = .{ .min_size = 1, .avg_size = 2, .max_size = 4, .normalization = .level1 },
    } });
    try testMergeConflictModifyDelete(.xit, .{ .is_test = true, .extra = .{
        .chunk_opts = .{ .min_size = 1, .avg_size = 2, .max_size = 4, .normalization = .level1 },
        .enable_patches = true,
    } });

    // delete/modify conflict (target deletes, source modifies)
    try testMergeConflictDeleteModify(.git, .{ .read_size = 1, .is_test = true });
    try testMergeConflictDeleteModify(.xit, .{ .read_size = 1, .is_test = true, .extra = .{
        .chunk_opts = .{ .min_size = 1, .avg_size = 2, .max_size = 4, .normalization = .level1 },
    } });
    try testMergeConflictDeleteModify(.xit, .{ .is_test = true, .extra = .{
        .chunk_opts = .{ .min_size = 1, .avg_size = 2, .max_size = 4, .normalization = .level1 },
        .enable_patches = true,
    } });

    // file/dir conflict (target has file, source has dir)
    try testMergeConflictFileDir(.git, .{ .read_size = 1, .is_test = true });
    try testMergeConflictFileDir(.xit, .{ .read_size = 1, .is_test = true, .extra = .{
        .chunk_opts = .{ .min_size = 1, .avg_size = 2, .max_size = 4, .normalization = .level1 },
    } });
    try testMergeConflictFileDir(.xit, .{ .is_test = true, .extra = .{
        .chunk_opts = .{ .min_size = 1, .avg_size = 2, .max_size = 4, .normalization = .level1 },
        .enable_patches = true,
    } });

    // dir/file conflict (target has dir, source has file)
    try testMergeConflictDirFile(.git, .{ .read_size = 1, .is_test = true });
    try testMergeConflictDirFile(.xit, .{ .read_size = 1, .is_test = true, .extra = .{
        .chunk_opts = .{ .min_size = 1, .avg_size = 2, .max_size = 4, .normalization = .level1 },
    } });
    try testMergeConflictDirFile(.xit, .{ .is_test = true, .extra = .{
        .chunk_opts = .{ .min_size = 1, .avg_size = 2, .max_size = 4, .normalization = .level1 },
        .enable_patches = true,
    } });
}

fn testMergeConflictSameFile(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-merge-conflict-same-file";

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

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "repo");
        defer repo.deinit();
    }

    var work_dir = try temp_dir.openDir("repo", .{});
    defer work_dir.close();

    var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = work_dir });
    defer repo.deinit();

    // A --- B --- D [master]
    //  \         /
    //   \       /
    //    `---- C [foo]

    try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt",
        \\a
        \\b
        \\c
    );
    _ = try repo.commit(allocator, .{ .message = "a" });
    try repo.addBranch(.{ .name = "foo" });
    try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt",
        \\a
        \\x
        \\c
    );
    _ = try repo.commit(allocator, .{ .message = "b" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt",
        \\a
        \\y
        \\c
    );
    _ = try repo.commit(allocator, .{ .message = "c" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.conflict == merge.result);

        // verify f.txt has conflict markers
        const f_txt = try repo.core.work_dir.openFile("f.txt", .{ .mode = .read_only });
        defer f_txt.close();
        const f_txt_content = try f_txt.readToEndAlloc(allocator, 1024);
        defer allocator.free(f_txt_content);
        const expected_f_txt_content = try std.fmt.allocPrint(allocator,
            \\a
            \\<<<<<<< target (master)
            \\x
            \\||||||| base ({s})
            \\b
            \\=======
            \\y
            \\>>>>>>> source (foo)
            \\c
        , .{merge.base_oid});
        defer allocator.free(expected_f_txt_content);
        try std.testing.expectEqualStrings(expected_f_txt_content, f_txt_content);
    }

    {
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, allocator, .status);
        defer root.deinit();

        const grid = try root.getGrid().?.toString(allocator);
        defer allocator.free(grid);

        var grid_without_tabs = grid;
        for (0..3) |_| {
            grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
        }

        try std.testing.expectEqualStrings(
            \\           ┌─────────────┐                                                       
            \\ added (0) │not added (1)│ not tracked (0)                                       
            \\           └─────────────┘                                                       
            \\   ┌─────┐          ┌───────────────────────────────────────────────────────────┐
            \\ ≠ │f.txt│          │                                                           │
            \\   └─────┘          │ diff --git a/f.txt b/f.txt                                │
            \\                    │ index 98d5083..c3736c3 100644                             │
            \\                    │ --- a/f.txt                                               │
            \\                    │ +++ b/f.txt                                               │
            \\                    │                                                           │
            \\                    │                                                           │
            \\                    │                                                           │
            \\                    │ @@ -1,3 +1,9 @@                                           │
            \\                    │   a                                                       │
            \\                    │ + <<<<<<< target (master)                                 │
            \\                    │   x                                                       │
            \\                    │ + ||||||| base (31791fdb2aea4e32bde323475a03cfec7ad51bf4) │
            \\                    │ + b                                                       │
            \\                    │ + =======                                                 │
            \\                    │ + y                                                       │
            \\                    │ + >>>>>>> source (foo)                                    │
            \\                    │   c                                                       │
            \\                    │                                                           │
            \\                    │                                                           │
            \\                    └───────────────────────────────────────────────────────────┘
        , grid_without_tabs);
    }

    // generate diff
    var status = try repo.status(allocator);
    defer status.deinit(allocator);
    var file_iter = try repo.filePairs(allocator, .{
        .work_dir = .{
            .conflict_diff_kind = .target,
            .status = &status,
        },
    });
    if (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();
    } else {
        return error.DiffResultExpected;
    }

    // ensure merge cannot be run again while there are unresolved conflicts
    {
        // can't merge again with an unresolved merge
        {
            var result_or_err = repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.UnfinishedMergeInProgress => {},
                else => |e| return e,
            }
        }

        // can't continue merge with unresolved conflicts
        {
            var result_or_err = repo.merge(allocator, .{ .kind = .full, .action = .cont }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.CannotContinueMergeWithUnresolvedConflicts => {},
                else => |e| return e,
            }
        }
    }

    // resolve conflict with changes from source branch
    try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt",
        \\a
        \\y
        \\c
    );

    {
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, allocator, .status);
        defer root.deinit();

        const grid = try root.getGrid().?.toString(allocator);
        defer allocator.free(grid);

        var grid_without_tabs = grid;
        for (0..3) |_| {
            grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
        }

        try std.testing.expectEqualStrings(
            \\┌─────────┐                                                                     
            \\│added (1)│ not added (0)  not tracked (0)                                      
            \\└─────────┘                                                                     
            \\   ┌─────┐          ┌──────────────────────────────────────────────────────────┐
            \\ ± │f.txt│          │                                                          │
            \\   └─────┘          │ diff --git a/f.txt b/f.txt                               │
            \\                    │ index 98d5083..ae42890 100644                            │
            \\                    │ --- a/f.txt                                              │
            \\                    │ +++ b/f.txt                                              │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    │ @@ -1,3 +1,3 @@                                          │
            \\                    │   a                                                      │
            \\                    │ - x                                                      │
            \\                    │ + y                                                      │
            \\                    │   c                                                      │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    └──────────────────────────────────────────────────────────┘
        , grid_without_tabs);
    }

    // resolve conflict with changes from target branch
    try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt",
        \\a
        \\x
        \\c
    );

    {
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, allocator, .status);
        defer root.deinit();

        const grid = try root.getGrid().?.toString(allocator);
        defer allocator.free(grid);

        var grid_without_tabs = grid;
        for (0..3) |_| {
            grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
        }

        try std.testing.expectEqualStrings(
            \\┌─────────┐                                                                     
            \\│added (1)│ not added (0)  not tracked (0)                                      
            \\└─────────┘                                                                     
            \\   ┌─────┐          ┌──────────────────────────────────────────────────────────┐
            \\ ≠ │f.txt│          │                                                          │
            \\   └─────┘          │ diff --git a/f.txt b/f.txt                               │
            \\                    │ index ae42890..98d5083 100644                            │
            \\                    │ --- a/f.txt                                              │
            \\                    │ +++ b/f.txt                                              │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    │ @@ -1,3 +1,3 @@                                          │
            \\                    │   a                                                      │
            \\                    │ - y                                                      │
            \\                    │ + x                                                      │
            \\                    │   c                                                      │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    └──────────────────────────────────────────────────────────┘
        , grid_without_tabs);
    }

    {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .cont }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
    }

    // if we try merging foo again, it does nothing
    {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.nothing == merge.result);
    }
}

fn testMergeConflictSameFileEmptyBase(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-merge-conflict-same-file-empty-base";

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

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "repo");
        defer repo.deinit();
    }

    var work_dir = try temp_dir.openDir("repo", .{});
    defer work_dir.close();

    var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = work_dir });
    defer repo.deinit();

    // A --- B --- D [master]
    //  \         /
    //   \       /
    //    `---- C [foo]

    // commit A (base commit) is empty
    _ = try repo.commit(allocator, .{ .message = "a", .allow_empty = true });

    // newlines are intentionally added to the end of the files this time,
    // to test that the merge code behaves correctly with end lines of zero length

    try repo.addBranch(.{ .name = "foo" });
    try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt",
        \\a
        \\x
        \\c
        \\
    );
    _ = try repo.commit(allocator, .{ .message = "b" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt",
        \\a
        \\y
        \\c
        \\
    );
    _ = try repo.commit(allocator, .{ .message = "c" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.conflict == merge.result);

        // verify f.txt has conflict markers
        const f_txt = try repo.core.work_dir.openFile("f.txt", .{ .mode = .read_only });
        defer f_txt.close();
        const f_txt_content = try f_txt.readToEndAlloc(allocator, 1024);
        defer allocator.free(f_txt_content);
        const expected_f_txt_content = try std.fmt.allocPrint(allocator,
            \\<<<<<<< target (master)
            \\a
            \\x
            \\c
            \\
            \\||||||| base ({s})
            \\=======
            \\a
            \\y
            \\c
            \\
            \\>>>>>>> source (foo)
        , .{merge.base_oid});
        defer allocator.free(expected_f_txt_content);
        try std.testing.expectEqualStrings(expected_f_txt_content, f_txt_content);
    }

    {
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, allocator, .status);
        defer root.deinit();

        const grid = try root.getGrid().?.toString(allocator);
        defer allocator.free(grid);

        var grid_without_tabs = grid;
        for (0..3) |_| {
            grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
        }

        try std.testing.expectEqualStrings(
            \\           ┌─────────────┐                                                       
            \\ added (0) │not added (1)│ not tracked (0)                                       
            \\           └─────────────┘                                                       
            \\   ┌─────┐          ┌───────────────────────────────────────────────────────────┐
            \\ ≠ │f.txt│          │                                                           │
            \\   └─────┘          │ diff --git a/f.txt b/f.txt                                │
            \\                    │ index f5aa8c1..c4f76dc 100644                             │
            \\                    │ --- a/f.txt                                               │
            \\                    │ +++ b/f.txt                                               │
            \\                    │                                                           │
            \\                    │                                                           │
            \\                    │                                                           │
            \\                    │ @@ -1,4 +1,12 @@                                          │
            \\                    │ + <<<<<<< target (master)                                 │
            \\                    │   a                                                       │
            \\                    │   x                                                       │
            \\                    │ + c                                                       │
            \\                    │ +                                                         │
            \\                    │ + ||||||| base (7b0a80ff255e0024621edbbb4d75b2859e8601e9) │
            \\                    │ + =======                                                 │
            \\                    │ + a                                                       │
            \\                    │ + y                                                       │
            \\                    │   c                                                       │
            \\                    │                                                           │
            \\                    │ + >>>>>>> source (foo)                                    │
            \\                    │                                                           │
            \\                    │                                                           │
            \\                    └───────────────────────────────────────────────────────────┘
        , grid_without_tabs);
    }

    // generate diff
    var status = try repo.status(allocator);
    defer status.deinit(allocator);
    var file_iter = try repo.filePairs(allocator, .{
        .work_dir = .{
            .conflict_diff_kind = .target,
            .status = &status,
        },
    });
    if (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();
    } else {
        return error.DiffResultExpected;
    }

    // ensure merge cannot be run again while there are unresolved conflicts
    {
        // can't merge again with an unresolved merge
        {
            var result_or_err = repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.UnfinishedMergeInProgress => {},
                else => |e| return e,
            }
        }

        // can't continue merge with unresolved conflicts
        {
            var result_or_err = repo.merge(allocator, .{ .kind = .full, .action = .cont }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.CannotContinueMergeWithUnresolvedConflicts => {},
                else => |e| return e,
            }
        }
    }

    // resolve conflict with changes from source branch
    try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt",
        \\a
        \\y
        \\c
        \\
    );

    {
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, allocator, .status);
        defer root.deinit();

        const grid = try root.getGrid().?.toString(allocator);
        defer allocator.free(grid);

        var grid_without_tabs = grid;
        for (0..3) |_| {
            grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
        }

        try std.testing.expectEqualStrings(
            \\┌─────────┐                                                                     
            \\│added (1)│ not added (0)  not tracked (0)                                      
            \\└─────────┘                                                                     
            \\   ┌─────┐          ┌──────────────────────────────────────────────────────────┐
            \\ ± │f.txt│          │                                                          │
            \\   └─────┘          │ diff --git a/f.txt b/f.txt                               │
            \\                    │ index f5aa8c1..475bb7f 100644                            │
            \\                    │ --- a/f.txt                                              │
            \\                    │ +++ b/f.txt                                              │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    │ @@ -1,4 +1,4 @@                                          │
            \\                    │   a                                                      │
            \\                    │ - x                                                      │
            \\                    │ + y                                                      │
            \\                    │   c                                                      │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    └──────────────────────────────────────────────────────────┘
        , grid_without_tabs);
    }

    // resolve conflict with changes from target branch
    try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt",
        \\a
        \\x
        \\c
        \\
    );

    {
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, allocator, .status);
        defer root.deinit();

        const grid = try root.getGrid().?.toString(allocator);
        defer allocator.free(grid);

        var grid_without_tabs = grid;
        for (0..3) |_| {
            grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
        }

        try std.testing.expectEqualStrings(
            \\┌─────────┐                                                                     
            \\│added (1)│ not added (0)  not tracked (0)                                      
            \\└─────────┘                                                                     
            \\   ┌─────┐          ┌──────────────────────────────────────────────────────────┐
            \\ ≠ │f.txt│          │                                                          │
            \\   └─────┘          │ diff --git a/f.txt b/f.txt                               │
            \\                    │ index 475bb7f..f5aa8c1 100644                            │
            \\                    │ --- a/f.txt                                              │
            \\                    │ +++ b/f.txt                                              │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    │ @@ -1,4 +1,4 @@                                          │
            \\                    │   a                                                      │
            \\                    │ - y                                                      │
            \\                    │ + x                                                      │
            \\                    │   c                                                      │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    └──────────────────────────────────────────────────────────┘
        , grid_without_tabs);
    }

    {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .cont }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
    }

    // if we try merging foo again, it does nothing
    {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.nothing == merge.result);
    }
}

fn testMergeConflictSameFileAutoresolved(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-merge-conflict-same-file-autoresolved";

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

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "repo");
        defer repo.deinit();
    }

    var work_dir = try temp_dir.openDir("repo", .{});
    defer work_dir.close();

    var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = work_dir });
    defer repo.deinit();

    // A --- B --- D [master]
    //  \         /
    //   \       /
    //    `---- C [foo]

    try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt",
        \\a
        \\b
        \\c
    );
    _ = try repo.commit(allocator, .{ .message = "a" });
    try repo.addBranch(.{ .name = "foo" });
    try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt",
        \\x
        \\b
        \\c
    );
    _ = try repo.commit(allocator, .{ .message = "b" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt",
        \\a
        \\b
        \\y
    );
    _ = try repo.commit(allocator, .{ .message = "c" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);

        // verify f.txt has been autoresolved
        const f_txt = try repo.core.work_dir.openFile("f.txt", .{ .mode = .read_only });
        defer f_txt.close();
        const f_txt_content = try f_txt.readToEndAlloc(allocator, 1024);
        defer allocator.free(f_txt_content);
        try std.testing.expectEqualStrings(
            \\x
            \\b
            \\y
        ,
            f_txt_content,
        );
    }

    // generate diff
    var status = try repo.status(allocator);
    defer status.deinit(allocator);
    var file_iter = try repo.filePairs(allocator, .{
        .work_dir = .{
            .conflict_diff_kind = .target,
            .status = &status,
        },
    });
    if (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();
        return error.DiffResultNotExpected;
    }

    // if we try merging foo again, it does nothing
    {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.nothing == merge.result);
    }
}

fn testMergeConflictModifyDelete(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-merge-conflict-modify-delete";

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

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "repo");
        defer repo.deinit();
    }

    var work_dir = try temp_dir.openDir("repo", .{});
    defer work_dir.close();

    var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = work_dir });
    defer repo.deinit();

    // A --- B --- D [master]
    //  \         /
    //   \       /
    //    `---- C [foo]

    try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt", "1");
    _ = try repo.commit(allocator, .{ .message = "a" });
    try repo.addBranch(.{ .name = "foo" });
    try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt", "2");
    _ = try repo.commit(allocator, .{ .message = "b" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try repo.remove(allocator, &.{"f.txt"}, .{});
    _ = try repo.commit(allocator, .{ .message = "c" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.conflict == merge.result);
    }

    {
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, allocator, .status);
        defer root.deinit();

        const grid = try root.getGrid().?.toString(allocator);
        defer allocator.free(grid);

        var grid_without_tabs = grid;
        for (0..3) |_| {
            grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
        }

        try std.testing.expectEqualStrings(
            \\           ┌─────────────┐                                                      
            \\ added (0) │not added (1)│ not tracked (0)                                      
            \\           └─────────────┘                                                      
            \\   ┌─────┐          ┌──────────────────────────────────────────────────────────┐
            \\ ≠ │f.txt│          │                                                          │
            \\   └─────┘          │ diff --git a/f.txt b/f.txt                               │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    └──────────────────────────────────────────────────────────┘
        , grid_without_tabs);
    }

    // generate diff
    var status = try repo.status(allocator);
    defer status.deinit(allocator);
    var file_iter = try repo.filePairs(allocator, .{
        .work_dir = .{
            .conflict_diff_kind = .target,
            .status = &status,
        },
    });
    if (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();
        try std.testing.expectEqualStrings("f.txt", line_iter_pair.path);
    } else {
        return error.DiffResultExpected;
    }

    // ensure merge cannot be run again while there are unresolved conflicts
    {
        // can't merge again with an unresolved merge
        {
            var result_or_err = repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.UnfinishedMergeInProgress => {},
                else => |e| return e,
            }
        }

        // can't continue merge with unresolved conflicts
        {
            var result_or_err = repo.merge(allocator, .{ .kind = .full, .action = .cont }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.CannotContinueMergeWithUnresolvedConflicts => {},
                else => |e| return e,
            }
        }
    }

    // resolve conflict
    try repo.add(allocator, &.{"f.txt"});
    {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .cont }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
    }

    // if we try merging foo again, it does nothing
    {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.nothing == merge.result);
    }
}

fn testMergeConflictDeleteModify(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-merge-conflict-delete-modify";

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

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "repo");
        defer repo.deinit();
    }

    var work_dir = try temp_dir.openDir("repo", .{});
    defer work_dir.close();

    var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = work_dir });
    defer repo.deinit();

    // A --- B --- D [master]
    //  \         /
    //   \       /
    //    `---- C [foo]

    try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt", "1");
    _ = try repo.commit(allocator, .{ .message = "a" });
    try repo.addBranch(.{ .name = "foo" });
    try repo.remove(allocator, &.{"f.txt"}, .{});
    _ = try repo.commit(allocator, .{ .message = "b" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt", "2");
    _ = try repo.commit(allocator, .{ .message = "c" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.conflict == merge.result);
    }

    {
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, allocator, .status);
        defer root.deinit();

        const grid = try root.getGrid().?.toString(allocator);
        defer allocator.free(grid);

        var grid_without_tabs = grid;
        for (0..3) |_| {
            grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
        }

        try std.testing.expectEqualStrings(
            \\           ┌─────────────┐                                                      
            \\ added (0) │not added (1)│ not tracked (0)                                      
            \\           └─────────────┘                                                      
            \\   ┌─────┐          ┌──────────────────────────────────────────────────────────┐
            \\ ≠ │f.txt│          │                                                          │
            \\   └─────┘          │ diff --git a/f.txt b/f.txt                               │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    └──────────────────────────────────────────────────────────┘
        , grid_without_tabs);
    }

    // generate diff
    var status = try repo.status(allocator);
    defer status.deinit(allocator);
    var file_iter = try repo.filePairs(allocator, .{
        .work_dir = .{
            .conflict_diff_kind = .target,
            .status = &status,
        },
    });
    if (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();
        return error.DiffResultNotExpected;
    }

    // ensure merge cannot be run again while there are unresolved conflicts
    {
        // can't merge again with an unresolved merge
        {
            var result_or_err = repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.UnfinishedMergeInProgress => {},
                else => |e| return e,
            }
        }

        // can't continue merge with unresolved conflicts
        {
            var result_or_err = repo.merge(allocator, .{ .kind = .full, .action = .cont }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.CannotContinueMergeWithUnresolvedConflicts => {},
                else => |e| return e,
            }
        }
    }

    // resolve conflict
    try repo.add(allocator, &.{"f.txt"});
    {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .cont }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
    }

    // if we try merging foo again, it does nothing
    {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.nothing == merge.result);
    }
}

fn testMergeConflictFileDir(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-merge-conflict-file-dir";

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

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "repo");
        defer repo.deinit();
    }

    var work_dir = try temp_dir.openDir("repo", .{});
    defer work_dir.close();

    var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = work_dir });
    defer repo.deinit();

    // A --- B --- D [master]
    //  \         /
    //   \       /
    //    `---- C [foo]

    try addFile(repo_kind, repo_opts, &repo, allocator, "hi.txt", "hi");
    _ = try repo.commit(allocator, .{ .message = "a" });
    try repo.addBranch(.{ .name = "foo" });
    try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt", "hi");
    _ = try repo.commit(allocator, .{ .message = "b" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt/g.txt", "hi");
    _ = try repo.commit(allocator, .{ .message = "c" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.conflict == merge.result);
    }

    // make sure renamed file exists
    var renamed_file = try repo.core.work_dir.openFile("f.txt~master", .{});
    defer renamed_file.close();

    {
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, allocator, .status);
        defer root.deinit();

        {
            const grid = try root.getGrid().?.toString(allocator);
            defer allocator.free(grid);

            var grid_without_tabs = grid;
            for (0..3) |_| {
                grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
            }

            try std.testing.expectEqualStrings(
                \\┌─────────┐                                                                     
                \\│added (1)│ not added (1)  not tracked (1)                                      
                \\└─────────┘                                                                     
                \\   ┌───────────┐    ┌──────────────────────────────────────────────────────────┐
                \\ + │f.txt/g.txt│    │                                                          │
                \\   └───────────┘    │ diff --git a/f.txt/g.txt b/f.txt/g.txt                   │
                \\                    │ new file mode 100644                                     │
                \\                    │ index 0000000..32f95c0                                   │
                \\                    │ --- a/f.txt/g.txt                                        │
                \\                    │ +++ b/f.txt/g.txt                                        │
                \\                    │                                                          │
                \\                    │                                                          │
                \\                    │                                                          │
                \\                    │ @@ -0,0 +0,1 @@                                          │
                \\                    │ + hi                                                     │
                \\                    │                                                          │
                \\                    │                                                          │
                \\                    └──────────────────────────────────────────────────────────┘
            , grid_without_tabs);
        }

        try ui.input(repo_kind, repo_opts, &root, .arrow_down);
        try ui.input(repo_kind, repo_opts, &root, .arrow_right);

        {
            const grid = try root.getGrid().?.toString(allocator);
            defer allocator.free(grid);

            var grid_without_tabs = grid;
            for (0..3) |_| {
                grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
            }

            try std.testing.expectEqualStrings(
                \\           ╔═════════════╗                                                      
                \\ added (1) ║not added (1)║ not tracked (1)                                      
                \\           ╚═════════════╝                                                      
                \\   ┌─────┐          ┌──────────────────────────────────────────────────────────┐
                \\ ≠ │f.txt│          │                                                          │
                \\   └─────┘          └──────────────────────────────────────────────────────────┘
            , grid_without_tabs);
        }

        try ui.input(repo_kind, repo_opts, &root, .arrow_right);

        {
            const grid = try root.getGrid().?.toString(allocator);
            defer allocator.free(grid);

            var grid_without_tabs = grid;
            for (0..3) |_| {
                grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
            }

            try std.testing.expectEqualStrings(
                \\                          ╔═══════════════╗                                     
                \\ added (1)  not added (1) ║not tracked (1)║                                     
                \\                          ╚═══════════════╝                                     
                \\   ┌────────────┐   ┌──────────────────────────────────────────────────────────┐
                \\ ? │f.txt~master│   │                                                          │
                \\   └────────────┘   │ diff --git a/f.txt~master b/f.txt~master                 │
                \\                    │ new file mode 100644                                     │
                \\                    │ index 0000000..32f95c0                                   │
                \\                    │ --- a/f.txt~master                                       │
                \\                    │ +++ b/f.txt~master                                       │
                \\                    │                                                          │
                \\                    │                                                          │
                \\                    │                                                          │
                \\                    │ @@ -0,0 +0,1 @@                                          │
                \\                    │ + hi                                                     │
                \\                    │                                                          │
                \\                    │                                                          │
                \\                    └──────────────────────────────────────────────────────────┘
            , grid_without_tabs);
        }
    }

    // generate diff
    var status = try repo.status(allocator);
    defer status.deinit(allocator);
    var file_iter = try repo.filePairs(allocator, .{
        .work_dir = .{
            .conflict_diff_kind = .target,
            .status = &status,
        },
    });
    if (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();
        try std.testing.expectEqualStrings("f.txt", line_iter_pair.path);
    } else {
        return error.DiffResultExpected;
    }

    // ensure merge cannot be run again while there are unresolved conflicts
    {
        // can't merge again with an unresolved merge
        {
            var result_or_err = repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.UnfinishedMergeInProgress => {},
                else => |e| return e,
            }
        }

        // can't continue merge with unresolved conflicts
        {
            var result_or_err = repo.merge(allocator, .{ .kind = .full, .action = .cont }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.CannotContinueMergeWithUnresolvedConflicts => {},
                else => |e| return e,
            }
        }
    }

    // resolve conflict
    try repo.add(allocator, &.{"f.txt"});
    {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .cont }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
    }

    // if we try merging foo again, it does nothing
    {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.nothing == merge.result);
    }
}

fn testMergeConflictDirFile(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-merge-conflict-dir-file";

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

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "repo");
        defer repo.deinit();
    }

    var work_dir = try temp_dir.openDir("repo", .{});
    defer work_dir.close();

    var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = work_dir });
    defer repo.deinit();

    // A --- B --- D [master]
    //  \         /
    //   \       /
    //    `---- C [foo]

    try addFile(repo_kind, repo_opts, &repo, allocator, "hi.txt", "hi");
    _ = try repo.commit(allocator, .{ .message = "a" });
    try repo.addBranch(.{ .name = "foo" });
    try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt/g.txt", "hi");
    _ = try repo.commit(allocator, .{ .message = "b" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt", "hi");
    _ = try repo.commit(allocator, .{ .message = "c" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.conflict == merge.result);
    }

    // make sure renamed file exists
    var renamed_file = try repo.core.work_dir.openFile("f.txt~foo", .{});
    defer renamed_file.close();

    {
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, allocator, .status);
        defer root.deinit();

        {
            const grid = try root.getGrid().?.toString(allocator);
            defer allocator.free(grid);

            var grid_without_tabs = grid;
            for (0..3) |_| {
                grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
            }

            try std.testing.expectEqualStrings(
                \\           ┌─────────────┐                                                      
                \\ added (0) │not added (1)│ not tracked (1)                                      
                \\           └─────────────┘                                                      
                \\   ┌─────┐          ┌──────────────────────────────────────────────────────────┐
                \\ ≠ │f.txt│          │                                                          │
                \\   └─────┘          └──────────────────────────────────────────────────────────┘
            , grid_without_tabs);
        }

        try ui.input(repo_kind, repo_opts, &root, .arrow_down);
        try ui.input(repo_kind, repo_opts, &root, .arrow_right);

        {
            const grid = try root.getGrid().?.toString(allocator);
            defer allocator.free(grid);

            var grid_without_tabs = grid;
            for (0..3) |_| {
                grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
            }

            try std.testing.expectEqualStrings(
                \\                          ╔═══════════════╗                                     
                \\ added (0)  not added (1) ║not tracked (1)║                                     
                \\                          ╚═══════════════╝                                     
                \\   ┌─────────┐      ┌──────────────────────────────────────────────────────────┐
                \\ ? │f.txt~foo│      │                                                          │
                \\   └─────────┘      │ diff --git a/f.txt~foo b/f.txt~foo                       │
                \\                    │ new file mode 100644                                     │
                \\                    │ index 0000000..32f95c0                                   │
                \\                    │ --- a/f.txt~foo                                          │
                \\                    │ +++ b/f.txt~foo                                          │
                \\                    │                                                          │
                \\                    │                                                          │
                \\                    │                                                          │
                \\                    │ @@ -0,0 +0,1 @@                                          │
                \\                    │ + hi                                                     │
                \\                    │                                                          │
                \\                    │                                                          │
                \\                    └──────────────────────────────────────────────────────────┘
            , grid_without_tabs);
        }
    }

    // generate diff
    var status = try repo.status(allocator);
    defer status.deinit(allocator);
    var file_iter = try repo.filePairs(allocator, .{
        .work_dir = .{
            .conflict_diff_kind = .target,
            .status = &status,
        },
    });
    if (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();
        return error.DiffResultNotExpected;
    }

    // ensure merge cannot be run again while there are unresolved conflicts
    {
        // can't merge again with an unresolved merge
        {
            var result_or_err = repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.UnfinishedMergeInProgress => {},
                else => |e| return e,
            }
        }

        // can't continue merge with unresolved conflicts
        {
            var result_or_err = repo.merge(allocator, .{ .kind = .full, .action = .cont }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.CannotContinueMergeWithUnresolvedConflicts => {},
                else => |e| return e,
            }
        }
    }

    // resolve conflict
    try repo.add(allocator, &.{"f.txt"});
    {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .cont }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
    }

    // if we try merging foo again, it does nothing
    {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.nothing == merge.result);
    }
}

test "merge conflict binary" {
    try testMergeConflictBinary(.git, .{ .is_test = true });
    try testMergeConflictBinary(.xit, .{ .is_test = true });
    try testMergeConflictBinary(.xit, .{ .is_test = true, .extra = .{ .enable_patches = true } });
}

/// creates a merge conflict with binary files, asserting that
/// it will not attempt to insert conflict markers or auto-resolve.
pub fn testMergeConflictBinary(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-merge-conflict-binary";

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

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "repo");
        defer repo.deinit();
    }

    var work_dir = try temp_dir.openDir("repo", .{});
    defer work_dir.close();

    var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = work_dir });
    defer repo.deinit();

    // A --- B --------- D [master]
    //  \               /
    //   \             /
    //    C ---------- [foo]

    var bin = [_]u8{0} ** 256;
    for (&bin, 0..) |*byte, i| {
        if (i % 2 == 1) {
            byte.* = '\n';
        } else {
            byte.* = @intCast(i % 255);
        }
    }

    try addFile(repo_kind, repo_opts, &repo, allocator, "bin", &bin);
    _ = try repo.commit(allocator, .{ .message = "a" });

    try repo.addBranch(.{ .name = "foo" });

    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }

    bin[0] = 1;

    try addFile(repo_kind, repo_opts, &repo, allocator, "bin", &bin);
    _ = try repo.commit(allocator, .{ .message = "c" });

    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }

    bin[0] = 2;

    try addFile(repo_kind, repo_opts, &repo, allocator, "bin", &bin);
    _ = try repo.commit(allocator, .{ .message = "b" });

    {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.conflict == merge.result);
    }

    {
        var root = try ui.rootWidget(repo_kind, repo_opts, &repo, allocator, .status);
        defer root.deinit();

        const grid = try root.getGrid().?.toString(allocator);
        defer allocator.free(grid);

        var grid_without_tabs = grid;
        for (0..3) |_| {
            grid_without_tabs = grid_without_tabs[std.mem.indexOfScalar(u8, grid_without_tabs, '\n').? + 1 ..];
        }

        try std.testing.expectEqualStrings(
            \\           ┌─────────────┐                                                      
            \\ added (0) │not added (1)│ not tracked (0)                                      
            \\           └─────────────┘                                                      
            \\   ┌───┐            ┌──────────────────────────────────────────────────────────┐
            \\ ≠ │bin│            │                                                          │
            \\   └───┘            │ diff --git a/bin b/bin                                   │
            \\                    │ index 6071ef1..47e3b37 100644                            │
            \\                    │ --- a/bin                                                │
            \\                    │ +++ b/bin                                                │
            \\                    │                                                          │
            \\                    │                                                          │
            \\                    └──────────────────────────────────────────────────────────┘
        , grid_without_tabs);
    }

    // verify no lines are longer than one byte
    // so we know that conflict markers haven't been added
    {
        const bin_file = try repo.core.work_dir.openFile("bin", .{ .mode = .read_only });
        defer bin_file.close();
        const bin_file_content = try bin_file.readToEndAlloc(allocator, 1024);
        defer allocator.free(bin_file_content);
        var iter = std.mem.splitScalar(u8, bin_file_content, '\n');
        while (iter.next()) |line| {
            try std.testing.expect(line.len <= 1);
        }
    }

    // resolve conflict
    try repo.add(allocator, &.{"bin"});
    {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .cont }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
    }

    // if we try merging foo again, it does nothing
    {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.nothing == merge.result);
    }

    // replace bin with a text file containing a single line that
    // is too long, and assert that it is considered a binary file
    {
        const file = try repo.core.work_dir.createFile("bin", .{ .truncate = true });
        defer file.close();
        while (try file.getPos() < repo_opts.max_line_size) {
            try file.writeAll(&[_]u8{' '} ** 256);
        }

        var status = try repo.status(allocator);
        defer status.deinit(allocator);
        var file_iter = try repo.filePairs(allocator, .{
            .work_dir = .{
                .conflict_diff_kind = .target,
                .status = &status,
            },
        });
        if (try file_iter.next()) |*line_iter_pair_ptr| {
            var line_iter_pair = line_iter_pair_ptr.*;
            defer line_iter_pair.deinit();
            try std.testing.expect(.binary == line_iter_pair.b.source);
        } else {
            return error.DiffResultExpected;
        }
    }
}

test "merge conflict shuffle" {
    try testMergeConflictShuffle(.git, .{ .is_test = true });
    try testMergeConflictShuffle(.xit, .{ .is_test = true, .extra = .{ .enable_patches = true } });
}

/// demonstrates an example of git shuffling lines unexpectedly
/// when auto-resolving a merge conflict
fn testMergeConflictShuffle(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-merge-conflict-shuffle";

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

    // from https://pijul.org/manual/why_pijul.html
    {
        {
            var repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "simple");
            defer repo.deinit();
        }

        var work_dir = try temp_dir.openDir("simple", .{});
        defer work_dir.close();

        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = work_dir });
        defer repo.deinit();

        // A --- B --- C --- E [master]
        //  \               /
        //   \             /
        //    `---------- D [foo]

        try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt",
            \\a
            \\b
        );
        _ = try repo.commit(allocator, .{ .message = "a" });
        try repo.addBranch(.{ .name = "foo" });
        try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt",
            \\g
            \\a
            \\b
        );
        _ = try repo.commit(allocator, .{ .message = "b" });
        try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt",
            \\a
            \\b
            \\g
            \\a
            \\b
        );
        _ = try repo.commit(allocator, .{ .message = "c" });
        {
            var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
            defer result.deinit();
        }
        try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt",
            \\a
            \\x
            \\b
        );
        _ = try repo.commit(allocator, .{ .message = "d" });
        {
            var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
            defer result.deinit();
        }
        {
            var merge = try repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
            defer merge.deinit();
            try std.testing.expect(.success == merge.result);

            // verify f.txt has been autoresolved
            const f_txt = try repo.core.work_dir.openFile("f.txt", .{ .mode = .read_only });
            defer f_txt.close();
            const f_txt_content = try f_txt.readToEndAlloc(allocator, 1024);
            defer allocator.free(f_txt_content);
            switch (repo_kind) {
                // git shuffles lines
                .git => try std.testing.expectEqualStrings(
                    \\a
                    \\x
                    \\b
                    \\g
                    \\a
                    \\b
                ,
                    f_txt_content,
                ),
                // xit does not!
                .xit => try std.testing.expectEqualStrings(
                    \\a
                    \\b
                    \\g
                    \\a
                    \\x
                    \\b
                ,
                    f_txt_content,
                ),
            }
        }

        // generate diff
        var status = try repo.status(allocator);
        defer status.deinit(allocator);
        var file_iter = try repo.filePairs(allocator, .{
            .work_dir = .{
                .conflict_diff_kind = .target,
                .status = &status,
            },
        });
        if (try file_iter.next()) |*line_iter_pair_ptr| {
            var line_iter_pair = line_iter_pair_ptr.*;
            defer line_iter_pair.deinit();
            return error.DiffResultNotExpected;
        }

        // if we try merging foo again, it does nothing
        {
            var merge = try repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
            defer merge.deinit();
            try std.testing.expect(.nothing == merge.result);
        }
    }

    // from https://tahoe-lafs.org/~zooko/badmerge/concrete-good-semantics.html
    {
        {
            var repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "concrete");
            defer repo.deinit();
        }

        var work_dir = try temp_dir.openDir("concrete", .{});
        defer work_dir.close();

        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = work_dir });
        defer repo.deinit();

        // A --- B --- C --- E [master]
        //  \               /
        //   \             /
        //    `---------- D [foo]

        try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt",
            \\int square(int x) {
            \\  int y = x;
            \\  /* Update y to equal the result. */
            \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
            \\  for (int i = 0; i < x; i++) y += x;
            \\  return y;
            \\}
        );
        _ = try repo.commit(allocator, .{ .message = "a" });
        try repo.addBranch(.{ .name = "foo" });
        try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt",
            \\int very_slow_square(int x) {
            \\  int y = 0;
            \\  /* Update y to equal the result. */
            \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
            \\  for (int i = 0; i < x; i++)
            \\    for (int j = 0; j < x; j++)
            \\      y += 1;
            \\  return y;
            \\}
            \\
            \\int square(int x) {
            \\  int y = x;
            \\  /* Update y to equal the result. */
            \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
            \\  for (int i = 0; i < x; i++) y += x;
            \\  return y;
            \\}
        );
        _ = try repo.commit(allocator, .{ .message = "b" });
        try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt",
            \\int square(int x) {
            \\  int y = x;
            \\  /* Update y to equal the result. */
            \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
            \\  return y * x;
            \\}
            \\
            \\int very_slow_square(int x) {
            \\  int y = 0;
            \\  /* Update y to equal the result. */
            \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
            \\  for (int i = 0; i < x; i++)
            \\    for (int j = 0; j < x; j++)
            \\      y += 1;
            \\  return y;
            \\}
            \\
            \\int slow_square(int x) {
            \\  int y = x;
            \\  /* Update y to equal the result. */
            \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
            \\  for (int i = 0; i < x; i++) y += x;
            \\  return y;
            \\}
        );
        _ = try repo.commit(allocator, .{ .message = "c" });
        {
            var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
            defer result.deinit();
        }
        try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt",
            \\int square(int x) {
            \\  int y = 0;
            \\  /* Update y to equal the result. */
            \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
            \\  for (int i = 0; i < x; i++) y += x;
            \\  return y;
            \\}
        );
        _ = try repo.commit(allocator, .{ .message = "d" });
        {
            var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
            defer result.deinit();
        }
        {
            var merge = try repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
            defer merge.deinit();

            const f_txt = try repo.core.work_dir.openFile("f.txt", .{ .mode = .read_only });
            defer f_txt.close();
            const f_txt_content = try f_txt.readToEndAlloc(allocator, 1024);
            defer allocator.free(f_txt_content);
            switch (repo_kind) {
                .git => {
                    try std.testing.expectEqualStrings(
                        \\int square(int x) {
                        \\  int y = 0;
                        \\  /* Update y to equal the result. */
                        \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
                        \\  return y * x;
                        \\}
                        \\
                        \\int very_slow_square(int x) {
                        \\  int y = 0;
                        \\  /* Update y to equal the result. */
                        \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
                        \\  for (int i = 0; i < x; i++)
                        \\    for (int j = 0; j < x; j++)
                        \\      y += 1;
                        \\  return y;
                        \\}
                        \\
                        \\int slow_square(int x) {
                        \\  int y = x;
                        \\  /* Update y to equal the result. */
                        \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
                        \\  for (int i = 0; i < x; i++) y += x;
                        \\  return y;
                        \\}
                    , f_txt_content);
                },
                .xit => {
                    try std.testing.expect(.success == merge.result);
                    try std.testing.expectEqualStrings(
                        \\int square(int x) {
                        \\  int y = x;
                        \\  /* Update y to equal the result. */
                        \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
                        \\  return y * x;
                        \\}
                        \\
                        \\int very_slow_square(int x) {
                        \\  int y = 0;
                        \\  /* Update y to equal the result. */
                        \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
                        \\  for (int i = 0; i < x; i++)
                        \\    for (int j = 0; j < x; j++)
                        \\      y += 1;
                        \\  return y;
                        \\}
                        \\
                        \\int slow_square(int x) {
                        \\  int y = 0;
                        \\  /* Update y to equal the result. */
                        \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
                        \\  for (int i = 0; i < x; i++) y += x;
                        \\  return y;
                        \\}
                    , f_txt_content);
                },
            }
        }
    }
}

test "cherry-pick" {
    try testCherryPick(.git, .{ .is_test = true });
    try testCherryPick(.xit, .{ .is_test = true });
    try testCherryPick(.xit, .{ .is_test = true, .extra = .{ .enable_patches = true } });
}

fn testCherryPick(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-cherry-pick";

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

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "repo");
        defer repo.deinit();
    }

    var work_dir = try temp_dir.openDir("repo", .{});
    defer work_dir.close();

    var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = work_dir });
    defer repo.deinit();

    // A --- B ------------ D' [master]
    //        \
    //         \
    //          C --- D --- E [foo]

    try addFile(repo_kind, repo_opts, &repo, allocator, "readme.md", "a");
    _ = try repo.commit(allocator, .{ .message = "a" });
    try addFile(repo_kind, repo_opts, &repo, allocator, "readme.md", "b");
    _ = try repo.commit(allocator, .{ .message = "b" });
    try repo.addBranch(.{ .name = "foo" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    // commit c will be the parent of the cherry-picked commit,
    // and it is modifying a different file, so it shouldn't
    // cause a conflict.
    try addFile(repo_kind, repo_opts, &repo, allocator, "stuff.md", "c");
    _ = try repo.commit(allocator, .{ .message = "c" });
    try addFile(repo_kind, repo_opts, &repo, allocator, "readme.md", "d");
    const commit_d = try repo.commit(allocator, .{ .message = "d" });
    try addFile(repo_kind, repo_opts, &repo, allocator, "readme.md", "e");
    _ = try repo.commit(allocator, .{ .message = "e" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }

    {
        var merge = try repo.merge(allocator, .{ .kind = .pick, .action = .{ .new = .{ .source = &.{.{ .oid = &commit_d }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
    }

    // make sure stuff.md does not exist
    if (repo.core.work_dir.openFile("stuff.md", .{})) |*file| {
        file.close();
        return error.UnexpectedFile;
    } else |_| {}

    // if we try cherry-picking the same commit again, it succeeds again
    {
        var merge = try repo.merge(allocator, .{
            .kind = .pick,
            .action = .{ .new = .{ .source = &.{.{ .oid = &commit_d }} } },
            .commit_metadata = .{ .allow_empty = true },
        }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
    }
}

test "cherry-pick conflict" {
    try testCherryPickConflict(.git, .{ .is_test = true });
    try testCherryPickConflict(.xit, .{ .is_test = true });
    try testCherryPickConflict(.xit, .{ .is_test = true, .extra = .{ .enable_patches = true } });
}

fn testCherryPickConflict(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-cherry-pick-conflict";

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

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "repo");
        defer repo.deinit();
    }

    var work_dir = try temp_dir.openDir("repo", .{});
    defer work_dir.close();

    var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = work_dir });
    defer repo.deinit();

    // A --- B ------------ D' [master]
    //        \
    //         \
    //          D --------- E [foo]

    try addFile(repo_kind, repo_opts, &repo, allocator, "readme.md", "a");
    _ = try repo.commit(allocator, .{ .message = "a" });
    try addFile(repo_kind, repo_opts, &repo, allocator, "readme.md", "b");
    _ = try repo.commit(allocator, .{ .message = "b" });
    try repo.addBranch(.{ .name = "foo" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, allocator, "readme.md", "c");
    _ = try repo.commit(allocator, .{ .message = "c" });
    try addFile(repo_kind, repo_opts, &repo, allocator, "readme.md", "d");
    const commit_d = try repo.commit(allocator, .{ .message = "d" });
    try addFile(repo_kind, repo_opts, &repo, allocator, "readme.md", "e");
    _ = try repo.commit(allocator, .{ .message = "e" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    {
        var merge = try repo.merge(allocator, .{ .kind = .pick, .action = .{ .new = .{ .source = &.{.{ .oid = &commit_d }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.conflict == merge.result);

        // verify readme.md has conflict markers
        const readme_md = try repo.core.work_dir.openFile("readme.md", .{ .mode = .read_only });
        defer readme_md.close();
        const readme_md_content = try readme_md.readToEndAlloc(allocator, 1024);
        defer allocator.free(readme_md_content);
        const expected_readme_md_content = try std.fmt.allocPrint(allocator,
            \\<<<<<<< target (master)
            \\b
            \\||||||| base ({s})
            \\c
            \\=======
            \\d
            \\>>>>>>> source ({s})
        , .{ merge.base_oid, commit_d });
        defer allocator.free(expected_readme_md_content);
        try std.testing.expectEqualStrings(expected_readme_md_content, readme_md_content);
    }

    // generate diff
    var status = try repo.status(allocator);
    defer status.deinit(allocator);
    var file_iter = try repo.filePairs(allocator, .{
        .work_dir = .{
            .conflict_diff_kind = .target,
            .status = &status,
        },
    });
    if (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();
    } else {
        return error.DiffResultExpected;
    }

    // ensure cherry-pick cannot be run again while there are unresolved conflicts
    {
        // can't cherry-pick again with an unresolved cherry-pick
        {
            var result_or_err = repo.merge(allocator, .{ .kind = .pick, .action = .{ .new = .{ .source = &.{.{ .oid = &([_]u8{0} ** hash.hexLen(repo_opts.hash)) }} } } }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.UnfinishedMergeInProgress => {},
                else => |e| return e,
            }
        }

        // can't continue cherry-pick with unresolved conflicts
        {
            var result_or_err = repo.merge(allocator, .{ .kind = .pick, .action = .cont }, null);
            if (result_or_err) |*result| {
                defer result.deinit();
                return error.ExpectedMergeToNotFinish;
            } else |err| switch (err) {
                error.CannotContinueMergeWithUnresolvedConflicts => {},
                else => |e| return e,
            }
        }
    }

    // resolve conflict
    try addFile(repo_kind, repo_opts, &repo, allocator, "readme.md",
        \\e
    );

    // can't continue with .kind = merge
    {
        var result_or_err = repo.merge(allocator, .{ .kind = .full, .action = .cont }, null);
        if (result_or_err) |*result| {
            defer result.deinit();
            return error.ExpectedMergeToNotFinish;
        } else |err| switch (err) {
            error.OtherMergeInProgress => {},
            else => |e| return e,
        }
    }

    // continue cherry-pick
    {
        var merge = try repo.merge(allocator, .{ .kind = .pick, .action = .cont }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
    }
}

test "log" {
    try testLog(.git, .{ .is_test = true });
    try testLog(.xit, .{ .is_test = true });
    try testLog(.xit, .{ .is_test = true, .extra = .{ .enable_patches = true } });
}

fn testLog(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-log";

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

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "repo");
        defer repo.deinit();
    }

    var work_dir = try temp_dir.openDir("repo", .{});
    defer work_dir.close();

    var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = work_dir });
    defer repo.deinit();

    // A --- B --- C --------- G --- H [master]
    //        \               /
    //         \             /
    //          D --- E --- F [foo]

    try addFile(repo_kind, repo_opts, &repo, allocator, "master.md", "a");
    const commit_a = try repo.commit(allocator, .{ .message = "a" });
    try addFile(repo_kind, repo_opts, &repo, allocator, "master.md", "b");
    const commit_b = try repo.commit(allocator, .{ .message = "b" });
    try repo.addBranch(.{ .name = "foo" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, allocator, "foo.md", "d");
    const commit_d = try repo.commit(allocator, .{ .message = "d" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, allocator, "master.md", "c");
    const commit_c = try repo.commit(allocator, .{ .message = "c" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "foo" } } });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, allocator, "foo.md", "e");
    const commit_e = try repo.commit(allocator, .{ .message = "e" });
    try addFile(repo_kind, repo_opts, &repo, allocator, "foo.md", "f");
    const commit_f = try repo.commit(allocator, .{ .message = "f" });
    {
        var result = try repo.switchDir(allocator, .{ .target = .{ .ref = .{ .kind = .head, .name = "master" } } });
        defer result.deinit();
    }
    const commit_g = blk: {
        var merge = try repo.merge(allocator, .{ .kind = .full, .action = .{ .new = .{ .source = &.{.{ .ref = .{ .kind = .head, .name = "foo" } }} } } }, null);
        defer merge.deinit();
        try std.testing.expect(.success == merge.result);
        break :blk merge.result.success.oid;
    };
    try addFile(repo_kind, repo_opts, &repo, allocator, "master.md", "h");
    const commit_h = try repo.commit(allocator, .{ .message = "h" });

    // put oids in a set
    var oid_set = std.StringArrayHashMap(void).init(allocator);
    defer oid_set.deinit();
    try oid_set.put(&commit_a, {});
    try oid_set.put(&commit_b, {});
    try oid_set.put(&commit_c, {});
    try oid_set.put(&commit_d, {});
    try oid_set.put(&commit_e, {});
    try oid_set.put(&commit_f, {});
    try oid_set.put(&commit_g, {});
    try oid_set.put(&commit_h, {});

    // assert that all commits have been found in the log
    // and they aren't repeated
    {
        var commit_iter = try repo.log(allocator, null);
        defer commit_iter.deinit();
        while (try commit_iter.next()) |commit_object| {
            defer commit_object.deinit();
            try std.testing.expect(oid_set.contains(&commit_object.oid));
            _ = oid_set.swapRemove(&commit_object.oid);
        }
        try std.testing.expectEqual(0, oid_set.count());
    }

    try oid_set.put(&commit_c, {});
    try oid_set.put(&commit_d, {});
    try oid_set.put(&commit_e, {});
    try oid_set.put(&commit_f, {});
    try oid_set.put(&commit_g, {});

    // assert that only some commits have been found in the log
    // and they aren't repeated
    {
        var commit_iter = try repo.log(allocator, &.{commit_g});
        defer commit_iter.deinit();
        try commit_iter.exclude(&commit_b);
        while (try commit_iter.next()) |commit_object| {
            defer commit_object.deinit();
            try std.testing.expect(oid_set.contains(&commit_object.oid));
            _ = oid_set.swapRemove(&commit_object.oid);
        }
        try std.testing.expectEqual(0, oid_set.count());
    }

    // iterate over all objects
    {
        var count: usize = 0;
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
        var obj_iter = try obj.ObjectIterator(repo_kind, repo_opts, .full).init(allocator, state, .{ .kind = .all });
        defer obj_iter.deinit();
        try obj_iter.include(&commit_g);
        while (try obj_iter.next()) |object| {
            defer object.deinit();
            count += 1;
        }
        try std.testing.expectEqual(20, count);
    }
}
