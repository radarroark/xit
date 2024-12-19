//! tests that create repos via the Repo struct.
//! runs with both git and xit modes.

const std = @import("std");
const hash = @import("../hash.zig");
const rp = @import("../repo.zig");
const ref = @import("../ref.zig");
const obj = @import("../object.zig");
const mrg = @import("../merge.zig");
const df = @import("../diff.zig");

fn addFile(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind), repo: *rp.Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, path: []const u8, content: []const u8) !void {
    if (std.fs.path.dirname(path)) |parent_path| {
        try repo.core.repo_dir.makePath(parent_path);
    }
    const file = try repo.core.repo_dir.createFile(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(content);
    try repo.add(allocator, &.{path});
}

fn removeFile(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind), repo: *rp.Repo(repo_kind, repo_opts), allocator: std.mem.Allocator, path: []const u8) !void {
    try repo.core.repo_dir.deleteFile(path);
    try repo.add(allocator, &.{path});
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

    var repo_dir = try temp_dir.openDir("repo", .{});
    defer repo_dir.close();

    var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
    defer repo.deinit();

    try addFile(repo_kind, repo_opts, &repo, allocator, "README.md", "Hello, world!");
    const commit_a = try repo.commit(allocator, .{ .message = "a" });
    try addFile(repo_kind, repo_opts, &repo, allocator, "README.md", "Goodbye, world!");
    const commit_b = try repo.commit(allocator, .{ .message = "b" });
    try removeFile(repo_kind, repo_opts, &repo, allocator, "README.md");
    const commit_c = try repo.commit(allocator, .{ .message = "c" });

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
    var commit_iter = try repo.log(allocator, null);
    defer commit_iter.deinit();
    while (try commit_iter.next()) |commit_object| {
        defer commit_object.deinit();
        _ = oid_set.swapRemove(&commit_object.oid);
    }
    try std.testing.expectEqual(0, oid_set.count());
}

test "simple" {
    try testSimple(.git, .{});
    try testSimple(.xit, .{});
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

    var repo_dir = try temp_dir.openDir("repo", .{});
    defer repo_dir.close();

    var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
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
        var result = try repo.switchHead(allocator, "foo", .{ .force = false });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, allocator, "foo.md", "d");
    const commit_d = try repo.commit(allocator, .{ .message = "d" });
    try repo.addBranch(.{ .name = "bar" });
    {
        var result = try repo.switchHead(allocator, "bar", .{ .force = false });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, allocator, "bar.md", "g");
    _ = try repo.commit(allocator, .{ .message = "g" });
    try addFile(repo_kind, repo_opts, &repo, allocator, "bar.md", "h");
    const commit_h = try repo.commit(allocator, .{ .message = "h" });
    {
        var result = try repo.switchHead(allocator, "master", .{ .force = false });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, allocator, "master.md", "c");
    _ = try repo.commit(allocator, .{ .message = "c" });
    {
        var result = try repo.switchHead(allocator, "foo", .{ .force = false });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, allocator, "foo.md", "e");
    _ = try repo.commit(allocator, .{ .message = "e" });
    try addFile(repo_kind, repo_opts, &repo, allocator, "foo.md", "f");
    _ = try repo.commit(allocator, .{ .message = "f" });
    {
        var result = try repo.switchHead(allocator, "master", .{ .force = false });
        defer result.deinit();
    }
    const commit_j = blk: {
        var result = try repo.merge(allocator, .{ .new = ref.RefOrOid(repo_opts.hash).initFromUser("foo") });
        defer result.deinit();
        try std.testing.expect(.success == result.data);
        break :blk result.data.success.oid;
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
        var merge_result = try repo.merge(allocator, .{ .new = ref.RefOrOid(repo_opts.hash).initFromUser("foo") });
        defer merge_result.deinit();
        try std.testing.expect(.nothing == merge_result.data);
    }

    // if we try merging master into foo, it fast forwards
    {
        var switch_result = try repo.switchHead(allocator, "foo", .{ .force = false });
        defer switch_result.deinit();
        var merge_result = try repo.merge(allocator, .{ .new = ref.RefOrOid(repo_opts.hash).initFromUser("master") });
        defer merge_result.deinit();
        try std.testing.expect(.fast_forward == merge_result.data);

        const head_oid = try ref.readHead(repo_kind, repo_opts, state);
        try std.testing.expectEqual(commit_k, head_oid);

        // make sure file from commit k exists
        var master_md = try repo.core.repo_dir.openFile("master.md", .{});
        defer master_md.close();
        const master_md_content = try master_md.readToEndAlloc(allocator, 1024);
        defer allocator.free(master_md_content);
        try std.testing.expectEqualStrings("k", master_md_content);
    }
}

test "merge" {
    try testMerge(.git, .{});
    try testMerge(.xit, .{});
}

fn testMergeConflict(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) !void {
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-merge-conflict";

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

    const checkMergeAbort = struct {
        fn run(repo: *rp.Repo(repo_kind, repo_opts)) !void {
            // can't merge again with an unresolved merge
            {
                var result_or_err = repo.merge(allocator, .{ .new = ref.RefOrOid(repo_opts.hash).initFromUser("foo") });
                if (result_or_err) |*result| {
                    defer result.deinit();
                    return error.ExpectedMergeToAbort;
                } else |err| switch (err) {
                    error.UnfinishedMergeAlreadyInProgress => {},
                    else => |e| return e,
                }
            }

            // can't continue merge with unresolved conflicts
            {
                var result_or_err = repo.merge(allocator, .cont);
                if (result_or_err) |*result| {
                    defer result.deinit();
                    return error.ExpectedMergeToAbort;
                } else |err| switch (err) {
                    error.CannotContinueMergeWithUnresolvedConflicts => {},
                    else => |e| return e,
                }
            }
        }
    }.run;

    // same file conflict
    {
        {
            var repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "same-file-conflict");
            defer repo.deinit();
        }

        var repo_dir = try temp_dir.openDir("same-file-conflict", .{});
        defer repo_dir.close();

        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
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
            var result = try repo.switchHead(allocator, "foo", .{ .force = false });
            defer result.deinit();
        }
        try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt",
            \\a
            \\y
            \\c
        );
        _ = try repo.commit(allocator, .{ .message = "c" });
        {
            var result = try repo.switchHead(allocator, "master", .{ .force = false });
            defer result.deinit();
        }
        {
            var result = try repo.merge(allocator, .{ .new = ref.RefOrOid(repo_opts.hash).initFromUser("foo") });
            defer result.deinit();
            try std.testing.expect(.conflict == result.data);

            // verify f.txt has conflict markers
            const f_txt = try repo.core.repo_dir.openFile("f.txt", .{ .mode = .read_only });
            defer f_txt.close();
            const f_txt_content = try f_txt.readToEndAlloc(allocator, 1024);
            defer allocator.free(f_txt_content);
            const expected_f_txt_content = try std.fmt.allocPrint(allocator,
                \\a
                \\<<<<<<< master
                \\x
                \\||||||| original ({s})
                \\b
                \\=======
                \\y
                \\>>>>>>> foo
                \\c
            , .{result.base_oid});
            defer allocator.free(expected_f_txt_content);
            try std.testing.expectEqualStrings(expected_f_txt_content, f_txt_content);
        }

        // generate diff
        var status = try repo.status(allocator);
        defer status.deinit();
        var file_iter = try repo.filePairs(allocator, .{
            .workspace = .{
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
        try checkMergeAbort(&repo);

        // resolve conflict
        try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt",
            \\a
            \\y
            \\c
        );
        {
            var result = try repo.merge(allocator, .cont);
            defer result.deinit();
            try std.testing.expect(.success == result.data);
        }

        // if we try merging foo again, it does nothing
        {
            var merge_result = try repo.merge(allocator, .{ .new = ref.RefOrOid(repo_opts.hash).initFromUser("foo") });
            defer merge_result.deinit();
            try std.testing.expect(.nothing == merge_result.data);
        }
    }

    // same file conflict (autoresolved)
    {
        {
            var repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "same-file-conflict-autoresolved");
            defer repo.deinit();
        }

        var repo_dir = try temp_dir.openDir("same-file-conflict-autoresolved", .{});
        defer repo_dir.close();

        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
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
            var result = try repo.switchHead(allocator, "foo", .{ .force = false });
            defer result.deinit();
        }
        try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt",
            \\a
            \\b
            \\y
        );
        _ = try repo.commit(allocator, .{ .message = "c" });
        {
            var result = try repo.switchHead(allocator, "master", .{ .force = false });
            defer result.deinit();
        }
        {
            var result = try repo.merge(allocator, .{ .new = ref.RefOrOid(repo_opts.hash).initFromUser("foo") });
            defer result.deinit();
            try std.testing.expect(.success == result.data);

            // verify f.txt has been autoresolved
            const f_txt = try repo.core.repo_dir.openFile("f.txt", .{ .mode = .read_only });
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
        defer status.deinit();
        var file_iter = try repo.filePairs(allocator, .{
            .workspace = .{
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
            var merge_result = try repo.merge(allocator, .{ .new = ref.RefOrOid(repo_opts.hash).initFromUser("foo") });
            defer merge_result.deinit();
            try std.testing.expect(.nothing == merge_result.data);
        }
    }

    // modify/delete conflict (target modifies, source deletes)
    {
        {
            var repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "modify-delete-conflict");
            defer repo.deinit();
        }

        var repo_dir = try temp_dir.openDir("modify-delete-conflict", .{});
        defer repo_dir.close();

        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
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
            var result = try repo.switchHead(allocator, "foo", .{ .force = false });
            defer result.deinit();
        }
        try removeFile(repo_kind, repo_opts, &repo, allocator, "f.txt");
        _ = try repo.commit(allocator, .{ .message = "c" });
        {
            var result = try repo.switchHead(allocator, "master", .{ .force = false });
            defer result.deinit();
        }
        {
            var result = try repo.merge(allocator, .{ .new = ref.RefOrOid(repo_opts.hash).initFromUser("foo") });
            defer result.deinit();
            try std.testing.expect(.conflict == result.data);
        }

        // generate diff
        var status = try repo.status(allocator);
        defer status.deinit();
        var file_iter = try repo.filePairs(allocator, .{
            .workspace = .{
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
        try checkMergeAbort(&repo);

        // resolve conflict
        try repo.add(allocator, &.{"f.txt"});
        {
            var result = try repo.merge(allocator, .cont);
            defer result.deinit();
            try std.testing.expect(.success == result.data);
        }

        // if we try merging foo again, it does nothing
        {
            var merge_result = try repo.merge(allocator, .{ .new = ref.RefOrOid(repo_opts.hash).initFromUser("foo") });
            defer merge_result.deinit();
            try std.testing.expect(.nothing == merge_result.data);
        }
    }

    // delete/modify conflict (target deletes, source modifies)
    {
        {
            var repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "delete-modify-conflict");
            defer repo.deinit();
        }

        var repo_dir = try temp_dir.openDir("delete-modify-conflict", .{});
        defer repo_dir.close();

        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
        defer repo.deinit();

        // A --- B --- D [master]
        //  \         /
        //   \       /
        //    `---- C [foo]

        try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt", "1");
        _ = try repo.commit(allocator, .{ .message = "a" });
        try repo.addBranch(.{ .name = "foo" });
        try removeFile(repo_kind, repo_opts, &repo, allocator, "f.txt");
        _ = try repo.commit(allocator, .{ .message = "b" });
        {
            var result = try repo.switchHead(allocator, "foo", .{ .force = false });
            defer result.deinit();
        }
        try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt", "2");
        _ = try repo.commit(allocator, .{ .message = "c" });
        {
            var result = try repo.switchHead(allocator, "master", .{ .force = false });
            defer result.deinit();
        }
        {
            var result = try repo.merge(allocator, .{ .new = ref.RefOrOid(repo_opts.hash).initFromUser("foo") });
            defer result.deinit();
            try std.testing.expect(.conflict == result.data);
        }

        // generate diff
        var status = try repo.status(allocator);
        defer status.deinit();
        var file_iter = try repo.filePairs(allocator, .{
            .workspace = .{
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
        try checkMergeAbort(&repo);

        // resolve conflict
        try repo.add(allocator, &.{"f.txt"});
        {
            var result = try repo.merge(allocator, .cont);
            defer result.deinit();
            try std.testing.expect(.success == result.data);
        }

        // if we try merging foo again, it does nothing
        {
            var merge_result = try repo.merge(allocator, .{ .new = ref.RefOrOid(repo_opts.hash).initFromUser("foo") });
            defer merge_result.deinit();
            try std.testing.expect(.nothing == merge_result.data);
        }
    }

    // file/dir conflict (target has file, source has dir)
    {
        {
            var repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "file-dir-conflict");
            defer repo.deinit();
        }

        var repo_dir = try temp_dir.openDir("file-dir-conflict", .{});
        defer repo_dir.close();

        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
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
            var result = try repo.switchHead(allocator, "foo", .{ .force = false });
            defer result.deinit();
        }
        try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt/g.txt", "hi");
        _ = try repo.commit(allocator, .{ .message = "c" });
        {
            var result = try repo.switchHead(allocator, "master", .{ .force = false });
            defer result.deinit();
        }
        {
            var result = try repo.merge(allocator, .{ .new = ref.RefOrOid(repo_opts.hash).initFromUser("foo") });
            defer result.deinit();
            try std.testing.expect(.conflict == result.data);
        }

        // generate diff
        var status = try repo.status(allocator);
        defer status.deinit();
        var file_iter = try repo.filePairs(allocator, .{
            .workspace = .{
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
        try checkMergeAbort(&repo);

        // make sure renamed file exists
        var renamed_file = try repo.core.repo_dir.openFile("f.txt~master", .{});
        defer renamed_file.close();

        // resolve conflict
        try repo.add(allocator, &.{"f.txt"});
        {
            var result = try repo.merge(allocator, .cont);
            defer result.deinit();
            try std.testing.expect(.success == result.data);
        }

        // if we try merging foo again, it does nothing
        {
            var merge_result = try repo.merge(allocator, .{ .new = ref.RefOrOid(repo_opts.hash).initFromUser("foo") });
            defer merge_result.deinit();
            try std.testing.expect(.nothing == merge_result.data);
        }
    }

    // dir/file conflict (target has dir, source has file)
    {
        {
            var repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "dir-file-conflict");
            defer repo.deinit();
        }

        var repo_dir = try temp_dir.openDir("dir-file-conflict", .{});
        defer repo_dir.close();

        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
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
            var result = try repo.switchHead(allocator, "foo", .{ .force = false });
            defer result.deinit();
        }
        try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt", "hi");
        _ = try repo.commit(allocator, .{ .message = "c" });
        {
            var result = try repo.switchHead(allocator, "master", .{ .force = false });
            defer result.deinit();
        }
        {
            var result = try repo.merge(allocator, .{ .new = ref.RefOrOid(repo_opts.hash).initFromUser("foo") });
            defer result.deinit();
            try std.testing.expect(.conflict == result.data);
        }

        // make sure renamed file exists
        var renamed_file = try repo.core.repo_dir.openFile("f.txt~foo", .{});
        defer renamed_file.close();

        // generate diff
        var status = try repo.status(allocator);
        defer status.deinit();
        var file_iter = try repo.filePairs(allocator, .{
            .workspace = .{
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
        try checkMergeAbort(&repo);

        // resolve conflict
        try repo.add(allocator, &.{"f.txt"});
        {
            var result = try repo.merge(allocator, .cont);
            defer result.deinit();
            try std.testing.expect(.success == result.data);
        }

        // if we try merging foo again, it does nothing
        {
            var merge_result = try repo.merge(allocator, .{ .new = ref.RefOrOid(repo_opts.hash).initFromUser("foo") });
            defer merge_result.deinit();
            try std.testing.expect(.nothing == merge_result.data);
        }
    }
}

test "merge conflict" {
    // read and write objects in small increments to help uncover bugs
    try testMergeConflict(.git, .{ .read_size = 1 });
    try testMergeConflict(.xit, .{ .read_size = 1, .extra = .{
        .chunk_opts = .{ .min_size = 1, .avg_size = 2, .max_size = 4, .normalization = .level1 },
    } });
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

    var repo_dir = try temp_dir.openDir("repo", .{});
    defer repo_dir.close();

    var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
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
        var result = try repo.switchHead(allocator, "foo", .{ .force = false });
        defer result.deinit();
    }

    bin[0] = 1;

    try addFile(repo_kind, repo_opts, &repo, allocator, "bin", &bin);
    _ = try repo.commit(allocator, .{ .message = "c" });

    {
        var result = try repo.switchHead(allocator, "master", .{ .force = false });
        defer result.deinit();
    }

    bin[0] = 2;

    try addFile(repo_kind, repo_opts, &repo, allocator, "bin", &bin);
    _ = try repo.commit(allocator, .{ .message = "b" });

    {
        var result = try repo.merge(allocator, .{ .new = ref.RefOrOid(repo_opts.hash).initFromUser("foo") });
        defer result.deinit();
        try std.testing.expect(.conflict == result.data);
    }

    // verify no lines are longer than one byte
    // so we know that conflict markers haven't been added
    {
        const bin_file = try repo.core.repo_dir.openFile("bin", .{ .mode = .read_only });
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
        var result = try repo.merge(allocator, .cont);
        defer result.deinit();
        try std.testing.expect(.success == result.data);
    }

    // if we try merging foo again, it does nothing
    {
        var merge_result = try repo.merge(allocator, .{ .new = ref.RefOrOid(repo_opts.hash).initFromUser("foo") });
        defer merge_result.deinit();
        try std.testing.expect(.nothing == merge_result.data);
    }

    // replace bin with a text file containing a single line that
    // is too long, and assert that it is considered a binary file
    {
        const file = try repo.core.repo_dir.createFile("bin", .{ .truncate = true });
        defer file.close();
        while (try file.getPos() < df.MAX_LINE_BYTES) {
            try file.writeAll(&[_]u8{' '} ** 256);
        }

        var status = try repo.status(allocator);
        defer status.deinit();
        var file_iter = try repo.filePairs(allocator, .{
            .workspace = .{
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

test "merge conflict binary" {
    try testMergeConflictBinary(.git, .{});
    try testMergeConflictBinary(.xit, .{});
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

        var repo_dir = try temp_dir.openDir("simple", .{});
        defer repo_dir.close();

        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
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
            var result = try repo.switchHead(allocator, "foo", .{ .force = false });
            defer result.deinit();
        }
        try addFile(repo_kind, repo_opts, &repo, allocator, "f.txt",
            \\a
            \\x
            \\b
        );
        _ = try repo.commit(allocator, .{ .message = "d" });
        {
            var result = try repo.switchHead(allocator, "master", .{ .force = false });
            defer result.deinit();
        }
        {
            var result = try repo.merge(allocator, .{ .new = ref.RefOrOid(repo_opts.hash).initFromUser("foo") });
            defer result.deinit();
            try std.testing.expect(.success == result.data);

            // verify f.txt has been autoresolved
            const f_txt = try repo.core.repo_dir.openFile("f.txt", .{ .mode = .read_only });
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
        defer status.deinit();
        var file_iter = try repo.filePairs(allocator, .{
            .workspace = .{
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
            var merge_result = try repo.merge(allocator, .{ .new = ref.RefOrOid(repo_opts.hash).initFromUser("foo") });
            defer merge_result.deinit();
            try std.testing.expect(.nothing == merge_result.data);
        }
    }

    // from https://tahoe-lafs.org/~zooko/badmerge/concrete-good-semantics.html
    {
        {
            var repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "concrete");
            defer repo.deinit();
        }

        var repo_dir = try temp_dir.openDir("concrete", .{});
        defer repo_dir.close();

        var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
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
            var result = try repo.switchHead(allocator, "foo", .{ .force = false });
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
            var result = try repo.switchHead(allocator, "master", .{ .force = false });
            defer result.deinit();
        }
        {
            var result = try repo.merge(allocator, .{ .new = ref.RefOrOid(repo_opts.hash).initFromUser("foo") });
            defer result.deinit();

            const f_txt = try repo.core.repo_dir.openFile("f.txt", .{ .mode = .read_only });
            defer f_txt.close();
            const f_txt_content = try f_txt.readToEndAlloc(allocator, 1024);
            defer allocator.free(f_txt_content);
            switch (repo_kind) {
                // verify f.txt has conflict markers
                .git => {
                    try std.testing.expect(.conflict == result.data);
                    try std.testing.expectEqualStrings(
                        \\int square(int x) {
                        \\<<<<<<< master
                        \\  int y = x;
                        \\  /* Update y to equal the result. */
                        \\  /* Question: what is the order of magnitude of this algorithm with respect to x? */
                        \\  return y * x;
                        \\}
                        \\
                        \\int very_slow_square(int x) {
                        \\  int y = 0;
                        \\||||||| original (218399a19e8507080980d6b43a64c069133fd26f)
                        \\  int y = x;
                        \\=======
                        \\  int y = 0;
                        \\>>>>>>> foo
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
                    ,
                        f_txt_content,
                    );
                },
                // verify f.txt has been autoresolved
                .xit => {
                    try std.testing.expect(.success == result.data);
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
                    ,
                        f_txt_content,
                    );
                },
            }
        }
    }
}

test "merge conflict shuffle" {
    try testMergeConflictShuffle(.git, .{});
    try testMergeConflictShuffle(.xit, .{});
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

    var repo_dir = try temp_dir.openDir("repo", .{});
    defer repo_dir.close();

    var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
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
        var result = try repo.switchHead(allocator, "foo", .{ .force = false });
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
        var result = try repo.switchHead(allocator, "master", .{ .force = false });
        defer result.deinit();
    }

    {
        var result = try repo.cherryPick(allocator, .{ .new = .{ .oid = &commit_d } });
        defer result.deinit();
        try std.testing.expect(.success == result.data);
    }

    // make sure stuff.md does not exist
    if (repo.core.repo_dir.openFile("stuff.md", .{})) |*file| {
        file.close();
        return error.UnexpectedFile;
    } else |_| {}

    // if we try cherry-picking the same commit again, it succeeds again
    {
        var merge_result = try repo.cherryPick(allocator, .{ .new = .{ .oid = &commit_d } });
        defer merge_result.deinit();
        try std.testing.expect(.success == merge_result.data);
    }
}

test "cherry-pick" {
    try testCherryPick(.git, .{});
    try testCherryPick(.xit, .{});
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

    const checkCherryPickAbort = struct {
        fn run(repo: *rp.Repo(repo_kind, repo_opts)) !void {
            // can't cherry-pick again with an unresolved cherry-pick
            {
                var result_or_err = repo.cherryPick(allocator, .{ .new = .{ .oid = &([_]u8{0} ** hash.hexLen(repo_opts.hash)) } });
                if (result_or_err) |*result| {
                    defer result.deinit();
                    return error.ExpectedMergeToAbort;
                } else |err| switch (err) {
                    error.UnfinishedMergeAlreadyInProgress => {},
                    else => |e| return e,
                }
            }

            // can't continue cherry-pick with unresolved conflicts
            {
                var result_or_err = repo.cherryPick(allocator, .cont);
                if (result_or_err) |*result| {
                    defer result.deinit();
                    return error.ExpectedMergeToAbort;
                } else |err| switch (err) {
                    error.CannotContinueMergeWithUnresolvedConflicts => {},
                    else => |e| return e,
                }
            }
        }
    }.run;

    {
        var repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "repo");
        defer repo.deinit();
    }

    var repo_dir = try temp_dir.openDir("repo", .{});
    defer repo_dir.close();

    var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
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
        var result = try repo.switchHead(allocator, "foo", .{ .force = false });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, allocator, "readme.md", "c");
    _ = try repo.commit(allocator, .{ .message = "c" });
    try addFile(repo_kind, repo_opts, &repo, allocator, "readme.md", "d");
    const commit_d = try repo.commit(allocator, .{ .message = "d" });
    try addFile(repo_kind, repo_opts, &repo, allocator, "readme.md", "e");
    _ = try repo.commit(allocator, .{ .message = "e" });
    {
        var result = try repo.switchHead(allocator, "master", .{ .force = false });
        defer result.deinit();
    }
    {
        var result = try repo.cherryPick(allocator, .{ .new = .{ .oid = &commit_d } });
        defer result.deinit();
        try std.testing.expect(.conflict == result.data);

        // verify readme.md has conflict markers
        const readme_md = try repo.core.repo_dir.openFile("readme.md", .{ .mode = .read_only });
        defer readme_md.close();
        const readme_md_content = try readme_md.readToEndAlloc(allocator, 1024);
        defer allocator.free(readme_md_content);
        const expected_readme_md_content = try std.fmt.allocPrint(allocator,
            \\<<<<<<< master
            \\b
            \\||||||| original ({s})
            \\c
            \\=======
            \\d
            \\>>>>>>> {s}
        , .{ result.base_oid, commit_d });
        defer allocator.free(expected_readme_md_content);
        try std.testing.expectEqualStrings(expected_readme_md_content, readme_md_content);
    }

    // generate diff
    var status = try repo.status(allocator);
    defer status.deinit();
    var file_iter = try repo.filePairs(allocator, .{
        .workspace = .{
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
    try checkCherryPickAbort(&repo);

    // resolve conflict
    try addFile(repo_kind, repo_opts, &repo, allocator, "readme.md",
        \\e
    );
    {
        var result = try repo.cherryPick(allocator, .cont);
        defer result.deinit();
        try std.testing.expect(.success == result.data);
    }
}

test "cherry-pick conflict" {
    try testCherryPickConflict(.git, .{});
    try testCherryPickConflict(.xit, .{});
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

    var repo_dir = try temp_dir.openDir("repo", .{});
    defer repo_dir.close();

    var repo = try rp.Repo(repo_kind, repo_opts).open(allocator, .{ .cwd = repo_dir });
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
        var result = try repo.switchHead(allocator, "foo", .{ .force = false });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, allocator, "foo.md", "d");
    const commit_d = try repo.commit(allocator, .{ .message = "d" });
    {
        var result = try repo.switchHead(allocator, "master", .{ .force = false });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, allocator, "master.md", "c");
    const commit_c = try repo.commit(allocator, .{ .message = "c" });
    {
        var result = try repo.switchHead(allocator, "foo", .{ .force = false });
        defer result.deinit();
    }
    try addFile(repo_kind, repo_opts, &repo, allocator, "foo.md", "e");
    const commit_e = try repo.commit(allocator, .{ .message = "e" });
    try addFile(repo_kind, repo_opts, &repo, allocator, "foo.md", "f");
    const commit_f = try repo.commit(allocator, .{ .message = "f" });
    {
        var result = try repo.switchHead(allocator, "master", .{ .force = false });
        defer result.deinit();
    }
    const commit_g = blk: {
        var result = try repo.merge(allocator, .{ .new = ref.RefOrOid(repo_opts.hash).initFromUser("foo") });
        defer result.deinit();
        try std.testing.expect(.success == result.data);
        break :blk result.data.success.oid;
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

    // iterate over all objects recursively
    {
        var count: usize = 0;
        var moment = try repo.core.latestMoment();
        const state = rp.Repo(repo_kind, repo_opts).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };
        var obj_iter = try obj.ObjectIterator(repo_kind, repo_opts, .full).init(allocator, state, &.{commit_g}, .{ .recursive = true });
        defer obj_iter.deinit();
        while (try obj_iter.next()) |object| {
            defer object.deinit();
            count += 1;
        }
        try std.testing.expectEqual(20, count);
    }
}

test "log" {
    try testLog(.git, .{});
    try testLog(.xit, .{});
}
