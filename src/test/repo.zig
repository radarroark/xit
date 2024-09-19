//! tests that create repos via the Repo struct.
//! runs with both git and xit modes.

const std = @import("std");
const hash = @import("../hash.zig");
const rp = @import("../repo.zig");
const ref = @import("../ref.zig");
const chk = @import("../checkout.zig");
const obj = @import("../object.zig");
const mrg = @import("../merge.zig");
const df = @import("../diff.zig");

fn addFile(comptime repo_kind: rp.RepoKind, repo: *rp.Repo(repo_kind), path: []const u8, content: []const u8) !void {
    if (std.fs.path.dirname(path)) |parent_path| {
        try repo.core.repo_dir.makePath(parent_path);
    }
    const file = try repo.core.repo_dir.createFile(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(content);
    try repo.add(&.{path});
}

fn removeFile(comptime repo_kind: rp.RepoKind, repo: *rp.Repo(repo_kind), path: []const u8) !void {
    try repo.core.repo_dir.deleteFile(path);
    try repo.add(&.{path});
}

fn testSimple(comptime repo_kind: rp.RepoKind) !void {
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

    const writers = .{ .out = std.io.null_writer, .err = std.io.null_writer };

    var repo = try rp.Repo(repo_kind).initWithCommand(allocator, .{ .cwd = temp_dir }, .{ .init = .{ .dir = "repo" } }, writers);
    defer repo.deinit();

    try addFile(repo_kind, &repo, "README.md", "Hello, world!");
    const commit_a = try repo.commit(null, .{ .message = "a" });
    try addFile(repo_kind, &repo, "README.md", "Goodbye, world!");
    const commit_b = try repo.commit(null, .{ .message = "b" });
    try removeFile(repo_kind, &repo, "README.md");
    const commit_c = try repo.commit(null, .{ .message = "c" });
    const commit_d = try repo.commit(null, .{ .message = "d" }); // make sure empty commits are possible

    // put oids in a set
    var oid_set = std.StringArrayHashMap(void).init(allocator);
    defer oid_set.deinit();
    try oid_set.put(&commit_a, {});
    try oid_set.put(&commit_b, {});
    try oid_set.put(&commit_c, {});
    try oid_set.put(&commit_d, {});

    // assert that all commits have been found in the log
    var commit_iter = try repo.log(null);
    defer commit_iter.deinit();
    while (try commit_iter.next()) |commit_object| {
        defer commit_object.deinit();
        _ = oid_set.swapRemove(&commit_object.oid);
    }
    try std.testing.expectEqual(0, oid_set.count());
}

test "simple" {
    try testSimple(.git);
    try testSimple(.xit);
}

fn testMerge(comptime repo_kind: rp.RepoKind) !void {
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

    const writers = .{ .out = std.io.null_writer, .err = std.io.null_writer };

    var repo = try rp.Repo(repo_kind).initWithCommand(allocator, .{ .cwd = temp_dir }, .{ .init = .{ .dir = "repo" } }, writers);
    defer repo.deinit();

    // A --- B --- C --------- J --- K [master]
    //        \               /
    //         \             /
    //          D --- E --- F [foo]
    //           \
    //            \
    //             G --- H [bar]

    try addFile(repo_kind, &repo, "master.md", "a");
    _ = try repo.commit(null, .{ .message = "a" });
    try addFile(repo_kind, &repo, "master.md", "b");
    _ = try repo.commit(null, .{ .message = "b" });
    try repo.addBranch(.{ .name = "foo" });
    {
        var result = try repo.switchHead("foo", .{ .force = false });
        defer result.deinit();
    }
    try addFile(repo_kind, &repo, "foo.md", "d");
    const commit_d = try repo.commit(null, .{ .message = "d" });
    try repo.addBranch(.{ .name = "bar" });
    {
        var result = try repo.switchHead("bar", .{ .force = false });
        defer result.deinit();
    }
    try addFile(repo_kind, &repo, "bar.md", "g");
    _ = try repo.commit(null, .{ .message = "g" });
    try addFile(repo_kind, &repo, "bar.md", "h");
    const commit_h = try repo.commit(null, .{ .message = "h" });
    {
        var result = try repo.switchHead("master", .{ .force = false });
        defer result.deinit();
    }
    try addFile(repo_kind, &repo, "master.md", "c");
    _ = try repo.commit(null, .{ .message = "c" });
    {
        var result = try repo.switchHead("foo", .{ .force = false });
        defer result.deinit();
    }
    try addFile(repo_kind, &repo, "foo.md", "e");
    _ = try repo.commit(null, .{ .message = "e" });
    try addFile(repo_kind, &repo, "foo.md", "f");
    _ = try repo.commit(null, .{ .message = "f" });
    {
        var result = try repo.switchHead("master", .{ .force = false });
        defer result.deinit();
    }
    const commit_j = blk: {
        var result = try repo.merge(.{ .new = .{ .source_name = "foo" } });
        defer result.deinit();
        try std.testing.expect(.success == result.data);
        break :blk result.data.success.oid;
    };
    try addFile(repo_kind, &repo, "master.md", "k");
    const commit_k = try repo.commit(null, .{ .message = "k" });

    var cursor = try repo.core.latestCursor();
    const core_cursor = switch (repo_kind) {
        .git => .{ .core = &repo.core },
        .xit => .{ .core = &repo.core, .cursor = &cursor },
    };

    // there are multiple common ancestors, b and d,
    // but d is the best one because it is a descendent of b
    const ancestor_k_h = try mrg.commonAncestor(repo_kind, allocator, core_cursor, &commit_k, &commit_h);
    try std.testing.expectEqualStrings(&commit_d, &ancestor_k_h);

    // if one commit is an ancestor of the other, it is the best common ancestor
    const ancestor_k_j = try mrg.commonAncestor(repo_kind, allocator, core_cursor, &commit_k, &commit_j);
    try std.testing.expectEqualStrings(&commit_j, &ancestor_k_j);

    // if we try merging foo again, it does nothing
    {
        var merge_result = try repo.merge(.{ .new = .{ .source_name = "foo" } });
        defer merge_result.deinit();
        try std.testing.expect(.nothing == merge_result.data);
    }

    // if we try merging master into foo, it fast forwards
    {
        var switch_result = try repo.switchHead("foo", .{ .force = false });
        defer switch_result.deinit();
        var merge_result = try repo.merge(.{ .new = .{ .source_name = "master" } });
        defer merge_result.deinit();
        try std.testing.expect(.fast_forward == merge_result.data);

        const head_oid = try ref.readHead(repo_kind, core_cursor);
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
    try testMerge(.git);
    try testMerge(.xit);
}

fn testMergeConflict(comptime repo_kind: rp.RepoKind) !void {
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

    const writers = .{ .out = std.io.null_writer, .err = std.io.null_writer };

    const checkMergeAbort = struct {
        fn run(repo: *rp.Repo(repo_kind)) !void {
            // can't merge again with an unresolved merge
            {
                var result_or_err = repo.merge(.{ .new = .{ .source_name = "foo" } });
                if (result_or_err) |*result| {
                    defer result.deinit();
                    return error.ExpectedMergeToAbort;
                } else |err| switch (err) {
                    error.UnfinishedMergeAlreadyInProgress => {},
                    else => return err,
                }
            }

            // can't continue merge with unresolved conflicts
            {
                var result_or_err = repo.merge(.cont);
                if (result_or_err) |*result| {
                    defer result.deinit();
                    return error.ExpectedMergeToAbort;
                } else |err| switch (err) {
                    error.CannotContinueMergeWithUnresolvedConflicts => {},
                    else => return err,
                }
            }
        }
    }.run;

    // same file conflict
    {
        var repo = try rp.Repo(repo_kind).initWithCommand(allocator, .{ .cwd = temp_dir }, .{ .init = .{ .dir = "same-file-conflict" } }, writers);
        defer repo.deinit();

        // A --- B --- D [master]
        //  \         /
        //   \       /
        //    `---- C [foo]

        try addFile(repo_kind, &repo, "f.txt",
            \\a
            \\b
            \\c
        );
        _ = try repo.commit(null, .{ .message = "a" });
        try repo.addBranch(.{ .name = "foo" });
        try addFile(repo_kind, &repo, "f.txt",
            \\a
            \\x
            \\c
        );
        _ = try repo.commit(null, .{ .message = "b" });
        {
            var result = try repo.switchHead("foo", .{ .force = false });
            defer result.deinit();
        }
        try addFile(repo_kind, &repo, "f.txt",
            \\a
            \\y
            \\c
        );
        _ = try repo.commit(null, .{ .message = "c" });
        {
            var result = try repo.switchHead("master", .{ .force = false });
            defer result.deinit();
        }
        {
            var result = try repo.merge(.{ .new = .{ .source_name = "foo" } });
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
            , .{result.common_oid});
            defer allocator.free(expected_f_txt_content);
            try std.testing.expectEqualStrings(expected_f_txt_content, f_txt_content);
        }

        // generate diff
        var status = try repo.status();
        defer status.deinit();
        var file_iter = try repo.filePairs(.{
            .workspace = .{
                .conflict_diff_kind = .current,
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
        try addFile(repo_kind, &repo, "f.txt",
            \\a
            \\y
            \\c
        );
        {
            var result = try repo.merge(.cont);
            defer result.deinit();
            try std.testing.expect(.success == result.data);
        }
    }

    // same file conflict (autoresolved)
    {
        var repo = try rp.Repo(repo_kind).initWithCommand(allocator, .{ .cwd = temp_dir }, .{ .init = .{ .dir = "same-file-conflict-autoresolved" } }, writers);
        defer repo.deinit();

        // A --- B --- D [master]
        //  \         /
        //   \       /
        //    `---- C [foo]

        try addFile(repo_kind, &repo, "f.txt",
            \\a
            \\b
            \\c
        );
        _ = try repo.commit(null, .{ .message = "a" });
        try repo.addBranch(.{ .name = "foo" });
        try addFile(repo_kind, &repo, "f.txt",
            \\x
            \\b
            \\c
        );
        _ = try repo.commit(null, .{ .message = "b" });
        {
            var result = try repo.switchHead("foo", .{ .force = false });
            defer result.deinit();
        }
        try addFile(repo_kind, &repo, "f.txt",
            \\a
            \\b
            \\y
        );
        _ = try repo.commit(null, .{ .message = "c" });
        {
            var result = try repo.switchHead("master", .{ .force = false });
            defer result.deinit();
        }
        {
            var result = try repo.merge(.{ .new = .{ .source_name = "foo" } });
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
        var status = try repo.status();
        defer status.deinit();
        var file_iter = try repo.filePairs(.{
            .workspace = .{
                .conflict_diff_kind = .current,
                .status = &status,
            },
        });
        if (try file_iter.next()) |*line_iter_pair_ptr| {
            var line_iter_pair = line_iter_pair_ptr.*;
            defer line_iter_pair.deinit();
            return error.DiffResultNotExpected;
        }
    }

    // modify/delete conflict (current modifies, source deletes)
    {
        var repo = try rp.Repo(repo_kind).initWithCommand(allocator, .{ .cwd = temp_dir }, .{ .init = .{ .dir = "modify-delete-conflict" } }, writers);
        defer repo.deinit();

        // A --- B --- D [master]
        //  \         /
        //   \       /
        //    `---- C [foo]

        try addFile(repo_kind, &repo, "f.txt", "1");
        _ = try repo.commit(null, .{ .message = "a" });
        try repo.addBranch(.{ .name = "foo" });
        try addFile(repo_kind, &repo, "f.txt", "2");
        _ = try repo.commit(null, .{ .message = "b" });
        {
            var result = try repo.switchHead("foo", .{ .force = false });
            defer result.deinit();
        }
        try removeFile(repo_kind, &repo, "f.txt");
        _ = try repo.commit(null, .{ .message = "c" });
        {
            var result = try repo.switchHead("master", .{ .force = false });
            defer result.deinit();
        }
        {
            var result = try repo.merge(.{ .new = .{ .source_name = "foo" } });
            defer result.deinit();
            try std.testing.expect(.conflict == result.data);
        }

        // generate diff
        var status = try repo.status();
        defer status.deinit();
        var file_iter = try repo.filePairs(.{
            .workspace = .{
                .conflict_diff_kind = .current,
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
        try repo.add(&.{"f.txt"});
        {
            var result = try repo.merge(.cont);
            defer result.deinit();
            try std.testing.expect(.success == result.data);
        }
    }

    // delete/modify conflict (current deletes, source modifies)
    {
        var repo = try rp.Repo(repo_kind).initWithCommand(allocator, .{ .cwd = temp_dir }, .{ .init = .{ .dir = "delete-modify-conflict" } }, writers);
        defer repo.deinit();

        // A --- B --- D [master]
        //  \         /
        //   \       /
        //    `---- C [foo]

        try addFile(repo_kind, &repo, "f.txt", "1");
        _ = try repo.commit(null, .{ .message = "a" });
        try repo.addBranch(.{ .name = "foo" });
        try removeFile(repo_kind, &repo, "f.txt");
        _ = try repo.commit(null, .{ .message = "b" });
        {
            var result = try repo.switchHead("foo", .{ .force = false });
            defer result.deinit();
        }
        try addFile(repo_kind, &repo, "f.txt", "2");
        _ = try repo.commit(null, .{ .message = "c" });
        {
            var result = try repo.switchHead("master", .{ .force = false });
            defer result.deinit();
        }
        {
            var result = try repo.merge(.{ .new = .{ .source_name = "foo" } });
            defer result.deinit();
            try std.testing.expect(.conflict == result.data);
        }

        // generate diff
        var status = try repo.status();
        defer status.deinit();
        var file_iter = try repo.filePairs(.{
            .workspace = .{
                .conflict_diff_kind = .current,
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
        try repo.add(&.{"f.txt"});
        {
            var result = try repo.merge(.cont);
            defer result.deinit();
            try std.testing.expect(.success == result.data);
        }
    }

    // file/dir conflict (current has file, source has dir)
    {
        var repo = try rp.Repo(repo_kind).initWithCommand(allocator, .{ .cwd = temp_dir }, .{ .init = .{ .dir = "file-dir-conflict" } }, writers);
        defer repo.deinit();

        // A --- B --- D [master]
        //  \         /
        //   \       /
        //    `---- C [foo]

        try addFile(repo_kind, &repo, "hi.txt", "hi");
        _ = try repo.commit(null, .{ .message = "a" });
        try repo.addBranch(.{ .name = "foo" });
        try addFile(repo_kind, &repo, "f.txt", "hi");
        _ = try repo.commit(null, .{ .message = "b" });
        {
            var result = try repo.switchHead("foo", .{ .force = false });
            defer result.deinit();
        }
        try addFile(repo_kind, &repo, "f.txt/g.txt", "hi");
        _ = try repo.commit(null, .{ .message = "c" });
        {
            var result = try repo.switchHead("master", .{ .force = false });
            defer result.deinit();
        }
        {
            var result = try repo.merge(.{ .new = .{ .source_name = "foo" } });
            defer result.deinit();
            try std.testing.expect(.conflict == result.data);
        }

        // generate diff
        var status = try repo.status();
        defer status.deinit();
        var file_iter = try repo.filePairs(.{
            .workspace = .{
                .conflict_diff_kind = .current,
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
        try repo.add(&.{"f.txt"});
        {
            var result = try repo.merge(.cont);
            defer result.deinit();
            try std.testing.expect(.success == result.data);
        }
    }

    // dir/file conflict (current has dir, source has file)
    {
        var repo = try rp.Repo(repo_kind).initWithCommand(allocator, .{ .cwd = temp_dir }, .{ .init = .{ .dir = "dir-file-conflict" } }, writers);
        defer repo.deinit();

        // A --- B --- D [master]
        //  \         /
        //   \       /
        //    `---- C [foo]

        try addFile(repo_kind, &repo, "hi.txt", "hi");
        _ = try repo.commit(null, .{ .message = "a" });
        try repo.addBranch(.{ .name = "foo" });
        try addFile(repo_kind, &repo, "f.txt/g.txt", "hi");
        _ = try repo.commit(null, .{ .message = "b" });
        {
            var result = try repo.switchHead("foo", .{ .force = false });
            defer result.deinit();
        }
        try addFile(repo_kind, &repo, "f.txt", "hi");
        _ = try repo.commit(null, .{ .message = "c" });
        {
            var result = try repo.switchHead("master", .{ .force = false });
            defer result.deinit();
        }
        {
            var result = try repo.merge(.{ .new = .{ .source_name = "foo" } });
            defer result.deinit();
            try std.testing.expect(.conflict == result.data);
        }

        // make sure renamed file exists
        var renamed_file = try repo.core.repo_dir.openFile("f.txt~foo", .{});
        defer renamed_file.close();

        // generate diff
        var status = try repo.status();
        defer status.deinit();
        var file_iter = try repo.filePairs(.{
            .workspace = .{
                .conflict_diff_kind = .current,
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
        try repo.add(&.{"f.txt"});
        {
            var result = try repo.merge(.cont);
            defer result.deinit();
            try std.testing.expect(.success == result.data);
        }
    }
}

test "merge conflict" {
    try testMergeConflict(.git);
    try testMergeConflict(.xit);
}

/// demonstrates an example of git shuffling lines unexpectedly
/// when auto-resolving a merge conflict
fn testMergeConflictShuffle(comptime repo_kind: rp.RepoKind) !void {
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

    const writers = .{ .out = std.io.null_writer, .err = std.io.null_writer };

    var repo = try rp.Repo(repo_kind).initWithCommand(allocator, .{ .cwd = temp_dir }, .{ .init = .{ .dir = "repo" } }, writers);
    defer repo.deinit();

    // A --- B --- C --- E [master]
    //  \               /
    //   \             /
    //    `---------- D [foo]

    try addFile(repo_kind, &repo, "f.txt",
        \\a
        \\b
    );
    _ = try repo.commit(null, .{ .message = "a" });
    try repo.addBranch(.{ .name = "foo" });
    try addFile(repo_kind, &repo, "f.txt",
        \\g
        \\a
        \\b
    );
    _ = try repo.commit(null, .{ .message = "b" });
    try addFile(repo_kind, &repo, "f.txt",
        \\a
        \\b
        \\g
        \\a
        \\b
    );
    _ = try repo.commit(null, .{ .message = "c" });
    {
        var result = try repo.switchHead("foo", .{ .force = false });
        defer result.deinit();
    }
    try addFile(repo_kind, &repo, "f.txt",
        \\a
        \\x
        \\b
    );
    _ = try repo.commit(null, .{ .message = "d" });
    {
        var result = try repo.switchHead("master", .{ .force = false });
        defer result.deinit();
    }
    {
        var result = try repo.merge(.{ .new = .{ .source_name = "foo" } });
        defer result.deinit();
        try std.testing.expect(.success == result.data);

        // verify f.txt has been autoresolved
        const f_txt = try repo.core.repo_dir.openFile("f.txt", .{ .mode = .read_only });
        defer f_txt.close();
        const f_txt_content = try f_txt.readToEndAlloc(allocator, 1024);
        defer allocator.free(f_txt_content);
        try std.testing.expectEqualStrings(
            \\a
            \\x
            \\b
            \\g
            \\a
            \\b
        ,
            f_txt_content,
        );
    }

    // generate diff
    var status = try repo.status();
    defer status.deinit();
    var file_iter = try repo.filePairs(.{
        .workspace = .{
            .conflict_diff_kind = .current,
            .status = &status,
        },
    });
    if (try file_iter.next()) |*line_iter_pair_ptr| {
        var line_iter_pair = line_iter_pair_ptr.*;
        defer line_iter_pair.deinit();
        return error.DiffResultNotExpected;
    }
}

test "merge conflict shuffle" {
    try testMergeConflictShuffle(.git);
    try testMergeConflictShuffle(.xit);
}

fn testCherryPick(comptime repo_kind: rp.RepoKind) !void {
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

    const writers = .{ .out = std.io.null_writer, .err = std.io.null_writer };

    var repo = try rp.Repo(repo_kind).initWithCommand(allocator, .{ .cwd = temp_dir }, .{ .init = .{ .dir = "repo" } }, writers);
    defer repo.deinit();

    // A --- B ------------ D' [master]
    //        \
    //         \
    //          C --- D --- E [foo]

    try addFile(repo_kind, &repo, "readme.md", "a");
    _ = try repo.commit(null, .{ .message = "a" });
    try addFile(repo_kind, &repo, "readme.md", "b");
    _ = try repo.commit(null, .{ .message = "b" });
    try repo.addBranch(.{ .name = "foo" });
    {
        var result = try repo.switchHead("foo", .{ .force = false });
        defer result.deinit();
    }
    // commit d will be the parent of the cherry-picked commit,
    // and it is modifying a different file, so it shouldn't
    // cause a conflict.
    try addFile(repo_kind, &repo, "stuff.md", "c");
    _ = try repo.commit(null, .{ .message = "c" });
    try addFile(repo_kind, &repo, "readme.md", "d");
    const commit_d = try repo.commit(null, .{ .message = "d" });
    try addFile(repo_kind, &repo, "readme.md", "e");
    _ = try repo.commit(null, .{ .message = "e" });
    {
        var result = try repo.switchHead("master", .{ .force = false });
        defer result.deinit();
    }

    {
        var result = try repo.cherryPick(.{ .new = .{ .source_name = &commit_d } });
        defer result.deinit();
        try std.testing.expect(.success == result.data);
    }

    // make sure stuff.md does not exist
    if (repo.core.repo_dir.openFile("stuff.md", .{})) |*file| {
        file.close();
        return error.UnexpectedFile;
    } else |_| {}

    // if we try cherry-picking the same commit again, it does succeeds again
    {
        var merge_result = try repo.cherryPick(.{ .new = .{ .source_name = &commit_d } });
        defer merge_result.deinit();
        try std.testing.expect(.success == merge_result.data);
    }
}

test "cherry-pick" {
    try testCherryPick(.git);
    try testCherryPick(.xit);
}

fn testCherryPickConflict(comptime repo_kind: rp.RepoKind) !void {
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

    const writers = .{ .out = std.io.null_writer, .err = std.io.null_writer };

    const checkCherryPickAbort = struct {
        fn run(repo: *rp.Repo(repo_kind)) !void {
            // can't cherry-pick again with an unresolved cherry-pick
            {
                var result_or_err = repo.cherryPick(.{ .new = .{ .source_name = "foo" } });
                if (result_or_err) |*result| {
                    defer result.deinit();
                    return error.ExpectedMergeToAbort;
                } else |err| switch (err) {
                    error.UnfinishedMergeAlreadyInProgress => {},
                    else => return err,
                }
            }

            // can't continue cherry-pick with unresolved conflicts
            {
                var result_or_err = repo.cherryPick(.cont);
                if (result_or_err) |*result| {
                    defer result.deinit();
                    return error.ExpectedMergeToAbort;
                } else |err| switch (err) {
                    error.CannotContinueMergeWithUnresolvedConflicts => {},
                    else => return err,
                }
            }
        }
    }.run;

    var repo = try rp.Repo(repo_kind).initWithCommand(allocator, .{ .cwd = temp_dir }, .{ .init = .{ .dir = "repo" } }, writers);
    defer repo.deinit();

    // A --- B ------------ D' [master]
    //        \
    //         \
    //          D --- D --- E [foo]

    try addFile(repo_kind, &repo, "readme.md", "a");
    _ = try repo.commit(null, .{ .message = "a" });
    try addFile(repo_kind, &repo, "readme.md", "b");
    _ = try repo.commit(null, .{ .message = "b" });
    try repo.addBranch(.{ .name = "foo" });
    {
        var result = try repo.switchHead("foo", .{ .force = false });
        defer result.deinit();
    }
    try addFile(repo_kind, &repo, "readme.md", "c");
    _ = try repo.commit(null, .{ .message = "c" });
    try addFile(repo_kind, &repo, "readme.md", "d");
    const commit_d = try repo.commit(null, .{ .message = "d" });
    try addFile(repo_kind, &repo, "readme.md", "e");
    _ = try repo.commit(null, .{ .message = "e" });
    {
        var result = try repo.switchHead("master", .{ .force = false });
        defer result.deinit();
    }
    {
        var result = try repo.cherryPick(.{ .new = .{ .source_name = &commit_d } });
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
        , .{ result.common_oid, commit_d });
        defer allocator.free(expected_readme_md_content);
        try std.testing.expectEqualStrings(expected_readme_md_content, readme_md_content);
    }

    // generate diff
    var status = try repo.status();
    defer status.deinit();
    var file_iter = try repo.filePairs(.{
        .workspace = .{
            .conflict_diff_kind = .current,
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
    try addFile(repo_kind, &repo, "readme.md",
        \\e
    );
    {
        var result = try repo.cherryPick(.cont);
        defer result.deinit();
        try std.testing.expect(.success == result.data);
    }
}

test "cherry-pick conflict" {
    try testCherryPickConflict(.git);
    try testCherryPickConflict(.xit);
}

fn testLog(comptime repo_kind: rp.RepoKind) !void {
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

    const writers = .{ .out = std.io.null_writer, .err = std.io.null_writer };

    var repo = try rp.Repo(repo_kind).initWithCommand(allocator, .{ .cwd = temp_dir }, .{ .init = .{ .dir = "repo" } }, writers);
    defer repo.deinit();

    // A --- B --- C --------- G --- H [master]
    //        \               /
    //         \             /
    //          D --- E --- F [foo]

    try addFile(repo_kind, &repo, "master.md", "a");
    const commit_a = try repo.commit(null, .{ .message = "a" });
    try addFile(repo_kind, &repo, "master.md", "b");
    const commit_b = try repo.commit(null, .{ .message = "b" });
    try repo.addBranch(.{ .name = "foo" });
    {
        var result = try repo.switchHead("foo", .{ .force = false });
        defer result.deinit();
    }
    try addFile(repo_kind, &repo, "foo.md", "d");
    const commit_d = try repo.commit(null, .{ .message = "d" });
    {
        var result = try repo.switchHead("master", .{ .force = false });
        defer result.deinit();
    }
    try addFile(repo_kind, &repo, "master.md", "c");
    const commit_c = try repo.commit(null, .{ .message = "c" });
    {
        var result = try repo.switchHead("foo", .{ .force = false });
        defer result.deinit();
    }
    try addFile(repo_kind, &repo, "foo.md", "e");
    const commit_e = try repo.commit(null, .{ .message = "e" });
    try addFile(repo_kind, &repo, "foo.md", "f");
    const commit_f = try repo.commit(null, .{ .message = "f" });
    {
        var result = try repo.switchHead("master", .{ .force = false });
        defer result.deinit();
    }
    const commit_g = blk: {
        var result = try repo.merge(.{ .new = .{ .source_name = "foo" } });
        defer result.deinit();
        try std.testing.expect(.success == result.data);
        break :blk result.data.success.oid;
    };
    try addFile(repo_kind, &repo, "master.md", "h");
    const commit_h = try repo.commit(null, .{ .message = "h" });

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
        var commit_iter = try repo.log(null);
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
        var commit_iter = try repo.log(&.{commit_g});
        defer commit_iter.deinit();
        try commit_iter.excludeParents(commit_c);
        try commit_iter.excludeParents(commit_d);
        while (try commit_iter.next()) |commit_object| {
            defer commit_object.deinit();
            try std.testing.expect(oid_set.contains(&commit_object.oid));
            _ = oid_set.swapRemove(&commit_object.oid);
        }
        try std.testing.expectEqual(0, oid_set.count());
    }
}

test "log" {
    try testLog(.git);
    try testLog(.xit);
}
