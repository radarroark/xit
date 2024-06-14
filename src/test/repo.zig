//! tests that create repos via the Repo struct.
//! runs with both git and xit modes.

const std = @import("std");
const hash = @import("../hash.zig");
const rp = @import("../repo.zig");
const ref = @import("../ref.zig");
const chk = @import("../checkout.zig");
const obj = @import("../object.zig");
const mrg = @import("../merge.zig");

fn expectEqual(expected: anytype, actual: anytype) !void {
    try std.testing.expectEqual(@as(@TypeOf(actual), expected), actual);
}

fn addFile(comptime repo_kind: rp.RepoKind, repo: *rp.Repo(repo_kind), path: []const u8, content: []const u8) !void {
    if (std.fs.path.dirname(path)) |parent_path| {
        try repo.core.repo_dir.makePath(parent_path);
    }
    const file = try repo.core.repo_dir.createFile(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(content);
    try repo.add(&[_][]const u8{path});
}

fn removeFile(comptime repo_kind: rp.RepoKind, repo: *rp.Repo(repo_kind), path: []const u8) !void {
    try repo.core.repo_dir.deleteFile(path);
    try repo.add(&[_][]const u8{path});
}

fn testSimple(comptime repo_kind: rp.RepoKind) !void {
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-simple";
    const cwd = std.fs.cwd();

    // create the temp dir
    if (cwd.openFile(temp_dir_name, .{})) |file| {
        file.close();
        try cwd.deleteTree(temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.makeOpenPath(temp_dir_name, .{});
    defer cwd.deleteTree(temp_dir_name) catch {};
    defer temp_dir.close();

    const writers = .{ .out = std.io.null_writer, .err = std.io.null_writer };

    var repo = try rp.Repo(repo_kind).initWithCommand(allocator, .{ .cwd = temp_dir }, .{ .init = .{ .dir = "repo" } }, writers);
    defer repo.deinit();

    try addFile(repo_kind, &repo, "README.md", "Hello, world!");
    const commit_a = try repo.commit(null, "a");
    try addFile(repo_kind, &repo, "README.md", "Goodbye, world!");
    const commit_b = try repo.commit(null, "b");
    try removeFile(repo_kind, &repo, "README.md");
    const commit_c = try repo.commit(null, "c");
    const commit_d = try repo.commit(null, "d"); // make sure empty commits are possible

    // put oids in a set
    var oid_set = std.StringArrayHashMap(void).init(allocator);
    defer oid_set.deinit();
    try oid_set.put(&commit_a, {});
    try oid_set.put(&commit_b, {});
    try oid_set.put(&commit_c, {});
    try oid_set.put(&commit_d, {});

    // assert that all commits have been found in the log
    var cursor = try repo.core.readOnlyCursor();
    const core_cursor = switch (repo_kind) {
        .git => .{ .core = &repo.core },
        .xit => .{ .core = &repo.core, .root_cursor = &cursor },
    };
    const head_oid = try ref.readHead(repo_kind, core_cursor);
    var commit_iter = try repo.log(head_oid);
    defer commit_iter.deinit();
    while (try commit_iter.next()) |commit_object| {
        defer commit_object.deinit();
        _ = oid_set.swapRemove(&commit_object.oid);
    }
    try expectEqual(0, oid_set.count());
}

test "simple" {
    try testSimple(.git);
    try testSimple(.xit);
}

fn testMerge(comptime repo_kind: rp.RepoKind) !void {
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-merge";
    const cwd = std.fs.cwd();

    // create the temp dir
    if (cwd.openFile(temp_dir_name, .{})) |file| {
        file.close();
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
    _ = try repo.commit(null, "a");
    try addFile(repo_kind, &repo, "master.md", "b");
    _ = try repo.commit(null, "b");
    try repo.create_branch("foo");
    {
        var result = try repo.switch_head("foo");
        defer result.deinit();
    }
    try addFile(repo_kind, &repo, "foo.md", "d");
    const commit_d = try repo.commit(null, "d");
    try repo.create_branch("bar");
    {
        var result = try repo.switch_head("bar");
        defer result.deinit();
    }
    try addFile(repo_kind, &repo, "bar.md", "g");
    _ = try repo.commit(null, "g");
    try addFile(repo_kind, &repo, "bar.md", "h");
    const commit_h = try repo.commit(null, "h");
    {
        var result = try repo.switch_head("master");
        defer result.deinit();
    }
    try addFile(repo_kind, &repo, "master.md", "c");
    _ = try repo.commit(null, "c");
    {
        var result = try repo.switch_head("foo");
        defer result.deinit();
    }
    try addFile(repo_kind, &repo, "foo.md", "e");
    _ = try repo.commit(null, "e");
    try addFile(repo_kind, &repo, "foo.md", "f");
    _ = try repo.commit(null, "f");
    {
        var result = try repo.switch_head("master");
        defer result.deinit();
    }
    try addFile(repo_kind, &repo, "master.md", "c");
    _ = try repo.commit(null, "c");
    const commit_j = blk: {
        var result = try repo.merge("foo");
        defer result.deinit();
        try std.testing.expect(.success == result.data);
        break :blk result.data.success.oid;
    };
    try addFile(repo_kind, &repo, "master.md", "k");
    const commit_k = try repo.commit(null, "k");

    var cursor = try repo.core.readOnlyCursor();
    const core_cursor = switch (repo_kind) {
        .git => .{ .core = &repo.core },
        .xit => .{ .core = &repo.core, .root_cursor = &cursor },
    };

    // there are multiple common ancestors, b and d,
    // but d is the best one because it is a descendent of b
    const ancestor_k_h = try obj.commonAncestor(repo_kind, allocator, core_cursor, &commit_k, &commit_h);
    try std.testing.expectEqualStrings(&commit_d, &ancestor_k_h);

    // if one commit is an ancestor of the other, it is the best common ancestor
    const ancestor_k_j = try obj.commonAncestor(repo_kind, allocator, core_cursor, &commit_k, &commit_j);
    try std.testing.expectEqualStrings(&commit_j, &ancestor_k_j);

    // if we try merging foo again, it does nothing
    {
        var merge_result = try repo.merge("foo");
        defer merge_result.deinit();
        try std.testing.expect(.nothing == merge_result.data);
    }

    // if we try merging master into foo, it fast forwards
    {
        var switch_result = try repo.switch_head("foo");
        defer switch_result.deinit();
        var merge_result = try repo.merge("master");
        defer merge_result.deinit();
        try std.testing.expect(.fast_forward == merge_result.data);

        const head_oid = try ref.readHead(repo_kind, core_cursor);
        try expectEqual(commit_k, head_oid);

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
    const cwd = std.fs.cwd();

    // create the temp dir
    if (cwd.openFile(temp_dir_name, .{})) |file| {
        file.close();
        try cwd.deleteTree(temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.makeOpenPath(temp_dir_name, .{});
    defer cwd.deleteTree(temp_dir_name) catch {};
    defer temp_dir.close();

    const writers = .{ .out = std.io.null_writer, .err = std.io.null_writer };

    // same file conflict
    {
        var repo = try rp.Repo(repo_kind).initWithCommand(allocator, .{ .cwd = temp_dir }, .{ .init = .{ .dir = "same-file-conflict" } }, writers);
        defer repo.deinit();

        // A --- B --- D [master]
        //  \         /
        //   \       /
        //    `---- C [foo]

        try addFile(repo_kind, &repo, "f.txt", "1");
        _ = try repo.commit(null, "a");
        try repo.create_branch("foo");
        try addFile(repo_kind, &repo, "f.txt", "2");
        _ = try repo.commit(null, "b");
        {
            var result = try repo.switch_head("foo");
            defer result.deinit();
        }
        try addFile(repo_kind, &repo, "f.txt", "3");
        _ = try repo.commit(null, "d");
        {
            var result = try repo.switch_head("master");
            defer result.deinit();
        }
        {
            var result = try repo.merge("foo");
            defer result.deinit();
            try std.testing.expect(.conflict == result.data);
        }

        // generate diff
        var diff_iter = try repo.diff(.workspace, .current);
        defer diff_iter.deinit();
        if (try diff_iter.next()) |diff_item| {
            defer diff_item.deinit();
            try std.testing.expectEqualStrings("f.txt", diff_item.path);
        } else {
            return error.DiffResultExpected;
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
        _ = try repo.commit(null, "a");
        try repo.create_branch("foo");
        try addFile(repo_kind, &repo, "f.txt", "2");
        _ = try repo.commit(null, "b");
        {
            var result = try repo.switch_head("foo");
            defer result.deinit();
        }
        try removeFile(repo_kind, &repo, "f.txt");
        _ = try repo.commit(null, "d");
        {
            var result = try repo.switch_head("master");
            defer result.deinit();
        }
        {
            var result = try repo.merge("foo");
            defer result.deinit();
            try std.testing.expect(.conflict == result.data);
        }

        // generate diff
        var diff_iter = try repo.diff(.workspace, .current);
        defer diff_iter.deinit();
        if (try diff_iter.next()) |diff_item| {
            defer diff_item.deinit();
            try std.testing.expectEqualStrings("f.txt", diff_item.path);
        } else {
            return error.DiffResultExpected;
        }
    }

    // modify/delete conflict (current deletes, source modifies)
    {
        var repo = try rp.Repo(repo_kind).initWithCommand(allocator, .{ .cwd = temp_dir }, .{ .init = .{ .dir = "delete-modify-conflict" } }, writers);
        defer repo.deinit();

        // A --- B --- D [master]
        //  \         /
        //   \       /
        //    `---- C [foo]

        try addFile(repo_kind, &repo, "f.txt", "1");
        _ = try repo.commit(null, "a");
        try repo.create_branch("foo");
        try removeFile(repo_kind, &repo, "f.txt");
        _ = try repo.commit(null, "b");
        {
            var result = try repo.switch_head("foo");
            defer result.deinit();
        }
        try addFile(repo_kind, &repo, "f.txt", "2");
        _ = try repo.commit(null, "d");
        {
            var result = try repo.switch_head("master");
            defer result.deinit();
        }
        {
            var result = try repo.merge("foo");
            defer result.deinit();
            try std.testing.expect(.conflict == result.data);
        }

        // generate diff
        var diff_iter = try repo.diff(.workspace, .current);
        defer diff_iter.deinit();
        if (try diff_iter.next()) |diff_item| {
            defer diff_item.deinit();
            return error.DiffResultNotExpected;
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
        _ = try repo.commit(null, "a");
        try repo.create_branch("foo");
        try addFile(repo_kind, &repo, "f.txt", "hi");
        _ = try repo.commit(null, "b");
        {
            var result = try repo.switch_head("foo");
            defer result.deinit();
        }
        try addFile(repo_kind, &repo, "f.txt/g.txt", "hi");
        _ = try repo.commit(null, "c");
        {
            var result = try repo.switch_head("master");
            defer result.deinit();
        }
        {
            var result = try repo.merge("foo");
            defer result.deinit();
            try std.testing.expect(.conflict == result.data);
        }

        // generate diff
        var diff_iter = try repo.diff(.workspace, .current);
        defer diff_iter.deinit();
        if (try diff_iter.next()) |diff_item| {
            defer diff_item.deinit();
            try std.testing.expectEqualStrings("f.txt", diff_item.path);
        } else {
            return error.DiffResultExpected;
        }

        // make sure renamed file exists
        var renamed_file = try repo.core.repo_dir.openFile("f.txt~master", .{});
        defer renamed_file.close();
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
        _ = try repo.commit(null, "a");
        try repo.create_branch("foo");
        try addFile(repo_kind, &repo, "f.txt/g.txt", "hi");
        _ = try repo.commit(null, "b");
        {
            var result = try repo.switch_head("foo");
            defer result.deinit();
        }
        try addFile(repo_kind, &repo, "f.txt", "hi");
        _ = try repo.commit(null, "c");
        {
            var result = try repo.switch_head("master");
            defer result.deinit();
        }
        {
            var result = try repo.merge("foo");
            defer result.deinit();
            try std.testing.expect(.conflict == result.data);
        }

        // generate diff
        var diff_iter = try repo.diff(.workspace, .current);
        defer diff_iter.deinit();
        if (try diff_iter.next()) |diff_item| {
            defer diff_item.deinit();
            return error.DiffResultNotExpected;
        }

        // make sure renamed file exists
        var renamed_file = try repo.core.repo_dir.openFile("f.txt~foo", .{});
        defer renamed_file.close();
    }
}

test "merge conflict" {
    try testMergeConflict(.git);
    try testMergeConflict(.xit);
}
