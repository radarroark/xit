//! tests that create repos by generating commits
//! from an array of structs.

const std = @import("std");
const hash = @import("../hash.zig");
const rp = @import("../repo.zig");
const ref = @import("../ref.zig");
const chk = @import("../checkout.zig");
const obj = @import("../object.zig");

fn expectEqual(expected: anytype, actual: anytype) !void {
    try std.testing.expectEqual(@as(@TypeOf(actual), expected), actual);
}

fn Action(comptime CommitName: type) type {
    return union(enum) {
        add_file: struct {
            path: []const u8,
            content: []const u8,
        },
        remove_file: struct {
            path: []const u8,
        },
        commit: struct {
            name: CommitName,
        },
        create_branch: struct {
            name: []const u8,
        },
        switch_head: struct {
            target: []const u8,
        },
        merge: struct {
            name: CommitName,
            source: []const u8,
        },
    };
}

/// executes the actions on the given repo
fn execActions(
    repo: *rp.Repo(.xit),
    comptime CommitName: type,
    actions: []const Action(CommitName),
    commit_name_to_oid: *std.AutoArrayHashMap(CommitName, [hash.SHA1_HEX_LEN]u8),
) !void {
    for (actions) |action| {
        switch (action) {
            .add_file => {
                const file = try repo.core.repo_dir.createFile(action.add_file.path, .{ .truncate = true });
                defer file.close();
                try file.writeAll(action.add_file.content);
                try repo.add(&[_][]const u8{action.add_file.path});
            },
            .remove_file => {
                try repo.core.repo_dir.deleteFile(action.remove_file.path);
                try repo.add(&[_][]const u8{action.remove_file.path});
            },
            .commit => {
                const oid_hex = try repo.commit(null, @tagName(action.commit.name));
                try commit_name_to_oid.put(action.commit.name, oid_hex);
            },
            .create_branch => {
                try repo.create_branch(action.create_branch.name);
            },
            .switch_head => {
                var result = try repo.switch_head(action.switch_head.target);
                defer result.deinit();
            },
            .merge => {
                const oid_hex = try repo.merge(action.merge.source);
                try commit_name_to_oid.put(action.merge.name, oid_hex);
            },
        }
    }
}

test "simple" {
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

    var repo = try rp.Repo(.xit).initWithCommand(allocator, .{ .cwd = temp_dir }, .{ .init = .{ .dir = "repo" } });
    defer repo.deinit();

    const CommitName = enum { a, b, c, d };

    const actions = &[_]Action(CommitName){
        .{ .add_file = .{ .path = "README.md", .content = "Hello, world!" } },
        .{ .commit = .{ .name = .a } },
        .{ .add_file = .{ .path = "README.md", .content = "Goodbye, world!" } },
        .{ .commit = .{ .name = .b } },
        .{ .remove_file = .{ .path = "README.md" } },
        .{ .commit = .{ .name = .c } },
        // make sure empty commits are possible
        .{ .commit = .{ .name = .d } },
    };

    var commit_name_to_oid = std.AutoArrayHashMap(CommitName, [hash.SHA1_HEX_LEN]u8).init(allocator);
    defer commit_name_to_oid.deinit();

    try execActions(&repo, CommitName, actions, &commit_name_to_oid);

    var oid_to_action = std.StringArrayHashMap(Action(CommitName)).init(allocator);
    defer oid_to_action.deinit();
    for (actions) |action| {
        if (action == .commit) {
            // we have to use getPtr here or else the oid will be copied to the local
            // and then destroyed when the scope ends
            const oid = commit_name_to_oid.getPtr(action.commit.name) orelse return error.CommitNotFound;
            try oid_to_action.put(oid, action);
        }
    }

    // assert that all commits in `actions` have been found in the log
    const head_oid = (try ref.readHeadMaybe(.xit, &repo.core)).?;
    var commit_iter = try repo.log(head_oid);
    defer commit_iter.deinit();
    while (try commit_iter.next()) |commit_object| {
        defer commit_object.deinit();
        _ = oid_to_action.swapRemove(&commit_object.oid);
    }
    try expectEqual(0, oid_to_action.count());
}

test "best common ancestor" {
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-best-common-ancestor";
    const cwd = std.fs.cwd();

    // create the temp dir
    if (cwd.openFile(temp_dir_name, .{})) |file| {
        file.close();
        try cwd.deleteTree(temp_dir_name);
    } else |_| {}
    var temp_dir = try cwd.makeOpenPath(temp_dir_name, .{});
    defer cwd.deleteTree(temp_dir_name) catch {};
    defer temp_dir.close();

    var repo = try rp.Repo(.xit).initWithCommand(allocator, .{ .cwd = temp_dir }, .{ .init = .{ .dir = "repo" } });
    defer repo.deinit();

    const CommitName = enum { a, b, c, d, e, f, g, h, j, k };

    const actions = &[_]Action(CommitName){
        .{ .add_file = .{ .path = "master.md", .content = "a" } },
        .{ .commit = .{ .name = .a } },
        .{ .add_file = .{ .path = "master.md", .content = "b" } },
        .{ .commit = .{ .name = .b } },
        .{ .create_branch = .{ .name = "foo" } },
        .{ .switch_head = .{ .target = "foo" } },
        .{ .add_file = .{ .path = "foo.md", .content = "d" } },
        .{ .commit = .{ .name = .d } },
        .{ .create_branch = .{ .name = "bar" } },
        .{ .switch_head = .{ .target = "bar" } },
        .{ .add_file = .{ .path = "bar.md", .content = "g" } },
        .{ .commit = .{ .name = .g } },
        .{ .add_file = .{ .path = "bar.md", .content = "h" } },
        .{ .commit = .{ .name = .h } },
        .{ .switch_head = .{ .target = "master" } },
        .{ .add_file = .{ .path = "master.md", .content = "c" } },
        .{ .commit = .{ .name = .c } },
        .{ .switch_head = .{ .target = "foo" } },
        .{ .add_file = .{ .path = "foo.md", .content = "e" } },
        .{ .commit = .{ .name = .e } },
        .{ .add_file = .{ .path = "foo.md", .content = "f" } },
        .{ .commit = .{ .name = .f } },
        .{ .switch_head = .{ .target = "master" } },
        .{ .add_file = .{ .path = "master.md", .content = "c" } },
        .{ .commit = .{ .name = .c } },
        .{ .merge = .{ .name = .j, .source = "foo" } },
        .{ .add_file = .{ .path = "master.md", .content = "k" } },
        .{ .commit = .{ .name = .k } },
    };

    var commit_name_to_oid = std.AutoArrayHashMap(CommitName, [hash.SHA1_HEX_LEN]u8).init(allocator);
    defer commit_name_to_oid.deinit();

    try execActions(&repo, CommitName, actions, &commit_name_to_oid);

    const commit_k = commit_name_to_oid.get(.k).?;
    const commit_h = commit_name_to_oid.get(.h).?;
    const commit_d = commit_name_to_oid.get(.d).?;

    const ancestor_commit = try obj.commonAncestor(.xit, allocator, &repo.core, &commit_k, &commit_h);
    try std.testing.expectEqualStrings(&commit_d, &ancestor_commit);
}
