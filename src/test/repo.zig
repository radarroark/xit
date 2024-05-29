//! tests that create repos by generating commits
//! from an array of structs.

const std = @import("std");
const hash = @import("../hash.zig");
const rp = @import("../repo.zig");
const ref = @import("../ref.zig");
const chk = @import("../checkout.zig");

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
            parents: []const CommitName,
        },
        create_branch: struct {
            name: []const u8,
        },
        switch_head: struct {
            target: []const u8,
        },
    };
}

/// executes the actions on the given repo
fn execActions(
    allocator: std.mem.Allocator,
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
                var parent_oids = std.ArrayList([hash.SHA1_HEX_LEN]u8).init(allocator);
                defer parent_oids.deinit();

                for (action.commit.parents) |commit_name| {
                    try parent_oids.append(commit_name_to_oid.get(commit_name) orelse return error.ParentNotFound);
                }

                const oid_hex = try repo.commit(parent_oids.items, @tagName(action.commit.name));
                try commit_name_to_oid.put(action.commit.name, oid_hex);
            },
            .create_branch => {
                try repo.create_branch(action.create_branch.name);
            },
            .switch_head => {
                var result = chk.SwitchResult.init();
                defer result.deinit();
                try repo.switch_head(action.switch_head.target, &result);
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

    const actions =
        &[_]Action(CommitName){
        .{ .add_file = .{ .path = "README.md", .content = "Hello, world!" } },
        .{ .commit = .{ .name = .a, .parents = &[_]CommitName{} } },
        .{ .add_file = .{ .path = "README.md", .content = "Goodbye, world!" } },
        .{ .commit = .{ .name = .b, .parents = &[_]CommitName{.a} } },
        .{ .remove_file = .{ .path = "README.md" } },
        .{ .commit = .{ .name = .c, .parents = &[_]CommitName{.b} } },
        // make sure empty commits are possible
        .{ .commit = .{ .name = .d, .parents = &[_]CommitName{.c} } },
    };

    var commit_name_to_oid = std.AutoArrayHashMap(CommitName, [hash.SHA1_HEX_LEN]u8).init(allocator);
    defer commit_name_to_oid.deinit();

    try execActions(allocator, &repo, CommitName, actions, &commit_name_to_oid);

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

test "branch" {
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-repo-branch";
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

    const CommitName = enum {
        master_a,
        foo_b,
    };

    const actions =
        &[_]Action(CommitName){
        .{ .add_file = .{ .path = "README.md", .content = "Hello, world!" } },
        .{ .commit = .{ .name = .master_a, .parents = &[_]CommitName{} } },
        .{ .create_branch = .{ .name = "foo" } },
        .{ .switch_head = .{ .target = "foo" } },
        .{ .add_file = .{ .path = "README.md", .content = "Goodbye, world!" } },
        .{ .commit = .{ .name = .foo_b, .parents = &[_]CommitName{.master_a} } },
    };

    var commit_name_to_oid = std.AutoArrayHashMap(CommitName, [hash.SHA1_HEX_LEN]u8).init(allocator);
    defer commit_name_to_oid.deinit();

    try execActions(allocator, &repo, CommitName, actions, &commit_name_to_oid);
}