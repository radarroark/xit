//! tests that create repos by generating commits
//! from an array of structs.

const std = @import("std");
const hash = @import("../hash.zig");
const rp = @import("../repo.zig");

fn expectEqual(expected: anytype, actual: anytype) !void {
    try std.testing.expectEqual(@as(@TypeOf(actual), expected), actual);
}

const Change = union(enum) {
    add: struct {
        path: []const u8,
        content: []const u8,
    },
    remove: struct {
        path: []const u8,
    },
};

fn Commit(comptime CommitName: type) type {
    return struct {
        name: CommitName,
        parents: []const CommitName,
        changes: []const Change,
    };
}

fn generateCommits(
    allocator: std.mem.Allocator,
    repo: *rp.Repo(.xit),
    comptime CommitName: type,
    commits: []const Commit(CommitName),
) !void {
    var name_to_oid = std.AutoHashMap(CommitName, [hash.SHA1_HEX_LEN]u8).init(allocator);
    defer name_to_oid.deinit();

    for (commits) |commit| {
        var parent_oids = std.ArrayList([hash.SHA1_HEX_LEN]u8).init(allocator);
        defer parent_oids.deinit();

        for (commit.parents) |commit_name| {
            try parent_oids.append(name_to_oid.get(commit_name) orelse return error.ParentNotFound);
        }

        for (commit.changes) |change| {
            switch (change) {
                .add => {
                    const file = try repo.core.repo_dir.createFile(change.add.path, .{ .truncate = true });
                    defer file.close();
                    try file.writeAll(change.add.content);
                    try repo.add(&[_][]const u8{change.add.path});
                },
                .remove => {
                    try repo.core.repo_dir.deleteFile(change.remove.path);
                    try repo.add(&[_][]const u8{change.remove.path});
                },
            }
        }

        const oid_hex = try repo.commit(parent_oids.items, @tagName(commit.name));
        try name_to_oid.put(commit.name, oid_hex);
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

    const CommitName = enum { a, b, c };

    const commits =
        &[_]Commit(CommitName){
        .{
            .name = .a,
            .parents = &[_]CommitName{},
            .changes = &[_]Change{
                .{ .add = .{ .path = "README.md", .content = "Hello, world!" } },
            },
        },
        .{
            .name = .b,
            .parents = &[_]CommitName{.a},
            .changes = &[_]Change{
                .{ .add = .{ .path = "README.md", .content = "Goodbye, world!" } },
            },
        },
        .{
            .name = .c,
            .parents = &[_]CommitName{.b},
            .changes = &[_]Change{
                .{ .remove = .{ .path = "README.md" } },
            },
        },
    };

    try generateCommits(allocator, &repo, CommitName, commits);
}
