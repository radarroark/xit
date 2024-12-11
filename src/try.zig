//! create a xit repo based on the contents of this project's
//! own repo, and then launch the TUI. this provides a nice
//! way to test things out safely.

const std = @import("std");
const mn = @import("./main.zig");
const rp = @import("./repo.zig");
const obj = @import("./object.zig");

const COMMIT_COUNT = 5;

fn copyDir(src_dir: std.fs.Dir, dest_dir: std.fs.Dir) !void {
    var iter = src_dir.iterate();
    while (try iter.next()) |entry| {
        switch (entry.kind) {
            .file => try src_dir.copyFile(entry.name, dest_dir, entry.name, .{}),
            .directory => {
                try dest_dir.makeDir(entry.name);
                var dest_entry_dir = try dest_dir.openDir(entry.name, .{ .access_sub_paths = true, .iterate = true, .no_follow = true });
                defer dest_entry_dir.close();
                var src_entry_dir = try src_dir.openDir(entry.name, .{ .access_sub_paths = true, .iterate = true, .no_follow = true });
                defer src_entry_dir.close();
                try copyDir(src_entry_dir, dest_entry_dir);
            },
            else => {},
        }
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const temp_dir_name = "temp-try";

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
        var src_git_dir = try cwd.openDir(".git", .{ .iterate = true });
        defer src_git_dir.close();

        try temp_dir.makeDir(".git");

        var dest_git_dir = try temp_dir.openDir(".git", .{});
        defer dest_git_dir.close();

        try copyDir(src_git_dir, dest_git_dir);
    }

    const writers = .{ .out = std.io.getStdOut().writer(), .err = std.io.getStdErr().writer() };

    {
        var git_repo = try rp.Repo(.git).init(allocator, .{ .cwd = temp_dir });
        defer git_repo.deinit();

        // restore all files in working tree
        // (they are all missing because we only copied the .git dir)
        var status = try git_repo.status(allocator);
        defer status.deinit();
        for (status.workspace_deleted.keys()) |path| {
            if (std.mem.startsWith(u8, path, "deps/")) continue;
            try writers.out.print("Restoring: {s}\n", .{path});
            git_repo.restore(allocator, path) catch |err| switch (err) {
                error.FileNotFound, error.ObjectInvalid => try writers.err.print("Failed to restore: {s}\n", .{path}),
                else => |e| return e,
            };
        }

        var commits = std.ArrayList(obj.Object(.git, .full)).init(allocator);
        defer {
            for (commits.items) |*commit| {
                commit.deinit();
            }
            commits.deinit();
        }

        var log_iter = try git_repo.log(allocator, null);
        defer log_iter.deinit();
        var commit_count: usize = 0;
        while (try log_iter.next()) |commit| {
            {
                errdefer commit.deinit();
                try commits.append(commit.*);
            }
            commit_count += 1;
            if (commit_count == COMMIT_COUNT) {
                break;
            }
        }

        var xit_repo = try rp.Repo(.xit).initWithCommand(allocator, .{ .cwd = temp_dir }, .{ .init = .{ .dir = "." } }, writers);
        defer xit_repo.deinit();

        for (0..commits.items.len) |i| {
            const commit_object = commits.items[commits.items.len - i - 1];
            try writers.out.print("Creating commit: {s}", .{commit_object.content.commit.metadata.message});

            var switch_result = try git_repo.switchHead(allocator, &commit_object.oid, .{ .force = true });
            defer switch_result.deinit();
            if (switch_result.data != .success) {
                return error.CheckoutFailed;
            }

            try xit_repo.add(allocator, &.{ "build.zig", "build.zig.zon", "src" });

            var metadata = commit_object.content.commit.metadata;
            metadata.allow_empty = true;
            _ = try xit_repo.commit(allocator, metadata);
        }

        // make changes so we see things in the status UI
        {
            var build_zig = try temp_dir.openFile("build.zig", .{ .mode = .read_write });
            defer build_zig.close();
            try build_zig.seekFromEnd(0);
            try build_zig.writeAll("\n// ...just felt like adding a new line!");
            try xit_repo.add(allocator, &.{"build.zig"});
            try build_zig.writeAll("\n// ...and here's another one!");
        }
        try temp_dir.deleteFile("build.zig.zon");

        // set some config values
        try xit_repo.addConfig(allocator, .{ .name = "core.editor", .value = "vim" });
        try xit_repo.addConfig(allocator, .{ .name = "branch.master.remote", .value = "origin" });
    }

    var args = std.ArrayList([]const u8).init(allocator);
    defer args.deinit();

    var arg_it = try std.process.argsWithAllocator(allocator);
    defer arg_it.deinit();
    _ = arg_it.skip();
    while (arg_it.next()) |arg| {
        try args.append(arg);
    }

    try mn.xitMain(.xit, allocator, args.items, temp_dir, writers);
}
