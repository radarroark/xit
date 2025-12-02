//! create a xit repo based on the contents of this project's
//! own repo, and then launch the TUI. this provides a nice
//! way to test things out safely.

const std = @import("std");
const xit = @import("xit");
const rp = xit.repo;
const obj = xit.object;

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
    var gpa: std.heap.DebugAllocator(.{}) = .init;
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

    const cwd_path = try std.process.getCwdAlloc(allocator);
    defer allocator.free(cwd_path);

    const temp_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name });
    defer allocator.free(temp_path);

    {
        var src_repo_dir = try cwd.openDir(".git", .{ .iterate = true });
        defer src_repo_dir.close();

        try temp_dir.makeDir(".git");

        var dest_repo_dir = try temp_dir.openDir(".git", .{});
        defer dest_repo_dir.close();

        try copyDir(src_repo_dir, dest_repo_dir);
    }

    var args = std.ArrayList([]const u8){};
    defer args.deinit(allocator);

    var patch_enabled = false;

    var arg_it = try std.process.argsWithAllocator(allocator);
    defer arg_it.deinit();
    _ = arg_it.skip();
    while (arg_it.next()) |arg| {
        if (std.mem.eql(u8, "--patch", arg)) {
            patch_enabled = true;
        } else {
            try args.append(allocator, arg);
        }
    }

    var stdout_writer = std.fs.File.stdout().writer(&.{});
    var stderr_writer = std.fs.File.stderr().writer(&.{});
    const writers = xit.main.Writers{ .out = &stdout_writer.interface, .err = &stderr_writer.interface };

    {
        var git_repo = try rp.Repo(.git, .{}).open(allocator, .{ .path = temp_path });
        defer git_repo.deinit(allocator);

        // restore all files in work dir
        // (they are all missing because we only copied the .git dir)
        var status = try git_repo.status(allocator);
        defer status.deinit(allocator);
        for (status.work_dir_deleted.keys()) |path| {
            if (std.mem.startsWith(u8, path, "deps/")) continue;
            try writers.out.print("Restoring: {s}\n", .{path});
            git_repo.restore(allocator, path) catch |err| switch (err) {
                error.FileNotFound, error.ObjectInvalid => try writers.err.print("Failed to restore: {s}\n", .{path}),
                else => |e| return e,
            };
        }

        var commits = std.ArrayList(obj.Object(.git, .{}, .full)){};
        defer {
            for (commits.items) |*commit| {
                commit.deinit();
            }
            commits.deinit(allocator);
        }

        var log_iter = try git_repo.log(allocator, null);
        defer log_iter.deinit();
        var commit_count: usize = 0;
        while (try log_iter.next()) |commit| {
            {
                errdefer commit.deinit();
                try commits.append(allocator, commit.*);
            }
            commit_count += 1;
            if (commit_count == COMMIT_COUNT) {
                break;
            }
        }

        var xit_repo = try rp.Repo(.xit, .{}).init(allocator, .{ .path = temp_path });
        defer xit_repo.deinit(allocator);

        for (0..commits.items.len) |i| {
            var commit_object = commits.items[commits.items.len - i - 1];
            try writers.out.print("Creating commit: {s}\n", .{commit_object.content.commit.metadata.message orelse ""});

            var switch_result = try git_repo.switchDir(allocator, .{ .target = .{ .oid = &commit_object.oid }, .force = true });
            defer switch_result.deinit();
            if (.success != switch_result.result) {
                return error.CheckoutFailed;
            }

            try xit_repo.add(allocator, &.{ "build.zig", "build.zig.zon", "src" });

            var metadata = commit_object.content.commit.metadata;
            metadata.parent_oids = null;
            metadata.allow_empty = true;
            _ = try xit_repo.commit(allocator, metadata);
        }

        if (patch_enabled) {
            try writers.out.print("Generating patches\n", .{});
            try xit_repo.patchAll(allocator, null);
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

    try xit.main.run(.xit, .{}, allocator, args.items, temp_path, writers);
}
