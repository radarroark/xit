const std = @import("std");
const builtin = @import("builtin");
const rp = @import("repo.zig");

const c = @cImport({
    @cInclude("git2.h");
});

const Protocol = enum {
    git,
    http,
};

fn testPull(comptime repo_kind: rp.RepoKind, comptime protocol: Protocol, allocator: std.mem.Allocator) !void {
    const temp_dir_name = "temp-testnet-pull";

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

    // add cgi script if necessary
    if (protocol == .http) {
        var cgi_bin_dir = try temp_dir.makeOpenPath("cgi-bin", .{});
        defer cgi_bin_dir.close();

        const cgi_file = try cgi_bin_dir.createFile("git-http-backend", .{});
        defer cgi_file.close();
        try cgi_file.writeAll(
            \\#!/bin/sh
            \\git http-backend
        );

        // make the script executable
        if (builtin.os.tag != .windows) {
            try cgi_file.setPermissions(.{ .inner = .{ .mode = 0o755 } });
        }
    }

    // init server process
    var process = std.process.Child.init(
        switch (protocol) {
            .git => &.{ "git", "daemon", "--reuseaddr", "--base-path=.", "--export-all", "--enable=receive-pack", "--port=3000" },
            .http => &.{ "python3", "-m", "http.server", "--cgi", "3000" },
        },
        allocator,
    );
    process.cwd = temp_dir_name;

    // start server
    try process.spawn();
    defer _ = process.kill() catch {};
    std.time.sleep(std.time.ns_per_s * 0.5);

    // start libgit
    _ = c.git_libgit2_init();
    defer _ = c.git_libgit2_shutdown();

    const writers = .{ .out = std.io.null_writer, .err = std.io.null_writer };

    // init server repo
    var server_repo = try rp.Repo(.git).initWithCommand(allocator, .{ .cwd = temp_dir }, .{ .init = .{ .dir = "server" } }, writers);
    defer server_repo.deinit();

    // make a commit
    {
        const hello_txt = try server_repo.core.repo_dir.createFile("hello.txt", .{ .truncate = true });
        defer hello_txt.close();
        try hello_txt.writeAll("hello, world!");
        try server_repo.add(allocator, &.{"server/hello.txt"});
        _ = try server_repo.commit(allocator, .{ .message = "let there be light" });
    }

    // export server repo
    {
        const export_file = try server_repo.core.git_dir.createFile("git-daemon-export-ok", .{});
        defer export_file.close();
    }

    // create the client dir
    var client_dir = try temp_dir.makeOpenPath("client", .{});
    defer client_dir.close();

    // init client repo
    var client_repo = try rp.Repo(repo_kind).initWithCommand(allocator, .{ .cwd = temp_dir }, .{ .init = .{ .dir = "client" } }, writers);
    defer client_repo.deinit();

    // add remote
    const remote_url = switch (protocol) {
        .git => "git://localhost:3000/server",
        .http => "http://localhost:3000/cgi-bin/git-http-backend/server",
    };
    try client_repo.addRemote(allocator, .{ .name = "origin", .value = remote_url });

    // get repo path for libgit
    var repo_path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
    const repo_path: [*c]const u8 = @ptrCast(try client_dir.realpath(".", &repo_path_buffer));

    // init client repo
    var repo: ?*c.git_repository = null;
    try std.testing.expectEqual(0, c.git_repository_open(&repo, repo_path));
    defer c.git_repository_free(repo);

    var refspec_strs = [_][*c]const u8{
        @ptrCast("+refs/heads/master:refs/heads/master"),
    };
    var refspecs: c.git_strarray = undefined;
    refspecs.strings = @ptrCast(&refspec_strs);
    refspecs.count = refspec_strs.len;

    var remote: ?*c.git_remote = null;
    try std.testing.expectEqual(0, c.git_remote_lookup(&remote, repo, "origin"));
    defer c.git_remote_free(remote);

    var callbacks: c.git_remote_callbacks = undefined;
    try std.testing.expectEqual(0, c.git_remote_init_callbacks(&callbacks, c.GIT_REMOTE_CALLBACKS_VERSION));

    var options: c.git_fetch_options = undefined;
    try std.testing.expectEqual(0, c.git_fetch_options_init(&options, c.GIT_FETCH_OPTIONS_VERSION));
    options.callbacks = callbacks;

    std.testing.expectEqual(0, c.git_remote_fetch(remote, &refspecs, &options, null)) catch |err| {
        const last_err = c.giterr_last();
        std.debug.print("{s}\n", .{last_err.*.message});
        return err;
    };

    // update the working dir
    var head_ref: ?*c.git_reference = null;
    try std.testing.expectEqual(0, c.git_repository_head(&head_ref, repo));
    defer c.git_reference_free(head_ref);
    var head_obj: ?*c.git_object = null;
    try std.testing.expectEqual(0, c.git_reference_peel(&head_obj, head_ref, c.GIT_OBJECT_COMMIT));
    defer c.git_object_free(head_obj);
    try std.testing.expectEqual(0, c.git_reset(repo, head_obj, c.GIT_RESET_HARD, null));

    // make sure pull was successful
    const hello_txt = try temp_dir.openFile("client/hello.txt", .{});
    defer hello_txt.close();
}

test "pull" {
    const allocator = std.testing.allocator;
    try testPull(.git, .git, allocator);
    try testPull(.git, .http, allocator);
}

fn testPush(comptime repo_kind: rp.RepoKind, comptime protocol: Protocol, allocator: std.mem.Allocator) !void {
    const temp_dir_name = "temp-testnet-push";

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

    // add cgi script if necessary
    if (protocol == .http) {
        var cgi_bin_dir = try temp_dir.makeOpenPath("cgi-bin", .{});
        defer cgi_bin_dir.close();

        const cgi_file = try cgi_bin_dir.createFile("git-http-backend", .{});
        defer cgi_file.close();
        try cgi_file.writeAll(
            \\#!/bin/sh
            \\git http-backend
        );

        // make the script executable
        if (builtin.os.tag != .windows) {
            try cgi_file.setPermissions(.{ .inner = .{ .mode = 0o755 } });
        }
    }

    // init server process
    var process = std.process.Child.init(
        switch (protocol) {
            .git => &.{ "git", "daemon", "--reuseaddr", "--base-path=.", "--export-all", "--enable=receive-pack", "--port=3001" },
            .http => &.{ "python3", "-m", "http.server", "--cgi", "3001" },
        },
        allocator,
    );
    process.cwd = temp_dir_name;

    // start server
    try process.spawn();
    defer _ = process.kill() catch {};
    std.time.sleep(std.time.ns_per_s * 0.5);

    // start libgit
    _ = c.git_libgit2_init();
    defer _ = c.git_libgit2_shutdown();

    const writers = .{ .out = std.io.null_writer, .err = std.io.null_writer };

    // init server repo
    var server_repo = try rp.Repo(.git).initWithCommand(allocator, .{ .cwd = temp_dir }, .{ .init = .{ .dir = "server" } }, writers);
    defer server_repo.deinit();
    try server_repo.addConfig(allocator, .{ .name = "core.bare", .value = "false" });
    try server_repo.addConfig(allocator, .{ .name = "receive.denycurrentbranch", .value = "updateinstead" });
    try server_repo.addConfig(allocator, .{ .name = "http.receivepack", .value = "true" });

    // export server repo
    {
        const export_file = try server_repo.core.git_dir.createFile("git-daemon-export-ok", .{});
        defer export_file.close();
    }

    // create the client dir
    var client_dir = try temp_dir.makeOpenPath("client", .{});
    defer client_dir.close();

    // init client repo
    var client_repo = try rp.Repo(repo_kind).initWithCommand(allocator, .{ .cwd = temp_dir }, .{ .init = .{ .dir = "client" } }, writers);
    defer client_repo.deinit();

    // make a commit
    {
        const hello_txt = try client_repo.core.repo_dir.createFile("hello.txt", .{ .truncate = true });
        defer hello_txt.close();
        try hello_txt.writeAll("hello, world!");
        try client_repo.add(allocator, &.{"client/hello.txt"});
        _ = try client_repo.commit(allocator, .{ .message = "let there be light" });
    }

    // add remote
    const remote_url = switch (protocol) {
        .git => "git://localhost:3001/server",
        .http => "http://localhost:3001/cgi-bin/git-http-backend/server",
    };
    try client_repo.addRemote(allocator, .{ .name = "origin", .value = remote_url });

    // get repo path for libgit
    var repo_path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
    const repo_path: [*c]const u8 = @ptrCast(try client_dir.realpath(".", &repo_path_buffer));

    // init client repo
    var repo: ?*c.git_repository = null;
    try std.testing.expectEqual(0, c.git_repository_open(&repo, repo_path));
    defer c.git_repository_free(repo);

    var refspec_strs = [_][*c]const u8{
        @ptrCast("+refs/heads/master:refs/heads/master"),
    };
    var refspecs: c.git_strarray = undefined;
    refspecs.strings = @ptrCast(&refspec_strs);
    refspecs.count = refspec_strs.len;

    var remote: ?*c.git_remote = null;
    try std.testing.expectEqual(0, c.git_remote_lookup(&remote, repo, "origin"));
    defer c.git_remote_free(remote);

    var callbacks: c.git_remote_callbacks = undefined;
    try std.testing.expectEqual(0, c.git_remote_init_callbacks(&callbacks, c.GIT_REMOTE_CALLBACKS_VERSION));

    var options: c.git_push_options = undefined;
    try std.testing.expectEqual(0, c.git_push_options_init(&options, c.GIT_PUSH_OPTIONS_VERSION));
    options.callbacks = callbacks;

    std.testing.expectEqual(0, c.git_remote_push(remote, &refspecs, &options)) catch |err| {
        const last_err = c.giterr_last();
        std.debug.print("{s}\n", .{last_err.*.message});
        return err;
    };

    // make sure push was successful
    const hello_txt = try temp_dir.openFile("server/hello.txt", .{});
    defer hello_txt.close();
}

test "push" {
    const allocator = std.testing.allocator;
    try testPush(.git, .git, allocator);
    //try testPush(.git, .http, allocator);
}
