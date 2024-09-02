const std = @import("std");
const rp = @import("repo.zig");

const c = @cImport({
    @cInclude("git2.h");
});

test "push" {
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-testnet";

    // start libgit
    _ = c.git_libgit2_init();
    defer _ = c.git_libgit2_shutdown();

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

    // init server process
    var process = std.process.Child.init(
        &.{ "git", "daemon", "--reuseaddr", "--base-path=.", "--export-all", "--enable=receive-pack" },
        allocator,
    );
    process.cwd = temp_dir_name;
    defer _ = process.kill() catch {};

    // init server repo
    {
        const writers = .{ .out = std.io.null_writer, .err = std.io.null_writer };

        var repo = try rp.Repo(.git).initWithCommand(allocator, .{ .cwd = temp_dir }, .{ .init = .{ .dir = "server" } }, writers);
        defer repo.deinit();

        try repo.addConfig(.{ .name = "core.bare", .value = "false" });
        try repo.addConfig(.{ .name = "receive.denycurrentbranch", .value = "updateinstead" });
    }

    // start server
    try process.spawn();
    std.time.sleep(1000000);

    // create the client dir
    var client_dir = try temp_dir.makeOpenPath("client", .{});
    defer client_dir.close();

    // get repo path for libgit
    var repo_path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
    const repo_path: [*c]const u8 = @ptrCast(try client_dir.realpath(".", &repo_path_buffer));

    // init client repo
    var repo: ?*c.git_repository = null;
    try std.testing.expectEqual(0, c.git_repository_init(&repo, repo_path, 0));
    defer c.git_repository_free(repo);

    // make sure the git dir was created
    var git_dir = try client_dir.openDir(".git", .{});
    defer git_dir.close();

    // add and commit
    var commit_oid1: c.git_oid = undefined;
    {
        // make file
        var hello_txt = try client_dir.createFile("hello.txt", .{});
        defer hello_txt.close();
        try hello_txt.writeAll("hello, world!");

        // make file
        var readme = try client_dir.createFile("README", .{});
        defer readme.close();
        try readme.writeAll("My cool project");

        // add the files
        var index: ?*c.git_index = null;
        try std.testing.expectEqual(0, c.git_repository_index(&index, repo));
        defer c.git_index_free(index);
        try std.testing.expectEqual(0, c.git_index_add_bypath(index, "hello.txt"));
        try std.testing.expectEqual(0, c.git_index_add_bypath(index, "README"));
        try std.testing.expectEqual(0, c.git_index_write(index));

        // make the commit
        var tree_oid: c.git_oid = undefined;
        try std.testing.expectEqual(0, c.git_index_write_tree(&tree_oid, index));
        var tree: ?*c.git_tree = null;
        try std.testing.expectEqual(0, c.git_tree_lookup(&tree, repo, &tree_oid));
        defer c.git_tree_free(tree);
        var signature: ?*c.git_signature = null;
        try std.testing.expectEqual(0, c.git_signature_default(&signature, repo));
        defer c.git_signature_free(signature);
        try std.testing.expectEqual(0, c.git_commit_create(
            &commit_oid1,
            repo,
            "HEAD",
            signature,
            signature,
            null,
            "let there be light",
            tree,
            0,
            null,
        ));
    }

    {
        var remote: ?*c.git_remote = null;
        try std.testing.expectEqual(0, c.git_remote_create(&remote, repo, "origin", "git://localhost:9418/server"));
        defer c.git_remote_free(remote);
    }

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
}
