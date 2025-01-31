const std = @import("std");
const hash = @import("../hash.zig");
const rp = @import("../repo.zig");
const obj = @import("../object.zig");
const pack = @import("../pack.zig");
const rf = @import("../ref.zig");

const c = @cImport({
    @cInclude("git2.h");
});

test "pack" {
    const allocator = std.testing.allocator;
    const temp_dir_name = "temp-test-pack";
    const repo_opts = rp.RepoOpts(.git){ .is_test = true };

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

    // create the repo dir
    var repo_dir = try temp_dir.makeOpenPath("repo", .{});
    defer repo_dir.close();

    // get repo path for libgit
    var repo_path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
    const repo_path: [*c]const u8 = @ptrCast(try repo_dir.realpath(".", &repo_path_buffer));

    // init repo
    var repo: ?*c.git_repository = null;
    try std.testing.expectEqual(0, c.git_repository_init(&repo, repo_path, 0));
    defer c.git_repository_free(repo);

    // make sure the git dir was created
    var git_dir = try repo_dir.openDir(".git", .{});
    defer git_dir.close();

    // add and commit
    var commit_oid1: c.git_oid = undefined;
    {
        // make file
        var hello_txt = try repo_dir.createFile("hello.txt", .{});
        defer hello_txt.close();
        try hello_txt.writeAll("hello, world!");

        // make file
        var readme = try repo_dir.createFile("README", .{});
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
        try std.testing.expectEqual(0, c.git_signature_new(&signature, "radarroark", "radarroark@radar.roark", 0, 0));
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

    // add and commit
    var commit_oid2: c.git_oid = undefined;
    {
        // make files
        var license = try repo_dir.createFile("LICENSE", .{});
        defer license.close();
        try license.writeAll("do whatever you want");
        var change_log = try repo_dir.createFile("CHANGELOG", .{});
        defer change_log.close();
        try change_log.writeAll("cha-cha-cha-changes");

        // change file
        const hello_txt = try repo_dir.openFile("hello.txt", .{ .mode = .read_write });
        defer hello_txt.close();
        try hello_txt.writeAll("goodbye, world!");
        try hello_txt.setEndPos(try hello_txt.getPos());

        // add the files
        var index: ?*c.git_index = null;
        try std.testing.expectEqual(0, c.git_repository_index(&index, repo));
        defer c.git_index_free(index);
        try std.testing.expectEqual(0, c.git_index_add_bypath(index, "LICENSE"));
        try std.testing.expectEqual(0, c.git_index_add_bypath(index, "CHANGELOG"));
        try std.testing.expectEqual(0, c.git_index_add_bypath(index, "hello.txt"));
        try std.testing.expectEqual(0, c.git_index_write(index));

        // get previous commit
        var parent_object: ?*c.git_object = null;
        var parent_ref: ?*c.git_reference = null;
        try std.testing.expectEqual(0, c.git_revparse_ext(&parent_object, &parent_ref, repo, "HEAD"));
        defer c.git_object_free(parent_object);
        defer c.git_reference_free(parent_ref);
        var parent_commit: ?*c.git_commit = null;
        try std.testing.expectEqual(0, c.git_commit_lookup(&parent_commit, repo, c.git_object_id(parent_object)));
        defer c.git_commit_free(parent_commit);
        var parents = [_]?*c.git_commit{parent_commit};

        // make the commit
        var tree_oid: c.git_oid = undefined;
        try std.testing.expectEqual(0, c.git_index_write_tree(&tree_oid, index));
        var tree: ?*c.git_tree = null;
        try std.testing.expectEqual(0, c.git_tree_lookup(&tree, repo, &tree_oid));
        defer c.git_tree_free(tree);
        var signature: ?*c.git_signature = null;
        try std.testing.expectEqual(0, c.git_signature_new(&signature, "radarroark", "radarroark@radar.roark", 0, 0));
        defer c.git_signature_free(signature);
        try std.testing.expectEqual(0, c.git_commit_create(
            &commit_oid2,
            repo,
            "HEAD",
            signature,
            signature,
            null,
            "add license",
            tree,
            1,
            &parents,
        ));
    }

    // create pack file
    {
        var pb: ?*c.git_packbuilder = null;
        try std.testing.expectEqual(0, c.git_packbuilder_new(&pb, repo));
        defer c.git_packbuilder_free(pb);
        try std.testing.expectEqual(0, c.git_packbuilder_insert_commit(pb, &commit_oid1));
        try std.testing.expectEqual(0, c.git_packbuilder_insert_commit(pb, &commit_oid2));
        try std.testing.expectEqual(0, c.git_packbuilder_write(pb, null, 0, null, null));
    }

    // check that pack file exists
    {
        var pack_dir = try repo_dir.openDir(".git/objects/pack", .{ .iterate = true });
        defer pack_dir.close();
        var entries = std.ArrayList([]const u8).init(allocator);
        defer entries.deinit();
        var iter = pack_dir.iterate();
        while (try iter.next()) |entry| {
            switch (entry.kind) {
                .file => try entries.append(entry.name),
                else => {},
            }
        }
        try std.testing.expectEqual(2, entries.items.len);
    }

    // delete the loose objects
    for (&[_]*c.git_oid{ &commit_oid1, &commit_oid2 }) |commit_oid| {
        var commit_oid_hex = [_]u8{0} ** hash.hexLen(repo_opts.hash);
        try std.testing.expectEqual(0, c.git_oid_fmt(@ptrCast(&commit_oid_hex), commit_oid));

        var path_buf = [_]u8{0} ** (hash.hexLen(repo_opts.hash) + 1);
        const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ commit_oid_hex[0..2], commit_oid_hex[2..] });

        var objects_dir = try repo_dir.openDir(".git/objects", .{});
        defer objects_dir.close();

        try objects_dir.deleteFile(path);
    }

    // read the pack objects
    for (
        &[_]*c.git_oid{ &commit_oid1, &commit_oid2 },
        &[_][]const u8{ "let there be light", "add license" },
    ) |commit_oid, message| {
        var commit_oid_hex = [_]u8{0} ** hash.hexLen(repo_opts.hash);
        try std.testing.expectEqual(0, c.git_oid_fmt(@ptrCast(&commit_oid_hex), commit_oid));

        var r = try rp.Repo(.git, repo_opts).open(allocator, .{ .cwd = repo_dir });
        defer r.deinit();

        var object = try obj.Object(.git, repo_opts, .full).init(allocator, .{ .core = &r.core, .extra = .{} }, &commit_oid_hex);
        defer object.deinit();
        try std.testing.expectEqualStrings(message, object.content.commit.metadata.message);
    }

    // write and read a pack object
    {
        var r = try rp.Repo(.git, repo_opts).open(allocator, .{ .cwd = repo_dir });
        defer r.deinit();

        const head_oid = try rf.readHead(.git, repo_opts, .{ .core = &r.core, .extra = .{} });

        var obj_iter = try obj.ObjectIterator(.git, repo_opts, .raw).init(allocator, .{ .core = &r.core, .extra = .{} }, &.{head_oid}, .{ .recursive = true });
        defer obj_iter.deinit();

        var pack_writer = try pack.PackObjectWriter(.git, repo_opts).init(allocator, &obj_iter);
        defer pack_writer.deinit();

        var pack_file = try temp_dir.createFile("test.pack", .{});
        defer pack_file.close();

        var buffer = [_]u8{0} ** 1;
        while (true) {
            const size = try pack_writer.read(&buffer);
            try pack_file.writeAll(buffer[0..size]);
            if (size < buffer.len) {
                break;
            }
        }

        const pack_file_path = try temp_dir.realpathAlloc(allocator, "test.pack");
        defer allocator.free(pack_file_path);

        for (&[_]*c.git_oid{ &commit_oid1, &commit_oid2 }) |commit_oid| {
            var commit_oid_hex = [_]u8{0} ** hash.hexLen(repo_opts.hash);
            try std.testing.expectEqual(0, c.git_oid_fmt(@ptrCast(&commit_oid_hex), commit_oid));

            var pack_reader = try pack.PackObjectReader(.git, repo_opts).initWithPath(allocator, pack_file_path, &commit_oid_hex);
            defer pack_reader.deinit();

            // make sure the reader's position is at the beginning
            try std.testing.expectEqual(0, pack_reader.relative_position);
        }
    }
}
