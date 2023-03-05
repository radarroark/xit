const std = @import("std");
const main = @import("./main.zig");
const hash = @import("./hash.zig");
const idx = @import("./index.zig");

const c = @cImport({
    @cInclude("git2.h");
});

const MAX_FILE_READ_SIZE: comptime_int = 1000; // FIXME: this is arbitrary...

fn readContents(dir: std.fs.Dir, path: []const u8, out: *[MAX_FILE_READ_SIZE]u8) !usize {
    var file_size: usize = 0;
    {
        const file = try dir.openFile(path, .{ .mode = .read_only });
        defer file.close();
        file_size = try file.pread(out, 0);
    }
    return file_size;
}

pub fn expectEqual(expected: anytype, actual: anytype) !void {
    try std.testing.expectEqual(@as(@TypeOf(actual), expected), actual);
}

test "init and commit" {
    const temp_dir_name = "temp-test-init-and-commit";

    const allocator = std.testing.allocator;
    var args = std.ArrayList([]const u8).init(allocator);
    defer args.deinit();

    // start libgit
    _ = c.git_libgit2_init();
    defer _ = c.git_libgit2_shutdown();

    // get the current working directory path.
    // we can't just call std.fs.cwd() all the time because we're
    // gonna change it later. and since defers run at the end,
    // if you call std.fs.cwd() in them you're gonna have a bad time.
    var cwd_path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
    const cwd_path = try std.fs.cwd().realpath(".", &cwd_path_buffer);
    var cwd = try std.fs.openDirAbsolute(cwd_path, .{});
    defer cwd.close();

    // create the temp dir
    var temp_dir = try cwd.makeOpenPath(temp_dir_name, .{});
    defer cwd.deleteTree(temp_dir_name) catch {};
    defer temp_dir.close();

    // init repo
    args.clearAndFree();
    try args.append("init");
    try args.append(temp_dir_name ++ "/repo");
    try main.zitMain(&args, allocator);

    // make sure the dirs were created
    var repo_dir = try temp_dir.openDir("repo", .{});
    defer repo_dir.close();
    var git_dir = try repo_dir.openDir(".git", .{});
    defer git_dir.close();

    // change the cwd
    try repo_dir.setAsCwd();

    // make file
    var hello_txt = try repo_dir.createFile("hello.txt", .{});
    defer hello_txt.close();
    try hello_txt.pwriteAll("hello, world!", 0);

    // make another file
    var readme = try repo_dir.createFile("README", .{});
    defer readme.close();
    try readme.pwriteAll("My cool project", 0);

    // add the files
    args.clearAndFree();
    try args.append("add");
    try args.append(".");
    try main.zitMain(&args, allocator);

    // make a commit
    args.clearAndFree();
    try args.append("commit");
    try args.append("-m");
    try args.append("first commit");
    try main.zitMain(&args, allocator);

    {
        // get HEAD contents
        var head_file_buffer = [_]u8{0} ** MAX_FILE_READ_SIZE;
        const head_file_size = try readContents(git_dir, "HEAD", &head_file_buffer);
        try expectEqual(hash.SHA1_HEX_LEN, head_file_size);
        const head_file_slice = head_file_buffer[0..head_file_size];

        // check that the commit object was created
        var objects_dir = try git_dir.openDir("objects", .{});
        defer objects_dir.close();
        var hash_prefix_dir = try objects_dir.openDir(head_file_slice[0..2], .{});
        defer hash_prefix_dir.close();
        var hash_suffix_file = try hash_prefix_dir.openFile(head_file_slice[2..], .{});
        defer hash_suffix_file.close();
    }

    // open repo with libgit
    var repo_path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
    const repo_path = try repo_dir.realpath(".", &repo_path_buffer);
    var repo: ?*c.git_repository = null;
    try expectEqual(0, c.git_repository_open(&repo, @ptrCast([*c]const u8, repo_path)));
    defer c.git_repository_free(repo);

    // can't commit again because nothing has changed
    args.clearAndFree();
    try args.append("commit");
    try args.append("-m");
    try args.append("pointless commit");
    try expectEqual(error.ObjectAlreadyExists, main.zitMain(&args, allocator));

    // change the first file
    try hello_txt.pwriteAll("goodbye, world!", 0);

    // make a few dirs
    var src_dir = try repo_dir.makeOpenPath("src", .{});
    defer src_dir.close();
    var src_zig_dir = try src_dir.makeOpenPath("zig", .{});
    defer src_zig_dir.close();

    // make a file in the dir
    var main_zig = try src_zig_dir.createFile("main.zig", .{});
    defer main_zig.close();
    try main_zig.pwriteAll("pub fn main() !void {}", 0);

    // add the files
    args.clearAndFree();
    try args.append("add");
    try args.append(".");
    try main.zitMain(&args, allocator);

    // make another commit
    args.clearAndFree();
    try args.append("commit");
    try args.append("-m");
    try args.append("second commit");
    try main.zitMain(&args, allocator);

    {
        // get HEAD contents
        var head_file_buffer = [_]u8{0} ** MAX_FILE_READ_SIZE;
        const head_file_size = try readContents(git_dir, "HEAD", &head_file_buffer);
        try expectEqual(hash.SHA1_HEX_LEN, head_file_size);
        const head_file_slice = head_file_buffer[0..head_file_size];

        // check that the commit object was created
        var objects_dir = try git_dir.openDir("objects", .{});
        defer objects_dir.close();
        var hash_prefix_dir = try objects_dir.openDir(head_file_slice[0..2], .{});
        defer hash_prefix_dir.close();
        var hash_suffix_file = try hash_prefix_dir.openFile(head_file_slice[2..], .{});
        defer hash_suffix_file.close();
    }

    // replace file with directory
    try repo_dir.deleteFile("hello.txt");
    var hello_txt_dir = try repo_dir.makeOpenPath("hello.txt", .{});
    defer hello_txt_dir.close();
    var nested_txt = try hello_txt_dir.createFile("nested.txt", .{});
    defer nested_txt.close();
    var nested2_txt = try hello_txt_dir.createFile("nested2.txt", .{});
    defer nested2_txt.close();

    // add the new file
    args.clearAndFree();
    try args.append("add");
    try args.append(".");
    try main.zitMain(&args, allocator);

    // read index
    {
        var index = try idx.readIndex(git_dir, allocator);
        defer index.deinit();
        try expectEqual(4, index.entries.count());
        try std.testing.expect(index.entries.contains("README"));
        try std.testing.expect(index.entries.contains("src/zig/main.zig"));
        try std.testing.expect(index.entries.contains("hello.txt/nested.txt"));
        try std.testing.expect(index.entries.contains("hello.txt/nested2.txt"));
    }

    // replace directory with file
    try hello_txt_dir.deleteFile("nested.txt");
    try hello_txt_dir.deleteFile("nested2.txt");
    try repo_dir.deleteDir("hello.txt");
    var hello_txt2 = try repo_dir.createFile("hello.txt", .{});
    defer hello_txt2.close();

    // add the new file
    args.clearAndFree();
    try args.append("add");
    try args.append(".");
    try main.zitMain(&args, allocator);

    // read index
    {
        var index = try idx.readIndex(git_dir, allocator);
        defer index.deinit();
        try expectEqual(3, index.entries.count());
        try std.testing.expect(index.entries.contains("README"));
        try std.testing.expect(index.entries.contains("src/zig/main.zig"));
        try std.testing.expect(index.entries.contains("hello.txt"));
    }

    // can't add a non-existent file
    args.clearAndFree();
    try args.append("add");
    try args.append("no-such-file");
    try expectEqual(error.FileNotFound, main.zitMain(&args, allocator));

    // a stale index lock file isn't hanging around
    {
        const lock_file_or_err = git_dir.openFile("index.lock", .{ .mode = .read_only });
        try expectEqual(error.FileNotFound, lock_file_or_err);
    }

    // reset the cwd
    try cwd.setAsCwd();
}
