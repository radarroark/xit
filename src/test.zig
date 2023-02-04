const std = @import("std");
const main = @import("./main.zig");
const expect = std.testing.expect;
const hash = @import("./hash.zig");

fn readContents(dir: std.fs.Dir, path: []const u8, out: *[main.MAX_FILE_READ_SIZE]u8) !usize {
    var file_size: usize = 0;
    {
        const file = try dir.openFile(path, .{ .mode = .read_only });
        defer file.close();
        file_size = try file.pread(out, 0);
    }
    return file_size;
}

test "init and commit" {
    const temp_dir_name = "temp-test-init-and-commit";

    const allocator = std.testing.allocator;
    var args = std.ArrayList([]const u8).init(allocator);
    defer args.deinit();

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

    // make a commit
    args.clearAndFree();
    try args.append("commit");
    try main.zitMain(&args, allocator);

    {
        // get HEAD contents
        var head_file_buffer = [_]u8{0} ** main.MAX_FILE_READ_SIZE;
        const head_file_size = try readContents(git_dir, "HEAD", &head_file_buffer);
        try expect(head_file_size == hash.SHA1_HEX_LEN);
        const head_file_slice = head_file_buffer[0..head_file_size];

        // check that the commit object was created
        var objects_dir = try git_dir.openDir("objects", .{});
        defer objects_dir.close();
        var hash_prefix_dir = try objects_dir.openDir(head_file_slice[0..2], .{});
        defer hash_prefix_dir.close();
        var hash_suffix_file = try hash_prefix_dir.openFile(head_file_slice[2..], .{});
        defer hash_suffix_file.close();
    }

    // change the first file
    try hello_txt.pwriteAll("goodbye, world!", 0);

    // make another commit
    args.clearAndFree();
    try args.append("commit");
    try main.zitMain(&args, allocator);

    {
        // get HEAD contents
        var head_file_buffer = [_]u8{0} ** main.MAX_FILE_READ_SIZE;
        const head_file_size = try readContents(git_dir, "HEAD", &head_file_buffer);
        try expect(head_file_size == hash.SHA1_HEX_LEN);
        const head_file_slice = head_file_buffer[0..head_file_size];

        // check that the commit object was created
        var objects_dir = try git_dir.openDir("objects", .{});
        defer objects_dir.close();
        var hash_prefix_dir = try objects_dir.openDir(head_file_slice[0..2], .{});
        defer hash_prefix_dir.close();
        var hash_suffix_file = try hash_prefix_dir.openFile(head_file_slice[2..], .{});
        defer hash_suffix_file.close();
    }

    // reset the cwd
    try cwd.setAsCwd();
}
