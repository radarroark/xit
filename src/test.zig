const std = @import("std");
const main = @import("./main.zig");

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

    // change the first file
    try hello_txt.pwriteAll("goodbye, world!", 0);

    // make another commit
    args.clearAndFree();
    try args.append("commit");
    try main.zitMain(&args, allocator);

    // reset the cwd
    try cwd.setAsCwd();
}
