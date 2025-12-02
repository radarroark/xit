const std = @import("std");
const builtin = @import("builtin");
const xit = @import("xit");
const rp = xit.repo;

test "sign commit and tag" {
    const allocator = std.testing.allocator;
    if (.windows != builtin.os.tag) {
        try testSign(.git, .{ .is_test = true }, allocator);
    }
}

fn testSign(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    allocator: std.mem.Allocator,
) !void {
    const temp_dir_name = "temp-testnet-sign";

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

    const work_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name });
    defer allocator.free(work_path);

    var repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .path = work_path });
    defer repo.deinit();

    // create priv key
    const priv_key_file = try temp_dir.createFile("key", .{});
    defer priv_key_file.close();
    try priv_key_file.writeAll(
        \\-----BEGIN OPENSSH PRIVATE KEY-----
        \\b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        \\QyNTUxOQAAACCniLPJiaooAWecvOCeAjoJwCSeWxzysvpTNkpYjF22JgAAAJA+7hikPu4Y
        \\pAAAAAtzc2gtZWQyNTUxOQAAACCniLPJiaooAWecvOCeAjoJwCSeWxzysvpTNkpYjF22Jg
        \\AAAEDVlopOMnKt/7by/IA8VZvQXUS/O6VLkixOqnnahUdPCKeIs8mJqigBZ5y84J4COgnA
        \\JJ5bHPKy+lM2SliMXbYmAAAAC3JhZGFyQHJvYXJrAQI=
        \\-----END OPENSSH PRIVATE KEY-----
        \\
    );
    if (.windows != builtin.os.tag) {
        try priv_key_file.setPermissions(.{ .inner = .{ .mode = 0o600 } });
    }

    // create pub key
    const pub_key_path = try std.fs.path.join(allocator, &.{ cwd_path, temp_dir_name, "key.pub" });
    defer allocator.free(pub_key_path);
    const pub_key_file = try cwd.createFile(pub_key_path, .{});
    defer pub_key_file.close();
    try pub_key_file.writeAll(
        \\ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKeIs8mJqigBZ5y84J4COgnAJJ5bHPKy+lM2SliMXbYm radar@roark
        \\
    );
    if (.windows != builtin.os.tag) {
        try pub_key_file.setPermissions(.{ .inner = .{ .mode = 0o600 } });
    }

    // add key to config
    try repo.addConfig(allocator, .{ .name = "user.signingkey", .value = pub_key_path });

    // make a commit
    const hello_txt = try repo.core.work_dir.createFile("hello.txt", .{ .truncate = true });
    defer hello_txt.close();
    try hello_txt.writeAll("hello, world!");
    try repo.add(allocator, &.{"hello.txt"});
    const commit_oid = try repo.commit(allocator, .{ .message = "let there be light" });

    // add a tag
    const tag_oid = try repo.addTag(allocator, .{ .name = "1.0.0", .message = "hi" });

    // TODO: verify the objects contain signatures
    _ = commit_oid;
    _ = tag_oid;
}
