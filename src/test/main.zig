fn testMain(comptime repo_kind: rp.RepoKind) ![hash.SHA1_HEX_LEN]u8 {
    const allocator = std.testing.allocator;
            xit_dir: std.fs.Dir,
            db_file: std.fs.File,
        .xit => blk: {
            const xit_dir = try repo_dir.openDir(".xit", .{});
            break :blk .{
                .xit_dir = xit_dir,
                .db_file = try xit_dir.openFile("db", .{ .mode = .read_write }),
            };
        .xit => {
            state.db_file.close();
            state.xit_dir.close();
        },
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
                    var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
                var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
            var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
            var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
                    var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
                var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
                var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
                var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
                var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
                var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
            var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
                var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
            var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
                var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
            var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
            var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
            var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
            var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
        var repo = try rp.Repo(repo_kind).init(allocator, .{ .cwd = repo_dir });
    const last_hash_git = try testMain(.git);
    const last_hash_xit = try testMain(.xit);