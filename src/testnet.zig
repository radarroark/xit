const std = @import("std");
const builtin = @import("builtin");
const rp = @import("./repo.zig");
const hash = @import("./hash.zig");

const c = @cImport({
    @cInclude("git2.h");
});

const Protocol = enum {
    git,
    http,
};

fn Server(comptime protocol: Protocol) type {
    return struct {
        core: Core,

        const Core = switch (protocol) {
            .git => struct {
                process: std.process.Child,
            },
            .http => struct {
                allocator: std.mem.Allocator,
                temp_dir_name: []const u8,
                stop_server_endpoint: []const u8,
                net_server: std.net.Server,
                server_thread: std.Thread,
            },
        };

        fn init(allocator: std.mem.Allocator, comptime temp_dir_name: []const u8, comptime port: u16) !Server(protocol) {
            switch (protocol) {
                .git => {
                    const port_str = std.fmt.comptimePrint("{}", .{port});
                    var process = std.process.Child.init(
                        &.{ "git", "daemon", "--reuseaddr", "--base-path=.", "--export-all", "--enable=receive-pack", "--port=" ++ port_str },
                        allocator,
                    );
                    process.cwd = temp_dir_name;
                    process.stdin_behavior = .Ignore;
                    process.stdout_behavior = .Ignore;
                    process.stderr_behavior = .Ignore;
                    return .{
                        .core = .{ .process = process },
                    };
                },
                .http => {
                    const address = try std.net.Address.parseIp("127.0.0.1", port);
                    const net_server = try address.listen(.{ .reuse_address = true });
                    errdefer net_server.deinit();
                    return .{
                        .core = .{
                            .allocator = allocator,
                            .temp_dir_name = temp_dir_name,
                            .stop_server_endpoint = std.fmt.comptimePrint("http://127.0.0.1:{}/stop-server", .{port}),
                            .net_server = net_server,
                            .server_thread = undefined,
                        },
                    };
                },
            }
        }

        fn start(self: *Server(protocol)) !void {
            switch (protocol) {
                .git => try self.core.process.spawn(),
                .http => {
                    const ServerHandler = struct {
                        fn run(core: *Core) !void {
                            accept: while (true) {
                                const conn = try core.net_server.accept();
                                defer conn.stream.close();

                                var header_buffer = [_]u8{0} ** 1024;
                                var http_server = std.http.Server.init(conn, &header_buffer);

                                while (http_server.state == .ready) {
                                    // give server some time to receive the request.
                                    // without it, POST requests sometimes don't have all the
                                    // expected data in their bodies because they use chunked encoding.
                                    std.time.sleep(std.time.ns_per_s * 0.5);

                                    var request = http_server.receiveHead() catch |err| switch (err) {
                                        error.HttpConnectionClosing => continue :accept,
                                        else => |e| return e,
                                    };
                                    if (std.mem.eql(u8, request.head.target, "/stop-server")) {
                                        break :accept;
                                    }

                                    const uri = try std.Uri.parseAfterScheme("", request.head.target);
                                    if (uri.path.percent_encoded[0] != '/') return error.PathMustStartWithSlash;
                                    const path = if (std.mem.indexOfScalar(u8, uri.path.percent_encoded[1..], '/')) |idx|
                                        uri.path.percent_encoded[idx + 1 ..]
                                    else
                                        return error.SlashNotFound;

                                    const temp_dir_path = try std.fs.cwd().realpathAlloc(core.allocator, core.temp_dir_name);
                                    defer core.allocator.free(temp_dir_path);
                                    const path_translated = try std.fmt.allocPrint(core.allocator, "{s}{s}", .{
                                        temp_dir_path,
                                        uri.path.percent_encoded,
                                    });
                                    defer core.allocator.free(path_translated);

                                    // init env map
                                    var env_map = std.process.EnvMap.init(core.allocator);
                                    defer env_map.deinit();
                                    try env_map.put("GATEWAY_INTERFACE", "CGI/1.1");
                                    try env_map.put("REQUEST_METHOD", @tagName(request.head.method));
                                    try env_map.put("PATH_INFO", path);
                                    try env_map.put("PATH_TRANSLATED", path_translated);
                                    if (uri.query) |query| {
                                        try env_map.put("QUERY_STRING", query.percent_encoded);
                                    }

                                    var accept = std.ArrayList([]const u8).init(core.allocator);
                                    defer accept.deinit();

                                    // iterate over headers to fill env map
                                    var req_header_it = request.iterateHeaders();
                                    while (req_header_it.next()) |header| {
                                        const header_name = header.name;
                                        const header_value = header.value;

                                        if (std.ascii.eqlIgnoreCase(header_name, "content-type")) {
                                            try env_map.put("CONTENT_TYPE", header_value);
                                        } else if (std.ascii.eqlIgnoreCase(header_name, "content-length")) {
                                            try env_map.put("CONTENT_LENGTH", header_value);
                                        } else if (std.ascii.eqlIgnoreCase(header_name, "referer")) {
                                            try env_map.put("HTTP_REFERER", header_value);
                                        } else if (std.ascii.eqlIgnoreCase(header_name, "accept")) {
                                            try accept.append(header_value);
                                        } else if (std.ascii.eqlIgnoreCase(header_name, "user-agent")) {
                                            try env_map.put("HTTP_USER_AGENT", header_value);
                                        }
                                    }

                                    const accept_str = try std.mem.join(core.allocator, ",", accept.items);
                                    defer core.allocator.free(accept_str);
                                    if (accept_str.len > 0) {
                                        try env_map.put("HTTP_ACCEPT", accept_str);
                                    }

                                    var process = std.process.Child.init(&.{ "git", "http-backend" }, core.allocator);
                                    process.cwd = core.temp_dir_name;
                                    process.stdin_behavior = .Pipe;
                                    process.stdout_behavior = .Pipe;
                                    process.stderr_behavior = .Pipe;
                                    process.env_map = &env_map;
                                    try process.spawn();

                                    if (request.head.method == .POST) {
                                        const reader = try request.reader();
                                        const request_body = try reader.readAllAlloc(core.allocator, 1024 * 1024);
                                        defer core.allocator.free(request_body);
                                        try process.stdin.?.writeAll(request_body);
                                    }

                                    var stdout = std.ArrayList(u8).init(core.allocator);
                                    defer stdout.deinit();
                                    var stderr = std.ArrayList(u8).init(core.allocator);
                                    defer stderr.deinit();
                                    try process.collectOutput(&stdout, &stderr, 1024 * 1024);

                                    _ = try process.wait();

                                    if (stderr.items.len > 0) {
                                        std.debug.print("Error from git-http-backend:\n{s}\n", .{stderr.items});
                                        try http_server.connection.stream.writeAll("HTTP/1.1 500 Internal Server Error\r\n\r\n");
                                    } else {
                                        try http_server.connection.stream.writeAll("HTTP/1.1 200 OK\r\n");
                                        try http_server.connection.stream.writeAll(stdout.items);
                                    }
                                }
                            }
                        }
                    };
                    self.core.server_thread = try std.Thread.spawn(.{}, ServerHandler.run, .{&self.core});
                },
            }

            // give server some time to start
            std.time.sleep(std.time.ns_per_s * 0.5);
        }

        fn stop(self: *Server(protocol)) void {
            switch (protocol) {
                .git => _ = self.core.process.kill() catch {},
                .http => {
                    var client = std.http.Client{ .allocator = self.core.allocator };
                    defer client.deinit();
                    _ = client.fetch(.{ .location = .{ .url = self.core.stop_server_endpoint } }) catch return;
                    self.core.server_thread.join();
                },
            }
        }
    };
}

fn testPull(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind), comptime protocol: Protocol, allocator: std.mem.Allocator) !void {
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

    // init server
    var server = try Server(protocol).init(allocator, temp_dir_name, 3000);
    try server.start();
    defer server.stop();

    // start libgit
    _ = c.git_libgit2_init();
    defer _ = c.git_libgit2_shutdown();

    // init server repo
    var server_repo = try rp.Repo(.git, .{}).init(allocator, .{ .cwd = temp_dir }, "server");
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
    var client_repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "client");
    defer client_repo.deinit();

    // add remote
    const remote_url = switch (protocol) {
        .git => "git://localhost:3000/server",
        .http => "http://localhost:3000/server",
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
    try testPull(.git, .{}, .git, allocator);
    try testPull(.git, .{}, .http, allocator);
}

fn testPush(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind), comptime protocol: Protocol, allocator: std.mem.Allocator) !void {
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

    // init server
    var server = try Server(protocol).init(allocator, temp_dir_name, 3001);
    try server.start();
    defer server.stop();

    // start libgit
    _ = c.git_libgit2_init();
    defer _ = c.git_libgit2_shutdown();

    // init server repo
    var server_repo = try rp.Repo(.git, .{}).init(allocator, .{ .cwd = temp_dir }, "server");
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
    var client_repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = temp_dir }, "client");
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
        .http => "http://localhost:3001/server",
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
    try testPush(.git, .{}, .git, allocator);
    try testPush(.git, .{}, .http, allocator);
}
