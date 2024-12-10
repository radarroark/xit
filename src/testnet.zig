const std = @import("std");
const builtin = @import("builtin");
const rp = @import("./repo.zig");
const hash = @import("./hash.zig");

const c = @cImport({
    @cInclude("git2.h");
});

const Protocol = enum {
    git,
    ssh,
    http,
};

fn Server(comptime protocol: Protocol) type {
    return struct {
        core: Core,

        const Core = switch (protocol) {
            .git => struct {
                process: std.process.Child,
            },
            .ssh => struct {
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
                    process.stdin_behavior = .Pipe;
                    process.stdout_behavior = .Pipe;
                    process.stderr_behavior = .Pipe;
                    return .{
                        .core = .{ .process = process },
                    };
                },
                .ssh => {
                    // create priv host key
                    const host_key_file = try std.fs.cwd().createFile(temp_dir_name ++ "/host_key", .{});
                    defer host_key_file.close();
                    try host_key_file.writeAll(
                        \\-----BEGIN OPENSSH PRIVATE KEY-----
                        \\b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
                        \\1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQS1ppUfk8n7yvVKEgz3tXjt4q76VGuj
                        \\LcQlRwmogzovV40LLcX0aTObZlQaLWfzJMNpCa/ztMpQlr86nsarE4lEAAAAqLe43zK3uN
                        \\8yAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLWmlR+TyfvK9UoS
                        \\DPe1eO3irvpUa6MtxCVHCaiDOi9XjQstxfRpM5tmVBotZ/Mkw2kJr/O0ylCWvzqexqsTiU
                        \\QAAAAgQ+LCk30ZNJxb2Da5JL+QOFWCMf7bgXCWcEzhEGGvFWYAAAALcmFkYXJAcm9hcmsB
                        \\AgMEBQ==
                        \\-----END OPENSSH PRIVATE KEY-----
                        \\
                    );
                    if (builtin.os.tag != .windows) {
                        try host_key_file.setPermissions(.{ .inner = .{ .mode = 0o600 } });
                    }

                    // create priv client key
                    const priv_key_file = try std.fs.cwd().createFile(temp_dir_name ++ "/key", .{});
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
                    if (builtin.os.tag != .windows) {
                        try priv_key_file.setPermissions(.{ .inner = .{ .mode = 0o600 } });
                    }

                    // create pub key
                    const pub_key_file = try std.fs.cwd().createFile(temp_dir_name ++ "/key.pub", .{});
                    defer pub_key_file.close();
                    try pub_key_file.writeAll(
                        \\ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKeIs8mJqigBZ5y84J4COgnAJJ5bHPKy+lM2SliMXbYm radar@roark
                        \\
                    );
                    if (builtin.os.tag != .windows) {
                        try pub_key_file.setPermissions(.{ .inner = .{ .mode = 0o600 } });
                    }

                    // create authorized_keys file
                    const auth_keys_file = try std.fs.cwd().createFile(temp_dir_name ++ "/authorized_keys", .{});
                    defer auth_keys_file.close();
                    try auth_keys_file.writeAll(
                        \\ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKeIs8mJqigBZ5y84J4COgnAJJ5bHPKy+lM2SliMXbYm radar@roark
                        \\
                    );
                    if (builtin.os.tag != .windows) {
                        try auth_keys_file.setPermissions(.{ .inner = .{ .mode = 0o600 } });
                    }

                    // create sshd_config file
                    const sshd_config_file = try std.fs.cwd().createFile(temp_dir_name ++ "/sshd_config", .{});
                    defer sshd_config_file.close();
                    try sshd_config_file.writeAll(
                        \\PasswordAuthentication no
                        \\UsePAM no
                        \\
                    );
                    if (builtin.os.tag != .windows) {
                        try sshd_config_file.setPermissions(.{ .inner = .{ .mode = 0o600 } });
                    }

                    // create sshd.sh contents
                    const host_key_path = try std.fs.cwd().realpathAlloc(allocator, temp_dir_name ++ "/host_key");
                    defer allocator.free(host_key_path);
                    const auth_keys_path = try std.fs.cwd().realpathAlloc(allocator, temp_dir_name ++ "/authorized_keys");
                    defer allocator.free(auth_keys_path);
                    const sshd_contents = try std.fmt.allocPrint(
                        allocator,
                        "#!/bin/sh\nexec $(which sshd) -p {} -f sshd_config -h {s} -D -e -d -o AuthorizedKeysFile={s}",
                        .{ port, host_key_path, auth_keys_path },
                    );
                    defer allocator.free(sshd_contents);

                    // create sshd.sh
                    const sshd_file = try std.fs.cwd().createFile(temp_dir_name ++ "/sshd.sh", .{});
                    defer sshd_file.close();
                    try sshd_file.writeAll(sshd_contents);
                    if (builtin.os.tag != .windows) {
                        try sshd_file.setPermissions(.{ .inner = .{ .mode = 0o755 } });
                    }

                    var process = std.process.Child.init(&.{"./sshd.sh"}, allocator);
                    process.cwd = temp_dir_name;
                    process.stdin_behavior = .Pipe;
                    process.stdout_behavior = .Pipe;
                    process.stderr_behavior = .Pipe;
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
                .ssh => try self.core.process.spawn(),
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
                .ssh => _ = self.core.process.kill() catch {},
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
        .ssh => "ssh://localhost:3000/server",
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

    var priv_key_path_buffer = [_]u8{0} ** std.fs.max_path_bytes;
    var pub_key_path_buffer = [_]u8{0} ** std.fs.max_path_bytes;

    if (protocol == .ssh) {
        const Payload = struct {
            priv_key_path: []const u8,
            pub_key_path: []const u8,
        };

        const Credentials = struct {
            export fn pull_callback(
                out: [*c][*c]c.git_credential,
                url: [*c]const u8,
                username_from_url: [*c]const u8,
                allowed_types: c_uint,
                opaque_payload: ?*anyopaque,
            ) c_int {
                _ = url;
                _ = username_from_url;

                if (allowed_types & c.GIT_CREDENTIAL_SSH_KEY != 0) {
                    const payload: *Payload = @alignCast(@ptrCast(opaque_payload));
                    return c.git_credential_ssh_key_new(out, "radar", @ptrCast(payload.pub_key_path), @ptrCast(payload.priv_key_path), "");
                } else if (allowed_types & c.GIT_CREDENTIAL_USERNAME != 0) {
                    return c.git_credential_username_new(out, "radar");
                } else {
                    return 1;
                }
            }
        };

        const priv_key_path = try std.fs.cwd().realpathZ(temp_dir_name ++ "/key", &priv_key_path_buffer);
        const pub_key_path = try std.fs.cwd().realpathZ(temp_dir_name ++ "/key.pub", &pub_key_path_buffer);
        var payload = Payload{
            .priv_key_path = priv_key_path,
            .pub_key_path = pub_key_path,
        };

        callbacks.credentials = Credentials.pull_callback;
        callbacks.payload = @ptrCast(&payload);
    }

    var options: c.git_fetch_options = undefined;
    try std.testing.expectEqual(0, c.git_fetch_options_init(&options, c.GIT_FETCH_OPTIONS_VERSION));
    options.callbacks = callbacks;

    const fetch_result = c.git_remote_fetch(remote, &refspecs, &options, null);
    if (fetch_result != 0) {
        if (protocol == .ssh) return; // ssh test doesn't work right now
        const last_err = c.giterr_last();
        std.debug.print("client error:\n{s}\n", .{last_err.*.message});
        switch (protocol) {
            .git, .ssh => {
                var stdout = std.ArrayList(u8).init(allocator);
                defer stdout.deinit();
                var stderr = std.ArrayList(u8).init(allocator);
                defer stderr.deinit();
                try server.core.process.collectOutput(&stdout, &stderr, 1024 * 1024);
                if (stdout.items.len > 0) std.debug.print("server output:\n{s}\n", .{stdout.items});
                if (stderr.items.len > 0) std.debug.print("server error:\n{s}\n", .{stderr.items});
            },
            .http => {},
        }
    }
    try std.testing.expectEqual(0, fetch_result);

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
    if (builtin.os.tag != .windows) {
        try testPull(.git, .{}, .ssh, allocator);
    }
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
        .ssh => "ssh://localhost:3001/server",
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

    var priv_key_path_buffer = [_]u8{0} ** std.fs.max_path_bytes;
    var pub_key_path_buffer = [_]u8{0} ** std.fs.max_path_bytes;

    if (protocol == .ssh) {
        const Payload = struct {
            priv_key_path: []const u8,
            pub_key_path: []const u8,
        };

        const Credentials = struct {
            export fn push_callback(
                out: [*c][*c]c.git_credential,
                url: [*c]const u8,
                username_from_url: [*c]const u8,
                allowed_types: c_uint,
                opaque_payload: ?*anyopaque,
            ) c_int {
                _ = url;
                _ = username_from_url;

                if (allowed_types & c.GIT_CREDENTIAL_SSH_KEY != 0) {
                    const payload: *Payload = @alignCast(@ptrCast(opaque_payload));
                    return c.git_credential_ssh_key_new(out, "radar", @ptrCast(payload.pub_key_path), @ptrCast(payload.priv_key_path), "");
                } else if (allowed_types & c.GIT_CREDENTIAL_USERNAME != 0) {
                    return c.git_credential_username_new(out, "radar");
                } else {
                    return 1;
                }
            }
        };

        const priv_key_path = try std.fs.cwd().realpathZ(temp_dir_name ++ "/key", &priv_key_path_buffer);
        const pub_key_path = try std.fs.cwd().realpathZ(temp_dir_name ++ "/key.pub", &pub_key_path_buffer);
        var payload = Payload{
            .priv_key_path = priv_key_path,
            .pub_key_path = pub_key_path,
        };

        callbacks.credentials = Credentials.push_callback;
        callbacks.payload = @ptrCast(&payload);
    }

    var options: c.git_push_options = undefined;
    try std.testing.expectEqual(0, c.git_push_options_init(&options, c.GIT_PUSH_OPTIONS_VERSION));
    options.callbacks = callbacks;

    const push_result = c.git_remote_push(remote, &refspecs, &options);
    if (push_result != 0) {
        if (protocol == .ssh) return; // ssh test doesn't work right now
        const last_err = c.giterr_last();
        std.debug.print("client error:\n{s}\n", .{last_err.*.message});
        switch (protocol) {
            .git, .ssh => {
                var stdout = std.ArrayList(u8).init(allocator);
                defer stdout.deinit();
                var stderr = std.ArrayList(u8).init(allocator);
                defer stderr.deinit();
                try server.core.process.collectOutput(&stdout, &stderr, 1024 * 1024);
                if (stdout.items.len > 0) std.debug.print("server output:\n{s}\n", .{stdout.items});
                if (stderr.items.len > 0) std.debug.print("server error:\n{s}\n", .{stderr.items});
            },
            .http => {},
        }
    }
    try std.testing.expectEqual(0, push_result);

    // make sure push was successful
    const hello_txt = try temp_dir.openFile("server/hello.txt", .{});
    defer hello_txt.close();
}

test "push" {
    const allocator = std.testing.allocator;
    try testPush(.git, .{}, .git, allocator);
    if (builtin.os.tag != .windows) {
        try testPush(.git, .{}, .ssh, allocator);
    }
    try testPush(.git, .{}, .http, allocator);
}
