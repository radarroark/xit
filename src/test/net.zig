const std = @import("std");
const builtin = @import("builtin");
const rp = @import("../repo.zig");
const rf = @import("../ref.zig");
const work = @import("../workdir.zig");
const hash = @import("../hash.zig");
const net = @import("../net.zig");
const net_transport = @import("../net/transport.zig");

test "fetch" {
    const allocator = std.testing.allocator;
    try testFetch(.git, .{ .is_test = true }, .{ .wire = .http }, 3002, allocator);
    if (.windows != builtin.os.tag) {
        try testFetch(.git, .{ .is_test = true }, .{ .wire = .raw }, 3000, allocator);
        try testFetch(.git, .{ .is_test = true }, .{ .wire = .ssh }, 3001, allocator);
    }
    try testFetch(.git, .{ .is_test = true }, .file, 0, allocator);
}

test "push" {
    const allocator = std.testing.allocator;
    try testPush(.git, .{ .is_test = true }, .{ .wire = .http }, 3005, allocator);
    if (.windows != builtin.os.tag) {
        try testPush(.git, .{ .is_test = true }, .{ .wire = .raw }, 3003, allocator);
        try testPush(.git, .{ .is_test = true }, .{ .wire = .ssh }, 3004, allocator);
    }
    try testPush(.git, .{ .is_test = true }, .file, 0, allocator);
}

test "clone" {
    const allocator = std.testing.allocator;
    try testClone(.git, .{ .is_test = true }, .{ .wire = .http }, 3008, allocator);
    if (.windows != builtin.os.tag) {
        try testClone(.git, .{ .is_test = true }, .{ .wire = .raw }, 3006, allocator);
        try testClone(.git, .{ .is_test = true }, .{ .wire = .ssh }, 3007, allocator);
    }
    try testClone(.git, .{ .is_test = true }, .file, 0, allocator);
}

fn Server(comptime transport_def_kind: net_transport.TransportDefinitionKind) type {
    return struct {
        core: Core,

        const Core = switch (transport_def_kind) {
            .file => void,
            .wire => |wire_kind| switch (wire_kind) {
                .http => struct {
                    allocator: std.mem.Allocator,
                    temp_dir_name: []const u8,
                    stop_server_endpoint: []const u8,
                    net_server: std.net.Server,
                    server_thread: std.Thread,
                },
                .raw => struct {
                    process: std.process.Child,
                },
                .ssh => struct {
                    process: std.process.Child,
                },
            },
        };

        fn init(allocator: std.mem.Allocator, comptime temp_dir_name: []const u8, comptime port: u16) !Server(transport_def_kind) {
            switch (transport_def_kind) {
                .file => return .{ .core = {} },
                .wire => |wire_kind| switch (wire_kind) {
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
                    .raw => {
                        const port_str = std.fmt.comptimePrint("{}", .{port});
                        var process = std.process.Child.init(
                            &.{ "git", "daemon", "--reuseaddr", "--base-path=.", "--export-all", "--enable=receive-pack", "--log-destination=stderr", "--port=" ++ port_str },
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
                        if (.windows != builtin.os.tag) {
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
                        if (.windows != builtin.os.tag) {
                            try priv_key_file.setPermissions(.{ .inner = .{ .mode = 0o600 } });
                        }

                        // create pub key
                        const pub_key_file = try std.fs.cwd().createFile(temp_dir_name ++ "/key.pub", .{});
                        defer pub_key_file.close();
                        try pub_key_file.writeAll(
                            \\ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKeIs8mJqigBZ5y84J4COgnAJJ5bHPKy+lM2SliMXbYm radar@roark
                            \\
                        );
                        if (.windows != builtin.os.tag) {
                            try pub_key_file.setPermissions(.{ .inner = .{ .mode = 0o600 } });
                        }

                        // create authorized_keys file
                        const auth_keys_file = try std.fs.cwd().createFile(temp_dir_name ++ "/authorized_keys", .{});
                        defer auth_keys_file.close();
                        try auth_keys_file.writeAll(
                            \\ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKeIs8mJqigBZ5y84J4COgnAJJ5bHPKy+lM2SliMXbYm radar@roark
                            \\
                        );
                        if (.windows != builtin.os.tag) {
                            try auth_keys_file.setPermissions(.{ .inner = .{ .mode = 0o600 } });
                        }

                        // create known_hosts file
                        const known_hosts_file = try std.fs.cwd().createFile(temp_dir_name ++ "/known_hosts", .{});
                        defer known_hosts_file.close();
                        const port_str = std.fmt.comptimePrint("{}", .{port});
                        try known_hosts_file.writeAll("[localhost]:" ++ port_str ++ " ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLWmlR+TyfvK9UoSDPe1eO3irvpUa6MtxCVHCaiDOi9XjQstxfRpM5tmVBotZ/Mkw2kJr/O0ylCWvzqexqsTiUQ=");
                        if (.windows != builtin.os.tag) {
                            try known_hosts_file.setPermissions(.{ .inner = .{ .mode = 0o600 } });
                        }

                        // create sshd_config file
                        const sshd_config_file = try std.fs.cwd().createFile(temp_dir_name ++ "/sshd_config", .{});
                        defer sshd_config_file.close();
                        try sshd_config_file.writeAll(
                            \\AuthenticationMethods publickey
                            \\PubkeyAuthentication yes
                            \\PasswordAuthentication no
                            \\StrictModes no
                            \\
                        );
                        if (.windows != builtin.os.tag) {
                            try sshd_config_file.setPermissions(.{ .inner = .{ .mode = 0o600 } });
                        }

                        // create sshd.sh contents
                        const host_key_path = try std.fs.cwd().realpathAlloc(allocator, temp_dir_name ++ "/host_key");
                        defer allocator.free(host_key_path);
                        const auth_keys_path = try std.fs.cwd().realpathAlloc(allocator, temp_dir_name ++ "/authorized_keys");
                        defer allocator.free(auth_keys_path);
                        const sshd_contents = try std.fmt.allocPrint(
                            allocator,
                            "#!/bin/sh\nexec $(which sshd) -p {} -f sshd_config -h \"{s}\" -D -e -ddd -o AuthorizedKeysFile=\"{s}\"",
                            .{ port, host_key_path, auth_keys_path },
                        );
                        defer allocator.free(sshd_contents);

                        // if path has a space char, it fucks up sshd
                        try std.testing.expect(null == std.mem.indexOfScalar(u8, auth_keys_path, ' '));

                        // create sshd.sh
                        const sshd_file = try std.fs.cwd().createFile(temp_dir_name ++ "/sshd.sh", .{});
                        defer sshd_file.close();
                        try sshd_file.writeAll(sshd_contents);
                        if (.windows != builtin.os.tag) {
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
                },
            }
        }

        fn start(self: *Server(transport_def_kind)) !void {
            switch (transport_def_kind) {
                .file => {},
                .wire => |wire_kind| switch (wire_kind) {
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

                                        var keep_alive = false;

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
                                            } else if (std.ascii.eqlIgnoreCase(header_name, "connection")) {
                                                keep_alive = std.ascii.eqlIgnoreCase(header_value, "keep-alive");
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

                                        if (!keep_alive) {
                                            continue :accept;
                                        }
                                    }
                                }
                            }
                        };
                        self.core.server_thread = try std.Thread.spawn(.{}, ServerHandler.run, .{&self.core});
                    },
                    .raw => try self.core.process.spawn(),
                    .ssh => try self.core.process.spawn(),
                },
            }

            // give server some time to start
            std.time.sleep(std.time.ns_per_s * 0.5);
        }

        fn stop(self: *Server(transport_def_kind)) void {
            switch (transport_def_kind) {
                .file => {},
                .wire => |wire_kind| switch (wire_kind) {
                    .http => {
                        var client = std.http.Client{ .allocator = self.core.allocator };
                        defer client.deinit();
                        _ = client.fetch(.{ .location = .{ .url = self.core.stop_server_endpoint } }) catch return;
                        self.core.server_thread.join();
                    },
                    .raw => _ = self.core.process.kill() catch {},
                    .ssh => _ = self.core.process.kill() catch {},
                },
            }
        }
    };
}

fn testFetch(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    comptime transport_def_kind: net_transport.TransportDefinitionKind,
    comptime port: u16,
    allocator: std.mem.Allocator,
) !void {
    const temp_dir_name = "temp-testnet-fetch";

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
    var server = try Server(transport_def_kind).init(allocator, temp_dir_name, port);
    try server.start();
    defer server.stop();

    // create the server dir
    var server_dir = try temp_dir.makeOpenPath("server", .{});
    defer server_dir.close();

    // init server repo
    var server_repo = try rp.Repo(.git, .{ .is_test = true }).init(allocator, .{ .cwd = server_dir }, ".");
    defer server_repo.deinit();

    // make a commit
    const commit1 = blk: {
        const hello_txt = try server_repo.core.work_dir.createFile("hello.txt", .{ .truncate = true });
        defer hello_txt.close();
        try hello_txt.writeAll("hello, world!");
        try server_repo.add(allocator, &.{"hello.txt"});
        break :blk try server_repo.commit(allocator, .{ .message = "let there be light" });
    };

    // export server repo
    {
        const export_file = try server_repo.core.git_dir.createFile("git-daemon-export-ok", .{});
        defer export_file.close();

        try server_repo.addConfig(allocator, .{ .name = "uploadpack.allowAnySHA1InWant", .value = "true" });
    }

    // add a tag
    _ = try server_repo.addTag(allocator, .{ .name = "1.0.0", .message = "hi" });

    // create the client dir
    var client_dir = try temp_dir.makeOpenPath("client", .{});
    defer client_dir.close();

    // init client repo
    var client_repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = client_dir }, ".");
    defer client_repo.deinit();

    // add remote
    {
        // get repo path
        var repo_path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
        const repo_path = try server_dir.realpath(".", &repo_path_buffer);

        if (.windows == builtin.os.tag) {
            std.mem.replaceScalar(u8, repo_path, '\\', '/');
        }
        const separator = if (repo_path[0] == '/') "" else "/";

        const remote_url = switch (transport_def_kind) {
            .file => try std.fmt.allocPrint(allocator, "file://{s}{s}", .{ separator, repo_path }),
            .wire => |wire_kind| switch (wire_kind) {
                .http => try std.fmt.allocPrint(allocator, "http://localhost:{}/server", .{port}),
                .raw => try std.fmt.allocPrint(allocator, "git://localhost:{}/server", .{port}),
                .ssh => try std.fmt.allocPrint(allocator, "ssh://localhost:{}{s}{s}", .{ port, separator, repo_path }),
            },
        };
        defer allocator.free(remote_url);

        try client_repo.addRemote(allocator, .{ .name = "origin", .value = remote_url });
        try client_repo.addConfig(allocator, .{ .name = "branch.master.remote", .value = "origin" });
    }

    // create refspec with oid as a test
    const oid_refspec = try std.fmt.allocPrint(allocator, "+{s}:refs/heads/foo", .{&commit1});
    defer allocator.free(oid_refspec);

    const refspecs = &.{
        "+refs/heads/master:refs/heads/master",
        oid_refspec,
    };

    var remote = try net.Remote(repo_kind, repo_opts).initFromConfig(.{ .core = &client_repo.core, .extra = .{} }, allocator, "origin");
    defer remote.deinit(allocator);

    const is_ssh = switch (transport_def_kind) {
        .file => false,
        .wire => |wire_kind| .ssh == wire_kind,
    };
    const ssh_cmd_maybe: ?[]const u8 = if (is_ssh) blk: {
        var known_hosts_path_buffer = [_]u8{0} ** std.fs.max_path_bytes;
        const known_hosts_path = try std.fs.cwd().realpath(temp_dir_name ++ "/known_hosts", &known_hosts_path_buffer);

        var priv_key_path_buffer = [_]u8{0} ** std.fs.max_path_bytes;
        const priv_key_path = try std.fs.cwd().realpath(temp_dir_name ++ "/key", &priv_key_path_buffer);

        break :blk try std.fmt.allocPrint(allocator, "ssh -o UserKnownHostsFile=\"{s}\" -o IdentityFile=\"{s}\"", .{ known_hosts_path, priv_key_path });
    } else null;
    defer if (ssh_cmd_maybe) |ssh_cmd| allocator.free(ssh_cmd);

    client_repo.fetch(
        allocator,
        "origin",
        .{ .refspecs = refspecs, .wire = .{ .ssh = .{ .command = ssh_cmd_maybe } } },
    ) catch |err| {
        if (false) {
            var stdout = std.ArrayList(u8).init(allocator);
            defer stdout.deinit();
            var stderr = std.ArrayList(u8).init(allocator);
            defer stderr.deinit();
            try server.core.process.collectOutput(&stdout, &stderr, 1024 * 1024);
            if (stdout.items.len > 0) std.debug.print("server output:\n{s}\n", .{stdout.items});
            if (stderr.items.len > 0) std.debug.print("server error:\n{s}\n", .{stderr.items});
        }
        return err;
    };

    // update the working dir
    try client_repo.restore(allocator, ".");

    // make sure fetch was successful
    {
        const hello_txt = try temp_dir.openFile("client/hello.txt", .{});
        defer hello_txt.close();
        const ref_1_0_0 = try temp_dir.openFile("client/.git/refs/tags/1.0.0", .{});
        defer ref_1_0_0.close();
        const ref_foo = try temp_dir.openFile("client/.git/refs/heads/foo", .{});
        defer ref_foo.close();

        const ref_master = try temp_dir.openFile("client/.git/refs/heads/master", .{});
        defer ref_master.close();
        var oid_master = [_]u8{0} ** hash.hexLen(repo_opts.hash);
        try ref_master.reader().readNoEof(&oid_master);
        try std.testing.expectEqualStrings(&commit1, &oid_master);
    }

    // restart the ssh server because it's flaky when multiple requests are made
    if (is_ssh) {
        server.stop();
        try server.start();
    }

    // make another commit
    const commit2 = blk: {
        const goodbye_txt = try server_repo.core.work_dir.createFile("goodbye.txt", .{ .truncate = true });
        defer goodbye_txt.close();
        try goodbye_txt.writeAll("goodbye, world!");
        try server_repo.add(allocator, &.{"goodbye.txt"});
        break :blk try server_repo.commit(allocator, .{ .message = "goodbye" });
    };

    client_repo.fetch(
        allocator,
        "origin",
        .{ .refspecs = refspecs, .wire = .{ .ssh = .{ .command = ssh_cmd_maybe } } },
    ) catch |err| {
        if (false) {
            var stdout = std.ArrayList(u8).init(allocator);
            defer stdout.deinit();
            var stderr = std.ArrayList(u8).init(allocator);
            defer stderr.deinit();
            try server.core.process.collectOutput(&stdout, &stderr, 1024 * 1024);
            if (stdout.items.len > 0) std.debug.print("server output:\n{s}\n", .{stdout.items});
            if (stderr.items.len > 0) std.debug.print("server error:\n{s}\n", .{stderr.items});
        }
        return err;
    };

    // update the working dir
    try client_repo.restore(allocator, ".");

    // make sure fetch was successful
    {
        const goodbye_txt = try temp_dir.openFile("client/goodbye.txt", .{});
        defer goodbye_txt.close();

        const ref_master = try temp_dir.openFile("client/.git/refs/heads/master", .{});
        defer ref_master.close();
        var oid_master = [_]u8{0} ** hash.hexLen(repo_opts.hash);
        try ref_master.reader().readNoEof(&oid_master);
        try std.testing.expectEqualStrings(&commit2, &oid_master);
    }
}

fn testPush(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    comptime transport_def_kind: net_transport.TransportDefinitionKind,
    comptime port: u16,
    allocator: std.mem.Allocator,
) !void {
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
    var server = try Server(transport_def_kind).init(allocator, temp_dir_name, port);
    try server.start();
    defer server.stop();

    // create the server dir
    var server_dir = try temp_dir.makeOpenPath("server", .{});
    defer server_dir.close();

    // init server repo
    var server_repo = try rp.Repo(.git, .{ .is_test = true }).init(allocator, .{ .cwd = server_dir }, ".");
    defer server_repo.deinit();
    switch (transport_def_kind) {
        .file => try server_repo.addConfig(allocator, .{ .name = "core.bare", .value = "true" }),
        .wire => {
            try server_repo.addConfig(allocator, .{ .name = "core.bare", .value = "false" });
            try server_repo.addConfig(allocator, .{ .name = "receive.denycurrentbranch", .value = "updateinstead" });
        },
    }
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
    var client_repo = try rp.Repo(repo_kind, repo_opts).init(allocator, .{ .cwd = client_dir }, ".");
    defer client_repo.deinit();

    // make a commit
    const commit1 = blk: {
        const hello_txt = try client_repo.core.work_dir.createFile("hello.txt", .{ .truncate = true });
        defer hello_txt.close();
        try hello_txt.writeAll("hello, world!");
        try client_repo.add(allocator, &.{"hello.txt"});
        break :blk try client_repo.commit(allocator, .{ .message = "let there be light" });
    };

    // add a tag
    _ = try client_repo.addTag(allocator, .{ .name = "1.0.0", .message = "hi" });

    // add remote
    {
        // get repo path
        var repo_path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
        const repo_path = try server_dir.realpath(".", &repo_path_buffer);

        if (.windows == builtin.os.tag) {
            std.mem.replaceScalar(u8, repo_path, '\\', '/');
        }
        const separator = if (repo_path[0] == '/') "" else "/";

        const remote_url = switch (transport_def_kind) {
            .file => try std.fmt.allocPrint(allocator, "file://{s}{s}", .{ separator, repo_path }),
            .wire => |wire_kind| switch (wire_kind) {
                .http => try std.fmt.allocPrint(allocator, "http://localhost:{}/server", .{port}),
                .raw => try std.fmt.allocPrint(allocator, "git://localhost:{}/server", .{port}),
                .ssh => try std.fmt.allocPrint(allocator, "ssh://localhost:{}{s}{s}", .{ port, separator, repo_path }),
            },
        };
        defer allocator.free(remote_url);

        try client_repo.addRemote(allocator, .{ .name = "origin", .value = remote_url });
        try client_repo.addConfig(allocator, .{ .name = "branch.master.remote", .value = "origin" });
    }

    const refspecs = &.{
        "+refs/heads/master:refs/heads/master",
        "refs/tags/1.0.0:refs/tags/1.0.0",
    };

    const is_ssh = switch (transport_def_kind) {
        .file => false,
        .wire => |wire_kind| .ssh == wire_kind,
    };
    const ssh_cmd_maybe: ?[]const u8 = if (is_ssh) blk: {
        var known_hosts_path_buffer = [_]u8{0} ** std.fs.max_path_bytes;
        const known_hosts_path = try std.fs.cwd().realpath(temp_dir_name ++ "/known_hosts", &known_hosts_path_buffer);

        var priv_key_path_buffer = [_]u8{0} ** std.fs.max_path_bytes;
        const priv_key_path = try std.fs.cwd().realpath(temp_dir_name ++ "/key", &priv_key_path_buffer);

        break :blk try std.fmt.allocPrint(allocator, "ssh -o UserKnownHostsFile=\"{s}\" -o IdentityFile=\"{s}\"", .{ known_hosts_path, priv_key_path });
    } else null;
    defer if (ssh_cmd_maybe) |ssh_cmd| allocator.free(ssh_cmd);

    client_repo.push(
        allocator,
        "origin",
        .{ .refspecs = refspecs, .wire = .{ .ssh = .{ .command = ssh_cmd_maybe } } },
    ) catch |err| {
        if (false) {
            var stdout = std.ArrayList(u8).init(allocator);
            defer stdout.deinit();
            var stderr = std.ArrayList(u8).init(allocator);
            defer stderr.deinit();
            try server.core.process.collectOutput(&stdout, &stderr, 1024 * 1024);
            if (stdout.items.len > 0) std.debug.print("server output:\n{s}\n", .{stdout.items});
            if (stderr.items.len > 0) std.debug.print("server error:\n{s}\n", .{stderr.items});
        }
        return err;
    };

    // make sure push was successful
    {
        const ref_1_0_0 = try temp_dir.openFile("server/.git/refs/tags/1.0.0", .{});
        defer ref_1_0_0.close();

        const ref_master = try temp_dir.openFile("server/.git/refs/heads/master", .{});
        defer ref_master.close();
        var oid_master = [_]u8{0} ** hash.hexLen(repo_opts.hash);
        try ref_master.reader().readNoEof(&oid_master);
        try std.testing.expectEqualStrings(&commit1, &oid_master);
    }

    // restart the ssh server because it's flaky when multiple requests are made
    if (is_ssh) {
        server.stop();
        try server.start();
    }

    // make another commit
    const commit2 = blk: {
        const goodbye_txt = try client_repo.core.work_dir.createFile("goodbye.txt", .{ .truncate = true });
        defer goodbye_txt.close();
        try goodbye_txt.writeAll("goodbye, world!");
        try client_repo.add(allocator, &.{"goodbye.txt"});
        break :blk try client_repo.commit(allocator, .{ .message = "goodbye" });
    };

    client_repo.push(
        allocator,
        "origin",
        .{ .refspecs = refspecs, .wire = .{ .ssh = .{ .command = ssh_cmd_maybe } } },
    ) catch |err| {
        if (false) {
            var stdout = std.ArrayList(u8).init(allocator);
            defer stdout.deinit();
            var stderr = std.ArrayList(u8).init(allocator);
            defer stderr.deinit();
            try server.core.process.collectOutput(&stdout, &stderr, 1024 * 1024);
            if (stdout.items.len > 0) std.debug.print("server output:\n{s}\n", .{stdout.items});
            if (stderr.items.len > 0) std.debug.print("server error:\n{s}\n", .{stderr.items});
        }
        return err;
    };

    // make sure push was successful
    {
        const ref_master = try temp_dir.openFile("server/.git/refs/heads/master", .{});
        defer ref_master.close();
        var oid_master = [_]u8{0} ** hash.hexLen(repo_opts.hash);
        try ref_master.reader().readNoEof(&oid_master);
        try std.testing.expectEqualStrings(&commit2, &oid_master);
    }

    // restart the ssh server because it's flaky when multiple requests are made
    if (is_ssh) {
        server.stop();
        try server.start();
    }

    // remove the remote tag
    {
        const del_refspecs = &.{
            ":refs/tags/1.0.0",
        };

        client_repo.push(
            allocator,
            "origin",
            .{ .refspecs = del_refspecs, .wire = .{ .ssh = .{ .command = ssh_cmd_maybe } } },
        ) catch |err| {
            if (false) {
                var stdout = std.ArrayList(u8).init(allocator);
                defer stdout.deinit();
                var stderr = std.ArrayList(u8).init(allocator);
                defer stderr.deinit();
                try server.core.process.collectOutput(&stdout, &stderr, 1024 * 1024);
                if (stdout.items.len > 0) std.debug.print("server output:\n{s}\n", .{stdout.items});
                if (stderr.items.len > 0) std.debug.print("server error:\n{s}\n", .{stderr.items});
            }
            return err;
        };
    }

    // make sure push was successful
    {
        if (temp_dir.openFile("server/.git/refs/tags/1.0.0", .{})) |ref_1_0_0| {
            defer ref_1_0_0.close();
            return error.UnexpectedFile;
        } else |err| switch (err) {
            error.FileNotFound => {},
            else => |e| return e,
        }
    }
}

fn testClone(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    comptime transport_def_kind: net_transport.TransportDefinitionKind,
    comptime port: u16,
    allocator: std.mem.Allocator,
) !void {
    const temp_dir_name = "temp-testnet-clone";

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
    var server = try Server(transport_def_kind).init(allocator, temp_dir_name, port);
    try server.start();
    defer server.stop();

    // create the server dir
    var server_dir = try temp_dir.makeOpenPath("server", .{});
    defer server_dir.close();

    // init server repo
    var server_repo = try rp.Repo(.git, .{ .is_test = true }).init(allocator, .{ .cwd = server_dir }, ".");
    defer server_repo.deinit();

    // make a commit
    {
        const hello_txt = try server_repo.core.work_dir.createFile("hello.txt", .{ .truncate = true });
        defer hello_txt.close();
        try hello_txt.writeAll("hello, world!");
        try server_repo.add(allocator, &.{"hello.txt"});
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

    // get remote url
    const remote_url = blk: {
        // get repo path
        var repo_path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
        const repo_path = try server_dir.realpath(".", &repo_path_buffer);

        if (.windows == builtin.os.tag) {
            std.mem.replaceScalar(u8, repo_path, '\\', '/');
        }
        const separator = if (repo_path[0] == '/') "" else "/";

        break :blk switch (transport_def_kind) {
            .file => try std.fmt.allocPrint(allocator, "file://{s}{s}", .{ separator, repo_path }),
            .wire => |wire_kind| switch (wire_kind) {
                .http => try std.fmt.allocPrint(allocator, "http://localhost:{}/server", .{port}),
                .raw => try std.fmt.allocPrint(allocator, "git://localhost:{}/server", .{port}),
                .ssh => try std.fmt.allocPrint(allocator, "ssh://localhost:{}{s}{s}", .{ port, separator, repo_path }),
            },
        };
    };
    defer allocator.free(remote_url);

    var repo_path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
    const repo_path: []const u8 = @ptrCast(try client_dir.realpath(".", &repo_path_buffer));

    const is_ssh = switch (transport_def_kind) {
        .file => false,
        .wire => |wire_kind| .ssh == wire_kind,
    };
    const ssh_cmd_maybe: ?[]const u8 = if (is_ssh) blk: {
        var known_hosts_path_buffer = [_]u8{0} ** std.fs.max_path_bytes;
        const known_hosts_path = try std.fs.cwd().realpath(temp_dir_name ++ "/known_hosts", &known_hosts_path_buffer);

        var priv_key_path_buffer = [_]u8{0} ** std.fs.max_path_bytes;
        const priv_key_path = try std.fs.cwd().realpath(temp_dir_name ++ "/key", &priv_key_path_buffer);

        break :blk try std.fmt.allocPrint(allocator, "ssh -o UserKnownHostsFile=\"{s}\" -o IdentityFile=\"{s}\"", .{ known_hosts_path, priv_key_path });
    } else null;
    defer if (ssh_cmd_maybe) |ssh_cmd| allocator.free(ssh_cmd);

    // clone repo
    var client_repo = rp.Repo(repo_kind, repo_opts).clone(
        allocator,
        remote_url,
        temp_dir,
        repo_path,
        .{ .wire = .{ .ssh = .{ .command = ssh_cmd_maybe } } },
    ) catch |err| {
        if (false) {
            var stdout = std.ArrayList(u8).init(allocator);
            defer stdout.deinit();
            var stderr = std.ArrayList(u8).init(allocator);
            defer stderr.deinit();
            try server.core.process.collectOutput(&stdout, &stderr, 1024 * 1024);
            if (stdout.items.len > 0) std.debug.print("server output:\n{s}\n", .{stdout.items});
            if (stderr.items.len > 0) std.debug.print("server error:\n{s}\n", .{stderr.items});
        }
        return err;
    };
    defer client_repo.deinit();

    // make sure clone was successful
    const hello_txt = try temp_dir.openFile("client/hello.txt", .{});
    defer hello_txt.close();
}
