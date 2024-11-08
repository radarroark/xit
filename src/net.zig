const std = @import("std");
const network = @import("network");
const rp = @import("./repo.zig");
const obj = @import("./object.zig");
const hash = @import("./hash.zig");

const TIMEOUT_MICRO_SECS: u32 = 2_000_000;

pub fn fetch(
    comptime repo_kind: rp.RepoKind,
    repo: *rp.Repo(repo_kind),
    allocator: std.mem.Allocator,
    remote_name: []const u8,
) !void {
    try network.init();
    defer network.deinit();

    var remote = try repo.remote();
    defer remote.deinit();

    const remote_section = remote.sections.get(remote_name) orelse return error.RemoteNotFound;
    const remote_url = remote_section.get("url") orelse return error.RemoteNotFound;
    const parsed_url = try std.Uri.parse(remote_url);
    const host = (parsed_url.host orelse return error.RemoteUrlInvalid).percent_encoded;
    const port = parsed_url.port orelse return error.RemoteUrlInvalid;
    const path = parsed_url.path.percent_encoded;

    var sock = try network.connectToHost(allocator, host, port, .tcp);
    defer sock.close();
    try sock.setTimeouts(TIMEOUT_MICRO_SECS, TIMEOUT_MICRO_SECS);

    const reader = sock.reader();
    const writer = sock.writer();

    // send command
    {
        var command_buf = [_]u8{0} ** 256;
        const command = try std.fmt.bufPrint(&command_buf, "0000git-upload-pack {s}\x00host={s}\x00", .{ path, host });

        var command_size_buf = [_]u8{0} ** 4;
        const command_size = try std.fmt.bufPrint(&command_size_buf, "{x}", .{command.len});

        @memcpy(command[command_size_buf.len - command_size.len .. command_size_buf.len], command_size);

        try writer.writeAll(command);
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var ref_to_oid = std.StringArrayHashMap(*const [hash.SHA1_HEX_LEN]u8).init(arena.allocator());
    var capabilities = std.ArrayList([]const u8).init(arena.allocator());

    // read messages
    while (true) {
        var size_buffer = [_]u8{0} ** 4;
        try reader.readNoEof(&size_buffer);

        var msg_size: usize = try std.fmt.parseInt(u16, &size_buffer, 16);

        // a flush packet has a size of 0
        if (msg_size == 0) {
            break;
        }

        // subtract the size of the hexadecimal size itself
        // to get the rest of the message size
        if (msg_size <= size_buffer.len) {
            return error.UnexpectedMessageSize;
        }
        msg_size -= size_buffer.len;

        // alloc the buffer that will hold the message
        var msg_buffer = try arena.allocator().alloc(u8, msg_size);
        try reader.readNoEof(msg_buffer);

        // ignore newline char
        if (msg_buffer[msg_buffer.len - 1] == '\n') {
            msg_buffer = msg_buffer[0 .. msg_buffer.len - 1];
        } else {
            return error.NewlineByteNotFound;
        }

        // the very first message should have a null byte
        // and include the capabilities after
        if (ref_to_oid.count() == 0) {
            if (std.mem.indexOfScalar(u8, msg_buffer, 0)) |null_index| {
                var iter = std.mem.splitScalar(u8, msg_buffer[null_index + 1 ..], ' ');
                while (iter.next()) |cap| {
                    try capabilities.append(cap);
                }

                msg_buffer = msg_buffer[0..null_index];
            } else {
                return error.NullByteNotFound;
            }
        }

        // populate the map of refs
        if (std.mem.indexOfScalar(u8, msg_buffer, ' ')) |space_index| {
            if (space_index != hash.SHA1_HEX_LEN) {
                return error.UnexpectedOidLength;
            }
            try ref_to_oid.put(msg_buffer[hash.SHA1_HEX_LEN + 1 ..], msg_buffer[0..hash.SHA1_HEX_LEN]);
        } else {
            return error.SpaceByteNotFound;
        }
    }

    var wanted_oids = std.StringArrayHashMap(void).init(allocator);
    defer wanted_oids.deinit();

    var moment = try repo.core.latestMoment();
    const state = rp.Repo(repo_kind).State(.read_only){ .core = &repo.core, .extra = .{ .moment = &moment } };

    for (ref_to_oid.values()) |oid| {
        if (wanted_oids.contains(oid)) {
            continue;
        }
        var object = obj.Object(repo_kind, .raw).init(allocator, state, oid) catch |err| switch (err) {
            error.ObjectNotFound => {
                std.debug.print("want {s}\n", .{oid});
                try wanted_oids.put(oid, {});
                continue;
            },
            else => return err,
        };
        defer object.deinit();
    }
}
