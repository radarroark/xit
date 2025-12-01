const std = @import("std");
const builtin = @import("builtin");

const CONNECT_TIMEOUT = 5000;

const INVALID_SOCKET = if (.windows == builtin.os.tag)
    std.os.windows.ws2_32.INVALID_SOCKET
else
    -1;

pub const SocketStream = struct {
    io: std.Io,
    host: []const u8,
    port: u16,
    socket: std.posix.socket_t,

    pub fn init(
        io: std.Io,
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
    ) !SocketStream {
        const host_dupe = try allocator.dupe(u8, host);
        errdefer allocator.free(host_dupe);

        return .{
            .io = io,
            .host = host_dupe,
            .port = port,
            .socket = INVALID_SOCKET,
        };
    }

    pub fn deinit(self: *SocketStream, allocator: std.mem.Allocator) void {
        allocator.free(self.host);
    }

    pub fn close(self: *SocketStream) !void {
        if (self.socket != INVALID_SOCKET) {
            std.posix.close(self.socket);
            self.socket = INVALID_SOCKET;
        }
    }

    pub fn read(
        self: *SocketStream,
        data: [*c]u8,
        len: usize,
    ) !usize {
        return try std.posix.recv(self.socket, data[0..len], 0);
    }

    pub fn write(
        self: *SocketStream,
        data: [*c]const u8,
        len: usize,
    ) !usize {
        return try std.posix.send(self.socket, data[0..len], 0);
    }

    pub fn writeAll(
        self: *SocketStream,
        data: [*c]const u8,
        len: usize,
    ) !void {
        var total_written: usize = 0;
        while (total_written < len) {
            const written = try self.write(data + total_written, len - total_written);
            total_written += written;
        }
    }

    pub fn connect(self: *SocketStream) !void {
        var canonical_name_buffer: [std.Io.net.HostName.max_len]u8 = undefined;
        var results_buffer: [32]std.Io.net.HostName.LookupResult = undefined;
        var results: std.Io.Queue(std.Io.net.HostName.LookupResult) = .init(&results_buffer);

        std.Io.net.HostName.lookup(try .init(self.host), self.io, &results, .{
            .port = self.port,
            .canonical_name_buffer = &canonical_name_buffer,
        });

        const address = while (results.getOne(self.io)) |result| switch (result) {
            .address => |address| break address,
            .canonical_name => continue,
            .end => |end| {
                try end;
                continue;
            },
        } else |err| return err;

        const family: u32 = switch (address) {
            .ip4 => std.os.linux.AF.INET,
            .ip6 => std.os.linux.AF.INET6,
        };

        const s = try std.posix.socket(family, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);

        if (INVALID_SOCKET != s) {
            try connectWithTimeout(s, &address, CONNECT_TIMEOUT);
        } else {
            return error.ConnectFailed;
        }

        self.socket = s;
    }
};

fn setBlocking(s: std.posix.socket_t, blocking: bool) !void {
    if (.windows == builtin.os.tag) {
        var nonblocking: u32 = if (blocking) 0 else 1;
        if (std.os.windows.ws2_32.ioctlsocket(s, std.os.windows.ws2_32.FIONBIO, &nonblocking) != 0) {
            return error.SocketError;
        }
    } else {
        var flags = try std.posix.fcntl(s, std.posix.F.GETFL, 0);

        if (flags == -1) {
            return error.SocketError;
        }

        if (blocking) {
            flags &= ~@as(usize, std.os.linux.SOCK.NONBLOCK);
        } else {
            flags |= std.os.linux.SOCK.NONBLOCK;
        }

        _ = try std.posix.fcntl(s, std.posix.F.SETFL, flags);
    }
}

fn waitWithTimeout(
    socket: std.posix.socket_t,
    timeout: c_int,
    comptime event_kind: enum { in, out },
) !void {
    if (.windows == builtin.os.tag) {
        const POLL = std.os.windows.ws2_32.POLL;
        const event = switch (event_kind) {
            .in => POLL.IN,
            .out => POLL.OUT,
        };

        var fds = [_]std.os.windows.ws2_32.pollfd{.{
            .fd = socket,
            .events = event,
            .revents = 0,
        }};

        const ret = std.os.windows.ws2_32.WSAPoll(&fds, fds.len, timeout);

        if (ret <= 0) {
            return error.SocketError;
        } else if ((fds[0].revents & (POLL.PRI | POLL.HUP | POLL.ERR)) != 0) {
            return error.SocketError;
        } else if ((fds[0].revents & event) != event) {
            return error.SocketError;
        }
    } else {
        const POLL = std.os.linux.POLL;
        const event = switch (event_kind) {
            .in => POLL.IN,
            .out => POLL.OUT,
        };

        var fds = [_]std.posix.pollfd{.{
            .fd = socket,
            .events = event,
            .revents = 0,
        }};

        const ret = try std.posix.poll(&fds, timeout);

        if (ret == 0) {
            return error.SocketError;
        } else if ((fds[0].revents & (POLL.PRI | POLL.HUP | POLL.ERR)) != 0) {
            return error.SocketError;
        } else if ((fds[0].revents & event) != event) {
            return error.SocketError;
        }
    }
}

fn connectWithTimeout(
    socket: std.posix.socket_t,
    address: *const std.Io.net.IpAddress,
    timeout: c_int,
) !void {
    if (0 != timeout) {
        try setBlocking(socket, false);
    }

    var storage: PosixAddress = undefined;
    const addr_len = addressToPosix(address, &storage);

    std.posix.connect(socket, &storage.any, addr_len) catch |err| switch (err) {
        error.WouldBlock => {},
        else => |e| return e,
    };

    if (0 != timeout) {
        try waitWithTimeout(socket, timeout, .out);

        try setBlocking(socket, true);
    }
}

pub const PosixAddress = extern union {
    any: std.posix.sockaddr,
    in: std.posix.sockaddr.in,
    in6: std.posix.sockaddr.in6,
};

fn addressToPosix(a: *const std.Io.net.IpAddress, storage: *PosixAddress) std.posix.socklen_t {
    return switch (a.*) {
        .ip4 => |ip4| {
            storage.in = address4ToPosix(ip4);
            return @sizeOf(std.posix.sockaddr.in);
        },
        .ip6 => |*ip6| {
            storage.in6 = address6ToPosix(ip6);
            return @sizeOf(std.posix.sockaddr.in6);
        },
    };
}

fn address4ToPosix(a: std.Io.net.Ip4Address) std.posix.sockaddr.in {
    return .{
        .port = std.mem.nativeToBig(u16, a.port),
        .addr = @bitCast(a.bytes),
    };
}

fn address6ToPosix(a: *const std.Io.net.Ip6Address) std.posix.sockaddr.in6 {
    return .{
        .port = std.mem.nativeToBig(u16, a.port),
        .flowinfo = a.flow,
        .addr = a.bytes,
        .scope_id = a.interface.index,
    };
}
