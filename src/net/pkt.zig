const std = @import("std");
const builtin = @import("builtin");
const net = @import("../net.zig");
const net_fetch = @import("./fetch.zig");
const net_wire = @import("./wire.zig");
const rp = @import("../repo.zig");
const hash = @import("../hash.zig");

pub fn Ref(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        head: net.RemoteHead(repo_kind, repo_opts),
        capabilities: ?[]const u8,

        pub fn deinit(self: *Ref(repo_kind, repo_opts), allocator: std.mem.Allocator) void {
            self.head.deinit(allocator);
            if (self.capabilities) |caps| allocator.free(caps);
        }
    };
}

pub fn Pkt(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return union(enum) {
        flush: void,
        ref: Ref(repo_kind, repo_opts),
        ack: struct {
            oid: [hash.hexLen(repo_opts.hash)]u8,
            status: ?enum {
                cont,
                common,
                ready,
            },
        },
        nak: void,
        comment: []u8,
        data: []u8,
        progress: []u8,
        err: []u8,
        ok: []u8,
        ng: []u8,
        unpack: struct {
            unpack_ok: bool,
        },
        unshallow: struct {
            oid: [hash.hexLen(repo_opts.hash)]u8,
        },
        shallow: struct {
            oid: [hash.hexLen(repo_opts.hash)]u8,
        },

        pub fn initMaybe(
            allocator: std.mem.Allocator,
            buffer: []const u8,
            found_capabilities: *bool,
            bufptr: *?[*]const u8,
        ) !?Pkt(repo_kind, repo_opts) {
            var line = buffer;

            if (line.len < PKT_LEN_SIZE) {
                return null;
            }

            var len = try std.fmt.parseInt(u16, line[0..PKT_LEN_SIZE], 16);

            if (line.len < len or (len != 0 and len < PKT_LEN_SIZE)) {
                return null;
            }

            line = line[PKT_LEN_SIZE..];

            if (len == PKT_LEN_SIZE) {
                return error.InvalidEmptyPacket;
            }

            if (len == 0) {
                bufptr.* = line.ptr;
                return .{ .flush = {} };
            }

            len -= PKT_LEN_SIZE;
            bufptr.* = line[len..].ptr;

            const content = line[0..len];

            return switch (line[0]) {
                1 => try dataPkt(repo_kind, repo_opts, allocator, content),
                2 => try sidebandProgressPkt(repo_kind, repo_opts, allocator, content),
                3 => try sidebandErrorPkt(repo_kind, repo_opts, allocator, content),
                else => if (std.mem.startsWith(u8, content, "ACK"))
                    try ackPkt(repo_kind, repo_opts, content)
                else if (std.mem.startsWith(u8, content, "NAK"))
                    .{ .nak = {} }
                else if (line[0] == '#')
                    try commentPkt(repo_kind, repo_opts, allocator, content)
                else if (std.mem.startsWith(u8, content, "ERR"))
                    try errPkt(repo_kind, repo_opts, allocator, content)
                else if (std.mem.startsWith(u8, content, "ok"))
                    try okPkt(repo_kind, repo_opts, allocator, content)
                else if (std.mem.startsWith(u8, content, "ng"))
                    try ngPkt(repo_kind, repo_opts, allocator, content)
                else if (std.mem.startsWith(u8, content, "unpack"))
                    try unpackPkt(repo_kind, repo_opts, content)
                else if (std.mem.startsWith(u8, content, "unshallow"))
                    try unshallowPkt(repo_kind, repo_opts, content)
                else if (std.mem.startsWith(u8, content, "shallow"))
                    try shallowPkt(repo_kind, repo_opts, content)
                else
                    try refPkt(repo_kind, repo_opts, allocator, content, found_capabilities),
            };
        }

        pub fn deinit(self: *Pkt(repo_kind, repo_opts), allocator: std.mem.Allocator) void {
            switch (self.*) {
                .flush => {},
                .ref => |*p| p.deinit(allocator),
                .ack => {},
                .nak => {},
                .comment => |p| allocator.free(p),
                .data => |p| allocator.free(p),
                .progress => |p| allocator.free(p),
                .err => |p| allocator.free(p),
                .ok => |p| allocator.free(p),
                .ng => |p| allocator.free(p),
                .unpack => {},
                .unshallow => {},
                .shallow => {},
            }
        }
    };
}

const PKT_HAVE_PREFIX = "have ";
const PKT_WANT_PREFIX = "want ";

const PKT_LEN_SIZE = 4;
const PKT_MAX_SIZE = 0xffff;

pub fn commandSize(command: []u8, len: usize) !void {
    var command_size_buf = [_]u8{'0'} ** 4;
    const command_size = try std.fmt.bufPrint(&command_size_buf, "{x}", .{len});
    @memcpy(command[command_size_buf.len - command_size.len .. command_size_buf.len], command_size);
}

pub fn bufferHave(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    allocator: std.mem.Allocator,
    oid_hex: *const [hash.hexLen(repo_opts.hash)]u8,
    buf: *std.ArrayList(u8),
) !void {
    var command_size_buf = [_]u8{'0'} ** 4;

    const line = try std.fmt.allocPrint(allocator, "{s}{s}{s}\n", .{ &command_size_buf, PKT_HAVE_PREFIX, oid_hex });
    defer allocator.free(line);

    try commandSize(&command_size_buf, line.len);
    @memcpy(line[0..4], &command_size_buf);

    try buf.appendSlice(line);
}

fn bufferWantWithCaps(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    allocator: std.mem.Allocator,
    head: *const net.RemoteHead(repo_kind, repo_opts),
    caps: *const net_wire.Capabilities,
    buf: *std.ArrayList(u8),
) !void {
    var line = std.ArrayList(u8).init(allocator);
    defer line.deinit();

    var command_size_buf = [_]u8{'0'} ** 4;

    try line.writer().print("{s}{s}{s} ", .{ &command_size_buf, PKT_WANT_PREFIX, &head.oid });

    if (caps.multi_ack_detailed) {
        try line.appendSlice("multi_ack_detailed ");
    } else if (caps.multi_ack) {
        try line.appendSlice("multi_ack ");
    }

    if (caps.side_band_64k) {
        try line.appendSlice("side-band-64k ");
    } else if (caps.side_band) {
        try line.appendSlice("side-band ");
    }

    if (caps.include_tag) {
        try line.appendSlice("include-tag ");
    }

    if (caps.thin_pack) {
        try line.appendSlice("thin-pack ");
    }

    if (caps.ofs_delta) {
        try line.appendSlice("ofs-delta ");
    }

    if (caps.shallow) {
        try line.appendSlice("shallow ");
    }

    try line.append('\n');

    const PKT_MAX_WANTLEN = (PKT_LEN_SIZE + PKT_WANT_PREFIX.len + hash.hexLen(repo_opts.hash) + 1);

    if (line.items.len > (PKT_MAX_SIZE - (PKT_MAX_WANTLEN + 1))) {
        return error.InvalidPacket;
    }

    try commandSize(&command_size_buf, line.items.len);
    @memcpy(line.items[0..4], &command_size_buf);

    try buf.appendSlice(line.items);
}

pub fn bufferWants(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    allocator: std.mem.Allocator,
    wants: *const net_fetch.FetchNegotiation(repo_kind, repo_opts),
    caps: *const net_wire.Capabilities,
    buf: *std.ArrayList(u8),
) !void {
    var idx: usize = 0;
    if (caps.common) {
        for (wants.refs, 0..) |*head, i| {
            if (!head.is_local) {
                idx = i;
                break;
            }
        }

        try bufferWantWithCaps(repo_kind, repo_opts, allocator, &wants.refs[idx], caps, buf);

        idx += 1;
    }

    for (idx..wants.refs.len) |i| {
        const head = &wants.refs[i];

        if (head.is_local) {
            continue;
        }

        var command_size_buf = [_]u8{'0'} ** 4;

        const line = try std.fmt.allocPrint(allocator, "{s}{s}{s}\n", .{ &command_size_buf, PKT_WANT_PREFIX, &head.oid });
        defer allocator.free(line);

        try commandSize(&command_size_buf, line.len);
        @memcpy(line[0..4], &command_size_buf);

        try buf.appendSlice(line);
    }

    try buf.appendSlice("0000");
}

fn dataPkt(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    allocator: std.mem.Allocator,
    content: []const u8,
) !Pkt(repo_kind, repo_opts) {
    var line = content.ptr;
    var len = content.len;

    line += 1;
    len -= 1;

    const data = try allocator.dupe(u8, line[0..len]);
    errdefer allocator.free(data);
    return .{ .data = data };
}

fn sidebandProgressPkt(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    allocator: std.mem.Allocator,
    content: []const u8,
) !Pkt(repo_kind, repo_opts) {
    var line = content.ptr;
    var len = content.len;

    line += 1;
    len -= 1;

    const progress = try allocator.dupe(u8, line[0..len]);
    errdefer allocator.free(progress);
    return .{ .progress = progress };
}

fn sidebandErrorPkt(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    allocator: std.mem.Allocator,
    content: []const u8,
) !Pkt(repo_kind, repo_opts) {
    var line = content.ptr;
    var len = content.len;

    line += 1;
    len -= 1;

    const err = try allocator.dupe(u8, line[0..len]);
    errdefer allocator.free(err);
    return .{ .err = err };
}

fn ackPkt(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    content: []const u8,
) !Pkt(repo_kind, repo_opts) {
    var line = content.ptr;
    var len = content.len;

    var pkt = Pkt(repo_kind, repo_opts){ .ack = .{ .oid = undefined, .status = null } };

    line += 4;
    len -= 4;

    if (len < hash.hexLen(repo_opts.hash)) {
        return error.InvalidPacket;
    }
    pkt.ack.oid = line[0..comptime hash.hexLen(repo_opts.hash)].*;

    line += hash.hexLen(repo_opts.hash);
    len -= hash.hexLen(repo_opts.hash);

    if (len > 0 and line[0] == ' ') {
        line += 1;
        len -= 1;

        pkt.ack.status =
            if (std.mem.startsWith(u8, line[0..len], "continue"))
                .cont
            else if (std.mem.startsWith(u8, line[0..len], "common"))
                .common
            else if (std.mem.startsWith(u8, line[0..len], "ready"))
                .ready
            else
                return error.InvalidPacket;
    }

    return pkt;
}

fn errPkt(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    allocator: std.mem.Allocator,
    content: []const u8,
) !Pkt(repo_kind, repo_opts) {
    var line = content.ptr;
    var len = content.len;

    line += 4;
    len -= 4;

    const err = try allocator.dupe(u8, line[0..len]);
    errdefer allocator.free(err);
    return .{ .err = err };
}

fn commentPkt(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    allocator: std.mem.Allocator,
    line: []const u8,
) !Pkt(repo_kind, repo_opts) {
    const comment = try allocator.dupe(u8, line);
    errdefer allocator.free(comment);
    return .{ .comment = comment };
}

fn okPkt(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    allocator: std.mem.Allocator,
    content: []const u8,
) !Pkt(repo_kind, repo_opts) {
    var line = content.ptr;
    var len = content.len;

    line += 3;
    len -= 3;

    if (len > 0 and line[len - 1] == '\n') {
        len -= 1;
    }
    const ok = try allocator.dupe(u8, line[0..len]);
    errdefer allocator.free(ok);
    return .{ .ok = ok };
}

fn ngPkt(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    allocator: std.mem.Allocator,
    content: []const u8,
) !Pkt(repo_kind, repo_opts) {
    var line = content.ptr;
    var len = content.len;

    line += 3;
    len -= 3;

    if (len > 0 and line[len - 1] == '\n') {
        len -= 1;
    }
    const ng = try allocator.dupe(u8, line[0..len]);
    errdefer allocator.free(ng);
    return .{ .ng = ng };
}

fn unpackPkt(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    content: []const u8,
) !Pkt(repo_kind, repo_opts) {
    return .{ .unpack = .{ .unpack_ok = std.mem.startsWith(u8, content, "unpack ok") } };
}

fn shallowPkt(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    content: []const u8,
) !Pkt(repo_kind, repo_opts) {
    var line = content.ptr;
    var len = content.len;

    line += 8;
    len -= 8;

    if (len < hash.hexLen(repo_opts.hash)) {
        return error.InvalidPacket;
    }

    return .{ .shallow = .{ .oid = line[0..comptime hash.hexLen(repo_opts.hash)].* } };
}

fn unshallowPkt(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    content: []const u8,
) !Pkt(repo_kind, repo_opts) {
    var line = content.ptr;
    var len = content.len;

    line += 10;
    len -= 10;

    if (len < hash.hexLen(repo_opts.hash)) {
        return error.InvalidPacket;
    }

    return .{ .unshallow = .{ .oid = line[0..comptime hash.hexLen(repo_opts.hash)].* } };
}

fn refPkt(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    allocator: std.mem.Allocator,
    content: []const u8,
    found_capabilities: *bool,
) !Pkt(repo_kind, repo_opts) {
    var line = content.ptr;
    var len = content.len;

    if (len < hash.hexLen(repo_opts.hash)) {
        return error.InvalidPacket;
    }
    const oid_hex = line[0..comptime hash.hexLen(repo_opts.hash)];

    line += hash.hexLen(repo_opts.hash);
    len -= hash.hexLen(repo_opts.hash);

    if (!std.mem.startsWith(u8, line[0..len], " ")) {
        return error.InvalidPacket;
    }

    line += 1;
    len -= 1;

    if (0 == len) {
        return error.InvalidPacket;
    }

    if (line[len - 1] == '\n') {
        len -= 1;
    }

    const line_slice = line[0..len];

    const head_name = try allocator.dupe(u8, std.mem.sliceTo(line_slice, 0));
    errdefer allocator.free(head_name);

    var head = net.RemoteHead(repo_kind, repo_opts).init(head_name);
    head.oid = oid_hex.*;

    var caps_maybe: ?[]const u8 = null;
    errdefer if (caps_maybe) |caps| allocator.free(caps);

    if (head_name.len < len) {
        if (!found_capabilities.*) {
            caps_maybe = try allocator.dupe(u8, line_slice[head_name.len + 1 ..]);
        } else {
            return error.InvalidPacket;
        }
    }

    found_capabilities.* = true;

    return .{ .ref = .{
        .head = head,
        .capabilities = caps_maybe,
    } };
}
