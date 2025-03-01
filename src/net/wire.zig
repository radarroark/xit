const std = @import("std");
const builtin = @import("builtin");
const net = @import("../net.zig");
const net_raw = @import("./raw.zig");
const net_http = @import("./http.zig");
const net_ssh = @import("./ssh.zig");
const net_push = @import("./push.zig");
const net_refspec = @import("./refspec.zig");
const net_pkt = @import("./pkt.zig");
const net_fetch = @import("./fetch.zig");
const net_transport = @import("./transport.zig");
const rp = @import("../repo.zig");
const obj = @import("../object.zig");
const pack = @import("../pack.zig");
const rf = @import("../ref.zig");
const hash = @import("../hash.zig");
const fs = @import("../fs.zig");

pub const Opts = struct {
    ssh: net_ssh.Opts = .{},
};

pub const WireKind = enum {
    http,
    raw,
    ssh,
};

pub const WireState = union(WireKind) {
    http: net_http.HttpState,
    raw: net_raw.RawState,
    ssh: net_ssh.SshState,

    pub fn close(self: *WireState) !void {
        switch (self.*) {
            .http => |*http| http.close(),
            .raw => |*raw| try raw.close(),
            .ssh => |*ssh| try ssh.close(),
        }
    }

    pub fn deinit(self: *WireState) void {
        switch (self.*) {
            .http => |*http| http.deinit(),
            .raw => |*raw| raw.deinit(),
            .ssh => |*ssh| ssh.deinit(),
        }
    }
};

pub const WireAction = enum {
    list_upload_pack,
    list_receive_pack,
    upload_pack,
    receive_pack,
};

pub const WireStream = union(WireKind) {
    http: net_http.HttpStream,
    raw: net_raw.RawStream,
    ssh: net_ssh.SshStream,

    pub fn initMaybe(
        allocator: std.mem.Allocator,
        wire_state: *WireState,
        url: []const u8,
        wire_action: WireAction,
    ) !?WireStream {
        return switch (wire_state.*) {
            .http => |*http| .{ .http = try net_http.HttpStream.init(http, url, wire_action) },
            .raw => |*raw| if (try net_raw.RawStream.initMaybe(allocator, raw, url, wire_action)) |stream| .{ .raw = stream } else null,
            .ssh => |*ssh| if (try net_ssh.SshStream.initMaybe(ssh, url, wire_action)) |stream| .{ .ssh = stream } else null,
        };
    }

    pub fn read(
        self: *WireStream,
        allocator: std.mem.Allocator,
        buffer: [*]u8,
        buf_size: usize,
    ) !usize {
        return switch (self.*) {
            .http => |*http| try http.read(allocator, buffer, buf_size),
            .raw => |*raw| try raw.read(buffer, buf_size),
            .ssh => |*ssh| try ssh.read(buffer, buf_size),
        };
    }

    pub fn write(
        self: *WireStream,
        allocator: std.mem.Allocator,
        buffer: [*]const u8,
        len: usize,
    ) !void {
        switch (self.*) {
            .http => |*http| try http.write(allocator, buffer, len),
            .raw => |*raw| try raw.write(buffer, len),
            .ssh => |*ssh| try ssh.write(buffer, len),
        }
    }

    pub fn deinit(self: *WireStream, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .http => |*http| http.deinit(),
            .raw => |*raw| raw.deinit(allocator),
            .ssh => |*ssh| ssh.deinit(),
        }
    }
};

pub fn Buffer(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        len: usize,
        data: [repo_opts.net_read_size]u8,

        fn consume(self: *Buffer(repo_kind, repo_opts), end: [*c]const u8) void {
            if (@intFromPtr(end) > @intFromPtr(&self.data) and
                @intFromPtr(end) <= @intFromPtr(&self.data) + self.len)
            {
                const consumed = @intFromPtr(end) - @intFromPtr(&self.data);
                const new_len = self.len - consumed;
                std.mem.copyForwards(u8, self.data[0..new_len], end[0..new_len]);
                self.data[new_len] = '\x00';
                self.len = new_len;
            }
        }

        fn remain(self: *const Buffer(repo_kind, repo_opts)) usize {
            return if (self.len > self.data.len) 0 else self.data.len - self.len;
        }

        fn offset(self: *const Buffer(repo_kind, repo_opts)) [*]u8 {
            return @ptrFromInt(@intFromPtr(&self.data) + self.len);
        }

        fn increase(self: *Buffer(repo_kind, repo_opts), len: usize) void {
            self.len += len;
        }
    };
}

pub fn WireTransport(comptime repo_kind: rp.RepoKind, comptime repo_opts: rp.RepoOpts(repo_kind)) type {
    return struct {
        wire_state: *WireState,
        wire_stream: ?WireStream,
        url: ?[]u8,
        direction: net.Direction,
        caps: Capabilities,
        refs: std.ArrayListUnmanaged(net_pkt.Ref(repo_kind, repo_opts)),
        heads: std.ArrayListUnmanaged(net.RemoteHead(repo_kind, repo_opts)),
        common: std.ArrayListUnmanaged(net_pkt.Pkt(repo_kind, repo_opts)),
        is_stateless: bool,
        have_refs: bool,
        connected: bool,
        buffer: Buffer(repo_kind, repo_opts),
        opts: net_transport.Opts,

        pub fn init(
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            allocator: std.mem.Allocator,
            wire_kind: WireKind,
            opts: net_transport.Opts,
        ) !WireTransport(repo_kind, repo_opts) {
            const wire_state = try allocator.create(WireState);
            errdefer allocator.destroy(wire_state);
            wire_state.* = switch (wire_kind) {
                .http => .{ .http = try net_http.HttpState.init(allocator) },
                .raw => .{ .raw = net_raw.RawState.init() },
                .ssh => .{ .ssh = try net_ssh.SshState.init(repo_kind, repo_opts, state, allocator, opts.wire.ssh) },
            };
            errdefer wire_state.deinit();

            return .{
                .wire_state = wire_state,
                .wire_stream = null,
                .url = null,
                .direction = .fetch,
                .caps = .{},
                .refs = std.ArrayListUnmanaged(net_pkt.Ref(repo_kind, repo_opts)){},
                .heads = std.ArrayListUnmanaged(net.RemoteHead(repo_kind, repo_opts)){},
                .common = std.ArrayListUnmanaged(net_pkt.Pkt(repo_kind, repo_opts)){},
                .is_stateless = switch (wire_kind) {
                    .http => true,
                    .raw => false,
                    .ssh => false,
                },
                .have_refs = false,
                .connected = false,
                .buffer = .{
                    .len = 0,
                    .data = [_]u8{0} ** repo_opts.net_read_size,
                },
                .opts = opts,
            };
        }

        pub fn deinit(self: *WireTransport(repo_kind, repo_opts), allocator: std.mem.Allocator) void {
            self.close(allocator) catch {};

            self.wire_state.deinit();
            allocator.destroy(self.wire_state);

            self.heads.deinit(allocator);

            for (self.refs.items) |*ref| {
                ref.deinit(allocator);
            }
            self.refs.deinit(allocator);

            self.common.deinit(allocator);
        }

        pub fn connect(
            self: *WireTransport(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
            url: []const u8,
            direction: net.Direction,
        ) !void {
            try self.closeWireState(allocator);

            const url_dupe = try allocator.dupe(u8, url);
            self.url = url_dupe;

            self.direction = direction;

            const action: WireAction = switch (direction) {
                .fetch => .list_upload_pack,
                .push => .list_receive_pack,
            };

            if (try WireStream.initMaybe(allocator, self.wire_state, url_dupe, action)) |stream| {
                self.clearStream(allocator);
                self.wire_stream = stream;
            }

            try self.addRefs(allocator, if (self.is_stateless) 2 else 1);

            self.have_refs = true;

            var first_ref = if (self.refs.items.len > 0) self.refs.items[0] else return error.InvalidRefs;

            var symrefs = std.ArrayList(net_refspec.RefSpec).init(allocator);
            defer {
                for (symrefs.items) |*spec| {
                    spec.deinit(allocator);
                }
                symrefs.deinit();
            }

            self.caps = try Capabilities.init(allocator, if (first_ref.capabilities) |caps| caps else null, &symrefs);

            if (1 == self.refs.items.len and
                !std.mem.eql(u8, first_ref.head.name, "capabilities^{}") and
                std.mem.allEqual(u8, &first_ref.head.oid, '0'))
            {
                for (self.refs.items) |*ref| {
                    ref.deinit(allocator);
                }
                self.refs.clearAndFree(allocator);
            }

            try self.updateHeads(allocator, &symrefs);

            if (self.is_stateless) {
                self.clearStream(allocator);
            }

            self.connected = true;
        }

        pub fn capabilities(self: *const WireTransport(repo_kind, repo_opts)) net_transport.Capabilities {
            return .{
                .fetch_by_oid = self.caps.allow_tip_sha1_in_want,
                .fetch_reachable = self.caps.allow_reachable_sha1_in_want,
                .push_options = self.caps.push_options,
            };
        }

        pub fn getHeads(self: *const WireTransport(repo_kind, repo_opts)) ![]net.RemoteHead(repo_kind, repo_opts) {
            if (!self.have_refs) {
                return error.RefsNotLoaded;
            }

            return self.heads.items;
        }

        pub fn push(
            self: *WireTransport(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
            git_push: *net_push.Push(repo_kind, repo_opts),
        ) !void {
            var need_pack = false;
            for (git_push.specs.items) |*spec| {
                if (spec.refspec.src.len > 0) {
                    need_pack = true;
                    break;
                }
            }

            if (.push != self.direction) {
                return error.InvalidDirection;
            }

            if (try WireStream.initMaybe(allocator, self.wire_state, self.url orelse return error.NotConnected, .receive_pack)) |stream| {
                self.clearStream(allocator);
                self.wire_stream = stream;
            }

            const stream = &(self.wire_stream orelse return error.StreamNotFound);

            var buffer = std.ArrayList(u8).init(allocator);
            defer buffer.deinit();

            try pktline(&buffer, git_push.specs.items);
            try stream.write(allocator, buffer.items.ptr, buffer.items.len);

            if (need_pack) {
                const obj_iter: *obj.ObjectIterator(repo_kind, repo_opts, .raw) = &git_push.obj_iter;

                var pack_writer = try pack.PackObjectWriter(repo_kind, repo_opts).init(allocator, obj_iter);
                defer pack_writer.deinit();

                var read_buffer = [_]u8{0} ** repo_opts.read_size;
                while (true) {
                    const size = try pack_writer.read(&read_buffer);
                    if (size == 0) {
                        break;
                    }
                    try stream.write(allocator, &read_buffer, size);
                }
            }

            if (0 == git_push.specs.items.len) {
                git_push.unpack_ok = true;
            } else {
                try self.handlePushPkts(allocator, git_push);
            }
        }

        pub fn negotiateFetch(
            self: *WireTransport(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_only),
            allocator: std.mem.Allocator,
            fetch_data: *const net_fetch.FetchNegotiation(repo_kind, repo_opts),
        ) !void {
            self.caps.shallow = false;

            var buffer = std.ArrayList(u8).init(allocator);
            defer buffer.deinit();

            try net_pkt.bufferWants(repo_kind, repo_opts, allocator, fetch_data, &self.caps, &buffer);

            var obj_iter = try obj.ObjectIterator(repo_kind, repo_opts, .raw).init(allocator, state, .{ .recursive = true });
            defer obj_iter.deinit();

            {
                var tags = try rf.RefList.init(repo_kind, repo_opts, state, allocator, .tag);
                defer tags.deinit();

                for (tags.refs.values()) |ref| {
                    if (try rf.readRecur(repo_kind, repo_opts, state, .{ .ref = ref })) |*oid| {
                        try obj_iter.include(oid);
                    }
                }

                var heads = try rf.RefList.init(repo_kind, repo_opts, state, allocator, .head);
                defer heads.deinit();

                for (heads.refs.values()) |ref| {
                    if (try rf.readRecur(repo_kind, repo_opts, state, .{ .ref = ref })) |*oid| {
                        try obj_iter.include(oid);
                    }
                }
            }

            var i: usize = 0;
            while (i < 256) {
                const object = try obj_iter.next() orelse break;
                defer object.deinit();
                try net_pkt.bufferHave(repo_kind, repo_opts, &object.oid, &buffer);

                i += 1;
                if (i % 20 == 0) {
                    try buffer.appendSlice("0000");

                    try self.negotiationStep(allocator, buffer.items);

                    buffer.clearAndFree();

                    if (self.caps.multi_ack or self.caps.multi_ack_detailed) {
                        while (true) {
                            var pkt = try self.recvPkt(allocator);
                            if (pkt != .ack) {
                                pkt.deinit(allocator);
                                return;
                            } else {
                                errdefer pkt.deinit(allocator);
                                try self.common.append(allocator, pkt);
                            }
                        }
                    } else {
                        var pkt = try self.recvPkt(allocator);
                        defer pkt.deinit(allocator);

                        switch (pkt) {
                            .ack => break,
                            .nak => continue,
                            else => return error.UnexpectedPktType,
                        }
                    }
                }

                if (self.common.items.len > 0) {
                    break;
                }

                if (i % 20 == 0 and self.is_stateless) {
                    try net_pkt.bufferWants(repo_kind, repo_opts, allocator, fetch_data, &self.caps, &buffer);

                    for (self.common.items) |*pkt| {
                        try net_pkt.bufferHave(repo_kind, repo_opts, &pkt.ack.oid, &buffer);
                    }
                }
            }

            if (self.is_stateless and self.common.items.len > 0) {
                try net_pkt.bufferWants(repo_kind, repo_opts, allocator, fetch_data, &self.caps, &buffer);

                for (self.common.items) |*pkt| {
                    try net_pkt.bufferHave(repo_kind, repo_opts, &pkt.ack.oid, &buffer);
                }
            }

            try buffer.appendSlice("0009done\n");

            try self.negotiationStep(allocator, buffer.items);

            if (!self.caps.multi_ack and !self.caps.multi_ack_detailed) {
                var pkt = try self.recvPkt(allocator);
                defer pkt.deinit(allocator);

                switch (pkt) {
                    .ack, .nak => {},
                    else => return error.UnexpectedPktType,
                }
            } else {
                try self.waitAck(allocator);
            }
        }

        fn pktline(buffer: *std.ArrayList(u8), specs: []net_push.PushSpec(repo_kind, repo_opts)) !void {
            for (specs, 0..) |*spec, i| {
                var len: usize = spec.refspec.dst.len + 7;

                const report_status = "report-status";
                const side_band_64k = "side-band-64k";

                if (i == 0) {
                    len += 1;

                    len += report_status.len + 1;

                    len += side_band_64k.len + 1;
                }

                const old_id_len = spec.roid.len;
                const new_id_len = spec.loid.len;

                len += (old_id_len + new_id_len);

                var command_size_buf = [_]u8{'0'} ** 4;
                try net_pkt.commandSize(&command_size_buf, len);

                try buffer.writer().print("{s}{s} {s} {s}", .{ &command_size_buf, &spec.roid, &spec.loid, spec.refspec.dst });

                if (i == 0) {
                    try buffer.append('\x00');
                    try buffer.appendSlice(" " ++ report_status);
                    try buffer.appendSlice(" " ++ side_band_64k);
                }

                try buffer.append('\n');
            }

            try buffer.appendSlice("0000");
        }

        fn negotiationStep(
            self: *WireTransport(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
            buffer: []const u8,
        ) !void {
            if (.fetch != self.direction) {
                return error.InvalidDirection;
            }

            if (try WireStream.initMaybe(allocator, self.wire_state, self.url orelse return error.NotConnected, .upload_pack)) |stream| {
                self.clearStream(allocator);
                self.wire_stream = stream;
            }

            if (self.wire_stream) |*stream| {
                try stream.write(allocator, buffer.ptr, buffer.len);
            }
        }

        pub fn downloadPack(
            self: *WireTransport(repo_kind, repo_opts),
            state: rp.Repo(repo_kind, repo_opts).State(.read_write),
            allocator: std.mem.Allocator,
        ) !void {
            const dir = switch (repo_kind) {
                .git => state.core.git_dir,
                .xit => state.core.xit_dir,
            };
            const temp_pack_name = "temp.pack";

            // receive pack file
            {
                var temp_pack = try fs.LockFile.init(dir, temp_pack_name);
                defer temp_pack.deinit();

                if (!self.caps.side_band and !self.caps.side_band_64k) {
                    while (true) {
                        try temp_pack.lock_file.writeAll(self.buffer.data[0..self.buffer.len]);

                        self.buffer.len = 0;
                        self.buffer.data[0] = 0;

                        const recvd = try self.recv(allocator);
                        if (recvd == 0) {
                            break;
                        }
                    }
                } else {
                    while (true) {
                        var pkt = try self.recvPkt(allocator);
                        defer pkt.deinit(allocator);

                        switch (pkt) {
                            .progress => |progress| if (self.opts.progress_text) |progress_text| {
                                try progress_text(progress);
                            },
                            .data => |data| if (data.len > 0) {
                                try temp_pack.lock_file.writeAll(data);
                            },
                            .flush => break,
                            else => {},
                        }
                    }
                }

                temp_pack.success = true;
            }

            // iterate over pack file
            {
                defer dir.deleteFile(temp_pack_name) catch {};
                const pack_file_path = try dir.realpathAlloc(allocator, temp_pack_name);
                defer allocator.free(pack_file_path);
                var pack_iter = try pack.PackObjectIterator(repo_kind, repo_opts).init(allocator, pack_file_path);
                defer pack_iter.deinit();
                try obj.copyFromPackObjectIterator(repo_kind, repo_opts, state, allocator, &pack_iter, self.opts.progress_text);
            }
        }

        fn recv(
            self: *WireTransport(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
        ) !usize {
            if (self.buffer.remain() == 0) {
                return error.OutOfBufferSpace;
            }

            const wire_stream = &(self.wire_stream orelse return error.StreamNotFound);

            const bytes_read = try wire_stream.read(allocator, self.buffer.offset(), self.buffer.remain());

            std.debug.assert(bytes_read <= self.buffer.remain());

            self.buffer.increase(bytes_read);

            return bytes_read;
        }

        fn addRefs(
            self: *WireTransport(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
            flushes: c_int,
        ) !void {
            for (self.refs.items) |*ref| {
                ref.deinit(allocator);
            }
            self.refs.clearAndFree(allocator);

            var flush: c_int = 0;
            var found_capabilities = false;
            var bufptr_maybe: ?[*]const u8 = null;
            while (true) {
                var pkt_maybe: ?net_pkt.Pkt(repo_kind, repo_opts) = null;
                if (self.buffer.len > 0) {
                    pkt_maybe = try net_pkt.Pkt(repo_kind, repo_opts).initMaybe(allocator, self.buffer.data[0..self.buffer.len], &found_capabilities, &bufptr_maybe);
                }

                if (pkt_maybe) |*pkt| {
                    const bufptr = bufptr_maybe orelse return error.BufPtrNotSet;
                    self.buffer.consume(bufptr);

                    switch (pkt.*) {
                        .err => {
                            pkt.deinit(allocator);
                            return error.ServerReportedError;
                        },
                        .flush => {
                            flush += 1;
                            pkt.deinit(allocator);
                        },
                        .ref => |*ref| {
                            errdefer ref.deinit(allocator);
                            try self.refs.append(allocator, ref.*);
                        },
                        else => pkt.deinit(allocator),
                    }

                    if (flush < flushes) {
                        continue;
                    } else {
                        break;
                    }
                } else {
                    const recvd = try self.recv(allocator);

                    if (recvd == 0) {
                        return error.CouldNotReadRefsFromRemoteRepo;
                    }
                }
            }
        }

        fn recvPkt(
            self: *WireTransport(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
        ) !net_pkt.Pkt(repo_kind, repo_opts) {
            var found_capabilities = true;
            var bufptr_maybe: ?[*]const u8 = null;

            while (true) {
                if (self.buffer.len > 0) {
                    if (try net_pkt.Pkt(repo_kind, repo_opts).initMaybe(allocator, self.buffer.data[0..self.buffer.len], &found_capabilities, &bufptr_maybe)) |pkt| {
                        const bufptr = bufptr_maybe orelse return error.BufPtrNotSet;
                        self.buffer.consume(bufptr);
                        return pkt;
                    }
                }

                const bytes_read = try self.recv(allocator);
                if (bytes_read == 0) {
                    return error.CouldNotReadFromRemoteRepo;
                }
            }
        }

        fn waitAck(
            self: *WireTransport(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
        ) !void {
            while (true) {
                var pkt = try self.recvPkt(allocator);
                defer pkt.deinit(allocator);

                switch (pkt) {
                    .nak => break,
                    .ack => |ack| if (ack.status == null) {
                        break;
                    },
                    else => {},
                }
            }
        }

        pub fn isConnected(self: *const WireTransport(repo_kind, repo_opts)) bool {
            return self.connected;
        }

        pub fn close(
            self: *WireTransport(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
        ) !void {
            const action: WireAction = switch (self.direction) {
                .fetch => .upload_pack,
                .push => .receive_pack,
            };

            const flush = "0000";
            if (self.connected and !self.is_stateless) {
                if (WireStream.initMaybe(allocator, self.wire_state, self.url orelse return error.NotConnected, action)) |stream_maybe| {
                    if (stream_maybe) |stream| {
                        self.wire_stream = stream;
                    }
                    if (self.wire_stream) |*stream| {
                        stream.write(allocator, flush, flush.len) catch {};
                    }
                } else |_| {}
            }

            self.clearStream(allocator);
            try self.closeWireState(allocator);

            for (self.common.items) |*pkt| {
                pkt.deinit(allocator);
            }
            self.common.clearAndFree(allocator);

            self.connected = false;
        }

        fn clearStream(self: *WireTransport(repo_kind, repo_opts), allocator: std.mem.Allocator) void {
            if (self.wire_stream) |*wire_stream| {
                wire_stream.deinit(allocator);
                self.wire_stream = null;
            }
        }

        fn closeWireState(self: *WireTransport(repo_kind, repo_opts), allocator: std.mem.Allocator) !void {
            if (self.url) |url| {
                allocator.free(url);
                self.url = null;
            }
            try self.wire_state.close();
        }

        fn updateHeads(self: *WireTransport(repo_kind, repo_opts), allocator: std.mem.Allocator, symrefs: *std.ArrayList(net_refspec.RefSpec)) !void {
            self.heads.clearAndFree(allocator);

            for (self.refs.items) |*ref| {
                var buffer = std.ArrayList(u8).init(allocator);
                defer buffer.deinit();

                for (symrefs.items) |*spec| {
                    buffer.clearAndFree();
                    if (net_refspec.matches(spec.src, ref.head.name)) {
                        try net_refspec.transform(&buffer, spec, ref.head.name);
                        if (ref.head.symref) |target| allocator.free(target);
                        ref.head.symref = try allocator.dupe(u8, buffer.items);
                    }
                }

                try self.heads.append(allocator, ref.head);
            }
        }

        fn handlePushPkts(
            self: *WireTransport(repo_kind, repo_opts),
            allocator: std.mem.Allocator,
            git_push: *net_push.Push(repo_kind, repo_opts),
        ) !void {
            var found_capabilities = false;
            var bufptr_maybe: ?[*]const u8 = null;

            while (true) {
                var pkt_maybe: ?net_pkt.Pkt(repo_kind, repo_opts) = null;

                if (self.buffer.len > 0) {
                    pkt_maybe = try net_pkt.Pkt(repo_kind, repo_opts).initMaybe(allocator, self.buffer.data[0..self.buffer.len], &found_capabilities, &bufptr_maybe);
                }

                if (pkt_maybe) |*pkt| {
                    defer pkt.deinit(allocator);

                    const bufptr = bufptr_maybe orelse return error.BufPtrNotSet;
                    self.buffer.consume(bufptr);

                    var iter_over = false;

                    switch (pkt.*) {
                        .data => |data| try handlePushSidebandPkt(allocator, git_push, data),
                        .err => return error.ServerReportedError,
                        .progress => |progress| if (self.opts.progress_text) |progress_text| {
                            try progress_text(progress);
                        },
                        else => iter_over = try handlePushPkt(git_push, pkt),
                    }

                    if (iter_over) {
                        return;
                    }
                } else {
                    const recvd = try self.recv(allocator);

                    if (recvd == 0) {
                        return error.CouldNotReadFromRemoteRepo;
                    }
                }
            }
        }

        fn handlePushPkt(
            git_push: *net_push.Push(repo_kind, repo_opts),
            pkt: *net_pkt.Pkt(repo_kind, repo_opts),
        ) !bool {
            switch (pkt.*) {
                .ok, .ng => {},
                .unpack => |unpack| git_push.unpack_ok = unpack.unpack_ok,
                .flush => return true,
                else => return error.ProtocolError,
            }
            return false;
        }

        fn handlePushSidebandPkt(
            allocator: std.mem.Allocator,
            git_push: *net_push.Push(repo_kind, repo_opts),
            data_pkt: []const u8,
        ) !void {
            var line = data_pkt.ptr;
            var line_len = data_pkt.len;
            var found_capabilities = false;
            var bufptr_maybe: ?[*]const u8 = null;

            while (line_len > 0) {
                var pkt = try net_pkt.Pkt(repo_kind, repo_opts).initMaybe(allocator, line[0..line_len], &found_capabilities, &bufptr_maybe) orelse return;
                defer pkt.deinit(allocator);

                const bufptr = bufptr_maybe orelse return error.BufPtrNotSet;
                line_len -= (@intFromPtr(bufptr) - @intFromPtr(line));
                line = bufptr;

                _ = try handlePushPkt(git_push, &pkt);
            }
        }
    };
}

pub const Capabilities = struct {
    allow_tip_sha1_in_want: bool = false,
    allow_reachable_sha1_in_want: bool = false,
    push_options: bool = false,
    ofs_delta: bool = false,
    multi_ack: bool = false,
    multi_ack_detailed: bool = false,
    side_band: bool = false,
    side_band_64k: bool = false,
    include_tag: bool = false,
    delete_refs: bool = false,
    report_status: bool = false,
    thin_pack: bool = false,
    shallow: bool = false,
    common: bool = false,

    fn init(allocator: std.mem.Allocator, caps_str: ?[]const u8, symrefs: *std.ArrayList(net_refspec.RefSpec)) !Capabilities {
        var caps = Capabilities{};
        var ptr = caps_str orelse return caps;

        while (ptr.len > 0) {
            if (ptr[0] == ' ') {
                ptr = ptr[1..];
            }

            if (std.mem.startsWith(u8, ptr, "ofs-delta")) {
                caps.ofs_delta = true;
                caps.common = true;
                ptr = ptr["ofs-delta".len..];
            } else if (std.mem.startsWith(u8, ptr, "multi_ack_detailed")) {
                caps.multi_ack_detailed = true;
                caps.common = true;
                ptr = ptr["multi_ack_detailed".len..];
            } else if (std.mem.startsWith(u8, ptr, "multi_ack")) {
                caps.multi_ack = true;
                caps.common = true;
                ptr = ptr["multi_ack".len..];
            } else if (std.mem.startsWith(u8, ptr, "include-tag")) {
                caps.include_tag = true;
                caps.common = true;
                ptr = ptr["include-tag".len..];
            } else if (std.mem.startsWith(u8, ptr, "side-band-64k")) {
                caps.side_band_64k = true;
                caps.common = true;
                ptr = ptr["side-band-64k".len..];
            } else if (std.mem.startsWith(u8, ptr, "side-band")) {
                caps.side_band = true;
                caps.common = true;
                ptr = ptr["side-band".len..];
            } else if (std.mem.startsWith(u8, ptr, "delete-refs")) {
                caps.delete_refs = true;
                caps.common = true;
                ptr = ptr["delete-refs".len..];
            } else if (std.mem.startsWith(u8, ptr, "push-options")) {
                caps.push_options = true;
                caps.common = true;
                ptr = ptr["push-options".len..];
            } else if (std.mem.startsWith(u8, ptr, "thin-pack")) {
                caps.thin_pack = true;
                caps.common = true;
                ptr = ptr["thin-pack".len..];
            } else if (std.mem.startsWith(u8, ptr, "symref")) {
                ptr = ptr["symref".len..];

                if (ptr[0] != '=') {
                    return error.InvalidSymref;
                }
                ptr = ptr[1..];

                const end = std.mem.indexOfScalar(u8, ptr, ' ') orelse std.mem.indexOfScalar(u8, ptr, '\x00') orelse return error.InvalidSymref;

                var spec = try net_refspec.RefSpec.init(allocator, ptr[0..end], .fetch);
                errdefer spec.deinit(allocator);

                try symrefs.append(spec);

                ptr = ptr[end..];
            } else if (std.mem.startsWith(u8, ptr, "allow-tip-sha1-in-want")) {
                caps.allow_tip_sha1_in_want = true;
                caps.common = true;
                ptr = ptr["allow-tip-sha1-in-want".len..];
            } else if (std.mem.startsWith(u8, ptr, "allow-reachable-sha1-in-want")) {
                caps.allow_reachable_sha1_in_want = true;
                caps.common = true;
                ptr = ptr["allow-reachable-sha1-in-want".len..];
            } else if (std.mem.startsWith(u8, ptr, "object-format=")) {
                ptr = ptr["object-format=".len..];
            } else if (std.mem.startsWith(u8, ptr, "agent=")) {
                ptr = ptr["agent=".len..];
            } else if (std.mem.startsWith(u8, ptr, "shallow")) {
                caps.shallow = true;
                caps.common = true;
                ptr = ptr["shallow".len..];
            }

            if (std.mem.indexOfScalar(u8, ptr, ' ')) |idx| {
                ptr = ptr[idx..];
            } else {
                break;
            }
        }

        return caps;
    }
};
