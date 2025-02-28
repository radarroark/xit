const std = @import("std");
const net_wire = @import("./wire.zig");

pub const HttpState = struct {
    http_client: std.http.Client,
    request: ?std.http.Client.Request,
    sent_request: bool,

    pub fn init(allocator: std.mem.Allocator) !HttpState {
        return .{
            .http_client = std.http.Client{ .allocator = allocator },
            .request = null,
            .sent_request = false,
        };
    }

    pub fn deinit(self: *HttpState) void {
        if (self.request) |*req| {
            req.deinit();
            self.request = null;
        }
        self.http_client.deinit();

        close(self);
    }

    pub fn close(_: *HttpState) void {}
};

pub const HttpStream = struct {
    wire_state: *HttpState,
    service: *const HttpInfo,
    url: []const u8,

    pub fn init(
        wire_state: *HttpState,
        url: []const u8,
        wire_action: net_wire.WireAction,
    ) !HttpStream {
        const service = switch (wire_action) {
            .list_upload_pack => &upload_pack_ls_info,
            .list_receive_pack => &receive_pack_ls_info,
            .upload_pack => &upload_pack_info,
            .receive_pack => &receive_pack_info,
        };

        return .{
            .service = service,
            .wire_state = wire_state,
            .url = url,
        };
    }

    pub fn deinit(_: *HttpStream) void {}

    pub fn write(
        self: *HttpStream,
        allocator: std.mem.Allocator,
        buffer: [*]const u8,
        len: usize,
    ) !void {
        if (self.wire_state.request) |*req| {
            try req.writeAll(buffer[0..len]);
        } else {
            var request = try HttpRequest.init(allocator, self, len);
            defer request.deinit(allocator);

            var req = try writeBuffer(&self.wire_state.http_client, &request, buffer[0..len]);
            errdefer req.deinit();
            self.wire_state.request = req;
        }
    }

    pub fn read(
        self: *HttpStream,
        allocator: std.mem.Allocator,
        buffer: [*]u8,
        buffer_size: usize,
    ) !usize {
        return switch (self.service.method) {
            .GET => try self.readGet(allocator, buffer, buffer_size),
            .POST => try self.readPost(allocator, buffer, buffer_size),
            else => error.UnexpectedHttpMethod,
        };
    }

    fn readGet(
        self: *HttpStream,
        allocator: std.mem.Allocator,
        buffer: [*]u8,
        buffer_size: usize,
    ) !usize {
        var complete = false;

        var request = try HttpRequest.init(allocator, self, 0);
        defer request.deinit(allocator);

        var response = HttpResponse{
            .status = undefined,
            .content_type = null,
            .location = null,
        };
        defer response.deinit(allocator);

        const body = try readBuffer(allocator, &self.wire_state.http_client, &request, &response);
        defer allocator.free(body);

        try handleResponse(&complete, self, &response, true);

        if (body.len > buffer_size) return error.BufferTooSmall;
        @memcpy(buffer[0..body.len], body);

        return body.len;
    }

    fn readPost(
        self: *HttpStream,
        allocator: std.mem.Allocator,
        buffer: [*]u8,
        buffer_size: usize,
    ) !usize {
        var out_len: usize = 0;

        if (self.wire_state.request) |*req| {
            if (!self.wire_state.sent_request) {
                try req.finish();
                try req.wait();
                self.wire_state.sent_request = true;
            }

            var response = HttpResponse{
                .status = undefined,
                .content_type = null,
                .location = null,
            };
            defer response.deinit(allocator);

            if (req.response.content_type) |content_type| {
                response.content_type = try allocator.dupe(u8, content_type);
            }

            if (req.response.location) |location| {
                response.location = try allocator.dupe(u8, location);
            }

            response.status = req.response.status;

            var complete = false;
            try handleResponse(&complete, self, &response, false);

            out_len = try req.reader().read(buffer[0..buffer_size]);

            if (out_len == 0) {
                req.deinit();
                self.wire_state.request = null;
                self.wire_state.sent_request = false;
            }
        }

        return out_len;
    }
};

const HttpInfo = struct {
    method: std.http.Method,
    url: []const u8,
    request_type: ?[]const u8,
    response_type: []const u8,
    chunked: bool,
};

const upload_pack_ls_info = HttpInfo{
    .method = .GET,
    .url = "/info/refs?service=git-upload-pack",
    .request_type = null,
    .response_type = "application/x-git-upload-pack-advertisement",
    .chunked = false,
};

const upload_pack_info = HttpInfo{
    .method = .POST,
    .url = "/git-upload-pack",
    .request_type = "application/x-git-upload-pack-request",
    .response_type = "application/x-git-upload-pack-result",
    .chunked = false,
};

const receive_pack_ls_info = HttpInfo{
    .method = .GET,
    .url = "/info/refs?service=git-receive-pack",
    .request_type = null,
    .response_type = "application/x-git-receive-pack-advertisement",
    .chunked = false,
};

const receive_pack_info = HttpInfo{
    .method = .POST,
    .url = "/git-receive-pack",
    .request_type = "application/x-git-receive-pack-request",
    .response_type = "application/x-git-receive-pack-result",
    .chunked = true,
};

const HttpRequest = struct {
    method: std.http.Method,
    url: []const u8,
    accept: []const u8,
    content_type: ?[]const u8,
    content_length: usize,
    chunked: bool,
    expect_continue: bool,

    fn init(
        allocator: std.mem.Allocator,
        stream: *HttpStream,
        len: usize,
    ) !HttpRequest {
        var uri = try std.Uri.parse(stream.url);
        const base_path = switch (uri.path) {
            .raw => |s| s,
            .percent_encoded => |s| s,
        };

        const path = try std.fmt.allocPrint(allocator, "{s}{s}", .{ base_path, stream.service.url });
        defer allocator.free(path);

        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();

        uri.path = .{ .percent_encoded = path };
        try uri.writeToStream(.{ .scheme = true, .authority = true, .path = true, .port = true }, buffer.writer());

        const url = try allocator.dupe(u8, buffer.items);
        errdefer allocator.free(url);

        return .{
            .method = stream.service.method,
            .url = url,
            .accept = stream.service.response_type,
            .content_type = stream.service.request_type,
            .content_length = if (stream.service.chunked) 0 else len,
            .chunked = stream.service.chunked,
            .expect_continue = false,
        };
    }

    fn deinit(self: *HttpRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.url);
    }
};

const HttpResponse = struct {
    status: std.http.Status,
    content_type: ?[]const u8,
    location: ?[]const u8,

    fn deinit(self: HttpResponse, allocator: std.mem.Allocator) void {
        if (self.content_type) |content_type| allocator.free(content_type);
        if (self.location) |location| allocator.free(location);
    }
};

fn handleResponse(
    complete: *bool,
    stream: *HttpStream,
    response: *HttpResponse,
    allow_replay: bool,
) !void {
    complete.* = false;

    const is_redirect = response.status == .moved_permanently or
        response.status == .found or
        response.status == .see_other or
        response.status == .temporary_redirect or
        response.status == .permanent_redirect;

    if (allow_replay and is_redirect) {
        if (response.location) |_| {
            return error.HttpRedirectNotImplemented;
        } else {
            return error.HttpRedirectWithoutLocation;
        }
        return;
    } else if (is_redirect) {
        return error.HttpRedirectUnexpected;
    }

    if (response.status == .unauthorized or response.status == .proxy_auth_required) {
        return error.HttpUnauthorized;
    }

    if (response.status != .ok) {
        const status_code: c_int = @intFromEnum(response.status);
        _ = status_code;
        return error.HttpStatusCodeUnexpected;
    }

    if (response.content_type) |content_type| {
        if (!std.mem.eql(u8, content_type, stream.service.response_type)) {
            return error.HttpContentTypeInvalid;
        }
    } else {
        return error.HttpContentTypeMissing;
    }

    complete.* = true;
}

fn readBuffer(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    request: *const HttpRequest,
    response: *HttpResponse,
) ![]u8 {
    const uri = try std.Uri.parse(request.url);

    var server_header_buffer: [1024]u8 = undefined;
    var req = try client.open(request.method, uri, .{
        .server_header_buffer = &server_header_buffer,
        .keep_alive = false,
    });
    defer req.deinit();

    try req.send();
    try req.wait();

    const body = try req.reader().readAllAlloc(allocator, 8192);
    errdefer allocator.free(body);

    if (req.response.content_type) |content_type| {
        response.content_type = try allocator.dupe(u8, content_type);
    }

    if (req.response.location) |location| {
        response.location = try allocator.dupe(u8, location);
    }

    response.status = req.response.status;

    return body;
}

fn writeBuffer(
    client: *std.http.Client,
    request: *const HttpRequest,
    buffer: []const u8,
) !std.http.Client.Request {
    const uri = try std.Uri.parse(request.url);

    var server_header_buffer: [1024]u8 = undefined;
    var req = try client.open(request.method, uri, .{
        .server_header_buffer = &server_header_buffer,
        .keep_alive = false,
    });
    errdefer req.deinit();

    req.transfer_encoding = if (request.chunked)
        .chunked
    else
        .{ .content_length = buffer.len };
    if (request.content_type) |content_type| {
        req.headers.content_type = .{ .override = content_type };
    }
    req.handle_continue = request.expect_continue;
    req.extra_headers = &.{
        .{ .name = "accept", .value = request.accept },
    };

    try req.send();
    try req.writeAll(buffer);

    return req;
}
