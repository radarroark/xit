const std = @import("std");
const rp = @import("./repo.zig");
const io = @import("./io.zig");

pub const AddConfigInput = struct {
    name: []const u8,
    value: []const u8,
};

pub const RemoveConfigInput = struct {
    name: []const u8,
};

pub const ConfigCommand = union(enum) {
    list,
    add: AddConfigInput,
    remove: RemoveConfigInput,
};

pub fn Config(comptime repo_kind: rp.RepoKind) type {
    return struct {
        allocator: std.mem.Allocator,
        arena: *std.heap.ArenaAllocator,
        sections: std.StringArrayHashMap(Variables),

        const Variables = std.StringArrayHashMap([]const u8);

        pub fn init(core_cursor: rp.Repo(repo_kind).CoreCursor, allocator: std.mem.Allocator) !Config(repo_kind) {
            var arena = try allocator.create(std.heap.ArenaAllocator);
            arena.* = std.heap.ArenaAllocator.init(allocator);
            errdefer {
                arena.deinit();
                allocator.destroy(arena);
            }

            var sections = std.StringArrayHashMap(Variables).init(arena.allocator());

            var current_section_name_maybe: ?[]const u8 = null;
            var current_variables = Variables.init(arena.allocator());

            switch (repo_kind) {
                .git => {
                    // categories of characters parsed in the config file
                    const CharKind = enum {
                        whitespace,
                        comment,
                        open_bracket,
                        close_bracket,
                        equals,
                        other,

                        fn init(rune: []const u8) @This() {
                            return if (rune.len == 1)
                                switch (rune[0]) {
                                    ' ', '\t' => .whitespace,
                                    '#' => .comment,
                                    '[' => .open_bracket,
                                    ']' => .close_bracket,
                                    '=' => .equals,
                                    else => .other,
                                }
                            else
                                .other;
                        }
                    };

                    // represents a line fully parsed from the config file
                    const ParsedLine = union(enum) {
                        empty,
                        section_header: []const u8,
                        variable: struct {
                            name: []const u8,
                            value: []const u8,
                        },
                        invalid,

                        const SectionHeaderPattern = [_]CharKind{
                            .open_bracket,
                            .other,
                            .close_bracket,
                        };

                        const VariablePattern = [_]CharKind{
                            .other,
                            .equals,
                            .other,
                        };

                        fn init(char_kinds: []CharKind, tokens: []const []const u8) @This() {
                            if (char_kinds.len == 0) {
                                return .empty;
                            } else if (std.mem.eql(CharKind, &SectionHeaderPattern, char_kinds)) {
                                return .{ .section_header = tokens[1] };
                            } else if (std.mem.eql(CharKind, &VariablePattern, char_kinds)) {
                                return .{ .variable = .{ .name = tokens[0], .value = tokens[2] } };
                            } else {
                                return .invalid;
                            }
                        }
                    };

                    var config_file = try core_cursor.core.git_dir.createFile("config", .{ .read = true, .truncate = false });
                    defer config_file.close();

                    const reader = config_file.reader();
                    var buf = [_]u8{0} ** 1024;

                    // for each line...
                    while (try reader.readUntilDelimiterOrEof(&buf, '\n')) |line| {
                        const text = try std.unicode.Utf8View.init(line);
                        var iter = text.iterator();
                        var next_cursor: usize = 0;

                        var token_kinds = std.ArrayList(CharKind).init(allocator);
                        defer token_kinds.deinit();

                        var token_ranges = std.ArrayList(struct { start: usize, end: usize }).init(allocator);
                        defer token_ranges.deinit();

                        var current_token_maybe: ?struct { kind: CharKind, start: usize } = null;

                        // for each codepoint...
                        while (iter.nextCodepointSlice()) |rune| {
                            const char_kind = CharKind.init(rune);

                            const cursor = next_cursor;
                            next_cursor += rune.len;

                            if (current_token_maybe) |*current_token| {
                                if (current_token.kind == char_kind or current_token.kind == .comment) {
                                    // this rune goes in the current token because either
                                    // its char kind is the same, or it's a comment
                                    // (comments go until the end of the line)
                                    continue;
                                } else {
                                    switch (current_token.kind) {
                                        .whitespace, .comment => {},
                                        else => {
                                            // the char kind changed, so save the current token
                                            try token_kinds.append(current_token.kind);
                                            try token_ranges.append(.{ .start = current_token.start, .end = cursor });
                                        },
                                    }
                                }
                            }

                            // change the current token. this happens if the char kind changed,
                            // or if current token is null (the very beginning of the line)
                            current_token_maybe = .{ .kind = char_kind, .start = cursor };
                        }

                        // add the last token if necessary
                        if (current_token_maybe) |current_token| {
                            switch (current_token.kind) {
                                .whitespace, .comment => {},
                                else => {
                                    try token_kinds.append(current_token.kind);
                                    try token_ranges.append(.{ .start = current_token.start, .end = next_cursor });
                                },
                            }
                        }

                        // get all the tokens from the line using the ranges
                        var tokens = std.ArrayList([]const u8).init(arena.allocator());
                        for (token_ranges.items) |range| {
                            try tokens.append(try arena.allocator().dupe(u8, line[range.start..range.end]));
                        }

                        // parse the lines and update the sections/variables
                        const parsed_line = ParsedLine.init(token_kinds.items, tokens.items);
                        switch (parsed_line) {
                            .empty => {},
                            .section_header => {
                                if (current_section_name_maybe) |current_section_name| {
                                    try sections.put(current_section_name, current_variables);
                                    current_variables = Variables.init(arena.allocator());
                                }
                                current_section_name_maybe = parsed_line.section_header;
                            },
                            .variable => {
                                try current_variables.put(parsed_line.variable.name, parsed_line.variable.value);
                            },
                            .invalid => return error.InvalidLine,
                        }
                    }

                    // add the last section if necessary
                    if (current_section_name_maybe) |current_section_name| {
                        try sections.put(current_section_name, current_variables);
                    }
                },
                .xit => return error.NotImplemented,
            }

            return .{
                .allocator = allocator,
                .arena = arena,
                .sections = sections,
            };
        }

        pub fn deinit(self: *Config(repo_kind)) void {
            self.arena.deinit();
            self.allocator.destroy(self.arena);
        }

        pub fn add(self: *Config(repo_kind), core_cursor: rp.Repo(repo_kind).CoreCursor, input: AddConfigInput) !void {
            if (std.mem.lastIndexOfScalar(u8, input.name, '.')) |index| {
                const section_name = try self.arena.allocator().dupe(u8, input.name[0..index]);
                const var_name = try self.arena.allocator().dupe(u8, input.name[index + 1 ..]);
                const var_value = try self.arena.allocator().dupe(u8, input.value);
                if (self.sections.getPtr(section_name)) |variables| {
                    try variables.put(var_name, var_value);
                } else {
                    var variables = Variables.init(self.arena.allocator());
                    try variables.put(var_name, var_value);
                    try self.sections.put(section_name, variables);
                }

                switch (repo_kind) {
                    .git => try self.write(core_cursor.core),
                    .xit => return error.NotImplemented,
                }
            } else {
                return error.KeyDoesNotContainASection;
            }
        }

        pub fn remove(self: *Config(repo_kind), core_cursor: rp.Repo(repo_kind).CoreCursor, input: RemoveConfigInput) !void {
            if (std.mem.lastIndexOfScalar(u8, input.name, '.')) |index| {
                const section_name = try self.arena.allocator().dupe(u8, input.name[0..index]);
                const var_name = try self.arena.allocator().dupe(u8, input.name[index + 1 ..]);
                if (self.sections.getPtr(section_name)) |variables| {
                    _ = variables.orderedRemove(var_name);
                } else {
                    return error.SectionDoesNotExist;
                }

                switch (repo_kind) {
                    .git => try self.write(core_cursor.core),
                    .xit => return error.NotImplemented,
                }
            } else {
                return error.KeyDoesNotContainASection;
            }
        }

        fn write(self: *Config(repo_kind), core: *rp.Repo(.git).Core) !void {
            var lock = try io.LockFile.init(self.allocator, core.git_dir, "config");
            defer lock.deinit();

            for (self.sections.keys(), self.sections.values()) |section_name, variables| {
                const section_line = try std.fmt.allocPrint(self.allocator, "[{s}]\n", .{section_name});
                defer self.allocator.free(section_line);
                try lock.lock_file.writeAll(section_line);

                for (variables.keys(), variables.values()) |name, value| {
                    const var_line = try std.fmt.allocPrint(self.allocator, "\t{s} = {s}\n", .{ name, value });
                    defer self.allocator.free(var_line);
                    try lock.lock_file.writeAll(var_line);
                }
            }

            lock.success = true;
        }
    };
}

pub const AddRemoteInput = struct {
    name: []const u8,
    url: []const u8,
};

pub const RemoveRemoteInput = struct {
    name: []const u8,
};

pub const RemoteCommand = union(enum) {
    list,
    add: AddRemoteInput,
    remove: RemoveRemoteInput,
};
