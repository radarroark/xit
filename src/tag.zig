const std = @import("std");
const hash = @import("./hash.zig");
const rf = @import("./ref.zig");
const rp = @import("./repo.zig");
const obj = @import("./object.zig");

pub const TagCommand = union(enum) {
    list,
    add: AddTagInput,
    remove: RemoveTagInput,
};

pub const AddTagInput = struct {
    name: []const u8,
    tagger: ?[]const u8 = null,
    message: ?[]const u8 = null,
};

pub const RemoveTagInput = struct {
    name: []const u8,
};

pub fn add(
    comptime repo_kind: rp.RepoKind,
    comptime repo_opts: rp.RepoOpts(repo_kind),
    state: rp.Repo(repo_kind, repo_opts).State(.read_write),
    allocator: std.mem.Allocator,
    input: AddTagInput,
) ![hash.hexLen(repo_opts.hash)]u8 {
    if (!rf.validateName(input.name)) {
        return error.InvalidTagName;
    }

    const ref_path = try std.fmt.allocPrint(allocator, "refs/tags/{s}", .{input.name});
    defer allocator.free(ref_path);

    const target = try rf.readHead(repo_kind, repo_opts, state.readOnly());
    const tag_oid = try obj.writeTag(repo_kind, repo_opts, state, allocator, input, &target);
    try rf.write(repo_kind, repo_opts, state, ref_path, &tag_oid);

    return tag_oid;
}
