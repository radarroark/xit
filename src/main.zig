//! you're looking at radar's hopeless attempt to implement
//! git in zig. one day, it will be the fastest git in the world,
//! with extra features for rewriting history like in BFG.
//! right now, though, it just makes a couple dirs and prints
//! messages out...which already makes it more usable than git.
//!
//! "C'mon Alex! You always dreamt about going on a big adventure!
//!  Let this be our first!" -- Lunar: Silver Star Story

const std = @import("std");
const builtin = @import("builtin");
const process = std.process;
const hash = @import("./hash.zig");
const compress = @import("./compress.zig");

/// takes the args passed to this program and puts them
/// in an arraylist. do we need to do this? i don't know,
/// but i'd rather have it in an arraylist so it's easier
/// to look at. so yeah, i do need it. fight me.
fn appendArgs(out: *std.ArrayList([]const u8)) !void {
    var arg_it = process.args();
    _ = arg_it.skip();

    while (true) {
        const s = arg_it.next();
        if (s == null) {
            break;
        }
        try out.append(s.?);
    }
}

const CommandKind = enum {
    invalid,
    usage,
    init,
    add,
    commit,
};

const Command = union(CommandKind) {
    invalid: struct {
        name: []const u8,
    },
    usage,
    init: struct {
        dir: []const u8,
    },
    add: struct {
        paths: std.ArrayList([]const u8),
    },
    commit: struct {
        message: ?[]const u8,
    },
};

const CommandError = error{
    AddPathsMissing,
    CommitMessageMissing,
};

/// returns the data from the process args in a nicer format.
/// right now it just parses the args into a sorted map. i was
/// thinking of using an existing arg parser lib but i decided
/// i should roll my own and let it evolve along with my needs.
/// i'm actually pretty happy with this already...it's stupid
/// but it works, and unlike those libs i understand every line.
fn parseArgs(args: *std.ArrayList([]const u8), allocator: std.mem.Allocator, arena: *std.heap.ArenaAllocator) !Command {
    if (args.items.len >= 1) {
        // put args into data structures for easy access
        var pos_args = std.ArrayList([]const u8).init(allocator);
        defer pos_args.deinit();
        var map_args = std.StringArrayHashMap(?[]const u8).init(allocator);
        defer map_args.deinit();
        for (args.items[1..]) |arg| {
            if (arg.len == 0) {
                continue;
            } else if (arg.len > 1 and arg[0] == '-') {
                try map_args.put(arg, null);
            } else {
                const keys = map_args.keys();
                if (keys.len > 0) {
                    const last_key = keys[keys.len - 1];
                    const last_val = map_args.get(last_key);
                    // if there isn't a spot for this arg in the map,
                    // it is a positional arg
                    if (last_val == null or last_val.? != null) {
                        try pos_args.append(arg);
                    }
                    // otherwise put it in the map
                    else if (last_val.? == null) {
                        try map_args.put(last_key, arg);
                    }
                } else {
                    try pos_args.append(arg);
                }
            }
        }
        // branch on the first arg
        if (std.mem.eql(u8, args.items[0], "init")) {
            return Command{ .init = .{ .dir = if (args.items.len > 1) args.items[1] else "." } };
        } else if (std.mem.eql(u8, args.items[0], "add")) {
            if (pos_args.items.len == 0) {
                return CommandError.AddPathsMissing;
            }
            var paths = try std.ArrayList([]const u8).initCapacity(arena.allocator(), pos_args.capacity);
            paths.appendSliceAssumeCapacity(pos_args.items);
            return Command{ .add = .{ .paths = paths } };
        } else if (std.mem.eql(u8, args.items[0], "commit")) {
            // if a message is included, it must have a non-null value
            const message_maybe = map_args.get("-m");
            const message = if (message_maybe == null) null else (message_maybe.? orelse return CommandError.CommitMessageMissing);
            return Command{ .commit = .{ .message = message } };
        } else {
            return Command{ .invalid = .{ .name = args.items[0] } };
        }
    }

    return Command{ .usage = {} };
}

test "parseArgs" {
    const allocator = std.testing.allocator;
    var args = std.ArrayList([]const u8).init(allocator);
    defer args.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    args.clearAndFree();
    try args.append("add");
    try std.testing.expect(CommandError.AddPathsMissing == parseArgs(&args, allocator, &arena));

    args.clearAndFree();
    try args.append("add");
    try args.append("file.txt");
    const add_cmd = try parseArgs(&args, allocator, &arena);
    try std.testing.expect(add_cmd == .add);
    defer add_cmd.add.paths.deinit();

    args.clearAndFree();
    try args.append("commit");
    try args.append("-m");
    try std.testing.expect(CommandError.CommitMessageMissing == parseArgs(&args, allocator, &arena));

    args.clearAndFree();
    try args.append("commit");
    const commit_cmd_without_msg = try parseArgs(&args, allocator, &arena);
    try std.testing.expect(commit_cmd_without_msg == .commit);
    try std.testing.expect(null == commit_cmd_without_msg.commit.message);

    args.clearAndFree();
    try args.append("commit");
    try args.append("-m");
    try args.append("let there be light");
    const commit_cmd_with_msg = try parseArgs(&args, allocator, &arena);
    try std.testing.expect(commit_cmd_with_msg == .commit);
    try std.testing.expect(null != commit_cmd_with_msg.commit.message);
    try std.testing.expect(std.mem.eql(u8, "let there be light", commit_cmd_with_msg.commit.message.?));
}

/// returns a single random character. just lower case for now.
/// eventually i'll make it return upper case and maybe numbers too.
fn randChar() !u8 {
    var rand_int: u8 = 0;
    try std.os.getrandom(std.mem.asBytes(&rand_int));
    var rand_float: f32 = (@intToFloat(f32, rand_int) / @intToFloat(f32, std.math.maxInt(u8)));
    const min = 'a';
    const max = 'z';
    return @floatToInt(u8, rand_float * (max - min)) + min;
}

/// fills the given buffer with random chars.
fn fillWithRandChars(buffer: []u8) !void {
    var i: u32 = 0;
    while (i < buffer.len) {
        buffer[i] = try randChar();
        i += 1;
    }
}

/// makes a new commit as a child of whatever is in HEAD.
/// uses the commit message provided to the command.
/// updates HEAD when it's done using a file locking thingy
/// so other processes don't step on each others' toes.
fn writeCommit(cwd: std.fs.Dir, allocator: std.mem.Allocator, cmd: Command, tree_sha1_hex: []const u8) !void {
    // open the internal dirs
    var git_dir = try cwd.openDir(".git", .{});
    defer git_dir.close();
    var objects_dir = try git_dir.openDir("objects", .{});
    defer objects_dir.close();

    // read HEAD
    var head_file_buffer = [_]u8{0} ** MAX_FILE_READ_SIZE;
    var head_file_size: usize = 0;
    {
        const head_file_or_err = git_dir.openFile("HEAD", .{ .mode = .read_only });
        const head_file = try if (head_file_or_err == error.FileNotFound)
            git_dir.createFile("HEAD", .{ .read = true })
        else
            head_file_or_err;
        defer head_file.close();
        head_file_size = try head_file.pread(&head_file_buffer, 0);
    }
    const head_file_slice = head_file_buffer[0..head_file_size];

    // metadata
    const author = "radar <radar@foo.com> 1512325222 +0000";
    const message = cmd.commit.message orelse "";
    const parent = if (head_file_size > 0)
        try std.fmt.allocPrint(allocator, "parent {s}\n", .{head_file_slice})
    else
        try std.fmt.allocPrint(allocator, "", .{});
    defer allocator.free(parent);

    // create commit contents
    const commit_contents = try std.fmt.allocPrint(allocator, "tree {s}\n{s}author {s}\ncommitter {s}\n\n{s}", .{ tree_sha1_hex, parent, author, author, message });
    defer allocator.free(commit_contents);

    // create commit
    const commit = try std.fmt.allocPrint(allocator, "commit {}\x00{s}", .{ commit_contents.len, commit_contents });
    defer allocator.free(commit);

    // calc the sha1 of its contents
    var commit_sha1_bytes = [_]u8{0} ** hash.SHA1_BYTES_LEN;
    try hash.sha1_buffer(commit, &commit_sha1_bytes);
    var commit_sha1_hex_buffer = [_]u8{0} ** hash.SHA1_HEX_LEN;
    const commit_sha1_hex = try std.fmt.bufPrint(&commit_sha1_hex_buffer, "{}", .{std.fmt.fmtSliceHexLower(&commit_sha1_bytes)});

    // make the two char dir
    var commit_hash_prefix_dir = try objects_dir.makeOpenPath(commit_sha1_hex[0..2], .{});
    defer commit_hash_prefix_dir.close();

    // open temp file
    var commit_rand_chars = [_]u8{0} ** 6;
    try fillWithRandChars(&commit_rand_chars);
    const commit_tmp_file_name = "tmp_obj_" ++ commit_rand_chars;
    const commit_tmp_file = try commit_hash_prefix_dir.createFile(commit_tmp_file_name, .{ .read = true });
    defer commit_tmp_file.close();

    // write to the temp file
    try commit_tmp_file.pwriteAll(commit, 0);

    // open compressed temp file
    var commit_comp_rand_chars = [_]u8{0} ** 6;
    try fillWithRandChars(&commit_comp_rand_chars);
    const commit_comp_tmp_file_name = "tmp_obj_" ++ commit_comp_rand_chars;
    const commit_comp_tmp_file = try commit_hash_prefix_dir.createFile(commit_comp_tmp_file_name, .{});
    defer commit_comp_tmp_file.close();

    // compress the file
    try compress.compress(commit_tmp_file, commit_comp_tmp_file, allocator);

    // delete first temp file
    try commit_hash_prefix_dir.deleteFile(commit_tmp_file_name);

    // rename the file
    try std.fs.rename(commit_hash_prefix_dir, commit_comp_tmp_file_name, commit_hash_prefix_dir, commit_sha1_hex[2..]);

    // write commit id to HEAD
    // first write to a lock file and then rename it to HEAD for safety
    {
        const head_file = try git_dir.createFile("HEAD.lock", .{ .exclusive = true, .lock = .Exclusive });
        defer head_file.close();
        try head_file.pwriteAll(commit_sha1_hex, 0);
    }
    try git_dir.rename("HEAD.lock", "HEAD");
}

fn writeBlob(file: std.fs.File, meta: std.fs.File.Metadata, objects_dir: std.fs.Dir, allocator: std.mem.Allocator, sha1_bytes_buffer: *[hash.SHA1_BYTES_LEN]u8) !void {
    // calc the sha1 of its contents
    try hash.sha1_file(file, sha1_bytes_buffer);
    var sha1_hex_buffer = [_]u8{0} ** hash.SHA1_HEX_LEN;
    const sha1_hex = try std.fmt.bufPrint(&sha1_hex_buffer, "{}", .{std.fmt.fmtSliceHexLower(sha1_bytes_buffer)});

    // make the two char dir
    var hash_prefix_dir = try objects_dir.makeOpenPath(sha1_hex[0..2], .{});
    defer hash_prefix_dir.close();

    // if the file already exists, exit early
    const rest_of_hash = sha1_hex[2..];
    if (hash_prefix_dir.openFile(rest_of_hash, .{})) |rest_of_hash_file| {
        rest_of_hash_file.close();
        return;
    } else |err| {
        if (err != error.FileNotFound) {
            return err;
        }
    }

    // open temp file
    var rand_chars = [_]u8{0} ** 6;
    try fillWithRandChars(&rand_chars);
    const tmp_file_name = "tmp_obj_" ++ rand_chars;
    const tmp_file = try hash_prefix_dir.createFile(tmp_file_name, .{ .read = true });
    defer tmp_file.close();

    // create blob header
    const file_size = meta.size();
    const blob = try std.fmt.allocPrint(allocator, "blob {}\x00", .{file_size});
    defer allocator.free(blob);
    try tmp_file.writeAll(blob);

    // copy file into temp file
    var read_buffer = [_]u8{0} ** MAX_FILE_READ_SIZE;
    var offset: u64 = 0;
    while (true) {
        const size = try file.pread(&read_buffer, offset);
        offset += size;
        if (size == 0) {
            break;
        }
        try tmp_file.writeAll(read_buffer[0..size]);
    }

    // compress the file
    const compressed_tmp_file_name = tmp_file_name ++ ".compressed";
    const compressed_tmp_file = try hash_prefix_dir.createFile(compressed_tmp_file_name, .{});
    defer compressed_tmp_file.close();
    try compress.compress(tmp_file, compressed_tmp_file, allocator);

    // delete uncompressed temp file
    try hash_prefix_dir.deleteFile(tmp_file_name);

    // rename the compressed temp file
    try std.fs.rename(hash_prefix_dir, compressed_tmp_file_name, hash_prefix_dir, rest_of_hash);
}

fn writeTree(objects_dir: std.fs.Dir, allocator: std.mem.Allocator, entries: *std.ArrayList([]const u8), sha1_bytes_buffer: *[hash.SHA1_BYTES_LEN]u8) !void {
    // create tree contents
    const tree_contents = try std.mem.join(allocator, "", entries.items);
    defer allocator.free(tree_contents);

    // create tree
    const tree = try std.fmt.allocPrint(allocator, "tree {}\x00{s}", .{ tree_contents.len, tree_contents });
    defer allocator.free(tree);

    // calc the sha1 of its contents
    try hash.sha1_buffer(tree, sha1_bytes_buffer);
    var tree_sha1_hex_buffer = [_]u8{0} ** hash.SHA1_HEX_LEN;
    const tree_sha1_hex = try std.fmt.bufPrint(&tree_sha1_hex_buffer, "{}", .{std.fmt.fmtSliceHexLower(sha1_bytes_buffer)});

    // make the two char dir
    var tree_hash_prefix_dir = try objects_dir.makeOpenPath(tree_sha1_hex[0..2], .{});
    defer tree_hash_prefix_dir.close();

    // open temp file
    var tree_rand_chars = [_]u8{0} ** 6;
    try fillWithRandChars(&tree_rand_chars);
    const tree_tmp_file_name = "tmp_obj_" ++ tree_rand_chars;
    const tree_tmp_file = try tree_hash_prefix_dir.createFile(tree_tmp_file_name, .{ .read = true });
    defer tree_tmp_file.close();

    // write to the temp file
    try tree_tmp_file.pwriteAll(tree, 0);

    // open compressed temp file
    var tree_comp_rand_chars = [_]u8{0} ** 6;
    try fillWithRandChars(&tree_comp_rand_chars);
    const tree_comp_tmp_file_name = "tmp_obj_" ++ tree_comp_rand_chars;
    const tree_comp_tmp_file = try tree_hash_prefix_dir.createFile(tree_comp_tmp_file_name, .{});
    defer tree_comp_tmp_file.close();

    // compress the file
    try compress.compress(tree_tmp_file, tree_comp_tmp_file, allocator);

    // delete first temp file
    try tree_hash_prefix_dir.deleteFile(tree_tmp_file_name);

    // rename the file
    try std.fs.rename(tree_hash_prefix_dir, tree_comp_tmp_file_name, tree_hash_prefix_dir, tree_sha1_hex[2..]);
}

pub const MAX_FILE_READ_SIZE: comptime_int = 1000; // FIXME: this is arbitrary...

/// writes the file/dir at the given path into the .git dir.
/// if it's a dir, all of its contents will be added too.
/// entries can be null when first called and sha1_hex_buffer
/// will have the oid when it's done. on windows files are
/// never marked as executable because apparently i can't
/// even check if they are...maybe i'll figure that out later.
fn writeObject(cwd: std.fs.Dir, path: []const u8, allocator: std.mem.Allocator, arena: *std.heap.ArenaAllocator, entries_maybe: ?*std.ArrayList([]const u8), sha1_bytes_buffer: *[hash.SHA1_BYTES_LEN]u8) !void {
    // open the internal dirs
    var git_dir = try cwd.openDir(".git", .{});
    defer git_dir.close();
    var objects_dir = try git_dir.openDir("objects", .{});
    defer objects_dir.close();

    // get absolute path of the file
    var path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
    const file_path = try cwd.realpath(path, &path_buffer);
    var file = try std.fs.openFileAbsolute(file_path, .{ .mode = std.fs.File.OpenMode.read_only });
    defer file.close();

    // see if it's a file or dir
    const meta = try file.metadata();
    switch (meta.kind()) {
        std.fs.File.Kind.File => {
            try writeBlob(file, meta, objects_dir, allocator, sha1_bytes_buffer);

            // add to entries if it's not null
            if (entries_maybe) |entries| {
                // get the file's mode
                const is_executable = switch (builtin.os.tag) {
                    .windows => false,
                    else => meta.permissions().inner.unixHas(std.fs.File.PermissionsUnix.Class.user, .execute),
                };
                const mode = if (is_executable) "100755" else "100644";

                const entry = try std.fmt.allocPrint(arena.allocator(), "{s} {s}\x00{s}", .{ mode, path, sha1_bytes_buffer });
                try entries.append(entry);
            }
        },
        std.fs.File.Kind.Directory => {
            // make list to store entries
            var subentries = std.ArrayList([]const u8).init(allocator);
            defer subentries.deinit();

            // make arena for the subentries
            var subarena = std.heap.ArenaAllocator.init(allocator);
            defer subarena.deinit();

            // iterate recursively
            var subdir = try cwd.openIterableDir(path, .{});
            defer subdir.close();
            var iter = subdir.iterate();
            while (try iter.next()) |entry| {
                // don't traverse the .git dir
                if (std.mem.eql(u8, entry.name, ".git")) {
                    continue;
                }

                const subpath = try std.fs.path.join(allocator, &[_][]const u8{ path, entry.name });
                defer allocator.free(subpath);
                var sub_sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
                try writeObject(cwd, subpath, allocator, &subarena, &subentries, &sub_sha1_bytes_buffer);
            }

            try writeTree(objects_dir, allocator, &subentries, sha1_bytes_buffer);

            // add to entries if it's not null
            if (entries_maybe) |entries| {
                const entry = try std.fmt.allocPrint(arena.allocator(), "40000 {s}\x00{s}", .{ path, sha1_bytes_buffer });
                try entries.append(entry);
            }
        },
        else => return,
    }
}

pub const Index = struct {
    version: u32,
    entries: std.StringArrayHashMap(Entry),

    pub const Entry = struct {
        ctime_secs: i32,
        ctime_nsecs: i32,
        mtime_secs: i32,
        mtime_nsecs: i32,
        dev: u32,
        ino: u32,
        mode: u32,
        uid: u32,
        gid: u32,
        file_size: u32,
        oid: [hash.SHA1_BYTES_LEN]u8,
        path_size: u16,
        path: []const u8,
    };
};

const ReadIndexError = error {
    InvalidSignature,
    InvalidVersion,
    InvalidPathSize,
    InvalidNullPadding,
};

/// if path is a file, adds it as an entry to the index struct.
/// if path is a dir, adds its children recursively.
/// ignoring symlinks for now but will add that later.
fn putEntry(cwd: std.fs.Dir, path: []const u8, allocator: std.mem.Allocator, arena: *std.heap.ArenaAllocator, index: *Index) !void {
    if (index.entries.contains(path)) {
        return;
    }
    const file = try cwd.openFile(path, .{ .mode = .read_only });
    defer file.close();
    const meta = try file.metadata();
    switch (meta.kind()) {
        std.fs.File.Kind.File => {
            const ctime = meta.created() orelse 0;
            const mtime = meta.modified();
            const is_executable = switch (builtin.os.tag) {
                .windows => false,
                else => meta.permissions().inner.unixHas(std.fs.File.PermissionsUnix.Class.user, .execute),
            };
            // is there a better place to write the object than here? probably...
            var oid = [_]u8{0} ** hash.SHA1_BYTES_LEN;
            try writeObject(cwd, path, allocator, arena, null, &oid);
            const entry = Index.Entry{
                .ctime_secs = @truncate(i32, @divTrunc(ctime, std.time.ns_per_s)),
                .ctime_nsecs = @truncate(i32, @mod(ctime, std.time.ns_per_s)),
                .mtime_secs = @truncate(i32, @divTrunc(mtime, std.time.ns_per_s)),
                .mtime_nsecs = @truncate(i32, @mod(mtime, std.time.ns_per_s)),
                .dev = 0,
                .ino = 0,
                .mode = if (is_executable) 100755 else 100644,
                .uid = 0,
                .gid = 0,
                .file_size = @truncate(u32, meta.size()),
                .oid = oid,
                .path_size = @truncate(u16, path.len),
                .path = path,
            };
            try index.entries.put(path, entry);
        },
        std.fs.File.Kind.Directory => {
            var dir = try cwd.openIterableDir(path, .{});
            defer dir.close();
            var iter = dir.iterate();
            while (try iter.next()) |entry| {
                // don't traverse the .git dir
                if (std.mem.eql(u8, entry.name, ".git")) {
                    continue;
                }

                const subpath = if (std.mem.eql(u8, path, "."))
                    try std.fmt.allocPrint(arena.allocator(), "{s}", .{entry.name})
                else
                    try std.fs.path.join(arena.allocator(), &[_][]const u8{ path, entry.name });
                try putEntry(cwd, subpath, allocator, arena, index);
            }
        },
        else => return,
    }
}

/// reads the index file into an Index struct.
fn readIndex(git_dir: std.fs.Dir, arena: *std.heap.ArenaAllocator) !Index {
    var entries = std.StringArrayHashMap(Index.Entry).init(arena.allocator());

    // open index
    const index_file = git_dir.openFile("index", .{ .mode = .read_only }) catch |err| {
        switch (err) {
            error.FileNotFound => return Index{ .version = 2, .entries = entries },
            else => return err,
        }
    };
    defer index_file.close();

    const reader = index_file.reader();
    const signature = try reader.readBytesNoEof(4);

    if (!std.mem.eql(u8, "DIRC", &signature)) {
        return error.InvalidSignature;
    }

    // ignoring version 3 and 4 for now
    const version = try reader.readIntBig(u32);
    if (version != 2) {
        return error.InvalidVersion;
    }

    var entry_count = try reader.readIntBig(u32);

    while (entry_count > 0) {
        entry_count -= 1;
        const start_pos = try reader.context.getPos();
        const entry = Index.Entry{
            .ctime_secs = try reader.readIntBig(i32),
            .ctime_nsecs = try reader.readIntBig(i32),
            .mtime_secs = try reader.readIntBig(i32),
            .mtime_nsecs = try reader.readIntBig(i32),
            .dev = try reader.readIntBig(u32),
            .ino = try reader.readIntBig(u32),
            .mode = try reader.readIntBig(u32),
            .uid = try reader.readIntBig(u32),
            .gid = try reader.readIntBig(u32),
            .file_size = try reader.readIntBig(u32),
            .oid = try reader.readBytesNoEof(hash.SHA1_BYTES_LEN),
            .path_size = try reader.readIntBig(u16),
            .path = try reader.readUntilDelimiterAlloc(arena.allocator(), 0, std.fs.MAX_PATH_BYTES),
        };
        if (entry.path.len != entry.path_size) {
            return error.InvalidPathSize;
        }
        var entry_size = try reader.context.getPos() - start_pos;
        while (entry_size % 8 != 0) {
            entry_size += 1;
            const bytes = try reader.readBytesNoEof(1);
            if (bytes[0] != 0) {
                return error.InvalidNullPadding;
            }
        }
        try entries.put(entry.path, entry);
    }

    // TODO: check the checksum
    // skipping for now because it will probably require changing
    // how i read the data above. i need access to the raw bytes
    // (before the big endian and type conversions) to do the hashing.
    _ = try reader.readBytesNoEof(hash.SHA1_BYTES_LEN);

    return Index{ .version = version, .entries = entries };
}

/// writes the index file with the supplied paths.
fn writeIndex(cwd: std.fs.Dir, paths: std.ArrayList([]const u8), allocator: std.mem.Allocator) !void {
    // open git dir
    var git_dir = try cwd.openDir(".git", .{});
    defer git_dir.close();

    // open index
    // first write to a lock file and then rename it to index for safety
    const index_lock_file = try git_dir.createFile("index.lock", .{ .exclusive = true, .lock = .Exclusive });
    defer index_lock_file.close();

    // create Index
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var index = try readIndex(git_dir, &arena);

    // read all the new entries
    for (paths.items) |path| {
        try putEntry(cwd, path, allocator, &arena, &index);
    }

    // sort the entries
    const SortCtx = struct {
        keys: [][]const u8,
        pub fn lessThan(ctx: @This(), a_index: usize, b_index: usize) bool {
            return std.mem.lessThan(u8, ctx.keys[a_index], ctx.keys[b_index]);
        }
    };
    index.entries.sort(SortCtx{ .keys = index.entries.keys() });

    // start the checksum
    var h = std.crypto.hash.Sha1.init(.{});

    // write the header
    const version: u32 = 2;
    const entry_count: u32 = @truncate(u32, index.entries.count());
    const header = try std.fmt.allocPrint(allocator, "DIRC{s}{s}", .{
        std.mem.asBytes(&std.mem.nativeToBig(u32, version)),
        std.mem.asBytes(&std.mem.nativeToBig(u32, entry_count)),
    });
    defer allocator.free(header);
    try index_lock_file.writeAll(header);
    h.update(header);

    // write the entries
    for (index.entries.values()) |entry| {
        var entry_buffer = std.ArrayList(u8).init(allocator);
        defer entry_buffer.deinit();
        try entry_buffer.writer().print("{s}{s}{s}{s}{s}{s}{s}{s}{s}{s}{s}{s}{s}\x00", .{
            std.mem.asBytes(&std.mem.nativeToBig(i32, entry.ctime_secs)),
            std.mem.asBytes(&std.mem.nativeToBig(i32, entry.ctime_nsecs)),
            std.mem.asBytes(&std.mem.nativeToBig(i32, entry.mtime_secs)),
            std.mem.asBytes(&std.mem.nativeToBig(i32, entry.mtime_nsecs)),
            std.mem.asBytes(&std.mem.nativeToBig(u32, entry.dev)),
            std.mem.asBytes(&std.mem.nativeToBig(u32, entry.ino)),
            std.mem.asBytes(&std.mem.nativeToBig(u32, entry.mode)),
            std.mem.asBytes(&std.mem.nativeToBig(u32, entry.uid)),
            std.mem.asBytes(&std.mem.nativeToBig(u32, entry.gid)),
            std.mem.asBytes(&std.mem.nativeToBig(u32, entry.file_size)),
            entry.oid,
            std.mem.asBytes(&std.mem.nativeToBig(u16, entry.path_size)),
            entry.path,
        });
        while (entry_buffer.items.len % 8 != 0) {
            try entry_buffer.writer().print("\x00", .{});
        }
        try index_lock_file.writeAll(entry_buffer.items);
        h.update(entry_buffer.items);
    }

    // write the checksum
    var overall_sha1_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
    h.final(&overall_sha1_buffer);
    try index_lock_file.writeAll(&overall_sha1_buffer);

    // rename lock file to index
    try git_dir.rename("index.lock", "index");
}

/// this is meant to be the main entry point if you wanted to use zit
/// as a library. there will definitely be more specialized functions
/// you can call as well, but if you just want to pass the CLI args and
/// have it behave just like the standalone git client than this is
/// where it's at, homie.
pub fn zitMain(args: *std.ArrayList([]const u8), allocator: std.mem.Allocator) !void {
    // make arena for any allocations that need to be made by parseArgs
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const cmd = try parseArgs(args, allocator, &arena);

    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    // get the cwd path
    var cwd_path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
    const cwd_path = try std.fs.cwd().realpath(".", &cwd_path_buffer);
    var cwd = try std.fs.openDirAbsolute(cwd_path, .{});
    defer cwd.close();

    switch (cmd) {
        Command.invalid => {
            try stderr.print("\"{s}\" is not a valid command\n", .{cmd.invalid.name});
            return;
        },
        Command.usage => {
            try stdout.print(
                \\usage: zit
                \\
                \\start a working area:
                \\   init
                \\
            , .{});
        },
        Command.init => {
            // get the root dir. no path was given to the init command, this
            // should just be the current working directory (cwd). if a path was
            // given, it should either append it to the cwd or, if it is absolute,
            // it should just use that path alone. IT'S MAGIC!
            var root_dir = try std.fs.cwd().makeOpenPath(cmd.init.dir, .{});
            defer root_dir.close();

            // make the .git dir. right now we're throwing an error if it already
            // exists. in git it says "Reinitialized existing Git repository" so
            // we'll need to do that eventually.
            root_dir.makeDir(".git") catch |err| {
                switch (err) {
                    error.PathAlreadyExists => {
                        try stderr.print("{s} is already a repository\n", .{cmd.init.dir});
                        return;
                    },
                    else => return err,
                }
            };

            // make a few dirs inside of .git
            var git_dir = try root_dir.openDir(".git", .{});
            defer git_dir.close();
            try git_dir.makeDir("objects");
            try git_dir.makeDir("refs");
        },
        Command.add => {
            try writeIndex(cwd, cmd.add.paths, allocator);
        },
        Command.commit => {
            // write commit object
            var sha1_bytes_buffer = [_]u8{0} ** hash.SHA1_BYTES_LEN;
            try writeObject(cwd, ".", allocator, &arena, null, &sha1_bytes_buffer);
            var sha1_hex_buffer = [_]u8{0} ** hash.SHA1_HEX_LEN;
            const sha1_hex = try std.fmt.bufPrint(&sha1_hex_buffer, "{}", .{std.fmt.fmtSliceHexLower(&sha1_bytes_buffer)});
            try writeCommit(cwd, allocator, cmd, sha1_hex);
        },
    }
}

/// this is the main "main". it's even mainier than zitMain.
/// this is the real deal. there is no main more main than this.
/// at least, not that i know of. i guess internally zig probably
/// has an earlier entrypoint which is even mainier than this.
/// i wonder where it all actually begins. when you first turn your
/// computer on, where does the big bang happen? it's a beautiful
/// thing to think about.
pub fn main() !void {
    const allocator = std.heap.page_allocator;
    var args = std.ArrayList([]const u8).init(allocator);
    defer args.deinit();

    try appendArgs(&args);
    try zitMain(&args, allocator);
}
