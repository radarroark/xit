//! you're looking at radar's hopeless attempt to implement
//! git in zig. one day, it will be the fastest git in the world,
//! with extra features for rewriting history like in BFG.
//! right now, though, it just makes a couple dirs and prints
//! messages out...which already makes it more usable than git.
//!
//! "C'mon Alex! You always dreamt about going on a big adventure!
//!  Let this be our first!" -- Lunar: Silver Star Story

const std = @import("std");
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
    commit,
};

/// returns the data from the process args in a nicer format.
/// i'm trying not to handle errors here. but maybe i will
/// need to eventually. we'll see.
fn parseArgs(args: *std.ArrayList([]const u8)) Command {
    if (args.items.len >= 1) {
        if (std.mem.eql(u8, args.items[0], "init")) {
            return Command{ .init = .{ .dir = if (args.items.len > 1) args.items[1] else "." } };
        } else if (std.mem.eql(u8, args.items[0], "commit")) {
            return Command{ .commit = {} };
        } else {
            return Command{ .invalid = .{ .name = args.items[0] } };
        }
    }

    return Command{ .usage = {} };
}

// returns a single random character. just lower case for now.
// eventually i'll make it return upper case and maybe numbers too.
fn randChar() !u8 {
    var rand_int: u8 = 0;
    try std.os.getrandom(std.mem.asBytes(&rand_int));
    var rand_float: f32 = (@intToFloat(f32, rand_int) / @intToFloat(f32, std.math.maxInt(u8)));
    const min = 'a';
    const max = 'z';
    return @floatToInt(u8, rand_float * (max - min)) + min;
}

// fills the given buffer with random chars.
fn fillWithRandChars(buffer: []u8) !void {
    var i: u32 = 0;
    while (i < buffer.len) {
        buffer[i] = try randChar();
        i += 1;
    }
}

// writes the file at the given path into the .git dir.
// this will need to go somewhere else eventually, just
// keeping it here until i figure out how to organize stuff.
fn writeObject(cwd: std.fs.Dir, path: []const u8, allocator: std.mem.Allocator, entries: *std.ArrayList([]const u8)) !void {
    // open the internal dirs
    var git_dir = try cwd.openDir(".git", .{});
    defer git_dir.close();
    var objects_dir = try git_dir.openDir("objects", .{});
    defer objects_dir.close();

    // get absolute path of the file
    var path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
    const in_path = try cwd.realpath(path, &path_buffer);
    var in = try std.fs.openFileAbsolute(in_path, .{ .mode = std.fs.File.OpenMode.read_only });
    defer in.close();

    // see if it's a file or dir
    const meta = try in.metadata();
    switch (meta.kind()) {
        std.fs.File.Kind.File => {
            // calc the sha1 of its contents
            var sha1_bytes = [_]u8{0} ** hash.SHA1_BYTES_LEN;
            try hash.sha1_file(in, &sha1_bytes);
            var sha1_hex_buffer = [_]u8{0} ** hash.SHA1_HEX_LEN;
            const sha1_hex = try std.fmt.bufPrint(&sha1_hex_buffer, "{}", .{std.fmt.fmtSliceHexLower(&sha1_bytes)});

            // make the two char dir
            var first_hash_dir = try objects_dir.makeOpenPath(sha1_hex[0..2], .{});
            defer first_hash_dir.close();

            // open temp file
            var rand_chars = [_]u8{0} ** 6;
            try fillWithRandChars(&rand_chars);
            const tmp_file_name = "tmp_obj_" ++ rand_chars;
            const tmp_file = try first_hash_dir.createFile(tmp_file_name, .{});
            defer tmp_file.close();

            // compress the file
            try compress.compress(in, tmp_file, allocator);

            // rename the file
            try std.fs.rename(first_hash_dir, tmp_file_name, first_hash_dir, sha1_hex[2..]);

            // add the file to entries
            const entry = try std.fmt.allocPrint(allocator, "100644 {s}\x00{s}", .{ path, &sha1_bytes });
            try entries.append(entry);
        },
        std.fs.File.Kind.Directory => {
            // create tree contents
            const tree_contents = try std.mem.join(allocator, "", entries.items);
            defer allocator.free(tree_contents);

            // create tree
            const tree = try std.fmt.allocPrint(allocator, "tree {}\x00{s}", .{ tree_contents.len, tree_contents });
            defer allocator.free(tree);

            // calc the sha1 of its contents
            var tree_sha1_bytes = [_]u8{0} ** hash.SHA1_BYTES_LEN;
            try hash.sha1_buffer(tree, &tree_sha1_bytes);
            var tree_sha1_hex_buffer = [_]u8{0} ** hash.SHA1_HEX_LEN;
            const tree_sha1_hex = try std.fmt.bufPrint(&tree_sha1_hex_buffer, "{}", .{std.fmt.fmtSliceHexLower(&tree_sha1_bytes)});

            // make the two char dir
            var tree_first_hash_dir = try objects_dir.makeOpenPath(tree_sha1_hex[0..2], .{});
            defer tree_first_hash_dir.close();

            // open temp file
            var tree_rand_chars = [_]u8{0} ** 6;
            try fillWithRandChars(&tree_rand_chars);
            const tree_tmp_file_name = "tmp_obj_" ++ tree_rand_chars;
            const tree_tmp_file = try tree_first_hash_dir.createFile(tree_tmp_file_name, .{ .read = true });
            defer tree_tmp_file.close();

            // write to the temp file
            try tree_tmp_file.pwriteAll(tree, 0);

            // open compressed temp file
            var tree_comp_rand_chars = [_]u8{0} ** 6;
            try fillWithRandChars(&tree_comp_rand_chars);
            const tree_comp_tmp_file_name = "tmp_obj_" ++ tree_comp_rand_chars;
            const tree_comp_tmp_file = try tree_first_hash_dir.createFile(tree_comp_tmp_file_name, .{});
            defer tree_comp_tmp_file.close();

            // compress the file
            try compress.compress(tree_tmp_file, tree_comp_tmp_file, allocator);

            // delete first temp file
            try tree_first_hash_dir.deleteFile(tree_tmp_file_name);

            // rename the file
            try std.fs.rename(tree_first_hash_dir, tree_comp_tmp_file_name, tree_first_hash_dir, tree_sha1_hex[2..]);

            // if this is the root of the repo, make the commit object too
            if (std.mem.eql(u8, path, ".")) {
                // read HEAD
                var head_file_buffer = [_]u8{0} ** 1024; // FIXME: this is arbitrary...
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
                const message = "let there be light";
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
                var commit_first_hash_dir = try objects_dir.makeOpenPath(commit_sha1_hex[0..2], .{});
                defer commit_first_hash_dir.close();

                // open temp file
                var commit_rand_chars = [_]u8{0} ** 6;
                try fillWithRandChars(&commit_rand_chars);
                const commit_tmp_file_name = "tmp_obj_" ++ commit_rand_chars;
                const commit_tmp_file = try commit_first_hash_dir.createFile(commit_tmp_file_name, .{ .read = true });
                defer commit_tmp_file.close();

                // write to the temp file
                try commit_tmp_file.pwriteAll(commit, 0);

                // open compressed temp file
                var commit_comp_rand_chars = [_]u8{0} ** 6;
                try fillWithRandChars(&commit_comp_rand_chars);
                const commit_comp_tmp_file_name = "tmp_obj_" ++ commit_comp_rand_chars;
                const commit_comp_tmp_file = try commit_first_hash_dir.createFile(commit_comp_tmp_file_name, .{});
                defer commit_comp_tmp_file.close();

                // compress the file
                try compress.compress(commit_tmp_file, commit_comp_tmp_file, allocator);

                // delete first temp file
                try commit_first_hash_dir.deleteFile(commit_tmp_file_name);

                // rename the file
                try std.fs.rename(commit_first_hash_dir, commit_comp_tmp_file_name, commit_first_hash_dir, commit_sha1_hex[2..]);

                // write commit id to HEAD
                // first write to a lock file and then rename it to HEAD for safety
                {
                    const head_file = try git_dir.createFile("HEAD.lock", .{ .exclusive = true, .lock = .Exclusive });
                    defer head_file.close();
                    try head_file.pwriteAll(commit_sha1_hex, 0);
                }
                try git_dir.rename("HEAD.lock", "HEAD");
            }
        },
        else => return,
    }
}

/// this is meant to be the main entry point if you wanted to use zit
/// as a library. there will definitely be more specialized functions
/// you can call as well, but if you just want to pass the CLI args and
/// have it behave just like the standalone git client than this is
/// where it's at, homie.
pub fn zitMain(args: *std.ArrayList([]const u8), allocator: std.mem.Allocator) !void {
    const cmd = parseArgs(args);

    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

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
        Command.commit => {
            // get the cwd path
            var cwd_path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
            const cwd_path = try std.fs.cwd().realpath(".", &cwd_path_buffer);
            var cwd = try std.fs.openDirAbsolute(cwd_path, .{});
            defer cwd.close();

            // make list to store entries
            var entries = std.ArrayList([]const u8).init(allocator);
            defer {
                for (entries.items) |entry| {
                    allocator.free(entry);
                }
                entries.deinit();
            }

            // get an iterator for the files in the cwd
            var root_dir = try cwd.makeOpenPathIterable(".", .{});
            defer root_dir.close();
            var iter = root_dir.iterate();

            // iterate over each file (not recursive...to do that, use walk instead of iterate)
            while (try iter.next()) |entry| {
                // skip things
                if (std.mem.eql(u8, entry.name, ".git")) {
                    continue;
                }
                // write the object to .git/objects
                try writeObject(cwd, entry.name, allocator, &entries);
            }

            try writeObject(cwd, ".", allocator, &entries);
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
