//! you're looking at radar's hopeless attempt to implement
//! the successor to git. key features planned for xit:
//!
//! 1. xitlets: small programs that live inside the repo and
//! whose data is versioned just like files are. changes to
//! their data will happen exclusively via CRDTs, so they
//! can be merged cleanly. this will allow building things
//! like issue trackers that are part of the repo, an idea
//! pioneered by fossil (though in a hard-coded form).
//! 2. patch-based changes and first-class conflicts, an
//! idea pioneered by pijul.
//! 3. git compatibility, most likely implemented by keeping
//! two different commit histories (a git-compatible one and
//! a patch-based one).
//!
//! this will be a stupid amount of work with no guarantee
//! of success, but good ol' radar has nothing better to do.
//!
//! "C'mon Alex! You always dreamt about going on a big adventure!
//!  Let this be our first!" -- Lunar: Silver Star Story

const std = @import("std");
const hash = @import("./hash.zig");
const cmd = @import("./command.zig");
const rp = @import("./repo.zig");

/// takes the args passed to this program and puts them
/// in an arraylist. do we need to do this? i don't know,
/// but i'd rather have it in an arraylist so it's easier
/// to look at. so yeah, i do need it. fight me.
fn appendArgs(out: *std.ArrayList([]const u8)) !void {
    var arg_it = std.process.args();
    _ = arg_it.skip();

    while (true) {
        const s = arg_it.next();
        if (s == null) {
            break;
        }
        try out.append(s.?);
    }
}

/// this is meant to be the main entry point if you wanted to use xit
/// as a library. there will definitely be more specialized functions
/// you can call as well, but if you just want to pass the CLI args and
/// have it behave just like the standalone xit client than this is
/// where it's at, homie.
pub fn xitMain(comptime kind: rp.RepoKind, allocator: std.mem.Allocator, args: *std.ArrayList([]const u8)) !void {
    var command = try cmd.Command.init(allocator, args);
    defer command.deinit();

    // get the cwd path
    var cwd_path_buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
    const cwd_path = try std.fs.cwd().realpath(".", &cwd_path_buffer);
    var cwd = try std.fs.openDirAbsolute(cwd_path, .{});
    defer cwd.close();

    var repo = try rp.Repo(kind).initWithCommand(allocator, .{ .cwd = cwd }, command.data);
    defer repo.deinit();
}

/// this is the main "main". it's even mainier than xitMain.
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
    try xitMain(.git, allocator, &args);
}
