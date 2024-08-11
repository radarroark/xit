const std = @import("std");
const xitui = @import("xitui");
const term = xitui.terminal;
const wgt = xitui.widget;
const layout = xitui.layout;
const inp = xitui.input;
const Grid = xitui.grid.Grid;
const Focus = xitui.focus.Focus;
const rp = @import("../repo.zig");
const df = @import("../diff.zig");

pub fn Diff(comptime Widget: type, comptime repo_kind: rp.RepoKind) type {
    return struct {
        box: wgt.Box(Widget),
        allocator: std.mem.Allocator,
        repo: *rp.Repo(repo_kind),
        bufs: std.ArrayList([]const u8),

        pub fn init(allocator: std.mem.Allocator, repo: *rp.Repo(repo_kind)) !Diff(Widget, repo_kind) {
            var inner_box = try wgt.Box(Widget).init(allocator, null, .vert);
            errdefer inner_box.deinit();

            var scroll = try wgt.Scroll(Widget).init(allocator, .{ .box = inner_box }, .both);
            errdefer scroll.deinit();

            var outer_box = try wgt.Box(Widget).init(allocator, .single, .vert);
            errdefer outer_box.deinit();
            try outer_box.children.put(scroll.getFocus().id, .{ .widget = .{ .scroll = scroll }, .rect = null, .min_size = null });

            return .{
                .box = outer_box,
                .allocator = allocator,
                .repo = repo,
                .bufs = std.ArrayList([]const u8).init(allocator),
            };
        }

        pub fn deinit(self: *Diff(Widget, repo_kind)) void {
            for (self.bufs.items) |buf| {
                self.allocator.free(buf);
            }
            self.bufs.deinit();
            self.box.deinit();
        }

        pub fn build(self: *Diff(Widget, repo_kind), constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            self.box.border_style = if (root_focus.grandchild_id == self.getFocus().id) .double else .single;
            if (self.bufs.items.len > 0) {
                try self.box.build(constraint, root_focus);
            }
        }

        pub fn input(self: *Diff(Widget, repo_kind), key: inp.Key, root_focus: *Focus) !void {
            _ = root_focus;
            switch (key) {
                .arrow_up => {
                    if (self.box.children.values()[0].widget.scroll.y > 0) {
                        self.box.children.values()[0].widget.scroll.y -= 1;
                    }
                },
                .arrow_down => {
                    if (self.box.grid) |outer_box_grid| {
                        const outer_box_height = outer_box_grid.size.height - 2;
                        const scroll_y = self.box.children.values()[0].widget.scroll.y;
                        const u_scroll_y: usize = if (scroll_y >= 0) @intCast(scroll_y) else 0;
                        if (self.box.children.values()[0].widget.scroll.child.box.grid) |inner_box_grid| {
                            const inner_box_height = inner_box_grid.size.height;
                            if (outer_box_height + u_scroll_y < inner_box_height) {
                                self.box.children.values()[0].widget.scroll.y += 1;
                            }
                        }
                    }
                },
                .arrow_left => {
                    if (self.box.children.values()[0].widget.scroll.x > 0) {
                        self.box.children.values()[0].widget.scroll.x -= 1;
                    }
                },
                .arrow_right => {
                    if (self.box.grid) |outer_box_grid| {
                        const outer_box_width = outer_box_grid.size.width - 2;
                        const scroll_x = self.box.children.values()[0].widget.scroll.x;
                        const u_scroll_x: usize = if (scroll_x >= 0) @intCast(scroll_x) else 0;
                        if (self.box.children.values()[0].widget.scroll.child.box.grid) |inner_box_grid| {
                            const inner_box_width = inner_box_grid.size.width;
                            if (outer_box_width + u_scroll_x < inner_box_width) {
                                self.box.children.values()[0].widget.scroll.x += 1;
                            }
                        }
                    }
                },
                .home => {
                    self.box.children.values()[0].widget.scroll.y = 0;
                },
                .end => {
                    if (self.box.grid) |outer_box_grid| {
                        if (self.box.children.values()[0].widget.scroll.child.box.grid) |inner_box_grid| {
                            const outer_box_height = outer_box_grid.size.height - 2;
                            const inner_box_height = inner_box_grid.size.height;
                            const max_scroll: isize = if (inner_box_height > outer_box_height) @intCast(inner_box_height - outer_box_height) else 0;
                            self.box.children.values()[0].widget.scroll.y = max_scroll;
                        }
                    }
                },
                .page_up => {
                    if (self.box.grid) |outer_box_grid| {
                        const outer_box_height = outer_box_grid.size.height - 2;
                        const scroll_y = self.box.children.values()[0].widget.scroll.y;
                        const scroll_change: isize = @intCast(outer_box_height / 2);
                        self.box.children.values()[0].widget.scroll.y = @max(0, scroll_y - scroll_change);
                    }
                },
                .page_down => {
                    if (self.box.grid) |outer_box_grid| {
                        if (self.box.children.values()[0].widget.scroll.child.box.grid) |inner_box_grid| {
                            const outer_box_height = outer_box_grid.size.height - 2;
                            const inner_box_height = inner_box_grid.size.height;
                            const max_scroll: isize = if (inner_box_height > outer_box_height) @intCast(inner_box_height - outer_box_height) else 0;
                            const scroll_y = self.box.children.values()[0].widget.scroll.y;
                            const scroll_change: isize = @intCast(outer_box_height / 2);
                            self.box.children.values()[0].widget.scroll.y = @min(scroll_y + scroll_change, max_scroll);
                        }
                    }
                },
                else => {},
            }
        }

        pub fn clearGrid(self: *Diff(Widget, repo_kind)) void {
            self.box.clearGrid();
        }

        pub fn getGrid(self: Diff(Widget, repo_kind)) ?Grid {
            return self.box.getGrid();
        }

        pub fn getFocus(self: *Diff(Widget, repo_kind)) *Focus {
            return self.box.getFocus();
        }

        pub fn clearDiffs(self: *Diff(Widget, repo_kind)) !void {
            // clear buffers
            for (self.bufs.items) |buf| {
                self.allocator.free(buf);
            }
            self.bufs.clearAndFree();

            // remove old diff widgets
            for (self.box.children.values()[0].widget.scroll.child.box.children.values()) |*child| {
                child.widget.deinit();
            }
            self.box.children.values()[0].widget.scroll.child.box.children.clearAndFree();

            // reset scroll position
            const widget = &self.box.children.values()[0].widget;
            widget.scroll.x = 0;
            widget.scroll.y = 0;
        }

        pub fn addHunks(self: *Diff(Widget, repo_kind), hunk_iter: *df.HunkIterator(repo_kind)) !void {
            const buf = blk: {
                var arr = std.ArrayList(u8).init(self.allocator);
                errdefer arr.deinit();
                const writer = arr.writer();

                // add header
                for (hunk_iter.header_lines.items) |header_line| {
                    try writer.print("{s}\n", .{header_line});
                }

                // add hunks
                while (try hunk_iter.next()) |*hunk_ptr| {
                    var hunk = hunk_ptr.*;
                    defer hunk.deinit();
                    // create buffer from hunk
                    const offsets = hunk.offsets();
                    try writer.print("@@ -{},{} +{},{} @@\n", .{
                        offsets.del_start,
                        offsets.del_count,
                        offsets.ins_start,
                        offsets.ins_count,
                    });
                    for (hunk.edits.items) |edit| {
                        try writer.print("{s} {s}\n", .{
                            switch (edit) {
                                .eql => " ",
                                .ins => "+",
                                .del => "-",
                            },
                            switch (edit) {
                                .eql => edit.eql.new_line.text,
                                .ins => edit.ins.new_line.text,
                                .del => edit.del.old_line.text,
                            },
                        });
                    }
                }

                break :blk try arr.toOwnedSlice();
            };

            // add buffer
            {
                errdefer self.allocator.free(buf);
                try self.bufs.append(buf);
            }

            // add new diff widget
            var text_box = try wgt.TextBox(Widget).init(self.allocator, buf, .hidden);
            errdefer text_box.deinit();
            try self.box.children.values()[0].widget.scroll.child.box.children.put(text_box.getFocus().id, .{ .widget = .{ .text_box = text_box }, .rect = null, .min_size = null });
        }

        pub fn getScrollX(self: Diff(Widget, repo_kind)) isize {
            return self.box.children.values()[0].widget.scroll.x;
        }

        pub fn getScrollY(self: Diff(Widget, repo_kind)) isize {
            return self.box.children.values()[0].widget.scroll.y;
        }

        pub fn isEmpty(self: Diff(Widget, repo_kind)) bool {
            return self.bufs.items.len == 0;
        }
    };
}