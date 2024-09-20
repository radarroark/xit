const std = @import("std");
const xitui = @import("xitui");
const wgt = xitui.widget;
const layout = xitui.layout;
const inp = xitui.input;
const Grid = xitui.grid.Grid;
const Focus = xitui.focus.Focus;
const ui_diff = @import("./diff.zig");
const rp = @import("../repo.zig");
const df = @import("../diff.zig");
const ref = @import("../ref.zig");
const obj = @import("../object.zig");

pub fn LogCommitList(comptime Widget: type, comptime repo_kind: rp.RepoKind) type {
    return struct {
        scroll: wgt.Scroll(Widget),
        repo: *rp.Repo(repo_kind),
        commits: std.ArrayList(obj.Object(repo_kind, .full)),

        pub fn init(allocator: std.mem.Allocator, repo: *rp.Repo(repo_kind)) !LogCommitList(Widget, repo_kind) {
            // init commits
            var commits = std.ArrayList(obj.Object(repo_kind, .full)).init(allocator);
            errdefer {
                for (commits.items) |*commit| {
                    commit.deinit();
                }
                commits.deinit();
            }

            // walk the commits
            var commit_iter = try repo.log(null);
            defer commit_iter.deinit();
            while (try commit_iter.next()) |commit_object| {
                errdefer commit_object.deinit();
                try commits.append(commit_object.*);
            }

            var inner_box = try wgt.Box(Widget).init(allocator, null, .vert);
            errdefer inner_box.deinit();
            for (commits.items) |commit_object| {
                const line = std.mem.sliceTo(commit_object.content.commit.metadata.message, '\n');
                var text_box = try wgt.TextBox(Widget).init(allocator, line, .hidden);
                errdefer text_box.deinit();
                text_box.getFocus().focusable = true;
                try inner_box.children.put(text_box.getFocus().id, .{ .widget = .{ .text_box = text_box }, .rect = null, .min_size = null });
            }

            // init scroll
            var scroll = try wgt.Scroll(Widget).init(allocator, .{ .box = inner_box }, .vert);
            errdefer scroll.deinit();
            if (inner_box.children.count() > 0) {
                scroll.getFocus().child_id = inner_box.children.keys()[0];
            }

            return .{
                .scroll = scroll,
                .repo = repo,
                .commits = commits,
            };
        }

        pub fn deinit(self: *LogCommitList(Widget, repo_kind)) void {
            for (self.commits.items) |*commit_object| {
                commit_object.deinit();
            }
            self.commits.deinit();
            self.scroll.deinit();
        }

        pub fn build(self: *LogCommitList(Widget, repo_kind), constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            const children = &self.scroll.child.box.children;
            for (children.keys(), children.values()) |id, *commit| {
                commit.widget.text_box.border_style = if (self.getFocus().child_id == id)
                    (if (root_focus.grandchild_id == id) .double else .single)
                else
                    .hidden;
            }
            try self.scroll.build(constraint, root_focus);
        }

        pub fn input(self: *LogCommitList(Widget, repo_kind), key: inp.Key, root_focus: *Focus) !void {
            if (self.getFocus().child_id) |child_id| {
                const children = &self.scroll.child.box.children;
                if (children.getIndex(child_id)) |current_index| {
                    var index = current_index;

                    switch (key) {
                        .arrow_up => {
                            index -|= 1;
                        },
                        .arrow_down => {
                            if (index + 1 < children.count()) {
                                index += 1;
                            }
                        },
                        .home => {
                            index = 0;
                        },
                        .end => {
                            if (children.count() > 0) {
                                index = children.count() - 1;
                            }
                        },
                        .page_up => {
                            if (self.getGrid()) |grid| {
                                const half_count = (grid.size.height / 3) / 2;
                                index -|= half_count;
                            }
                        },
                        .page_down => {
                            if (self.getGrid()) |grid| {
                                if (children.count() > 0) {
                                    const half_count = (grid.size.height / 3) / 2;
                                    index = @min(index + half_count, children.count() - 1);
                                }
                            }
                        },
                        else => {},
                    }

                    if (index != current_index) {
                        try root_focus.setFocus(children.keys()[index]);
                        self.updateScroll(index);
                    }
                }
            }
        }

        pub fn clearGrid(self: *LogCommitList(Widget, repo_kind)) void {
            self.scroll.clearGrid();
        }

        pub fn getGrid(self: LogCommitList(Widget, repo_kind)) ?Grid {
            return self.scroll.getGrid();
        }

        pub fn getFocus(self: *LogCommitList(Widget, repo_kind)) *Focus {
            return self.scroll.getFocus();
        }

        pub fn getSelectedIndex(self: LogCommitList(Widget, repo_kind)) ?usize {
            if (self.scroll.child.box.focus.child_id) |child_id| {
                const children = &self.scroll.child.box.children;
                return children.getIndex(child_id);
            } else {
                return null;
            }
        }

        fn updateScroll(self: *LogCommitList(Widget, repo_kind), index: usize) void {
            const left_box = &self.scroll.child.box;
            if (left_box.children.values()[index].rect) |rect| {
                self.scroll.scrollToRect(rect);
            }
        }
    };
}

pub fn Log(comptime Widget: type, comptime repo_kind: rp.RepoKind) type {
    return struct {
        box: wgt.Box(Widget),
        repo: *rp.Repo(repo_kind),
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, repo: *rp.Repo(repo_kind)) !Log(Widget, repo_kind) {
            var box = try wgt.Box(Widget).init(allocator, null, .horiz);
            errdefer box.deinit();

            // add commit list
            {
                var commit_list = try LogCommitList(Widget, repo_kind).init(allocator, repo);
                errdefer commit_list.deinit();
                try box.children.put(commit_list.getFocus().id, .{ .widget = .{ .ui_log_commit_list = commit_list }, .rect = null, .min_size = .{ .width = 30, .height = null } });
            }

            // add diff
            {
                var diff = Widget{ .ui_diff = try ui_diff.Diff(Widget, repo_kind).init(allocator, repo) };
                errdefer diff.deinit();
                diff.getFocus().focusable = true;
                try box.children.put(diff.getFocus().id, .{ .widget = diff, .rect = null, .min_size = .{ .width = 60, .height = null } });
            }

            var git_log = Log(Widget, repo_kind){
                .box = box,
                .repo = repo,
                .allocator = allocator,
            };
            git_log.getFocus().child_id = box.children.keys()[0];
            try git_log.updateDiff();

            return git_log;
        }

        pub fn deinit(self: *Log(Widget, repo_kind)) void {
            self.box.deinit();
        }

        pub fn build(self: *Log(Widget, repo_kind), constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            try self.box.build(constraint, root_focus);
        }

        pub fn input(self: *Log(Widget, repo_kind), key: inp.Key, root_focus: *Focus) !void {
            const diff_scroll_x = self.box.children.values()[1].widget.ui_diff.box.children.values()[0].widget.scroll.x;

            if (self.getFocus().child_id) |child_id| {
                if (self.box.children.getIndex(child_id)) |current_index| {
                    const child = &self.box.children.values()[current_index].widget;

                    const index = blk: {
                        switch (key) {
                            .arrow_left => {
                                if (child.* == .ui_diff and diff_scroll_x == 0) {
                                    break :blk 0;
                                }
                            },
                            .arrow_right => {
                                if (child.* == .ui_log_commit_list) {
                                    break :blk 1;
                                }
                            },
                            .codepoint => {
                                switch (key.codepoint) {
                                    13 => {
                                        if (child.* == .ui_log_commit_list) {
                                            break :blk 1;
                                        }
                                    },
                                    127, '\x1B' => {
                                        if (child.* == .ui_diff) {
                                            break :blk 0;
                                        }
                                    },
                                    else => {},
                                }
                            },
                            else => {},
                        }
                        try child.input(key, root_focus);
                        if (child.* == .ui_log_commit_list) {
                            try self.updateDiff();
                        }
                        break :blk current_index;
                    };

                    if (index != current_index) {
                        try root_focus.setFocus(self.box.children.keys()[index]);
                    }
                }
            }
        }

        pub fn clearGrid(self: *Log(Widget, repo_kind)) void {
            self.box.clearGrid();
        }

        pub fn getGrid(self: Log(Widget, repo_kind)) ?Grid {
            return self.box.getGrid();
        }

        pub fn getFocus(self: *Log(Widget, repo_kind)) *Focus {
            return self.box.getFocus();
        }

        pub fn scrolledToTop(self: Log(Widget, repo_kind)) bool {
            if (self.box.focus.child_id) |child_id| {
                if (self.box.children.getIndex(child_id)) |current_index| {
                    const child = &self.box.children.values()[current_index].widget;
                    switch (child.*) {
                        .ui_log_commit_list => {
                            const commit_list = &child.ui_log_commit_list;
                            if (commit_list.getSelectedIndex()) |commit_index| {
                                return commit_index == 0;
                            }
                        },
                        .ui_diff => {
                            const diff = &child.ui_diff;
                            return diff.getScrollY() == 0;
                        },
                        else => {},
                    }
                }
            }
            return true;
        }

        fn updateDiff(self: *Log(Widget, repo_kind)) !void {
            const commit_list = &self.box.children.values()[0].widget.ui_log_commit_list;
            if (commit_list.getSelectedIndex()) |commit_index| {
                const commit_object = commit_list.commits.items[commit_index];

                const commit_oid = commit_object.oid;

                const parent_oid_maybe = if (commit_object.content.commit.parents.items.len == 1)
                    commit_object.content.commit.parents.items[0]
                else
                    null;

                var tree_diff = try self.repo.treeDiff(parent_oid_maybe, commit_oid);
                defer tree_diff.deinit();

                var file_iter = try self.repo.filePairs(.{ .tree = .{ .tree_diff = &tree_diff } });

                var diff = &self.box.children.values()[1].widget.ui_diff;
                try diff.clearDiffs();

                while (try file_iter.next()) |*line_iter_pair_ptr| {
                    var line_iter_pair = line_iter_pair_ptr.*;
                    defer line_iter_pair.deinit();
                    var hunk_iter = try df.HunkIterator(repo_kind).init(self.allocator, &line_iter_pair.a, &line_iter_pair.b);
                    defer hunk_iter.deinit();
                    try diff.addHunks(&hunk_iter);
                }
            }
        }
    };
}
