const std = @import("std");
const xitui = @import("xitui");
const wgt = xitui.widget;
const layout = xitui.layout;
const inp = xitui.input;
const Grid = xitui.grid.Grid;
const Focus = xitui.focus.Focus;
const ui_diff = @import("./diff.zig");
const ui_root = @import("./root.zig");
const rp = @import("../repo.zig");
const st = @import("../status.zig");
const df = @import("../diff.zig");
const io = @import("../io.zig");

pub const StatusItem = struct {
    kind: st.StatusKind,
    path: []const u8,
};

pub fn StatusListItem(comptime Widget: type) type {
    return struct {
        box: wgt.Box(Widget),

        pub fn init(allocator: std.mem.Allocator, status: StatusItem) !StatusListItem(Widget) {
            const status_kind_sym = switch (status.kind) {
                .added => switch (status.kind.added) {
                    .created => "+",
                    .modified => "±",
                    .deleted => "-",
                },
                .not_added => switch (status.kind.not_added) {
                    .modified => "±",
                    .deleted => "-",
                },
                .not_tracked => "?",
            };
            var status_text = try wgt.TextBox(Widget).init(allocator, status_kind_sym, .hidden);
            errdefer status_text.deinit();

            var path_text = try wgt.TextBox(Widget).init(allocator, status.path, .hidden);
            errdefer path_text.deinit();

            var box = try wgt.Box(Widget).init(allocator, null, .horiz);
            errdefer box.deinit();
            try box.children.put(status_text.getFocus().id, .{ .widget = .{ .text_box = status_text }, .rect = null, .min_size = null });
            try box.children.put(path_text.getFocus().id, .{ .widget = .{ .text_box = path_text }, .rect = null, .min_size = null });

            return .{
                .box = box,
            };
        }

        pub fn deinit(self: *StatusListItem(Widget)) void {
            self.box.deinit();
        }

        pub fn build(self: *StatusListItem(Widget), constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            try self.box.build(constraint, root_focus);
        }

        pub fn input(self: *StatusListItem(Widget), key: inp.Key, root_focus: *Focus) !void {
            _ = self;
            _ = key;
            _ = root_focus;
        }

        pub fn clearGrid(self: *StatusListItem(Widget)) void {
            self.box.clearGrid();
        }

        pub fn getGrid(self: StatusListItem(Widget)) ?Grid {
            return self.box.getGrid();
        }

        pub fn getFocus(self: *StatusListItem(Widget)) *Focus {
            return self.box.getFocus();
        }

        pub fn setBorder(self: *StatusListItem(Widget), border_style: ?wgt.Box(Widget).BorderStyle) void {
            self.box.children.values()[1].widget.text_box.border_style = border_style;
        }
    };
}

pub fn StatusList(comptime Widget: type) type {
    return struct {
        scroll: wgt.Scroll(Widget),
        statuses: []StatusItem,

        pub fn init(allocator: std.mem.Allocator, statuses: []StatusItem) !StatusList(Widget) {
            // init inner_box
            var inner_box = try wgt.Box(Widget).init(allocator, null, .vert);
            errdefer inner_box.deinit();
            for (statuses) |item| {
                var list_item = try StatusListItem(Widget).init(allocator, item);
                errdefer list_item.deinit();
                list_item.getFocus().focusable = true;
                try inner_box.children.put(list_item.getFocus().id, .{ .widget = .{ .ui_status_list_item = list_item }, .rect = null, .min_size = null });
            }

            // init scroll
            var scroll = try wgt.Scroll(Widget).init(allocator, .{ .box = inner_box }, .vert);
            errdefer scroll.deinit();
            if (inner_box.children.count() > 0) {
                scroll.getFocus().child_id = inner_box.children.keys()[0];
            }

            return .{
                .scroll = scroll,
                .statuses = statuses,
            };
        }

        pub fn deinit(self: *StatusList(Widget)) void {
            self.scroll.deinit();
        }

        pub fn build(self: *StatusList(Widget), constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            const children = &self.scroll.child.box.children;
            for (children.keys(), children.values()) |id, *item| {
                item.widget.ui_status_list_item.setBorder(if (self.getFocus().child_id == id)
                    (if (root_focus.grandchild_id == id) .double else .single)
                else
                    .hidden);
            }
            try self.scroll.build(constraint, root_focus);
        }

        pub fn input(self: *StatusList(Widget), key: inp.Key, root_focus: *Focus) !void {
            if (self.getFocus().child_id) |child_id| {
                const children = &self.scroll.child.box.children;
                if (children.getIndex(child_id)) |current_index| {
                    const index = blk: {
                        switch (key) {
                            .arrow_up => {
                                break :blk current_index - 1;
                            },
                            .arrow_down => {
                                if (current_index + 1 < children.count()) {
                                    break :blk current_index + 1;
                                }
                            },
                            .home => {
                                break :blk 0;
                            },
                            .end => {
                                if (children.count() > 0) {
                                    break :blk children.count() - 1;
                                }
                            },
                            .page_up => {
                                if (self.getGrid()) |grid| {
                                    const half_count = (grid.size.height / 3) / 2;
                                    break :blk current_index -| half_count;
                                }
                            },
                            .page_down => {
                                if (self.getGrid()) |grid| {
                                    if (children.count() > 0) {
                                        const half_count = (grid.size.height / 3) / 2;
                                        break :blk @min(current_index + half_count, children.count() - 1);
                                    }
                                }
                            },
                            else => {},
                        }
                        break :blk current_index;
                    };

                    if (index != current_index) {
                        try root_focus.setFocus(children.keys()[index]);
                        self.updateScroll(index);
                    }
                }
            }
        }

        pub fn clearGrid(self: *StatusList(Widget)) void {
            self.scroll.clearGrid();
        }

        pub fn getGrid(self: StatusList(Widget)) ?Grid {
            return self.scroll.getGrid();
        }

        pub fn getFocus(self: *StatusList(Widget)) *Focus {
            return self.scroll.getFocus();
        }

        pub fn getSelectedIndex(self: StatusList(Widget)) ?usize {
            if (self.scroll.child.box.focus.child_id) |child_id| {
                const children = &self.scroll.child.box.children;
                return children.getIndex(child_id);
            } else {
                return null;
            }
        }

        fn updateScroll(self: *StatusList(Widget), index: usize) void {
            const left_box = &self.scroll.child.box;
            if (left_box.children.values()[index].rect) |rect| {
                self.scroll.scrollToRect(rect);
            }
        }
    };
}

pub fn StatusTabs(comptime Widget: type, comptime repo_kind: rp.RepoKind) type {
    return struct {
        box: wgt.Box(Widget),
        arena: std.heap.ArenaAllocator,

        const tab_count = @typeInfo(st.IndexKind).Enum.fields.len;

        pub fn init(allocator: std.mem.Allocator, status: *st.Status(repo_kind)) !StatusTabs(Widget, repo_kind) {
            var box = try wgt.Box(Widget).init(allocator, null, .horiz);
            errdefer box.deinit();

            var arena = std.heap.ArenaAllocator.init(allocator);
            errdefer arena.deinit();

            const counts = [_]usize{
                status.index_added.items.len + status.index_modified.items.len + status.index_deleted.items.len,
                status.workspace_modified.items.len + status.workspace_deleted.items.len,
                status.untracked.items.len,
            };

            var selected_maybe: ?st.IndexKind = null;

            inline for (@typeInfo(st.IndexKind).Enum.fields, 0..) |field, i| {
                const index_kind: st.IndexKind = @enumFromInt(field.value);
                if (selected_maybe == null and counts[i] > 0) {
                    selected_maybe = index_kind;
                }
                const name = switch (index_kind) {
                    .added => "added",
                    .not_added => "not added",
                    .not_tracked => "not tracked",
                };
                const label = try std.fmt.allocPrint(arena.allocator(), "{s} ({})", .{ name, counts[i] });
                var text_box = try wgt.TextBox(Widget).init(allocator, label, .single);
                errdefer text_box.deinit();
                text_box.getFocus().focusable = true;
                try box.children.put(text_box.getFocus().id, .{ .widget = .{ .text_box = text_box }, .rect = null, .min_size = null });
            }

            var ui_status_tabs = StatusTabs(Widget, repo_kind){
                .box = box,
                .arena = arena,
            };
            ui_status_tabs.getFocus().child_id = box.children.keys()[@intFromEnum(selected_maybe orelse .added)];
            return ui_status_tabs;
        }

        pub fn deinit(self: *StatusTabs(Widget, repo_kind)) void {
            self.box.deinit();
            self.arena.deinit();
        }

        pub fn build(self: *StatusTabs(Widget, repo_kind), constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            for (self.box.children.keys(), self.box.children.values()) |id, *tab| {
                tab.widget.text_box.border_style = if (self.getFocus().child_id == id)
                    (if (root_focus.grandchild_id == id) .double else .single)
                else
                    .hidden;
            }
            try self.box.build(constraint, root_focus);
        }

        pub fn input(self: *StatusTabs(Widget, repo_kind), key: inp.Key, root_focus: *Focus) !void {
            if (self.getFocus().child_id) |child_id| {
                const children = &self.box.children;
                if (children.getIndex(child_id)) |current_index| {
                    const index = blk: {
                        switch (key) {
                            .arrow_left => {
                                break :blk current_index - 1;
                            },
                            .arrow_right => {
                                if (current_index + 1 < children.count()) {
                                    break :blk current_index + 1;
                                }
                            },
                            else => {},
                        }
                        break :blk current_index;
                    };

                    if (index != current_index) {
                        try root_focus.setFocus(children.keys()[index]);
                    }
                }
            }
        }

        pub fn clearGrid(self: *StatusTabs(Widget, repo_kind)) void {
            self.box.clearGrid();
        }

        pub fn getGrid(self: StatusTabs(Widget, repo_kind)) ?Grid {
            return self.box.getGrid();
        }

        pub fn getFocus(self: *StatusTabs(Widget, repo_kind)) *Focus {
            return self.box.getFocus();
        }

        pub fn getSelectedIndex(self: StatusTabs(Widget, repo_kind)) ?usize {
            if (self.box.focus.child_id) |child_id| {
                const children = &self.box.children;
                return children.getIndex(child_id);
            } else {
                return null;
            }
        }
    };
}

pub fn StatusContent(comptime Widget: type, comptime repo_kind: rp.RepoKind) type {
    return struct {
        box: wgt.Box(Widget),
        filtered_statuses: std.ArrayList(StatusItem),
        repo: *rp.Repo(repo_kind),
        status: *st.Status(repo_kind),
        allocator: std.mem.Allocator,

        const FocusKind = enum { status_list, diff };

        pub fn init(allocator: std.mem.Allocator, repo: *rp.Repo(repo_kind), status: *st.Status(repo_kind), selected: st.IndexKind) !StatusContent(Widget, repo_kind) {
            var filtered_statuses = std.ArrayList(StatusItem).init(allocator);
            errdefer filtered_statuses.deinit();

            switch (selected) {
                .added => {
                    for (status.index_added.items) |path| {
                        try filtered_statuses.append(.{ .kind = .{ .added = .created }, .path = path });
                    }
                    for (status.index_modified.items) |path| {
                        try filtered_statuses.append(.{ .kind = .{ .added = .modified }, .path = path });
                    }
                    for (status.index_deleted.items) |path| {
                        try filtered_statuses.append(.{ .kind = .{ .added = .deleted }, .path = path });
                    }
                },
                .not_added => {
                    for (status.workspace_modified.items) |entry| {
                        try filtered_statuses.append(.{ .kind = .{ .not_added = .modified }, .path = entry.path });
                    }
                    for (status.workspace_deleted.items) |path| {
                        try filtered_statuses.append(.{ .kind = .{ .not_added = .deleted }, .path = path });
                    }
                },
                .not_tracked => {
                    for (status.untracked.items) |entry| {
                        try filtered_statuses.append(.{ .kind = .not_tracked, .path = entry.path });
                    }
                },
            }

            var box = try wgt.Box(Widget).init(allocator, null, .horiz);
            errdefer box.deinit();

            inline for (@typeInfo(FocusKind).Enum.fields) |focus_kind_field| {
                const focus_kind: FocusKind = @enumFromInt(focus_kind_field.value);
                switch (focus_kind) {
                    .status_list => {
                        var status_list = try StatusList(Widget).init(allocator, filtered_statuses.items);
                        errdefer status_list.deinit();
                        try box.children.put(status_list.getFocus().id, .{ .widget = .{ .ui_status_list = status_list }, .rect = null, .min_size = .{ .width = 20, .height = null } });
                    },
                    .diff => {
                        var diff = try ui_diff.Diff(Widget, repo_kind).init(allocator, repo);
                        errdefer diff.deinit();
                        diff.getFocus().focusable = true;
                        try box.children.put(diff.getFocus().id, .{ .widget = .{ .ui_diff = diff }, .rect = null, .min_size = .{ .width = 60, .height = null } });
                    },
                }
            }

            var status_content = StatusContent(Widget, repo_kind){
                .box = box,
                .filtered_statuses = filtered_statuses,
                .repo = repo,
                .status = status,
                .allocator = allocator,
            };
            status_content.getFocus().child_id = box.children.keys()[0];
            try status_content.updateDiff();
            return status_content;
        }

        pub fn deinit(self: *StatusContent(Widget, repo_kind)) void {
            self.box.deinit();
            self.filtered_statuses.deinit();
        }

        pub fn build(self: *StatusContent(Widget, repo_kind), constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            if (self.filtered_statuses.items.len > 0) {
                try self.box.build(constraint, root_focus);
            }
        }

        pub fn input(self: *StatusContent(Widget, repo_kind), key: inp.Key, root_focus: *Focus) !void {
            const diff_scroll_x = self.box.children.values()[1].widget.ui_diff.getScrollX();

            if (self.getFocus().child_id) |child_id| {
                if (self.box.children.getIndex(child_id)) |current_index| {
                    const child = &self.box.children.values()[current_index].widget;

                    var index = blk: {
                        switch (key) {
                            .arrow_left => {
                                if (child.* == .ui_diff and diff_scroll_x == 0) {
                                    break :blk @intFromEnum(FocusKind.status_list);
                                }
                            },
                            .arrow_right => {
                                if (child.* == .ui_status_list) {
                                    break :blk @intFromEnum(FocusKind.diff);
                                }
                            },
                            .codepoint => {
                                switch (key.codepoint) {
                                    13 => {
                                        if (child.* == .ui_status_list) {
                                            break :blk @intFromEnum(FocusKind.status_list);
                                        }
                                    },
                                    127, '\x1B' => {
                                        if (child.* == .ui_diff) {
                                            break :blk @intFromEnum(FocusKind.diff);
                                        }
                                    },
                                    else => {},
                                }
                            },
                            else => {},
                        }
                        try child.input(key, root_focus);
                        if (child.* == .ui_status_list) {
                            try self.updateDiff();
                        }
                        break :blk current_index;
                    };

                    if (index == @intFromEnum(FocusKind.diff) and self.box.children.values()[@intFromEnum(FocusKind.diff)].widget.ui_diff.isEmpty()) {
                        index = @intFromEnum(FocusKind.status_list);
                    }

                    if (index != current_index) {
                        try root_focus.setFocus(self.box.children.keys()[index]);
                    }
                }
            }
        }

        pub fn clearGrid(self: *StatusContent(Widget, repo_kind)) void {
            self.box.clearGrid();
        }

        pub fn getGrid(self: StatusContent(Widget, repo_kind)) ?Grid {
            return self.box.getGrid();
        }

        pub fn getFocus(self: *StatusContent(Widget, repo_kind)) *Focus {
            return self.box.getFocus();
        }

        pub fn scrolledToTop(self: StatusContent(Widget, repo_kind)) bool {
            if (self.box.focus.child_id) |child_id| {
                if (self.box.children.getIndex(child_id)) |current_index| {
                    const child = &self.box.children.values()[current_index].widget;
                    switch (child.*) {
                        .ui_status_list => {
                            const status_list = &child.ui_status_list;
                            if (status_list.getSelectedIndex()) |status_index| {
                                return status_index == 0;
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

        fn updateDiff(self: *StatusContent(Widget, repo_kind)) !void {
            const status_list = &self.box.children.values()[0].widget.ui_status_list;
            if (status_list.getSelectedIndex()) |status_index| {
                const status_item = status_list.statuses[status_index];

                // get widget
                var diff = &self.box.children.values()[1].widget.ui_diff;
                try diff.clearDiffs();

                var line_iter_pair = self.repo.filePair(status_item.path, status_item.kind, self.status) catch |err| switch (err) {
                    error.IsDir => return,
                    else => return err,
                };
                defer line_iter_pair.deinit();

                var hunk_iter = try df.HunkIterator(repo_kind).init(self.allocator, &line_iter_pair.a, &line_iter_pair.b);
                defer hunk_iter.deinit();
                try diff.addHunks(&hunk_iter);
            }
        }
    };
}

pub fn Status(comptime Widget: type, comptime repo_kind: rp.RepoKind) type {
    return struct {
        box: wgt.Box(Widget),
        status: *st.Status(repo_kind),
        allocator: std.mem.Allocator,

        const FocusKind = enum { status_tabs, status_content };

        pub fn init(allocator: std.mem.Allocator, repo: *rp.Repo(repo_kind)) !Status(Widget, repo_kind) {
            var status = try repo.status();
            errdefer status.deinit();

            // put Status object on the heap so the pointer is stable
            const status_ptr = try allocator.create(st.Status(repo_kind));
            errdefer allocator.destroy(status_ptr);
            status_ptr.* = status;

            // init box
            var box = try wgt.Box(Widget).init(allocator, null, .vert);
            errdefer box.deinit();

            inline for (@typeInfo(FocusKind).Enum.fields) |focus_kind_field| {
                const focus_kind: FocusKind = @enumFromInt(focus_kind_field.value);
                switch (focus_kind) {
                    .status_tabs => {
                        var status_tabs = try StatusTabs(Widget, repo_kind).init(allocator, status_ptr);
                        errdefer status_tabs.deinit();
                        try box.children.put(status_tabs.getFocus().id, .{ .widget = .{ .ui_status_tabs = status_tabs }, .rect = null, .min_size = null });
                    },
                    .status_content => {
                        var stack = ui_root.RootStack(Widget).init(allocator);
                        errdefer stack.deinit();

                        inline for (@typeInfo(st.IndexKind).Enum.fields) |index_kind_field| {
                            const index_kind: st.IndexKind = @enumFromInt(index_kind_field.value);
                            var status_content = try StatusContent(Widget, repo_kind).init(allocator, repo, status_ptr, index_kind);
                            errdefer status_content.deinit();
                            try stack.children.put(status_content.getFocus().id, .{ .ui_status_content = status_content });
                        }

                        try box.children.put(stack.getFocus().id, .{ .widget = .{ .ui_root_stack = stack }, .rect = null, .min_size = null });
                    },
                }
            }

            var ui_status = Status(Widget, repo_kind){
                .box = box,
                .status = status_ptr,
                .allocator = allocator,
            };
            ui_status.getFocus().child_id = box.children.keys()[0];
            return ui_status;
        }

        pub fn deinit(self: *Status(Widget, repo_kind)) void {
            self.box.deinit();
            self.status.deinit();
            self.allocator.destroy(self.status);
        }

        pub fn build(self: *Status(Widget, repo_kind), constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            const status_tabs = &self.box.children.values()[@intFromEnum(FocusKind.status_tabs)].widget.ui_status_tabs;
            const stack = &self.box.children.values()[@intFromEnum(FocusKind.status_content)].widget.ui_root_stack;
            if (status_tabs.getSelectedIndex()) |index| {
                stack.getFocus().child_id = stack.children.keys()[index];
            }
            try self.box.build(constraint, root_focus);
        }

        pub fn input(self: *Status(Widget, repo_kind), key: inp.Key, root_focus: *Focus) !void {
            if (self.getFocus().child_id) |child_id| {
                if (self.box.children.getIndex(child_id)) |current_index| {
                    const child = &self.box.children.values()[current_index].widget;

                    var index = blk: {
                        switch (child.*) {
                            .ui_status_tabs => {
                                const status_tabs = &child.ui_status_tabs;
                                if (key == .arrow_down) {
                                    break :blk @intFromEnum(FocusKind.status_content);
                                } else {
                                    try status_tabs.input(key, root_focus);
                                }
                            },
                            .ui_root_stack => {
                                const stack = &child.ui_root_stack;
                                if (stack.getSelected()) |selected_widget| {
                                    if (key == .arrow_up and selected_widget.ui_status_content.scrolledToTop()) {
                                        break :blk @intFromEnum(FocusKind.status_tabs);
                                    } else {
                                        try stack.input(key, root_focus);
                                    }
                                }
                            },
                            else => {},
                        }
                        break :blk current_index;
                    };

                    if (index == @intFromEnum(FocusKind.status_content)) {
                        if (self.box.children.values()[@intFromEnum(FocusKind.status_content)].widget.ui_root_stack.getSelected()) |selected_widget| {
                            if (selected_widget.ui_status_content.getGrid() == null) {
                                index = @intFromEnum(FocusKind.status_tabs);
                            }
                        }
                    }

                    if (index != current_index) {
                        try root_focus.setFocus(self.box.children.keys()[index]);
                    }
                }
            }
        }

        pub fn clearGrid(self: *Status(Widget, repo_kind)) void {
            self.box.clearGrid();
        }

        pub fn getGrid(self: Status(Widget, repo_kind)) ?Grid {
            return self.box.getGrid();
        }

        pub fn getFocus(self: *Status(Widget, repo_kind)) *Focus {
            return self.box.getFocus();
        }

        pub fn getSelectedIndex(self: Status(Widget, repo_kind)) ?usize {
            if (self.box.focus.child_id) |child_id| {
                const children = &self.box.children;
                return children.getIndex(child_id);
            } else {
                return null;
            }
        }
    };
}
