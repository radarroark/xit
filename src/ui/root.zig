const std = @import("std");
const xitui = @import("xitui");
const wgt = xitui.widget;
const layout = xitui.layout;
const inp = xitui.input;
const Grid = xitui.grid.Grid;
const Focus = xitui.focus.Focus;
const ui_log = @import("./log.zig");
const rp = @import("../repo.zig");

pub fn RootTabs(comptime Widget: type) type {
    return struct {
        box: wgt.Box(Widget),

        const FocusKind = enum { log, status };

        pub fn init(allocator: std.mem.Allocator) !RootTabs(Widget) {
            var box = try wgt.Box(Widget).init(allocator, null, .horiz);
            errdefer box.deinit();

            inline for (@typeInfo(FocusKind).Enum.fields) |focus_kind_field| {
                const focus_kind: FocusKind = @enumFromInt(focus_kind_field.value);
                const name = switch (focus_kind) {
                    .log => "log",
                    .status => "status",
                };
                var text_box = try wgt.TextBox(Widget).init(allocator, name, .single);
                errdefer text_box.deinit();
                text_box.getFocus().focusable = true;
                try box.children.put(text_box.getFocus().id, .{ .widget = .{ .text_box = text_box }, .rect = null, .min_size = null });
            }

            var ui_root_tabs = RootTabs(Widget){
                .box = box,
            };
            ui_root_tabs.getFocus().child_id = box.children.keys()[0];
            return ui_root_tabs;
        }

        pub fn deinit(self: *RootTabs(Widget)) void {
            self.box.deinit();
        }

        pub fn build(self: *RootTabs(Widget), constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            for (self.box.children.keys(), self.box.children.values()) |id, *tab| {
                tab.widget.text_box.border_style = if (self.getFocus().child_id == id)
                    (if (root_focus.grandchild_id == id) .double else .single)
                else
                    .hidden;
            }
            try self.box.build(constraint, root_focus);
        }

        pub fn input(self: *RootTabs(Widget), key: inp.Key, root_focus: *Focus) !void {
            if (self.getFocus().child_id) |child_id| {
                const children = &self.box.children;
                if (children.getIndex(child_id)) |current_index| {
                    var index = current_index;

                    switch (key) {
                        .arrow_left => {
                            index -|= 1;
                        },
                        .arrow_right => {
                            if (index + 1 < self.box.children.count()) {
                                index += 1;
                            }
                        },
                        else => {},
                    }

                    if (index != current_index) {
                        try root_focus.setFocus(children.keys()[index]);
                    }
                }
            }
        }

        pub fn clearGrid(self: *RootTabs(Widget)) void {
            self.box.clearGrid();
        }

        pub fn getGrid(self: RootTabs(Widget)) ?Grid {
            return self.box.getGrid();
        }

        pub fn getFocus(self: *RootTabs(Widget)) *Focus {
            return self.box.getFocus();
        }

        pub fn getSelectedIndex(self: RootTabs(Widget)) ?usize {
            if (self.box.focus.child_id) |child_id| {
                const children = &self.box.children;
                return children.getIndex(child_id);
            } else {
                return null;
            }
        }
    };
}

pub fn RootStack(comptime Widget: type) type {
    return struct {
        focus: Focus,
        children: std.AutoArrayHashMap(usize, Widget),

        pub fn init(allocator: std.mem.Allocator) RootStack(Widget) {
            return .{
                .focus = Focus.init(allocator),
                .children = std.AutoArrayHashMap(usize, Widget).init(allocator),
            };
        }

        pub fn deinit(self: *RootStack(Widget)) void {
            self.focus.deinit();
            for (self.children.values()) |*child| {
                child.deinit();
            }
            self.children.deinit();
        }

        pub fn build(self: *RootStack(Widget), constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            self.getFocus().clear();
            if (self.getSelected()) |selected_widget| {
                try selected_widget.build(constraint, root_focus);
                if (selected_widget.getGrid()) |child_grid| {
                    try self.getFocus().addChild(selected_widget.getFocus(), child_grid.size, 0, 0);
                }
            }
        }

        pub fn input(self: *RootStack(Widget), key: inp.Key, root_focus: *Focus) !void {
            if (self.getSelected()) |selected_widget| {
                try selected_widget.input(key, root_focus);
            }
        }

        pub fn clearGrid(self: *RootStack(Widget)) void {
            if (self.getSelected()) |selected_widget| {
                selected_widget.clearGrid();
            }
        }

        pub fn getGrid(self: RootStack(Widget)) ?Grid {
            if (self.getSelected()) |selected_widget| {
                return selected_widget.getGrid();
            } else {
                return null;
            }
        }

        pub fn getFocus(self: *RootStack(Widget)) *Focus {
            return &self.focus;
        }

        pub fn getSelected(self: RootStack(Widget)) ?*Widget {
            if (self.focus.child_id) |child_id| {
                if (self.children.getIndex(child_id)) |current_index| {
                    return &self.children.values()[current_index];
                }
            }
            return null;
        }
    };
}

pub fn Root(comptime Widget: type, comptime repo_kind: rp.RepoKind) type {
    return struct {
        box: wgt.Box(Widget),

        const FocusKind = enum { tabs, stack };

        pub fn init(allocator: std.mem.Allocator, repo: *rp.Repo(repo_kind)) !Root(Widget, repo_kind) {
            var box = try wgt.Box(Widget).init(allocator, null, .vert);
            errdefer box.deinit();

            inline for (@typeInfo(FocusKind).Enum.fields) |focus_kind_field| {
                const focus_kind: FocusKind = @enumFromInt(focus_kind_field.value);
                switch (focus_kind) {
                    .tabs => {
                        var ui_root_tabs = try RootTabs(Widget).init(allocator);
                        errdefer ui_root_tabs.deinit();
                        try box.children.put(ui_root_tabs.getFocus().id, .{ .widget = .{ .ui_root_tabs = ui_root_tabs }, .rect = null, .min_size = null });
                    },
                    .stack => {
                        var stack = RootStack(Widget).init(allocator);
                        errdefer stack.deinit();

                        {
                            var log = Widget{ .ui_log = try ui_log.Log(Widget, repo_kind).init(allocator, repo) };
                            errdefer log.deinit();
                            try stack.children.put(log.getFocus().id, log);
                        }

                        {
                            var stat = Widget{ .text_box = try wgt.TextBox(Widget).init(allocator, "Status", .hidden) };
                            errdefer stat.deinit();
                            try stack.children.put(stat.getFocus().id, stat);
                        }

                        try box.children.put(stack.getFocus().id, .{ .widget = .{ .ui_root_stack = stack }, .rect = null, .min_size = null });
                    },
                }
            }

            var ui_root = Root(Widget, repo_kind){
                .box = box,
            };
            ui_root.getFocus().child_id = box.children.keys()[0];
            return ui_root;
        }

        pub fn deinit(self: *Root(Widget, repo_kind)) void {
            self.box.deinit();
        }

        pub fn build(self: *Root(Widget, repo_kind), constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            const ui_root_tabs = &self.box.children.values()[@intFromEnum(FocusKind.tabs)].widget.ui_root_tabs;
            const ui_root_stack = &self.box.children.values()[@intFromEnum(FocusKind.stack)].widget.ui_root_stack;
            if (ui_root_tabs.getSelectedIndex()) |index| {
                ui_root_stack.getFocus().child_id = ui_root_stack.children.keys()[index];
            }
            try self.box.build(constraint, root_focus);
        }

        pub fn input(self: *Root(Widget, repo_kind), key: inp.Key, root_focus: *Focus) !void {
            if (self.getFocus().child_id) |child_id| {
                if (self.box.children.getIndex(child_id)) |current_index| {
                    const child = &self.box.children.values()[current_index].widget;
                    var index = current_index;

                    switch (key) {
                        .arrow_up => {
                            switch (child.*) {
                                .ui_root_tabs => {
                                    try child.input(key, root_focus);
                                },
                                .ui_root_stack => {
                                    if (child.ui_root_stack.getSelected()) |selected_widget| {
                                        switch (selected_widget.*) {
                                            .ui_log => {
                                                if (selected_widget.ui_log.scrolledToTop()) {
                                                    index = @intFromEnum(FocusKind.tabs);
                                                } else {
                                                    try child.input(key, root_focus);
                                                }
                                            },
                                            else => {},
                                        }
                                    }
                                },
                                else => {},
                            }
                        },
                        .arrow_down => {
                            switch (child.*) {
                                .ui_root_tabs => {
                                    index = @intFromEnum(FocusKind.stack);
                                },
                                .ui_root_stack => {
                                    try child.input(key, root_focus);
                                },
                                else => {},
                            }
                        },
                        else => {
                            try child.input(key, root_focus);
                        },
                    }

                    if (index != current_index) {
                        try root_focus.setFocus(self.box.children.keys()[index]);
                    }
                }
            }
        }

        pub fn clearGrid(self: *Root(Widget, repo_kind)) void {
            self.box.clearGrid();
        }

        pub fn getGrid(self: Root(Widget, repo_kind)) ?Grid {
            return self.box.getGrid();
        }

        pub fn getFocus(self: *Root(Widget, repo_kind)) *Focus {
            return self.box.getFocus();
        }
    };
}
