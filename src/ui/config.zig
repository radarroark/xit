const std = @import("std");
const xitui = @import("xitui");
const wgt = xitui.widget;
const layout = xitui.layout;
const inp = xitui.input;
const Grid = xitui.grid.Grid;
const Focus = xitui.focus.Focus;
const rp = @import("../repo.zig");
const cfg = @import("../config.zig");

pub fn Config(comptime Widget: type, comptime repo_kind: rp.RepoKind) type {
    return struct {
        box: wgt.Box(Widget),
        config: cfg.Config(repo_kind),
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, repo: *rp.Repo(repo_kind)) !Config(Widget, repo_kind) {
            var config = try repo.config();
            errdefer config.deinit();

            // init box
            var box = try wgt.Box(Widget).init(allocator, null, .vert);
            errdefer box.deinit();

            for (config.sections.keys()) |section_name| {
                var text_box = try wgt.TextBox(Widget).init(allocator, section_name, .single);
                errdefer text_box.deinit();
                text_box.getFocus().focusable = true;
                try box.children.put(text_box.getFocus().id, .{ .widget = .{ .text_box = text_box }, .rect = null, .min_size = null });
            }

            var ui_config = Config(Widget, repo_kind){
                .box = box,
                .config = config,
                .allocator = allocator,
            };
            if (box.children.count() > 0) {
                ui_config.getFocus().child_id = box.children.keys()[0];
            }
            return ui_config;
        }

        pub fn deinit(self: *Config(Widget, repo_kind)) void {
            self.box.deinit();
            self.config.deinit();
        }

        pub fn build(self: *Config(Widget, repo_kind), constraint: layout.Constraint, root_focus: *Focus) !void {
            self.clearGrid();
            for (self.box.children.keys(), self.box.children.values()) |id, *tab| {
                tab.widget.text_box.border_style = if (self.getFocus().child_id == id)
                    (if (root_focus.grandchild_id == id) .double else .single)
                else
                    .hidden;
            }
            try self.box.build(constraint, root_focus);
        }

        pub fn input(self: *Config(Widget, repo_kind), key: inp.Key, root_focus: *Focus) !void {
            if (self.getFocus().child_id) |child_id| {
                const children = &self.box.children;
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
                    }
                }
            }
        }

        pub fn clearGrid(self: *Config(Widget, repo_kind)) void {
            self.box.clearGrid();
        }

        pub fn getGrid(self: Config(Widget, repo_kind)) ?Grid {
            return self.box.getGrid();
        }

        pub fn getFocus(self: *Config(Widget, repo_kind)) *Focus {
            return self.box.getFocus();
        }

        pub fn getSelectedIndex(self: Config(Widget, repo_kind)) ?usize {
            if (self.box.focus.child_id) |child_id| {
                const children = &self.box.children;
                return children.getIndex(child_id);
            } else {
                return null;
            }
        }
    };
}
