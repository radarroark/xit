const std = @import("std");
const xitui = @import("xitui");
const term = xitui.terminal;
const wgt = xitui.widget;
const layout = xitui.layout;
const inp = xitui.input;
const Grid = xitui.grid.Grid;
const Focus = xitui.focus.Focus;
const ui_root = @import("./ui/root.zig");
const ui_log = @import("./ui/log.zig");
const rp = @import("./repo.zig");

pub fn Widget(comptime repo_kind: rp.RepoKind) type {
    return union(enum) {
        text: wgt.Text(Widget(repo_kind)),
        box: wgt.Box(Widget(repo_kind)),
        text_box: wgt.TextBox(Widget(repo_kind)),
        scroll: wgt.Scroll(Widget(repo_kind)),
        ui_root: ui_root.Root(Widget(repo_kind), repo_kind),
        ui_root_stack: ui_root.RootStack(Widget(repo_kind)),
        ui_root_tabs: ui_root.RootTabs(Widget(repo_kind)),
        ui_log: ui_log.Log(Widget(repo_kind), repo_kind),
        ui_log_commit_list: ui_log.LogCommitList(Widget(repo_kind), repo_kind),

        pub fn deinit(self: *Widget(repo_kind)) void {
            switch (self.*) {
                inline else => |*case| case.deinit(),
            }
        }

        pub fn build(self: *Widget(repo_kind), constraint: layout.Constraint, root_focus: *Focus) anyerror!void {
            switch (self.*) {
                inline else => |*case| try case.build(constraint, root_focus),
            }
        }

        pub fn input(self: *Widget(repo_kind), key: inp.Key, root_focus: *Focus) anyerror!void {
            switch (self.*) {
                inline else => |*case| try case.input(key, root_focus),
            }
        }

        pub fn clearGrid(self: *Widget(repo_kind)) void {
            switch (self.*) {
                inline else => |*case| case.clearGrid(),
            }
        }

        pub fn getGrid(self: Widget(repo_kind)) ?Grid {
            switch (self) {
                inline else => |*case| return case.getGrid(),
            }
        }

        pub fn getFocus(self: *Widget(repo_kind)) *Focus {
            switch (self.*) {
                inline else => |*case| return case.getFocus(),
            }
        }
    };
}

pub fn start(comptime repo_kind: rp.RepoKind, repo: *rp.Repo(repo_kind), allocator: std.mem.Allocator) !void {
    // init root widget
    var root = Widget(repo_kind){ .ui_root = try ui_root.Root(Widget(repo_kind), repo_kind).init(allocator, repo) };
    defer root.deinit();

    // set initial focus for root widget
    try root.build(.{
        .min_size = .{ .width = null, .height = null },
        .max_size = .{ .width = 10, .height = 10 },
    }, root.getFocus());
    if (root.getFocus().child_id) |child_id| {
        try root.getFocus().setFocus(child_id);
    }

    // init term
    term.terminal = try term.Terminal.init(allocator);
    defer term.terminal.deinit();

    var last_size = layout.Size{ .width = 0, .height = 0 };
    var last_grid = try Grid.init(allocator, last_size);
    defer last_grid.deinit();

    while (true) {
        // render to tty
        try term.terminal.render(&root, &last_grid, &last_size);

        // process any inputs
        while (try term.terminal.readKey()) |key| {
            if (key == .codepoint and key.codepoint == 'q') {
                return;
            }
            try root.input(key, root.getFocus());
        }

        // rebuild widget
        try root.build(.{
            .min_size = .{ .width = null, .height = null },
            .max_size = .{ .width = last_size.width, .height = last_size.height },
        }, root.getFocus());

        // TODO: do variable sleep with target frame rate
        std.time.sleep(5000000);
    }
}
