comptime {
    _ = @import("test/net.zig");

    // this has nothing to do with networking,
    // but it's here because it needs to shell
    // out to ssh, and I don't want the regular
    // tests to have to do that
    _ = @import("test/sign.zig");
}
