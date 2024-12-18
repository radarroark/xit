const std = @import("std");

const zlib = @import("deps/zlib.zig");
const mbedtls = @import("deps/mbedtls.zig");
const libssh2 = @import("deps/libssh2.zig");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    // main
    {
        const z = zlib.create(b, target, optimize);
        const tls = mbedtls.create(b, target, optimize);
        const ssh2 = libssh2.create(b, target, optimize);
        tls.link(ssh2.step);

        const exe = b.addExecutable(.{
            .name = "xit",
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        });
        //exe.root_module.addAnonymousImport("xitdb", .{
        //    .root_source_file = b.path("../xitdb/src/lib.zig"),
        //});
        //exe.root_module.addAnonymousImport("xitui", .{
        //    .root_source_file = b.path("../xitui/src/lib.zig"),
        //});
        exe.root_module.addImport("xitdb", b.dependency("xitdb", .{}).module("xitdb"));
        exe.root_module.addImport("xitui", b.dependency("xitui", .{}).module("xitui"));
        exe.root_module.addImport("network", b.dependency("network", .{}).module("network"));
        exe.linkLibC();
        exe.linkLibrary(z.step);
        exe.linkLibrary(tls.step);
        exe.linkLibrary(ssh2.step);
        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        const run_step = b.step("run", "Run the app");
        run_step.dependOn(&run_cmd.step);
    }

    // try
    {
        const z = zlib.create(b, target, optimize);
        const tls = mbedtls.create(b, target, optimize);
        const ssh2 = libssh2.create(b, target, optimize);
        tls.link(ssh2.step);

        const exe = b.addExecutable(.{
            .name = "try",
            .root_source_file = b.path("src/try.zig"),
            .target = target,
            .optimize = optimize,
        });
        //exe.root_module.addAnonymousImport("xitdb", .{
        //    .root_source_file = b.path("../xitdb/src/lib.zig"),
        //});
        //exe.root_module.addAnonymousImport("xitui", .{
        //    .root_source_file = b.path("../xitui/src/lib.zig"),
        //});
        exe.root_module.addImport("xitdb", b.dependency("xitdb", .{}).module("xitdb"));
        exe.root_module.addImport("xitui", b.dependency("xitui", .{}).module("xitui"));
        exe.root_module.addImport("network", b.dependency("network", .{}).module("network"));
        exe.linkLibC();
        exe.linkLibrary(z.step);
        exe.linkLibrary(tls.step);
        exe.linkLibrary(ssh2.step);
        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        const run_step = b.step("try", "Try the app");
        run_step.dependOn(&run_cmd.step);
    }

    // test
    {
        const libgit2 = @import("deps/test/libgit2.zig");

        const z = zlib.create(b, target, optimize);
        const tls = mbedtls.create(b, target, optimize);
        const ssh2 = libssh2.create(b, target, optimize);
        tls.link(ssh2.step);

        const git2 = try libgit2.create(b, target, optimize);
        ssh2.link(git2.step);
        tls.link(git2.step);
        z.link(git2.step);

        const unit_tests = b.addTest(.{
            .root_source_file = b.path("src/test.zig"),
            .optimize = optimize,
        });
        //unit_tests.root_module.addAnonymousImport("xitdb", .{
        //    .root_source_file = b.path("../xitdb/src/lib.zig"),
        //});
        //unit_tests.root_module.addAnonymousImport("xitui", .{
        //    .root_source_file = b.path("../xitui/src/lib.zig"),
        //});
        unit_tests.root_module.addImport("xitdb", b.dependency("xitdb", .{}).module("xitdb"));
        unit_tests.root_module.addImport("xitui", b.dependency("xitui", .{}).module("xitui"));
        unit_tests.root_module.addImport("network", b.dependency("network", .{}).module("network"));
        unit_tests.linkLibC();
        unit_tests.addIncludePath(b.path("deps/test/libgit2/include"));
        unit_tests.linkLibrary(git2.step);

        const run_unit_tests = b.addRunArtifact(unit_tests);
        run_unit_tests.has_side_effects = true;
        const test_step = b.step("test", "Run unit tests");
        test_step.dependOn(&run_unit_tests.step);
    }

    // testnet
    {
        const libgit2 = @import("deps/test/libgit2.zig");

        const z = zlib.create(b, target, optimize);
        const tls = mbedtls.create(b, target, optimize);
        const ssh2 = libssh2.create(b, target, optimize);
        tls.link(ssh2.step);

        const git2 = try libgit2.create(b, target, optimize);
        ssh2.link(git2.step);
        tls.link(git2.step);
        z.link(git2.step);

        const unit_tests = b.addTest(.{
            .root_source_file = b.path("src/testnet.zig"),
            .optimize = optimize,
        });
        //unit_tests.root_module.addAnonymousImport("xitdb", .{
        //    .root_source_file = b.path("../xitdb/src/lib.zig"),
        //});
        //unit_tests.root_module.addAnonymousImport("xitui", .{
        //    .root_source_file = b.path("../xitui/src/lib.zig"),
        //});
        unit_tests.root_module.addImport("xitdb", b.dependency("xitdb", .{}).module("xitdb"));
        unit_tests.root_module.addImport("xitui", b.dependency("xitui", .{}).module("xitui"));
        unit_tests.root_module.addImport("network", b.dependency("network", .{}).module("network"));
        unit_tests.linkLibC();
        unit_tests.addIncludePath(b.path("deps/test/libgit2/include"));
        unit_tests.linkLibrary(git2.step);

        const run_unit_tests = b.addRunArtifact(unit_tests);
        run_unit_tests.has_side_effects = true;
        const test_step = b.step("testnet", "Run network unit tests");
        test_step.dependOn(&run_unit_tests.step);
    }
}
