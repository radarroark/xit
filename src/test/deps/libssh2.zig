// https://github.com/mattnite/zig-libssh2

const std = @import("std");

fn root() []const u8 {
    return std.fs.path.dirname(@src().file) orelse unreachable;
}

const root_path = root() ++ "/";
const srcs = &.{
    root_path ++ "libssh2/src/channel.c",
    root_path ++ "libssh2/src/comp.c",
    root_path ++ "libssh2/src/crypt.c",
    root_path ++ "libssh2/src/hostkey.c",
    root_path ++ "libssh2/src/kex.c",
    root_path ++ "libssh2/src/mac.c",
    root_path ++ "libssh2/src/misc.c",
    root_path ++ "libssh2/src/packet.c",
    root_path ++ "libssh2/src/publickey.c",
    root_path ++ "libssh2/src/scp.c",
    root_path ++ "libssh2/src/session.c",
    root_path ++ "libssh2/src/sftp.c",
    root_path ++ "libssh2/src/userauth.c",
    root_path ++ "libssh2/src/transport.c",
    root_path ++ "libssh2/src/version.c",
    root_path ++ "libssh2/src/knownhost.c",
    root_path ++ "libssh2/src/agent.c",
    root_path ++ "libssh2/src/mbedtls.c",
    root_path ++ "libssh2/src/pem.c",
    root_path ++ "libssh2/src/keepalive.c",
    root_path ++ "libssh2/src/global.c",
    root_path ++ "libssh2/src/blowfish.c",
    root_path ++ "libssh2/src/bcrypt_pbkdf.c",
    root_path ++ "libssh2/src/agent_win.c",
};

pub const include_dir = root_path ++ "libssh2/include";
const config_dir = root_path ++ "libssh2_extra";

pub const Library = struct {
    step: *std.build.LibExeObjStep,

    pub fn link(self: Library, other: *std.build.LibExeObjStep) void {
        other.addIncludePath(.{ .cwd_relative = include_dir });
        other.linkLibrary(self.step);
    }
};

pub fn create(
    b: *std.build.Builder,
    target: std.zig.CrossTarget,
    optimize: std.builtin.OptimizeMode,
) Library {
    const ret = b.addStaticLibrary(.{
        .name = "ssh2",
        .target = target,
        .optimize = optimize,
    });
    ret.addIncludePath(.{ .cwd_relative = include_dir });
    ret.addIncludePath(.{ .cwd_relative = config_dir });
    ret.addCSourceFiles(.{
        .files = srcs,
        .flags = &.{},
    });
    ret.linkLibC();

    ret.defineCMacro("LIBSSH2_MBEDTLS", null);
    if (target.isWindows()) {
        ret.defineCMacro("_CRT_SECURE_NO_DEPRECATE", "1");
        ret.defineCMacro("HAVE_LIBCRYPT32", null);
        ret.defineCMacro("HAVE_WINSOCK2_H", null);
        ret.defineCMacro("HAVE_IOCTLSOCKET", null);
        ret.defineCMacro("HAVE_SELECT", null);
        ret.defineCMacro("LIBSSH2_DH_GEX_NEW", "1");

        if (target.getAbi().isGnu()) {
            ret.defineCMacro("HAVE_UNISTD_H", null);
            ret.defineCMacro("HAVE_INTTYPES_H", null);
            ret.defineCMacro("HAVE_SYS_TIME_H", null);
            ret.defineCMacro("HAVE_GETTIMEOFDAY", null);
        }
    } else {
        ret.defineCMacro("HAVE_UNISTD_H", null);
        ret.defineCMacro("HAVE_INTTYPES_H", null);
        ret.defineCMacro("HAVE_STDLIB_H", null);
        ret.defineCMacro("HAVE_SYS_SELECT_H", null);
        ret.defineCMacro("HAVE_SYS_UIO_H", null);
        ret.defineCMacro("HAVE_SYS_SOCKET_H", null);
        ret.defineCMacro("HAVE_SYS_IOCTL_H", null);
        ret.defineCMacro("HAVE_SYS_TIME_H", null);
        ret.defineCMacro("HAVE_SYS_UN_H", null);
        ret.defineCMacro("HAVE_LONGLONG", null);
        ret.defineCMacro("HAVE_GETTIMEOFDAY", null);
        ret.defineCMacro("HAVE_INET_ADDR", null);
        ret.defineCMacro("HAVE_POLL", null);
        ret.defineCMacro("HAVE_SELECT", null);
        ret.defineCMacro("HAVE_SOCKET", null);
        ret.defineCMacro("HAVE_STRTOLL", null);
        ret.defineCMacro("HAVE_SNPRINTF", null);
        ret.defineCMacro("HAVE_O_NONBLOCK", null);
    }

    return Library{ .step = ret };
}
