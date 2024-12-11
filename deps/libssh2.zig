const std = @import("std");

fn root() []const u8 {
    return std.fs.path.dirname(@src().file) orelse unreachable;
}

const srcs = &.{
    "libssh2/src/crypto.c",
    "libssh2/src/scp.c",
    "libssh2/src/wincng.c",
    "libssh2/src/knownhost.c",
    "libssh2/src/userauth.c",
    "libssh2/src/mbedtls.c",
    "libssh2/src/poly1305.c",
    "libssh2/src/misc.c",
    "libssh2/src/mac.c",
    "libssh2/src/publickey.c",
    "libssh2/src/channel.c",
    "libssh2/src/session.c",
    "libssh2/src/blowfish.c",
    "libssh2/src/agent.c",
    "libssh2/src/keepalive.c",
    "libssh2/src/hostkey.c",
    "libssh2/src/libgcrypt.c",
    "libssh2/src/global.c",
    "libssh2/src/userauth_kbd_packet.c",
    "libssh2/src/chacha.c",
    "libssh2/src/kex.c",
    "libssh2/src/pem.c",
    "libssh2/src/openssl.c",
    "libssh2/src/transport.c",
    "libssh2/src/cipher-chachapoly.c",
    "libssh2/src/version.c",
    "libssh2/src/agent_win.c",
    "libssh2/src/sftp.c",
    "libssh2/src/bcrypt_pbkdf.c",
    "libssh2/src/crypt.c",
    "libssh2/src/packet.c",
    "libssh2/src/comp.c",
    "libssh2/src/os400qc3.c",
};

const root_path = root() ++ "/";
pub const include_dir = root_path ++ "libssh2/include";
const config_dir = root_path ++ "libssh2_extra";

pub const Library = struct {
    step: *std.Build.Step.Compile,

    pub fn link(self: Library, other: *std.Build.Step.Compile) void {
        other.addIncludePath(.{ .cwd_relative = include_dir });
        other.linkLibrary(self.step);
    }
};

pub fn create(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
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
        .root = .{ .cwd_relative = root() },
        .files = srcs,
        .flags = &.{},
    });
    ret.linkLibC();

    ret.defineCMacro("LIBSSH2_MBEDTLS", null);
    if (target.result.os.tag == .windows) {
        ret.defineCMacro("_CRT_SECURE_NO_DEPRECATE", "1");
        ret.defineCMacro("HAVE_LIBCRYPT32", null);
        ret.defineCMacro("HAVE_WINSOCK2_H", null);
        ret.defineCMacro("HAVE_IOCTLSOCKET", null);
        ret.defineCMacro("HAVE_SELECT", null);
        ret.defineCMacro("LIBSSH2_DH_GEX_NEW", "1");

        if (target.result.abi == .gnu) {
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
