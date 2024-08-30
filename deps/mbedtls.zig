const std = @import("std");

pub const Library = struct {
    step: *std.Build.Step.Compile,

    pub fn link(self: Library, other: *std.Build.Step.Compile) void {
        other.addIncludePath(.{ .cwd_relative = include_dir });
        other.linkLibrary(self.step);
    }
};

fn root() []const u8 {
    return std.fs.path.dirname(@src().file) orelse ".";
}

const root_path = root() ++ "/";
pub const include_dir = root_path ++ "mbedtls/include";
const library_include = root_path ++ "mbedtls/library";

pub fn create(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) Library {
    const ret = b.addStaticLibrary(.{
        .name = "mbedtls",
        .target = target,
        .optimize = optimize,
    });
    ret.addIncludePath(.{ .cwd_relative = include_dir });
    ret.addIncludePath(.{ .cwd_relative = library_include });

    // not sure why, but mbedtls has runtime issues when it's not built as
    // release-small or with the -Os flag, definitely need to figure out what's
    // going on there
    ret.addCSourceFiles(.{
        .root = .{ .cwd_relative = root() },
        .files = srcs,
        .flags = &.{"-Os"},
    });
    ret.linkLibC();

    if (target.result.os.tag == .windows)
        ret.linkSystemLibrary("ws2_32");

    return Library{ .step = ret };
}

const srcs = &.{
    "mbedtls/library/oid.c",
    "mbedtls/library/ctr_drbg.c",
    "mbedtls/library/bignum.c",
    "mbedtls/library/entropy.c",
    "mbedtls/library/nist_kw.c",
    "mbedtls/library/psa_crypto_slot_management.c",
    "mbedtls/library/mps_trace.c",
    "mbedtls/library/aes.c",
    "mbedtls/library/md4.c",
    "mbedtls/library/ssl_tls13_keys.c",
    "mbedtls/library/ccm.c",
    "mbedtls/library/pk.c",
    "mbedtls/library/psa_crypto_mac.c",
    "mbedtls/library/psa_crypto_rsa.c",
    "mbedtls/library/constant_time.c",
    "mbedtls/library/poly1305.c",
    "mbedtls/library/md5.c",
    "mbedtls/library/hmac_drbg.c",
    "mbedtls/library/padlock.c",
    "mbedtls/library/blowfish.c",
    "mbedtls/library/timing.c",
    "mbedtls/library/hkdf.c",
    "mbedtls/library/xtea.c",
    "mbedtls/library/entropy_poll.c",
    "mbedtls/library/cmac.c",
    "mbedtls/library/net_sockets.c",
    "mbedtls/library/psa_crypto_hash.c",
    "mbedtls/library/aesni.c",
    "mbedtls/library/sha256.c",
    "mbedtls/library/ecp.c",
    "mbedtls/library/ecp_curves.c",
    "mbedtls/library/psa_crypto_driver_wrappers.c",
    "mbedtls/library/debug.c",
    "mbedtls/library/arc4.c",
    "mbedtls/library/asn1write.c",
    "mbedtls/library/ssl_cookie.c",
    "mbedtls/library/pkwrite.c",
    "mbedtls/library/asn1parse.c",
    "mbedtls/library/base64.c",
    "mbedtls/library/x509.c",
    "mbedtls/library/pkcs5.c",
    "mbedtls/library/psa_crypto_aead.c",
    "mbedtls/library/pk_wrap.c",
    "mbedtls/library/psa_crypto_client.c",
    "mbedtls/library/psa_crypto_cipher.c",
    "mbedtls/library/psa_crypto_ecp.c",
    "mbedtls/library/camellia.c",
    "mbedtls/library/aria.c",
    "mbedtls/library/platform_util.c",
    "mbedtls/library/x509write_csr.c",
    "mbedtls/library/sha1.c",
    "mbedtls/library/x509_create.c",
    "mbedtls/library/md.c",
    "mbedtls/library/gcm.c",
    "mbedtls/library/ssl_srv.c",
    "mbedtls/library/chacha20.c",
    "mbedtls/library/pkcs12.c",
    "mbedtls/library/pem.c",
    "mbedtls/library/x509write_crt.c",
    "mbedtls/library/ecdsa.c",
    "mbedtls/library/psa_crypto_se.c",
    "mbedtls/library/threading.c",
    "mbedtls/library/md2.c",
    "mbedtls/library/rsa.c",
    "mbedtls/library/mps_reader.c",
    "mbedtls/library/memory_buffer_alloc.c",
    "mbedtls/library/x509_csr.c",
    "mbedtls/library/ecjpake.c",
    "mbedtls/library/cipher.c",
    "mbedtls/library/havege.c",
    "mbedtls/library/error.c",
    "mbedtls/library/version.c",
    "mbedtls/library/x509_crl.c",
    "mbedtls/library/cipher_wrap.c",
    "mbedtls/library/ssl_tls.c",
    "mbedtls/library/sha512.c",
    "mbedtls/library/ssl_cli.c",
    "mbedtls/library/ssl_ticket.c",
    "mbedtls/library/psa_crypto.c",
    "mbedtls/library/psa_its_file.c",
    "mbedtls/library/pkparse.c",
    "mbedtls/library/certs.c",
    "mbedtls/library/platform.c",
    "mbedtls/library/ecdh.c",
    "mbedtls/library/ssl_msg.c",
    "mbedtls/library/des.c",
    "mbedtls/library/pkcs11.c",
    "mbedtls/library/ssl_cache.c",
    "mbedtls/library/version_features.c",
    "mbedtls/library/rsa_internal.c",
    "mbedtls/library/chachapoly.c",
    "mbedtls/library/ssl_ciphersuites.c",
    "mbedtls/library/ripemd160.c",
    "mbedtls/library/dhm.c",
    "mbedtls/library/psa_crypto_storage.c",
    "mbedtls/library/x509_crt.c",
};
