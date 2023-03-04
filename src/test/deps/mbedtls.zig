// https://github.com/mattnite/zig-mbedtls

const std = @import("std");
const Builder = std.build.Builder;
const CompileStep = std.build.CompileStep;

pub const Library = struct {
    step: *CompileStep,

    pub fn link(self: Library, other: *CompileStep) void {
        other.addIncludePath(include_dir);
        other.linkLibrary(self.step);
    }
};

fn root() []const u8 {
    return std.fs.path.dirname(@src().file) orelse ".";
}

const root_path = root() ++ "/";
pub const include_dir = root_path ++ "mbedtls/include";
const library_include = root_path ++ "mbedtls/library";

pub fn create(b: *Builder, target: std.zig.CrossTarget, optimize: std.builtin.OptimizeMode) Library {
    const ret = b.addStaticLibrary(.{
        .name = "mbedtls",
        .target = target,
        .optimize = optimize,
    });
    ret.addIncludePath(include_dir);
    ret.addIncludePath(library_include);

    // not sure why, but mbedtls has runtime issues when it's not built as
    // release-small or with the -Os flag, definitely need to figure out what's
    // going on there
    ret.addCSourceFiles(srcs, &.{"-Os"});
    ret.linkLibC();

    if (target.isWindows())
        ret.linkSystemLibrary("ws2_32");

    return Library{ .step = ret };
}

const srcs = &.{
    root_path ++ "mbedtls/library/certs.c",
    root_path ++ "mbedtls/library/pkcs11.c",
    root_path ++ "mbedtls/library/x509.c",
    root_path ++ "mbedtls/library/x509_create.c",
    root_path ++ "mbedtls/library/x509_crl.c",
    root_path ++ "mbedtls/library/x509_crt.c",
    root_path ++ "mbedtls/library/x509_csr.c",
    root_path ++ "mbedtls/library/x509write_crt.c",
    root_path ++ "mbedtls/library/x509write_csr.c",
    root_path ++ "mbedtls/library/debug.c",
    root_path ++ "mbedtls/library/net_sockets.c",
    root_path ++ "mbedtls/library/ssl_cache.c",
    root_path ++ "mbedtls/library/ssl_ciphersuites.c",
    root_path ++ "mbedtls/library/ssl_cli.c",
    root_path ++ "mbedtls/library/ssl_cookie.c",
    root_path ++ "mbedtls/library/ssl_msg.c",
    root_path ++ "mbedtls/library/ssl_srv.c",
    root_path ++ "mbedtls/library/ssl_ticket.c",
    root_path ++ "mbedtls/library/ssl_tls13_keys.c",
    root_path ++ "mbedtls/library/ssl_tls.c",
    root_path ++ "mbedtls/library/aes.c",
    root_path ++ "mbedtls/library/aesni.c",
    root_path ++ "mbedtls/library/arc4.c",
    root_path ++ "mbedtls/library/aria.c",
    root_path ++ "mbedtls/library/asn1parse.c",
    root_path ++ "mbedtls/library/asn1write.c",
    root_path ++ "mbedtls/library/base64.c",
    root_path ++ "mbedtls/library/bignum.c",
    root_path ++ "mbedtls/library/blowfish.c",
    root_path ++ "mbedtls/library/camellia.c",
    root_path ++ "mbedtls/library/ccm.c",
    root_path ++ "mbedtls/library/chacha20.c",
    root_path ++ "mbedtls/library/chachapoly.c",
    root_path ++ "mbedtls/library/cipher.c",
    root_path ++ "mbedtls/library/cipher_wrap.c",
    root_path ++ "mbedtls/library/cmac.c",
    root_path ++ "mbedtls/library/ctr_drbg.c",
    root_path ++ "mbedtls/library/des.c",
    root_path ++ "mbedtls/library/dhm.c",
    root_path ++ "mbedtls/library/ecdh.c",
    root_path ++ "mbedtls/library/ecdsa.c",
    root_path ++ "mbedtls/library/ecjpake.c",
    root_path ++ "mbedtls/library/ecp.c",
    root_path ++ "mbedtls/library/ecp_curves.c",
    root_path ++ "mbedtls/library/entropy.c",
    root_path ++ "mbedtls/library/entropy_poll.c",
    root_path ++ "mbedtls/library/error.c",
    root_path ++ "mbedtls/library/gcm.c",
    root_path ++ "mbedtls/library/havege.c",
    root_path ++ "mbedtls/library/hkdf.c",
    root_path ++ "mbedtls/library/hmac_drbg.c",
    root_path ++ "mbedtls/library/md2.c",
    root_path ++ "mbedtls/library/md4.c",
    root_path ++ "mbedtls/library/md5.c",
    root_path ++ "mbedtls/library/md.c",
    root_path ++ "mbedtls/library/memory_buffer_alloc.c",
    root_path ++ "mbedtls/library/mps_reader.c",
    root_path ++ "mbedtls/library/mps_trace.c",
    root_path ++ "mbedtls/library/nist_kw.c",
    root_path ++ "mbedtls/library/oid.c",
    root_path ++ "mbedtls/library/padlock.c",
    root_path ++ "mbedtls/library/pem.c",
    root_path ++ "mbedtls/library/pk.c",
    root_path ++ "mbedtls/library/pkcs12.c",
    root_path ++ "mbedtls/library/pkcs5.c",
    root_path ++ "mbedtls/library/pkparse.c",
    root_path ++ "mbedtls/library/pk_wrap.c",
    root_path ++ "mbedtls/library/pkwrite.c",
    root_path ++ "mbedtls/library/platform.c",
    root_path ++ "mbedtls/library/platform_util.c",
    root_path ++ "mbedtls/library/poly1305.c",
    root_path ++ "mbedtls/library/psa_crypto_aead.c",
    root_path ++ "mbedtls/library/psa_crypto.c",
    root_path ++ "mbedtls/library/psa_crypto_cipher.c",
    root_path ++ "mbedtls/library/psa_crypto_client.c",
    root_path ++ "mbedtls/library/psa_crypto_driver_wrappers.c",
    root_path ++ "mbedtls/library/psa_crypto_ecp.c",
    root_path ++ "mbedtls/library/psa_crypto_hash.c",
    root_path ++ "mbedtls/library/psa_crypto_mac.c",
    root_path ++ "mbedtls/library/psa_crypto_rsa.c",
    root_path ++ "mbedtls/library/psa_crypto_se.c",
    root_path ++ "mbedtls/library/psa_crypto_slot_management.c",
    root_path ++ "mbedtls/library/psa_crypto_storage.c",
    root_path ++ "mbedtls/library/psa_its_file.c",
    root_path ++ "mbedtls/library/ripemd160.c",
    root_path ++ "mbedtls/library/rsa.c",
    root_path ++ "mbedtls/library/rsa_internal.c",
    root_path ++ "mbedtls/library/sha1.c",
    root_path ++ "mbedtls/library/sha256.c",
    root_path ++ "mbedtls/library/sha512.c",
    root_path ++ "mbedtls/library/threading.c",
    root_path ++ "mbedtls/library/timing.c",
    root_path ++ "mbedtls/library/version.c",
    root_path ++ "mbedtls/library/version_features.c",
    root_path ++ "mbedtls/library/xtea.c",
};
