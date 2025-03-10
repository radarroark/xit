const std = @import("std");

fn root() []const u8 {
    return std.fs.path.dirname(@src().file) orelse unreachable;
}

const root_path = root() ++ "/";
pub const include_dir = root_path ++ "libgit2/include";

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
) !Library {
    const ret = b.addStaticLibrary(.{
        .name = "git2",
        .target = target,
        .optimize = optimize,
    });

    var flags = std.ArrayList([]const u8).init(b.allocator);
    defer flags.deinit();

    try flags.appendSlice(&.{
        "-DLIBGIT2_NO_FEATURES_H",
        "-DGIT_TRACE=1",
        "-DGIT_THREADS=1",
        "-DGIT_USE_FUTIMENS=1",
        "-DGIT_REGEX_PCRE",
        "-DGIT_SSH=1",
        "-DGIT_SSH_MEMORY_CREDENTIALS=1",
        "-DGIT_HTTPS=1",
        "-DGIT_MBEDTLS=1",
        "-DGIT_SHA1_MBEDTLS=1",
        "-DGIT_SHA256_BUILTIN=1",
        "-DGIT_HTTPPARSER_BUILTIN=1",
        "-DGIT_SSH_EXEC=1",
        "-fno-sanitize=all",
    });

    if (target.result.os.tag == .windows) {
        try flags.append("-DGIT_IO_WSAPOLL");
    } else {
        try flags.append("-DGIT_IO_POLL=1");
    }

    if (64 == target.result.ptrBitWidth()) {
        try flags.append("-DGIT_ARCH_64=1");
    }

    ret.addCSourceFiles(.{
        .root = .{ .cwd_relative = root() },
        .files = srcs,
        .flags = flags.items,
    });

    if (target.result.os.tag == .windows) {
        try flags.appendSlice(&.{
            "-DGIT_WIN32",
            "-DGIT_WINHTTP",
        });
        ret.addCSourceFiles(.{
            .root = .{ .cwd_relative = root() },
            .files = win32_srcs,
            .flags = flags.items,
        });
        ret.linkSystemLibrary("secur32");
    } else {
        ret.addCSourceFiles(.{
            .root = .{ .cwd_relative = root() },
            .files = posix_srcs,
            .flags = flags.items,
        });
        ret.addCSourceFiles(.{
            .root = .{ .cwd_relative = root() },
            .files = unix_srcs,
            .flags = flags.items,
        });
    }

    ret.addCSourceFiles(.{
        .root = .{ .cwd_relative = root() },
        .files = pcre_srcs,
        .flags = &.{
            "-DLINK_SIZE=2",
            "-DNEWLINE=10",
            "-DPOSIX_MALLOC_THRESHOLD=10",
            "-DMATCH_LIMIT_RECURSION=MATCH_LIMIT",
            "-DPARENS_NEST_LIMIT=250",
            "-DMATCH_LIMIT=10000000",
            "-DMAX_NAME_SIZE=32",
            "-DMAX_NAME_COUNT=10000",
        },
    });

    ret.addIncludePath(.{ .cwd_relative = include_dir });
    ret.addIncludePath(.{ .cwd_relative = root_path ++ "libgit2/src/libgit2" });
    ret.addIncludePath(.{ .cwd_relative = root_path ++ "libgit2/src/util" });
    ret.addIncludePath(.{ .cwd_relative = root_path ++ "libgit2/deps/pcre" });
    ret.addIncludePath(.{ .cwd_relative = root_path ++ "libgit2/deps/xdiff" });
    ret.addIncludePath(.{ .cwd_relative = root_path ++ "libgit2/deps/llhttp" });
    ret.linkLibC();

    return Library{ .step = ret };
}

const srcs = &.{
    "libgit2/src/libgit2/refdb.c",
    "libgit2/src/libgit2/oid.c",
    "libgit2/src/libgit2/message.c",
    "libgit2/src/libgit2/signature.c",
    "libgit2/src/libgit2/offmap.c",
    "libgit2/src/libgit2/delta.c",
    "libgit2/src/libgit2/streams/socket.c",
    "libgit2/src/libgit2/streams/mbedtls.c",
    "libgit2/src/libgit2/streams/registry.c",
    "libgit2/src/libgit2/streams/openssl_legacy.c",
    "libgit2/src/libgit2/streams/openssl_dynamic.c",
    "libgit2/src/libgit2/streams/tls.c",
    "libgit2/src/libgit2/streams/openssl.c",
    "libgit2/src/libgit2/streams/stransport.c",
    "libgit2/src/libgit2/streams/schannel.c",
    "libgit2/src/libgit2/blame.c",
    "libgit2/src/libgit2/buf.c",
    "libgit2/src/libgit2/object.c",
    "libgit2/src/libgit2/config_cache.c",
    "libgit2/src/libgit2/email.c",
    "libgit2/src/libgit2/odb_mempack.c",
    "libgit2/src/libgit2/ident.c",
    "libgit2/src/libgit2/object_api.c",
    "libgit2/src/libgit2/config_parse.c",
    "libgit2/src/libgit2/diff_file.c",
    "libgit2/src/libgit2/reader.c",
    "libgit2/src/libgit2/patch_generate.c",
    "libgit2/src/libgit2/apply.c",
    "libgit2/src/libgit2/libgit2.c",
    "libgit2/src/libgit2/trace.c",
    "libgit2/src/libgit2/odb_pack.c",
    "libgit2/src/libgit2/fetchhead.c",
    "libgit2/src/libgit2/proxy.c",
    "libgit2/src/libgit2/refspec.c",
    "libgit2/src/libgit2/push.c",
    "libgit2/src/libgit2/diff_generate.c",
    "libgit2/src/libgit2/fetch.c",
    "libgit2/src/libgit2/odb.c",
    "libgit2/src/libgit2/blob.c",
    "libgit2/src/libgit2/commit_list.c",
    "libgit2/src/libgit2/patch.c",
    "libgit2/src/libgit2/worktree.c",
    "libgit2/src/libgit2/rebase.c",
    "libgit2/src/libgit2/diff_xdiff.c",
    "libgit2/src/libgit2/attrcache.c",
    "libgit2/src/libgit2/diff_tform.c",
    "libgit2/src/libgit2/mwindow.c",
    "libgit2/src/libgit2/idxmap.c",
    "libgit2/src/libgit2/branch.c",
    "libgit2/src/libgit2/checkout.c",
    "libgit2/src/libgit2/commit.c",
    "libgit2/src/libgit2/indexer.c",
    "libgit2/src/libgit2/clone.c",
    "libgit2/src/libgit2/patch_parse.c",
    "libgit2/src/libgit2/reset.c",
    "libgit2/src/libgit2/revwalk.c",
    "libgit2/src/libgit2/cherrypick.c",
    "libgit2/src/libgit2/hashsig.c",
    "libgit2/src/libgit2/commit_graph.c",
    "libgit2/src/libgit2/sysdir.c",
    "libgit2/src/libgit2/oidmap.c",
    "libgit2/src/libgit2/refdb_fs.c",
    "libgit2/src/libgit2/diff_stats.c",
    "libgit2/src/libgit2/diff_driver.c",
    "libgit2/src/libgit2/diff_parse.c",
    "libgit2/src/libgit2/odb_loose.c",
    "libgit2/src/libgit2/config_file.c",
    "libgit2/src/libgit2/config_snapshot.c",
    "libgit2/src/libgit2/tag.c",
    "libgit2/src/libgit2/settings.c",
    "libgit2/src/libgit2/stash.c",
    "libgit2/src/libgit2/config.c",
    "libgit2/src/libgit2/merge_file.c",
    "libgit2/src/libgit2/oidarray.c",
    "libgit2/src/libgit2/cache.c",
    "libgit2/src/libgit2/parse.c",
    "libgit2/src/libgit2/grafts.c",
    "libgit2/src/libgit2/annotated_commit.c",
    "libgit2/src/libgit2/merge_driver.c",
    "libgit2/src/libgit2/merge.c",
    "libgit2/src/libgit2/trailer.c",
    "libgit2/src/libgit2/transport.c",
    "libgit2/src/libgit2/reflog.c",
    "libgit2/src/libgit2/submodule.c",
    "libgit2/src/libgit2/status.c",
    "libgit2/src/libgit2/graph.c",
    "libgit2/src/libgit2/ignore.c",
    "libgit2/src/libgit2/crlf.c",
    "libgit2/src/libgit2/config_list.c",
    "libgit2/src/libgit2/describe.c",
    "libgit2/src/libgit2/pack-objects.c",
    "libgit2/src/libgit2/tree.c",
    "libgit2/src/libgit2/mailmap.c",
    "libgit2/src/libgit2/config_mem.c",
    "libgit2/src/libgit2/transaction.c",
    "libgit2/src/libgit2/blame_git.c",
    "libgit2/src/libgit2/revparse.c",
    "libgit2/src/libgit2/tree-cache.c",
    "libgit2/src/libgit2/midx.c",
    "libgit2/src/libgit2/filter.c",
    "libgit2/src/libgit2/pathspec.c",
    "libgit2/src/libgit2/path.c",
    "libgit2/src/libgit2/repository.c",
    "libgit2/src/libgit2/iterator.c",
    "libgit2/src/libgit2/transports/credential.c",
    "libgit2/src/libgit2/transports/auth_sspi.c",
    "libgit2/src/libgit2/transports/winhttp.c",
    "libgit2/src/libgit2/transports/httpclient.c",
    "libgit2/src/libgit2/transports/smart.c",
    "libgit2/src/libgit2/transports/auth_gssapi.c",
    "libgit2/src/libgit2/transports/auth.c",
    "libgit2/src/libgit2/transports/http.c",
    "libgit2/src/libgit2/transports/credential_helpers.c",
    "libgit2/src/libgit2/transports/auth_ntlmclient.c",
    "libgit2/src/libgit2/transports/local.c",
    "libgit2/src/libgit2/transports/smart_protocol.c",
    "libgit2/src/libgit2/transports/ssh_exec.c",
    "libgit2/src/libgit2/transports/smart_pkt.c",
    "libgit2/src/libgit2/transports/ssh.c",
    //"libgit2/src/libgit2/transports/ssh_libssh2.c",
    "libgit2/src/libgit2/transports/httpparser.c",
    "libgit2/src/libgit2/transports/git.c",
    "libgit2/src/libgit2/attr_file.c",
    "libgit2/src/libgit2/diff_print.c",
    "libgit2/src/libgit2/strarray.c",
    "libgit2/src/libgit2/remote.c",
    "libgit2/src/libgit2/refs.c",
    "libgit2/src/libgit2/diff.c",
    "libgit2/src/libgit2/index.c",
    "libgit2/src/libgit2/revert.c",
    "libgit2/src/libgit2/attr.c",
    "libgit2/src/libgit2/notes.c",
    "libgit2/src/libgit2/pack.c",

    "libgit2/src/util/filebuf.c",
    "libgit2/src/util/date.c",
    "libgit2/src/util/futils.c",
    "libgit2/src/util/errors.c",
    "libgit2/src/util/regexp.c",
    "libgit2/src/util/tsort.c",
    "libgit2/src/util/varint.c",
    "libgit2/src/util/runtime.c",
    "libgit2/src/util/fs_path.c",
    "libgit2/src/util/str.c",
    "libgit2/src/util/net.c",
    "libgit2/src/util/alloc.c",
    "libgit2/src/util/wildmatch.c",
    "libgit2/src/util/hash/mbedtls.c",
    //"libgit2/src/util/hash/common_crypto.c",
    "libgit2/src/util/hash/sha1dc/ubc_check.c",
    "libgit2/src/util/hash/sha1dc/sha1.c",
    "libgit2/src/util/hash/rfc6234/sha224-256.c",
    //"libgit2/src/util/hash/collisiondetect.c",
    //"libgit2/src/util/hash/openssl.c",
    "libgit2/src/util/hash/builtin.c",
    "libgit2/src/util/strmap.c",
    "libgit2/src/util/allocators/debugalloc.c",
    "libgit2/src/util/allocators/stdalloc.c",
    "libgit2/src/util/allocators/win32_leakcheck.c",
    "libgit2/src/util/allocators/failalloc.c",
    "libgit2/src/util/rand.c",
    "libgit2/src/util/hash.c",
    "libgit2/src/util/strlist.c",
    "libgit2/src/util/sortedcache.c",
    "libgit2/src/util/pqueue.c",
    "libgit2/src/util/util.c",
    "libgit2/src/util/pool.c",
    "libgit2/src/util/utf8.c",
    "libgit2/src/util/thread.c",
    "libgit2/src/util/zstream.c",
    "libgit2/src/util/posix.c",
    "libgit2/src/util/vector.c",

    "libgit2/deps/xdiff/xpatience.c",
    "libgit2/deps/xdiff/xdiffi.c",
    "libgit2/deps/xdiff/xmerge.c",
    "libgit2/deps/xdiff/xprepare.c",
    "libgit2/deps/xdiff/xhistogram.c",
    "libgit2/deps/xdiff/xutils.c",
    "libgit2/deps/xdiff/xemit.c",

    "libgit2/deps/llhttp/http.c",
    "libgit2/deps/llhttp/api.c",
    "libgit2/deps/llhttp/llhttp.c",
};

const pcre_srcs = &.{
    "libgit2/deps/pcre/pcre_byte_order.c",
    "libgit2/deps/pcre/pcre_chartables.c",
    "libgit2/deps/pcre/pcre_get.c",
    "libgit2/deps/pcre/pcre_maketables.c",
    "libgit2/deps/pcre/pcre_version.c",
    "libgit2/deps/pcre/pcre_tables.c",
    "libgit2/deps/pcre/pcre_jit_compile.c",
    "libgit2/deps/pcre/pcre_xclass.c",
    "libgit2/deps/pcre/pcre_config.c",
    "libgit2/deps/pcre/pcre_study.c",
    "libgit2/deps/pcre/pcre_globals.c",
    "libgit2/deps/pcre/pcre_compile.c",
    "libgit2/deps/pcre/pcre_ord2utf8.c",
    "libgit2/deps/pcre/pcre_exec.c",
    "libgit2/deps/pcre/pcre_ucd.c",
    "libgit2/deps/pcre/pcre_fullinfo.c",
    "libgit2/deps/pcre/pcre_refcount.c",
    "libgit2/deps/pcre/pcre_string_utils.c",
    "libgit2/deps/pcre/pcre_newline.c",
    "libgit2/deps/pcre/pcre_dfa_exec.c",
    "libgit2/deps/pcre/pcre_valid_utf8.c",
    "libgit2/deps/pcre/pcreposix.c",
    "libgit2/deps/pcre/pcre_printint.c",
};

const posix_srcs = &.{
    "libgit2/src/util/posix.c",
};

const unix_srcs = &.{
    "libgit2/src/util/unix/map.c",
    "libgit2/src/util/unix/process.c",
    "libgit2/src/util/unix/realpath.c",
};

const win32_srcs = &.{
    "libgit2/src/util/win32/dir.c",
    "libgit2/src/util/win32/w32_buffer.c",
    "libgit2/src/util/win32/path_w32.c",
    "libgit2/src/util/win32/precompiled.c",
    "libgit2/src/util/win32/w32_util.c",
    "libgit2/src/util/win32/w32_leakcheck.c",
    "libgit2/src/util/win32/error.c",
    "libgit2/src/util/win32/process.c",
    "libgit2/src/util/win32/thread.c",
    "libgit2/src/util/win32/utf-conv.c",
    "libgit2/src/util/win32/posix_w32.c",
    "libgit2/src/util/win32/map.c",

    "libgit2/src/util/hash/win32.c",
};
