// https://github.com/mattnite/zig-libgit2

const std = @import("std");

fn root() []const u8 {
    return std.fs.path.dirname(@src().file) orelse unreachable;
}

const root_path = root() ++ "/";
pub const include_dir = root_path ++ "libgit2/include";

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
        "-fno-sanitize=all",
    });

    if (64 == target.toTarget().ptrBitWidth())
        try flags.append("-DGIT_ARCH_64=1");

    ret.addCSourceFiles(srcs, flags.items);
    if (target.isWindows()) {
        try flags.appendSlice(&.{
            "-DGIT_WIN32",
            "-DGIT_WINHTTP",
        });
        ret.addCSourceFiles(win32_srcs, flags.items);

        if (target.getAbi().isGnu()) {
            ret.addCSourceFiles(posix_srcs, flags.items);
            ret.addCSourceFiles(unix_srcs, flags.items);
        }
    } else {
        ret.addCSourceFiles(posix_srcs, flags.items);
        ret.addCSourceFiles(unix_srcs, flags.items);
    }

    if (target.isLinux())
        try flags.appendSlice(&.{
            "-DGIT_USE_NSEC=1",
            "-DGIT_USE_STAT_MTIM=1",
        });

    ret.addCSourceFiles(pcre_srcs, &.{
        "-DLINK_SIZE=2",
        "-DNEWLINE=10",
        "-DPOSIX_MALLOC_THRESHOLD=10",
        "-DMATCH_LIMIT_RECURSION=MATCH_LIMIT",
        "-DPARENS_NEST_LIMIT=250",
        "-DMATCH_LIMIT=10000000",
        "-DMAX_NAME_SIZE=32",
        "-DMAX_NAME_COUNT=10000",
    });

    ret.addIncludePath(.{ .cwd_relative = include_dir });
    ret.addIncludePath(.{ .cwd_relative = root_path ++ "libgit2/src/libgit2" });
    ret.addIncludePath(.{ .cwd_relative = root_path ++ "libgit2/src/util" });
    ret.addIncludePath(.{ .cwd_relative = root_path ++ "libgit2/deps/pcre" });
    ret.addIncludePath(.{ .cwd_relative = root_path ++ "libgit2/deps/http-parser" });
    ret.linkLibC();

    return Library{ .step = ret };
}

const srcs = &.{
    root_path ++ "libgit2/src/libgit2/mailmap.c",
    root_path ++ "libgit2/src/libgit2/describe.c",
    root_path ++ "libgit2/src/libgit2/revwalk.c",
    root_path ++ "libgit2/src/libgit2/threadstate.c",
    root_path ++ "libgit2/src/libgit2/refdb_fs.c",
    root_path ++ "libgit2/src/libgit2/refspec.c",
    root_path ++ "libgit2/src/libgit2/oid.c",
    root_path ++ "libgit2/src/libgit2/merge_driver.c",
    root_path ++ "libgit2/src/libgit2/cherrypick.c",
    root_path ++ "libgit2/src/libgit2/oidmap.c",
    root_path ++ "libgit2/src/libgit2/attrcache.c",
    root_path ++ "libgit2/src/libgit2/libgit2.c",
    root_path ++ "libgit2/src/libgit2/diff_file.c",
    root_path ++ "libgit2/src/libgit2/diff_xdiff.c",
    root_path ++ "libgit2/src/libgit2/filter.c",
    root_path ++ "libgit2/src/libgit2/mwindow.c",
    root_path ++ "libgit2/src/libgit2/notes.c",
    root_path ++ "libgit2/src/libgit2/tag.c",
    root_path ++ "libgit2/src/libgit2/buf.c",
    root_path ++ "libgit2/src/libgit2/blame_git.c",
    root_path ++ "libgit2/src/libgit2/worktree.c",
    root_path ++ "libgit2/src/libgit2/blob.c",
    root_path ++ "libgit2/src/libgit2/tree.c",
    root_path ++ "libgit2/src/libgit2/midx.c",
    root_path ++ "libgit2/src/libgit2/apply.c",
    root_path ++ "libgit2/src/libgit2/config.c",
    root_path ++ "libgit2/src/libgit2/config_parse.c",
    root_path ++ "libgit2/src/libgit2/object.c",
    root_path ++ "libgit2/src/libgit2/diff_parse.c",
    root_path ++ "libgit2/src/libgit2/odb_pack.c",
    root_path ++ "libgit2/src/libgit2/strarray.c",
    root_path ++ "libgit2/src/libgit2/config_snapshot.c",
    root_path ++ "libgit2/src/libgit2/idxmap.c",
    root_path ++ "libgit2/src/libgit2/reader.c",
    root_path ++ "libgit2/src/libgit2/revparse.c",
    root_path ++ "libgit2/src/libgit2/email.c",
    root_path ++ "libgit2/src/libgit2/remote.c",
    root_path ++ "libgit2/src/libgit2/diff.c",
    root_path ++ "libgit2/src/libgit2/indexer.c",
    root_path ++ "libgit2/src/libgit2/merge_file.c",
    root_path ++ "libgit2/src/libgit2/branch.c",
    root_path ++ "libgit2/src/libgit2/diff_print.c",
    root_path ++ "libgit2/src/libgit2/config_file.c",
    root_path ++ "libgit2/src/libgit2/push.c",
    root_path ++ "libgit2/src/libgit2/diff_driver.c",
    root_path ++ "libgit2/src/libgit2/attr.c",
    root_path ++ "libgit2/src/libgit2/pack-objects.c",
    root_path ++ "libgit2/src/libgit2/diff_tform.c",
    root_path ++ "libgit2/src/libgit2/xdiff/xemit.c",
    root_path ++ "libgit2/src/libgit2/xdiff/xmerge.c",
    root_path ++ "libgit2/src/libgit2/xdiff/xutils.c",
    root_path ++ "libgit2/src/libgit2/xdiff/xprepare.c",
    root_path ++ "libgit2/src/libgit2/xdiff/xhistogram.c",
    root_path ++ "libgit2/src/libgit2/xdiff/xdiffi.c",
    root_path ++ "libgit2/src/libgit2/xdiff/xpatience.c",
    root_path ++ "libgit2/src/libgit2/blame.c",
    root_path ++ "libgit2/src/libgit2/streams/registry.c",
    root_path ++ "libgit2/src/libgit2/streams/tls.c",
    root_path ++ "libgit2/src/libgit2/streams/socket.c",
    root_path ++ "libgit2/src/libgit2/streams/stransport.c",
    root_path ++ "libgit2/src/libgit2/streams/openssl.c",
    root_path ++ "libgit2/src/libgit2/streams/openssl_legacy.c",
    root_path ++ "libgit2/src/libgit2/streams/openssl_dynamic.c",
    root_path ++ "libgit2/src/libgit2/streams/mbedtls.c",
    root_path ++ "libgit2/src/libgit2/reflog.c",
    root_path ++ "libgit2/src/libgit2/fetchhead.c",
    root_path ++ "libgit2/src/libgit2/refs.c",
    root_path ++ "libgit2/src/libgit2/iterator.c",
    root_path ++ "libgit2/src/libgit2/parse.c",
    root_path ++ "libgit2/src/libgit2/transaction.c",
    root_path ++ "libgit2/src/libgit2/oidarray.c",
    root_path ++ "libgit2/src/libgit2/errors.c",
    root_path ++ "libgit2/src/libgit2/trailer.c",
    root_path ++ "libgit2/src/libgit2/odb_loose.c",
    root_path ++ "libgit2/src/libgit2/odb.c",
    root_path ++ "libgit2/src/libgit2/checkout.c",
    root_path ++ "libgit2/src/libgit2/trace.c",
    root_path ++ "libgit2/src/libgit2/transports/smart_protocol.c",
    root_path ++ "libgit2/src/libgit2/transports/git.c",
    root_path ++ "libgit2/src/libgit2/transports/auth.c",
    root_path ++ "libgit2/src/libgit2/transports/auth_ntlm.c",
    root_path ++ "libgit2/src/libgit2/transports/http.c",
    root_path ++ "libgit2/src/libgit2/transports/local.c",
    root_path ++ "libgit2/src/libgit2/transports/auth_negotiate.c",
    root_path ++ "libgit2/src/libgit2/transports/smart.c",
    root_path ++ "libgit2/src/libgit2/transports/smart_pkt.c",
    root_path ++ "libgit2/src/libgit2/transports/credential_helpers.c",
    root_path ++ "libgit2/src/libgit2/transports/winhttp.c",
    root_path ++ "libgit2/src/libgit2/transports/credential.c",
    root_path ++ "libgit2/src/libgit2/transports/ssh.c",
    root_path ++ "libgit2/src/libgit2/transports/httpclient.c",
    root_path ++ "libgit2/src/libgit2/rebase.c",
    root_path ++ "libgit2/src/libgit2/diff_stats.c",
    root_path ++ "libgit2/src/libgit2/diff_generate.c",
    root_path ++ "libgit2/src/libgit2/clone.c",
    root_path ++ "libgit2/src/libgit2/commit.c",
    root_path ++ "libgit2/src/libgit2/ident.c",
    root_path ++ "libgit2/src/libgit2/message.c",
    root_path ++ "libgit2/src/libgit2/index.c",
    root_path ++ "libgit2/src/libgit2/pathspec.c",
    root_path ++ "libgit2/src/libgit2/cache.c",
    root_path ++ "libgit2/src/libgit2/tree-cache.c",
    root_path ++ "libgit2/src/libgit2/commit_list.c",
    root_path ++ "libgit2/src/libgit2/patch.c",
    root_path ++ "libgit2/src/libgit2/offmap.c",
    root_path ++ "libgit2/src/libgit2/commit_graph.c",
    root_path ++ "libgit2/src/libgit2/config_entries.c",
    root_path ++ "libgit2/src/libgit2/config_mem.c",
    root_path ++ "libgit2/src/libgit2/hashsig.c",
    root_path ++ "libgit2/src/libgit2/patch_parse.c",
    root_path ++ "libgit2/src/libgit2/revert.c",
    root_path ++ "libgit2/src/libgit2/proxy.c",
    root_path ++ "libgit2/src/libgit2/submodule.c",
    root_path ++ "libgit2/src/libgit2/repository.c",
    root_path ++ "libgit2/src/libgit2/fetch.c",
    root_path ++ "libgit2/src/libgit2/patch_generate.c",
    root_path ++ "libgit2/src/libgit2/pack.c",
    root_path ++ "libgit2/src/libgit2/stash.c",
    root_path ++ "libgit2/src/libgit2/signature.c",
    root_path ++ "libgit2/src/libgit2/sysdir.c",
    root_path ++ "libgit2/src/libgit2/attr_file.c",
    root_path ++ "libgit2/src/libgit2/status.c",
    root_path ++ "libgit2/src/libgit2/annotated_commit.c",
    root_path ++ "libgit2/src/libgit2/merge.c",
    root_path ++ "libgit2/src/libgit2/reset.c",
    root_path ++ "libgit2/src/libgit2/odb_mempack.c",
    root_path ++ "libgit2/src/libgit2/config_cache.c",
    root_path ++ "libgit2/src/libgit2/crlf.c",
    root_path ++ "libgit2/src/libgit2/ignore.c",
    root_path ++ "libgit2/src/libgit2/transport.c",
    root_path ++ "libgit2/src/libgit2/path.c",
    root_path ++ "libgit2/src/libgit2/refdb.c",
    root_path ++ "libgit2/src/libgit2/graph.c",
    root_path ++ "libgit2/src/libgit2/netops.c",
    root_path ++ "libgit2/src/libgit2/delta.c",
    root_path ++ "libgit2/src/libgit2/object_api.c",

    root_path ++ "libgit2/src/util/hash.c",
    root_path ++ "libgit2/src/util/util.c",
    root_path ++ "libgit2/src/util/zstream.c",
    root_path ++ "libgit2/src/util/futils.c",
    root_path ++ "libgit2/src/util/regexp.c",
    root_path ++ "libgit2/src/util/utf8.c",
    root_path ++ "libgit2/src/util/filebuf.c",
    root_path ++ "libgit2/src/util/allocators/failalloc.c",
    root_path ++ "libgit2/src/util/allocators/stdalloc.c",
    root_path ++ "libgit2/src/util/allocators/win32_leakcheck.c",
    root_path ++ "libgit2/src/util/vector.c",
    root_path ++ "libgit2/src/util/pool.c",
    root_path ++ "libgit2/src/util/fs_path.c",
    root_path ++ "libgit2/src/util/varint.c",
    root_path ++ "libgit2/src/util/sortedcache.c",
    root_path ++ "libgit2/src/util/runtime.c",
    root_path ++ "libgit2/src/util/net.c",
    root_path ++ "libgit2/src/util/date.c",
    root_path ++ "libgit2/src/util/strmap.c",
    root_path ++ "libgit2/src/util/wildmatch.c",
    root_path ++ "libgit2/src/util/hash/builtin.c",
    root_path ++ "libgit2/src/util/hash/rfc6234/sha224-256.c",
    //root_path ++ "libgit2/src/util/hash/collisiondetect.c",
    root_path ++ "libgit2/src/util/hash/sha1dc/sha1.c",
    root_path ++ "libgit2/src/util/hash/sha1dc/ubc_check.c",
    //root_path ++ "libgit2/src/util/hash/common_crypto.c",
    //root_path ++ "libgit2/src/util/hash/openssl.c",
    root_path ++ "libgit2/src/util/hash/mbedtls.c",
    root_path ++ "libgit2/src/util/alloc.c",
    root_path ++ "libgit2/src/util/rand.c",
    root_path ++ "libgit2/src/util/thread.c",
    root_path ++ "libgit2/src/util/tsort.c",
    root_path ++ "libgit2/src/util/pqueue.c",
    root_path ++ "libgit2/src/util/str.c",

    root_path ++ "libgit2_extra/mbedtls.c",
    root_path ++ "libgit2/deps/http-parser/http_parser.c",
};

const pcre_srcs = &.{
    root_path ++ "libgit2/deps/pcre/pcre_byte_order.c",
    root_path ++ "libgit2/deps/pcre/pcre_chartables.c",
    root_path ++ "libgit2/deps/pcre/pcre_compile.c",
    root_path ++ "libgit2/deps/pcre/pcre_config.c",
    root_path ++ "libgit2/deps/pcre/pcre_dfa_exec.c",
    root_path ++ "libgit2/deps/pcre/pcre_exec.c",
    root_path ++ "libgit2/deps/pcre/pcre_fullinfo.c",
    root_path ++ "libgit2/deps/pcre/pcre_get.c",
    root_path ++ "libgit2/deps/pcre/pcre_globals.c",
    root_path ++ "libgit2/deps/pcre/pcre_jit_compile.c",
    root_path ++ "libgit2/deps/pcre/pcre_maketables.c",
    root_path ++ "libgit2/deps/pcre/pcre_newline.c",
    root_path ++ "libgit2/deps/pcre/pcre_ord2utf8.c",
    root_path ++ "libgit2/deps/pcre/pcreposix.c",
    root_path ++ "libgit2/deps/pcre/pcre_printint.c",
    root_path ++ "libgit2/deps/pcre/pcre_refcount.c",
    root_path ++ "libgit2/deps/pcre/pcre_string_utils.c",
    root_path ++ "libgit2/deps/pcre/pcre_study.c",
    root_path ++ "libgit2/deps/pcre/pcre_tables.c",
    root_path ++ "libgit2/deps/pcre/pcre_ucd.c",
    root_path ++ "libgit2/deps/pcre/pcre_valid_utf8.c",
    root_path ++ "libgit2/deps/pcre/pcre_version.c",
    root_path ++ "libgit2/deps/pcre/pcre_xclass.c",
};

const posix_srcs = &.{
    root_path ++ "libgit2/src/util/posix.c",
};

const unix_srcs = &.{
    root_path ++ "libgit2/src/util/unix/map.c",
    root_path ++ "libgit2/src/util/unix/realpath.c",
};

const win32_srcs = &.{
    root_path ++ "libgit2/src/util/win32/w32_util.c",
    root_path ++ "libgit2/src/util/win32/error.c",
    root_path ++ "libgit2/src/util/win32/path_w32.c",
    root_path ++ "libgit2/src/util/win32/map.c",
    root_path ++ "libgit2/src/util/win32/w32_buffer.c",
    root_path ++ "libgit2/src/util/win32/w32_leakcheck.c",
    root_path ++ "libgit2/src/util/win32/posix_w32.c",
    root_path ++ "libgit2/src/util/win32/thread.c",
    root_path ++ "libgit2/src/util/win32/precompiled.c",
    root_path ++ "libgit2/src/util/win32/utf-conv.c",
    root_path ++ "libgit2/src/util/win32/dir.c",

    root_path ++ "libgit2/src/util/hash/win32.c",
};
