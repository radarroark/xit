const std = @import("std");

const c = @cImport({
    @cInclude("git2.h");
});

const c_extra = @cImport({
    @cInclude("extra.h");
});

const c_remote = @cImport({
    @cInclude("libgit2/remote.h");
});

const c_str = @cImport({
    @cInclude("str.h");
});

const c_errors = @cImport({
    @cInclude("git2/sys/errors.h");
});

fn check(err_code: c_int) !void {
    return switch (err_code) {
        0 => {},

        -1 => error.GitGenericError,
        -3 => error.GitObjectNotFound,
        -4 => error.GitObjectExists,
        -5 => error.GitObjectAmbiguous,
        -6 => error.GitBufferTooSmall,
        -7 => error.GitCallbackError,
        -8 => error.GitOpNotAllowedOnBareRepo,
        -9 => error.GitHeadRefersToBranchWithNoCommits,
        -10 => error.GitMergeInProgress,
        -11 => error.GitRefNotFastForwardable,
        -12 => error.GitSpecInvalid,
        -13 => error.GitCheckoutConflict,
        -14 => error.GitFileLocked,
        -15 => error.GitRefValueUnexpected,
        -16 => error.GitAuthError,
        -17 => error.GitCertError,
        -18 => error.GitAlreadyApplied,
        -19 => error.GitPeelNotPossible,
        -20 => error.GitUnexpectedEOF,
        -21 => error.GitInvalidOpOrInput,
        -22 => error.GitUncommitedChanges,
        -23 => error.GitOpInvalidForDirectory,
        -24 => error.GitMergeConflict,

        -30 => error.GitCallbackRefusedToAct,
        -31 => error.GitEndOfIteration,
        -32 => error.GitRetry,
        -33 => error.GitHashsumMismatch,
        -34 => error.GitUnsavedChangesInIndex,
        -35 => error.GitPatchApplyFailed,
        -36 => error.GitObjectNotOwned,
        -37 => error.GitTimeout,
        -38 => error.GitNoChanges,
        -39 => error.GitOptionNotSupported,
        -40 => error.GitReadOnly,

        else => error.GitUnrecognizedError,
    };
}

fn connectOrResetOptions(
    remote_maybe: ?*c.git_remote,
    direction: c_uint,
    opts: *c.git_remote_connect_options,
) !void {
    if (0 == c.git_remote_connected(remote_maybe)) {
        try check(c.git_remote_connect_ext(remote_maybe, direction, opts));
    } else {
        const remote: *c_remote.git_remote = @alignCast(@ptrCast(remote_maybe orelse return error.GitInvalidOpOrInput));
        const set_connect_opts = remote.transport.*.set_connect_opts orelse return error.FieldNotFound;
        try check(set_connect_opts(remote.transport, @ptrCast(opts)));
    }
}

pub fn fetch(
    remote_maybe: ?*c.git_remote,
    refspecs: ?*c.git_strarray,
    opts_maybe: ?*c.git_fetch_options,
    reflog_message_maybe: ?*c_char,
) !void {
    var reflog_msg_buf: c_str.git_str = undefined;
    try check(c_str.git_str_init(&reflog_msg_buf, 0));
    defer c_str.git_str_dispose(&reflog_msg_buf);

    var connect_opts: c.git_remote_connect_options = undefined;
    try check(c.git_remote_connect_options_init(&connect_opts, c.GIT_REMOTE_CONNECT_OPTIONS_VERSION));
    defer c_remote.git_remote_connect_options_dispose(@ptrCast(&connect_opts));

    const remote: *c_remote.git_remote = @alignCast(@ptrCast(remote_maybe orelse return error.GitInvalidOpOrInput));
    if (remote.repo == null) {
        c_errors.git_error_set(c.GIT_ERROR_INVALID, "cannot download detached remote");
        try check(-1);
    }

    try check(c_remote.git_remote_connect_options__from_fetch_opts(@ptrCast(&connect_opts), remote, @ptrCast(opts_maybe)));

    try connectOrResetOptions(remote_maybe, c.GIT_DIRECTION_FETCH, &connect_opts);
    defer _ = c.git_remote_disconnect(remote_maybe);

    var update_flags: c_uint = c.GIT_REMOTE_UPDATE_FETCHHEAD;
    var tagopt: c.git_remote_autotag_option_t = remote.*.download_tags;
    if (opts_maybe) |opts| {
        update_flags = opts.update_fetchhead;
        tagopt = opts.download_tags;
    }

    var capabilities: c_uint = undefined;
    try check(c_remote.git_remote_capabilities(&capabilities, remote));

    var oid_type: c.git_oid_t = undefined;
    try check(c_remote.git_remote_oid_type(&oid_type, remote));

    // Connect and download everything
    try check(c_extra.git_remote__download(@ptrCast(remote), @ptrCast(refspecs), @ptrCast(opts_maybe)));

    // Default reflog message
    if (reflog_message_maybe) |reflog_message| {
        _ = c_str.git_str_sets(&reflog_msg_buf, @ptrCast(reflog_message));
    } else {
        _ = c_str.git_str_printf(&reflog_msg_buf, "fetch %s", remote.name orelse remote.url);
    }

    // Create "remote/foo" branches for all remote branches
    try check(c.git_remote_update_tips(remote_maybe, &connect_opts.callbacks, update_flags, tagopt, c_str.git_str_cstr(&reflog_msg_buf)));

    var prune = false;
    if (opts_maybe) |opts| {
        if (opts.prune == c.GIT_FETCH_PRUNE) {
            prune = true;
        } else if (opts.prune == c.GIT_FETCH_PRUNE_UNSPECIFIED and 1 == remote.prune_refs) {
            prune = true;
        } else if (opts.prune == c.GIT_FETCH_NO_PRUNE) {
            prune = false;
        } else {
            prune = 1 == remote.prune_refs;
        }
    } else {
        prune = 1 == remote.prune_refs;
    }
    if (prune) {
        try check(c.git_remote_prune(remote_maybe, &connect_opts.callbacks));
    }
}
