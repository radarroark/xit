#ifndef INCLUDE_extra_h__
#define INCLUDE_extra_h__

#include <libgit2/remote.h>

int git_remote__download(
  git_remote *remote,
  const git_strarray *refspecs,
  const git_fetch_options *opts);

#endif
