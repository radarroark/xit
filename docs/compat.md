When Linus released git to the world in April 2005, it had no networking at all. We were still playing tunes on Winamp, cars still had physical goddamn buttons, and the US was still dropping freedom on the middle east. It was a simpler time. Today, any version control system (VCS) with no networking, or no ability to talk to git hosts like Github, is pretty much dead on arrival.

Git compatibility was the single biggest constraint on xit's design. I look at git the same way the authors of Zig look at C: it is critical to be as compatible as possible with it (to reduce the switching cost and to integrate with its ecosystem), while also improving upon it enough to make the remaining switching cost worth paying.

Another VCS that clearly gets this is jujutsu. Its approach to compatibility, however, is very different than xit's. Jujutsu attains git compatibility by using the same on-disk repo format as git. This gives it a few advantages:

1. It can lean pretty heavily on libraries like libgit2, or even shell out to git itself (yuck though), to update the internal repo state and to perform network operations like push, fetch, and clone.

2. It allows switching between the jujutsu and git CLI tools within the same repo. This is particularly useful for situations where there are functionality holes, like submodule support, because you can always switch back to git.

The repo format used by xit is completely different. It creates a `.xit` directory at the root of your project, and its internals have nothing in common with the `.git` directory you are used to.

I believe that a new on-disk repo format is critical to fixing many of git's limitations. In particular, I think [better merging](patch.md) and [better large file support](chunk.md) can't be attained without moving to a new repo format.

* You could say that jujutsu *does* improve merging on the periphery, by making merge conflict resolution more ergonomic, but its actual merge algorithm is the same as in git: the three-way merge.

* If we want to reduce the number of merge conflicts that occur in the first place, we need to improve the way merges are done. That requires storing completely new data that the git repo format has no place for. A [real database](db.md) helps here a lot.

With this in mind, xit achieves git compatibility at the *network* layer instead of the storage layer. When you do a network operation like push, pull, or clone, xit will use the git networking protocol over the wire, and will store the data locally using xit's native repo format.

To do this, xit has its own [built-in implementation](lib.md) of git's networking protocol. This means that any functionality holes in git support are *our problem*, and we will need to fix them ourselves. This is a difficult road to go down, but in the long run I'm confident that we'll be in a better place. Who knows...maybe even a better place than 2005.
