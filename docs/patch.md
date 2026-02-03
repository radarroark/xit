There are two broad categories of version control: snapshot-based and patch-based.

A snapshot-based system tracks the state of the repo after each change (the full content of the files at each commit). It's fair to say this side has "won", as the dominant VCS (git) and most of the lesser used ones (mercurial, fossil, etc) are in this category.

A patch-based system tracks the change itself (a diff of what changed since the last "commit"). The best examples are Darcs and Pijul. This side is clearly not as popular, but by being more obscure you do get to enjoy the warm fuzzy feelings of superiority over plebs who use the more popular approach. This is, naturally, its own form of winning.

* The category can get confusing because some VCSes, such as mercurial, *do* store diffs internally at times. Even the much-maligned CVS (and RCS, on which it was built) stored diffs internally, rather than full contents of files. However, these are implementation details. Those systems used internal diffs merely as a storage optimization. What made Darcs and Pijul unique is that they exposed those diffs to the user as a first class concept, representing history as a set of patches and applying those patches to move changes.

Performance

* Some have concluded that snapshot-based systems are inherently faster, though this really depends on what action we're talking about, how they are implemented, and whether they had a Linus Torvalds to write their code.

* When restoring files (such as when checking out a commit), a naively-implemented patch-based system will be slower, because they would have to apply each patch to the working tree to get at the desired state, while snapshot-based systems can immediately query the content of the file at a given commit and copy it to the working tree. A smarter patch-based system could routinely keep internal snapshots at various commits to avoid applying so many patches.

* When merging a branch, a patch-based system will probably be slower because (once again) it has to apply each patch from the source branch onto the target branch separately. A snapshot-based system generally uses some form of three-way merge, which computes a consolidated diff of *all* changes on the source branch that aren't on the target branch, and merges it with the changes on the target branch. The three-way merge is faster because it skips the intermediate changes made in each commit.

  * However, this is a tradeoff. By skipping the intermediate changes, the three-way merge is missing useful information. This can lead to unnecessary merge conflicts -- or worse, successful merges that put the code in the wrong place. See the merge conflicts section below for more.

  * Darcs had an additional performance problem in which some merges could end up taking an exponentially long time. This problem was specific to Darcs, though, because it used operational transforms when applying patches. Pijul solves this by using a CRDT to represent the history of a file, and patch application is merely about updating this CRDT.

    * I realize "because CRDT" isn't a great explanation for why it's faster, but it does sound good. I even started using it in totally inappropriate situations. Why should I buy your product? Because CRDT. Why haven't you paid the electric bill yet? Because CRDT. Why were you speeding, sir? Because CRDT.

    * The solution in xit is similar to Pijul, but quite a bit simpler because it doesn't actually need to be a CRDT. Darcs and Pijul are "pure" patch-based VCSes whose patches are shared over the network and can arrive out-of-order, so their data structures must be robust enough to give the same result regardless of the order they are applied. As discussed below, xit is a hybrid system that only shares the snapshot-based history over the network, and only generates patches locally. This means that it doesn't need to care about out-of-order patch application.

Merge Conflicts

* Snapshot-based systems tend to lead to more merge conflicts. A classic example happens when combining merging and cherry-picking. If you cherry-pick a commit from the source branch onto the target branch, and then later attempt to fully merge the source branch into the target branch, you very often will experience a conflict.

* The core reason why it's problematic to combine merging and cherry-picking in snapshot-based systems is that the cherry-picked commit is a completely new commit with no connection to the one it came from. When attempting to do a merge afterwards, the system isn't smart enough to exclude the change you cherry-picked.

  * Remember, since a snapshot-based system typically uses a three-way merge, it isn't moving each commit one-at-a-time, so it can't really "skip" a commit even if it knew which one to skip. As mentioned above, it makes a single consolidated diff of all changes, so inevitably it will include the changes that were already cherry-picked. This is how the conflict happens.

* Patch-based systems don't need to distinguish between merging and cherry-picking. Both are the exact same action: applying patches. When "cherry-picking", you're simply applying the patch from a single commit. When "merging", you're applying all patches from the source branch that aren't already in the target branch. Since patches have stable identities, they can naturally skip patches that have already been applied there.

* Another unnecessary merge conflict that git produces is adjacent line conflicts. If one branch edits a line, and another branch edits the line directly above or below it, git will produce a conflict -- even though they're not the same line. People assume this is a safety feature, but it isn't; it's a limitation of the diff3 algorithm that git uses. Read [the blog post](https://xit-vcs.github.io/xitlog/devlog-patch-merge-default.html) for more.

* Lastly, git can sometimes produce a *successful* merge where changes from the source branch end up [in the wrong place](https://tahoe-lafs.org/~zooko/badmerge/simple.html). While not as common as adjacent line conflicts, it's scary that it's even possible.

Combining snapshots and patches

* Based on the above, we can conclude that neither snapshots nor patches are "better"; they are better at different things. An ideal system would combine them to get the benefits of both.

* In xit, there is a history of commits that closely mirrors git. Additionally, it computes patches for all changes to text files, which it uses when merging or cherry-picking. In this way, xit gets the primary benefit of patch-based systems (better merges), while using snapshots for everything else.

* Since xit only uses patches for merging, there is no need for it to compute patches for binary files. Unlike in text files, merge conflicts in binary files cannot be resolved by merging their contents, because this would certainly produce an invalid file. Much like other VCSes, xit just forces you to choose either the source or target branch's version of the binary file.

* Since xit exclusively uses the git networking protocol, its patches are a purely local phenomenon. There is no way to send them over the network with this protocol, and no way for a git host to understand them, so patches are always computed locally by xit clients. This ends up being better anyway, because patches have implementation details (like the diff algorithm) that other clients should have the freedom to change; sending them over the network would force these implementation details onto other clients.

* Patch-based merging is enabled by default, and patches will be generated the first time you do a merge. This can take a long time on repos with large histories, since it has to generate a patch for every commit in the entire history. You can run `xit patch all` to generate patches for all commits in advance. If it is taking too long, and you just want to do a quick merge, you can run `xit patch off` and it will fall back on the three-way merge for merging and cherry-picking, just like git.

* The above-mentioned problem with combining merging and cherry-picking is not an issue in xit because patches retain their identities: two commits that make the same change will produce the same patches. The problem *could* still happen if you squash multiple commits that modify the same file, because then the patch for that file would have a new identity. Currently xit doesn't even have an option to cherry-pick multiple commits into a single squashed commit, so this shouldn't happen easily.
