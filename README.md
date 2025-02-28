You're looking at xit, a new version control system. Here be dragons, as they say. This is new and unstable software. Maybe one day it will be a worthy successor to git, but for now, only use it if you're adventurous. Here are the main features:

* git compatible
  * supports the git networking protocol for push/fetch/clone
  * [read more](docs/compat.md) about git compatibility
* combine snapshot-based and patch-based version control
  * merging and cherry-picking uses patches like Darcs and Pijul
  * restoring files and anything sent over the network uses snapshots like git
  * [read more](docs/patch.md) about snapshots vs patches
* built-in TUI
  * all functionality will be exposed via the TUI
  * for now though, it only shows log and status...baby steps!
  * [read more](docs/tui.md) about the TUI
* store large/binary files efficiently
  * uses a modern chunking algorithm (FastCDC) to deltify large files
  * doesn't compress binary files...it has no benefit and can even make them larger
  * [read more](docs/chunk.md) about chunking
* universal undo
  * any change to the repo can be cleanly undone
  * this feature is still under development, so it's not available yet
  * [read more](docs/db.md) about the immutable database
* clean implementation
  * uses *no* third-party libraries in production...all bugs are our bugs
  * can be easily used as a library in other projects
  * contains a reuseable git implementation in pure Zig
  * [read more](docs/lib.md) about xit's internals and using xit as a library

To get started, install zig 0.13.0. There is also a branch for zig 0.14.0, which will be merged once it is released. Run `zig build` and you'll find the binary at `zig-out/bin/xit`. The CLI is similar to git:

```
xit init test
cd test
echo hello > readme.md
xit add readme.md
xit commit -m "hello world!"
```

Yeah, that's pretty boring stuff. You can also create branches and perform merges:

```
xit branch add stuff
xit branch list
xit switch stuff
echo goodbye > readme.md
xit add readme.md
xit commit -m "goodbye world!"
xit switch master
xit merge stuff
```

Here's the output of `xit --help` to give you an idea of what's supported so far:

```
help: xit <command> [<args>]

init         create an empty xit repository.
add          add file contents to the index.
unadd        remove any changes to a file that were added to the index.
             similar to `git reset HEAD`.
untrack      no longer track file in the index, but leave it in the work dir.
             similar to `git rm --cached`.
rm           no longer track file in the index *and* remove it from the work dir.
commit       create a new commit.
tag          add, remove, and list tags.
status       show the status of uncommitted changes.
diff         show changes between the last commit and the work dir that haven't been added to the index.
diff-added   show changes between the last commit and what has been added to the index.
             similar to `git diff --cached`.
branch       add, remove, and list branches.
switch       switch to a branch or commit id.
             updates both the index and the work dir.
reset        make the current branch point to a new commit id.
             updates the index, but the files in the work dir are left alone.
reset-dir    make the current branch point to a new commit id.
             updates both the index and the work dir.
             similar to `git reset --hard`.
reset-add    make the current branch point to a new commit id.
             does not update the index or the work dir.
             this is like calling reset and then adding everything to the index.
             similar to `git reset --soft`.
restore      restore files in the work dir.
log          show commit logs.
merge        join two or more development histories together.
cherry-pick  apply the changes introduced by an existing commit.
config       add, remove, and list config options.
remote       add, remove, and list remotes.
```

To launch the TUI, just run `xit` without arguments. Press `q` to quit the TUI. In the repo created above, it'll look like this:

```
╔═══╗                                                               
║log║ status                                                        
╚═══╝                                                               
┌──────────────┐    ┌─────────────────────────────────────────────┐ 
│goodbye world!│    │                                             │ 
└──────────────┘    │ diff --git a/readme.md b/readme.md          │ 
                    │ index ce01362..dd7e1c6 100644               │ 
 hello world!       │ --- a/readme.md                             │ 
                    │ +++ b/readme.md                             │ 
                    │                                             │ 
                    │                                             │ 
                    │                                             │ 
                    │ @@ -1,2 +1,2 @@                             │ 
                    │ - hello                                     │ 
                    │ + goodbye                                   │ 
                    │                                             │ 
                    │                                             │ 
                    │                                             │ 
                    └─────────────────────────────────────────────┘ 
                                                                    
 
```

Here's what the status tab looks like after making a change to the file:

```
     ╔══════╗                                                                
 log ║status║                                                                
     ╚══════╝                                                                
           ┌─────────────┐                                                   
 added (0) │not added (1)│ not tracked (0)                                   
           └─────────────┘                                                   
   ┌─────────┐      ┌─────────────────────────────────────────────┐          
 ± │readme.md│      │                                             │          
   └─────────┘      │ diff --git a/readme.md b/readme.md          │          
                    │ index dd7e1c6..68ce77a 100644               │          
                    │ --- a/readme.md                             │          
                    │ +++ b/readme.md                             │          
                    │                                             │          
                    │                                             │          
                    │                                             │          
                    │ @@ -1,2 +1,2 @@                             │          
                    │ - goodbye                                   │          
                    │ + bon voyage                                │          
                    │                                             │          
                    │                                             │          
                    │                                             │          
                    └─────────────────────────────────────────────┘          
                                                                             
 
```

If you're interested in working on this code, [read more](docs/dev.md) about contributing, running tests, and whatnot. As Willy Wonka said, we have so much time, and so little to do!
