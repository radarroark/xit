A version control system written in Zig. Is it ready yet? Nope...it doesn't even have networking right now, so using it is a very lonely experience. Nonetheless, here are the goals:

* git compatible
  * supports the git networking protocol for push/pull/clone
  * *status: partially implemented (networking isn't done, but has internal support for git including packfiles)*
* combine snapshot-based and patch-based version control
  * merging and cherry-picking uses patches like Darcs and Pijul
  * checking out commits and anything sent over the network uses snapshots like git
  * *status: mostly implemented*
* universal undo
  * any change to the repo can be cleanly undone
  * *status: not implemented, but [xitdb](https://github.com/radarroark/xitdb) will make it trivial*
* built-in TUI
  * all functionality will be exposed via the TUI
  * *status: partially implemented (only log and status for now)*
* store large/binary files efficiently
  * use modern chunking algorithm (FastCDC) so files are deltified efficiently
  * only use compression on text data so the cost isn't paid on binary files where it has no benefit
  * *status: fully implemented*

To get started, run `zig build` and you'll find the binary in the `zig-out` dir. The CLI is similar to git:

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

Once you have that repo built, you can launch the TUI by just running `xit` without arguments (press `q` to quit the TUI). It'll look like this:

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

There is so much left to do, it's overwhelming. Maybe one day this can be a git successor. If not, there's always money in the banana stand.
