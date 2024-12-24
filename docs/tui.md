* The Simplicity and Timelessness of TUIs (text user interfaces)

  * The lowest common denominator of all UIs is text. In a way, TUIs (and CLIs) are the only truly cross-platform UI. They can be rendered anywhere, including *inside* of other interfaces. They're nearly guaranteed to work on any hardware we invent in the future.

  * Compared to GUIs, however, TUIs are much lower resolution. You are limited to monospaced unicode characters. This feels like a negative, but it isn't. TUIs force you to distill your interface down to its most basic elements. Anything nonessential must go.

  * TUIs are inoculated from the excesses of modern software design. You don't get to have drop shadows, transparency, or scrolljacking. You get a limited palette of characters and colors, leaving the raw design of your interface to stand or fall on its own.

  * Limitations are a powerful catalyst for creativity. Curious people see limitations as an invitation to overcome them. Give a curious child a TI-83 and he will give you Space Invaders. Give him Minecraft and he will give you Roman aqueducts.

  * Orson Welles put it succinctly: "The enemy of art is the absence of limitations." There is no better way to snuff creativity out of a man than to give him endless resources and no deadline. Often, your best work comes when you have the strictest constraints.

  * I hope you enjoyed today's locker room speech...*bows*.

* TUIs are incredibly underused

  * For developer tools it seems like a no-brainer, but instead we see tools like Postman being written with Electron. Granted, I am sure a TUI would be a harder sell to VCs...

  * It's especially baffling that both git and mercurial have built-in UIs, but they aren't TUIs. I mean, their users are already in the terminal! And yet [git gui](https://git-scm.com/docs/git-gui) launches a Tcl/Tk window, while [hg serve](https://wiki.mercurial-scm.org/hgserve) fires up a web app. Why, guys...why?!

  * All functionality in xit will exposed via the built-in TUI. It's not an afterthought; the TUI is meant to be the primary way you interact with it.

* Many TUIs are really terribly designed. I have a few opinions on how to do it right. Granted, I'm not that experienced with designing TUIs, but ignorance has never stopped me from having strong opinions in the past, so why would I let it stop me now.

* Responsive Design

  * We should learn from web developers about responsive design. A TUI in a small terminal should hide nonessential things, and then show them when the terminal is expanded. Take for example this (early) TUI for xit:

```
┌───┐                                                   
│log│ status                                            
└───┘                                                   
╔══════════════════════════════════════════════╗        
║show first child even if min size is too large║        
╚══════════════════════════════════════════════╝        
                                                        
 only sort when necessary                               
                                                        
                                                        
 call addChild on empty child widgets too               
                                                        
                                                        
 fix child focus id                                     
                                                        
                                                        
 update for zig 0.12.0-dev.2154                         
                                                        
                                                        
 remove focused field                                   
                                                        
                                                        
 pass root_focus to build and input                     
                                                        
```

This interface is showing a commit log. With the arrow keys, you can move the selection down the list. When you hit the right arrow (or enter), you see this:

```
┌───┐                                                   
│log│ status                                            
└───┘                                                   
╔══════════════════════════════════════════════════════╗
║                                                      ║
║ diff --git a/src/widget.zig b/src/widget.zig         ║
║ index 60791e5..4467b35 100644                        ║
║ --- a/src/widget.zig                                 ║
║ +++ b/src/widget.zig                                 ║
║ @@ -166,19 +166,22 @@ pub fn Box(comptime Widget: typ║
║                  var child = &self.children.values()[║
║                  child.widget.clearGrid();           ║
║                                                      ║
║ -                if (remaining_width_maybe) |remainin║
║ -                    if (remaining_width <= 0) contin║
║ -                    if (child.min_size) |min_size| {║
║ -                        if (min_size.width) |min_wid║
║ -                            if (remaining_width < mi║
║ +                // skip any children after the first║
║ +                if (sorted_child_index > 0) {       ║
║ +                    if (remaining_width_maybe) |rema║
║ +                        if (remaining_width <= 0) co║
║ +                        if (child.min_size) |min_siz║
╚══════════════════════════════════════════════════════╝
```

The list is hidden, and the diff of the selected commit is shown. Now let's resize the terminal so you can see both the commit list and diff:

```
┌───┐                                                                                           
│log│ status                                                                                    
└───┘                                                                                           
┌────────────────────────────┐╔════════════════════════════════════════════════════════════════╗
│show first child even if min│║                                                                ║
└────────────────────────────┘║ diff --git a/src/widget.zig b/src/widget.zig                   ║
                              ║ index 60791e5..4467b35 100644                                  ║
 only sort when necessary     ║ --- a/src/widget.zig                                           ║
                              ║ +++ b/src/widget.zig                                           ║
                              ║ @@ -166,19 +166,22 @@ pub fn Box(comptime Widget: type) type { ║
 call addChild on empty child ║                  var child = &self.children.values()[child_inde║
                              ║                  child.widget.clearGrid();                     ║
                              ║                                                                ║
 fix child focus id           ║ -                if (remaining_width_maybe) |remaining_width| {║
                              ║ -                    if (remaining_width <= 0) continue;       ║
                              ║ -                    if (child.min_size) |min_size| {          ║
 update for zig 0.12.0-dev.21 ║ -                        if (min_size.width) |min_width| {     ║
                              ║ -                            if (remaining_width < min_width) c║
                              ║ +                // skip any children after the first if their ║
 remove focused field         ║ +                if (sorted_child_index > 0) {                 ║
                              ║ +                    if (remaining_width_maybe) |remaining_widt║
                              ║ +                        if (remaining_width <= 0) continue;   ║
 pass root_focus to build and ║ +                        if (child.min_size) |min_size| {      ║
                              ╚════════════════════════════════════════════════════════════════╝
```

This sort of thing is common on the web, but not in TUIs. When TUIs were being built for a specific computer, such as the Apple II, this wasn't necessary, since the dimensions didn't change. Today, TUIs are mostly run in terminal emulators that can be resized at will.

* Focus and Selection

  * It should always be apparent where the focus is, and how to change it. In the examples above, I use a single border for selection, and a double border for focus. You never need to guess which widget receives your inputs.

  * To move the focus, you only need to use the arrow keys. Every single focusable part of the TUI can be reached by just moving the arrow keys. This is a powerful design limitation; all functionality must be laid out so the user can navigate to it without special shortcuts.

  * There is nothing wrong with having shortcuts as well, but many TUIs force the user to learn them upfront. I think TUIs should be navigable with only arrow keys, and should also support clicking/scrolling widgets with a mouse. This makes their use more discoverable.

* Accessibility

  * Color should only be used for emphasis. You should never rely on color for functionality, because some users turn color off entirely for accessibility. There are also displays, such as e-ink, that are still grayscale only.

  * In general, accessibility is probably the weakest area of TUIs. The web is much better at accessibility, because browsers have more semantic information about the page. Screenreaders need to know that this is a button, and that is a text field.

  * Terminals have no such semantic information. To them, a given TUI is just rendering a grid of characters. There is no high-level concept of a button or a text field. To fix this, we need to build new standards. There is a lot we can learn from the web here.

* I tried to design my own TUI library, [xitui](https://github.com/radarroark/xitui), around these ideas. It has built-in support for responsive design, and a built-in focus system.

* TUIs are not a relic of the past. Every GUI framework you are using today will eventually become obsolete, while the simplicity and timelessness of TUIs will remain. [GUIs get remembered, but TUIs never die](https://www.youtube.com/shorts/U_pqRP-4hUc).
