Handling large, binary files well is non-negotiable for the next version control system. People are using VCSes for more things than in the past, and many of those things involve tracking non-text files.

Git is famously bad at handling large, binary files, but most people can't articulate why. Is it because version control as a concept just isn't compatible with them? Is it a conspiracy by Big Text to force you to keep your binary files outside of your repo? No, it's way more boring than that. I would give two main technical reasons:

1. Git is pretty bad at deltification (deduplicating files with a lot of data in common). Initially it doesn't try to at all -- it just stores each version of a file separately as "loose objects". Then, at various points, it tries to combine them into pack files that have a very idiosyncratic delta scheme.

2. Git always compresses objects with zlib, regardless of whether it helps. While zlib is great at compressing text files, it often will cause binary files to become *larger*. This is especially true for formats that are already compressed, like audio and video files.

The above issues were very straight-forward to solve in xit:

1. When an object is added to xit, it immediately splits it into chunks using FastCDC, a content-defined chunking algorithm. By chunking files, they are immediately being deduplicated because only the chunks that changed need to be saved internally. This is pretty much what every backup program on the planet does, so there is no innovation going on here, but that won't stop me from pretending there is.

2. A chunk with binary data is always stored uncompressed. Chunks mark their compression type with a special byte at the beginning of the chunk. If the first byte is 0, it is uncompressed; if it is 1, it is zlib-compressed. Other algorithms can be accomodated later.

While xit has compression support, it currently disables it even for text files, because it significantly slows down patch creation/application. This means xit repos with text files will probably be larger on disk than git repos. We may re-enable it if perf improves, or possibly put it behind a config option, but I don't think it's that important these days. Disk space is cheap, and xit's patch code is computationally intense, so for now it's a good tradeoff to use more of the former to make the latter faster.
