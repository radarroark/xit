Handling large, binary files well is non-negotiable for the next version control system. People are using VCSes for more things than in the past, and many of those things involve tracking non-text files.

Git is famously bad at handling large, binary files, but most people can't articulate why. Is it because version control as a concept just isn't compatible with them? Is it a conspiracy by Big Text to force you to keep your binary files outside of your repo? No, it's way more boring than that. I would give two main technical reasons:

1. Git is pretty bad at deltification (deduplicating files with a lot of data in common). Initially it doesn't try to at all -- it just stores each version of a file separately as "loose objects". Then, at various points, it tries to combine them into pack files that have a very idiosyncratic delta scheme.

2. Git always compresses objects with zlib, regardless of whether it helps. While zlib is great at compressing text files, it often will cause binary files to become *larger*. This is especially true for formats that are already compressed, like audio and video files.

The above issues were very straight-forward to solve in xit:

1. When an object is added to xit, it immediately splits it into chunks using FastCDC, a content-defined chunking algorithm. By chunking files, they are immediately being deduplicated because only the chunks that changed need to be saved internally. This is pretty much what every backup program on the planet does, so there is no innovation going on here, but that won't stop me from pretending there is.

2. A chunk is only compressed if it contains text data. A chunk with binary data is always stored uncompressed. It marks this with a special byte at the beginning of the chunk. If the first byte is 0, it is uncompressed; if it is 1, it is zlib-compressed. Other algorithms can be accomodated later.

Since compression is done per chunk, rather than on the entire object, it won't compress as well as it would in git. You get more benefit from compression if you can run it over the entire file. I think this is a worthwhile tradeoff:

* Compressing before chunking would harm deduplication by causing more chunks to be different compared to an earlier revision.

* Compressing before chunking would force the system to decompress all previous chunks before getting the data in a given chunk. By compressing per chunk, we can jump directly to the chunk we want and only start decompressing from there.
