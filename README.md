HLS TS tools: do some very specific things to some very particular MPEG-TS
video files to enable [HTTP Live Streaming][hlswiki].

NOTE: currently, ts_split won't work on some (well, most) .ts files. If you
need this functionality for your own project, file a bug or send me an email
and I'll get around to generalizing this code.

# Compiling

These are standard C99 files (I think), so you can just run

    $ gcc -o ts_split ts_split.c -std=c99
    $ gcc -o ts_restamp ts_restamp.c -std=c99

# Why?

The [Aduro project][aduro] produces fractal flame animations by interpolating
between artist-designed control points. The result is a richly-connected cyclic
graph of animations, where each node in the graph is a point where animations
can be joined seamlessly. To play the animations, a random walk of the graph is
done, providing a nearly infinite variety of unique orderings while still
giving a sense of the familiar, as previously-seen nodes are accessed with
different combinations of input and output edges.

Part of the Aduro project is using feedback from viewers to guide a genetic
algorithm towards evolving interesting edges. (In this aspect, it's a lot like
the [Electric Sheep][sheep] project that inspired it.) In many cases, we use
HTTP Live Streaming to get this content to users. At a minimum, HLS works best
when reasonable segment sizes are available, which requires that we split the
animations into multiple MPEG-TS files. This is pretty typical stuff.

However, MPEG-TS stores absolute timestamps for content in a few different
places within a bitstream. Many decoders, upon encountering a stream with a
discontinuity in these timestamps, flush their buffers, resulting in a lengthy
delay or at least a hiccup in playback. To avoid this, we need to normalize the
timestamps in the files so that the reconstructed timestamps are continuous.
Since the playback order is random for any given user, however, it's not
feasible to do this in advance; we need to renormalize timestamps as the files
are being served.

To this end, `ts_split` normalizes the transport streams as they are written,
and logs the location and relative offset of every transport stream timestamp
in a separate index. `ts_restamp` uses this index file to efficiently rewrite
the timestamps on the fly, without having to parse or remux the file. Streaming
is then a matter of simply passing the appropriate options to `ts_restamp` via
the URL specified in the playlist file, and allowing it to serve the files as a
CGI script.

# ts_split

    ./ts_split input_file.ts output/path/

This tool reads an MPEG-TS file containing a single program, itself consisting
of a single H.264 elementary stream, and splits it into one or more complete
and independently-decodable MPEG-TS files. This is the sort of thing required
for HLS, and I'm pretty sure Apple [has a tool][hlsapple] to do this which
works on more than , if you happen to prepare your streaming tools on a Mac.

`ts_split` copies the program association table and program map table from the
original TS to each split TS, and inserts copies of the PPS and SPS NALUs into
the H.264 byte stream at the start of each new file, which allows for
independent decoding. It also strips adaptation fields containing program clock
reference fields from the input. This latter feature is useful for the
immediate purpose of the tool, described below.

## Limitations

`ts_split` currently operates on a file with a single program map at a fixed
PID of 0x20, which specifies a single H.264 PES at a fixed PID of 0x40. This
is, not coincidentally, exactly what GStreamer's `mpegtsmux` element creates.
Most adaptation field and PES flags are also unsupported.

Each split contains exactly one group of pictures, since we currently just open
a new file at every IDR (I-frame). If the encoder decides to insert a bunch of
scene-cuts, or have a really long GOP, or anything other than inserting IDRs
every 10 seconds or so, the slice sizes will be silly.

# ts_restamp

Gotta write it first.

[aduro]: http://aduro.strobe.cc/
[hlswiki]: http://en.wikipedia.org/wiki/HTTP_Live_Streaming
[hlsapple]: http://developer.apple.com/resources/http-streaming/
