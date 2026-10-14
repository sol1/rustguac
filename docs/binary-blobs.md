# Binary blobs

Blob payloads travel as base64 inside text instructions. Base64 sends four
bytes for every three, so **a quarter of everything on the wire is encoding
overhead**. This replaces that with binary WebSocket frames on the streams
where it pays, and changes nothing else.

Measured on two captures of the same Windows host:

| capture | payload | on the wire | overhead | wire bitrate |
|---------|---------|-------------|----------|--------------|
| idle desktop, 339s | 15.3 MB | 20.4 MB | 5.1 MB | 0.48 -> 0.36 Mbps |
| video, 167s | 81.2 MB | 108.3 MB | **27.1 MB** | 5.18 -> 3.88 Mbps |

## Why upstream does not do this

Not an oversight. The Guacamole protocol is defined as text -- one grammar of
length-prefixed UTF-8 elements -- and `.guac` recordings are that same stream
on disk, which `SessionRecording.js` parses and operators grep. Guacamole also
still supports HTTP long-polling (`Guacamole.HTTPTunnel`), which cannot carry
interleaved binary, so a binary path forks the protocol across its two
tunnels. And upstream's workload is PNG/JPEG tiles at modest rates, where a
quarter of a small number is a small number.

Sustained multi-megabit H.264 is a workload upstream does not have. It exists
here because of `patch 004`, which is what changes the arithmetic.

## Scope: which streams

Only streams whose consumer wants bytes:

- **`h264`** -- 108.3 MB of the video capture.
- **`audio`** -- 36.2 MB of it. Same reader, so it comes free.

Together that is 144.5 MB of the 144.9 MB of blob traffic in that capture.

**Not `img`.** Its blobs reach `DataURIReader`, which concatenates base64
directly into a `data:` URI and genuinely wants the encoded form. Converting
it would mean re-encoding to undo the conversion. It is also 0.0 MB in both
captures.

On the client every one of these funnels through a single chokepoint:
`Guacamole.ArrayBufferReader`, used directly by the H.264 path and
`AudioPlayer`, and wrapped by `StringReader` and `InputStream`. One reader
change covers all of it.

## Where the conversion happens, and why not in guacd

Encoding today is `guac_protocol_send_blob()`
(`guacamole-server/src/libguac/protocol.c:246`), which calls
`guac_socket_write_base64()`. The H.264 path reaches it through
`guac_protocol_send_blobs()`, which chunks each access unit.

**The conversion belongs in rustguac, not in a guacd patch.** rustguac tees the
raw guacd stream to disk as the recording, so converting upstream of that tee
turns every recording binary and drags `SessionRecording.js`, the playback
page and the recording format along with it. Converting on the way out to the
browser leaves guacd and the recording format untouched and still captures the
whole win, because the guacd -> rustguac hop is loopback, where saving 25% of
nothing is nothing.

The cost is that `guacd_to_ws` stops being a blind forwarder and has to parse
instructions to find the blobs. It is already halfway there -- it scans for
instruction boundaries on that same path.

Order within `guacd_to_ws` is therefore: **record, then convert, then send.**
The recording sees exactly what it sees today.

## Wire format

A binary frame carries an 8-byte header and then the raw payload:

    byte 0      format version (1)
    byte 1      frame type (0 = blob)
    bytes 2-3   reserved, zero
    bytes 4-7   stream index, u32 little-endian
    bytes 8..   payload

The stream index is in the frame rather than inferred from the preceding text
instruction, so the frame is interpretable on its own and the client's parser
stays stateless. The header is 8 bytes so the payload starts aligned.

WebSocket delivers text and binary frames in one order, so a blob converted to
a binary frame still arrives between the same neighbours it had as text.
Nothing here can reorder the stream, which is what keeps this a change of
encoding rather than a change of transport: no sequencing, no reassembly, and
no ordering hazard of any kind.

## Negotiation

The client appends `binaryBlobs=1` to the WebSocket query, and the server
converts only when it sees it. A client that does not send it -- an older
cached `client.html`, a third-party integration, a recording player -- receives
exactly the base64 text it does today.

This matters more than usual here: `index.html` and `client.html` are cached in
memory at startup, so a browser can hold an older client than the server. The
default has to be the old behaviour.

## Verifying it is actually on

**From the browser console**, on a live session:

    __guac_tunnel.binaryFrames    // frames received; 0 means base64 is in use
    __guac_tunnel.binaryBytes     // payload bytes carried by them

**From the journal**: `Starting proxy` logs `binary_blobs=true|false` per
connection.

Zero frames on a session that is otherwise working means the client did not
negotiate it -- almost always a cached `client.html` or `Tunnel.js`, since the
server falls back to base64 for any client that does not ask.
