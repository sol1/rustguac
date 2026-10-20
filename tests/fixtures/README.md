# Fixtures

## `x264-high-bframes.264`

An H.264 Annex B stream from libx264, read by `src/h264_refs.rs`'s tests.

```sh
ffmpeg -f lavfi -i testsrc=size=128x96:rate=10:duration=2 -pix_fmt yuv420p \
       -c:v libx264 -profile:v high -bf 2 -refs 3 -f h264 \
       tests/fixtures/x264-high-bframes.264
```

High profile with B frames and three reference frames, so a reader has to cross
the scaling-list branch of the SPS, the B-slice fields of the slice header and
both reference lists. It carries non-reference pictures (`nal_ref_idc` 0), which
is the signature the probe exists to recognise in an AVC444 auxiliary view.

Kept as a real encoder's bytes rather than built in the test: the whole risk in
that parser is disagreeing with an encoder, and a fixture written by the same
understanding that reads it agrees with itself no matter how wrong both are.

The expected values in the tests are **ffmpeg's**, not ours:

```sh
ffmpeg -v trace -i tests/fixtures/x264-high-bframes.264 -c copy \
       -bsf:v trace_headers -f null - 2>&1 |
    grep -E "nal_ref_idc|slice_type|frame_num"
```
