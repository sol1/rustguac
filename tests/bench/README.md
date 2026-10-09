# AVC444 combine benchmark

Times the work the AVC444 4:4:4 combine adds on top of an ordinary AVC420
stream, using the real `static/guac/Yuv444.js` and real `VideoDecoder` output.

```sh
node tests/bench/run.mjs                 # headless, on the GPU
node tests/bench/run.mjs --json out.json # also write the raw numbers
node tests/bench/run.mjs --headed        # watch it
node tests/bench/run.mjs --software      # SwiftShader, for comparison
```

No dependencies: the driver talks to Chrome over the DevTools protocol using
the `WebSocket` and `fetch` built into Node 22+.

Two things about the environment are not incidental and the driver sets both:

* **The page is served over `http://127.0.0.1`, not opened as a file.**
  WebCodecs is exposed only to secure contexts, and `file://` is not one — under
  `file://` `VideoDecoder` is simply `undefined` and there is nothing to decode.

* **Chrome is started with `--use-gl=angle --use-angle=gl-egl`.** Headless Chrome
  brings up no GL implementation by default, so `Yuv444Renderer.isSupported()`
  returns false and the benchmark refuses to run. Falling back to SwiftShader
  instead would make the fragment shader dominate everything and invert the
  conclusions, which is why that is behind `--software` rather than automatic.

## What it reports

* **Per phase** — read-back, upload, conversion, paint, measured separately with
  a real `gl.finish()` between them, so the end-to-end number can be attributed
  rather than guessed at.
* **End to end** — each optimisation switched on in turn, median of five runs, at
  1080p and 4K, against three damage patterns (whole screen, one window, a
  caret and its line) and against the AVC420 path that does not combine at all.
  That last row is also the steady state of adaptive suspension, so it doubles
  as the ceiling on what suspending combining during video can be worth.
* **Two correctness checks** — that scissoring changes no pixel inside the
  regions the caller draws, and that the auxiliary view is actually being
  applied. A combine that had quietly stopped working would otherwise benchmark
  extremely well.

## Hardware versus software decode

This decides the answer to every read-back question, so the benchmark asks for
hardware decode explicitly and **reports which it got** rather than assuming:

```
frames 1920x1080: I420 from a real VideoDecoder
  decode: software (hardware NOT offered by this browser), read-back 22.3 GB/s
    — memcpy speed, so the planes are in system memory
```

A software decoder's planes are already in system memory, where `copyTo()` is a
`memcpy`. A hardware decoder leaves them on the GPU, where the same call is a
transfer across the bus and considerably dearer — and where uploading the frame
as RGB instead (skipping the read-back entirely) becomes worth considering.
The throughput line settles it independently of what the browser claims: tens
of GB/s is a memcpy, single digits is a transfer.

On a machine reporting `software`, treat the read-back row, the value of
overlapping the two views' copies, and the RGB-upload probe as **lower bounds**
that do not settle the hardware case. Re-run it on a client that actually
hardware-decodes before acting on any of the three.

Chrome declines VA-API for WebCodecs on the development box this was written on
— `VideoDecoder.isConfigSupported({hardwareAcceleration: 'prefer-hardware'})`
returns false, headless and headed alike, with `VaapiVideoDecodeLinuxGL` and
friends set and `vainfo` reporting `VAProfileH264High : VAEntrypointVLD`. The
driver passes the flags anyway, since they cost nothing where they do not
apply.
