# H.264 passthrough for RDP

rustguac can forward an RDP server's H.264 stream straight to the browser's
WebCodecs decoder instead of having guacd decode it and re-encode the pixels as
JPEG/WebP. With 1080p video playing, that takes guacd from roughly a full CPU
core down to about 2% of one — measured on both xrdp and Windows 11.

Enable it per connection with the **H.264** checkbox on the entry. There is no
server-side configuration and no environment variables.

## What the server has to send

Passthrough only engages when the server actually sends H.264 over the RDPGFX
Graphics Pipeline. Both AVC420 and AVC444 work.

- **xrdp** — set a GFX codec order listing H.264 in `/etc/xrdp/gfx.toml`. Nothing
  else is needed; xrdp sends AVC420 and passthrough applies to every frame.
- **Windows** — needs the host settings below. Without them Windows sends
  CLEARCODEC and CAPROGRESSIVE instead, and guacd falls back to decoding and
  re-encoding. The display is still correct, just far more expensive.

## Windows 11 host settings

These are not optional, and two of them are non-obvious. Verified on Windows 11
Pro with an NVIDIA RTX 3070.

### 1. Disable the WDDM display driver for Remote Desktop

Group Policy → Computer Configuration → Administrative Templates → Windows
Components → Remote Desktop Services → Remote Desktop Session Host → Remote
Session Environment → **"Use WDDM graphics display driver for Remote Desktop
Connections"** → **Disabled**. Reboot.

**This is what allows hardware H.264 encoding to engage at all.** With the WDDM
driver in place, the session runs on the GPU for rendering but never reaches the
encoder: Task Manager shows GPU 3D under load while **Video Encode stays at 0%**
and `nvidia-smi encodersessions` reports nothing. Setting the registry values
below without also disabling WDDM changes nothing — the policy is accepted and
has no effect.

Note this changes the display pipeline, so check dynamic resize and
multi-monitor behaviour after enabling it.

### 2. Prefer AVC 4:4:4

```
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services
    AVC444ModePreferred = 1   (DWORD)
```

Counter-intuitively this is required **for hardware encoding**, not for image
quality: setting it to 0 on the test host stopped NVENC entirely and fell back
to software encoding. Windows then sends AVC444, which rustguac handles — both
views are forwarded to the browser and combined there into full 4:4:4 chroma,
so leaving this on costs nothing in image quality and is what makes hardware
encoding engage.

### 3. Raise the frame rate cap

```
HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations
    DWMFRAMEINTERVAL = 15   (DWORD)   # 60fps; default is 30
```

### 4. Hardware encoding policy

```
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services
    AVCHardwareEncodePreferred = 1   (DWORD)
    bEnumerateHWBeforeSW       = 1   (DWORD)
```

`contrib/setup-rdp-performance.ps1` applies items 2–4; item 1 is a Group Policy
change and must be made separately. Run the script with `-Report` first to see
what is already configured.

### What you do *not* need

The **"Prioritize H.264/AVC 444 Graphics Mode for Remote Desktop Connections"**
policy does not need to be Disabled. It was used during development to force
AVC420, but rustguac handles AVC444 directly now, and on the test host Windows
ignored the client's AVC420 request regardless — it confirmed RDPGFX capability
version 10.7 with the `AVC_THINCLIENT` flag set and sent AVC444 anyway.

## Verifying

After connecting, on the Windows host: Task Manager → Performance → GPU →
**Video Encode** should be non-zero during activity. If it reads 0%, hardware
encoding is not engaged — check the WDDM policy first.

On the rustguac host, with `GUACD_LOG_LEVEL=trace` in `/opt/rustguac/guacd.env`:

```bash
# Which codecs the server is sending. 11 = AVC420, 14/15 = AVC444(v2).
# 8 = CLEARCODEC and 9 = CAPROGRESSIVE mean H.264 is not being used.
journalctl -u rustguac-guacd --since '1 min ago' | grep "TRACE:" \
  | grep -oP 'codec=\K[0-9]+' | sort -n | uniq -c

# The RDPGFX capability version the server confirmed
journalctl -u rustguac-guacd --since '2 min ago' | grep "RDPGFX capability version"

# guacd CPU with the workload running
./contrib/measure-guacd-cpu.sh
```

`display-wrk` near zero in that last output is the sign that passthrough is
working: it means image encoding is not happening.

In the browser console, the decoder says what it does as `[rustguac] H.264`
lines, on the state change rather than per frame: decoder rebuilds, waits for
a keyframe, abandoned frames, the codec it configured, and whether 4:4:4
combining is on and why not when it is off (`chroma_off`,
`chroma_aux_dropped`, `chroma_declined`, and the gate's own reasons). A quiet
console on a working session is the expected state.

For per-stage timings — decode, the copy and its parts, combine, queue, draw,
paint, and how the copy banded — set `h264CombineLog` and read the five-second
report.

(There was previously an `__h264.stats()` documented here reporting
`avgDecodeLatencyMs`, `framesDropped`, `gcLeaks` and `auxViewsDecoded`. No part
of that survives: neither the global, nor the method, nor any of those fields.)

## When the whole picture looks soft

Before blaming the codec, check that the client is not resampling. In the
browser console on the client tab:

```js
__guac_client.getDisplay().getScale() * devicePixelRatio
```

**1.0** means one framebuffer pixel per physical pixel. Anything else is a
resample, and it softens text, icons and images uniformly — which a codec does
not do. Measured on a Windows session at 2.016, the picture contained almost no
single-pixel edges at all: 0.01% of adjacent pixels differing by more than 100
levels, against 0.82% for the same page rendered natively, with the sharpest
transition anywhere reaching 114 where native reached 194.

The fix is the entry's **Native Resolution (HiDPI)** checkbox, which asks for
the framebuffer in physical pixels. Note it multiplies the pixels the host
encodes and the browser decodes by the square of the ratio.

### Asking for the exact DPI scaling

MS-RDPBCGR restricts `deviceScaleFactor` to 100, 140 or 180. Pairing a
framebuffer sized for a 2.0 display with 180% scaling draws the UI about 10%
smaller than nominal — sharp, but small.

The protocol is not the whole obstacle: `desktopScaleFactor` is legal from 100
to 500. FreeRDP transposes the pair when it synthesises the single-monitor
definition (`libfreerdp/core/settings.c`, the monitor's `desktopScaleFactor`
filled from `FreeRDP_DeviceScaleFactor` and vice versa), so any unequal pair
reaches the server backwards and an out-of-range device factor makes it discard
both. Equal values are the only ones that survive that path, which is what
`guac_rdp_normalize_desktop_scale` snaps to.

**The display-control channel is not subject to that.** `disp.c` builds the
`DISPLAY_CONTROL_MONITOR_LAYOUT` itself and hands it straight to the channel,
so nothing transposes it, and MS-RDPEDISP 2.2.2.2.1 likewise restricts only
`DeviceScaleFactor`. The layout therefore carries the exact percentage —
`DesktopScaleFactor = 200` beside `DeviceScaleFactor = 180` — and since the
client fits the display to the browser window shortly after connecting, that
layout is what the session ends up scaled by. The connection-time core data
still goes out snapped and is overridden a moment later.

An xrdp target is unaffected either way: xrdp parses the scale factors and
drops them unused (`docs/xrdp-dpi-scaling.md`), so a session script setting
`/Gdk/WindowScalingFactor` or `/Xft/DPI` remains the only thing scaling that
desktop.

### When 4:4:4 combining is declined, and when it is given up

An AVC444 stream that is not combined is still decoded; it is painted at 4:2:0,
from the main view alone. Three things can cause that, in the order they act.

**A prior on framebuffer area** (`COMBINE_MAX_PIXELS`, 4K). A ceiling on the
worst case a session may open with before anything has been measured, and no
longer the thing that decides. It was 4MP until 2026-09-12, set against the
plane uploads and the shader pass; those were later measured at under 2ms
together, while the cost that matters is not a function of the framebuffer at
all once the copy is limited to the damaged rows. A 4.93MP Windows session
doing desktop work copies 3-5% of its planes and spends ~9ms a picture, which
the old threshold declined outright.

**A gate on the measured copy** (`COMBINE_COPY_TRIP_SHARE`, 30% of wall clock
spent inside `copyTo()`). Gives up when the mean *synchronous* copy per picture over a busy 10s
window exceeds it. `VideoFrame.copyTo()`'s synchronous half is the cost of
combining -- see the investigation below -- and it is blocking main-thread
time, so it is both what the user feels and a wall-clock delta that is exact
and free to measure. Typing at 4.93MP measures ~9ms a picture and full-screen
video ~42ms; neither is near the line.

**Two latches beneath both**, on sync-gate timeouts and on slow display
flushes. Their minimums decide which fires first: the sync-timeout latch has
none (3 timeouts in 10s), the copy gate needs 30 pictures in its window, the
flush latch 100 syncs. So a session degraded to a few frames a second -- what
full-screen video at high resolution does, once every row is damaged and the
copies go back to whole planes -- is caught by the sync-timeout latch within
seconds, and by the copy gate at the next window boundary, while the flush
latch may never reach its minimum.

**The area prior is keyed on framebuffer area rather than the desktop scale**,
which was the first thing tried and is wrong twice over. The scale only says
whether HiDPI scaling was applied, so a 4K display at `devicePixelRatio` 1
slips past it. And the cost is not a property of the host: the same picture
costs the same to combine whatever sent it, which is why this was taken for an
xrdp problem until a Windows session was run at native resolution.

`h264Chroma444` overrides, `h264CombineMaxPixels` moves the prior, and
the declined case logs once saying why. Setting the override disables every
gate above, since an override is an instruction rather than a preference.

### Why the gates are latches rather than controllers

They are **one-way** on purpose. An earlier version measured the combine
against a frame budget whose divisor was the observed interval between
pictures -- which is what `012`'s frame-ack back-pressure has already throttled
the server to, and that back-pressure reacts to the lag combining causes. It
read its own output as its input. A latch has no loop.

A trip caused by something else -- a slow link, a struggling decoder -- gives
up chroma for nothing. That is the accepted cost: a little colour resolution,
no frames, and `h264Chroma444` brings it back -- as `window.__h264Chroma444
= true` for the current page, or the `h264Chroma444` key in localStorage to
survive a reconnect. Not as a query parameter: client.html rebuilds
`/client/{id}?name=...` on every launch and drops anything added by hand, so
one lasts until the first reconnect. The recording player is the exception,
since nothing rewrites its URL.

**They resume once the load passes.** After the session has stayed *quiet* for
`COMBINE_RECOVER_MS`, combining is tried again (`chroma_resumed`), up to three
times per session; after the third it stays off for good. Quiet rather than
merely clean: 4:2:0 never flushes slowly, so a "clean" test resumed mid-video
and spent every attempt on the same one. Tripping during a video and resuming
once it stops is the expected shape -- heavy video is exactly where 4:2:0
chroma costs least and where the combine costs most, and reading text
afterwards is where the auxiliary stream earns its keep.

The long recovery window is not about hiding a visible flap; there barely is
one, since only newly painted regions change chroma resolution. It is about the
**resync**: the first combine after a gap copies and uploads whole planes
rather than damaged rows, which is the most expensive kind there is, and
delivering that to a client that has only just stopped struggling is how a gate
makes things worse. Three attempts then draws the line between a desktop that
had a video playing and a client that simply cannot sustain the combine --
sample by sample the two look identical, and only time separates them.

**Measuring the combine's GPU work is still the hard part**, and is why the
latches gate on symptoms. Timing GPU execution needs a `gl.finish()` per
picture -- stalling the pipeline the gate protects -- or timer queries that are
not reliably available. `h264CombineLog` now calls `Yuv444Renderer.finish()`
before stamping, so its `combine` figure is execution rather than submission,
at the cost of that stall; it is a diagnostic, not something a gate could use.
None of this applies to `COMBINE_COPY_TRIP_SHARE`, which times synchronous calls
on the main thread rather than GPU work.

### Is it the combine, or the handoff? (investigation)

The field numbers do not add up to what `tests/bench` measures. At 1920x1072
against the xrdp fork, 4:2:0 ran at 54.7 syncs/s with a 0.6ms mean flush and
4:4:4 at 33-41/s with 16-22ms. Part of that ratio is an accounting artifact --
the 4:2:0 path snapshots the `VideoFrame` into a 2D canvas inside the decoder's
output callback, so its pixel copy is already paid before flush begins, while
the combine path only *submits* GPU work there and the result is first needed
inside flush. But the sync rate cannot be an artifact: 54.7/s to 33-41/s is
6-12ms per frame, against a benched combine of ~2.8ms at 2.06MP.

The same slowdown appears on an RTX 3070 and an Intel 770. Those differ by
roughly 8x in memory bandwidth and the NVIDIA part decodes on a separate
engine, so agreement between them rules out shader cost, GPU bandwidth, and
contention between the two hardware decodes and the combine. What survives is
what is *not* GPU throughput: CPU-side driver staging (which is what
`texSubImage2D` already is), and synchronous GPU-to-CPU transfers.

That points at a boundary the 4:2:0 path never crosses. The combine's output is
a GPU-resident `ImageBitmap` produced by the renderer's own WebGL2 context, and
it is consumed by `drawImage()` into the display layer's 2D context. If the
driver cannot share that surface, the blit is a readback -- area-proportional,
vendor-independent, and invisible to every existing instrument. And it would
not shrink with damage: `render()` scissors the conversion to the damage rects,
but `transferToImageBitmap()` hands over the **whole drawing buffer** every
frame. At 1920x1072 that is 8.2MB crossing the boundary to repaint a caret,
which is also why banding the plane uploads measured 2.0x in the bench and much
less in the field.

**How it was tested, and why none of it is still here.** A `paint` stage timed
the `drawImage()` calls in `drawDecoded()` against two denominators -- damaged
megapixels against buffer megapixels, since which one the cost tracks says
whether it is the blit or the handoff -- split by which kind of surface
crossed, with `sync_hold` splitting its flush the same way. The control was an
override that snapshotted an unpaired main view the way the 4:2:0 path does,
skipping `render()` for that picture only, so both handoffs could be measured
on one stream and one session. All of it came out at 0.01ms/MP, answered the
question once, and was removed with the rest of the scaffolding; it is on
`feature/combine-handoff-instrumentation` if the question ever reopens.

#### Result: it is not the handoff, and `flush` was never measuring the display

Measured at 1920x1072 against the xrdp fork with `CHROMA_INTERVAL=8`, combining
forced on, over three 5s windows:

```
  decode  chroma 35 mean 14.4 max 50.7  |  luma 274 mean 6.1 max 43.4
  combine chroma 35 mean  0.5 max  0.9  |  luma 239 mean 0.3 max 1.0
  draw    chroma 35 mean 12.5 max 33.1  |  luma 239 mean 15.1 max 57.5
  paint   bitmap 274 mean  0.0 max  0.4 0.01ms/MP  |  canvas none
  read-back wait mean 0.0 max 0.1
sync_hold: 2090 syncs (34.8/s) held 3 (0%) timeouts 0
           | flush mean 19.9ms max 89ms
```

**The handoff is free.** `paint` is 0.0ms mean, 0.4ms max, 0.01ms/MP against
either denominator. The ImageBitmap crosses into the display's 2D context at
no measurable cost, so the driver is sharing the surface, not reading it back.
The bounding-box change that would have followed is not worth making, and the
vendor-independence that pointed here has a duller explanation: nothing on this
path is GPU-bound at all.

**The combine is also cheap in situ** -- 0.3-0.5ms with `gl.finish()` forcing
completion, against the bench's ~1.37ms/MP (~2.8ms at this size). No
contradiction: the bench measures full-frame damage, and a real desktop's
damage is small, which is exactly what the banded uploads and the scissored
conversion were built for. The bench is a worst case, not a typical one.

**And `flush` was measuring the wrong thing.** The stack that produced these
numbers runs `recordHold` <- `waitForPending` <- `displaySyncComplete` <-
`Frame.flush` <- `__flush_frames` <- `Task.unblock` <- `__display_h264_ready`
<- the combine's own promise. The display's flush *completes inside the
decoder's unblock*: a frame carrying H.264 blocks its display task until the
picture is available, so `flush mean 19.9ms` is how long the display waited for
the decoder, not how long the display took to draw.

That matters beyond this investigation. `COMBINE_FLUSH_TRIP_MS` gives up
combining when the mean flush exceeds 8ms, and what it is reading is decode
latency rather than display cost.

*(Corrected 2026-09-12. It was written here that the latch therefore trips on
something it cannot fix, since lever 3 removes the combine and not a single
decode. That is wrong, and the measurements later in this section disprove it:
`decode` fell from 28-38ms to 1-4ms once the copies were banded. Combining
blocks the main thread, which delays the decoder's output callbacks, which
inflates decode latency, which is what flush measures -- so combining does
influence the signal and suspending it does reduce it. The chain is real, just
indirect. What is true is weaker: the flush latch reads the cost at three
removes where `COMBINE_COPY_TRIP_SHARE` reads it directly, and it has the
strictest minimum of the three latches -- 100 syncs in 10s against the copy
gate's 30 pictures and the sync-timeout latch's none -- so it is the least
likely of them to fire first. Subsumed and second-hand, not misdirected, and
worth keeping for the main-thread congestion that combining contributes to
without the copy time alone showing it.)*

**What is left unexplained is `draw`:** 12.5-19.8ms from the `VideoFrame`
arriving in `output()` to the paint, of which the combine is 0.5ms, the
read-back wait 0.0ms and the paint 0.0ms. Roughly 12-18ms is unaccounted for.
A `queue` stage now splits it -- `onReady` is wrapped to stamp when the
picture actually became available, so `draw` minus `queue` is the asynchronous
chain and `queue` is time spent in the display's ordered queue behind frames
that were not ready yet.

**Next measurement:** the same three stages with `window.__h264Chroma444 =
false` on the same session and host. `false` is an override like any other, so
the latch stays out of the way and the comparison is clean. If `decode` and
`queue` are what grow between the two runs, the cost is the second access unit
and the pipelining around it, and the client-side combine gate is aimed at the
wrong thing.

#### It is not `copyTo()` either -- and the decode times say why

The natural next suspect is `VideoFrame.copyTo()`: pulling the planes out of a
decoded frame is a GPU-to-CPU transfer, and that cost looks unavoidable. The
run above already measures it. `read-back wait` -- issuing the copy to the
chain resolving it -- is **mean 0.0ms, max 0.1-0.2ms**. It is not the
bottleneck, and it is not close to being one.

But a near-free `copyTo()` is itself strange, and taken together with the rest
of the run it points somewhere specific:

* `copyTo()` costs nothing, which is what happens when the planes are **already
  in system memory** rather than in GPU memory.
* `decode` is **6-10ms for a main view and 14-20ms for an auxiliary one** at
  1920x1072. A hardware decoder does 1080p in single-digit *tenths* of a
  millisecond of engine time and a few ms of latency; this is an order out.
* Nothing on the GPU path costs anything: combine 0.5ms, paint 0.0ms.
* The slowdown is identical on an RTX 3070 and an Intel 770 -- which is
  expected if the GPU is barely involved.

That is the signature of **software decoding**. `H264Decoder.js` already
documents the trap: `hardwareAcceleration: 'prefer-hardware'` is a *preference,
not a requirement*, and a stream whose frames exceed the declared codec level
falls back to software silently -- which is exactly why `DEFAULT_CODEC` was
raised to level 5.2, after a 2688x1488 session "decoded in software at roughly
twenty times the latency, and under AVC444 for two pictures per frame."

If that is what is happening here, every conclusion inverts. AVC444 would not
be expensive because combining is expensive -- combining is nearly free. It
would be expensive because it asks a *software* decoder for two access units
per picture instead of one, and the client-side combine gate cannot remove a
single one of them.

**The cheapest check is the format the decoder hands back**, now printed in the
`h264CombineLog` header as `(decoder gives ...)`. A hardware decoder on Windows
gives **NV12**; **I420** is Chrome's software decoder. `chrome://media-internals`
confirms it by name, and shows why a fallback was taken.

An `issue` stage was also added, timing `combineFrame()` entry to the copy being
issued -- `allocationSize()` plus the synchronous half of `copyTo()`, which sat
in neither `copyWait` nor `combine` and was inside the unexplained window.
With `decode`, `issue`, `copyWait`, `combine`, `queue` and `paint`, `draw` is
fully accounted for.

#### Result: it *is* `copyTo()`, in its synchronous half

Measured at 2992x1648 (4.93MP) on a HiDPI laptop against a Windows host,
hardware decode confirmed (`chrome://media-internals`: `D3D11VideoDecoder`,
NV12, `kIsPlatformVideoDecoder: true`):

```
  issue   chroma 28.5  |  luma 34.7
  alloc   chroma  0.0  |  luma  0.0
  buf     chroma  0.0  |  luma  0.0
  copy    chroma 28.5 5.77ms/MP  |  luma 34.6 7.01ms/MP
  combine chroma  1.5  |  luma  0.9
  paint   0.01ms/MP
```

`allocationSize()` and the buffer pool are free. **`copyTo()`'s synchronous
prologue is the whole of it** -- the D3D11 array-texture copy and staging map,
blocking, on the main thread. `read-back wait` reads 0.0-0.1ms because it times
the *promise*, and by the time the promise is awaited the work is already done.
That is why the transfer looked free for three rounds of this investigation.

Two things follow from the per-megapixel figures. Both views compute to the
same 4.93MP, so **the AVC444 auxiliary view is a full-size picture**: a paired
picture reads back 14.8MB, two whole NV12 frames. And at ~101 copies per 5s
this is **roughly 69% of the main thread**, which is what the rest of the
pipeline is queueing behind -- `queue` 18-33ms, `draw` 47-62ms, flush 68ms,
and in a worse window a decode backlog that took `decode` to 617ms before
draining.

So AVC444 does not cost twice as much because combining is expensive.
Combining is 0.9-1.6ms. It costs twice as much because it demands a **second
full-frame GPU-to-CPU readback**, and that readback is the pipeline.

This also vindicates `COMBINE_MAX_PIXELS` while correcting the reasoning behind
it. The 4MP threshold is right -- this session is 4.93MP and would have
declined to combine had the measurement not overridden it -- but the cost it
was set against was the shader and the uploads, which together are under 2ms.
The real curve is the readback's.

**What is not yet settled** is whether the cost is a transfer or a fixed stall
per call, because only one framebuffer size has been sampled. 34.6ms for 7.4MB
is ~214MB/s, which looks like a transfer, but a stable ms/MP at *one* size
proves nothing about proportionality. Resizing the client and re-reading
`copy`'s ms/MP settles it: steady means a transfer, rising as the area falls
means a fixed stall.

If it is a transfer, the fix follows the banding already built everywhere else.
`copyTo()` accepts a `rect` and is currently handed the whole coded frame every
picture, while the plane uploads are banded to the damage and the shader is
scissored to it -- the narrowest stage of the pipeline feeding off the widest.
Restricting the rect to the damaged rows would cut it in proportion, with the
v1 auxiliary layout rounding outward to its 16-row bands as `auxV1LumaBands()`
already does, and a resync still copying everything.

It would transform desktop work and do nothing for full-screen video, which
damages every row. For video at this resolution the answer stays lever 1 or the
4MP gate.

#### Outcome: copy the damaged rows, and gate on what the copy costs

Both views now copy only the rows their region rects touch, rounded outward to
16. Measured on a Windows host at 2992x1648 (4.93MP), light typing, combining
forced on:

| | no banding | main only | both views |
|---|---|---|---|
| main view copy | 34.6ms | 5.6ms | 7.0ms |
| auxiliary view copy | 27.3ms | 26.9ms | 7.4ms |
| main thread in `copyTo()` | ~77% | ~24% | **~16%** |

The pipeline behind it went with it: `decode` from 617ms at its worst and
28-38ms in steady state to 1.1-3.8ms, `queue` to nil, `draw` from 20-36ms to
7.4-11.7ms.

**Windows declares real damage on both views**; the xrdp fork declares a full
frame on both, deliberately (`xrdp_encoder.c`, to keep the two chroma sources
refreshing from the same instant), so none of this fires there until
`XRDP_AVC444_DAMAGE_RECTS=1` -- and the fork's own comment notes that only
16-aligned rects are bit-exact, which is the shape this wants anyway.

**No per-layout band arithmetic was needed.** Rounding outward to 16 is exactly
what `auxV1LumaBands()` does to reach the v1 layout's 16-row bands, and a
superset of the v2 layout's one-to-one rows and both layouts' chroma rows at
`y >> 1`. `tests/h264-copy-band.mjs` lifts that inverse out of `Yuv444.js` and
checks all three mappings rather than trusting the argument.

**Banding is then exhausted, and the gate had to change.** At 3-5% span the
copies are 0.15-0.25MP but still cost 7-11ms, so the per-call stall now
dominates -- fitted at 5-10ms, well above the 2.7ms a two-point fit suggested.
Narrowing further buys nothing. But that also means cost is no longer a
function of framebuffer area, which is all `COMBINE_MAX_PIXELS` could see: at
4.93MP it declined to combine on sessions costing ~9ms a picture.

So the threshold is now a prior only, raised to 4K, with a measured gate
underneath: a busy window gives up combining when more than
`COMBINE_COPY_TRIP_SHARE` (30%) of wall clock goes inside `copyTo()`.

**Share, not cost per picture.** A mean-per-picture threshold sat beside this
until 2026-09-12 and both had to be exceeded, which vetoed the one case the
gate most needed to catch: xrdp at 1920x1080 dragging a VS Code scrollbar ran
39-47 pictures a second at 12ms each -- 46-60% of the main thread, and drags
that lost the scrollbar thumb -- while the per-picture figure sat under any
sane threshold. Many cheap copies is the shape that hurts, and per picture is
blind to it by construction.

The near-idle desktop the per-picture condition was added to protect (33-38ms
a picture, where the per-call cost rises because part of it is waiting for a
frame to be ready) needs no protecting: it spends 4.6% of the main thread.
Measured shares -- Windows idle 4.6%, Windows typing 17-19%, full-screen video
~45%, xrdp scrolling 46-60%, glxgears 70% -- all fall on the right side of 30%
unaided. And the pathological case per picture would have caught, one enormous
copy against an otherwise idle session, exceeds `SYNC_WAIT_TIMEOUT_MS`, so the
sync-timeout latch takes it.

**This is not the mistake adaptive suspension made.** That design failed
because timing GPU execution needs a `gl.finish()` per picture, stalling the
pipeline the gate exists to protect, so it gated on symptoms instead. None of
that applies to `copyTo()`'s prologue: it is a wall-clock delta across a
synchronous call, exact and free, on a path already paying it. The earlier
reasoning was right about GPU work and this is not GPU work.

The sync-timeout and slow-flush latches stay as the safety net beneath it.
Note their signal is decoder latency, not display cost -- see above -- which
is worth revisiting now that the latency has collapsed.

#### xrdp's damage: measured, and the answer

Windows declares tight region rects; the xrdp fork declared a single
full-frame rect for AVC444 by design until 2026-09-12. Once that was fixed,
the rects arriving still covered 34-99% of rows, with `span` and `damage`
equal, and for a while that was read as xrdp coarsening the damage.

It was not. Each of those captures was mislabelled by what was on the screen:

| the capture was called | what was actually running | damage |
| --- | --- | --- |
| desktop work | glxgears animating a window | 33-34% |
| idle | the tail of a scroll | 98-99% |
| idle desktop, clock ticking | VS Code, maximized | 97-99% |

The last one settles it arithmetically. VS Code was 1920x1047 on a 1920x1072
screen: 97.67%, against a measured mean of 97% and max of 99%. An
Electron/Chromium window repaints its whole surface on any change, a blinking
caret included, so what was called an idle desktop was one application
damaging almost the entire screen a few times a second. Minimising it dropped
declared damage to a few per cent -- across the straddling 100-capture window,
the 66 captures still at ~97% account for the whole 64% mean on their own,
which leaves the other 34 at essentially zero.

So the damage rects are honest and banding works on xrdp. What banding cannot
do is help while one application owns the screen and repaints all of it, and
that is a property of the application rather than of the server.

**`MAX_CAPTURE_RECTS` is not involved, and never was.** The hypothesis was
that sixteen dirty rects -- a caret, a scrollbar, a tray clock, some text --
would trip the extents collapse in `rdpCapRect()` and hand the client a
corner-to-corner bounding box. Instrumenting the server directly (xorgxrdp
`feature/gbm-dmabuf-hwencode`, reported under `XORGXRDP_TIMING`) shows the
branch is never entered:

```
xorgxrdp dirty region: 100 captures, rects mean 1 max 1,
  monitor covered mean 97% max 99%, 100 captures covered 90% or more
xorgxrdp dirty region collapse: fired 0 of 0 multi-rect frames
```

`rects mean 1 max 1`, in every regime measured -- idle, light activity, and
glxgears saturated at 58 fps -- across more than 1200 captures. A caret and a
clock do not produce sixteen rects; they produce one. The collapse needs more
than fifteen and has never seen more than one, so raising the cap, or
switching to the area-ratio rule that now sits behind `XORGXRDP_COLLAPSE=area`,
would change nothing on this pipe.

Coarsening to row bands upstream is not the answer either. It is redundant
with `copyBandsFor()`, which merges using a cost model -- `minWorthwhileGap()`
derived from the measured copy fit and the real plane width -- that xorgxrdp
does not have, and it would give up the horizontal extent the server still
uses in `rdpCopyBoxList()`'s blit and in the v2 auxiliary shader pass. The end
that owns the cost model should do the coarsening.

None of this was visible from either end of the wire. xrdp receives
`REGION_NUM_RECTS()` of the already-collapsed region, so from there a collapse
and a genuine full-screen rect look identical, and the client only ever sees
what xrdp declares. The question stayed open across three captures for want of
an instrument in the one place that could answer it.

A single bounding span in the client is still defeated by a clock in one
corner and a caret in the other, which is why `copyBandsFor()` produces
several.

#### The per-call floor, and a threshold that outlived its calibration

Windows, light typing at 4.93MP, both views banded to 3% of their planes, one
band each (multi-band never fires there -- the rects are tight and
contiguous):

```
  copy    chroma 8.1ms 53.71ms/MP  |  luma 8.8ms 59.02ms/MP
  band    78 main: banded 78 (100%) copied 3% damage 3% in 1.0 bands
          aux 32 views: banded 32 (100%) copied 3% damage 3% in 1.0 bands
```

3% of 4.93MP is 0.148MP, which at 6.5ms/MP is under a millisecond of
transfer. The copies cost 6-18ms. **Banding has reached its limit**: what is
left is per-call, narrowing further buys nothing, and AVC444 pays it twice per
paired picture whatever the damage.

**The per-call cost is not fixed -- it falls as the session gets busier.**
Measured across four windows of one session: 17.5ms at 1.4 pictures a second,
8.5ms at 5.2, and **6.2ms at 20.6**. So part of it is waiting for the decoder
to have a frame ready, which shrinks when frames are already queued, rather
than the transfer or a constant stall. A single window read in isolation will
mislead about it, which the 2.7ms of the original two-point fit and an
intermediate reading of 8-12ms both did in opposite directions.

At steady state that is 8.3ms of copy per picture (103 main views at 6.2ms
plus 33 auxiliary at 6.5ms over 5s), against the 20ms the gate trips at -- so
better than two times headroom -- and 12-17% of the main thread, from ~77% before
any of this.

**And it exposed a stale threshold.** That session suspended combining:

```
gave up 4:4:4 combining: mean flush 11.1ms over 142 syncs in 10s, over the 8ms
```

Copy was ~12ms a picture and well under the share threshold, so the gate
that measures the cost directly correctly held off -- and the flush latch
overrode it. `COMBINE_FLUSH_TRIP_MS` was 8ms, set in September when combining
cost 30-60ms a picture and 4:4:4 flushed at 16-22ms against 4:2:0's 0.6ms.

A flush is the display waiting for the decoder, and under combining that wait
is mostly the copy -- flush is roughly copy + decode + the display's own work.
So **a flush threshold below the copy threshold fires first every time**, by
construction, on a cost the copy gate has already judged affordable and
without being able to say why. It is now derived as
30ms, measured rather than derived. What the
latch is still for is main-thread congestion the copy does not explain, and
for that it has to sit above the copy gate rather than below it.

## Colour range

The samples an RDP host sends are **full range**. [MS-RDPEGFX Color
Conversion](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/954d7546-6873-4466-95c8-20a7569c43e5)
defines the ARGB-to-AYUV transform as full-range BT.709 with the components
clamped to 0...255, and Microsoft's RDP 10 AVC announcement requires decoders
to support "BT.709 Full Range color conversion".

Converting those as limited range expands 16-235 to 0-255: blacks crush to
zero, whites clip, and chroma over-saturates by 255/224. It looks punchier and
is wrong — and it is the more damaging of the two mistakes, since clipping
destroys information that the opposite error merely compresses.

The stream is supposed to prevent that by carrying `video_full_range_flag = 1`
in the SPS. **Chrome honours that flag in every shape but one.** Measured
2026-09-09, and pinned by `tests/h264-vui-range.mjs`:

| `video_full_range_flag` | colour description | `colorSpace.fullRange` | 16,16,16 painted as |
|---|---|---|---|
| 1 | absent | `true` | 15,17,14 |
| 1 | present, 2/2 (unspecified) | **`false`** | **0,1,0** |
| 1 | present, 1/1 (BT.709) | `true` | 14,17,14 |
| 0 | present, 1/1 (BT.709) | `false` | 13,16,13 |

A colour description that is *present* and says *unspecified* makes Chrome
discard the whole `video_signal_type` and fall back to limited BT.709. Leaving
the description out altogether does not.

**That table is software decode, and the hardware path is stricter.** Measured
on one browser against two hosts, both decoding to NV12:

| host | SPS | Chrome reports |
|---|---|---|
| xrdp fork | `full_range=1`, primaries/transfer/matrix all BT.709 | full |
| Windows | `full_range=1`, **no description** | **limited** |

Same client, same hardware decoder; the description is the only difference. So
a bare range flag — which the software decoder honours — is ignored once
D3D11/VAAPI is in the path. That is why Windows renders with crushed blacks
while xrdp does not, and why signalling the range in the fork
(`xrdp_accel_assist_vaapi.c`, `video_signal_type_present_flag` through
`matrix_coefficients`) visibly fixed the colour there.

It is invisible from both ends: the host declared the range, the client reports
limited, and neither can see the disagreement. It also applies to `drawImage()`
as much as to the shader, since both read the same reported colour space, so no
client-side flag can reach the AVC420 path.

### The fix: rustguac completes the SPS

`src/h264_rewrite.rs` completes the SPS's colour signalling, in either of the
two shapes seen in the field: a declared range with no description (Windows), or
no `video_signal_type` at all (stock xrdp, whose x264 defaults omit it). The
first has its description added and its declared range left alone; the second
gets full-range BT.709 written, because that is what the transport defines and
what the encoder actually produced. It fixes both render paths and every
client, including third-party ones, and needs no configuration.

Cheap by construction: the first SPS decides. A stream that already carries a
description, and bounds its reordering (below), is never examined again, so
xrdp and every non-passthrough session pay one check per connection and nothing
after it.

BT.709 is not a guess — MS-RDPEGFX defines the transform as BT.709, and Chrome
already reported `bt709` for these streams, so the value is the one the decoder
was assuming anyway. The splice is verified byte-for-byte against ffmpeg's own
`h264_metadata` bitstream filter performing the same edit
(`the_splice_matches_ffmpegs_own_rewrite`), because a bad bit offset or a
missed emulation-prevention byte does not fail loudly: the picture stops while
both ends look healthy.

Recordings are teed upstream of the rewrite and keep the host's original
stream, which is what a recording should be. Playing back a Windows recording
is subject to the original fault; `?h264FullRange=on` is the lever there.

### Diagnosing it

rustguac reads the first SPS of every passthrough session and logs what it
found, once per session (`src/h264_sps.rs`):

```bash
journalctl -u rustguac --since '5 min ago' | grep 'H.264 colour'
```

```
H.264 colour: video_full_range_flag=1 colour_primaries=2 (unspecified) \
  transfer=2 (unspecified) matrix=1 (BT.709) — UNUSABLE: ...
```

A second line says what the browser made of it, reported by the client:

```
Client diagnostic: full range, BT.709; decoder gave NV12 frames  event=colour_space
```

The two together are the whole picture — the first describes the wire, the
second the render — and a colour fault is a disagreement between them. `NV12`
means hardware decode and `I420` software, which matters because the two honour
different things.

Outcomes and fixes:

* **`NO SIGNAL TYPE`** — the SPS says nothing about colour at all. Stock xrdp
  0.10.6 does this: it passes x264 no VUI parameters, and with `video_format`
  at 5 and no colour description x264 omits the whole block. Its samples are
  full-range BT.709 regardless — xrdp names its own conversion
  `XRDP_yuv444_709fr` — so the browser's fallback to limited crushes the
  blacks. Full-range BT.709 is spliced in.
* **`NO DESCRIPTION`** — rustguac splices one in and logs `splicing a BT.709
  description into the SPS`. The client line should then read `full range`.
  This is the Windows case, and it is confirmed working end to end:

  ```
  H.264 colour: video_full_range_flag=1 colour_primaries=absent ... NO DESCRIPTION: ...
  H.264 colour: splicing a BT.709 description into the SPS ...
  Client diagnostic: full range, BT.709; decoder gave NV12 frames  event=colour_space
  ```
* **`UNUSABLE`** (description present, unspecified) — not rewritten, since
  replacing 2 with 1 would assert a colourimetry the host declined to claim.
  Fix it at the encoder.
* **`full_range=0`, usable** — the host is declaring limited range. If its
  samples are nevertheless full range, as MS-RDPEGFX requires, nothing on the
  wire can be believed and the client has to be told. Set the `h264FullRange`
  key in localStorage: on a live session that is the only form that survives,
  since the client builds `/client/{id}?name=...` itself on every launch and
  relaunch and drops anything added by hand. `?h264FullRange=on` works on the
  recording player, whose URL nothing rewrites. `window.__h264FullRange` is
  read once per decoder generation, behind the same latch as the colour-space
  report, so setting it mid-session does nothing until the decoder is rebuilt.
  The console then logs `(FORCED -- frame reported limited)`.
* **`usable`, and the client reports the matching range** — the colour is
  right, and a picture that still looks wrong is not a range problem.

## Picture reordering: a frozen or white screen from an NVENC host

**Chrome's hardware decoder holds pictures back unless the SPS says it need
not**, and one encoder's defaults say nothing. Chromium's `H264Decoder`
(`UpdateMaxNumReorderFrames()`, `media/gpu/h264_decoder.cc`) takes the reorder
depth from the VUI's `bitstream_restriction` when present, as zero for the
High-family profiles carrying `constraint_set3_flag`, and as the whole DPB
otherwise. It has no shortcut for `pic_order_cnt_type` 2, even though that POC
type is the stream stating that output order is decode order.

NVENC left at its defaults, as the xrdp fork's accel-assist first used it,
writes exactly the shape that falls through: Main profile, `constraint_set1`
only, POC type 2, a VUI with timing info and no restriction. At 2992x1648 and
level 5.0 the DPB is five pictures, so every picture emerged five pictures
late. On an idle desktop that is past the client's 1000ms decode watchdog,
which gives the frame up and discards it when it does arrive -- so nothing was
ever painted, and the session showed guacd's white connect-time fill or froze
on whatever came before. mstsc and ffmpeg decode the same stream without delay,
and the recording decodes perfectly, which is what makes this look like a
rustguac fault.

What gives it away is the timing, not the picture: `frames_abandoned` lines in
the browser console with no decode error beside them, and a recording ffmpeg
decodes cleanly.

**`src/h264_sps.rs` adds the restriction on the way past**
(`declare_no_reordering`), and only where the stream has already guaranteed
the answer: POC type 2 and no `bitstream_restriction`. `max_num_reorder_frames`
is 0 and `max_dec_frame_buffering` is `max_num_ref_frames`, which is what the
fork's VA-API encoder declares; the remaining fields are the values the
standard infers when the block is absent, so they claim nothing new. POC types
0 and 1 are left alone -- reordering is possible there, and declaring
otherwise would be a guess about the host. An SPS with no VUI gets an empty one
carrying only the restriction. `declaring_no_reordering_matches_ffmpegs_reading`
checks both shapes against ffmpeg, field by field. The journal says
`declaring max_num_reorder_frames=0 in the SPS` once per session when it fires.

Encoders can say it themselves -- NVENC's `bitstreamRestrictionFlag` -- and the
edit then finds nothing to do.

## Full Colour (4:4:4)

Each RDP entry has a **Full Colour (4:4:4)** checkbox, off by default. AVC444
is offered either way, for the reasons in the next section; what the checkbox
decides is whether the auxiliary chroma view is used.

- **Off (Standard colour).** The auxiliary view is dropped in transit wherever
  the stream proves it can be spared, and the browser never combines, so even a
  stream the drop refuses paints plain 4:2:0 at the lowest cost available. An
  entry decides from the least evidence that can answer; an ad-hoc session,
  which no entry vouches for, waits for the full sample.
- **On.** The auxiliary view is kept and the browser combines it into 4:4:4,
  which sharpens coloured text. The browser still gives 4:4:4 up when it
  costs too much -- see *When 4:4:4 combining is declined, and when it is given
  up*, above -- and at a HiDPI resolution it commonly does within seconds.

At native resolution on a HiDPI screen Full Colour makes little visible
difference; it is worth turning on for a standard-density display where colour
fringing on text matters.

## Dropping the chroma view in transit

AVC444 sends two pictures per frame: a main view, which is ordinary 4:2:0, and
an auxiliary view carrying the chroma 4:2:0 leaves out. The browser can combine
them into full 4:4:4, but only by reading every decoded frame back from the GPU
with `VideoFrame.copyTo()` -- WebCodecs offers no way to reach a frame's planes
on the GPU -- and that read-back blocks the main thread input is handled on.
It is most of what AVC444 costs a client.

A Windows host cannot simply be asked for AVC420 instead. Its hardware encoder
engages only in AVC444 mode (`AVC444ModePreferred`, above), and FreeRDP
advertises the RDPGFX 10.x capability sets only alongside AVC444: offered
AVC420 alone it offers 8.1, and Windows at 8.1 sent only CLEARCODEC and
CAPROGRESSIVE when tested, no H.264 at all. So the host has to be offered a
picture the client may not want, and at native resolution on a HiDPI screen,
where a 4:2:0 chroma block already covers about one logical pixel, does not
need.

`src/h264_aux_drop.rs` removes the auxiliary view between guacd and the
browser, where the stream proves it can be spared: 13% of the H.264 bytes
against a Windows host and 43% against xrdp sending AVC444, and one decode per
frame instead of two. The browser is told with an `h264-aux` instruction --
rustguac's own, which guacd never sees and an older client ignores -- so it
stops holding main views for a picture that is no longer coming.

**It has to be proved per stream**, because the two views are one H.264
sequence sharing one decoded picture buffer. `src/h264_refs.rs` reads the
slice headers (it never decodes) to establish two things:

- **Nothing that survives predicts from a dropped picture.** The two views must
  keep separate long-term reference chains, and nothing in the main view may
  reorder short-term references relatively, since a removed picture shifts
  every `PicNum` after it.
- **The decoder has room for what the gap obliges it to invent.** Dropping
  leaves holes in `frame_num`, and H.264 8.2.5.2 requires a decoder to fill
  each with an inferred short-term reference. A stream whose
  `max_num_ref_frames` is all taken by long-term pictures has nowhere to put
  one, and freezes.

`gaps_in_frame_num_value_allowed_flag` is set on every SPS from the start of
the session, which is inert on a stream that is never dropped from. The
evidence only arrives with the first inter slices, so the decision takes about
2.5 seconds, almost all of it the connect-time keyframe burst. A stream that
cannot be proved is passed through unchanged and the reason is logged;
auxiliary IDRs are always kept.

The dropper sits after the recording tee, so recordings keep the full stream.
`RUSTGUAC_H264_AUX_DROP=0` switches it off for the whole deployment, and
`RUSTGUAC_H264_AUX_DROP=unproven` relaxes the gate for experiments.

Two harnesses check it against real streams: `tests/aux-drop-replay.mjs
<recording>` strips the auxiliary views from a recording and compares the
decoded pictures with ffmpeg, and `RUSTGUAC_AUX_DROP_RECORDING=<recording>
cargo test aux_drop_over_a_recording -- --ignored` runs the real dropper over
one and checks the result is a stream a client can follow.

## Recording

Session recordings capture the raw stream, so a recording of an H.264 session
contains `h264` instructions and needs the same WebCodecs decoder to play back.
