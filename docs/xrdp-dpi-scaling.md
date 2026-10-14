# Making xrdp act on the client's DPI scale factor

Notes for a possible xrdp patch. Written against the xrdp tree at
`/home/tim/Repos/xrdp`; line numbers are from that checkout and will drift.

This is **not** required for rustguac. A session script that reads the
framebuffer width and picks a scale factor already works (see "Current
workaround" below). The patch buys exactness — correct scaling for any client,
rather than bucketing by a width threshold — and matters mainly when clients
with different `devicePixelRatio` values connect to the same host.

**The case is stronger than it was.** rustguac now sends the *exact* scaling
percentage rather than one of 100/140/180 (see the caveat below), and xrdp
accepts and stores it. So the number the session wants is already sitting in
`client_info` and nothing reads it — the patch is plumbing, not negotiation.

Note also what the patch cannot do: there is no X11 equivalent of the Windows
mechanism it is named after. Windows acts on `desktopScaleFactor` because the
OS has a system-wide DPI that applications honour; X has no such thing, and
scaling is a toolkit convention applied inside the session (`Xft/DPI` via
XSETTINGS for GTK, its own for Qt). So a session-side hook is unavoidable in
principle. What the patch removes is the *guessing*, not the hook — and if the
export is paired with a change to xrdp's own shipped `startwm.sh`, the hook
stops being something a deployment has to write and maintain.

## What already works

xrdp **parses and validates the scale factors**; it just never uses them.

`libxrdp/libxrdp.c` reads them from the monitor data:

- `:2114` — `in_uint32_le(s, monitor_layout->desktop_scale_factor);` from
  `[MS-RDPBCGR] 2.2.1.3.9.1 TS_MONITOR_ATTRIBUTES`
- `:2217` — the same from `[MS-RDPEDISP] 2.2.2.2.1
  DISPLAYCONTROL_MONITOR_LAYOUT`
- `:1939-1964` — validation: `desktop_scale_factor` must be 100–500,
  `device_scale_factor` must be exactly 100, 140 or 180. If either is out of
  range **both are reset to 100**.
- `:2137` and `:2232` — both values are logged, which makes verification free.

They are stored per-monitor in `struct display_size_description`
(`common/xrdp_client_info.h:46-47`):

```c
unsigned int desktop_scale_factor;
unsigned int device_scale_factor;
```

A grep across `sesman/` and `xrdp/` returns **no consumers**. The values are
parsed, validated, logged, stored, and dropped.

## Verify before building anything

The whole idea depends on the client actually sending monitor attributes. One
log line settles it:

```
grep -i "scale_factor" /var/log/xrdp.log | tail
```

- Non-100 values → the scale is arriving intact; the patch has something to read.
- `100` with a client that should be sending more → nothing is arriving, and
  that is the problem to solve first. The patch would have no input.

## What the patch needs to do

### 1. Carry the value from xrdp to sesexec

This is the bulk of the work. The scale lives in `client_info` inside the
**xrdp** process; the reconnect script is launched by **sesexec**. They
communicate over SCP, and the connect request carries no such field
(`libipm/scp.h:437-442`):

```c
int
scp_send_connect_session_request(struct trans *trans,
                                 const struct guid *guid,
                                 const char *client_ip,
                                 const char *client_name,
                                 unsigned int flags);
```

Adding a field touches:

- `libipm/scp.h` — the prototypes for send and parse
- `libipm/scp.c:532` — `scp_send_connect_session_request()` and its parse
  counterpart
- `xrdp/xrdp_mm.c:374` — the caller, which has `client_info` in reach

This is a **wire-format change to the sesman control protocol**, so xrdp and
sesman must be upgraded together. Worth checking whether libipm's versioning
allows an optional trailing field, which would avoid a hard lockstep.

Use the **primary** monitor's `desktop_scale_factor`. With several monitors at
different scales there is no single right answer, and the primary is what a
session-wide DPI setting should follow.

### 2. Export it to the session scripts

Trivial once the value is there, and the mechanism already exists.

For the **reconnect** script, `sesman/sesexec/ercp_server.c:135-140` builds a
NULL-terminated key/value list that `start_reconnect_script()` walks and
`g_setenv()`s (`sesman/sesexec/session.c:1376-1382`):

```c
const char *vars[] =
{
    "XRDP_CLIENT_IP", g_client_ip,
    "XRDP_CLIENT_NAME", g_client_name,
    NULL // Terminator
};
```

Add `"XRDP_DESKTOP_SCALE_FACTOR", buf` alongside.

For **first connect**, follow `XRDP_START_WIDTH` / `XRDP_START_HEIGHT` at
`sesman/sesexec/session.c:383-386`:

```c
g_snprintf(text, sizeof(text), "%d", sd->params.desktop_scale_factor);
g_setenv_log("XRDP_DESKTOP_SCALE_FACTOR", text, 1);
```

Note the reconnect path matters more than first connect: a session outlives its
clients, and reconnecting from a different machine should re-scale. The
`vars[]` list is per-connection, so it handles that correctly; the session-start
variable is fixed for the session's life.

### 3. What the session script then becomes

```sh
SCALE=${XRDP_DESKTOP_SCALE_FACTOR:-100}
xfconf-query -c xsettings -p /Xft/DPI -s $(( 96 * SCALE / 100 ))
```

Exact, continuous, no width threshold, no polling for the resolution to settle.

Prefer `/Xft/DPI` over `/Gdk/WindowScalingFactor`: the latter takes only
integers, so it cannot express 140% or 180% at all, and overshoots by ~11% when
used to approximate 180%.

### 4. Apply it in xrdp's own startwm.sh

Exporting the variable leaves every deployment writing the same three lines.
Applying it in the `startwm.sh` xrdp ships makes HiDPI work out of the box and
is what turns this from a hook a site maintains into a feature xrdp has — which
is also the version worth proposing upstream, since the guessing it replaces is
guessing every xrdp user is currently doing.

Guard it so it changes nothing for the clients that send no scale: with
`XRDP_DESKTOP_SCALE_FACTOR` unset or 100 the computed DPI is 96, which is the
default already.

## Caveat: FreeRDP transposes the pair

FreeRDP fills the synthesised single-monitor definition with the two factors
swapped (`libfreerdp/core/settings.c`, introduced in `401f81683`, present
through 3.x HEAD):

```c
const UINT32 desktopScaleFactor = get(FreeRDP_DeviceScaleFactor);   /* reads Device */
const UINT32 deviceScaleFactor  = get(FreeRDP_DesktopScaleFactor);  /* reads Desktop */
...
monitor.attributes.desktopScaleFactor = desktopScaleFactor;
monitor.attributes.deviceScaleFactor  = deviceScaleFactor;
```

Any **unequal** pair therefore reaches xrdp backwards, and xrdp's own validation
then rejects it — a desktop factor of 200 lands in `device_scale_factor`, fails
the 100/140/180 check, and both are reset to 100.

Equal values are immune, which is why FreeRDP's own `/scale` accepts only 100,
140 and 180 and sets both at once.

**That is only true of the connection-time core data.** The transposition lives
in FreeRDP's synthesis of a single-monitor definition; the display-control
layout is built directly by the client and passes through untouched. So
`patches/011-rdp-dpi-scaling.patch` now snaps only the core-data pair and sends
the **exact** percentage in the `DISPLAY_CONTROL_MONITOR_LAYOUT` that follows —
`desktopScaleFactor = 200` beside `deviceScaleFactor = 180` on a 2.0 display.

xrdp accepts that pair. Its validation (`libxrdp/libxrdp.c:1888-1914`) requires
`desktop_scale_factor` in 100–500 and `device_scale_factor` in {100, 140, 180},
resetting **both** to 100 if either fails; 200/180 satisfies both. The value is
therefore already stored per-monitor and is exact — a patch reading it gets the
client's true ratio, not a bucketed approximation.

An xrdp patch should still not assume well-formed input from FreeRDP clients
generally: anything arriving over the core-data path from a client that sets the
two settings independently is transposed, and the 100/100 reset above is what
that looks like from inside xrdp.

## Current workaround (no patch)

`/etc/xrdp/reconnectwm.sh` infers the scale from the framebuffer width. Two
things to get right:

**Wait for the resolution to settle.** rustguac renegotiates the display size
up to 4s after connecting (`sendSize` at 800ms, 2s and 4s — a retry sequence,
because the Display Control channel is often not ready for the first attempt).
A fixed `sleep 1` samples a stale mode:

```sh
prev=""
for _ in $(seq 1 20); do
    cur=$(DISPLAY=$DISPLAY xrandr 2>/dev/null | awk '/\*/{print $1; exit}')
    if [ -n "$cur" ] && [ "$cur" = "$prev" ]; then break; fi
    prev=$cur
    sleep 0.5
done
WIDTH=$(echo "$prev" | cut -dx -f1)
```

**Beware shell syntax in the client test.** `if [ echo "$X" | grep -qi ... ]`
is not a valid test — the pipe splits the command, `[` fails with "missing
`]`", and the exit status comes from `grep` reading empty stdin, so the branch
never fires. Use `if echo "$X" | grep -qi ...` or a `case` statement.

Also note that a branch forcing `SCALING_FACTOR=1` for Guacamole clients dates
from when rustguac sent CSS pixels. Once it sends device pixels that branch
suppresses exactly the scaling you want.
