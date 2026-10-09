#!/usr/bin/env node
/*
 * Pins how Chrome reads an H.264 stream's colour range, which decides whether
 * a passthrough session paints the right picture.
 *
 * MS-RDPEGFX specifies full-range BT.709, so an RDP host's samples span
 * 0-255. Converting them as limited expands 16-235 to 0-255: blacks crush to
 * zero, whites clip, chroma over-saturates by 255/224. The stream is supposed
 * to prevent that by carrying `video_full_range_flag = 1` in its SPS.
 *
 * Chrome honours that flag in every shape but one: a colour description that
 * is *present* and says *unspecified* (`colour_primaries = 2`,
 * `transfer_characteristics = 2`) makes it discard the whole
 * `video_signal_type` and fall back to limited BT.709 -- reporting
 * `fullRange: false` from a stream that plainly says otherwise, and painting
 * it crushed. Leaving the description out altogether does not: the range still
 * carries. Saying less works and saying "unspecified" does not, which is not a
 * distinction anyone would guess at.
 *
 * That is a trap worth a test. It looks from the encoder like the range has
 * been signalled, it looks from the client like the host sent limited, and
 * neither end can see the disagreement.
 *
 * Four streams are built with known SPS contents and decoded through the real
 * WebCodecs decoder, and both what Chrome *reports* and what it *paints* are
 * checked. Requires ffmpeg with libx264 and google-chrome; skips without them.
 *
 * Usage: node tests/h264-vui-range.mjs [--headed]
 */

import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, normalize } from 'node:path';
import assert from 'node:assert/strict';

const headed = process.argv.includes('--headed');

function have(command, args) {
    const probe = spawnSync(command, args, { stdio: 'ignore' });
    return !probe.error && probe.status === 0;
}

if (!have('ffmpeg', ['-version']) || !have('google-chrome', ['--version'])) {
    console.log('SKIP: needs ffmpeg and google-chrome');
    process.exit(0);
}

const work = await mkdtemp(join(tmpdir(), 'rustguac-vui-'));

/* Flat patches rather than a test pattern: the range error is a contrast
 * stretch, so it shows on near-black and near-white and hides in mid-tones,
 * and a flat patch can be sampled without landing on an edge. */
const PATCHES = [
    [16, 16, 16], [8, 8, 8], [128, 128, 128],
    [200, 60, 60], [13, 53, 98], [235, 235, 235]
];

/* A 384x64 BMP, six 64px patches. Written by hand so the test needs no image
 * library and no checked-in binary. */
async function writeSource(path) {
    const w = 384, h = 64, rowBytes = w * 3, pad = (4 - rowBytes % 4) % 4;
    const pixels = Buffer.alloc((rowBytes + pad) * h);
    for (let y = 0; y < h; y++) {
        for (let x = 0; x < w; x++) {
            const [r, g, b] = PATCHES[Math.floor(x / 64)];
            const at = y * (rowBytes + pad) + x * 3;
            pixels[at] = b; pixels[at + 1] = g; pixels[at + 2] = r;
        }
    }
    const header = Buffer.alloc(54);
    header.write('BM', 0);
    header.writeUInt32LE(54 + pixels.length, 2);
    header.writeUInt32LE(54, 10);
    header.writeUInt32LE(40, 14);
    header.writeInt32LE(w, 18);
    header.writeInt32LE(-h, 22);      /* top-down */
    header.writeUInt16LE(1, 26);
    header.writeUInt16LE(24, 28);
    header.writeUInt32LE(pixels.length, 34);
    await writeFile(path, Buffer.concat([header, pixels]));
}

const source = join(work, 'patches.bmp');
await writeSource(source);

/* An AUD at the head of every access unit, so the page can split the stream
 * into chunks without a full NAL parser. */
function encode(name, { range, fullRangeFlag, description }) {
    /* description: 'bt709' writes 1/1/1, 'unspecified' writes 2/2/1, and null
     * leaves colour_description_present_flag at 0. The three are not
     * interchangeable, which is the point. */
    const values = { bt709: [1, 1, 1], unspecified: [2, 2, 1] }[description];
    const metadata = [
        `video_full_range_flag=${fullRangeFlag}`,
        ...(values
            ? [`colour_primaries=${values[0]}`,
               `transfer_characteristics=${values[1]}`,
               `matrix_coefficients=${values[2]}`]
            : []),
        'aud=insert'
    ].join(':');

    const out = join(work, name + '.h264');
    const result = spawnSync('ffmpeg', [
        '-v', 'error', '-y', '-loop', '1', '-i', source,
        '-frames:v', '4', '-c:v', 'libx264', '-profile:v', 'high',
        '-pix_fmt', 'yuv420p', '-qp', '1',
        '-color_range', range,
        '-x264-params', `fullrange=${range === 'pc' ? 'on' : 'off'}`,
        '-bsf:v', `h264_metadata=${metadata}`,
        out
    ], { stdio: 'pipe' });

    assert.equal(result.status, 0,
        `ffmpeg failed for ${name}: ${result.stderr}`);
    return out;
}

/* Full-range samples throughout except the last, described three ways. */
encode('full-unspecified',
    { range: 'pc', fullRangeFlag: 1, description: 'unspecified' });
encode('full-no-description',
    { range: 'pc', fullRangeFlag: 1, description: null });
/* What the xrdp fork writes -- xrdp_accel_assist_vaapi.c. */
encode('full-complete',
    { range: 'pc', fullRangeFlag: 1, description: 'bt709' });
encode('limited-complete',
    { range: 'tv', fullRangeFlag: 0, description: 'bt709' });

/* ---- decode each in Chrome and read back what it painted ---------------- */

const PAGE = `<!doctype html><meta charset="utf-8"><title>vui</title><script>
window.__done = false; window.__results = {};

/* Access units start at an AUD, which is the only NAL type 9 here. */
function accessUnits(buf) {
    var starts = [];
    for (var i = 0; i + 4 < buf.length; ) {
        var t = null, skip = 1;
        if (buf[i] === 0 && buf[i+1] === 0 && buf[i+2] === 0 && buf[i+3] === 1) {
            t = buf[i+4] & 0x1f; skip = 5;
        } else if (buf[i] === 0 && buf[i+1] === 0 && buf[i+2] === 1) {
            t = buf[i+3] & 0x1f; skip = 4;
        }
        if (t === 9) starts.push(i);
        i += skip;
    }
    return starts.length ? starts : [0];
}

async function probe(name) {
    const buf = new Uint8Array(await (await fetch(name + '.h264')).arrayBuffer());
    let got = null, failed = null;
    const dec = new VideoDecoder({
        output: (f) => {
            if (!got) {
                const cs = f.colorSpace;
                const c = new OffscreenCanvas(f.displayWidth, f.displayHeight);
                const ctx = c.getContext('2d', { willReadFrequently: true });
                ctx.drawImage(f, 0, 0);
                got = {
                    fullRange: cs ? cs.fullRange : null,
                    painted: [32, 96, 160, 224, 288, 352].map((x) =>
                        Array.from(ctx.getImageData(x, 32, 1, 1).data).slice(0, 3))
                };
            }
            f.close();
        },
        error: (e) => { failed = e.message; }
    });
    dec.configure({ codec: 'avc1.640015', optimizeForLatency: true });
    const starts = accessUnits(buf);
    dec.decode(new EncodedVideoChunk({ type: 'key', timestamp: 0,
        data: buf.subarray(starts[0], starts.length > 1 ? starts[1] : buf.length) }));
    await Promise.race([
        dec.flush().catch((e) => { failed = failed || e.message; }),
        new Promise((r) => setTimeout(r, 5000))
    ]);
    try { dec.close(); } catch (e) { /* already closed */ }
    return got || { error: failed || 'no frames' };
}

(async () => {
  try {
    for (const n of ['full-unspecified', 'full-no-description',
                     'full-complete', 'limited-complete'])
        window.__results[n] = await probe(n);
  } catch (e) { window.__results.__throw = String(e && e.stack || e); }
  window.__done = true;
})();
</script>`;

await writeFile(join(work, 'vui.html'), PAGE);

const PORT = 8700 + (process.pid % 400);
const DEBUG_PORT = 9200 + (process.pid % 400);

const server = createServer(async (req, res) => {
    const path = normalize(join(work, decodeURI(req.url.split('?')[0])));
    if (!path.startsWith(work)) { res.statusCode = 403; return res.end(); }
    let body;
    try { body = await readFile(path); }
    catch { res.statusCode = 404; return res.end('not found'); }
    /* WebCodecs is exposed only to secure contexts; loopback counts, but the
     * page still has to be served rather than opened as a file. */
    res.writeHead(200, { 'content-type': path.endsWith('.html')
        ? 'text/html; charset=utf-8' : 'application/octet-stream' });
    res.end(body);
});
await new Promise((r) => server.listen(PORT, '127.0.0.1', r));

const profile = await mkdtemp(join(tmpdir(), 'rustguac-vui-profile-'));
const chrome = spawn('google-chrome', [
    ...(headed ? [] : ['--headless=new']),
    `--remote-debugging-port=${DEBUG_PORT}`,
    `--user-data-dir=${profile}`,
    '--no-first-run', '--no-default-browser-check',
    `http://127.0.0.1:${PORT}/vui.html`
], { stdio: ['ignore', 'pipe', 'pipe'] });

let chromeErr = '';
chrome.stderr.on('data', (b) => { chromeErr += b.toString(); });

async function cleanup() {
    try { chrome.kill('SIGTERM'); } catch { /* already gone */ }
    server.close();
    await rm(profile, { recursive: true, force: true, maxRetries: 5 }).catch(() => {});
    await rm(work, { recursive: true, force: true, maxRetries: 5 }).catch(() => {});
}
process.on('exit', () => { try { chrome.kill('SIGKILL'); } catch { /* gone */ } });

async function endpoint() {
    for (let i = 0; i < 100; i++) {
        try {
            const targets = await (await fetch(
                    `http://127.0.0.1:${DEBUG_PORT}/json/list`)).json();
            const target = targets.find((t) => t.type === 'page'
                    && t.url.startsWith('http://127.0.0.1'));
            if (target?.webSocketDebuggerUrl) return target.webSocketDebuggerUrl;
        } catch { /* not up yet */ }
        await new Promise((r) => setTimeout(r, 200));
    }
    throw new Error('Chrome debugging port never opened\n' + chromeErr);
}

const ws = new WebSocket(await endpoint());
await new Promise((ok, no) => {
    ws.addEventListener('open', ok, { once: true });
    ws.addEventListener('error', no, { once: true });
});

let nextId = 1;
const pending = new Map();
ws.addEventListener('message', (event) => {
    const msg = JSON.parse(event.data);
    if (msg.id && pending.has(msg.id)) {
        const { ok, no } = pending.get(msg.id);
        pending.delete(msg.id);
        msg.error ? no(new Error(msg.error.message)) : ok(msg.result);
    }
});

function evaluate(expression) {
    const id = nextId++;
    ws.send(JSON.stringify({ id, method: 'Runtime.evaluate',
        params: { expression, awaitPromise: true, returnByValue: true } }));
    return new Promise((ok, no) => pending.set(id, { ok, no }))
        .then(({ result, exceptionDetails }) => {
            if (exceptionDetails)
                throw new Error(exceptionDetails.exception?.description);
            return result.value;
        });
}

for (let i = 0; i < 160; i++) {
    if (await evaluate('window.__done === true')) break;
    await new Promise((r) => setTimeout(r, 250));
}

const results = await evaluate('window.__results');
await cleanup();

/* ---- assertions --------------------------------------------------------- */

assert.equal(results.__throw, undefined, `page threw: ${results.__throw}`);

for (const name of Object.keys(results))
    assert.equal(results[name].error, undefined,
        `${name}: ${results[name].error}`);

/** How far the darkest patch is from the 16,16,16 it was encoded from. */
const blackError = (r) => Math.abs(r.painted[0][0] - 16);

const unspecified = results['full-unspecified'];
const absent = results['full-no-description'];
const complete = results['full-complete'];
const limited = results['limited-complete'];

assert.equal(complete.fullRange, true,
    'a BT.709 colour description must carry the range through');
assert.ok(blackError(complete) <= 4,
    'full range, BT.709 description: near-black came back '
    + `${complete.painted[0]}, expected about 16,16,16`);

/* The asymmetry: absent is not unspecified. */
assert.equal(absent.fullRange, true,
    'an absent colour description must not void the range flag');
assert.ok(blackError(absent) <= 4,
    `full range, no description: near-black came back ${absent.painted[0]}`);

assert.equal(limited.fullRange, false, 'limited range must be reported as such');
assert.ok(blackError(limited) <= 4,
    `limited range: near-black came back ${limited.painted[0]}`);

/* The trap. If this ever starts passing the range through, the client's
 * assumptions can be relaxed -- but do not assume it silently. */
assert.equal(unspecified.fullRange, false,
    'Chrome is expected to DISCARD video_full_range_flag when the colour '
    + 'description is present and unspecified. If this now reports true, '
    + 'Chrome has changed and docs/rdp-h264.md needs revisiting.');
assert.ok(blackError(unspecified) >= 8,
    'and to paint it crushed, which is the visible half of the same fault; '
    + `near-black came back ${unspecified.painted[0]}`);

const row = (label, r) => console.log('  %s -> reported %s, near-black %s',
    label.padEnd(34), String(r.fullRange).padEnd(5), r.painted[0].join(','));

console.log('h264-vui-range: OK  (source near-black is 16,16,16)');
row('full range, BT.709 description', complete);
row('full range, no description', absent);
row('full range, UNSPECIFIED description', unspecified);
row('limited range, BT.709 description', limited);
