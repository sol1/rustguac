#!/usr/bin/env node
/*
 * Runs tests/bench/h264-combine-bench.html in headless Chrome and prints the
 * results as a table.
 *
 * Talks to Chrome over the DevTools protocol directly, using the WebSocket and
 * fetch built into Node 22+, so that benchmarking the client needs no
 * node_modules at all -- the alternative, puppeteer, is a browser download and
 * a dependency tree to keep a stopwatch running.
 *
 * Usage: node tests/bench/run.mjs [--headed] [--json out.json]
 */

import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, dirname, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..', '..');

const headed = process.argv.includes('--headed');
const software = process.argv.includes('--software');
const jsonAt = process.argv.includes('--json')
    ? process.argv[process.argv.indexOf('--json') + 1] : null;

const DEBUG_PORT = 9222 + (process.pid % 500);
const HTTP_PORT = 8700 + (process.pid % 500);

/* Served over http://127.0.0.1 rather than opened as a file. WebCodecs is
 * exposed only to secure contexts, and a file:// page is not one -- under
 * file:// VideoDecoder is simply undefined and the benchmark has nothing to
 * decode. Loopback counts as trustworthy, so this is the whole fix. */
const server = createServer(async (req, res) => {
    const path = normalize(join(root, decodeURI(req.url.split('?')[0])));
    if (!path.startsWith(root)) { res.statusCode = 403; return res.end(); }
    try {
        res.setHeader('content-type',
                path.endsWith('.js') ? 'text/javascript' : 'text/html');
        res.end(await readFile(path));
    } catch {
        res.statusCode = 404;
        res.end('not found');
    }
});
await new Promise((r) => server.listen(HTTP_PORT, '127.0.0.1', r));

const url = `http://127.0.0.1:${HTTP_PORT}/tests/bench/h264-combine-bench.html`;

const profile = await mkdtemp(join(tmpdir(), 'rustguac-bench-'));

/* Headless Chrome brings up no GL implementation by default, so WebGL2 is
 * unavailable and the renderer refuses to run at all. ANGLE over EGL reaches
 * the real GPU, which is what these numbers have to be measured on: under
 * SwiftShader the fragment shader dominates everything and scissoring looks
 * far better than it is. --software asks for exactly that comparison. */
const gpuArgs = software
    ? ['--use-gl=angle', '--use-angle=swiftshader']
    : ['--use-gl=angle', '--use-angle=gl-egl'];

/* Asking for VA-API costs nothing where it is unavailable and is the only way
 * to get hardware decode where it is. Whether it took is reported rather than
 * assumed: on this machine Chrome declines it in every combination tried,
 * headless and headed alike, and a benchmark that quietly measured a software
 * decoder while claiming otherwise would be worse than no benchmark. */
const decodeArgs = [
    '--enable-features=VaapiVideoDecodeLinuxGL,VaapiVideoEncodeLinuxGL,'
        + 'AcceleratedVideoDecodeLinuxGL',
    '--disable-features=UseChromeOSDirectVideoDecoder'
];

const args = [
    `--remote-debugging-port=${DEBUG_PORT}`,
    `--user-data-dir=${profile}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-background-timer-throttling',
    '--disable-renderer-backgrounding',
    '--enable-gpu',
    '--ignore-gpu-blocklist',
    ...gpuArgs,
    ...decodeArgs,
    url
];

if (!headed)
    args.unshift('--headless=new');

const chrome = spawn('google-chrome', args, { stdio: ['ignore', 'pipe', 'pipe'] });
let chromeErr = '';
chrome.stderr.on('data', (b) => { chromeErr += b.toString(); });

const cleanup = async () => {
    try { chrome.kill('SIGTERM'); } catch {}
    server.close();
    /* Chrome is still writing its profile out as it exits; one retry is
     * enough and a leftover temp dir is not worth failing the run over. */
    await rm(profile, { recursive: true, force: true, maxRetries: 5 })
            .catch(() => {});
};

process.on('exit', () => { try { chrome.kill('SIGKILL'); } catch {} });

/** Waits for the debugging endpoint to come up. */
async function endpoint() {
    for (let i = 0; i < 100; i++) {
        try {
            const res = await fetch(`http://127.0.0.1:${DEBUG_PORT}/json/list`);
            const targets = await res.json();
            const target = targets.find((t) => t.type === 'page'
                    && t.url.startsWith('http://127.0.0.1'));
            if (target?.webSocketDebuggerUrl) return target.webSocketDebuggerUrl;
        } catch { /* not up yet */ }
        await new Promise((r) => setTimeout(r, 200));
    }
    let seen = '(none)';
    try {
        seen = JSON.stringify(await (await fetch(
                `http://127.0.0.1:${DEBUG_PORT}/json/list`)).json());
    } catch (e) { seen = 'list failed: ' + e.message; }
    throw new Error(`Chrome debugging port never opened.\ntargets: ${seen}\n${chromeErr}`);
}

const ws = new WebSocket(await endpoint());
await new Promise((res, rej) => {
    ws.addEventListener('open', res, { once: true });
    ws.addEventListener('error', rej, { once: true });
});

let nextId = 1;
const pending = new Map();

ws.addEventListener('message', (event) => {
    const msg = JSON.parse(event.data);
    if (msg.id && pending.has(msg.id)) {
        const { resolve: ok, reject: no } = pending.get(msg.id);
        pending.delete(msg.id);
        msg.error ? no(new Error(msg.error.message)) : ok(msg.result);
    }
});

function send(method, params = {}) {
    const id = nextId++;
    ws.send(JSON.stringify({ id, method, params }));
    return new Promise((ok, no) => pending.set(id, { resolve: ok, reject: no }));
}

async function evaluate(expression) {
    const { result, exceptionDetails } = await send('Runtime.evaluate', {
        expression,
        awaitPromise: true,
        returnByValue: true
    });
    if (exceptionDetails)
        throw new Error(exceptionDetails.exception?.description
                ?? exceptionDetails.text);
    return result.value;
}

await send('Runtime.enable');
await send('Log.enable');

/* Surface page-side errors rather than letting them show up as a silent
 * timeout ten minutes later. */
ws.addEventListener('message', (event) => {
    const msg = JSON.parse(event.data);
    if (msg.method === 'Log.entryAdded' && msg.params.entry.level === 'error')
        console.error('  [page] ' + msg.params.entry.text);
});

console.error(`Chrome ${await evaluate('navigator.userAgent')
        .then((ua) => ua.match(/Chrome\/[\d.]+/)?.[0] ?? '?')} — benchmarking…`);

const deadline = Date.now() + 15 * 60 * 1000;
let last = '';

while (!(await evaluate('window.__benchDone === true'))) {

    if (Date.now() > deadline) {
        await cleanup();
        throw new Error('benchmark did not finish within 15 minutes');
    }

    const status = await evaluate(
            'document.getElementById("status")?.textContent ?? ""');
    if (status && status !== last) {
        console.error('  ' + status);
        last = status;
    }

    await new Promise((r) => setTimeout(r, 500));

}

const results = await evaluate('window.__benchResults');
await cleanup();

if (results.error) {
    console.error('\nbenchmark failed: ' + results.error);
    console.error(results.stack);
    process.exit(1);
}

if (jsonAt)
    await writeFile(jsonAt, JSON.stringify(results, null, 2));

/* ---------------- report ---------------- */

console.log('');
console.log('GPU: ' + results.webgl);

for (const [size, info] of Object.entries(results.frames)) {
    console.log(`frames ${size}: ${info.format}`
            + (info.real ? ' from a real VideoDecoder'
                         : ' SYNTHETIC -- read-back understated')
            + (info.note ? `\n  ${info.note}` : ''));
    if (info.real)
        console.log(`  decode: ${info.usedHardware ? 'HARDWARE'
                : 'software'} (hardware ${info.hardwareOffered
                ? 'offered' : 'NOT offered by this browser'})`
                + `, read-back ${info.readBackGBs} GB/s`
                + (info.readBackGBs > 8
                    ? ' — memcpy speed, so the planes are in system memory'
                    : ' — a transfer, so the planes are GPU-resident'));
}

if (results.checks.scissor)
    console.log('scissor check: ' + results.checks.scissor.pixels
            + ' px compared, max channel delta '
            + results.checks.scissor.maxDelta
            + (results.checks.scissor.maxDelta === 0
                ? '  (scissored output is identical inside the rects)' : ''));

if (results.checks.combining)
    console.log('combine check: ' + results.checks.combining.differing + ' of '
            + results.checks.combining.sampled
            + ' sampled pixels differ between the 4:2:0 and 4:4:4 renders'
            + (results.checks.combining.differing > 0
                ? '  (the auxiliary view is being applied)'
                : '  *** THE AUXILIARY VIEW IS NOT BEING APPLIED ***'));

for (const [size, phase] of Object.entries(results.phases)) {
    console.log(`\n${size} — where the time goes, ms per picture`);
    const width = Math.max(...Object.keys(phase).map((k) => k.length));
    for (const [name, ms] of Object.entries(phase))
        console.log('  ' + name.padEnd(width) + '  '
                + String(ms).padStart(8) + ' ms');
}

const groups = new Map();
for (const run of results.runs) {
    const key = `${run.size}  ${run.damage} (${run.coverage}% of screen damaged)`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(run);
}

for (const [key, runs] of groups) {

    console.log('\n' + key);

    const base = runs.find((r) => r.config.startsWith('baseline'));
    const width = Math.max(...runs.map((r) => r.config.length));

    for (const run of runs) {
        const speedup = base && !run.config.startsWith('baseline')
            ? `  ${(base.msPerPicture / run.msPerPicture).toFixed(2)}x` : '';
        console.log('  ' + run.config.padEnd(width)
                + '  ' + String(run.msPerPicture).padStart(8) + ' ms'
                + '  ' + String(run.fps).padStart(5) + ' pic/s'
                + speedup);
    }

}

console.log('');
