#!/usr/bin/env node
/*
 * Pins the binary blob frame format across the language boundary.
 *
 * The header is written in Rust (`src/binary_blob.rs`) and read in JavaScript
 * (`static/guac/Tunnel.js`), and nothing at build time connects the two. A
 * one-byte disagreement about the header length or the version does not fail
 * loudly: the client drops every frame it cannot recognise, so H.264 and audio
 * simply stop arriving while the session looks healthy from both ends. That is
 * exactly the shape of fault this codebase has spent the most time on, so the
 * constants are lifted out of both sources and compared rather than restated
 * here -- a copy in this file would drift with them.
 *
 * Also exercises Guacamole.ArrayBufferReader's binary branch, since every
 * converted stream reaches the page through it.
 *
 * Usage: node tests/binary-blob-format.mjs
 */

import { readFile } from 'node:fs/promises';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

let failures = 0;
function check(name, fn) {
    try {
        fn();
        console.log(`  ok   ${name}`);
    } catch (e) {
        failures++;
        console.log(`  FAIL ${name}\n       ${e.message}`);
    }
}

/* ── Constants, lifted from each source ──────────────────────────────── */

const rust = await readFile(join(root, 'src/binary_blob.rs'), 'utf8');
const tunnel = await readFile(join(root, 'static/guac/Tunnel.js'), 'utf8');

function rustConst(name) {
    const m = rust.match(new RegExp(`pub const ${name}\\s*:\\s*\\w+\\s*=\\s*(\\d+)`));
    assert.ok(m, `could not find Rust constant ${name} in src/binary_blob.rs`);
    return Number(m[1]);
}

function jsConst(name) {
    const m = tunnel.match(new RegExp(`var ${name}\\s*=\\s*(\\d+)`));
    assert.ok(m, `could not find JS constant ${name} in static/guac/Tunnel.js`);
    return Number(m[1]);
}

console.log('binary blob frame format');

check('header length agrees between Rust and JS', () => {
    assert.equal(rustConst('HEADER_LEN'), jsConst('BINARY_HEADER_LENGTH'));
});

check('frame version agrees between Rust and JS', () => {
    assert.equal(rustConst('FRAME_VERSION'), jsConst('BINARY_FRAME_VERSION'));
});

check('blob frame type agrees between Rust and JS', () => {
    assert.equal(rustConst('FRAME_TYPE_BLOB'), jsConst('BINARY_FRAME_BLOB'));
});

check('header leaves the payload 8-byte aligned', () => {
    // Not cosmetic: the payload is handed straight to a decoder as a typed
    // array, and an unaligned start would force a copy on every blob.
    assert.equal(rustConst('HEADER_LEN') % 8, 0);
});

/* ── The decode the client actually performs ─────────────────────────── */

const HEADER = rustConst('HEADER_LEN');

/* Mirrors Tunnel.js's receiveBinary(). Kept deliberately small: what it must
 * agree with is the Rust writer, and the constants above are what tie them. */
function decode(buffer) {
    if (buffer.byteLength < HEADER) return null;
    const header = new DataView(buffer, 0, HEADER);
    if (header.getUint8(0) !== rustConst('FRAME_VERSION')
            || header.getUint8(1) !== rustConst('FRAME_TYPE_BLOB'))
        return null;
    return { index: header.getUint32(4, true), payload: buffer.slice(HEADER) };
}

/* Mirrors the Rust frame() writer. */
function encode(index, payload) {
    const out = new Uint8Array(HEADER + payload.length);
    out[0] = rustConst('FRAME_VERSION');
    out[1] = rustConst('FRAME_TYPE_BLOB');
    new DataView(out.buffer).setUint32(4, index, true);
    out.set(payload, HEADER);
    return out.buffer;
}

check('a frame round-trips its index and payload', () => {
    const got = decode(encode(0x01020304, new Uint8Array([0xAA, 0xBB, 0xCC])));
    assert.equal(got.index, 0x01020304);
    assert.deepEqual([...new Uint8Array(got.payload)], [0xAA, 0xBB, 0xCC]);
});

check('a high stream index survives as unsigned', () => {
    // Stream indices are u32 in the frame. Reading it signed would turn a
    // large index negative and silently misroute the payload.
    const got = decode(encode(0xFFFFFF01, new Uint8Array([1])));
    assert.equal(got.index, 0xFFFFFF01);
});

check('an unknown version is dropped, not guessed at', () => {
    const buf = encode(1, new Uint8Array([1]));
    new Uint8Array(buf)[0] = 99;
    assert.equal(decode(buf), null);
});

check('a truncated frame is dropped', () => {
    assert.equal(decode(new ArrayBuffer(HEADER - 1)), null);
});

check('an empty payload is legal', () => {
    const got = decode(encode(5, new Uint8Array([])));
    assert.equal(got.index, 5);
    assert.equal(got.payload.byteLength, 0);
});

/* ── ArrayBufferReader accepts both forms ────────────────────────────── */

const Guacamole = {};
globalThis.Guacamole = Guacamole;
globalThis.window = globalThis;
new Function('Guacamole', await readFile(
        join(root, 'static/guac/ArrayBufferReader.js'), 'utf8'))(Guacamole);

function readerFor() {
    const stream = { onblob: null };
    const reader = new Guacamole.ArrayBufferReader(stream);
    const got = [];
    reader.ondata = (buf) => got.push(new Uint8Array(buf));
    return { stream, got };
}

check('ArrayBufferReader passes an ArrayBuffer straight through', () => {
    const { stream, got } = readerFor();
    const payload = new Uint8Array([1, 2, 3]);
    stream.onblob(payload.buffer);
    assert.equal(got.length, 1);
    assert.deepEqual([...got[0]], [1, 2, 3]);
});

check('ArrayBufferReader still decodes base64, for unconverted streams', () => {
    const { stream, got } = readerFor();
    stream.onblob('AQID'); // 0x01 0x02 0x03
    assert.equal(got.length, 1);
    assert.deepEqual([...got[0]], [1, 2, 3]);
});

check('the two forms produce identical bytes', () => {
    const a = readerFor(), b = readerFor();
    a.stream.onblob('AQID');
    b.stream.onblob(new Uint8Array([1, 2, 3]).buffer);
    assert.deepEqual([...a.got[0]], [...b.got[0]]);
});

console.log(failures ? `\n${failures} failure(s)` : '\nall passed');
process.exit(failures ? 1 : 0);
