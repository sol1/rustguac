#!/usr/bin/env node
/*
 * Proves — or disproves — that dropping an AVC444 stream's auxiliary view
 * changes nothing the browser would have painted.
 *
 * The gate in `src/h264_refs.rs` reads the slice headers, and on some hosts
 * they cannot settle it. The xrdp fork is the case: its main slices take the
 * default reference list and activate two entries, so the auxiliary picture
 * sits at index 1 and is reachable. Whether a macroblock actually reaches it
 * is in the slice data, below anything a header parser can see.
 *
 * This answers it from the other end. A recording holds the full 4:4:4 stream
 * — recordings are teed upstream of the dropper for exactly this reason — so:
 *
 *   1. extract the H.264 access units from the recording, with their views,
 *   2. build a second bitstream with the non-IDR auxiliary views removed and
 *      `gaps_in_frame_num_value_allowed_flag` set, the way rustguac does,
 *   3. decode both with ffmpeg, and
 *   4. compare the pictures that came from main views, frame for frame.
 *
 * Identical output means no main picture ever predicted from an auxiliary one,
 * for this capture. That is a real proof about a real stream rather than an
 * argument about what an encoder probably does — and if it differs, the frame
 * it first differs at says exactly where the assumption broke.
 *
 * It cannot prove the negative for all time: another workload could encode a
 * reference this capture never did. Run it on a capture that exercises the
 * host properly — video, dragging, scrolling — not an idle desktop.
 *
 * Usage:
 *   node tests/aux-drop-replay.mjs <recording> [--keep]
 *
 * Needs ffmpeg on PATH. --keep leaves the intermediates for inspection.
 */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const [, , recordingPath, ...flags] = process.argv;
if (!recordingPath) {
    console.error('usage: node tests/aux-drop-replay.mjs <recording> [--keep]');
    process.exit(2);
}
const keep = flags.includes('--keep');

/* ---- the Guacamole wire format, as much of it as this needs ---- */

/**
 * Splits one `LENGTH.VALUE` element off a buffer, returning the value, the
 * offset past the separator, and the separator itself.
 *
 * Read as bytes rather than as a string: a recording is a byte stream whose
 * lengths count UTF-16 code units, and blob payloads are long. Everything this
 * looks at is ASCII.
 */
function element(buf, pos) {
    const dot = buf.indexOf(0x2e /* . */, pos);
    if (dot < 0) return null;
    const len = Number(buf.subarray(pos, dot).toString('latin1'));
    if (!Number.isInteger(len)) return null;
    const start = dot + 1;
    const end = start + len;
    if (end >= buf.length) return null;
    return {
        value: buf.subarray(start, end).toString('latin1'),
        next: end + 1,
        separator: buf[end],
    };
}

/** Every instruction in the recording, as an array of string arguments. */
function* instructions(buf) {
    let pos = 0;
    while (pos < buf.length) {
        const args = [];
        let separator = 0x2c /* , */;
        while (separator === 0x2c) {
            const el = element(buf, pos);
            if (!el) return;
            args.push(el.value);
            pos = el.next;
            separator = el.separator;
        }
        if (separator !== 0x3b /* ; */) return;
        yield args;
    }
}

/* ---- pull the access units out ---- */

const recording = readFileSync(recordingPath);

/** @type {Map<number, {view: number, keyframe: boolean, parts: string[]}>} */
const open = new Map();
/** @type {{view: number, keyframe: boolean, data: Buffer}[]} */
const accessUnits = [];

for (const args of instructions(recording)) {
    const [opcode, ...rest] = args;

    if (opcode === 'h264') {
        // stream, layer, keyframe, x, y, w, h, view, numrects, rects..., paired
        const index = Number(rest[0]);
        open.set(index, {
            view: Number(rest[7] ?? 0),
            keyframe: rest[2] === '1',
            parts: [],
        });
    } else if (opcode === 'blob') {
        const entry = open.get(Number(rest[0]));
        if (entry) entry.parts.push(rest[1]);
    } else if (opcode === 'end') {
        const index = Number(rest[0]);
        const entry = open.get(index);
        if (entry) {
            accessUnits.push({
                view: entry.view,
                keyframe: entry.keyframe,
                data: Buffer.from(entry.parts.join(''), 'base64'),
            });
            open.delete(index);
        }
    }
}

if (accessUnits.length === 0) {
    console.error(`no H.264 access units in ${recordingPath} — is this a `
        + 'recording of a passthrough session?');
    process.exit(2);
}

const auxUnits = accessUnits.filter((au) => au.view !== 0);
if (auxUnits.length === 0) {
    console.error(`${accessUnits.length} access units, none of them auxiliary: `
        + 'this is an AVC420 capture and there is nothing to drop.');
    process.exit(2);
}

/* ---- set gaps_in_frame_num_value_allowed_flag, as rustguac does ---- */

/**
 * The SPS is rewritten here rather than reusing the Rust, because the point is
 * to check what the Rust does against an independent decoder. Sharing the
 * implementation would make the comparison agree with itself.
 *
 * Only the bit is set, in place; exp-Golomb fields before it are walked to
 * find it, and the payload is re-escaped because flipping a bit can create a
 * `00 00 00` or `00 00 01` sequence.
 */
function setGapsFlag(nalPayload) {
    const rbsp = [];
    for (let i = 0; i < nalPayload.length; i++) {
        if (i + 2 < nalPayload.length && nalPayload[i] === 0
                && nalPayload[i + 1] === 0 && nalPayload[i + 2] === 3) {
            rbsp.push(0, 0);
            i += 2;
        } else {
            rbsp.push(nalPayload[i]);
        }
    }

    let bit = 0;
    const readBit = () => (rbsp[bit >> 3] >> (7 - (bit++ & 7))) & 1;
    const readBits = (n) => { let v = 0; for (let i = 0; i < n; i++) v = (v << 1) | readBit(); return v; };
    const ue = () => {
        let zeros = 0;
        while (readBit() === 0 && zeros < 32) zeros++;
        return zeros === 0 ? 0 : (1 << zeros) - 1 + readBits(zeros);
    };
    const se = () => { const k = ue(); return k % 2 === 0 ? -(k / 2) : (k + 1) / 2; };

    const profileIdc = readBits(8);
    readBits(8);
    readBits(8);
    ue();                                   // seq_parameter_set_id

    if ([100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135].includes(profileIdc)) {
        const chromaFormatIdc = ue();
        if (chromaFormatIdc === 3) readBit();
        ue();
        ue();
        readBit();
        if (readBit() === 1) {
            const lists = chromaFormatIdc === 3 ? 12 : 8;
            for (let i = 0; i < lists; i++) {
                if (readBit() === 1) {
                    const size = i < 6 ? 16 : 64;
                    let last = 8, next = 8;
                    for (let j = 0; j < size; j++) {
                        if (next !== 0) next = (last + se() + 256) % 256;
                        if (next !== 0) last = next;
                    }
                }
            }
        }
    }

    ue();                                   // log2_max_frame_num_minus4
    const pocType = ue();
    if (pocType === 0) ue();
    else if (pocType === 1) {
        readBit();
        se();
        se();
        const cycle = ue();
        for (let i = 0; i < cycle; i++) se();
    }
    ue();                                   // max_num_ref_frames

    const gapsBit = bit;
    if ((rbsp[gapsBit >> 3] >> (7 - (gapsBit & 7))) & 1) return null;
    rbsp[gapsBit >> 3] |= 0x80 >> (gapsBit & 7);

    const escaped = [];
    let zeroRun = 0;
    for (const byte of rbsp) {
        if (zeroRun === 2 && byte <= 3) {
            escaped.push(3);
            zeroRun = 0;
        }
        escaped.push(byte);
        zeroRun = byte === 0 ? zeroRun + 1 : 0;
    }
    return Buffer.from(escaped);
}

/** Rewrites every SPS in one Annex B access unit. */
function permitGaps(au) {
    const out = [];
    let i = 0;
    let changed = false;
    while (i < au.length) {
        const isLong = au[i] === 0 && au[i + 1] === 0 && au[i + 2] === 0 && au[i + 3] === 1;
        const isShort = !isLong && au[i] === 0 && au[i + 1] === 0 && au[i + 2] === 1;
        if (!isLong && !isShort) {
            out.push(au[i++]);
            continue;
        }
        const headerAt = i + (isLong ? 4 : 3);
        let end = headerAt + 1;
        while (end + 2 < au.length
                && !(au[end] === 0 && au[end + 1] === 0 && (au[end + 2] === 1
                    || (au[end + 2] === 0 && au[end + 3] === 1)))) {
            end++;
        }
        if (end + 2 >= au.length) end = au.length;

        out.push(...au.subarray(i, headerAt + 1));
        if ((au[headerAt] & 0x1f) === 7) {
            const rewritten = setGapsFlag(au.subarray(headerAt + 1, end));
            if (rewritten) {
                out.push(...rewritten);
                changed = true;
            } else {
                out.push(...au.subarray(headerAt + 1, end));
            }
        } else {
            out.push(...au.subarray(headerAt + 1, end));
        }
        i = end;
    }
    return { data: Buffer.from(out), changed };
}

/* ---- build both bitstreams ---- */

/*
 * Pictures are compared by position, which is only sound where decode order
 * and presentation order agree. Both hosts this exists for are P-only with
 * pic_order_cnt_type 2, where they do. A stream with B slices reorders its
 * output, and comparing positionally there reports differences that are
 * nothing but the reordering -- so refuse rather than mislead.
 */
for (const au of accessUnits) {
    for (let i = 0; i + 4 < au.data.length; i++) {
        const long = au.data[i] === 0 && au.data[i+1] === 0 && au.data[i+2] === 0 && au.data[i+3] === 1;
        const short = !long && au.data[i] === 0 && au.data[i+1] === 0 && au.data[i+2] === 1;
        if (!long && !short) continue;
        const header = au.data[long ? i + 4 : i + 3];
        if ((header & 0x1f) !== 1 && (header & 0x1f) !== 5) continue;

        // slice_type is the second exp-Golomb field of the slice header.
        let bit = 0;
        const payload = au.data.subarray((long ? i + 5 : i + 4));
        const readBit = () => (payload[bit >> 3] >> (7 - (bit++ & 7))) & 1;
        const ue = () => {
            let zeros = 0;
            while (readBit() === 0 && zeros < 32) zeros++;
            if (zeros === 0) return 0;
            let v = 0;
            for (let j = 0; j < zeros; j++) v = (v << 1) | readBit();
            return (1 << zeros) - 1 + v;
        };
        ue();
        if (ue() % 5 === 1) {
            console.error('this capture contains B slices, whose presentation '
                + 'order differs from their decode order. This tool compares '
                + 'pictures by position and would report that reordering as a '
                + 'difference. Not a stream it can judge.');
            process.exit(2);
        }
        break;
    }
}

const dir = mkdtempSync(join(tmpdir(), 'rustguac-aux-replay-'));
const full = join(dir, 'full.264');
const stripped = join(dir, 'stripped.264');

const fullParts = [];
const strippedParts = [];
/** Which output picture index each main view will land at, in each stream. */
let mainCount = 0;
let keptAux = 0;
let droppedAux = 0;
let droppedBytes = 0;
let gapsSet = 0;

for (const au of accessUnits) {
    fullParts.push(au.data);

    if (au.view !== 0 && !au.keyframe) {
        // Exactly what src/h264_aux_drop.rs drops: non-IDR auxiliary views.
        droppedAux++;
        droppedBytes += au.data.length;
        continue;
    }
    if (au.view !== 0) keptAux++;
    else mainCount++;

    const { data, changed } = permitGaps(au.data);
    if (changed) gapsSet++;
    strippedParts.push(data);
}

writeFileSync(full, Buffer.concat(fullParts));
writeFileSync(stripped, Buffer.concat(strippedParts));

/* ---- decode both, and compare only the main pictures ---- */

function decode(path, label) {
    const out = join(dir, `${label}`);
    execFileSync('ffmpeg', [
        '-y', '-v', 'error',
        '-i', path,
        '-f', 'image2', '-pix_fmt', 'yuv420p',
        join(dir, `${label}-%05d.pgm`),
    ], { stdio: ['ignore', 'ignore', 'inherit'] });
    return out;
}

console.log(`recording: ${recordingPath}`);
console.log(`  ${accessUnits.length} access units: ${mainCount} main, `
    + `${auxUnits.length} auxiliary`);
console.log(`  dropped ${droppedAux} auxiliary pictures `
    + `(${(droppedBytes / 1024).toFixed(0)} KiB), kept ${keptAux} auxiliary keyframes`);
console.log(`  gaps_in_frame_num_value_allowed_flag set on ${gapsSet} access units`);

try {
    decode(full, 'full');
    decode(stripped, 'stripped');
} catch (e) {
    console.error('\nffmpeg failed to decode one of the streams. If it is the '
        + 'stripped one, that is itself the answer: the drop broke it.');
    if (!keep) rmSync(dir, { recursive: true, force: true });
    process.exit(1);
}

/*
 * ffmpeg emits one picture per decoded frame, in decode order. The full stream
 * decodes both views, so its main pictures are the ones at the positions where
 * a main view sat; the stripped stream decodes main views plus the auxiliary
 * keyframes that were kept.
 */
const { readdirSync } = await import('node:fs');
const pictures = (label) => readdirSync(dir)
    .filter((f) => f.startsWith(`${label}-`) && f.endsWith('.pgm'))
    .sort();

const fullPics = pictures('full');
const strippedPics = pictures('stripped');

const fullMainAt = [];
accessUnits.forEach((au, i) => { if (au.view === 0) fullMainAt.push(i); });
const strippedMainAt = [];
let k = 0;
for (const au of accessUnits) {
    if (au.view !== 0 && !au.keyframe) continue;
    if (au.view === 0) strippedMainAt.push(k);
    k++;
}

/*
 * Every access unit carries exactly one picture, so a decoder that emits fewer
 * pictures than it was fed could not reconstruct some of them. That is a
 * cleaner answer than any comparison -- and it has to be checked first,
 * because missing pictures also break the positional alignment below and would
 * otherwise surface as a difference at an arbitrary index.
 */
const fullExpected = accessUnits.length;
const strippedExpected = accessUnits.filter(
    (au) => au.view === 0 || au.keyframe).length;

if (fullPics.length !== fullExpected) {
    console.error(`\nthe UNMODIFIED stream decoded ${fullPics.length} pictures `
        + `from ${fullExpected} access units. Something is wrong with this `
        + 'capture or with ffmpeg, not with the drop — no conclusion.');
    if (!keep) rmSync(dir, { recursive: true, force: true });
    process.exit(2);
}

if (strippedPics.length !== strippedExpected) {
    console.error(`\nNOT SAFE: the stripped stream decoded `
        + `${strippedPics.length} pictures from ${strippedExpected} access `
        + `units — ${strippedExpected - strippedPics.length} could not be `
        + 'reconstructed at all, while the unmodified stream decoded every '
        + `one of its ${fullExpected}. Main pictures on this host predict from `
        + 'the auxiliary view.');
    console.error(keep ? `  intermediates in ${dir}` : '  rerun with --keep to inspect');
    if (!keep) rmSync(dir, { recursive: true, force: true });
    process.exit(1);
}

let compared = 0;
let firstDifference = null;

for (let i = 0; i < Math.min(fullMainAt.length, strippedMainAt.length); i++) {
    const a = fullPics[fullMainAt[i]];
    const b = strippedPics[strippedMainAt[i]];
    if (!a || !b) break;

    const left = readFileSync(join(dir, a));
    const right = readFileSync(join(dir, b));
    compared++;
    if (!left.equals(right)) {
        firstDifference = { picture: i, a, b };
        break;
    }
}

console.log(`  decoded ${fullPics.length} / ${strippedPics.length} pictures; `
    + `compared ${compared} main views`);

if (compared === 0) {
    console.error('\nnothing was compared — the decoders produced no pictures '
        + 'this could line up. Treat as a failed run, not a pass.');
    if (!keep) rmSync(dir, { recursive: true, force: true });
    process.exit(1);
}

if (firstDifference) {
    console.error(`\nDIFFERENT at main picture ${firstDifference.picture}: `
        + `${firstDifference.a} vs ${firstDifference.b}`);
    console.error('A main picture predicted from an auxiliary one. The drop is '
        + 'NOT safe on this host.');
    console.error(keep ? `  intermediates in ${dir}` : '  rerun with --keep to inspect');
    if (!keep) rmSync(dir, { recursive: true, force: true });
    process.exit(1);
}

console.log(`\nIDENTICAL across ${compared} main pictures. No main picture in `
    + 'this capture predicted from an auxiliary one, so dropping them changes '
    + 'nothing that gets painted.');
console.log('This proves the capture, not the host: another workload could '
    + 'encode a reference this one never did.');
if (keep) console.log(`  intermediates in ${dir}`);
else rmSync(dir, { recursive: true, force: true });
