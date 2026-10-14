/*
 * The copy bands decide which rows of a decoded frame are pulled out of the
 * GPU, and they have to satisfy three things at once:
 *
 *   - cover every damaged row, or a region is painted from stale pixels;
 *   - land on the 16-row grid, or the auxiliary view's v1 layout reads its
 *     chroma tiles from the wrong place;
 *   - be a superset of the rows the renderer then uploads, which are
 *     computed independently by bandsFor() and auxV1LumaBands() in Yuv444.js
 *     from the same rects.
 *
 * None of those fail loudly. A band one row short uploads a row of the
 * previous picture into the middle of this one, which reads as a faint tear
 * on moving content and as nothing at all on a static desktop. So the
 * functions are lifted out of the real sources rather than copied here, and
 * checked against each other over the shapes a server actually sends.
 */

import { readFileSync } from 'fs';

function lift(file, start) {
    const src = readFileSync(new URL(file, import.meta.url), 'utf8');
    const from = src.indexOf(start);
    if (from < 0)
        throw new Error('cannot find ' + start + ' in ' + file);

    let depth = 0, i = src.indexOf('{', from);
    for (; i < src.length; i++) {
        if (src[i] === '{') depth++;
        else if (src[i] === '}' && --depth === 0) break;
    }
    return src.slice(from, i + 1);
}

const DEC = '../static/guac/H264Decoder.js';
const YUV = '../static/guac/Yuv444.js';

/* Constants come from the sources too, so changing one cannot quietly leave
 * this test checking the old value. */
const consts = {};
for (const [file, names] of [
    [DEC, ['COPY_BAND_ALIGN', 'COPY_BAND_MAX_SPAN', 'COPY_BAND_MAX_RECTS',
           'COPY_BAND_MAX_BANDS', 'COPY_BAND_FIXED_MS', 'COPY_BAND_MS_PER_MP',
           'COPY_BAND_GAP_FACTOR']],
    [YUV, ['BAND_LIMIT', 'MAX_CLIP_RECTS']],
]) {
    const src = readFileSync(new URL(file, import.meta.url), 'utf8');
    for (const n of names) {
        const m = src.match(new RegExp('var ' + n + ' = ([0-9.]+);'));
        if (!m) throw new Error('cannot find ' + n + ' in ' + file);
        consts[n] = Number(m[1]);
    }
}

const align = consts.COPY_BAND_ALIGN;

const scope = {};
new Function('scope', 'override', 'noteBand', ...Object.keys(consts), `
    ${lift(DEC, 'function minWorthwhileGap(planeW)')}
    ${lift(DEC, 'function clipRectsToBand(rects, band)')}
    ${lift(DEC, 'function copyBandsFor(rects, planeH, planeW, isAux)')}
    ${lift(YUV, 'function merge(bands, planeHeight)')}
    ${lift(YUV, 'function bandsFor(rects, shift, planeHeight)')}
    ${lift(YUV, 'function auxV1LumaBands(rects, planeHeight)')}
    Object.assign(scope, { copyBandsFor, clipRectsToBand, minWorthwhileGap,
                           bandsFor, auxV1LumaBands });
`)(scope, () => undefined, () => {}, ...Object.values(consts));

const { copyBandsFor, clipRectsToBand, minWorthwhileGap,
        bandsFor, auxV1LumaBands } = scope;

let failures = 0;
function check(name, ok, detail) {
    console.log((ok ? '  ok   ' : '  FAIL ') + name + (detail ? '  ' + detail : ''));
    if (!ok) failures++;
}

const W = 2992, H = 1648;
const gap = minWorthwhileGap(W);
console.log(`plane ${W}x${H}, minimum worthwhile gap ${gap} rows\n`);

const cases = [
    ['caret',            [{ y: 800, height: 18 }]],
    ['caret + clock',    [{ y: 800, height: 18 }, { y: 1600, height: 24 }]],
    ['three scattered',  [{ y: 8, height: 20 }, { y: 700, height: 20 },
                          { y: 1500, height: 20 }]],
    ['near neighbours',  [{ y: 700, height: 20 }, { y: 760, height: 20 }]],
    ['many small',       Array.from({ length: 12 },
                            (_, i) => ({ y: i * 130 + 5, height: 9 }))],
    ['top edge',         [{ y: 0, height: 5 }]],
    ['bottom edge',      [{ y: 1640, height: 8 }]],
    ['single row',       [{ y: 823, height: 1 }]],
    ['odd origin',       [{ y: 801, height: 17 }]],
    ['whole picture',    [{ y: 0, height: H }]],

    /* A gap wide enough to pay for the second copy it costs. The threshold is
     * derived from COPY_BAND_FIXED_MS and COPY_BAND_MS_PER_MP, and when those
     * were refitted on 2026-09-13 it went from 309 rows to about 1337 -- which
     * took every case above down to a single band, 'caret + clock' included,
     * and left the splitting this file exists to check with nothing exercising
     * it. This is the shape that still splits: the two ends of the screen.
     *
     * It is deliberately expressed against the real threshold rather than a
     * fixed row number, so that it keeps testing what it means to test if the
     * costs are measured again. */
    ['screen ends',      [{ y: 0, height: 16 },
                          { y: H - 16, height: 16 }]],
];

let maxBandsSeen = 0;

for (const [name, rects] of cases) {
    for (const isAux of [false, true]) {

        const label = name + (isAux ? ' [aux]' : '');
        /* Tracked so the run can assert, at the end, that something actually
         * exercised the multi-band path. */
        const bands = copyBandsFor(rects.map(r => ({ x: 0, width: W, ...r })),
                H, W, isAux);

        if (!bands) {
            /* Declining is always safe: the whole frame is copied. */
            check(label + ' (declined, copies whole frame)', true);
            continue;
        }

        if (bands && bands.length > maxBandsSeen) maxBandsSeen = bands.length;

        check(label + ` at most ${consts.COPY_BAND_MAX_BANDS} bands`,
                bands.length <= consts.COPY_BAND_MAX_BANDS,
                `${bands.length}`);

        let rows = 0, prevEnd = -Infinity, ordered = true, gapsOk = true;
        for (const b of bands) {
            check(label + ` band ${align}-aligned`,
                    b.y0 % align === 0 && (b.y0 + b.h) % align === 0
                        || b.y0 + b.h === H,
                    `[${b.y0},${b.y0 + b.h})`);
            if (b.y0 < prevEnd) ordered = false;
            if (prevEnd > -Infinity && b.y0 - prevEnd < gap) gapsOk = false;
            prevEnd = b.y0 + b.h;
            rows += b.h;
        }
        check(label + ' bands ordered and disjoint', ordered);
        check(label + ' gaps worth a second copy', gapsOk);
        check(label + ' inside the plane',
                bands[0].y0 >= 0 && prevEnd <= H);
        check(label + ' under the span limit',
                rows < H * consts.COPY_BAND_MAX_SPAN,
                `${rows} of ${H}`);

        /* Nothing damaged may fall outside every band. This is the one that
         * multi-band makes possible to get wrong. */
        let covered = true;
        for (const r of rects)
            for (let y = r.y; y < r.y + r.height; y++)
                if (!bands.some(b => y >= b.y0 && y < b.y0 + b.h))
                    covered = false;
        check(label + ' covers every damaged row', covered);

        /* And each band must contain the uploads its own clipped rects
         * generate, in all three plane mappings. */
        for (const b of bands) {

            const clipped = clipRectsToBand(
                    rects.map(r => ({ x: 0, width: W, ...r })), b);
            const y0 = b.y0, y1 = b.y0 + b.h;

            check(label + ' clipped rects non-empty', clipped.length > 0);

            for (const [what, got, lo, hi] of [
                ['luma',     bandsFor(clipped, 0, H),               y0, y1],
                ['chroma',   bandsFor(clipped, 1, (H + 1) >> 1),    y0 >> 1, y1 >> 1],
                ['aux v1',   auxV1LumaBands(clipped, H),            y0, y1],
                ['aux v2',   bandsFor(clipped, 0, H),               y0, y1],
            ]) {
                check(label + ` ${what} bands exist`, got !== null);
                check(label + ` ${what} inside [${lo},${hi})`,
                        (got || []).every(x => x.y0 >= lo && x.y1 <= hi),
                        JSON.stringify(got));
            }

        }

    }
}

check('null rects declines', copyBandsFor(null, H, W, false) === null);
check('empty rects declines', copyBandsFor([], H, W, false) === null);

/* The splitting logic is the point of this file, and a threshold change can
 * take it out of reach without failing anything: every case collapses to one
 * band and every assertion still passes. */
check(`multi-band splitting is still reachable (gap ${minWorthwhileGap(W)} rows)`,
        maxBandsSeen > 1, `most bands any case produced: ${maxBandsSeen}`);

console.log(failures ? `\n${failures} FAILED` : '\nall passed');
process.exit(failures ? 1 : 0);
