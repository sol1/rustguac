/*
 * Copyright (C) 2025 rustguac contributors
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

var Guacamole = Guacamole || {};

/**
 * Combines the two views of an AVC444 picture into a 4:4:4 image and converts
 * it to RGB, on the GPU.
 *
 * An AVC444 picture arrives as two H.264 access units. The main (luma) view is
 * an ordinary YUV420 picture, displayable on its own. The auxiliary view is not
 * an image at all: its three planes carry the chroma samples that the main
 * view's 4:2:0 subsampling discarded, packed by position. Combining them
 * recovers full-resolution chroma, which matters most for text -- ClearType
 * antialiases glyphs with per-pixel colour fringes, exactly the detail 4:2:0
 * averages away over 2x2 blocks.
 *
 * The unpacking is done in the fragment shader rather than in JavaScript. The
 * layouts are pure address arithmetic, so each output pixel can work out which
 * source sample it needs; doing the same per-pixel work on the CPU would mean
 * several million array writes per frame, far too slow at 1080p and above.
 *
 * Layouts are those of MS-RDPEGFX 3.3.8.3.2, and follow FreeRDP's
 * general_LumaToYUV444(), general_ChromaV1ToYUV444() and
 * general_ChromaV2ToYUV444() in libfreerdp/primitives/prim_YUV.c, which is the
 * reference every RDP server is written against.
 *
 * @constructor
 */
Guacamole.Yuv444Renderer = function Yuv444Renderer() {

    /**
     * Reference to this renderer.
     *
     * @private
     * @type {!Guacamole.Yuv444Renderer}
     */
    var renderer = this;

    /**
     * The canvas the combined image is rendered into.
     *
     * Offscreen rather than an element, so that the finished picture can leave
     * by transferToImageBitmap(). That hands the drawing buffer over whole,
     * where reading it back out of an element means drawImage() into a second
     * canvas -- a full-frame RGBA copy per view, 8MB a picture at 1080p and
     * four times that at 4K, on the main thread.
     *
     * @private
     * @type {!OffscreenCanvas}
     */
    var canvas = (typeof OffscreenCanvas !== 'undefined')
        ? new OffscreenCanvas(1, 1) : null;

    /**
     * The WebGL2 context, or null if WebGL2 is unavailable.
     *
     * @private
     * @type {WebGL2RenderingContext}
     */
    var gl = null;

    try {
        if (!canvas)
            throw new Error('no OffscreenCanvas');

        /* preserveDrawingBuffer is deliberately absent. It exists to keep the
         * buffer readable after a compositing boundary, which is what a
         * drawImage() readback needs and what costs the driver a copy of every
         * frame. transferToImageBitmap() takes the buffer itself, immediately
         * after the draw and with no compositing in between, so the guarantee
         * is not needed and the copy is not paid. */
        gl = canvas.getContext('webgl2', {
            alpha: false,
            antialias: false,
            depth: false,
            stencil: false,
            premultipliedAlpha: false
        });
    } catch (e) {
        gl = null;
    }

    /**
     * Whether this renderer can be used at all. False when the browser has no
     * WebGL2 context to give, or the shaders failed to build; the caller is
     * expected to fall back to drawing the main view alone.
     *
     * @type {!boolean}
     */
    this.supported = !!gl;

    /* A lost context is the failure mode with no error attached: drawArrays()
     * silently does nothing and every frame reads back black, for the rest of
     * the session. Mobile GPUs lose contexts routinely -- backgrounding the
     * tab is enough -- so this has to be watched for rather than assumed away.
     */
    if (gl) {
        canvas.addEventListener('webglcontextlost', function(e) {
            e.preventDefault();
            console.warn('[rustguac] YUV444 WebGL context lost;'
                    + ' falling back to 4:2:0');
            renderer.supported = false;
        });
    }

    /**
     * The picture's dimensions, in pixels.
     *
     * @private
     */
    var width = 0;
    var height = 0;

    /**
     * Dimensions of the auxiliary view's luma plane. The v1 layout pads it to
     * a multiple of 16 rows, so it is not always the picture's height, and the
     * shader has to know where the real data ends.
     *
     * @private
     */
    var auxWidth = 0;
    var auxHeight = 0;

    /**
     * Whether each view's chroma arrived interleaved (NV12) rather than as two
     * planes (I420). Set by the upload functions, since only they see the
     * shape of what they were given.
     *
     * @private
     */
    var lumaInterleaved = false;
    var auxInterleaved = false;

    /* ==================== Shaders ==================== */

    var VERTEX_SHADER = [
        '#version 300 es',

        /* A single triangle large enough to cover the viewport. Cheaper than a
         * quad and needs no vertex buffer at all -- the positions come from
         * gl_VertexID. */
        'void main() {',
        '    vec2 p = vec2(float((gl_VertexID << 1) & 2), float(gl_VertexID & 2));',
        '    gl_Position = vec4(p * 2.0 - 1.0, 0.0, 1.0);',
        '}'
    ].join('\n');

    var FRAGMENT_SHADER = [
        '#version 300 es',
        'precision highp float;',
        'precision highp int;',
        'precision highp sampler2D;',

        'uniform sampler2D uLumaY;',
        'uniform sampler2D uLumaU;',
        'uniform sampler2D uLumaV;',
        'uniform sampler2D uAuxY;',
        'uniform sampler2D uAuxU;',
        'uniform sampler2D uAuxV;',

        'uniform ivec2 uSize;',    /* picture dimensions */
        'uniform ivec2 uAuxSize;', /* auxiliary luma plane dimensions */
        'uniform int uLayout;',    /* 0 = 4:2:0 only, 1 = chroma v1, 2 = chroma v2 */
        'uniform int uInterleaved;',/* bit 0: main view is NV12, bit 1: auxiliary is */
        'uniform float uFilter;',  /* recovery threshold, or 0 to leave the mean alone */
        'uniform vec2 uRange;',    /* luma offset, luma scale */
        'uniform float uCScale;',  /* chroma scale */
        'uniform vec4 uCoef;',     /* R:v, G:u, G:v, B:u */

        'out vec4 fragColor;',

        'float fetch(sampler2D s, int x, int y) {',
        '    return texelFetch(s, ivec2(x, y), 0).r;',
        '}',

        /**
         * One sample of a view's V plane, wherever the decoder happened to put
         * it. A hardware decoder generally produces NV12, whose chroma is a
         * single plane of interleaved pairs; that plane is uploaded as a
         * two-channel texture in the U slot, so V is its second channel and
         * the V slot is unused. A software decoder produces I420, with the
         * two planes separate. Converting between them is not an option --
         * VideoFrame.copyTo() refuses that particular conversion -- so both
         * are addressed here instead.
         */
        'float fetchV(sampler2D su, sampler2D sv, int inter, int x, int y) {',
        '    if (inter != 0) return texelFetch(su, ivec2(x, y), 0).g;',
        '    return texelFetch(sv, ivec2(x, y), 0).r;',
        '}',

        /**
         * Chroma for one pixel, as the combination rules of the negotiated
         * layout place it. Written as a function because the reverse filter in
         * main() needs the same lookup for three neighbouring pixels.
         */
        'void chromaAt(int x, int y, out float U, out float V) {',

        /* The luma pass replicates each 4:2:0 chroma sample across its 2x2
         * block, so every pixel starts with a value even where the auxiliary
         * view carries none. */
        '    U = fetch(uLumaU, x >> 1, y >> 1);',
        '    V = fetchV(uLumaU, uLumaV, uInterleaved & 1, x >> 1, y >> 1);',

        '    int halfW = uSize.x >> 1;',
        '    int quarterW = uSize.x >> 2;',

        '    if (uLayout == 2) {',

        /*  v2 -- B4/B5: every row, odd columns, taken from the auxiliary luma
         *  plane, whose left half holds U and right half V. */
        '        if ((x & 1) == 1) {',
        '            int k = x >> 1;',
        '            U = fetch(uAuxY, k, y);',
        '            V = fetch(uAuxY, k + halfW, y);',
        '        }',

        /*  v2 -- B6..B9: odd rows, even columns. Columns at 4k come from the
         *  auxiliary U plane and those at 4k+2 from its V plane, each again
         *  split left/right into U and V. Even rows keep the 4:2:0 value. */
        '        else if ((y & 1) == 1) {',
        '            int ay = y >> 1;',
        '            if ((x & 3) == 0) {',
        '                int k = x >> 2;',
        '                U = fetch(uAuxU, k, ay);',
        '                V = fetch(uAuxU, k + quarterW, ay);',
        '            }',
        '            else {',
        '                int k = (x - 2) >> 2;',
        '                U = fetchV(uAuxU, uAuxV, uInterleaved & 2, k, ay);',
        '                V = fetchV(uAuxU, uAuxV, uInterleaved & 2, k + quarterW, ay);',
        '            }',
        '        }',
        '    }',

        '    else if (uLayout == 1) {',

        /*  v1 -- B4/B5: odd output rows are whole rows of the auxiliary luma
         *  plane. Which one is not a simple doubling: the encoder writes them
         *  in bands of 16, the first 8 rows of each band feeding U and the
         *  second 8 feeding V, counted continuously across the padded plane.
         *  Inverting that gives band = i >> 3, offset = i & 7. */
        '        if ((y & 1) == 1) {',
        '            int i = y >> 1;',
        '            int band = i >> 3;',
        '            int off = i & 7;',
        '            int uRow = band * 16 + off;',
        '            int vRow = uRow + 8;',
        '            if (uRow < uAuxSize.y) U = fetch(uAuxY, x, uRow);',
        '            if (vRow < uAuxSize.y) V = fetch(uAuxY, x, vRow);',
        '        }',

        /*  v1 -- B6/B7: even rows, odd columns, straight from the auxiliary
         *  chroma planes. */
        '        else if ((x & 1) == 1) {',
        '            U = fetch(uAuxU, x >> 1, y >> 1);',
        '            V = fetchV(uAuxU, uAuxV, uInterleaved & 2, x >> 1, y >> 1);',
        '        }',
        '    }',
        '}',

        /**
         * The reverse of the encoder's chroma filter, for the one sample per
         * 2x2 block that no auxiliary view carries.
         *
         * The main view's value at that position is not a subsample of the
         * 4:4:4 source but the mean of the block, so the sample belonging to
         * the pixel itself has to be solved for from the mean and the three
         * neighbours the auxiliary view did carry:
         *
         *     u0 = 4 * mean - u1 - u2 - u3
         *
         * uFilter guards the multiplication. Scaling the mean by four scales
         * its quantisation error by four as well, so a difference too small to
         * be a real chroma edge is discarded in favour of the unfiltered
         * value. This mirrors CONDITIONAL_CLIP in FreeRDP's prim_internal.h,
         * whose threshold of 30/255 is where the caller's default comes from.
         */
        'float unfilter(float mean, float sum3) {',
        '    float recovered = clamp(4.0 * mean - sum3, 0.0, 1.0);',
        '    if (abs(recovered - mean) < uFilter) return mean;',
        '    return recovered;',
        '}',

        'void main() {',

        /* gl_FragCoord is bottom-up; the picture is top-down. */
        '    int x = int(gl_FragCoord.x);',
        '    int y = uSize.y - 1 - int(gl_FragCoord.y);',

        '    float Y = fetch(uLumaY, x, y);',

        '    float U, V;',
        '    chromaAt(x, y, U, V);',

        /* Even column of an even row is the one position in each 2x2 block
         * that stayed at the main view's averaged value. Both layouts leave
         * exactly that position untouched, and in both the other three are
         * real samples, so the inversion is well posed either way.
         *
         * Skipped when no auxiliary view has been combined: with all four
         * values equal the expression collapses to an identity, and the three
         * extra fetches would buy nothing. Skipped at the right and bottom
         * edges for the same reason -- the neighbours are outside the picture,
         * and CLAMP_TO_EDGE would feed the arithmetic duplicates. */
        '    if (uFilter >= 0.0 && uLayout != 0',
        '            && (x & 1) == 0 && (y & 1) == 0',
        '            && x + 1 < uSize.x && y + 1 < uSize.y) {',

        '        float uR, vR, uD, vD, uRD, vRD;',
        '        chromaAt(x + 1, y,     uR,  vR);',
        '        chromaAt(x,     y + 1, uD,  vD);',
        '        chromaAt(x + 1, y + 1, uRD, vRD);',

        '        U = unfilter(U, uR + uD + uRD);',
        '        V = unfilter(V, vR + vD + vRD);',
        '    }',

        /* YUV to RGB, with the matrix and range the decoder reported for
         * this stream rather than an assumed pair.
         *
         * This matters because the 4:2:0 path does not come through here: the
         * browser draws that VideoFrame itself and applies the frame's own
         * colour space, including the limited-range expansion of 16-235 to
         * 0-255. Converting here as though the same samples were full range
         * leaves blacks at 16 and whites at 235, so the combined 4:4:4 picture
         * renders visibly flatter than the 4:2:0 one beside it -- the same
         * session, two different colours, depending only on which codec the
         * server happened to choose. setColorSpace() supplies these. */
        '    float luma = (Y - uRange.x) * uRange.y;',
        '    float u = (U - 0.50196078) * uCScale;',  /* 128/255 */
        '    float v = (V - 0.50196078) * uCScale;',

        '    vec3 rgb = vec3(',
        '        luma + uCoef.x * v,',
        '        luma - uCoef.y * u - uCoef.z * v,',
        '        luma + uCoef.w * u);',

        '    fragColor = vec4(clamp(rgb, 0.0, 1.0), 1.0);',
        '}'
    ].join('\n');

    /* ==================== Program setup ==================== */

    /**
     * Compiles one shader, returning null and logging on failure.
     *
     * @private
     */
    function compile(type, source) {

        var shader = gl.createShader(type);
        gl.shaderSource(shader, source);
        gl.compileShader(shader);

        if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
            console.error('[rustguac] YUV444 shader failed to compile:',
                    gl.getShaderInfoLog(shader));
            gl.deleteShader(shader);
            return null;
        }

        return shader;

    }

    var program = null;
    var uniforms = {};
    var textures = {};

    /**
     * Names of the six plane textures, in the order their texture units are
     * assigned.
     *
     * @private
     * @constant
     */
    var PLANES = ['uLumaY', 'uLumaU', 'uLumaV', 'uAuxY', 'uAuxU', 'uAuxV'];

    /**
     * The most regions worth converting one draw call at a time. Past this,
     * the scissored draws cost more than they save and the whole picture is
     * converted in one -- scattered rects cover most of the screen between
     * them long before the call overhead matters, so the threshold is not a
     * sensitive one.
     *
     * @private
     * @constant
     * @type {!number}
     */
    var MAX_CLIP_RECTS = 32;

    if (gl) {

        var vs = compile(gl.VERTEX_SHADER, VERTEX_SHADER);
        var fs = compile(gl.FRAGMENT_SHADER, FRAGMENT_SHADER);

        if (!vs || !fs)
            this.supported = false;

        else {

            program = gl.createProgram();
            gl.attachShader(program, vs);
            gl.attachShader(program, fs);
            gl.linkProgram(program);

            if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
                console.error('[rustguac] YUV444 program failed to link:',
                        gl.getProgramInfoLog(program));
                this.supported = false;
            }

            else {

                gl.useProgram(program);

                uniforms.size = gl.getUniformLocation(program, 'uSize');
                uniforms.auxSize = gl.getUniformLocation(program, 'uAuxSize');
                uniforms.layout = gl.getUniformLocation(program, 'uLayout');
                uniforms.filter = gl.getUniformLocation(program, 'uFilter');
                uniforms.range = gl.getUniformLocation(program, 'uRange');
                uniforms.cScale = gl.getUniformLocation(program, 'uCScale');
                uniforms.coef = gl.getUniformLocation(program, 'uCoef');
                uniforms.interleaved = gl.getUniformLocation(program,
                        'uInterleaved');

                /* One texture per plane, each on its own unit and bound once.
                 * Nearest filtering throughout: these are data planes, and
                 * interpolating between packed chroma samples would blend
                 * values that are not neighbours in the image at all. */
                for (var i = 0; i < PLANES.length; i++) {

                    var texture = gl.createTexture();
                    gl.activeTexture(gl.TEXTURE0 + i);
                    gl.bindTexture(gl.TEXTURE_2D, texture);
                    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
                    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
                    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
                    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);

                    gl.uniform1i(gl.getUniformLocation(program, PLANES[i]), i);
                    textures[PLANES[i]] = {
                        texture: texture,
                        unit: i,
                        w: 0,
                        h: 0,
                        channels: 0
                    };

                }

                gl.pixelStorei(gl.UNPACK_ALIGNMENT, 1);

            }

        }

    }

    /* ==================== Uploading ==================== */

    /**
     * The fraction of a plane's rows past which uploading bands is not worth
     * it: the rows saved no longer pay for the extra calls and the partial
     * texture updates they cause.
     *
     * @private
     * @constant
     */
    var BAND_LIMIT = 0.75;

    /**
     * Turns a damage list into the row ranges of a plane it touches, merged
     * and in order, or null to upload the plane whole.
     *
     * Rows, not rectangles: a plane's rows are contiguous in memory, so a row
     * range is one texSubImage2D against one run of bytes, while a rectangle
     * would be a call per row. The packed chroma layouts rule out cropping
     * horizontally in any case -- both halves of an auxiliary row carry
     * different components of the same output pixels.
     *
     * @private
     *
     * @param {Array} rects
     *     The damaged regions, in picture coordinates.
     *
     * @param {!number} shift
     *     How many times to halve a picture row to reach a plane row: 0 for a
     *     full-resolution plane, 1 for a chroma plane. Ranges are rounded
     *     outward, so a rect starting on an odd row still brings in the chroma
     *     row it shares with the row above.
     *
     * @param {!number} planeHeight
     *     The plane's height, in its own rows.
     *
     * @returns {Array}
     *     The row ranges, or null if the whole plane should be uploaded.
     */
    function bandsFor(rects, shift, planeHeight) {

        if (!rects || !rects.length || rects.length > MAX_CLIP_RECTS)
            return null;

        var round = (1 << shift) - 1;
        var bands = [];

        for (var i = 0; i < rects.length; i++) {

            var y0 = Math.max(0, (rects[i].y | 0)) >> shift;
            var y1 = Math.min(planeHeight << shift,
                    (rects[i].y | 0) + (rects[i].height | 0) + round) >> shift;

            if (y1 > y0)
                bands.push({ y0: y0, y1: Math.min(planeHeight, y1) });

        }

        return merge(bands, planeHeight);

    }

    /**
     * Sorts row ranges and joins those that touch, so that overlapping rects --
     * a caret inside the line it sits on, say -- do not upload the same rows
     * twice. Returns null when the ranges cover so much of the plane that
     * uploading it whole is the cheaper call.
     *
     * @private
     */
    function merge(bands, planeHeight) {

        if (!bands.length)
            return null;

        bands.sort(function(a, b) { return a.y0 - b.y0; });

        var merged = [bands[0]];
        var rows = 0;

        for (var i = 1; i < bands.length; i++) {
            var last = merged[merged.length - 1];
            if (bands[i].y0 <= last.y1)
                last.y1 = Math.max(last.y1, bands[i].y1);
            else
                merged.push(bands[i]);
        }

        for (var m = 0; m < merged.length; m++)
            rows += merged[m].y1 - merged[m].y0;

        return (rows >= planeHeight * BAND_LIMIT) ? null : merged;

    }

    /**
     * The rows of a v1 auxiliary luma plane that a damage list touches.
     *
     * The v1 layout does not put output row y at plane row y. Odd output rows
     * are whole rows of this plane, written in bands of 16 -- the first 8 rows
     * of each band feeding U and the second 8 feeding V, counted continuously
     * across the padded plane, which is what main() inverts as
     * band * 16 + off. Rounding each range out to whole 16-row bands is the
     * cheap way to be certain every row the shader will read has been
     * uploaded; the alternative is two ranges per rect for no useful saving.
     *
     * @private
     */
    function auxV1LumaBands(rects, planeHeight) {

        if (!rects || !rects.length || rects.length > MAX_CLIP_RECTS)
            return null;

        var bands = [];

        for (var i = 0; i < rects.length; i++) {

            var i0 = Math.max(0, rects[i].y | 0) >> 1;
            var i1 = ((rects[i].y | 0) + (rects[i].height | 0) + 1) >> 1;
            if (i1 <= i0) i1 = i0 + 1;

            bands.push({
                y0: (i0 >> 3) * 16,
                y1: Math.min(planeHeight, (((i1 - 1) >> 3) + 1) * 16)
            });

        }

        return merge(bands, planeHeight);

    }

    /**
     * Uploads one plane into its texture, reallocating only when the plane's
     * dimensions change.
     *
     * @private
     * @param {!string} name - Which plane, one of PLANES.
     * @param {!Uint8Array} data - The plane's bytes, starting at its first row.
     * @param {!number} stride - Bytes per row within data.
     * @param {!number} w - Plane width, in samples.
     * @param {!number} h - Plane height, in samples.
     * @param {number} [channels=1] - Samples per texel: 1 for an ordinary
     *                                plane, 2 for an interleaved NV12 chroma
     *                                plane, whose pairs become RG texels.
     * @param {Array} [bands] - The row ranges to upload, or null for all of
     *                          them. Ignored on the first upload into a
     *                          texture, and whenever the texture has just been
     *                          reallocated: the rows outside the bands are
     *                          meant to still hold the previous picture's, and
     *                          a fresh texture holds nothing.
     * @param {number} [srcY0=0] - The plane row `data` begins at. Non-zero
     *                             when the caller copied only part of the
     *                             plane out of the frame, which is the
     *                             expensive half of this pipeline -- see
     *                             uploadLuma().
     */
    function uploadPlane(name, data, stride, w, h, channels, bands, srcY0) {

        srcY0 = srcY0 || 0;

        channels = channels || 1;

        var internal = (channels === 2) ? gl.RG8 : gl.R8;
        var format = (channels === 2) ? gl.RG : gl.RED;

        var slot = textures[name];
        gl.activeTexture(gl.TEXTURE0 + slot.unit);
        gl.bindTexture(gl.TEXTURE_2D, slot.texture);

        /* Rows are addressed through UNPACK_ROW_LENGTH rather than by copying
         * the plane out, so a padded stride costs nothing. It counts texels
         * rather than bytes, so an interleaved plane's byte stride halves. */
        gl.pixelStorei(gl.UNPACK_ROW_LENGTH, (stride / channels) | 0);

        if (slot.w !== w || slot.h !== h || slot.channels !== channels) {
            /* Callers with partial data are refused before any upload begins
             * -- see canUploadPartial() -- so reaching here means data spans
             * the whole plane. */
            gl.texImage2D(gl.TEXTURE_2D, 0, internal, w, h, 0,
                    format, gl.UNSIGNED_BYTE, data);
            slot.w = w;
            slot.h = h;
            slot.channels = channels;
        }

        /* Only the damaged rows. The rest of the texture still holds the
         * previous picture's, which is what the server said is still valid --
         * the same argument that lets the caller repaint only those regions.
         * srcOffset is in elements of the view handed in, which starts at the
         * plane, so a row range is one call against one run of bytes. */
        else if (bands) {
            for (var i = 0; i < bands.length; i++) {
                var rows = bands[i].y1 - bands[i].y0;
                if (rows > 0)
                    gl.texSubImage2D(gl.TEXTURE_2D, 0, 0, bands[i].y0, w, rows,
                            format, gl.UNSIGNED_BYTE, data,
                            (bands[i].y0 - srcY0) * stride);
            }
        }

        else
            gl.texSubImage2D(gl.TEXTURE_2D, 0, 0, 0, w, h,
                    format, gl.UNSIGNED_BYTE, data);

        gl.pixelStorei(gl.UNPACK_ROW_LENGTH, 0);

    }

    /**
     * Whether a texture is already allocated at the given shape, and so can
     * take rows without being reallocated from data that does not span it.
     *
     * @private
     */
    function allocatedAt(name, w, h, channels) {
        var slot = textures[name];
        return !!slot && slot.w === w && slot.h === h
                && slot.channels === channels;
    }

    /**
     * Uploads the main view of a picture: an ordinary YUV420 frame.
     *
     * @param {!Uint8Array} y - The luma plane.
     * @param {!Uint8Array} u - The U plane, at half resolution in both axes,
     *                           or the interleaved UV plane if v is null.
     * @param {Uint8Array} v - The V plane, or null if the chroma is
     *                         interleaved into u (NV12).
     * @param {!number[]} strides - Bytes per row for [y, u, v].
     * @param {!number} w - Picture width.
     * @param {!number} h - Picture height.
     * @param {number} [copyY0] - The plane row the caller's buffer begins
     *                              at, when it copied only part of the frame
     *                              out. Absent means whole planes.
     * @param {Array} [rects] - The regions this view updates, in picture
     *                          coordinates. Only the rows they touch are
     *                          uploaded; omit, or pass null, to upload the
     *                          whole picture.
     */
    this.uploadLuma = function uploadLuma(y, u, v, strides, w, h, rects,
            copyY0) {

        if (!renderer.supported)
            return false;

        if (width !== w || height !== h) {
            width = w;
            height = h;
            canvas.width = w;
            canvas.height = h;
        }

        var halfW = (w + 1) >> 1;
        var halfH = (h + 1) >> 1;

        lumaInterleaved = !v;

        var lumaBands = bandsFor(rects, 0, h);
        var chromaBands = bandsFor(rects, 1, halfH);

        /* A partial copy can only ever add rows to textures that already
         * exist at this shape: there is nothing to initialise the rows it does
         * not carry with, and texImage2D from a short buffer is a GL error at
         * best and a torn picture at worst. Checked for every plane before any
         * of them is written, so a refusal leaves the textures exactly as they
         * were and the caller can resync rather than repair.
         *
         * The same applies to the bands: without them there is no destination
         * row to write partial data at. */
        var partial = (typeof copyY0 === 'number');

        if (partial && (!lumaBands || !chromaBands
                || !allocatedAt('uLumaY', w, h, 1)
                || (lumaInterleaved
                    ? !allocatedAt('uLumaU', halfW, halfH, 2)
                    : (!allocatedAt('uLumaU', halfW, halfH, 1)
                        || !allocatedAt('uLumaV', halfW, halfH, 1)))))
            return false;

        /* Chroma is subsampled vertically, so a luma row origin is a chroma
         * row origin halved. The caller rounds the copy to even rows so this
         * cannot land between two. */
        var lumaY0 = partial ? copyY0 : 0;
        var chromaY0 = partial ? (copyY0 >> 1) : 0;

        uploadPlane('uLumaY', y, strides[0], w, h, 1, lumaBands, lumaY0);

        if (lumaInterleaved)
            uploadPlane('uLumaU', u, strides[1], halfW, halfH, 2, chromaBands,
                    chromaY0);
        else {
            uploadPlane('uLumaU', u, strides[1], halfW, halfH, 1, chromaBands,
                    chromaY0);
            uploadPlane('uLumaV', v, strides[2], halfW, halfH, 1, chromaBands,
                    chromaY0);
        }

        return true;

    };

    /**
     * Uploads the auxiliary view of a picture. Its planes are not an image;
     * how they map onto the output is the shader's business.
     *
     * @param {!Uint8Array} y - The auxiliary luma plane.
     * @param {!Uint8Array} u - The auxiliary U plane, or the interleaved UV
     *                           plane if v is null.
     * @param {Uint8Array} v - The auxiliary V plane, or null if interleaved.
     * @param {!number[]} strides - Bytes per row for [y, u, v].
     * @param {!number} w - Auxiliary frame width.
     * @param {!number} h - Auxiliary frame height, which the v1 layout pads to
     *                      a multiple of 16 and so may exceed the picture's.
     * @param {number} [layout] - Which chroma layout this view is in, 1 or 2.
     *                            Required to upload less than the whole plane:
     *                            the two layouts put an output row in
     *                            different places, so which plane rows a
     *                            region touches depends on it.
     * @param {Array} [rects] - The regions this view updates, in picture
     *                          coordinates, or null for the whole picture.
     * @param {number} [copyY0] - The plane row the caller's buffer begins at,
     *                            when it copied only part of the frame out.
     *                            Absent means whole planes.
     * @returns {!boolean} False if the planes could not be uploaded from a
     *                     partial buffer, in which case nothing was written.
     */
    this.uploadAux = function uploadAux(y, u, v, strides, w, h, layout, rects,
            copyY0) {

        if (!renderer.supported)
            return false;

        auxWidth = w;
        auxHeight = h;

        var halfW = (w + 1) >> 1;
        var halfH = (h + 1) >> 1;

        auxInterleaved = !v;

        /* The v2 layout puts output row y at plane row y, so its luma bands
         * are the picture's. The v1 layout scatters them across 16-row bands
         * and needs its own inverse. Both layouts read the auxiliary chroma
         * planes at y >> 1, as an ordinary chroma plane. */
        var lumaBands = (layout === 1)
            ? auxV1LumaBands(rects, h)
            : (layout === 2 ? bandsFor(rects, 0, h) : null);
        var chromaBands = layout ? bandsFor(rects, 1, halfH) : null;

        /* As uploadLuma(): a partial buffer can only add rows to textures
         * that already exist at this shape, and only where there are bands
         * saying which rows. Checked for every plane before any is written.
         *
         * The caller's band covers both plane spaces. Its rows are rounded
         * outward to 16, which is exactly what auxV1LumaBands() does to reach
         * the v1 layout's 16-row bands, and a superset of the v2 layout's
         * one-to-one rows and of both layouts' chroma rows at y >> 1. */
        var partial = (typeof copyY0 === 'number');

        if (partial && (!lumaBands || !chromaBands
                || !allocatedAt('uAuxY', w, h, 1)
                || (auxInterleaved
                    ? !allocatedAt('uAuxU', halfW, halfH, 2)
                    : (!allocatedAt('uAuxU', halfW, halfH, 1)
                        || !allocatedAt('uAuxV', halfW, halfH, 1)))))
            return false;

        var lumaY0 = partial ? copyY0 : 0;
        var chromaY0 = partial ? (copyY0 >> 1) : 0;

        uploadPlane('uAuxY', y, strides[0], w, h, 1, lumaBands, lumaY0);

        if (auxInterleaved)
            uploadPlane('uAuxU', u, strides[1], halfW, halfH, 2, chromaBands,
                    chromaY0);
        else {
            uploadPlane('uAuxU', u, strides[1], halfW, halfH, 1, chromaBands,
                    chromaY0);
            uploadPlane('uAuxV', v, strides[2], halfW, halfH, 1, chromaBands,
                    chromaY0);
        }

        return true;

    };

    /* ==================== Rendering ==================== */

    /**
     * Renders the currently uploaded planes, returning the finished picture as
     * an ImageBitmap.
     *
     * @param {!number} layout
     *     Which auxiliary layout to apply: 0 to use the main view alone
     *     (yielding an ordinary 4:2:0 image), 1 or 2 for the AVC444 chroma
     *     layouts of that version.
     *
     * @param {number|boolean} [filter=false]
     *     Whether to also undo the encoder's chroma filter, recovering the one
     *     sample per 2x2 block that the auxiliary view does not carry, and if
     *     so with what threshold: a value in 0-255 below which the recovered
     *     sample is discarded as noise, or false not to recover at all. Has no
     *     effect when the layout is 0.
     *
     * @param {Array} [clip]
     *     The regions of the picture the caller intends to use, each
     *     {x, y, width, height} in picture coordinates. Only those are
     *     converted; the rest of the returned image is left blank, so a caller
     *     passing this MUST draw only these regions. Omit, or pass null, to
     *     convert the whole picture.
     *
     * @returns {ImageBitmap}
     *     The rendered image, whose ownership passes to the caller and which
     *     must be close()d once drawn, or null if this renderer is not usable.
     */
    /**
     * The conversion currently in effect: full-range BT.709.
     *
     * Full range because that is what an RDP host sends. MS-RDPEGFX defines
     * the ARGB-to-AYUV transform as full-range BT.709, and both hosts measured
     * here encode to it -- read out of their SPS, not inferred: the xrdp fork
     * writes video_full_range_flag=1 with a complete BT.709 description, and
     * Windows writes video_full_range_flag=1 with no description at all.
     * Neither sends limited range.
     *
     * Nearly inert in practice, since setColorSpace() runs before the first
     * render and Chrome always populates VideoFrame.colorSpace. It matters
     * only for a decoder that reports nothing at all.
     *
     * @private
     */
    var colorSpace = conversionFor(true, 'bt709', true);

    /**
     * Returns the luma offset, scales and matrix coefficients for a decoded
     * frame's colour space.
     *
     * Range is the half of this that shows: limited range carries black at 16
     * and white at 235, so the two differ by the whole picture's contrast. The
     * matrix mostly shifts hue in saturated regions, and only the two common
     * ones are distinguished.
     *
     * @private
     *
     * @param {!boolean} fullRange
     *     Whether the samples span 0-255 rather than 16-235.
     *
     * @param {String} matrix
     *     The VideoColorSpace matrix name, if the decoder reported one.
     *
     * @param {!boolean} assumed
     *     Whether the range was defaulted rather than signalled by the stream.
     *     Carried only into the description, so that a session rendering with
     *     the wrong contrast can be told from one rendering with the right
     *     contrast for a different reason.
     *
     * @returns {!Object}
     *     The conversion, as consumed by render().
     */
    function conversionFor(fullRange, matrix, assumed) {

        /* BT.601 for the standard-definition matrices, BT.709 otherwise --
         * including when nothing was reported, since these are desktop
         * streams. */
        var sd = (matrix === 'smpte170m' || matrix === 'bt470bg');

        return {
            yOffset : fullRange ? 0.0 : 16.0 / 255.0,
            yScale  : fullRange ? 1.0 : 255.0 / 219.0,
            cScale  : fullRange ? 1.0 : 255.0 / 224.0,
            coef    : sd
                ? [1.402, 0.344136, 0.714136, 1.772]
                : [1.5748, 0.187324, 0.468124, 1.8556],
            describe: (fullRange ? 'full' : 'limited') + ' range'
                    + (assumed ? ' (ASSUMED -- stream did not signal it)' : '')
                    + ', ' + (sd ? 'BT.601' : 'BT.709')
                    + (matrix ? '' : ' (assumed)')
        };

    }

    /**
     * Adopts the colour space of a decoded frame, so the combined picture
     * matches what the browser draws for the 4:2:0 path.
     *
     * Following the frame rather than deciding for ourselves is what keeps the
     * two paths agreeing: the 4:2:0 picture never reaches this shader, and
     * whatever the browser makes of it is not ours to override. Where the
     * frame is wrong, the fix belongs upstream of the browser -- rustguac
     * completes the host's SPS on the way past (src/h264_rewrite.rs) so that
     * both paths are told the truth, rather than this one being taught to
     * disbelieve what it is handed.
     *
     * @param {VideoColorSpace} reported
     *     The colorSpace of a decoded VideoFrame, if any.
     *
     * @param {boolean} forced
     *     True to render full range and false to render limited range
     *     whatever the frame reports, or undefined to follow it.
     *
     *     The escape hatch for a host whose signalling the browser will not
     *     act on. Chrome discards video_full_range_flag when the SPS carries
     *     an explicitly unspecified colour_primaries or transfer -- it reports
     *     limited for a stream that says full, and paints it crushed -- so a
     *     host can be correct on the wire and wrong on the screen with nothing
     *     to show for it. rustguac logs which case a session is in at connect
     *     (`H.264 colour:` in the journal, from src/h264_sps.rs).
     *
     * @returns {!String}
     *     A description of the conversion now in effect.
     */
    this.setColorSpace = function setColorSpace(reported, forced) {

        var signalled = !!(reported && reported.fullRange !== null
                && reported.fullRange !== undefined);

        if (forced !== undefined && forced !== null) {
            colorSpace = conversionFor(!!forced,
                    reported && reported.matrix, false);
            return colorSpace.describe + ' (FORCED -- frame reported '
                    + (signalled ? (reported.fullRange ? 'full' : 'limited')
                                 : 'nothing') + ')';
        }

        /* Full range unless the frame says otherwise. MS-RDPEGFX specifies
         * the ARGB-to-AYUV transform as full-range BT.709 with the components
         * clamped to 0...255, so an RDPEGFX stream the decoder says nothing
         * about is full range by definition -- and expanding 16-235 to 0-255
         * on it crushes blacks, clips whites and over-saturates chroma by
         * 255/224. It looks punchier and is wrong.
         *
         * A reported flag still wins, because the 4:2:0 path obeys it too and
         * a session whose two codecs disagree is worse than one that is
         * uniformly a little off. Note that the flag is the *browser's*
         * reading, not the host's: Chrome's hardware decoder reports limited
         * for a Windows host that plainly declared full, having dropped a
         * range flag that carried no colour description beside it. That is why
         * the SPS is completed server-side rather than second-guessed here,
         * and why `forced` exists for anything the splice cannot reach. */
        var fullRange = signalled ? !!reported.fullRange : true;

        colorSpace = conversionFor(fullRange, reported && reported.matrix,
                !signalled);
        return colorSpace.describe;

    };

    this.render = function render(layout, filter, clip) {

        if (!renderer.supported || gl.isContextLost() || !width || !height)
            return null;

        gl.useProgram(program);
        gl.viewport(0, 0, width, height);

        gl.uniform2i(uniforms.size, width, height);
        gl.uniform2i(uniforms.auxSize, auxWidth, auxHeight);
        gl.uniform1i(uniforms.layout, layout);
        gl.uniform1f(uniforms.filter, filter === false ? -1.0 : filter / 255.0);
        gl.uniform2f(uniforms.range, colorSpace.yOffset, colorSpace.yScale);
        gl.uniform1f(uniforms.cScale, colorSpace.cScale);
        gl.uniform4f(uniforms.coef, colorSpace.coef[0], colorSpace.coef[1],
                colorSpace.coef[2], colorSpace.coef[3]);
        gl.uniform1i(uniforms.interleaved,
                (lumaInterleaved ? 1 : 0) | (auxInterleaved ? 2 : 0));

        /* Every pixel of the picture costs a chroma unpack and, on three of
         * every four, three more of them for the reverse filter. Converting a
         * whole 4K surface to repaint a caret is most of the cost of combining
         * for none of the benefit, so where the server said which regions it
         * actually updated, only those are converted -- the caller draws no
         * more than that either way.
         *
         * The scissor rectangle is in GL's bottom-up coordinates, while the
         * picture and its rects are top-down. */
        var drawn = 0;

        if (clip && clip.length && clip.length <= MAX_CLIP_RECTS) {

            gl.enable(gl.SCISSOR_TEST);

            for (var i = 0; i < clip.length; i++) {

                var rect = clip[i];

                /* Clamped rather than trusted: a rect reaching outside the
                 * picture is a server bug, but glScissor with a negative
                 * width is a GL error that would take the whole frame with
                 * it. */
                var x0 = Math.max(0, rect.x | 0);
                var y0 = Math.max(0, rect.y | 0);
                var x1 = Math.min(width, (rect.x | 0) + (rect.width | 0));
                var y1 = Math.min(height, (rect.y | 0) + (rect.height | 0));

                if (x1 <= x0 || y1 <= y0)
                    continue;

                gl.scissor(x0, height - y1, x1 - x0, y1 - y0);
                gl.drawArrays(gl.TRIANGLES, 0, 3);
                drawn++;

            }

            gl.disable(gl.SCISSOR_TEST);

        }

        /* No regions given, too many of them to be worth a draw call each, or
         * every one of them empty: convert the whole picture. The caller is
         * still free to draw only part of it. */
        if (!drawn)
            gl.drawArrays(gl.TRIANGLES, 0, 3);

        /* Checked again on the far side of the draw. The check at the top of
         * this function has already passed by the time the context dies
         * mid-frame, and a lost context makes drawArrays() a silent no-op --
         * so the canvas returned would be the clear colour, which with
         * alpha:false is opaque black, and the caller would blit that over
         * whatever the frame's rects cover.
         *
         * This narrows the window rather than closing it: drawArrays() only
         * queues work, so a draw that will never execute can still leave
         * isContextLost() false here, and the webglcontextlost event arrives
         * in a later task. Closing it properly needs a fence or a readback
         * after every frame, which costs a GPU sync per frame -- more than the
         * failure it guards against. */
        if (gl.isContextLost()) {
            console.warn('[rustguac] YUV444 context lost mid-frame;'
                    + ' dropping frame and falling back to 4:2:0');
            return null;
        }

        /* Hands over the drawing buffer rather than copying out of it. The
         * canvas is left with a fresh blank buffer of the same size, which the
         * next render() overwrites entirely -- every draw covers the whole
         * viewport with a single triangle -- so nothing is carried between
         * frames that would need clearing. */
        return canvas.transferToImageBitmap();

    };

    /**
     * Returns the canvas this renderer draws into.
     *
     * @returns {!OffscreenCanvas}
     */
    /**
     * Blocks until the GPU work issued so far has completed.
     *
     * Only for measurement. Uploads, the shader pass and the bitmap transfer
     * are all asynchronous, so timing them without this measures how fast work
     * can be *submitted* -- which is roughly a quarter of what the combine
     * actually costs, and is why it was twice concluded to be nearly free.
     * tests/bench has always forced completion for exactly this reason.
     *
     * Stalls the pipeline, so it belongs behind a diagnostic flag and nowhere
     * else.
     */
    this.finish = function finish() {
        if (!renderer.supported || gl.isContextLost())
            return;
        gl.finish();
    };

    this.getCanvas = function getCanvas() {
        return canvas;
    };

    /**
     * Releases the GPU resources held by this renderer.
     */
    this.destroy = function destroy() {

        if (!gl)
            return;

        for (var name in textures)
            gl.deleteTexture(textures[name].texture);

        textures = {};

        if (program) {
            gl.deleteProgram(program);
            program = null;
        }

        renderer.supported = false;

    };

};

/**
 * Whether the browser can combine AVC444 views at all. Requires WebGL2 and the
 * ability to read raw planes out of a decoded frame.
 *
 * @returns {!boolean}
 */
Guacamole.Yuv444Renderer.isSupported = function isSupported() {

    if (typeof VideoFrame === 'undefined'
            || typeof VideoFrame.prototype.copyTo !== 'function')
        return false;

    /* The finished picture leaves as an ImageBitmap; without that the readback
     * costs a full-frame copy per view, which is most of what combining is
     * trying to avoid. */
    if (typeof OffscreenCanvas === 'undefined'
            || typeof OffscreenCanvas.prototype.transferToImageBitmap
                !== 'function')
        return false;

    try {
        var probe = new OffscreenCanvas(1, 1);
        return !!probe.getContext('webgl2');
    } catch (e) {
        return false;
    }

};
