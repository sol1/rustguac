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
     * @private
     * @type {!HTMLCanvasElement}
     */
    var canvas = document.createElement('canvas');

    /**
     * The WebGL2 context, or null if WebGL2 is unavailable.
     *
     * @private
     * @type {WebGL2RenderingContext}
     */
    var gl = null;

    try {
        /* This canvas is never in the document; it exists to be read back
         * from with drawImage(). That rules out two attributes that would
         * otherwise be the obvious choice here:
         *
         * desynchronized asks for the low-latency present path, which is for
         * canvases actually on screen and on some drivers -- mobile ones in
         * particular -- puts the drawing buffer somewhere that is not a
         * reliable source for a readback.
         *
         * preserveDrawingBuffer: false leaves the buffer's contents undefined
         * after a compositing boundary. The drawImage() here is synchronous
         * with the draw, so in principle it never crosses one, but it runs
         * from a promise callback and that is a thinner guarantee than it
         * looks. The copy it costs is one the driver is likely making anyway.
         */
        gl = canvas.getContext('webgl2', {
            alpha: false,
            antialias: false,
            depth: false,
            stencil: false,
            premultipliedAlpha: false,
            preserveDrawingBuffer: true
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

        /* YUV to RGB. BT.709 at full range, matching the coefficients FreeRDP
         * decodes these streams with (prim_internal.h: 403, 475, 48, 120 over
         * 256, with no 16 offset on Y). Using limited-range or BT.601 here
         * would tint the whole session. */
        '    float u = U - 0.50196078;',  /* 128/255 */
        '    float v = V - 0.50196078;',

        '    vec3 rgb = vec3(',
        '        Y + 1.57421875 * v,',
        '        Y - 0.18750000 * u - 0.46875000 * v,',
        '        Y + 1.85546875 * u);',

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
     */
    function uploadPlane(name, data, stride, w, h, channels) {

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
            gl.texImage2D(gl.TEXTURE_2D, 0, internal, w, h, 0,
                    format, gl.UNSIGNED_BYTE, data);
            slot.w = w;
            slot.h = h;
            slot.channels = channels;
        }
        else
            gl.texSubImage2D(gl.TEXTURE_2D, 0, 0, 0, w, h,
                    format, gl.UNSIGNED_BYTE, data);

        gl.pixelStorei(gl.UNPACK_ROW_LENGTH, 0);

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
     */
    this.uploadLuma = function uploadLuma(y, u, v, strides, w, h) {

        if (!renderer.supported)
            return;

        if (width !== w || height !== h) {
            width = w;
            height = h;
            canvas.width = w;
            canvas.height = h;
        }

        var halfW = (w + 1) >> 1;
        var halfH = (h + 1) >> 1;

        lumaInterleaved = !v;

        uploadPlane('uLumaY', y, strides[0], w, h);

        if (lumaInterleaved)
            uploadPlane('uLumaU', u, strides[1], halfW, halfH, 2);
        else {
            uploadPlane('uLumaU', u, strides[1], halfW, halfH);
            uploadPlane('uLumaV', v, strides[2], halfW, halfH);
        }

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
     */
    this.uploadAux = function uploadAux(y, u, v, strides, w, h) {

        if (!renderer.supported)
            return;

        auxWidth = w;
        auxHeight = h;

        var halfW = (w + 1) >> 1;
        var halfH = (h + 1) >> 1;

        auxInterleaved = !v;

        uploadPlane('uAuxY', y, strides[0], w, h);

        if (auxInterleaved)
            uploadPlane('uAuxU', u, strides[1], halfW, halfH, 2);
        else {
            uploadPlane('uAuxU', u, strides[1], halfW, halfH);
            uploadPlane('uAuxV', v, strides[2], halfW, halfH);
        }

    };

    /* ==================== Rendering ==================== */

    /**
     * Renders the currently uploaded planes, returning the canvas holding the
     * result.
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
     * @returns {HTMLCanvasElement}
     *     The canvas holding the rendered image, or null if this renderer is
     *     not usable.
     */
    this.render = function render(layout, filter) {

        if (!renderer.supported || gl.isContextLost() || !width || !height)
            return null;

        gl.useProgram(program);
        gl.viewport(0, 0, width, height);

        gl.uniform2i(uniforms.size, width, height);
        gl.uniform2i(uniforms.auxSize, auxWidth, auxHeight);
        gl.uniform1i(uniforms.layout, layout);
        gl.uniform1f(uniforms.filter, filter === false ? -1.0 : filter / 255.0);
        gl.uniform1i(uniforms.interleaved,
                (lumaInterleaved ? 1 : 0) | (auxInterleaved ? 2 : 0));

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

        return canvas;

    };

    /**
     * Returns the canvas this renderer draws into.
     *
     * @returns {!HTMLCanvasElement}
     */
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

    try {
        var probe = document.createElement('canvas');
        return !!probe.getContext('webgl2');
    } catch (e) {
        return false;
    }

};
