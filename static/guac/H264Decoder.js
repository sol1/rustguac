/*
 * H.264 decoder for Guacamole using the WebCodecs API.
 * Decodes H.264 NAL units received via the "h264" instruction and
 * renders decoded frames to a Guacamole Display layer.
 *
 * Copyright (C) 2026 Sol1 Pty Ltd. Licensed under Apache 2.0.
 */

var Guacamole = Guacamole || {};

/**
 * H.264 video decoder that uses the WebCodecs VideoDecoder API for
 * hardware-accelerated decoding of H.264 NAL units received from guacd.
 *
 * Frames are not drawn from the decoder's output callback. They are drawn from
 * a task scheduled on the display's queue at the point the instruction
 * arrived, so that decoded video is painted in stream order rather than
 * whenever decode happens to finish. See Guacamole.Display.drawH264().
 *
 * @constructor
 * @param {!Guacamole.Display} display
 *     The Guacamole display to render decoded frames to.
 */
Guacamole.H264Decoder = function H264Decoder(display) {

    /**
     * The WebCodecs VideoDecoder instance, or null if not yet initialised
     * or if WebCodecs is not supported.
     *
     * @private
     * @type {?VideoDecoder}
     */
    var decoder = null;

    /**
     * Whether the decoder has been configured with codec parameters.
     *
     * @private
     * @type {boolean}
     */
    var configured = false;

    /**
     * Whether the next access unit submitted must be a keyframe. Set after a
     * terminal decoder error, since a rebuilt decoder holds no reference
     * frames and a delta frame would only error it again immediately.
     *
     * @private
     * @type {boolean}
     */
    var needsKeyFrame = false;

    /**
     * Monotonic timestamp counter for EncodedVideoChunk (microseconds). Also
     * serves as the token identifying each submitted frame.
     *
     * @private
     * @type {number}
     */
    var timestamp = 0;

    /**
     * Number of frames submitted to the decoder but not yet painted.
     *
     * @private
     * @type {number}
     */
    var pendingDecodes = 0;

    /**
     * Maximum number of frames allowed to remain in flight when acknowledging
     * a Guacamole sync. A depth of 0 forces the sync ack to wait for every
     * frame to fully decode and paint, serializing network RTT and async
     * decode time on every frame and causing severe input lag. Allowing a
     * shallow pipeline overlaps RTT with decode while keeping the backlog
     * bounded, so guacd backpressure still applies beyond this depth.
     *
     * @private
     * @constant
     * @type {number}
     */
    var MAX_PIPELINE_DEPTH = 2;

    /**
     * Safety timeout (ms) for the sync gate. If pending decodes do not drain
     * within this window the sync is acked anyway, preventing a permanent
     * stall if the decoder wedges.
     *
     * @private
     * @constant
     * @type {number}
     */
    var SYNC_WAIT_TIMEOUT_MS = 200;

    /**
     * How long a scheduled draw task may wait for its frame before giving up,
     * in milliseconds. The task blocks the display queue until its frame
     * arrives, so a frame lost without an error being reported would stall the
     * display indefinitely; skipping one frame is the lesser cost. Generous,
     * because a healthy decoder returns frames in single-digit milliseconds.
     *
     * @private
     * @constant
     * @type {number}
     */
    var DECODE_WATCHDOG_MS = 1000;

    /**
     * Timestamp of the last sync-timeout warning, for rate-limiting the log so
     * a struggling decoder cannot flood the console (heavy logging on the main
     * thread itself worsens decode and paint latency).
     *
     * @private
     * @type {number}
     */
    var lastTimeoutWarn = 0;

    /**
     * Per-frame state keyed by token, from submission until the frame is drawn
     * or abandoned.
     *
     * @private
     * @type {Object.<number, Object>}
     */
    var pendingFrames = {};

    /**
     * Callbacks waiting for pending decodes to drain, used by waitForPending
     * to gate the Guacamole sync response.
     *
     * @private
     * @type {function[]}
     */
    var flushResolvers = [];

    /**
     * If the backlog has drained, fire and clear all flush resolvers.
     *
     * @private
     */
    function resolveIfIdle() {
        if (pendingDecodes <= 0 && flushResolvers.length > 0) {
            var resolvers = flushResolvers;
            flushResolvers = [];
            for (var i = 0; i < resolvers.length; i++)
                resolvers[i]();
        }
    }

    /**
     * Marks a pending decode as finished exactly once, whatever its outcome:
     * drawn, failed, or abandoned. pendingDecodes gates the sync response, so
     * a decode that is never settled leaves the client reporting a backlog
     * forever and every sync waiting out its timeout.
     *
     * @private
     * @param {!Object} frameState
     *     The per-frame state to settle.
     */
    function settle(frameState) {
        if (!frameState || frameState.settled)
            return;
        frameState.settled = true;
        pendingDecodes--;
        resolveIfIdle();
    }

    /**
     * Cancels a frame's decode watchdog, if it is still armed.
     *
     * @private
     * @param {object} frameState
     *     The frame's pending state, or null.
     */
    function clearWatchdog(frameState) {
        if (frameState && frameState.watchdog) {
            clearTimeout(frameState.watchdog);
            frameState.watchdog = null;
        }
    }

    /**
     * Canvases available for reuse as frame snapshots. A snapshot is held from
     * decode until its draw task runs, so several are live at once and one
     * shared canvas will not do. Allocating a fresh canvas per frame instead
     * would churn a 1080p-sized buffer at frame rate.
     *
     * @private
     * @type {HTMLCanvasElement[]}
     */
    var canvasPool = [];

    /**
     * Maximum number of canvases to retain for reuse. The pipeline holds only a
     * few frames at a time; canvases beyond this are dropped for collection
     * rather than kept alive indefinitely after a burst.
     *
     * @private
     * @constant
     * @type {number}
     */
    var MAX_CANVAS_POOL = 8;

    /**
     * Returns a canvas of the given size, reusing a pooled one where possible.
     *
     * @private
     * @param {number} width - Required width, in pixels.
     * @param {number} height - Required height, in pixels.
     * @returns {!HTMLCanvasElement}
     */
    function acquireCanvas(width, height) {

        var canvas = canvasPool.pop();
        if (!canvas)
            canvas = document.createElement('canvas');

        /* Assigning either dimension clears the canvas, so only resize when the
         * size actually differs; the frame is about to overwrite it anyway. */
        if (canvas.width !== width)
            canvas.width = width;
        if (canvas.height !== height)
            canvas.height = height;

        return canvas;

    }

    /**
     * Returns a canvas to the pool for reuse.
     *
     * @private
     * @param {HTMLCanvasElement} canvas - The canvas to release.
     */
    function releaseCanvas(canvas) {
        if (canvas && canvasPool.length < MAX_CANVAS_POOL)
            canvasPool.push(canvas);
    }

    /**
     * Combines the two views of an AVC444 picture into 4:4:4, or null when the
     * stream carries no auxiliary view, the browser cannot support it, or it
     * has been switched off. Created lazily, on first sight of an auxiliary
     * view, so an AVC420 stream never allocates a GL context.
     *
     * @private
     * @type {Guacamole.Yuv444Renderer}
     */
    var yuv444 = null;

    /**
     * Whether 4:4:4 combining has been ruled out for this stream, so it is not
     * attempted again on every frame.
     *
     * @private
     * @type {!boolean}
     */
    var yuv444Unavailable = false;

    /**
     * Whether the current stream is being combined to 4:4:4. False until an
     * auxiliary view actually arrives: an AVC420 stream has no second view to
     * combine, and reading planes back costs a copy per frame that would buy
     * nothing there.
     *
     * @private
     * @type {!boolean}
     */
    var combining = false;

    /**
     * Serialises plane read-back across frames. Both views of a picture write
     * into the same set of textures, and the auxiliary view refines what the
     * main view uploaded, so the copies have to complete in decode order --
     * copyTo() promises settling out of order would combine one picture's
     * chroma into another's luma.
     *
     * @private
     * @type {!Promise}
     */
    var copyChain = Promise.resolve();

    /**
     * Buffers available for reuse when reading planes back out of a frame,
     * keyed by byte length. A 1080p I420 frame is about 3MB, so allocating one
     * per frame would churn heavily at frame rate.
     *
     * @private
     * @type {!Object.<number, ArrayBuffer[]>}
     */
    var bufferPool = {};

    /**
     * Maximum buffers to retain per size.
     *
     * @private
     * @constant
     * @type {!number}
     */
    var MAX_BUFFER_POOL = 4;

    /**
     * Returns a buffer of at least the given size, reusing a pooled one where
     * possible.
     *
     * @private
     * @param {!number} size - Required size, in bytes.
     * @returns {!Uint8Array}
     */
    function acquireBuffer(size) {
        var pool = bufferPool[size];
        if (pool && pool.length)
            return pool.pop();
        return new Uint8Array(size);
    }

    /**
     * Returns a buffer to the pool.
     *
     * @private
     * @param {Uint8Array} buffer - The buffer to release.
     */
    function releaseBuffer(buffer) {
        if (!buffer)
            return;
        var pool = bufferPool[buffer.length];
        if (!pool)
            pool = bufferPool[buffer.length] = [];
        if (pool.length < MAX_BUFFER_POOL)
            pool.push(buffer);
    }

    /**
     * Returns the 4:4:4 renderer, creating it on first use. Returns null if the
     * browser cannot provide one, having recorded that so the attempt is not
     * repeated.
     *
     * @private
     * @returns {Guacamole.Yuv444Renderer}
     */
    function ensureYuv444() {

        if (yuv444 || yuv444Unavailable)
            return yuv444;

        if (typeof Guacamole.Yuv444Renderer === 'undefined'
                || !Guacamole.Yuv444Renderer.isSupported()) {
            console.warn('[rustguac] H.264: 4:4:4 chroma unavailable'
                    + ' (needs WebGL2 and VideoFrame.copyTo); AVC444 will'
                    + ' render at 4:2:0');
            yuv444Unavailable = true;
            return null;
        }

        yuv444 = new Guacamole.Yuv444Renderer();

        if (!yuv444.supported) {
            yuv444 = null;
            yuv444Unavailable = true;
            return null;
        }

        console.log('[rustguac] H.264: combining AVC444 views to 4:4:4');
        return yuv444;

    }

    /**
     * Reads a runtime override, from a window global, a query parameter, or
     * localStorage, in that order. The last two exist because the devices
     * where these paths behave differently -- phones and tablets -- are the
     * ones with no console to set a global from.
     *
     * @private
     * @param {!string} name - The override's name.
     * @returns {*} The override's value, or undefined if unset.
     */
    function override(name) {

        if (typeof window === 'undefined')
            return undefined;

        if (window['__' + name] !== undefined)
            return window['__' + name];

        var value = null;

        try {
            value = new URLSearchParams(window.location.search).get(name);
            if (value === null && window.localStorage)
                value = window.localStorage.getItem(name);
        } catch (e) {
            /* Storage can be blocked outright; the global still works. */
        }

        if (value === null || value === undefined)
            return undefined;

        /* '0' is deliberately not in that list: it is a valid threshold for
         * h264ChromaFilter, and an override that takes a number has to be
         * able to take zero. It still switches a boolean override off, since
         * callers coerce, and 0 is falsy. */
        if (value === 'off' || value === 'false')
            return false;
        if (value === 'on' || value === 'true')
            return true;

        var number = parseFloat(value);
        return isNaN(number) ? true : number;

    }

    /**
     * Whether 4:4:4 combining is switched on. Overridable at runtime as
     * window.__h264Chroma444 = false, as ?h264Chroma444=off on the client's
     * URL, or as the h264Chroma444 key in localStorage, to compare against the
     * 4:2:0 path.
     *
     * @private
     * @returns {!boolean}
     */
    function chroma444Enabled() {
        var value = override('h264Chroma444');
        return value === undefined ? true : !!value;
    }

    /**
     * Whether the encoder's chroma filter is undone as part of combining, and
     * with what threshold. The auxiliary view carries three of every four
     * chroma samples; the fourth is left as the mean of its 2x2 block by the
     * encoder and has to be solved for.
     *
     * Kept separate from chroma444Enabled() because it is the newer and less
     * certain half: it multiplies the main view's chroma by four, so if a host
     * turns out not to average that sample the error is amplified rather than
     * corrected. Overridable at runtime as window.__h264ChromaFilter = false,
     * which leaves plain 4:4:4 combining in place, so one build can compare
     * 4:2:0, combined, and combined-plus-filtered without a reload. Setting it
     * to a number overrides the threshold instead of switching the filter off;
     * that constant is inherited from FreeRDP rather than specified anywhere,
     * and is the part of this least backed by evidence. Also settable as
     * ?h264ChromaFilter= on the URL or from localStorage -- see override().
     *
     * @private
     * @returns {!(number|boolean)}
     */
    function chromaFilter() {
        var value = override('h264ChromaFilter');
        if (value === undefined || value === true)
            return 30;
        if (typeof value === 'number')
            return value;
        return false;
    }

    /**
     * Reads the three planes out of a decoded frame and hands them to the
     * renderer, then renders and snapshots the result.
     *
     * The frame is held across copyTo(), which is asynchronous and has no
     * synchronous equivalent -- there is no other way to reach the raw planes,
     * and the auxiliary view's planes are not an image, so drawing it through a
     * canvas would give colour-converted nonsense. The close is therefore in a
     * finally on the chained promise, and the draw task's watchdog still covers
     * a copy that never settles at all.
     *
     * @private
     * @param {!VideoFrame} frame - The decoded frame. Closed by this function.
     * @param {!object} frameState - The frame's pending state.
     */
    function combineFrame(frame, frameState) {

        var renderer = yuv444;
        var view = frameState.view;
        var rect = frame.codedRect || null;

        /* Copied in whatever format the decoder produced, with no format
         * option at all. Asking for I420 looks like the tidier choice -- one
         * layout for the renderer to handle -- but copyTo() only converts
         * between a narrow set of formats, and NV12 to I420 is not among
         * them. A hardware decoder on Windows hands back NV12, so requesting
         * I420 there throws before a single frame is copied.
         *
         * The two formats differ only in whether the chroma samples are in
         * one interleaved plane or two, which the renderer can address either
         * way, so taking what the decoder gives costs nothing. */
        var format = frame.format || '';
        var interleaved = (format.indexOf('NV12') === 0);
        var planar = (format.indexOf('I420') === 0);

        /* The coded frame rather than the visible one: the v1 chroma layout
         * pads the auxiliary view to a multiple of 16 rows and addresses that
         * padding, so cropping to the visible rect would drop rows the combine
         * reads. */
        var options = rect
            ? { rect: { x: 0, y: 0, width: rect.width, height: rect.height } }
            : {};

        var planeW = rect ? rect.width : frame.codedWidth;
        var planeH = rect ? rect.height : frame.codedHeight;
        var pictureW = frame.displayWidth;
        var pictureH = frame.displayHeight;

        var buffer = null;
        var size = 0;

        try {

            if (!interleaved && !planar)
                throw new Error('decoded frame is ' + (format || 'an unknown'
                        + ' format') + ', which carries no YUV planes');

            size = frame.allocationSize(options);
            buffer = acquireBuffer(size);

        } catch (e) {

            console.error('[rustguac] H.264: cannot size frame planes:',
                    e.message);

            /* Whatever stopped the copy will stop the next one too, and this
             * frame is already lost. Falling back here rather than only in
             * the copy's catch matters: without it every later frame takes
             * this same path, is neither combined nor drawn, and the display
             * stays black for the rest of the session. */
            combining = false;
            yuv444Unavailable = true;

            try { frame.close(); } catch (ignore) { /* already closed */ }
            if (frameState.onReady) frameState.onReady();
            return;

        }

        copyChain = copyChain.then(function() {
            return frame.copyTo(buffer, options);
        }).then(function(layout) {

            /* NV12 has two planes rather than three; a null V plane is how
             * the renderer is told the chroma is interleaved into U. */
            var y = new Uint8Array(buffer.buffer,
                    buffer.byteOffset + layout[0].offset);
            var u = new Uint8Array(buffer.buffer,
                    buffer.byteOffset + layout[1].offset);
            var v = interleaved ? null : new Uint8Array(buffer.buffer,
                    buffer.byteOffset + layout[2].offset);

            var strides = interleaved
                ? [layout[0].stride, layout[1].stride]
                : [layout[0].stride, layout[1].stride, layout[2].stride];

            if (view === 0)
                renderer.uploadLuma(y, u, v, strides, pictureW, pictureH);
            else
                renderer.uploadAux(y, u, v, strides, planeW, planeH);

            /* The main view renders on its own as an ordinary 4:2:0 picture,
             * exactly as a luma-only (LC=1) update does for FreeRDP; the
             * auxiliary view then re-renders the same picture with its chroma
             * applied. Two paints per picture is the reference behaviour, not
             * an accident. */
            var rendered = renderer.render(view === 0 ? 0 : view,
                    chromaFilter());

            /* Nothing to snapshot means the renderer has given up -- a lost
             * context, most likely. Returning alone would leave every frame
             * from here on blank, so drop the whole path. */
            if (!rendered) {
                combining = false;
                yuv444Unavailable = true;
                return;
            }

            /* The watchdog may have released this frame's task while the
             * copy was in flight, in which case drawDecoded() has already run
             * and nothing will ever paint this snapshot -- keeping it would
             * strand a canvas outside the pool. */
            if (frameState.settled)
                return;

            /* Sized from the rendered canvas rather than from this frame:
             * the v1 chroma layout pads the auxiliary view to a multiple of
             * 16 rows, so an auxiliary frame's own dimensions can exceed the
             * picture's. The renderer draws at the main view's size, leaving
             * anything below that in a taller snapshot blank -- and with no
             * rects the whole snapshot is blitted, painting that blank strip
             * over the bottom of the display. */
            var snapshot = acquireCanvas(rendered.width, rendered.height);
            snapshot.getContext('2d').drawImage(rendered, 0, 0);
            frameState.canvas = snapshot;

        }).catch(function(e) {

            console.error('[rustguac] H.264: 4:4:4 combine failed:',
                    e && e.message ? e.message : e);

            /* One failure is usually terminal for this path -- an unsupported
             * pixel format does not become supported later -- so fall back
             * rather than failing once per frame for the rest of the session. */
            combining = false;
            yuv444Unavailable = true;

        }).then(function() {

            try {
                frame.close();
            } catch (ignore) {
                /* Already closed */
            }

            releaseBuffer(buffer);

            /* The copy has settled, one way or the other; there is nothing
             * left for the watchdog to cover. */
            clearWatchdog(frameState);

            if (frameState.onReady)
                frameState.onReady();

        });

    }

    /**
     * Releases any frame snapshot still held awaiting its draw task. Snapshots
     * live here between decode and draw, so discarding the map without
     * reclaiming them throws away the pool's canvases.
     *
     * @private
     */
    function releaseHeldFrames() {
        for (var key in pendingFrames) {
            var frameState = pendingFrames[key];
            if (frameState && frameState.canvas) {
                releaseCanvas(frameState.canvas);
                frameState.canvas = null;
            }
        }
        pendingFrames = {};
    }

    /**
     * Initialise the VideoDecoder if not already done.
     *
     * @private
     * @param {number} width - Expected frame width.
     * @param {number} height - Expected frame height.
     */
    function ensureDecoder(width, height) {

        /* A decoder that has hit a terminal error is left closed. Treating it
         * as usable because `configured` is still set means every later frame
         * is dropped and nothing is drawn again -- and since guacd suppresses
         * ordinary image operations for a layer carrying an H.264 stream, that
         * is a permanently black screen rather than a degraded one. */
        if (decoder && configured && decoder.state !== 'closed')
            return;

        if (typeof VideoDecoder === 'undefined') {
            console.warn('[rustguac] WebCodecs VideoDecoder not available');
            return;
        }

        /* Release any decoder being replaced. reset() clears the configured
         * flag, so a later decode() can reach this point with a live decoder
         * still assigned; overwriting it without closing leaks its GPU
         * resources and leaves a second decoder able to deliver frames here. */
        if (decoder && decoder.state !== 'closed') {
            try {
                decoder.close();
            } catch (e) {
                /* Already in an error state */
            }
        }

        decoder = new VideoDecoder({

            output: function(frame) {

                var frameState = null;
                var canvas = null;

                /* Everything touching the frame runs inside this try, so that
                 * the close in the finally covers every path out -- including
                 * one thrown from acquiring the snapshot canvas. A frame that
                 * escapes without being closed holds one of the hardware
                 * decoder's output surfaces until the collector runs, and
                 * enough of them stall decoding outright. */
                try {

                    frameState = pendingFrames[frame.timestamp];

                    /* The draw task already gave up on this frame, or it
                     * belongs to a decoder that has since been replaced. */
                    if (!frameState)
                        return;

                    /* An auxiliary view means this is an AVC444 stream, so
                     * its chroma can be recovered. Switch over for the frames
                     * that follow; this one cannot be combined, because the
                     * main view it refines went through the 4:2:0 path and its
                     * planes were never uploaded. */
                    if (frameState.view !== 0 && !combining) {

                        if (chroma444Enabled() && ensureYuv444())
                            combining = true;

                        /* Not an image on its own: drawing packed chroma would
                         * paint garbage over the screen. Leave canvas null so
                         * nothing is drawn, but release the task below. */
                        return;

                    }

                    /* Both views go through the combiner: the main one renders
                     * as an ordinary 4:2:0 picture and uploads the planes the
                     * auxiliary one then refines. It closes the frame and
                     * releases the task itself, since it must do both after an
                     * asynchronous plane copy. */
                    if (combining) {
                        var handed = frame;
                        combineFrame(handed, frameState);
                        /* Ownership passes only once the call has returned; a
                         * synchronous throw leaves the frame ours to close,
                         * which the finally below then does. */
                        frame = null;
                        return;
                    }

                    /* Snapshot to a canvas and release the VideoFrame before
                     * returning, rather than holding it until the draw task
                     * runs. Holding frames until their scheduled draw exhausts
                     * the surface pool as soon as the display queue falls
                     * behind: the decoder stalls, which delays the draws,
                     * which holds more frames.
                     *
                     * The copy is synchronous, and deliberately so.
                     * Snapshotting via createImageBitmap() leaves the frame
                     * open across a promise, and any path where that promise
                     * neither resolves nor rejects orphans the frame with its
                     * surface still held. Closing in a finally, with no await
                     * in between, removes the window rather than narrowing
                     * it. */
                    canvas = acquireCanvas(frame.displayWidth,
                            frame.displayHeight);

                    canvas.getContext('2d').drawImage(frame, 0, 0);
                    frameState.canvas = canvas;

                } catch (e) {

                    console.error('[rustguac] H.264 snapshot failed:',
                            e.message);

                    releaseCanvas(canvas);
                    if (frameState)
                        frameState.canvas = null;

                } finally {

                    /* Null when combineFrame() took ownership: it closes the
                     * frame once its plane copy has settled, and releases the
                     * task itself. */
                    if (frame) {

                        /* Cleared here rather than on the way in, because the
                         * combine path holds the frame across an asynchronous
                         * copyTo() that nothing else times out: clearing the
                         * watchdog before handing the frame over would leave a
                         * copy that never settles holding the ordered display
                         * queue with nothing able to release it.
                         * combineFrame() clears it once the copy settles. */
                        clearWatchdog(frameState);

                        frame.close();

                    }

                    /* Released here rather than after the try, because the
                     * early returns above exit the function once this finally
                     * has run -- they do not fall through to code following
                     * the block. Releasing there left every AVC444 auxiliary
                     * view's draw task blocked forever, its watchdog having
                     * been cleared above, and the display queue is ordered, so
                     * the first auxiliary frame stopped the display for good.
                     *
                     * Ordered after the close deliberately: this runs the
                     * display queue synchronously and may draw several frames,
                     * by which point the frame's surface is back in the
                     * decoder's pool. */
                    if (frame && frameState && frameState.onReady)
                        frameState.onReady();

                }

            },

            error: function(e) {

                console.error('[rustguac] H.264 decode error:', e.message);

                /* Terminal: the decoder is now closed and will never accept
                 * another chunk. Force ensureDecoder() to build a replacement,
                 * and hold frames until the next keyframe, the earliest point
                 * a fresh decoder can produce a picture at all. */
                configured = false;
                needsKeyFrame = true;

                /* A VideoDecoder error is terminal for everything queued on
                 * it: those frames will never reach the output callback. Each
                 * holds a blocked task on the display queue, and the display
                 * renders frames in order, so leaving them blocked freezes the
                 * display on whatever was last painted. */
                for (var key in pendingFrames) {
                    var frameState = pendingFrames[key];
                    if (frameState && frameState.onReady)
                        frameState.onReady();
                }

            }

        });

        decoder.configure({
            codec: 'avc1.640029', // High profile, level 4.1
            hardwareAcceleration: 'prefer-hardware',
            optimizeForLatency: true
        });

        configured = true;

    }

    /**
     * Submits a complete H.264 access unit for decoding. The frame is not
     * drawn here; the caller schedules the draw and is notified via onReady
     * once the frame is available, or once it is known that it cannot be.
     *
     * @param {!Guacamole.Display.VisibleLayer} layer
     *     The layer to draw the decoded frame to.
     *
     * @param {number} x - X position on the layer.
     * @param {number} y - Y position on the layer.
     * @param {number} width - Frame width.
     * @param {number} height - Frame height.
     *
     * @param {!ArrayBuffer} nalData
     *     Raw H.264 NAL unit data, in Annex B format.
     *
     * @param {boolean} isKeyFrame
     *     Whether this access unit contains an IDR slice.
     *
     * @param {Array} [rects]
     *     The regions of the decoded picture that are valid, each
     *     {x, y, width, height} in surface coordinates. An H.264 picture is
     *     always full-surface sized, but a server encoding only part of the
     *     screen leaves the rest holding no meaningful content. Omit when the
     *     entire picture is valid.
     *
     * @param {function} [onReady]
     *     Called once the frame is ready to draw, or cannot be produced.
     *
     * @param {number} [view=0]
     *     Which view this access unit carries: 0 is a displayable picture,
     *     non-zero an AVC444 auxiliary chroma view, which is decoded for its
     *     references but never drawn.
     *
     * @returns {?number}
     *     A token identifying this frame, to be passed to drawDecoded(), or
     *     null if it could not be submitted.
     */
    this.decode = function(layer, x, y, width, height, nalData, isKeyFrame,
            rects, onReady, view) {

        ensureDecoder(width, height);

        /* No decoder at all: the caller's task must still be released, or the
         * display queue stalls behind a frame that will never arrive. */
        if (!decoder || decoder.state === 'closed') {
            if (onReady) onReady();
            return null;
        }

        /* Recovering from a terminal error. A rebuilt decoder holds no
         * reference frames, so a delta would error it again at once and
         * recovery would never converge; wait for the next IDR instead. */
        if (needsKeyFrame) {
            if (!isKeyFrame) {
                if (onReady) onReady();
                return null;
            }
            needsKeyFrame = false;
            console.warn('[rustguac] H.264: decoder rebuilt, resuming at'
                    + ' keyframe');
        }

        try {

            var chunk = new EncodedVideoChunk({
                type: isKeyFrame ? 'key' : 'delta',
                timestamp: timestamp,
                data: nalData
            });

            var token = timestamp;
            timestamp += 33333; // ~30fps in microseconds

            var frameState = pendingFrames[token] = {
                layer: layer,
                x: x,
                y: y,
                rects: (rects && rects.length) ? rects : null,
                view: view || 0,
                onReady: onReady,
                canvas: null,
                settled: false,
                watchdog: null
            };

            pendingDecodes++;

            frameState.watchdog = setTimeout(function() {
                frameState.watchdog = null;
                if (!frameState.canvas && frameState.onReady)
                    frameState.onReady();
            }, DECODE_WATCHDOG_MS);

            decoder.decode(chunk);
            return token;

        } catch (e) {

            console.error('[rustguac] H.264 chunk error:', e.message);

            /* The frame may already have been registered and counted before
             * the throw. Returning null means drawDecoded() will never be
             * called for it, so nothing else will ever settle it, and an
             * unsettled decode holds pendingDecodes above zero permanently:
             * resolveIfIdle() then never fires again and every subsequent sync
             * waits out its full timeout. Undo the registration here.
             *
             * frameState is undefined if the throw came from constructing the
             * chunk, before anything was registered. */
            if (frameState) {
                clearWatchdog(frameState);
                delete pendingFrames[token];

                /* A snapshot already taken for this frame would otherwise be
                 * stranded outside the pool, since no draw task will run. */
                if (frameState.canvas) {
                    releaseCanvas(frameState.canvas);
                    frameState.canvas = null;
                }

                settle(frameState);
            }

            if (onReady) onReady();
            return null;

        }

    };

    /**
     * Draws the frame decoded for the given token, then releases it. Called
     * from the display's task queue so that frames are painted in the order
     * the instruction stream specified, rather than whenever decode finished.
     *
     * Safe to call with a token that has no decoded frame: the decode may have
     * failed, or the watchdog may have released the task early, in which case
     * nothing is drawn.
     *
     * @param {number} token
     *     The token returned by decode().
     */
    this.drawDecoded = function(token) {

        if (token === null || token === undefined)
            return;

        var frameState = pendingFrames[token];
        if (!frameState)
            return;

        delete pendingFrames[token];

        clearWatchdog(frameState);

        var snapshot = frameState.canvas;
        if (!snapshot) {
            settle(frameState);
            return;
        }

        try {

            if (frameState.layer) {

                var ctx = frameState.layer.getCanvas().getContext('2d');

                /* Draw only the regions the server marked valid. The decoded
                 * picture spans the whole surface, so blitting all of it would
                 * overwrite areas delivered via other codecs on a server that
                 * mixes them within a frame. */
                if (frameState.rects) {
                    for (var r = 0; r < frameState.rects.length; r++) {
                        var rect = frameState.rects[r];
                        ctx.drawImage(snapshot,
                                rect.x, rect.y, rect.width, rect.height,
                                rect.x, rect.y, rect.width, rect.height);
                    }
                }

                /* No regions given: the entire picture is valid */
                else
                    ctx.drawImage(snapshot, frameState.x, frameState.y);

            }

        } finally {
            frameState.canvas = null;
            releaseCanvas(snapshot);
            settle(frameState);
        }

    };

    /**
     * Waits for pending decodes to drain, then invokes the callback. Used to
     * gate the Guacamole sync response so that guacd receives accurate
     * backpressure from the client's decode speed.
     *
     * @param {function} callback
     *     Called when the backlog is within the allowed pipeline depth.
     */
    this.waitForPending = function(callback) {

        if (pendingDecodes <= MAX_PIPELINE_DEPTH || !decoder
                || decoder.state === 'closed') {
            callback();
            return;
        }

        var waitingOn = pendingDecodes;
        var resolved = false;

        var timer = setTimeout(function() {
            if (!resolved) {
                resolved = true;
                var now = performance.now();
                if (now - lastTimeoutWarn > 1000) {
                    lastTimeoutWarn = now;
                    console.warn('[rustguac] H.264: sync wait timeout ('
                            + waitingOn + ' frames pending), forcing flush');
                }
                callback();
            }
        }, SYNC_WAIT_TIMEOUT_MS);

        flushResolvers.push(function() {
            if (!resolved) {
                resolved = true;
                clearTimeout(timer);
                callback();
            }
        });

    };

    /**
     * Resets the decoder, e.g. after reconnection or error recovery. The next
     * frame submitted must be a keyframe.
     */
    this.reset = function() {

        if (decoder && decoder.state !== 'closed') {
            try {
                decoder.reset();
                configured = false;
                needsKeyFrame = true;
                timestamp = 0;
            } catch (e) {
                /* Decoder may be in an error state */
            }
        }

        pendingDecodes = 0;
        releaseHeldFrames();

        var resolvers = flushResolvers;
        flushResolvers = [];
        for (var i = 0; i < resolvers.length; i++)
            resolvers[i]();

    };

    /**
     * Closes and releases the decoder.
     */
    this.destroy = function() {

        if (decoder && decoder.state !== 'closed') {
            try {
                decoder.close();
            } catch (e) {
                /* Ignore */
            }
        }

        decoder = null;
        configured = false;
        needsKeyFrame = false;

        if (yuv444) {
            yuv444.destroy();
            yuv444 = null;
        }
        combining = false;
        bufferPool = {};
        pendingDecodes = 0;
        releaseHeldFrames();

        var resolvers = flushResolvers;
        flushResolvers = [];
        for (var i = 0; i < resolvers.length; i++)
            resolvers[i]();

    };

};

/**
 * Check if the browser supports H.264 decoding via WebCodecs.
 *
 * @returns {boolean}
 *     true if WebCodecs VideoDecoder is available and supports H.264.
 */
Guacamole.H264Decoder.isSupported = function isSupported() {
    return typeof VideoDecoder !== 'undefined';
};
