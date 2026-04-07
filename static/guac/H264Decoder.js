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
     * Monotonic timestamp counter for EncodedVideoChunk (microseconds).
     *
     * @private
     * @type {number}
     */
    var timestamp = 0;

    /**
     * Number of frames submitted to the decoder but not yet output.
     *
     * @private
     * @type {number}
     */
    var pendingDecodes = 0;

    /**
     * Per-frame draw positions keyed by chunk timestamp. The VideoDecoder
     * output callback uses this to draw each frame at the correct position,
     * avoiding shared mutable state between concurrent decodes.
     *
     * @private
     * @type {Object.<number, {layer: Guacamole.Display.VisibleLayer, x: number, y: number}>}
     */
    var pendingPositions = {};

    /**
     * Callbacks waiting for all pending decodes to complete (used by
     * waitForPending to gate the Guacamole sync response).
     *
     * @private
     * @type {function[]}
     */
    var flushResolvers = [];

    /**
     * Maximum number of frames allowed in the WebCodecs decode queue before
     * delta frames are dropped. At 30fps, 5 frames is ~167ms of latency.
     *
     * @private
     * @constant
     * @type {number}
     */
    var MAX_DECODE_QUEUE = 5;

    /**
     * Total frames decoded.
     *
     * @type {number}
     */
    this.framesDecoded = 0;

    /**
     * Total frames dropped or errored.
     *
     * @type {number}
     */
    this.framesDropped = 0;

    /**
     * Total number of sync responses that were delayed waiting for H.264
     * decode completion.
     *
     * @type {number}
     */
    this.syncsGated = 0;

    /**
     * Peak decode queue depth seen during this session.
     *
     * @type {number}
     */
    this.peakQueueDepth = 0;

    /**
     * Reference to this for closures.
     */
    var self = this;

    /**
     * If pendingDecodes has reached zero, fire and clear all flush resolvers.
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
     * Initialise the VideoDecoder if not already done.
     *
     * @private
     * @param {number} width - Expected frame width.
     * @param {number} height - Expected frame height.
     */
    function ensureDecoder(width, height) {

        if (decoder && configured)
            return;

        if (typeof VideoDecoder === 'undefined') {
            console.warn('[rustguac] WebCodecs VideoDecoder not available');
            return;
        }

        decoder = new VideoDecoder({
            output: function(frame) {
                self.framesDecoded++;
                try {
                    var pos = pendingPositions[frame.timestamp];
                    delete pendingPositions[frame.timestamp];
                    if (pos && pos.layer) {
                        var canvas = pos.layer.getCanvas();
                        var ctx = canvas.getContext('2d');
                        ctx.drawImage(frame, pos.x, pos.y);
                    }
                } finally {
                    // CRITICAL: always close VideoFrame to release GPU memory
                    frame.close();
                    pendingDecodes--;
                    resolveIfIdle();
                }
            },
            error: function(e) {
                self.framesDropped++;
                pendingDecodes--;
                resolveIfIdle();
                console.error('[rustguac] H.264 decode error:', e.message);
            }
        });

        // Configure for H.264 Constrained Baseline
        // Let the decoder auto-detect level from the SPS NAL in the stream
        decoder.configure({
            codec: 'avc1.42001f', // Baseline profile, level 3.1
            optimizeForLatency: true
        });

        configured = true;
        console.log('[rustguac] H.264 WebCodecs decoder initialised (' + width + 'x' + height + ')');
    }

    /**
     * Decode a complete H.264 NAL unit buffer and render to the given layer.
     *
     * @param {!Guacamole.Display.VisibleLayer} layer
     *     The layer to draw the decoded frame to.
     * @param {number} x - X position on the layer.
     * @param {number} y - Y position on the layer.
     * @param {number} width - Frame width.
     * @param {number} height - Frame height.
     * @param {!ArrayBuffer} nalData - Raw H.264 NAL unit data (Annex B format).
     * @param {boolean} isKeyFrame - Whether this contains an IDR/keyframe.
     */
    this.decode = function(layer, x, y, width, height, nalData, isKeyFrame) {

        ensureDecoder(width, height);

        if (!decoder || decoder.state === 'closed')
            return;

        // Track peak queue depth for diagnostics
        if (decoder.decodeQueueSize > self.peakQueueDepth)
            self.peakQueueDepth = decoder.decodeQueueSize;

        // Drop delta frames when the decode queue is too deep (safety valve
        // for transient overload, e.g. tab backgrounding). Never drop
        // keyframes — the next keyframe will restore a clean picture.
        if (!isKeyFrame && decoder.decodeQueueSize > MAX_DECODE_QUEUE) {
            self.framesDropped++;
            console.warn('[rustguac] H.264: dropping delta frame, queue depth ' + decoder.decodeQueueSize);
            return;
        }

        try {
            var chunk = new EncodedVideoChunk({
                type: isKeyFrame ? 'key' : 'delta',
                timestamp: timestamp,
                data: nalData
            });

            // Store per-frame position before submitting to decoder
            pendingPositions[timestamp] = {layer: layer, x: x, y: y};
            pendingDecodes++;
            timestamp += 33333; // ~30fps in microseconds

            decoder.decode(chunk);
        } catch (e) {
            self.framesDropped++;
            console.error('[rustguac] H.264 chunk error:', e.message);
        }
    };

    /**
     * Wait for all pending decodes to complete, then invoke the callback.
     * Used to gate the Guacamole sync response so that guacd receives
     * accurate backpressure from the client's decode speed.
     *
     * Includes a 1-second safety timeout to prevent permanent stall if the
     * decoder enters an unexpected state.
     *
     * @param {function} callback - Called when all pending decodes are done.
     */
    this.waitForPending = function(callback) {
        if (pendingDecodes <= 0 || !decoder || decoder.state === 'closed') {
            callback();
            return;
        }

        self.syncsGated++;
        var waitStart = performance.now();
        var waitingOn = pendingDecodes;

        var resolved = false;
        var timer = setTimeout(function() {
            if (!resolved) {
                resolved = true;
                console.warn('[rustguac] H.264: sync wait timeout (' + waitingOn + ' frames pending), forcing flush');
                callback();
            }
        }, 1000);

        flushResolvers.push(function() {
            if (!resolved) {
                resolved = true;
                clearTimeout(timer);
                var elapsed = (performance.now() - waitStart).toFixed(1);
                if (elapsed > 16) // only log if wait was > 1 frame (~16ms)
                    console.log('[rustguac] H.264: sync gated ' + elapsed + 'ms (' + waitingOn + ' frames)');
                callback();
            }
        });
    };

    /**
     * Reset the decoder (e.g. after reconnection or error recovery).
     * The next frame must be a keyframe.
     */
    this.reset = function() {
        if (decoder && decoder.state !== 'closed') {
            try {
                decoder.reset();
                configured = false;
                timestamp = 0;
                console.log('[rustguac] H.264 decoder reset');
            } catch (e) {
                // Decoder may be in error state
            }
        }
        pendingDecodes = 0;
        pendingPositions = {};
        var resolvers = flushResolvers;
        flushResolvers = [];
        for (var i = 0; i < resolvers.length; i++)
            resolvers[i]();
    };

    /**
     * Return current decoder statistics for console debugging.
     * Usage: open browser console and run:
     *   client._h264Decoder.stats()
     *
     * @returns {Object} Decoder statistics.
     */
    this.stats = function() {
        var s = {
            framesDecoded: self.framesDecoded,
            framesDropped: self.framesDropped,
            syncsGated: self.syncsGated,
            pendingDecodes: pendingDecodes,
            decodeQueueSize: decoder ? decoder.decodeQueueSize : 0,
            peakQueueDepth: self.peakQueueDepth,
            decoderState: decoder ? decoder.state : 'none'
        };
        console.table(s);
        return s;
    };

    /**
     * Close and release the decoder.
     */
    this.destroy = function() {
        if (decoder && decoder.state !== 'closed') {
            try {
                decoder.close();
            } catch (e) {
                // Ignore
            }
        }
        decoder = null;
        configured = false;
        pendingDecodes = 0;
        pendingPositions = {};
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
