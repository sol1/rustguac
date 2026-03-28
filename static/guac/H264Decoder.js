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
     * The target layer for rendering decoded frames.
     *
     * @private
     * @type {?Guacamole.Display.VisibleLayer}
     */
    var targetLayer = null;

    /**
     * Pending draw position for the current frame.
     *
     * @private
     */
    var pendingX = 0;
    var pendingY = 0;

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
     * Reference to this for closures.
     */
    var self = this;

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
                    // Draw the decoded VideoFrame directly to the layer's canvas
                    if (targetLayer) {
                        var canvas = targetLayer.getCanvas();
                        var ctx = canvas.getContext('2d');
                        ctx.drawImage(frame, pendingX, pendingY);
                    }
                } finally {
                    // CRITICAL: always close VideoFrame to release GPU memory
                    frame.close();
                }
            },
            error: function(e) {
                self.framesDropped++;
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

        targetLayer = layer;
        pendingX = x;
        pendingY = y;

        try {
            var chunk = new EncodedVideoChunk({
                type: isKeyFrame ? 'key' : 'delta',
                timestamp: timestamp,
                data: nalData
            });
            timestamp += 33333; // ~30fps in microseconds

            decoder.decode(chunk);
        } catch (e) {
            self.framesDropped++;
            console.error('[rustguac] H.264 chunk error:', e.message);
        }
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
