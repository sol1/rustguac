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
     * Whether a hardware-accelerated configuration has been refused, in which
     * case none is asked for again. See ensureDecoder().
     *
     * @private
     * @type {boolean}
     */
    var hardwareRefused = false;

    /**
     * The codec string most recently configured, so that a change is logged
     * once rather than on every decoder rebuild.
     *
     * @private
     * @type {?string}
     */
    var lastCodec = null;

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
     * Default framebuffer area, in pixels, up to which AVC444 views are
     * combined into 4:4:4. See combineMaxPixels().
     *
     * A fast prior, and no longer the thing that decides. It was 4MP, set
     * against the shader and the plane uploads; those were later measured at
     * under 2ms together, while the cost that matters -- copyTo()'s
     * synchronous prologue -- is not a function of the framebuffer at all
     * once the copy is narrowed to the damaged rows. A 4.93MP Windows
     * session doing desktop work copies 3-5% of its planes and spends ~9ms a
     * picture; the old threshold declined to combine on exactly the sessions
     * that could afford it.
     *
     * So this is now only a ceiling on the worst case a session can open
     * with, before COMBINE_COPY_TRIP_SHARE has had a window to measure it:
     * 4K, beyond which even a banded copy's per-call floor and the whole-plane
     * copy of a resync are more than a session should risk unmeasured.
     * Between that and the measured gate, resolution is no longer the
     * question -- what the screen is doing is.
     *
     * @private
     * @constant
     * @type {!number}
     */
    var COMBINE_MAX_PIXELS = 8300000;

    /**
     * How long a session that gave up combining must stay quiet -- under
     * QUIET_SYNCS_PER_SECOND, with no sync gate timeout -- before its **first**
     * attempt at combining again, in milliseconds. Each further trip doubles
     * it; see recoverWindow().
     *
     * Long, because the point is to distinguish "the video ended" from "the
     * video paused between scenes". Resuming is not free: the first combine
     * after a gap uploads whole planes rather than the damaged rows, which is
     * the most expensive kind of combine there is, and delivering that spike to
     * a client that has just stopped struggling is how a gate makes things
     * worse. The flapping itself is nearly invisible -- only newly painted
     * regions change chroma resolution -- so the cost being avoided here is the
     * resync, not the appearance.
     *
     * @private
     * @constant
     * @type {!number}
     */
    var COMBINE_RECOVER_MS = 30000;

    /**
     * The longest the recovery window may grow to, in milliseconds.
     *
     * A cap on the number of attempts looks like the natural alternative, on
     * the reasoning that a client recovering from transient load and one that
     * simply cannot sustain the combine look identical sample by sample, and
     * only time separates them. That much is true, but a permanent latch is
     * the wrong instrument for it: it condemns the rest of the session for a
     * workload that has passed -- a video at lunchtime would mean reading text
     * at 4:2:0 until the next reconnect -- and it bounds the cost of
     * re-probing no better than backing off does.
     *
     * What re-probing costs is a whole-plane resync (suspendCombining leaves
     * resyncNeeded set, so the first picture back copies and uploads every
     * row) plus the length of a copy window spent combining at a price the
     * client cannot afford, since the gate needs that long to measure and trip
     * again. At 30s between attempts that is around a quarter of the session
     * degraded, indefinitely. Doubling to eight minutes takes it to a few per
     * cent while never giving up: when the load passes, the next attempt
     * sticks.
     *
     * Probing is the only signal there is. A suspended session paints 4:2:0,
     * which never times out and never flushes slowly, so nothing in that state
     * can report that the video has ended -- and QUIET_SYNCS_PER_SECOND cannot
     * either at a framebuffer where both modes run below it. So it must be
     * paid occasionally; backing off is what makes it cheap.
     *
     * @private
     * @constant
     * @type {!number}
     */
    var COMBINE_RECOVER_MAX_MS = 480000;

    /**
     * How long combining must run without tripping before the backoff eases
     * by one doubling.
     *
     * Without this the backoff is monotonic for the life of the session: a
     * video at lunchtime leaves an eight-minute wait standing in front of the
     * evening's first trip, hours later and unrelated. That is the same fault
     * the attempt cap had, only softer -- a session condemned by a workload
     * that has passed.
     *
     * One doubling per clean stretch rather than a reset, so a session that
     * trips just often enough to keep clearing the bar still backs off
     * overall. Five minutes is long enough not to be reached by a recovery
     * window plus a lull, and short enough that a working afternoon returns to
     * the base window.
     *
     * Reachable in a way the cap's forgiveness was not: nothing here is
     * terminal, so a backed-off session always resumes eventually and can
     * accrue the clean time. Under the cap it could not -- combining never
     * restarted, so the clock never ran.
     *
     * @private
     * @constant
     * @type {!number}
     */
    var COMBINE_BACKOFF_DECAY_MS = 300000;

    /**
     * When the current uninterrupted stretch of combining began, or 0.
     *
     * @private
     * @type {!number}
     */
    var combineCleanSince = 0;

    /**
     * Whether the "combining is switched off" note has been made this session.
     *
     * @private
     * @type {!boolean}
     */
    var combineDisabledLogged = false;

    /**
     * How long the session must be calm before the next attempt: the base
     * window doubled once per trip so far, capped.
     *
     * @private
     * @returns {!number}
     */
    function recoverWindow() {
        var doublings = Math.min(Math.max(combineTrips - 1, 0), 16);
        return Math.min(COMBINE_RECOVER_MS * Math.pow(2, doublings),
                COMBINE_RECOVER_MAX_MS);
    }

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
     * When each diagnostic event was last reported, keyed by event name.
     *
     * Diagnostics go to the server and end up in its journal, so they are
     * deduplicated here as well as rate limited there: the conditions being
     * reported (a decoder waiting for a keyframe, frames being abandoned) last
     * for as long as the fault does, and would otherwise report on every frame
     * for the duration.
     *
     * @private
     * @type {Object.<string, number>}
     */
    var diagLastSent = {};

    /**
     * Minimum spacing between reports of the same diagnostic event, in ms.
     *
     * @private
     * @constant
     * @type {number}
     */
    var DIAG_INTERVAL_MS = 30000;

    /**
     * Reports a diagnostic observation to whatever the page has installed as
     * Guacamole.H264Decoder.onDiagnostic, if anything, and to the console
     * either way.
     *
     * What the decoder knows -- that it rebuilt itself, that it is holding
     * every frame until a keyframe the server may not send for minutes, that
     * it gave up on frames -- is invisible from the server, and a console
     * message is no use for a fault that appears once in days on someone
     * else's machine. This is how it reaches the session log.
     *
     * @private
     * @param {!string} event
     *     Short machine-readable event name.
     *
     * @param {!string} detail
     *     Human-readable description.
     *
     * @param {boolean} [always]
     *     Send even if this event was reported within DIAG_INTERVAL_MS. Used
     *     for one-shot transitions, which are meaningful individually.
     */
    function diagnostic(event, detail, always) {

        var now = nowMs();
        if (!always && diagLastSent[event]
                && now - diagLastSent[event] < DIAG_INTERVAL_MS)
            return;

        diagLastSent[event] = now;
        console.warn('[rustguac] H.264 ' + event + ': ' + detail);

        var sink = Guacamole.H264Decoder.onDiagnostic;
        if (sink) {
            try { sink(event, detail); }
            catch (e) { /* a broken sink must not break decoding */ }
        }

    }

    /**
     * Counts of abandoned frames already reported, so that each report covers
     * only what has happened since the last one.
     *
     * @private
     */
    var diagReportedWatchdog = 0;
    var diagReportedSync = 0;

    /**
     * When the decoder started holding frames for want of a keyframe, and how
     * many it has dropped since. A decoder in this state paints nothing at all
     * while the server has no reason to send a keyframe unprompted, so the
     * duration is the length of time the screen was frozen.
     *
     * @private
     */
    var keyframeWaitSince = 0;
    var keyframeWaitDropped = 0;

    /**
     * Reports frames given up on, if any have been since the last report. Both
     * counters are also consumed by the console stats block, which may be off,
     * so this tracks what it has reported rather than resetting them.
     *
     * @private
     */
    function reportAbandoned() {

        var watchdog = watchdogFires - diagReportedWatchdog;
        var sync = syncTimeouts - diagReportedSync;

        if (watchdog <= 0 && sync <= 0)
            return;

        diagReportedWatchdog = watchdogFires;
        diagReportedSync = syncTimeouts;

        diagnostic('frames_abandoned', watchdog + ' frame(s) past the '
                + DECODE_WATCHDOG_MS + 'ms decode watchdog, ' + sync
                + ' sync gate timeout(s). Damage carried by an abandoned '
                + 'frame is never repainted: the server only sends it once.');

    }

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
     * If the backlog is back within the pipeline depth, fire and clear all
     * flush resolvers.
     *
     * The threshold has to be the one waitForPending() gates on. Releasing
     * only at zero meant that once the backlog exceeded the depth it had to
     * drain completely to let a sync through, and a session decoding
     * continuously never reaches zero -- so every sync waited out its full
     * 200ms timeout instead. That reports ~200ms of processing lag upstream
     * whatever the client is actually doing, which guacd answers by holding
     * frame acknowledgements and a self-pacing server answers by stretching
     * its capture interval. The symptom is a stuttering session whose client
     * is not in fact behind, and a console full of sync wait timeouts.
     *
     * It bites AVC444 first because a picture is two access units there, so
     * the backlog is twice as deep for the same frame rate and far less
     * likely to touch zero between frames -- which looks like AVC444 being
     * expensive rather than like a threshold mismatch.
     *
     * @private
     */
    function resolveIfIdle() {
        if (pendingDecodes <= MAX_PIPELINE_DEPTH && flushResolvers.length > 0) {
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
     * How long the framebuffer must keep one size before combining may start,
     * in milliseconds.
     *
     * The size changes several times in the first seconds of a session -- the
     * connect-time fit, then fullscreen -- and one of those steps (2240x1648,
     * 3.7MP) sits under COMBINE_MAX_PIXELS for about four seconds on the way
     * to 2992x2000 (6MP). An auxiliary view arriving inside it switched
     * combining on only for fullscreen to switch it off again, and a session
     * that went through that transition stalled -- one that did not, on the
     * same host, did not. Whether the first auxiliary view landed inside the
     * window was a race, which is why a reload could make it go away. Waiting
     * for the size to settle takes the window out of play.
     *
     * @private
     * @constant
     * @type {!number}
     */
    var COMBINE_SETTLE_MS = 5000;

    /**
     * The framebuffer size last seen, as "WxH", and when it last changed.
     *
     * @private
     */
    var lastFramebufferSize = '';
    var framebufferChangedAt = 0;

    /**
     * Notes the framebuffer's current size, restarting the settle clock if it
     * has changed. Called for every decoded picture: a string compare.
     *
     * @private
     */
    function noteFramebufferSize() {
        if (!display)
            return;
        var size = display.getWidth() + 'x' + display.getHeight();
        if (size !== lastFramebufferSize) {
            lastFramebufferSize = size;
            framebufferChangedAt = nowMs();
        }
    }

    /**
     * Canvas that blackFraction() downscales into.
     *
     * @private
     * @type {?HTMLCanvasElement}
     */
    var blackCanvas = null;

    /**
     * The fraction of a picture that is black, judged from a 64x32 downscale:
     * enough to tell an empty surface from a desktop, at the cost of one small
     * drawImage() and an 8KB read-back per keyframe.
     *
     * @private
     * @param {!(HTMLCanvasElement|OffscreenCanvas|ImageBitmap)} source
     * @returns {?number}
     *     Between 0 and 1, or null for an empty source.
     */
    function blackFraction(source) {

        if (!source.width || !source.height)
            return null;

        if (!blackCanvas) {
            blackCanvas = document.createElement('canvas');
            blackCanvas.width = 64;
            blackCanvas.height = 32;
        }

        var ctx = blackCanvas.getContext('2d', { willReadFrequently: true });
        ctx.clearRect(0, 0, 64, 32);
        ctx.drawImage(source, 0, 0, source.width, source.height, 0, 0, 64, 32);
        var data = ctx.getImageData(0, 0, 64, 32).data;

        var black = 0;
        for (var i = 0; i < data.length; i += 4) {
            var luma = 0.2126 * data[i] + 0.7152 * data[i + 1]
                    + 0.0722 * data[i + 2];
            if (luma < 8)
                black++;
        }

        return black / 2048;

    }

    /**
     * Whether the framebuffer has kept its size for COMBINE_SETTLE_MS. An
     * explicit h264Chroma444=on skips the wait, as it skips every other gate.
     *
     * @private
     * @returns {!boolean}
     */
    function framebufferSettled() {
        if (override('h264Chroma444') === true)
            return true;
        return framebufferChangedAt !== 0
                && nowMs() - framebufferChangedAt >= COMBINE_SETTLE_MS;
    }

    /**
     * Fraction of a keyframe's decoded picture that must be black for it to be
     * withheld, and how long the framebuffer must have kept its size first.
     * See keepPictureOverBlackKeyframe().
     *
     * @private
     * @constant
     */
    var BLACK_KEYFRAME_FRACTION = 0.98;
    var BLACK_KEYFRAME_STABLE_MS = 5000;

    /**
     * Whether a keyframe about to be painted should be withheld instead,
     * leaving the picture already on screen in place.
     *
     * Windows sometimes deletes and recreates its RDPGFX surface at the same
     * size, mid-session, with no resize. The new surface is empty, so its
     * first keyframe decodes black and covers the whole screen -- and Windows
     * then repaints only what it thinks changed, trusting the client still to
     * hold the rest. In the field, guacd logged a same-size Delete+Create-
     * Surface (2992x2000 over 2992x2000) 2-4s before each black-display
     * episode, and at no other time.
     *
     * It is the same Windows behaviour as sol1/rustguac#118, where a resize
     * reallocated the surface and left regions unpainted. The evidence there
     * rules out asking Windows to repaint: a guacd patch sending
     * SuppressOutput off/on and RefreshRect after each resize fired and the
     * black stayed, since Windows does not re-stream its surface cache for
     * either. What fixed it was re-sending pixels the client side already had
     * (patch 005). Under passthrough guacd has none, but the browser does: it
     * is still showing the right picture when the black keyframe arrives. So
     * the keyframe is decoded -- later pictures reference it -- and not
     * painted, and the regions Windows does repaint land on the old picture,
     * which is what Windows assumes the client is showing.
     *
     * Not while the size is changing: after a resize or at connect, Windows
     * repaints everything, and what is on screen is the wrong size anyway.
     * The cost of being wrong is a genuinely black screen shown late, until
     * the next update arrives. h264KeepBlackKeyframes=off disables this.
     *
     * @private
     * @returns {!boolean}
     */
    function keepPictureOverBlackKeyframe(frameState, snapshot) {

        if (!frameState.keyFrame || override('h264KeepBlackKeyframes') === false)
            return false;

        if (!framebufferChangedAt
                || nowMs() - framebufferChangedAt < BLACK_KEYFRAME_STABLE_MS)
            return false;

        /* Both halves are required, and each covers the other's false
         * positive. A screen that has legitimately gone black -- a blank
         * screensaver, a display blanking on lock, a fade to black -- produces
         * no surface recreation, so the flag declines it. A same-size
         * recreation whose picture is real content is not black, so the sample
         * declines that. Content alone suppresses a genuinely black screen and
         * leaves the previous desktop on display; the flag alone suppresses
         * whatever the recreation was carrying, sight unseen. */
        var fraction;
        try {
            fraction = blackFraction(snapshot);
        }
        catch (e) {
            return false;
        }

        if (fraction === null)
            return false;

        var black = fraction >= BLACK_KEYFRAME_FRACTION;

        if (black && !frameState.recreated) {

            /* Reported rather than acted on: withholding on content alone is
             * what the server-side flag exists to stop. One of these with no
             * recreation logged beside it is the shape of an episode the flag
             * does not see. */
            diagnostic('h264_black_keyframe_unarmed', 'a keyframe decoded '
                    + (fraction * 100).toFixed(0) + '% black arrived with '
                    + 'the framebuffer unchanged for '
                    + ((nowMs() - framebufferChangedAt) / 1000).toFixed(0)
                    + 's, but no surface recreation was signalled: painted as '
                    + 'usual', true);

            return false;

        }

        if (!black || !frameState.recreated)
            return false;

        diagnostic('h264_black_keyframe_kept', 'withheld a keyframe decoded '
                + (fraction * 100).toFixed(0) + '% black on a surface the '
                + 'server recreated at its existing size, with the framebuffer '
                + 'unchanged for '
                + ((nowMs() - framebufferChangedAt) / 1000).toFixed(0)
                + 's. Keeping the picture on screen; '
                + 'h264KeepBlackKeyframes=off paints it',
                true);

        return true;

    }

    /**
     * Whether combining is currently given up. See suspendCombining().
     *
     * @private
     * @type {!boolean}
     */
    var combineLatchedOff = false;

    /**
     * When combining was last given up, or 0 if it never has.
     *
     * The recovery window is measured from here rather than only from the
     * quiet and timeout clocks, because neither of those starts at the trip.
     * `lastBusyAt` only moves when a one-second bucket exceeds
     * QUIET_SYNCS_PER_SECOND, and a session slow enough to trip the copy gate
     * never gets there -- measured in the field at 0.5-1.7 syncs/s against a
     * threshold of 10. So `lastBusyAt` sat at its initial 0, `now - 0` passed
     * the window within 30s of page load, there were no timeouts either, and
     * the latch resumed on the very next sync while reporting that it had
     * waited 30s.
     *
     * @private
     * @type {!number}
     */
    var combineLatchedOffAt = 0;

    /**
     * When the last sync gate timeout happened, in ms, or 0 if none has. A
     * suspended session resumes only once COMBINE_RECOVER_MS have passed
     * without one.
     *
     * @private
     * @type {!number}
     */
    var lastSyncTimeoutAt = 0;

    /**
     * How many times combining has been given up this session.
     *
     * @private
     * @type {!number}
     */
    var combineTrips = 0;


    /**
     * Sync timeouts, in ms, charged to combining within the last
     * COMBINE_TIMEOUT_WINDOW_MS.
     *
     * @private
     * @type {!number[]}
     */
    var recentSyncTimeouts = [];

    /**
     * Sync gate timeouts within COMBINE_TIMEOUT_WINDOW_MS that give up
     * combining.
     *
     * Measured at 2992x2000 on the same client and host: 4:2:0 held 0-3% of
     * syncs for a mean of 1.5ms, with no timeouts in thousands; 4:4:4 held 10%
     * for a mean of 271ms, with 25 timeouts a minute -- about four per window.
     * Held syncs outlasted the 200ms timer by up to 140ms, so the combine was
     * blocking the main thread, not only the GPU.
     *
     * @private
     * @constant
     */
    var COMBINE_TIMEOUT_TRIP = 3;
    var COMBINE_TIMEOUT_WINDOW_MS = 10000;

    /**
     * Counts a sync gate timeout, giving up combining when enough land close
     * together while it is on.
     *
     * **Why sync timeouts and not the decode backlog**, which is what this
     * gate watched first. 012's pacing holds each ack until the backlog is
     * within MAX_PIPELINE_DEPTH, so guacd slows to the client's pace and the
     * queue stays short: a client that is merely slow never builds a backlog,
     * and a session combining at 6MP felt much slower while every snapshot
     * read pending=0. The cost lands on the sync gate instead. And a backlog
     * cannot build without timeouts -- every sync waits for the queue to
     * drain and gives up after SYNC_WAIT_TIMEOUT_MS if it does not -- so this
     * also trips before a backlog gate would, on a client that is drowning.
     *
     * **Deliberately a latch and not a controller.** An earlier version
     * measured the combine against a frame budget whose divisor was the
     * interval between pictures, which is what 012's back-pressure has already
     * throttled the server to -- so it read its own output as its input and
     * had to be kept from hunting. This gives up once, one way, and resumes
     * only after a clear window -- doubling each trip, so a client that keeps
     * failing is probed rarely rather than condemned.
     *
     * **And it gates on the symptom, not the cost.** Measuring the combine
     * means timing GPU execution, which needs a gl.finish() per picture --
     * stalling the pipeline this protects -- or timer queries that are not
     * reliably available. A held ack needs neither and is what the user feels.
     *
     * The cost of being wrong is bounded: timeouts caused by something else --
     * a slow link, a struggling decoder -- give up chroma for nothing, which
     * loses a little colour resolution and no frames.
     *
     * @private
     * @param {!string} mode
     *     '444' if the ack was held while combining, '420' otherwise.
     */
    function noteSyncTimeout(mode) {

        /* The operator is driving this by hand: an override is an
         * instruction, not a preference, and a gate that fought it would make
         * the comparison it exists for impossible. */
        if (override('h264Chroma444') !== undefined)
            return;

        var now = nowMs();

        /* Any timeout, combining or not, says the client is not clear of load,
         * and so holds off a resume. */
        lastSyncTimeoutAt = now;

        if (mode !== '444' || !combining || combineLatchedOff)
            return;

        recentSyncTimeouts.push(now);
        while (recentSyncTimeouts.length
                && now - recentSyncTimeouts[0] > COMBINE_TIMEOUT_WINDOW_MS)
            recentSyncTimeouts.shift();

        if (recentSyncTimeouts.length < COMBINE_TIMEOUT_TRIP)
            return;

        suspendCombining(COMBINE_TIMEOUT_TRIP + ' sync gate timeouts in '
                + ((now - recentSyncTimeouts[0]) / 1000).toFixed(1) + 's');

    }

    /**
     * Gives up combining until the load that caused it has passed, counting
     * the trip. Shared by the two trips: sync gate timeouts (the client cannot
     * keep up at all) and slow flushes (it keeps up, but sets the frame rate).
     *
     * Only the latch is set here. Combining stops at the next main view, where
     * the output callback re-checks chroma444Enabled(): a trip can land between
     * a paired main view -- uploaded, deliberately unpainted -- and the
     * auxiliary view that paints it. Stopping in between discards that
     * picture, and if it is a keyframe nothing repaints the screen.
     *
     * @private
     * @param {!string} reason
     *     What tripped it, for the diagnostic.
     */
    function suspendCombining(reason) {

        combineLatchedOff = true;
        combineLatchedOffAt = nowMs();
        combineTrips++;
        recentSyncTimeouts = [];
        flushWindow = null;
        copyWindow = null;
        combineProbing = false;
        combineCopyMs = 0;

        diagnostic('chroma_suspended', 'gave up 4:4:4 combining: ' + reason
                + ' -- the client is setting the frame rate. Painting 4:2:0'
                + ' until the session has been quiet (under '
                + QUIET_SYNCS_PER_SECOND + ' syncs/s, no timeouts) for '
                + (recoverWindow() / 1000) + 's (trip ' + combineTrips
                + '; each one doubles the wait, up to '
                + (COMBINE_RECOVER_MAX_MS / 60000) + ' minutes)'
                + '; window.__h264Chroma444 = true forces it back on now,'
                + ' or the h264Chroma444 key in localStorage across'
                + ' reconnects', true);

    }


    /**
     * Share of wall clock spent inside copyTo() above which a busy window
     * while combining gives the combine up. **The only copy condition.**
     *
     * There is deliberately no mean-per-picture threshold beside it. Requiring
     * both misses the case this gate most needs to catch: xrdp at 1920x1080
     * dragging a VS Code
     * scrollbar ran 39-47 pictures a second at 12ms each -- 46-60% of the main
     * thread, and drags that lost the scrollbar thumb -- while the per-picture
     * figure sat under any sane threshold and vetoed the trip. Many cheap
     * copies is the shape that hurts, and per picture is blind to it by
     * construction.
     *
     * The near-idle desktop a per-picture condition would protect (33-38ms a
     * picture) needs no protecting: it spends 4.6% of the
     * main thread and this declines on its own. Measured shares: Windows idle
     * 4.6%, Windows typing 17-19%, full-screen video ~45%, xrdp scrolling
     * 46-60%, xrdp with glxgears 70%. Every one of them lands on the right
     * side of 30% without help.
     *
     * The pathological case per picture would catch -- one enormous copy
     * against an otherwise idle session -- is covered: a block long enough to
     * matter exceeds SYNC_WAIT_TIMEOUT_MS and the sync-timeout latch takes it.
     *
     * @private
     * @constant
     * @type {!number}
     */
    var COMBINE_COPY_TRIP_SHARE = 0.30;

    /**
     * Mean flush time, in ms, above which a busy window while combining gives
     * the combine up.
     *
     * A flush is the display waiting for the decoder, and under combining
     * that wait is mostly the copy -- flush is roughly copy + decode + the
     * display's own work -- so this is the same cost seen from further
     * downstream, and it is the backstop for congestion the copy share does
     * not explain.
     *
     * Lower thresholds condemn healthy sessions once the copies are banded:
     * the same client at ~12ms of copy a picture flushes at 11.1ms, with
     * decode at 1-3ms and combine at 0.4ms.
     *
     * 30ms is well evidenced: it is what caught the xrdp VS Code scrolling
     * case (`mean flush 30.0ms over 128 syncs in 10s`). Roughly
     * two frames at 60Hz of the display waiting.
     *
     * @private
     * @constant
     * @type {!number}
     */
    var COMBINE_FLUSH_TRIP_MS = 30;


    /**
     * Pictures a window must carry before its mean copy time is acted on.
     * Over COMBINE_FLUSH_WINDOW_MS this is a few a second -- enough to mean
     * something, and low enough that a mostly idle desktop still keeps full
     * chroma, which is where it is worth having.
     *
     * @private
     * @constant
     * @type {!number}
     */
    var COMBINE_COPY_MIN_PICTURES = 30;

    /**
     * The window and sample count used for the **first** measurement after
     * resuming, rather than the full ones above.
     *
     * Resuming during a load that has not passed is a probe, and a probe has
     * to be short, because the whole of it is spent combining at a price the
     * client cannot afford. At the full window that is ten seconds of reduced
     * frame rate every time -- which on sustained video is a visible stutter
     * on a timer, and far worse to watch than its share of the session
     * suggests.
     *
     * It can afford to be short because the answer it needs is not a close
     * one. A session that cannot sustain the combine copies whole planes,
     * measured at ~42ms a picture against a 16ms line; the full window exists
     * to judge the marginal cases that arise while combining is working, not
     * to decide whether a video is still playing.
     *
     * Eight pictures is enough for a mean that is not one outlier, and the
     * resync that every resume begins with is already excluded upstream --
     * flushCombineCost() does not report a picture that uploaded whole planes.
     *
     * @private
     * @constant
     * @type {!number}
     */
    var COMBINE_PROBE_WINDOW_MS = 2000;
    var COMBINE_PROBE_MIN_PICTURES = 8;

    /**
     * Whether the next copy window is the first since resuming.
     *
     * @private
     * @type {!boolean}
     */
    var combineProbing = false;
    var COMBINE_FLUSH_WINDOW_MS = 10000;
    var COMBINE_FLUSH_MIN_SYNCS = 100;

    /**
     * The flush window in progress while combining, or null.
     *
     * @private
     * @type {?{start: number, syncs: number, sumMs: number}}
     */
    var flushWindow = null;

    /**
     * The copy window in progress while combining, or null.
     *
     * @private
     */
    var copyWindow = null;

    /**
     * Synchronous copy time accumulated for the picture being combined, in
     * ms, across both of its views.
     *
     * @private
     */
    var combineCopyMs = 0;

    /**
     * Counts one sync's flush while combining, and gives combining up at the
     * end of a busy window whose mean flush is over COMBINE_FLUSH_TRIP_MS.
     *
     * @private
     */
    function noteCombineCopy(copyMs) {

        if (override('h264Chroma444') !== undefined || !combining
                || combineLatchedOff || !(copyMs > 0)) {
            copyWindow = null;
            return;
        }

        var now = nowMs();

        if (!copyWindow)
            copyWindow = { start: now, pictures: 0, sumMs: 0 };

        copyWindow.pictures++;
        copyWindow.sumMs += copyMs;

        var probing = combineProbing;
        var windowMs = probing
            ? COMBINE_PROBE_WINDOW_MS : COMBINE_FLUSH_WINDOW_MS;
        var minPictures = probing
            ? COMBINE_PROBE_MIN_PICTURES : COMBINE_COPY_MIN_PICTURES;

        /* Both conditions, and the window is never thrown away for failing
         * the count. Discarding it meant a session below the sample rate --
         * three pictures a second, which at a large framebuffer is an
         * ordinary rate and exactly where the combine hurts -- never reached
         * a verdict at all, and combined indefinitely at whatever it cost. */
        if (now - copyWindow.start < windowMs
                || copyWindow.pictures < minPictures)
            return;

        var mean = copyWindow.sumMs / copyWindow.pictures;
        var copyMsInWindow = copyWindow.sumMs;
        var pictures = copyWindow.pictures;
        var span = now - copyWindow.start;
        copyWindow = null;
        combineProbing = false;

        var share = span > 0 ? copyMsInWindow / span : 0;

        if (share > COMBINE_COPY_TRIP_SHARE)
            suspendCombining((probing ? 'probe: ' : '')
                    + (share * 100).toFixed(0) + '% of the main thread spent'
                    + ' copying, over the '
                    + (COMBINE_COPY_TRIP_SHARE * 100).toFixed(0)
                    + '% the combine is worth (' + pictures + ' pictures in '
                    + (span / 1000).toFixed(1) + 's, ' + mean.toFixed(1)
                    + 'ms each)');

    }

    function noteCombineFlush(flushMs) {

        if (override('h264Chroma444') !== undefined || !combining
                || combineLatchedOff || typeof flushMs !== 'number') {
            flushWindow = null;
            return;
        }

        var now = nowMs();
        if (!flushWindow)
            flushWindow = { start: now, syncs: 0, sumMs: 0 };

        flushWindow.syncs++;
        flushWindow.sumMs += flushMs;

        if (now - flushWindow.start < COMBINE_FLUSH_WINDOW_MS)
            return;

        var mean = flushWindow.sumMs / flushWindow.syncs;
        var syncs = flushWindow.syncs;
        var span = now - flushWindow.start;
        flushWindow = null;

        if (syncs >= COMBINE_FLUSH_MIN_SYNCS && mean > COMBINE_FLUSH_TRIP_MS)
            suspendCombining('mean flush ' + mean.toFixed(1) + 'ms over '
                    + syncs + ' syncs in ' + (span / 1000).toFixed(0)
                    + 's, over the ' + COMBINE_FLUSH_TRIP_MS + 'ms a '
                    + 'combining client is expected to stay within');

    }

    /**
     * Syncs per second at or under which the session counts as quiet, for
     * resuming. See maybeResumeCombining().
     *
     * @private
     * @constant
     * @type {!number}
     */
    var QUIET_SYNCS_PER_SECOND = 10;

    /**
     * When the session was last busier than QUIET_SYNCS_PER_SECOND, measured
     * over one-second buckets; and the bucket in progress.
     *
     * @private
     */
    var lastBusyAt = 0;
    var busyBucket = null;

    /**
     * Counts a sync towards the busy/quiet measure.
     *
     * @private
     */
    function noteActivity() {
        var now = nowMs();
        if (!busyBucket || now - busyBucket.start >= 1000) {
            if (busyBucket && busyBucket.syncs > QUIET_SYNCS_PER_SECOND)
                lastBusyAt = now;
            busyBucket = { start: now, syncs: 0 };
        }
        busyBucket.syncs++;
    }

    /**
     * Lets a suspended session try combining again, once it has gone
     * COMBINE_RECOVER_MS without a sync gate timeout. Checked on every sync,
     * which is where a timeout would show. Resuming only clears the latch:
     * combining itself restarts at the next auxiliary view, through the same
     * area check as at connect.
     *
     * @private
     */
    function maybeResumeCombining() {

        var now = nowMs();

        /* Combining and holding up: the backoff eases, so the session is not
         * carrying this morning's video into tonight's first trip. */
        if (!combineLatchedOff) {

            if (combining && combineTrips > 0 && combineCleanSince
                    && now - combineCleanSince >= COMBINE_BACKOFF_DECAY_MS) {

                combineTrips--;
                combineCleanSince = now;

                diagnostic('chroma_backoff_eased', 'combining has held up for '
                        + (COMBINE_BACKOFF_DECAY_MS / 60000) + ' minutes; the '
                        + 'wait after the next trip drops to '
                        + (recoverWindow() / 1000) + 's', true);

            }

            return;

        }

        var window = recoverWindow();

        /* Three clocks, all against the backed-off window. The first is what
         * guarantees a window exists at all: the other two can both be older
         * than the trip, and on a session slow enough to trip they always are.
         *
         * Not merely timeout-free: 4:2:0 never times out and never flushes
         * slowly, so that alone would resume in the middle of the video that
         * tripped it. Quiet is what says the motion has passed -- as far as
         * anything can, from a state that generates no signal. */
        if (now - combineLatchedOffAt < window
                || now - lastSyncTimeoutAt < window
                || now - lastBusyAt < window)
            return;

        combineLatchedOff = false;
        combineProbing = true;
        combineCleanSince = now;

        diagnostic('chroma_resumed', 'resuming 4:4:4 combining: '
                + ((now - combineLatchedOffAt) / 1000).toFixed(0)
                + 's since giving up, quiet and with no sync gate timeout for '
                + (window / 1000) + 's (trip ' + combineTrips + '; the next '
                + 'wait would be ' + (Math.min(window * 2,
                    COMBINE_RECOVER_MAX_MS) / 1000) + 's)', true);

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
     * Releases a frame's snapshot, whatever kind it is. The 4:2:0 path
     * snapshots into a pooled canvas; the combine path renders offscreen and
     * hands the drawing buffer over as an ImageBitmap, which owns GPU memory
     * until it is closed and belongs to no pool.
     *
     * @private
     * @param {HTMLCanvasElement|ImageBitmap} snapshot - The snapshot, if any.
     */
    function releaseSnapshot(snapshot) {

        if (!snapshot)
            return;

        if (typeof ImageBitmap !== 'undefined'
                && snapshot instanceof ImageBitmap) {
            try {
                snapshot.close();
            } catch (ignore) {
                /* Already closed */
            }
            return;
        }

        releaseCanvas(snapshot);

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
     * Whether the renderer has been told this stream's colour space. Applied
     * from the first main-view frame and not revisited: a decoder replaced
     * mid-session re-runs this, but the stream's signalling does not change
     * frame to frame, and reading it per frame would be pure overhead.
     *
     * @private
     * @type {!boolean}
     */
    var colorSpaceApplied = false;

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
     * Whether rustguac has said it is removing the AVC444 auxiliary view from
     * the wire, so no picture the combiner is holding a main view for will
     * ever arrive.
     *
     * The server is asked because the browser cannot tell. Combining is
     * switched on by an auxiliary view and off by nothing in particular, and
     * the auxiliary IDRs are deliberately kept -- so one of those arms it and
     * every main view afterwards pays a plane read-back, six texture uploads
     * and a shader pass to produce the ordinary 4:2:0 picture drawImage()
     * would have produced almost free. Measured on a Windows session with the
     * drop active: 163 pictures in 10s at 19.0ms of copying each, 31% of the
     * main thread, until the copy gate gave up 4:4:4 for a reason that was
     * true and beside the point.
     *
     * Inferring it from a quiet stretch was the alternative and is guessing:
     * Windows sends chroma in about one picture in eight and the xrdp fork's
     * CHROMA_INTERVAL sends it rarer still, so a silence long enough to be
     * evidence has already cost the session, and each wrong guess costs a
     * whole-plane resync on the way back.
     *
     * @private
     * @type {!boolean}
     */
    var auxDropped = false;


    /**
     * Whether the picture currently being combined had to upload whole planes
     * because the textures were stale. Such a picture is the most expensive
     * kind of combine there is, so it is not representative of what combining
     * costs in the steady state and is left out of the diagnostic.
     *
     * @private
     * @type {!boolean}
     */
    var combineResynced = false;

    /**
     * Whether the renderer's textures no longer hold the previous picture, so
     * the next combine must upload whole planes rather than the damaged rows.
     *
     * Banded upload assumes every row outside the damage still holds what it
     * held last picture. That stops being true the moment a picture is painted
     * without being combined: the screen moved on and the textures did not.
     *
     * @private
     * @type {!boolean}
     */
    var resyncNeeded = true;

    /**
     * Work already done for the current picture's main view, carried across to
     * the auxiliary view that completes it so the gate is charged once per
     * picture rather than once per view.
     *
     * @private
     * @type {!number}
     */
    var combineWorkMs = 0;

    /**
     * Per-picture combine cost, split by whether the picture carried an
     * auxiliary view. Off unless h264CombineLog is set.
     *
     * The gate averages every picture into one figure, which is the right
     * input for deciding whether combining is affordable but the wrong one
     * for finding a stutter. A server sending chroma every Nth picture makes
     * one picture in N several times dearer than its neighbours, and a mean
     * taken across both hides exactly that: throughput looks healthy while
     * the session hitches N times a second. Splitting the two says whether a
     * long tail lives in the chroma pictures or is spread across all of them
     * -- the first is the combine's fault and can be gated, the second is the
     * decode's and cannot.
     *
     * @private
     */
    var stats = null;

    /**
     * Events since the last diagnostic report: plane read-backs and the two
     * ways a frame can be given up on.
     *
     * The read-back wait is the gap this instrument was missing. Combine cost
     * is deliberately timed as work and not wait, so that the gate cannot feed
     * on its own backlog -- which also means a slow copyTo(), a GPU-to-CPU
     * transfer at HiDPI rather than the memcpy a software decoder makes it,
     * does not appear in it at all. The wait includes queueing behind earlier
     * pictures on purpose: that is what a backlog looks like from here.
     *
     * @private
     */
    var copyWait = null;
    var watchdogFires = 0;
    var syncTimeouts = 0;

    /**
     * The picture size of the last main view combined, as [w, h], or null.
     * A copy narrowed to the damaged rows may only be uploaded into textures
     * that already exist at the current size, so the first picture at a new
     * size is copied whole.
     *
     * @private
     */
    var lastPictureSize = null;

    /**
     * The plane size of the last auxiliary view combined, as [w, h], or null.
     * Tracked apart from the picture's: the v1 layout pads the auxiliary
     * frame to a multiple of 16 rows, so the two are not the same number.
     *
     * @private
     */
    var lastAuxSize = null;

    /**
     * Rows are rounded outward to a multiple of this before being copied.
     *
     * Two reasons, neither about correctness -- the bands the renderer uploads
     * are computed from the rects independently and are always inside this.
     * It keeps the number of distinct copy sizes down, so the buffer pool
     * keeps hitting (it is keyed by exact length, four deep per size), and it
     * keeps the origin even, which chroma subsampling requires.
     *
     * @private
     * @constant
     * @type {!number}
     */
    var COPY_BAND_ALIGN = 16;

    /**
     * The share of the plane a band may span before the whole frame is copied
     * instead.
     *
     * Not a tuning constant -- it keeps the copy and the upload agreeing.
     * Yuv444.js's merge() gives up and returns no bands at all once the
     * damage covers BAND_LIMIT (0.75) of a plane, and a partial copy with no
     * bands to upload it into has to be thrown away and resynced. Half is
     * comfortably under that for the chroma planes too, which are half the
     * height and so reach the limit sooner, and by the time damage spans half
     * the screen the copy saves little anyway.
     *
     * @private
     * @constant
     * @type {!number}
     */
    var COPY_BAND_MAX_SPAN = 0.5;

    /**
     * More regions than this and the renderer uploads whole planes, so a
     * narrowed copy would have nothing to land in. Mirrors MAX_CLIP_RECTS in
     * Yuv444.js.
     *
     * @private
     * @constant
     * @type {!number}
     */
    var COPY_BAND_MAX_RECTS = 32;

    /**
     * Most separate copies one view may be split into.
     *
     * Each is a fixed stall, and the gap rule below only guarantees that each
     * extra one pays for itself -- it does not bound how many there are. Four
     * is enough for the shapes that motivate this (an editor and a clock, a
     * terminal and a status bar) without letting a busy screen spend its
     * budget on per-call overhead.
     *
     * @private
     * @constant
     * @type {!number}
     */
    var COPY_BAND_MAX_BANDS = 4;

    /**
     * The two halves of the copy's measured cost, used to decide when a gap
     * between damaged regions is worth a second copy rather than being read
     * through.
     *
     * Fitted on a Windows client with hardware decode, against a
     * Windows host at 2992x1648: 28 `copy` windows spanning 0.15MP to 4.96MP,
     * giving **10ms + 5ms/MP**, R-squared 0.90, with bucketed residuals inside
     * 2ms across the whole range.
     *
     * Fit only large copies and the intercept goes wrong: two points at
     * 4.93MP and 1.72MP give 2.7ms + 6.5ms/MP, an extrapolation off a short
     * lever arm that predicts 3.6ms at 0.15MP where eight measured copies
     * averaged **11.8ms**. The two models agree to 0.4ms at 4.93MP and differ
     * only where the short one has no data -- and small copies are exactly
     * what banding produces.
     *
     * Erring low on the fixed cost is not the conservative choice. The
     * threshold is `FIXED * rowsPerMs * FACTOR`, so a *smaller* fixed cost
     * makes splitting *easier*: it buys more copies and smaller ones, each
     * costing more than it was budgeted.
     *
     * At 2992 wide the minimum worthwhile gap is about 1280 rows, so a second
     * copy has to skip roughly 4MP of transfer to
     * pay for itself. That is deliberate and it is what the arithmetic says:
     * at 10ms a call and 5ms/MP, nothing smaller earns the stall. It does not
     * touch the win banding was built for, which is cropping one copy to the
     * damaged rows rather than reading whole planes; what it removes is the
     * marginal second and third copy. The case that still splits is the one
     * that motivated splitting -- a clock in one corner and a caret in the
     * other, with most of a 1648-row frame between them.
     *
     * Both numbers are properties of one client's GPU and driver. What is not
     * machine-specific is that the fixed part is the larger term for any copy
     * a banded picture makes, and that measuring it needs small copies in the
     * sample.
     *
     * @private
     * @constant
     * @type {!number}
     */
    var COPY_BAND_FIXED_MS = 10;
    var COPY_BAND_MS_PER_MP = 5;

    /**
     * How many times over a gap must pay for the copy it costs before it is
     * worth splitting. At 1 the split merely breaks even, which is not worth
     * the extra call's variance; 2 asks it to save twice what it costs.
     *
     * @private
     * @constant
     * @type {!number}
     */
    var COPY_BAND_GAP_FACTOR = 2;

    /**
     * The smallest gap between damaged regions worth skipping with a second
     * copy rather than reading straight through, in plane rows.
     *
     * Derived rather than constant because it depends on the width: skipping
     * a row saves `planeW` pixels of transfer, so a narrow plane needs a much
     * bigger gap to pay for the same fixed stall. At 2992 wide it comes to
     * about 308 rows.
     *
     * @private
     */
    function minWorthwhileGap(planeW) {

        if (!planeW)
            return Infinity;

        var rowsPerMs = 1e6 / (COPY_BAND_MS_PER_MP * planeW);

        return Math.max(COPY_BAND_ALIGN,
                Math.ceil(COPY_BAND_FIXED_MS * rowsPerMs
                    * COPY_BAND_GAP_FACTOR));

    }

    /**
     * The rects that fall inside one band, clipped to it, in picture
     * coordinates.
     *
     * Safe for the auxiliary view's layouts as well as the main view's,
     * because the band's edges are multiples of 16 in picture rows and
     * `auxV1LumaBands()` rounds to the same grid -- so a rect clipped to a
     * band maps to plane rows inside that band. Pinned in
     * tests/h264-copy-band.mjs.
     *
     * @private
     */
    function clipRectsToBand(rects, band) {

        var out = [];
        var y0 = band.y0;
        var y1 = band.y0 + band.h;

        for (var i = 0; i < rects.length; i++) {

            var top = Math.max(y0, rects[i].y | 0);
            var bottom = Math.min(y1,
                    (rects[i].y | 0) + (rects[i].height | 0));

            if (bottom > top)
                out.push({ x: rects[i].x, y: top,
                           width: rects[i].width, height: bottom - top });

        }

        return out;

    }

    /**
     * How the copy band came out, over the reporting window, or null.
     *
     * The band is a single bounding span, so scattered damage costs exactly
     * what solid damage does: two thin rects a thousand rows apart span a
     * thousand rows. Whether that is worth fixing with multiple copies --
     * each costs ~2.7ms of fixed stall, so a second one pays only if it skips
     * more than ~139 rows -- depends entirely on what real damage looks like,
     * which nothing so far measures.
     *
     * `damage` is the rows actually touched, merged; `span` is the rows the
     * band therefore has to copy. The two being far apart on the declined
     * copies is the whole case for multi-band, and their being close is the
     * case for leaving it alone.
     *
     * @private
     */
    var bandStats = null;

    /**
     * Records one main view's band outcome. Only under h264CombineLog: the
     * merged damage total below is cheap but not free, and nothing acts on
     * these.
     *
     * @private
     */
    function noteBand(outcome, spanRows, rects, planeH, isAux, nbands) {

        if (!override('h264CombineLog'))
            return;

        if (!bandStats)
            bandStats = { banded: 0, spanSum: 0, damageSum: 0,
                          whole: 0, tooMany: 0, tooWide: 0,
                          wideSpanSum: 0, wideDamageSum: 0,
                          aux: 0, auxBanded: 0, auxSpanSum: 0,
                          auxDamageSum: 0, bandsSum: 0, auxBandsSum: 0,
                          auxWhole: 0, auxTooMany: 0, auxTooWide: 0,
                          auxWideSpanSum: 0, auxWideDamageSum: 0 };

        /* Merged, so overlapping rects are not counted twice. */
        var damage = 0;
        if (rects && rects.length) {
            var iv = [];
            for (var i = 0; i < rects.length; i++)
                iv.push([rects[i].y | 0,
                        (rects[i].y | 0) + (rects[i].height | 0)]);
            iv.sort(function(a, b) { return a[0] - b[0]; });
            var lo = iv[0][0];
            var hi = iv[0][1];
            for (var j = 1; j < iv.length; j++) {
                if (iv[j][0] <= hi)
                    hi = Math.max(hi, iv[j][1]);
                else {
                    damage += hi - lo;
                    lo = iv[j][0];
                    hi = iv[j][1];
                }
            }
            damage += hi - lo;
        }

        if (isAux) {

            bandStats.aux++;

            if (outcome === 'banded') {
                bandStats.auxBanded++;
                bandStats.auxSpanSum += spanRows / planeH;
                bandStats.auxDamageSum += damage / planeH;
                bandStats.auxBandsSum += nbands || 1;
            }
            else if (outcome === 'whole')
                bandStats.auxWhole++;
            else if (outcome === 'tooMany')
                bandStats.auxTooMany++;
            else {
                /* The one that matters on a server accumulating chroma
                 * across frames: an auxiliary view carries the union of the
                 * damage since the last one, so its declared regions are
                 * inherently larger than a main view's and reach the span
                 * limit sooner. Reported so that is distinguishable from a
                 * server declaring nothing at all. */
                bandStats.auxTooWide++;
                bandStats.auxWideSpanSum += spanRows / planeH;
                bandStats.auxWideDamageSum += damage / planeH;
            }

            return;

        }

        if (outcome === 'banded') {
            bandStats.banded++;
            bandStats.spanSum += spanRows / planeH;
            bandStats.damageSum += damage / planeH;
            bandStats.bandsSum += nbands || 1;
        }
        else if (outcome === 'whole')
            bandStats.whole++;
        else if (outcome === 'tooMany')
            bandStats.tooMany++;
        else {
            bandStats.tooWide++;
            bandStats.wideSpanSum += spanRows / planeH;
            bandStats.wideDamageSum += damage / planeH;
        }

    }

    /**
     * The rows a view's regions touch, as a list of {y0, h} bands in plane
     * rows, or null to copy the whole frame.
     *
     * This is the one stage of the pipeline that was still reading
     * everything. The plane uploads are banded to the damage and the shader
     * is scissored to it, but copyTo() was handed the whole coded frame every
     * picture -- and copyTo()'s synchronous half is ~92% area-proportional at
     * roughly 6.5ms per megapixel, which made it about 70% of the main thread
     * at 4.93MP. Reading only the damaged rows cuts it in proportion.
     *
     * **Several bands rather than one**, because a single bounding span is
     * defeated by anything scattered: a clock in one corner and a caret in
     * the other span the whole screen between them, and a desktop reliably
     * has both. Each extra band costs a fixed stall, so two regions are only
     * worth separating when the gap between them saves more transfer than the
     * call costs -- see minWorthwhileGap().
     *
     * @private
     */
    function copyBandsFor(rects, planeH, planeW, isAux) {

        if (override('h264CopyBands') === false)
            return null;

        if (!rects || !rects.length) {
            noteBand('whole', planeH, rects, planeH, isAux);
            return null;
        }

        if (rects.length > COPY_BAND_MAX_RECTS) {
            noteBand('tooMany', planeH, rects, planeH, isAux);
            return null;
        }

        /* Each rect's rows, rounded outward to the alignment before anything
         * is merged, so every band edge is on the grid the auxiliary view's
         * v1 layout needs. */
        var spans = [];

        for (var i = 0; i < rects.length; i++) {

            var top = rects[i].y | 0;
            var bottom = top + (rects[i].height | 0);

            if (bottom <= top)
                continue;

            top = Math.max(0,
                    Math.floor(top / COPY_BAND_ALIGN) * COPY_BAND_ALIGN);
            bottom = Math.min(planeH,
                    Math.ceil(bottom / COPY_BAND_ALIGN) * COPY_BAND_ALIGN);

            if (bottom > top)
                spans.push([top, bottom]);

        }

        if (!spans.length) {
            noteBand('whole', planeH, rects, planeH, isAux);
            return null;
        }

        spans.sort(function(a, b) { return a[0] - b[0]; });

        /* Merged where they overlap, touch, or sit closer than a gap worth
         * skipping. */
        var minGap = minWorthwhileGap(planeW);
        var bands = [{ y0: spans[0][0], y1: spans[0][1] }];

        for (var j = 1; j < spans.length; j++) {

            var last = bands[bands.length - 1];

            if (spans[j][0] - last.y1 < minGap)
                last.y1 = Math.max(last.y1, spans[j][1]);
            else
                bands.push({ y0: spans[j][0], y1: spans[j][1] });

        }

        /* Bounded by closing the cheapest gaps first, so what survives is the
         * splits that save most. */
        while (bands.length > COPY_BAND_MAX_BANDS) {

            var at = 1;
            var smallest = Infinity;

            for (var k = 1; k < bands.length; k++) {
                var gap = bands[k].y0 - bands[k - 1].y1;
                if (gap < smallest) {
                    smallest = gap;
                    at = k;
                }
            }

            bands[at - 1].y1 = Math.max(bands[at - 1].y1, bands[at].y1);
            bands.splice(at, 1);

        }

        var rows = 0;
        for (var m = 0; m < bands.length; m++)
            rows += bands[m].y1 - bands[m].y0;

        /* Little enough saved that the whole-plane copy is the simpler and
         * the safer path -- and past merge()'s BAND_LIMIT the renderer would
         * decline to band the upload, leaving a partial copy with nowhere to
         * land. */
        if (rows >= planeH * COPY_BAND_MAX_SPAN) {
            noteBand('tooWide', rows, rects, planeH, isAux);
            return null;
        }

        var out = [];
        for (var n = 0; n < bands.length; n++)
            out.push({ y0: bands[n].y0, h: bands[n].y1 - bands[n].y0 });

        noteBand('banded', rows, rects, planeH, isAux, out.length);
        return out;

    }

    /**
     * Records one sample against a named stage, split by whether the picture
     * carried an auxiliary view, and reports every few seconds. Cheap enough
     * to leave in the path: one comparison when off.
     *
     * Three stages between the wire and the screen, so that time unaccounted
     * for by one is visible in the next rather than inferred:
     *
     *   decode   decode() submitted to the frame arriving in output(). The
     *            decoder's own cost plus anything queued inside it. An
     *            auxiliary view is coded full-frame while a main view codes
     *            damage only, so this is where that asymmetry would show.
     *   combine  read-back, plane upload, conversion and transfer.
     *   draw     the frame being ready to it reaching the layer, which is
     *            time spent in the display's ordered task queue rather than
     *            doing work.
     *
     *   paint    the blit from the snapshot into the display's layer. Split
     *            by which kind of surface crossed that boundary rather than
     *            by chroma: the 4:2:0 path hands over a 2D canvas, the
     *            combine path a GPU-resident ImageBitmap produced by a
     *            different (WebGL2) context. If that second handoff is a
     *            readback rather than a texture share it is area-proportional
     *            and vendor-independent, which is the shape the field numbers
     *            have -- so this is reported per megapixel as well as per
     *            picture, since a readback's cost tracks pixels and a texture
     *            share's does not.
     *
     * @private
     * @param {!string} stage - 'decode', 'combine', 'draw' or 'paint'.
     * @param {!(boolean|string)} variant - Whether the picture carried an
     *                                      auxiliary view, or an explicit
     *                                      bucket name for stages not split
     *                                      that way.
     * @param {!number} ms - The sample.
     * @param {number} [pixels] - Pixels this sample covered, where the stage
     *                            has a meaningful area. Reported as ms/MP.
     */
    function recordStat(stage, variant, ms, pixels) {

        if (!override('h264CombineLog'))
            return;

        var now = nowMs();

        if (!stats)
            stats = { since: now };

        var key = stage + ':' + (typeof variant === 'string' ? variant
                : (variant ? 'chroma' : 'luma'));
        var bucket = stats[key]
                || (stats[key] = { n: 0, sum: 0, max: 0, px: 0 });

        bucket.n++;
        bucket.sum += ms;
        bucket.px += pixels || 0;
        if (ms > bucket.max)
            bucket.max = ms;

        if (now - stats.since < 5000)
            return;

        function one(b) {
            if (!b || !b.n)
                return 'none';
            return b.n + ' mean ' + (b.sum / b.n).toFixed(1)
                    + ' max ' + b.max.toFixed(1)
                    + (b.px ? ' ' + (b.sum / (b.px / 1e6)).toFixed(2)
                        + 'ms/MP' : '');
        }

        var lines = ['[rustguac] H.264 over '
                + ((now - stats.since) / 1000).toFixed(1) + 's, ms:'];

        ['decode', 'issue', 'alloc', 'buf', 'copy', 'combine', 'draw',
                'queue'].forEach(function(name) {
            lines.push('  ' + (name + '     ').slice(0, 8)
                    + 'chroma ' + one(stats[name + ':chroma'])
                    + '  |  luma ' + one(stats[name + ':luma']));
        });


        if (bandStats) {

            var b = bandStats;
            var tried = b.banded + b.whole + b.tooMany + b.tooWide;
            var pct = function(x) { return (100 * x).toFixed(0) + '%'; };

            lines.push('  band    ' + tried + ' main views: banded ' + b.banded
                    + (tried ? ' (' + pct(b.banded / tried) + ')' : '')
                    + (b.banded ? ' copied ' + pct(b.spanSum / b.banded)
                        + ' damage ' + pct(b.damageSum / b.banded)
                        + ' in ' + (b.bandsSum / b.banded).toFixed(1)
                        + ' bands' : '')
                    + '  |  declined ' + (b.whole + b.tooMany + b.tooWide)
                    + ': ' + b.whole + ' no-rects, ' + b.tooMany + ' >'
                    + COPY_BAND_MAX_RECTS + ' rects, ' + b.tooWide + ' wide'
                    + (b.tooWide ? ' (span ' + pct(b.wideSpanSum / b.tooWide)
                        + ' damage ' + pct(b.wideDamageSum / b.tooWide) + ')'
                        : ''));

            if (b.aux)
                lines.push('          aux ' + b.aux + ' views: banded '
                        + b.auxBanded + ' (' + pct(b.auxBanded / b.aux) + ')'
                        + (b.auxBanded
                            ? ' copied ' + pct(b.auxSpanSum / b.auxBanded)
                                + ' damage ' + pct(b.auxDamageSum / b.auxBanded)
                                + ' in '
                                + (b.auxBandsSum / b.auxBanded).toFixed(1)
                                + ' bands'
                            : '')
                        + (b.auxBanded < b.aux
                            ? '  |  declined ' + (b.aux - b.auxBanded) + ': '
                                + b.auxWhole + ' no-rects, ' + b.auxTooMany
                                + ' >' + COPY_BAND_MAX_RECTS + ' rects, '
                                + b.auxTooWide + ' wide'
                                + (b.auxTooWide
                                    ? ' (copied '
                                        + pct(b.auxWideSpanSum / b.auxTooWide)
                                        + ' damage '
                                        + pct(b.auxWideDamageSum / b.auxTooWide)
                                        + ')'
                                    : '')
                            : ''));

        }

        var tail = [];
        if (copyWait && copyWait.n)
            tail.push('read-back wait mean '
                    + (copyWait.sum / copyWait.n).toFixed(1) + ' max '
                    + copyWait.max.toFixed(1));
        if (watchdogFires || syncTimeouts)
            tail.push('GIVEN UP: ' + watchdogFires + ' watchdog, '
                    + syncTimeouts + ' sync timeout');
        if (tail.length)
            lines.push('  ' + tail.join('  |  '));

        console.log(lines.join('\n'));

        stats = null;
        copyWait = null;
        bandStats = null;
        watchdogFires = 0;
        syncTimeouts = 0;

    }

    /**
     * A monotonic clock in milliseconds, falling back where performance is
     * absent.
     *
     * @private
     * @returns {!number}
     */
    /**
     * Forces the renderer's outstanding GPU work to complete, so that the
     * combine timing that follows measures execution rather than submission.
     *
     * Costs a pipeline stall, so it happens only when h264CombineLog has asked
     * for numbers. Without it the log reports the combine at well under a
     * millisecond while tests/bench, which does force completion, measures
     * ~1.37ms per megapixel for the same work -- a discrepancy that has twice
     * been read as the combine being cheap.
     *
     * @private
     */
    function finishForTiming() {
        if (yuv444 && yuv444.finish && override('h264CombineLog'))
            yuv444.finish();
    }

    function nowMs() {
        return (typeof performance !== 'undefined' && performance.now)
            ? performance.now() : Date.now();
    }


    /**
     * Serialises the work that follows plane read-back. Both views of a
     * picture write into the same set of textures, and the auxiliary view
     * refines what the main view uploaded, so the uploads have to happen in
     * decode order -- out of order, one picture's chroma is combined into
     * another's luma.
     *
     * Only the uploads are ordered, not the copies themselves. Each copyTo()
     * is issued as soon as its frame arrives, into a buffer of its own, and
     * this chain merely waits for it in turn. Chaining the call instead left
     * the two views of a picture strictly sequential, so every picture paid
     * two round trips to the GPU end to end rather than overlapping them.
     *
     * @private
     * @type {!Promise}
     */
    var copyChain = Promise.resolve();

    /**
     * Whether a main view has been uploaded and deferred, awaiting the
     * auxiliary view that will paint the picture, and the regions that main
     * view declared valid -- null meaning the whole picture.
     *
     * The two views carry separate region rects, and the picture they combine
     * to is valid wherever either one says it is. While both views painted,
     * each painted its own; with the main view's paint dropped, its regions
     * would go unpainted unless they are carried over to the view that does
     * paint.
     *
     * @private
     */
    var deferredMain = false;
    var deferredMainRects = null;

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
            diagnostic('chroma_unavailable', '4:4:4 combining unavailable '
                    + '(needs WebGL2 and VideoFrame.copyTo); AVC444 will '
                    + 'render at 4:2:0', true);
            yuv444Unavailable = true;
            return null;
        }

        yuv444 = new Guacamole.Yuv444Renderer();
        colorSpaceApplied = false;

        if (!yuv444.supported) {
            yuv444 = null;
            yuv444Unavailable = true;
            return null;
        }

        console.log('[rustguac] H.264: combining AVC444 views to 4:4:4');
        return yuv444;

    }

    /**
     * Overrides already read from the query string or localStorage, by name.
     * Neither source can change without a reload, so each is read once.
     *
     * @private
     * @type {!Object.<string, *>}
     */
    var storedOverrides = {};

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

        /* The window global above is a property read and is checked every
         * time, so setting one still takes effect mid-session -- which is the
         * point of these, since one build is meant to compare 4:2:0, combined
         * and combined-plus-filtered without a reload.
         *
         * The query string and localStorage cannot change without a reload,
         * and reading them is not free: URLSearchParams parses the whole query
         * on construction and localStorage is a synchronous, disk-backed read.
         * On the combine path this ran twice per picture -- 60 times a second
         * on the main thread -- for a value that was fixed before the first
         * frame arrived. */
        if (name in storedOverrides)
            return storedOverrides[name];

        /* The query string is read, but on a live session it cannot be
         * reached: client.html builds `/client/{id}?name=...` itself on every
         * launch and relaunch and drops anything added by hand, so a pasted
         * parameter lasts until the first reconnect and no longer. It is the
         * usable form only on the recording player, whose URL nothing
         * rewrites. localStorage is what survives a live session; a window
         * global takes effect immediately but does not outlive the page.
         * Operator-facing messages in this file should say so rather than
         * naming a query parameter. */
        var value = null;

        try {
            value = new URLSearchParams(window.location.search).get(name);
            if (value === null && window.localStorage)
                value = window.localStorage.getItem(name);
        } catch (e) {
            /* Storage can be blocked outright; the global still works. */
        }

        if (value === null || value === undefined)
            return (storedOverrides[name] = undefined);

        /* '0' is deliberately not in that list: it is a valid threshold for
         * h264ChromaFilter, and an override that takes a number has to be
         * able to take zero. It still switches a boolean override off, since
         * callers coerce, and 0 is falsy. */
        if (value === 'off' || value === 'false')
            return (storedOverrides[name] = false);
        if (value === 'on' || value === 'true')
            return (storedOverrides[name] = true);

        var number = parseFloat(value);
        return (storedOverrides[name] = isNaN(number) ? true : number);

    }

    /**
     * Whether 4:4:4 combining is switched on. Overridable at runtime as
     * window.__h264Chroma444 = false for the current page, or as the
     * h264Chroma444 key in localStorage to survive a reconnect, to compare
     * against the 4:2:0 path. A query parameter is read but cannot be reached
     * on a live session -- see override().
     *
     * @private
     * @returns {!boolean}
     */
    function chroma444Enabled() {

        /* Ahead of the override, which everything else here defers to. The
         * override exists so a session can be compared against the other
         * setting, and there is nothing to compare: the auxiliary view has
         * been removed from the wire, so combining cannot produce 4:4:4 from
         * what arrives, only the cost of trying. The lever that answers this
         * question is the connection entry's Full Colour setting, which keeps
         * the auxiliary view on the wire. */
        if (auxDropped)
            return false;

        /* An explicit override always wins: it is how a session is compared
         * against the other setting, and a policy that could not be overridden
         * would make that comparison impossible. */
        var value = override('h264Chroma444');
        if (value !== undefined)
            return !!value;

        /* Given up for now by suspendCombining(). */
        if (combineLatchedOff)
            return false;

        /* Decided from the framebuffer's area, because that is what the cost
         * is a function of. The combine is a plane read-back, six texture
         * uploads and a shader pass per picture, all proportional to pixels
         * and all contending with the hardware video decoder on the same GPU,
         * so at high resolution it costs frame rate rather than buying
         * chroma -- and by then a 4:2:0 chroma block already covers close to
         * one logical pixel, so there is little left to recover.
         *
         * Not the desktop scale, which was the first thing tried: that only
         * says whether HiDPI scaling was applied, so a 4K display at a device
         * pixel ratio of 1 slips past it and combines at 8.3 megapixels, the
         * most expensive case there is. It is also not a property of the host
         * -- the same picture costs the same to combine whatever sent it,
         * which is why this was mistaken for an xrdp problem before a Windows
         * session was run at native resolution. */
        var pixels = display ? display.getWidth() * display.getHeight() : 0;

        /* Nothing sized yet: combine, and let the next picture decide once
         * the display has been sized. */
        if (!pixels)
            return true;

        var limit = combineMaxPixels();
        var combine = pixels <= limit;

        /* Once, and only where the answer is no -- ensureYuv444() already
         * announces the yes. A session painting 4:2:0 from an AVC444 stream
         * looks like a fault otherwise, and this is the line that says it was
         * a decision. */
        if (!combine && !chromaDeclineLogged) {
            chromaDeclineLogged = true;
            console.log('[rustguac] H.264: not combining AVC444 -- '
                    + display.getWidth() + 'x' + display.getHeight() + ' is '
                    + (pixels / 1e6).toFixed(1) + 'MP, over the '
                    + (limit / 1e6).toFixed(1) + 'MP the combine is worth its '
                    + 'GPU cost at; window.__h264Chroma444 = true '
                    + 'overrides, or the h264Chroma444 key in localStorage');
        }

        return combine;

    }

    /**
     * Whether the decision not to combine has been reported. The gate is
     * consulted on every auxiliary view until combining starts, so the line
     * would otherwise repeat for the life of the session.
     *
     * @private
     * @type {!boolean}
     */
    var chromaDeclineLogged = false;

    /**
     * The framebuffer area, in pixels, up to which AVC444 views are combined.
     *
     * From tests/bench on an Intel UHD 770, where the combine costs about
     * 1.37ms per megapixel (2.46ms at 1080p, 12.93ms at 4K, banded upload,
     * whole-screen damage). Four megapixels is therefore roughly a third of a
     * 60fps frame budget: 1080p spends 17% of a frame on it and 1440p 30%,
     * while 4K would spend 68% and a 5.5MP native-resolution session 45% --
     * which was measured in the field as a frame backlog and sync timeouts.
     *
     * Overridable as window.__h264CombineMaxPixels, ?h264CombineMaxPixels= on
     * the client's URL, or the h264CombineMaxPixels key in localStorage, since
     * the figure comes from one GPU and a faster or slower one moves the line.
     *
     * @private
     * @returns {!number}
     */
    function combineMaxPixels() {
        var value = override('h264CombineMaxPixels');
        return (typeof value === 'number' && value > 0)
            ? value : COMBINE_MAX_PIXELS;
    }

    /**
     * Whether the renderer is to be given full range (true), limited (false),
     * or left to follow the frame. Set as window.__h264FullRange, as
     * ?h264FullRange=off on the client's URL, or as the h264FullRange key in
     * localStorage.
     *
     * Exists because a stream's own signalling does not always survive the
     * browser: Chrome discards video_full_range_flag when the SPS names an
     * explicitly unspecified colour_primaries or transfer, reporting limited
     * for a host that said full and painting it with crushed blacks. See
     * Yuv444Renderer.setColorSpace(), and `H.264 colour:` in rustguac's
     * journal for which case a given host is in.
     *
     * @private
     * @returns {boolean}
     */
    function fullRangeOverride() {
        return override('h264FullRange');
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

    /**
     * Reports one whole picture's combine cost to the diagnostic.
     *
     * Once per picture rather than once per view: a main view accumulates and
     * the auxiliary view that refines it closes the picture out, or the next
     * main view does when none followed. Splitting a picture across two
     * samples would halve every figure it reports.
     *
     * @private
     * @param {!number} ms - Wall time the picture's combine work took.
     */
    function flushCombineCost(hadAux) {

        var ms = combineWorkMs;
        var copyMs = combineCopyMs;
        var resynced = combineResynced;

        combineWorkMs = 0;
        combineCopyMs = 0;
        combineResynced = false;

        if (ms <= 0)
            return;

        /* A picture that had to resync uploaded whole planes, so it says
         * nothing about the steady state -- and it copied whole planes too,
         * which would trip the gate on the one picture that is expected to
         * be expensive. */
        if (!resynced) {
            recordStat('combine', hadAux, ms);
            noteCombineCopy(copyMs);
        }

    }


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
     * A main view whose auxiliary view is still to come is uploaded but not
     * rendered: the auxiliary view is about to re-render the same picture with
     * real chroma, so rendering here would draw the 4:2:0 version of a picture
     * that is overwritten microseconds later -- a shader pass and a blit per
     * picture, thrown away. The server says which pictures those are
     * (MS-RDPEGFX LC=0), since only it knows before the second access unit
     * arrives. Its regions are carried over to the view that does paint.
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

        /* Neither `copyWait` nor `combine` covers what happens between here
         * and the copy being issued -- allocationSize(), which can force a
         * GPU-backed frame to be mapped, and the synchronous half of
         * copyTo(). That window sits inside `draw` and was part of the
         * 12-18ms it could not account for. */
        var enteredAt = nowMs();

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
        var planeW = rect ? rect.width : frame.codedWidth;
        var planeH = rect ? rect.height : frame.codedHeight;
        var pictureW = frame.displayWidth;
        var pictureH = frame.displayHeight;

        /* Narrowed to the damaged rows where that is safe: a main view, with
         * regions, whose textures already exist at this size (a resync has to
         * carry every row, and so does the first picture after a resize). */
        var sameSize = (view === 0)
            ? (!!lastPictureSize && lastPictureSize[0] === pictureW
                && lastPictureSize[1] === pictureH)
            : (!!lastAuxSize && lastAuxSize[0] === planeW
                && lastAuxSize[1] === planeH);

        /* Both views, and the same band arithmetic for each.
         *
         * An auxiliary view's plane rows are not its picture rows, but the
         * rounding already reconciles them: the band is rounded outward to
         * 16, which is exactly what auxV1LumaBands() does to reach the v1
         * layout's 16-row bands, and a superset of the v2 layout's
         * one-to-one rows and of both layouts' chroma rows at y >> 1.
         * Checked against that inverse in tests/h264-copy-band.mjs rather
         * than argued from here.
         *
         * Worth the care because the auxiliary view is the larger half of
         * what is left: on a Windows host it is one picture in two or three,
         * against xrdp's one in nine under CHROMA_INTERVAL=8. */
        var bands = (!resyncNeeded && sameSize)
                ? copyBandsFor(frameState.rects, planeH, planeW, view !== 0)
                : null;

        if (view === 0)
            lastPictureSize = [pictureW, pictureH];
        else
            lastAuxSize = [planeW, planeH];

        /* One copy per band, all into a single pooled buffer laid out
         * end to end. Each carries its own plane layout, so a band is an
         * independent little upload with its own source origin. */
        var segments = [];
        var si;

        if (bands) {
            for (si = 0; si < bands.length; si++)
                segments.push({
                    band: bands[si],
                    options: { rect: { x: 0, y: bands[si].y0,
                                       width: planeW, height: bands[si].h } }
                });
        }
        else {
            segments.push({
                band: null,
                options: rect
                    ? { rect: { x: 0, y: 0, width: rect.width,
                                height: rect.height } }
                    : {}
            });
        }

        var buffer = null;
        var size = 0;

        try {

            if (!interleaved && !planar)
                throw new Error('decoded frame is ' + (format || 'an unknown'
                        + ' format') + ', which carries no YUV planes');

            /* Timed apart, because `issue` measures all three and only one
             * of them can be fixed. allocationSize() may force a GPU-backed
             * frame to be mapped; acquireBuffer() zero-fills several
             * megabytes on a pool miss; copyTo()'s synchronous prologue does
             * the D3D11 array-texture copy and staging map. */
            var allocAt = nowMs();

            for (si = 0; si < segments.length; si++) {
                segments[si].offset = size;
                segments[si].size =
                        frame.allocationSize(segments[si].options);
                size += segments[si].size;
            }

            var bufAt = nowMs();
            recordStat('alloc', view !== 0, bufAt - allocAt);

            buffer = acquireBuffer(size);
            recordStat('buf', view !== 0, nowMs() - bufAt);

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

        /* Issued here rather than inside the chain, so that the two views of
         * a picture are in flight at once; only what follows is ordered. */
        var copyAt = nowMs();
        var copies = [];
        var copiedRows = 0;

        for (si = 0; si < segments.length; si++) {

            var seg = segments[si];

            seg.data = new Uint8Array(buffer.buffer,
                    buffer.byteOffset + seg.offset, seg.size);

            try {
                copies.push(frame.copyTo(seg.data, seg.options));
            } catch (e) {
                copies.push(Promise.reject(e));
            }

            copiedRows += seg.band ? seg.band.h : planeH;

        }

        var copy = Promise.all(copies);

        /* The synchronous half of copyTo(). `read-back wait` times the
         * promise, which is why the transfer looked free: by the time the
         * promise is awaited the blocking work is already done.
         *
         * Charged per plane megapixel, because that is what says whether
         * copying less would help. A cost proportional to area is a transfer,
         * and restricting the rect to the damaged rows would cut it in
         * proportion. A cost that barely moves between a full-size main view
         * and a smaller auxiliary one is a fixed pipeline stall per call, and
         * the thing to reduce is then the number of copies, not their size.
         * The two lead to different fixes, so measure before building
         * either. */
        var copyElapsed = nowMs() - copyAt;
        recordStat('copy', view !== 0, copyElapsed, planeW * copiedRows);

        /* The chain below is this copy's real error handler, but it may not
         * attach for some time, and a rejection with nothing attached yet is
         * reported as unhandled. */
        copy.catch(function() { /* handled by the chain */ });

        var copyIssuedAt = nowMs();
        recordStat('issue', view !== 0, copyIssuedAt - enteredAt);

        copyChain = copyChain.then(function() {
            return copy;
        }).then(function(layouts) {

            /* Times the work, not the wait. The awaits above queue behind
             * whatever else is in flight, so including them would measure the
             * backlog and feed the suspension decision with its own output. */
            var startedAt = nowMs();

            if (override('h264CombineLog')) {
                if (!copyWait)
                    copyWait = { n: 0, sum: 0, max: 0 };
                var waited = startedAt - copyIssuedAt;
                copyWait.n++;
                copyWait.sum += waited;
                if (waited > copyWait.max)
                    copyWait.max = waited;
            }

            /* A main view opens a picture, so anything still accumulated
             * belongs to the previous one -- which evidently carried no
             * auxiliary view, or that view would have closed it. Done before
             * this picture's uploads so the resync flag they may set is not
             * charged to the picture before it. */
            if (view === 0)
                flushCombineCost(false);

            /* Charged after that close-out, not before it, or a main view
             * hands its own copy to the picture in front of it -- and the
             * very first one is closed out against an empty picture and
             * discarded. Charged here rather than where it was measured
             * because the copy chain's ordering is what says which picture a
             * copy belongs to: issue order does not, since a picture's
             * auxiliary view is issued while its main view's copy is still in
             * flight. */
            combineCopyMs += copyElapsed;

            /* Each band's own plane views and rects. Built for every band
             * before any is uploaded, so that a band whose clipped regions
             * turn out unusable stops the picture rather than leaving the
             * textures half written -- the same all-or-nothing the renderer
             * enforces per plane.
             *
             * NV12 has two planes rather than three; a null V plane is how
             * the renderer is told the chroma is interleaved into U. */
            var uploads = [];
            var ui;

            for (ui = 0; ui < segments.length; ui++) {

                var useg = segments[ui];
                var ulay = layouts[ui];

                var urects = resyncNeeded ? null
                    : (useg.band
                        ? clipRectsToBand(frameState.rects, useg.band)
                        : frameState.rects);

                /* Every band is built from at least one rect, so an empty
                 * list here means the clip and the band disagree. Copying the
                 * whole plane next time is the cheap way to be sure. */
                if (useg.band && (!urects || !urects.length)) {
                    resyncNeeded = true;
                    lastPictureSize = null;
                    lastAuxSize = null;
                    return;
                }

                uploads.push({
                    y: new Uint8Array(useg.data.buffer,
                            useg.data.byteOffset + ulay[0].offset),
                    u: new Uint8Array(useg.data.buffer,
                            useg.data.byteOffset + ulay[1].offset),
                    v: interleaved ? null
                        : new Uint8Array(useg.data.buffer,
                                useg.data.byteOffset + ulay[2].offset),
                    strides: interleaved
                        ? [ulay[0].stride, ulay[1].stride]
                        : [ulay[0].stride, ulay[1].stride, ulay[2].stride],
                    rects: urects,
                    y0: useg.band ? useg.band.y0 : undefined
                });

            }

            if (view === 0) {

                /* Adopt whatever the decoder says this stream is, once. The
                 * 4:2:0 path never reaches the shader -- the browser draws
                 * that VideoFrame and applies its colour space itself -- so
                 * converting here on an assumption is how the two paths come
                 * out different colours on the same session. */
                if (!colorSpaceApplied && renderer.setColorSpace) {

                    /* Reported rather than logged to the console, so it lands
                     * in the journal beside the `H.264 colour:` line rustguac
                     * reads out of the SPS (src/h264_sps.rs). The two together
                     * are the whole question: the first says what the host
                     * declared, this says what the browser made of it, and a
                     * disagreement between them is invisible in either alone.
                     * A colour fault reported hours later has both. */
                    diagnostic('colour_space',
                            renderer.setColorSpace(frame.colorSpace,
                                fullRangeOverride())
                            + '; decoder gave ' + (frame.format || 'unknown')
                            + ' frames', true);

                    colorSpaceApplied = true;
                }

                /* This view's own regions, not the union built below: a
                 * region the other view did not update has no new samples in
                 * this plane either, and uploading over it would replace
                 * valid rows with the same rows. */
                if (resyncNeeded)
                    combineResynced = true;

                /* A refusal means nothing was uploaded -- the check happens
                 * before the first plane is written -- so the textures still
                 * match the screen and the next picture can carry every row
                 * rather than this one repairing a half-written state. The
                 * check is a property of the picture rather than of a band,
                 * so it refuses the first band or none of them. */
                for (ui = 0; ui < uploads.length; ui++)
                    if (!renderer.uploadLuma(uploads[ui].y, uploads[ui].u,
                            uploads[ui].v, uploads[ui].strides,
                            pictureW, pictureH, uploads[ui].rects,
                            uploads[ui].y0)) {
                        resyncNeeded = true;
                        lastPictureSize = null;
                        return;
                    }

            }
            else {

                if (resyncNeeded)
                    combineResynced = true;

                for (ui = 0; ui < uploads.length; ui++)
                    if (!renderer.uploadAux(uploads[ui].y, uploads[ui].u,
                            uploads[ui].v, uploads[ui].strides,
                            planeW, planeH, view, uploads[ui].rects,
                            uploads[ui].y0)) {
                        resyncNeeded = true;
                        lastAuxSize = null;
                        return;
                    }

            }

            /* An auxiliary view paints the picture its main view did not, so
             * it paints both views' regions. A null list on either side means
             * that view called the whole picture valid, which the union of the
             * two must then be as well. */
            if (view !== 0 && deferredMain) {

                frameState.rects =
                    (!deferredMainRects || !frameState.rects) ? null
                        : deferredMainRects.concat(frameState.rects);

                deferredMain = false;
                deferredMainRects = null;

            }

            /* Nothing more to do for a main view that an auxiliary view is
             * about to refine: its planes are uploaded, and the auxiliary
             * view's render reads them. Its draw task is released below with
             * no snapshot, which draws nothing -- the picture is painted once,
             * by the task immediately behind this one.
             *
             * The cost of being wrong is one skipped picture: if that
             * auxiliary view then fails to combine, this update is not painted
             * at all rather than painted at 4:2:0, and the screen catches up
             * on the next update. Every path that can fail there also
             * abandons combining, so it is one picture, not a permanent
             * regression -- and the server only sets the flag when it has
             * already queued both views. */
            if (view === 0 && frameState.paired) {
                deferredMain = true;
                deferredMainRects = frameState.paint ? frameState.rects : [];
                finishForTiming();
                combineWorkMs += nowMs() - startedAt;
                return;
            }

            /* Whole planes have now been uploaded for whichever views this
             * picture carries, so the textures match the screen again and the
             * next picture may go back to uploading only its damaged rows. */
            resyncNeeded = false;

            /* A main view that paints its own picture leaves nothing for a
             * later auxiliary view to inherit. Cleared here rather than only
             * on consumption, so that a picture whose auxiliary view never
             * arrived cannot hand its regions to an unrelated one. */
            if (view === 0) {
                deferredMain = false;
                deferredMainRects = null;
            }

            /* A main view with no auxiliary view behind it renders on its own
             * as an ordinary 4:2:0 picture, exactly as a luma-only (LC=1)
             * update does for FreeRDP. */
            var rendered = renderer.render(view === 0 ? 0 : view,
                    chromaFilter(), frameState.rects);

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
             * and nothing will ever paint this picture -- keeping it would
             * leak the bitmap's GPU memory. */
            if (frameState.settled) {
                releaseSnapshot(rendered);
                return;
            }

            /* The renderer hands over its drawing buffer whole, so there is no
             * copy to make here and no size to choose. That matters for the v1
             * chroma layout, which pads the auxiliary view to a multiple of 16
             * rows: the bitmap is the size the renderer drew at, which is the
             * main view's, not this frame's taller one. Copying at the frame's
             * size instead left a blank strip below the picture, blitted over
             * the bottom of the display whenever the server sent no rects. */
            frameState.canvas = rendered;

            finishForTiming();
            combineWorkMs += nowMs() - startedAt;

            /* An auxiliary view completes the picture it refines, so the gate
             * is charged here for both views at once -- suspending drops both.
             * A main view cannot know whether one follows, so it only
             * accumulates; the next main view closes it out if none did. */
            if (view !== 0)
                flushCombineCost(true);

        }).catch(function(e) {

            console.error('[rustguac] H.264: 4:4:4 combine failed:',
                    e && e.message ? e.message : e);

            /* One failure is usually terminal for this path -- an unsupported
             * pixel format does not become supported later -- so fall back
             * rather than failing once per frame for the rest of the session. */
            combining = false;
            yuv444Unavailable = true;
            combineWorkMs = 0;
            combineResynced = false;

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
     * reclaiming them throws away the pool's canvases and leaks the GPU memory
     * behind any combined frame's ImageBitmap.
     *
     * @private
     */
    function releaseHeldFrames() {

        /* Nothing will paint the deferred main view's regions now, and holding
         * them would apply one picture's regions to another. */
        deferredMain = false;
        deferredMainRects = null;
        combineWorkMs = 0;
        combineResynced = false;

        /* Whatever is uploaded no longer corresponds to what is on screen, so
         * the next combine uploads whole planes. */
        resyncNeeded = true;

        for (var key in pendingFrames) {
            var frameState = pendingFrames[key];
            if (frameState && frameState.canvas) {
                releaseSnapshot(frameState.canvas);
                frameState.canvas = null;
            }
        }
        pendingFrames = {};
    }

    /**
     * The codec string to configure the decoder with, when no sequence
     * parameter set has been seen yet. High profile at level 5.2, which
     * covers every picture size this decoder is asked for, rather than the
     * level 4.1 that is too small for them.
     *
     * The level in a codec string is not advisory: Chrome sizes its hardware
     * decoder from it, and a stream whose frames exceed the declared level
     * silently falls back to software, because hardwareAcceleration is a
     * preference rather than a requirement. Level 4.1 permits 8192
     * macroblocks, so it holds for 1920x944 (7080) and fails for 2688x1488
     * (15624) -- which decoded in software at roughly twenty times the
     * latency, and under AVC444 for two pictures per frame.
     *
     * @private
     * @constant {string}
     */
    var DEFAULT_CODEC = 'avc1.640034';

    /**
     * Reads the codec string out of a sequence parameter set, if the given
     * access unit carries one.
     *
     * The three bytes following an SPS NAL header are profile_idc,
     * constraint_flags and level_idc, which are exactly the three bytes of an
     * avc1 codec string. Taking them from the stream keeps the decoder's
     * configuration in step with whatever the server chose, and the server
     * does vary it: the level follows the picture size, so one session's
     * stream may be 4.2 and the next 5.1.
     *
     * @private
     * @param {!ArrayBuffer} nalData
     *     A complete access unit in Annex B format.
     *
     * @returns {?string}
     *     The codec string, or null if this access unit carries no SPS.
     */
    function codecFromSps(nalData) {

        var bytes = new Uint8Array(nalData);
        var i;

        /* Annex B start codes are three or four bytes; scanning for the
         * three-byte form finds both, since the four-byte form ends with it. */
        for (i = 0; i + 4 < bytes.length; i++) {

            if (bytes[i] !== 0 || bytes[i + 1] !== 0 || bytes[i + 2] !== 1)
                continue;

            /* nal_unit_type is the low five bits of the header byte. 7 is a
             * sequence parameter set. */
            if ((bytes[i + 3] & 0x1F) !== 7)
                continue;

            if (i + 6 >= bytes.length)
                return null;

            return 'avc1.'
                + ('0' + bytes[i + 4].toString(16)).slice(-2)
                + ('0' + bytes[i + 5].toString(16)).slice(-2)
                + ('0' + bytes[i + 6].toString(16)).slice(-2);

        }

        return null;

    }

    /**
     * Initialise the VideoDecoder if not already done.
     *
     * @private
     * @param {number} width - Expected frame width.
     * @param {number} height - Expected frame height.
     * @param {ArrayBuffer} [nalData]
     *     The access unit about to be decoded, read for its sequence
     *     parameter set if it carries one.
     */
    function ensureDecoder(width, height, nalData) {

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

                    /* Submitted to arrived. Stamped before anything else here
                     * so no work of ours is counted as the decoder's. */
                    frameState.decodedAt = nowMs();
                    noteFramebufferSize();
                    if (frameState.submittedAt)
                        recordStat('decode', frameState.view !== 0,
                                frameState.decodedAt - frameState.submittedAt);

                    /* The decision to combine is made from the framebuffer's
                     * area at the time, and the framebuffer is resized after
                     * connecting: a fit that passed through 2240x1648 (3.7MP)
                     * switched combining on, and it stayed on at 2992x2000
                     * (6MP), where it costs ~8ms of GPU per picture. So
                     * re-check it while combining -- a multiply and a cached
                     * lookup -- but only on a main view, where a picture
                     * begins. A paired main view has already been uploaded
                     * and deliberately not painted, leaving its auxiliary
                     * view to paint the picture; stopping between the two
                     * throws that picture away. When it is the connect-time
                     * keyframe, nothing else repaints the screen and the
                     * session looks hung until a resize brings another one.
                     *
                     * Stopping here leaves this main view to the 4:2:0 path
                     * below, which paints it, and its auxiliary view to the
                     * block after, which declines it. Resuming, should the
                     * framebuffer shrink again, uploads whole planes, since
                     * what was uploaded no longer matches the screen. */
                    if (combining && frameState.view === 0
                            && !chroma444Enabled()) {
                        combining = false;
                        resyncNeeded = true;

                        /* Suspended by the sync gate, which has reported it
                         * already; this is only where it takes effect.
                         *
                         * Otherwise say which of the other two reasons it
                         * was. The override is read per picture, so it can
                         * stop combining at any point in a session, and
                         * blaming the framebuffer for it sends whoever reads
                         * the line looking at the wrong thing. */
                        if (!combineLatchedOff) {

                            var declineOverride = override('h264Chroma444');

                            diagnostic('chroma_declined', auxDropped
                                ? 'stopped 4:4:4 combining: the server is '
                                    + 'dropping the auxiliary view in transit, '
                                    + 'so no view the combiner holds a main '
                                    + 'picture for will arrive and every main '
                                    + 'view would pay the plane read-back for '
                                    + 'nothing'
                                : declineOverride !== undefined
                                ? 'stopped 4:4:4 combining: the h264Chroma444 '
                                    + 'override is off'
                                : 'stopped 4:4:4 combining: the framebuffer '
                                    + 'grew to ' + display.getWidth() + 'x'
                                    + display.getHeight() + ', over the '
                                    + (combineMaxPixels() / 1e6).toFixed(1)
                                    + 'MP it is worth its cost at',
                                true);

                        }
                    }

                    /* An auxiliary view means this is an AVC444 stream, so
                     * its chroma can be recovered. Switch over for the frames
                     * that follow; this one cannot be combined, because the
                     * main view it refines went through the 4:2:0 path and its
                     * planes were never uploaded. */
                    if (frameState.view !== 0 && !combining) {

                        /* Not before the size has settled; see
                         * COMBINE_SETTLE_MS. The next auxiliary view after it
                         * has asks again. */
                        if (chroma444Enabled() && framebufferSettled()
                                && ensureYuv444())
                            combining = true;

                        /* Say so when a server is sending auxiliary views and
                         * nothing combines them. An explicit override returns
                         * from chroma444Enabled() before the decline is
                         * logged, and the whole apparatus is silent -- which
                         * reads exactly like a server that never sent AVC444
                         * at all, and cost an afternoon proving otherwise once
                         * the wire turned out to be carrying codec 0x000f the
                         * whole time. Once per session, and only where the
                         * question can arise. */
                        else if (!combineDisabledLogged
                                && override('h264Chroma444') !== undefined) {

                            combineDisabledLogged = true;

                            /* Standard colour is the entry saying so, not a
                             * setting to go and find: expected on every AVC444
                             * host until the in-transit drop stops the views,
                             * which reports on its own account server-side. */
                            if (window.__h264StandardColour === true)
                                console.info('[rustguac] H.264: Standard '
                                        + 'colour -- auxiliary views are '
                                        + 'decoded and not combined until the '
                                        + 'drop in transit stops them.');

                            else
                                diagnostic('chroma_off', 'the server is '
                                        + 'sending AVC444 auxiliary views and '
                                        + '4:4:4 combining is switched off by '
                                        + 'an explicit h264Chroma444 '
                                        + 'override, so they are decoded and '
                                        + 'discarded. Check '
                                        + 'window.__h264Chroma444 and the '
                                        + 'h264Chroma444 key in localStorage.',
                                        true);

                        }

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
                    /* Nothing will be painted, so there is nothing to copy.
                     * The finally below closes the frame and releases the
                     * task, which drawDecoded() then settles. */
                    if (!frameState.paint)
                        return;

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

                /* A configuration refused for want of a hardware decoder,
                 * which is the one error that is worth answering by trying
                 * something different rather than by rebuilding the same
                 * thing. Latched, so it is asked for once per session and the
                 * rebuild below is not an endless alternation. */
                if (!hardwareRefused && /nsupported configuration/.test(
                        e.message || '')) {
                    hardwareRefused = true;
                    lastCodec = null;
                    console.warn('[rustguac] H.264: no hardware decoder for'
                            + ' this stream; falling back to whatever the'
                            + ' browser will give us. Expect the decode to'
                            + ' cost considerably more.');
                    diagnostic('decoder_software_fallback', 'the browser '
                            + 'refused a hardware-accelerated configuration '
                            + 'and H.264 is being decoded without that hint. '
                            + 'On a client with no hardware decoder this is '
                            + 'the difference between a picture and a black '
                            + 'screen, and it is much slower than the path '
                            + 'this feature was built for.', true);
                }

                else
                    diagnostic('decoder_rebuild', 'decode error: ' + e.message
                            + '. Every queued frame is discarded and nothing '
                            + 'is painted until the next keyframe.', true);

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

        var codec = (nalData && codecFromSps(nalData)) || DEFAULT_CODEC;

        if (codec !== lastCodec) {
            console.info('[rustguac] H.264: decoding as ' + codec);
            lastCodec = codec;
        }

        var config = {
            codec: codec,
            optimizeForLatency: true
        };

        /* 'prefer-hardware' reads as a hint and is not one: Chrome reports a
         * configuration carrying it as unsupported outright where no hardware
         * decoder exists, rather than falling back. So a client without one
         * (a VM, a machine whose driver is blocklisted, a browser with
         * acceleration switched off) loses H.264 altogether, and loses it in
         * the worst way: configure() fails asynchronously, the decoder closes,
         * every frame is held for a keyframe that cures nothing, and since
         * guacd suppresses ordinary image operations for a layer carrying
         * H.264 the result is a permanently black screen rather than a
         * degraded one.
         *
         * So ask for hardware once, and if that is refused build again without
         * asking. Dropping the hint unconditionally would hand the choice to
         * the browser on every client, including the ones this path exists
         * for, where a software decode costs far more than it saves. */
        if (!hardwareRefused)
            config.hardwareAcceleration = 'prefer-hardware';

        decoder.configure(config);

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
     * @param {boolean} [paired=false]
     *     Whether an auxiliary chroma view for this same picture follows
     *     immediately. Only a main view can be paired, and only the server
     *     knows: the auxiliary view is a separate access unit that has not
     *     arrived yet. When it is combined, a paired main view is uploaded but
     *     never painted, since the auxiliary view repaints the same picture.
     *
     * @returns {?number}
     *     A token identifying this frame, to be passed to drawDecoded(), or
     *     null if it could not be submitted.
     */
    this.decode = function(layer, x, y, width, height, nalData, isKeyFrame,
            rects, onReady, view, paired, recreated) {

        ensureDecoder(width, height, nalData);

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

                /* Held, not painted. Nothing on screen changes until the
                 * server happens to send a keyframe, and an idle desktop
                 * gives it no reason to. */
                if (!keyframeWaitSince)
                    keyframeWaitSince = nowMs();
                keyframeWaitDropped++;

                if (nowMs() - keyframeWaitSince > 2000)
                    diagnostic('keyframe_wait', 'holding every frame for want '
                            + 'of a keyframe: ' + keyframeWaitDropped
                            + ' dropped over '
                            + ((nowMs() - keyframeWaitSince) / 1000).toFixed(1)
                            + 's. The picture is frozen until the server sends '
                            + 'one, which an idle desktop may not do.');

                if (onReady) onReady();
                return null;
            }
            needsKeyFrame = false;
            console.warn('[rustguac] H.264: decoder rebuilt, resuming at'
                    + ' keyframe');

            if (keyframeWaitSince) {
                diagnostic('keyframe_resumed', 'keyframe arrived after '
                        + ((nowMs() - keyframeWaitSince) / 1000).toFixed(1)
                        + 's and ' + keyframeWaitDropped + ' dropped frame(s)',
                        true);
                keyframeWaitSince = 0;
                keyframeWaitDropped = 0;
            }
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

                /* An empty list, unlike an absent one, says no region of the
                 * picture changed: decode it for its references, paint none
                 * of it. See drawDecoded(). */
                paint: !(rects && rects.length === 0),
                view: view || 0,
                paired: !!paired,
                recreated: !!recreated,
                onReady: onReady,
                canvas: null,
                settled: false,
                watchdog: null
            };

            /* Wrapped after construction, so the wrapper can stamp into the
             * frameState it belongs to. Every path that finishes a frame --
             * combine, snapshot, watchdog, decode failure -- goes through
             * onReady, so one wrapper here covers all of them where patching
             * each call site would miss one.
             *
             * This is what splits `draw` in two. The display's flush completes
             * *inside* the unblock this calls (Display.js __display_h264_ready
             * -> Task.unblock -> __flush_frames, synchronously), so a frame
             * that is slow to become available is indistinguishable, from
             * sync_hold's side, from a display that is slow to draw. `queue`
             * is the half that is genuinely the display's: the picture was
             * ready and waited anyway, behind frames ahead of it that were
             * not. */
            if (onReady)
                frameState.onReady = function __h264_ready() {
                    if (!frameState.readyAt)
                        frameState.readyAt = nowMs();
                    onReady();
                };

            frameState.submittedAt = nowMs();
            pendingDecodes++;

            frameState.watchdog = setTimeout(function() {
                frameState.watchdog = null;
                if (!frameState.canvas) {
                    watchdogFires++;
                    reportAbandoned();
                    if (frameState.onReady) frameState.onReady();
                }
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
                    releaseSnapshot(frameState.canvas);
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

        /* A picture whose region list was sent empty changed nothing on
         * screen. Reported because it is rare and was, painted whole, the
         * cause of the black-display episodes: a keyframe of uninitialised
         * content that the server never meant to show. */
        if (!frameState.paint) {
            diagnostic('h264_undisplayed', (frameState.keyFrame ? 'keyframe'
                    : 'delta') + ' view=' + frameState.view + ' with no '
                    + 'region rects: decoded for its references, not painted');
            if (frameState.canvas) {
                releaseSnapshot(frameState.canvas);
                frameState.canvas = null;
            }
            settle(frameState);
            return;
        }

        var snapshot = frameState.canvas;
        if (!snapshot) {
            settle(frameState);
            return;
        }

        /* A black keyframe over a stable framebuffer: keep what is on screen.
         * See keepPictureOverBlackKeyframe(). */
        if (keepPictureOverBlackKeyframe(frameState, snapshot)) {
            frameState.canvas = null;
            releaseSnapshot(snapshot);
            settle(frameState);
            return;
        }

        /* Decoded to painted: the asynchronous chain that turns a VideoFrame
         * into a snapshot, plus the wait below. */
        if (frameState.decodedAt)
            recordStat('draw', frameState.view !== 0,
                    nowMs() - frameState.decodedAt);

        /* Ready to painted: time in the display's ordered queue, not work.
         * `draw` minus this is the chain; this is the queue. */
        if (frameState.readyAt)
            recordStat('queue', frameState.view !== 0,
                    nowMs() - frameState.readyAt);

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
            releaseSnapshot(snapshot);
            settle(frameState);
        }

    };

    /**
     * How long sync acknowledgements are held waiting for decodes, split by
     * whether the picture was being combined into 4:4:4 at the time.
     *
     * The hold is the throttle itself: guacd paces frames on the ack, so a
     * client that is slow but not drowning shows up here -- as acks held
     * longer -- and never as a growing backlog, which is all the combine latch
     * watches. These are the numbers a gate on sluggishness would need, and
     * they are collected before anything acts on them because a normal hold on
     * a large framebuffer is not zero and has not been measured.
     *
     * The window is reported and reset once a minute as `sync_hold`.
     *
     * @private
     */
    function newHoldStats() {
        function flushBucket() {
            return { flushes: 0, flushSumMs: 0, flushMaxMs: 0, flushSlow: 0 };
        }
        function mode() {
            var m = flushBucket();
            m.syncs = 0;
            m.held = 0;
            m.sumMs = 0;
            m.maxMs = 0;
            m.timeouts = 0;
            return m;
        }
        return { '420': mode(), '444': mode() };
    }

    /**
     * Adds one flush sample to a bucket.
     *
     * @private
     */
    function addFlush(bucket, flushMs) {
        bucket.flushes++;
        bucket.flushSumMs += flushMs;
        bucket.flushMaxMs = Math.max(bucket.flushMaxMs, flushMs);
        if (flushMs >= FLUSH_SLOW_MS)
            bucket.flushSlow++;
    }


    /**
     * A display flush at least this long, in milliseconds, is counted as slow.
     * At 60fps a frame is 16.7ms; this is six of them.
     *
     * @private
     * @constant
     * @type {!number}
     */
    var FLUSH_SLOW_MS = 100;
    var holdWindow = newHoldStats();
    var holdWindowStart = 0;

    /**
     * How often the window above is reported, in milliseconds.
     *
     * @private
     * @constant
     * @type {!number}
     */
    var HOLD_REPORT_INTERVAL_MS = 60000;

    /**
     * Records one sync acknowledgement's hold, and reports the window if a
     * minute has passed. Reporting from here rather than from a timer means a
     * session sending no frames reports nothing, and nothing outlives the
     * decoder.
     *
     * @private
     */
    function recordHold(mode, ms, timedOut, flushMs) {

        noteActivity();
        if (mode === '444')
            noteCombineFlush(flushMs);

        var stats = holdWindow[mode];
        if (typeof flushMs === 'number')
            addFlush(stats, flushMs);
        stats.syncs++;
        if (ms > 0) {
            stats.held++;
            stats.sumMs += ms;
            stats.maxMs = Math.max(stats.maxMs, ms);
        }
        if (timedOut)
            stats.timeouts++;

        var now = nowMs();
        if (!holdWindowStart) {
            holdWindowStart = now;
            return;
        }

        var elapsed = now - holdWindowStart;
        if (elapsed < HOLD_REPORT_INTERVAL_MS)
            return;

        /* Quiet unless it has something to say. This was the last always-on
         * periodic reporter -- once a minute, with a console.warn stack trace,
         * for the life of every session -- where everything else in this file
         * speaks on a state change. A window with no sync timeout in it is a
         * window where the gate is working, and there is nothing to read.
         *
         * A timeout still reports without any flag set, because that is the
         * shape a fault takes here and the journal has to carry it; asking for
         * h264CombineLog gets every window regardless. */
        var noteworthy = holdWindow['420'].timeouts + holdWindow['444'].timeouts;

        if (!noteworthy && !override('h264CombineLog')) {
            holdWindow = newHoldStats();
            holdWindowStart = now;
            return;
        }

        diagnostic('sync_hold', 'last ' + (elapsed / 1000).toFixed(0) + 's at '
                + (display ? display.getWidth() + 'x' + display.getHeight()
                    : '?') + ': ' + describeHolds(holdWindow, elapsed), true);

        holdWindow = newHoldStats();
        holdWindowStart = now;

    }

    /**
     * One mode's holds as text: syncs and their rate, how many were held at
     * all, the mean hold across every sync (the throttle's average cost per
     * frame) and across the held ones, the longest, and timeouts.
     *
     * @private
     */
    function describeHolds(stats, elapsedMs) {
        var parts = [];
        ['420', '444'].forEach(function(mode) {
            var s = stats[mode];
            if (!s.syncs)
                return;
            parts.push((mode === '444' ? '4:4:4' : '4:2:0') + ' ' + s.syncs
                    + ' syncs'
                    + (elapsedMs ? ' (' + (s.syncs * 1000 / elapsedMs)
                        .toFixed(1) + '/s)' : '')
                    + ' held ' + s.held + ' ('
                    + (100 * s.held / s.syncs).toFixed(0) + '%)'
                    + ' mean ' + (s.sumMs / s.syncs).toFixed(1) + 'ms'
                    + (s.held ? ' mean-held ' + (s.sumMs / s.held).toFixed(1)
                        + 'ms' : '')
                    + ' max ' + s.maxMs.toFixed(0) + 'ms'
                    + ' timeouts ' + s.timeouts
                    + (s.flushes ? ' | flush mean '
                        + (s.flushSumMs / s.flushes).toFixed(1) + 'ms max '
                        + s.flushMaxMs.toFixed(0) + 'ms slow '
                        + s.flushSlow : ''));
        });
        return parts.length ? parts.join('; ') : 'no syncs';
    }


    /**
     * Waits for pending decodes to drain, then invokes the callback. Used to
     * gate the Guacamole sync response so that guacd receives accurate
     * backpressure from the client's decode speed.
     *
     * @param {function} callback
     *     Called when the backlog is within the allowed pipeline depth.
     *
     * @param {number} [flushMs]
     *     How long the display took to flush this sync's frame, from the sync
     *     arriving to the flush completing. The ack waits for the flush before
     *     it ever reaches this gate, so a display queue that is slow holds
     *     acks where the hold above cannot see it -- measured in the field as
     *     2.2 syncs/s with no holds while the screen stopped updating. Reported
     *     beside the hold in `sync_hold`.
     */
    this.waitForPending = function(callback, flushMs) {

        /* Charged to the mode the ack was held under, which is the one whose
         * cost is being measured -- a combine switched off mid-hold still
         * caused it. */
        var mode = combining ? '444' : '420';

        maybeResumeCombining();

        if (pendingDecodes <= MAX_PIPELINE_DEPTH || !decoder
                || decoder.state === 'closed') {
            recordHold(mode, 0, false, flushMs);
            callback();
            return;
        }

        var waitingOn = pendingDecodes;
        var resolved = false;
        var heldSince = nowMs();

        var timer = setTimeout(function() {
            if (!resolved) {
                resolved = true;
                recordHold(mode, nowMs() - heldSince, true, flushMs);
                noteSyncTimeout(mode);
                syncTimeouts++;
                reportAbandoned();
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
                recordHold(mode, nowMs() - heldSince, false, flushMs);
                callback();
            }
        });

    };

    /**
     * Tells the decoder whether the AVC444 auxiliary view is being removed
     * from the wire between the server and here, which only the server knows.
     * Carried by rustguac's `h264-aux` instruction.
     *
     * Combining stops at the next main view, through the same re-check that
     * handles a framebuffer growing past its threshold -- never between a
     * paired main view and the auxiliary view that paints it, which would
     * throw that picture away. It restarts of its own accord at the next
     * auxiliary view once the drop stops, since that is the only thing that
     * ever starts it.
     *
     * @param {!boolean} dropped
     */
    this.setAuxDropped = function(dropped) {

        dropped = !!dropped;
        if (dropped === auxDropped)
            return;

        auxDropped = dropped;

        /* Resuming: whatever the textures hold predates the gap, so the first
         * combine back must upload whole planes. Set here rather than where
         * combining restarts, which cannot tell this apart from an ordinary
         * first auxiliary view. */
        if (!dropped)
            resyncNeeded = true;

        /* Said on the state change, as everything else in this file is. It is
         * not the same event as chroma_declined, which fires only where
         * combining was actually running and only at the next main view: the
         * drop can arm before the first auxiliary view has switched combining
         * on, and then nothing else would mark the moment the client learned
         * of it. That timestamp is what the server's own line is read
         * against. */
        diagnostic('chroma_aux_dropped', dropped
            ? 'the server is dropping the AVC444 auxiliary view in transit, '
                + 'so 4:4:4 combining is off: there is no chroma to recover '
                + 'and combining would pay the plane read-back per picture '
                + 'for a view that will never arrive'
            : 'the server has stopped dropping the AVC444 auxiliary view, so '
                + '4:4:4 combining may resume at the next one', true);

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

/**
 * Sink for decoder diagnostics, or null. Called as onDiagnostic(event, detail)
 * with a short event name and a description, no more than once per event every
 * 30 seconds (transitions excepted). The page is expected to forward these to
 * the server; a fault that appears once in days is not going to be caught in
 * anyone's console.
 *
 * @type {?function(string, string)}
 */
Guacamole.H264Decoder.onDiagnostic = null;

