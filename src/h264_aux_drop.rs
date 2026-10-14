//! Drops an AVC444 stream's auxiliary chroma view on the way to the browser,
//! where the stream proves it can be dropped.
//!
//! The combine gate in `H264Decoder.js` gives up 4:4:4 by discarding the
//! auxiliary view *after* it has crossed the link and been decoded, so it
//! removes main-thread cost and nothing else. This removes the view from the
//! wire instead: the same 4:2:0 picture for less bandwidth and one decode per
//! frame rather than two. It cannot be had at the source, because a Windows
//! host has to be offered AVC444 to send H.264 at all.
//!
//! # The gate
//!
//! The two views share one decoded picture buffer, so dropping is safe only if
//! two things hold. `crate::h264_refs` reads both from the slice headers.
//!
//! **Nothing surviving may predict from a dropped picture.** Windows names its
//! references explicitly with disjoint long-term indices, and the xrdp fork
//! does the same with dual long-term references.
//!
//! **The decoder must have room for the pictures a gap makes it invent.**
//! Dropping a picture leaves a hole in `frame_num`, and 8.2.5.2 obliges a
//! decoder to fill each hole with an inferred *non-existing* frame held as a
//! **short-term** reference. The sliding window can only evict short-term
//! pictures, so a stream whose `max_num_ref_frames` is entirely consumed by
//! long-term references has nowhere to put one, and the decoder fails outright
//! rather than degrading. Asking whether anything *refers* to a dropped picture
//! says nothing about this: an xrdp stream with perfectly separate chains,
//! long-term 0 for main and 1 for the auxiliary view and `max_num_ref_frames`
//! 2, froze within a fifth of a second of the first drop. Windows has 3, two
//! long-term and one to spare.
//!
//! # What it does, in order
//!
//! 1. **Permits gaps immediately.** Every SPS gets
//!    `gaps_in_frame_num_value_allowed_flag` set from the first instruction of
//!    the session, before anything has been decided, because an SPS only rides
//!    a keyframe and a host can go minutes without one. Setting it on a stream
//!    that is never dropped from is inert.
//! 2. **Waits** while the probe accumulates -- three auxiliary inter slices
//!    and ten main ones, or one of each for a connection entry at Standard
//!    colour. Inter slices rather than pictures: an IDR names no reference and
//!    marks nothing, so excluding them is already the guard against deciding
//!    from the connect-time keyframe burst, and a count of pictures would only
//!    add delay on a quiet desktop that sends few.
//! 3. **Drops**, as soon as the stream proves itself, the `h264`, `blob` and
//!    `end` instructions of every non-IDR auxiliary view, and clears the
//!    trailing `<paired>` flag on main views so the client paints them instead
//!    of holding them for a view that is no longer coming.
//! 4. **Keeps watching.** A verdict reached from the first few auxiliary views
//!    is a verdict about the first few auxiliary views, so one that turns
//!    unsafe later stops the drop.
//!
//! From the first SPS to the decision takes about 2.5s on both hosts, almost
//! all of it the keyframe burst. A session that never gets past step 2 says
//! what it was short of in its disconnect summary, since the gate is otherwise
//! silent until it decides and a stream that never qualifies would look
//! identical to one that is merely slow.
//!
//! # What it never drops
//!
//! **Auxiliary IDRs.** An IDR with `long_term_reference_flag` set marks every
//! other reference unused and claims `LongTermFrameIdx` 0 (8.2.5.1), so a main
//! slice naming long-term 0 straight after one is naming that auxiliary
//! picture. guacd flags a keyframe on `nal_type` 5, so every auxiliary IDR
//! passes through and the main slice gets the identical picture either way.
//! They are a few pictures in a hundred.
//!
//! Dropping is safe for guacd too: it calls `guac_client_free_stream` as soon
//! as it has written the blobs, so nothing waits on an acknowledgement for a
//! stream swallowed here.
//!
//! # Where it sits
//!
//! In `guacd_to_ws`, after the recording tee -- so recordings keep the full
//! 4:4:4 stream and `SessionRecording.js` is unaffected -- and before the
//! colour rewrite and the binary blob splitter.
//!
//! `RUSTGUAC_H264_AUX_DROP=0` turns it off. `=unproven` extends it to streams
//! the slice headers cannot prove (`Safety::Unproven`: an auxiliary picture
//! reachable in a main slice's reference list). That is for experiments only:
//! on the one such stream measured, a replay showed 12 of 141 main access
//! units undecodable once the views were removed.

use std::borrow::Cow;
use std::collections::HashSet;

use crate::h264_refs::{NalProbe, Safety};

/// Stream indices whose remaining instructions are being swallowed. Bounded so
/// a stream that never ends cannot grow it without limit.
const MAX_DROPPED_STREAMS: usize = 256;

/// How far the probe's own decision is trusted before the first drop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Accumulating. Everything passes through untouched -- except that every
    /// SPS is already being given permission to skip frame_num values, so that
    /// permission is older than any gap could be.
    Deciding,
    /// Dropping.
    Dropping,
    /// Proved unsafe, or switched off. Never looks again.
    Off,
}

/// Removes the auxiliary view from a stream that has proved it can spare it.
pub struct AuxDropper {
    probe: NalProbe,
    /// Whether to drop on streams the headers leave `Unproven`. Off by
    /// default, because the one host with that shape corrupted; never extends
    /// to `Unsafe`.
    unproven: bool,
    /// Set when the connection entry asked for this, which decides from the
    /// least evidence that can answer rather than from a corroborated sample.
    /// The gate still applies, and so does the running re-check.
    eager: bool,
    state: State,
    dropped_streams: HashSet<u32>,
    /// Auxiliary pictures dropped, and the payload bytes they carried.
    dropped_pictures: u64,
    dropped_bytes: u64,
    /// Auxiliary IDRs kept, which is the part that is deliberately not done.
    kept_idrs: u64,
    /// Main views whose `<paired>` flag was cleared.
    unpaired: u64,
    /// Times the in-flight set was cleared wholesale for overflow.
    ///
    /// Instrumented rather than assumed. Entries are added when an auxiliary
    /// view is dropped and removed at its `end`, so the set should hold one or
    /// two at a time; if an `end` were ever missed they would accumulate, the
    /// set would be cleared, and the blobs of anything mid-drop would leak
    /// through as orphans -- an `h264` with no data and no end, which is
    /// exactly the shape that hangs a client. Nothing has been seen to cause
    /// it, which is why it is counted rather than worked around.
    orphan_clears: u64,
    /// Whether this session was never in the running: the deployment kill
    /// switch, or an entry set to "never drop".
    ///
    /// Kept apart from `State::Off`, which a stream also reaches by being
    /// examined and refused. Both never drop; only one of them has anything
    /// to report. A summary saying the gate saw no auxiliary view "in 0
    /// pictures" describes a gate that was waiting, and this one was not.
    switched_off: bool,
    /// The session the summary belongs to, when there is one to name.
    ///
    /// Held here because the summary is written from `Drop` rather than by the
    /// caller. See the `Drop` impl.
    session: Option<uuid::Uuid>,
}

impl AuxDropper {
    /// A dropper for one session.
    ///
    /// `setting` comes from the session's colour choice (see
    /// `Session::aux_drop_setting`): `None` waits for the corroborated sample,
    /// `Some(true)` decides from the least evidence that can answer, and
    /// `Some(false)` -- full colour, which needs the view -- never drops. The
    /// environment variable still overrides everything, as a kill switch that
    /// needs no entry edited.
    pub fn for_session(setting: Option<bool>) -> Self {
        let mut dropper = Self::new();

        match setting {
            // Decide from the least evidence that can answer the question,
            // rather than from the corroborated sample. The gate still
            // applies: what an entry asserts is that this target is worth
            // dropping on, not that the stream should go unexamined.
            //
            // It cannot mean "drop from the first picture", however the
            // setting is worded. The evidence lives in inter slices, and a
            // host opens with a burst of keyframes that name no reference and
            // mark nothing -- 14 of them on the xrdp fork, about two seconds.
            // Dropping through that would be dropping blind, and a wrong guess
            // is not recoverable: the decoder errors, discards its queue and
            // waits for a keyframe an idle desktop never sends.
            Some(true) if dropper.state != State::Off => dropper.eager = true,
            Some(false) => {
                dropper.state = State::Off;
                dropper.switched_off = true;
            }
            _ => {}
        }

        dropper
    }

    fn new() -> Self {
        let setting = std::env::var("RUSTGUAC_H264_AUX_DROP").unwrap_or_default();
        let setting = setting.trim().to_ascii_lowercase();
        let enabled = !matches!(setting.as_str(), "0" | "off" | "false" | "no");
        // Only what the slice headers can prove, by default: the one unproven
        // stream measured corrupted when its auxiliary views were dropped (see
        // the module documentation). `unproven` puts it back for experiments.
        let unproven = matches!(setting.as_str(), "unproven" | "force");

        Self {
            probe: NalProbe::new(),
            unproven,
            state: if enabled { State::Deciding } else { State::Off },
            dropped_streams: HashSet::new(),
            dropped_pictures: 0,
            dropped_bytes: 0,
            kept_idrs: 0,
            unpaired: 0,
            orphan_clears: 0,
            eager: false,
            switched_off: !enabled,
            session: None,
        }
    }

    /// Names the session its summary belongs to. Without it the summary is
    /// still written, just without the field to correlate it by.
    pub fn reporting_as(mut self, session: uuid::Uuid) -> Self {
        self.session = Some(session);
        self
    }

    /// Reads one chunk of the guacd → browser stream, returning what should be
    /// sent in its place and any lines to log.
    ///
    /// The chunk always ends on an instruction boundary (see `guacd_to_ws`),
    /// so every instruction start in it is a real one, and an instruction is
    /// never split across two calls.
    pub fn process<'a>(&mut self, text: &'a str) -> (Cow<'a, str>, Vec<String>) {
        self.probe.observe(text);
        let mut lines = Vec::new();

        if self.state == State::Off {
            return (Cow::Borrowed(text), lines);
        }

        // A verdict reached from the first few auxiliary views is a verdict
        // about the first few auxiliary views. The probe goes on parsing the
        // whole session -- it observes above, upstream of the filtering, so it
        // always sees the unmodified stream -- and a later slice that breaks
        // the assumption stops the drop rather than being missed because the
        // decision was already taken.
        if self.state == State::Dropping && self.probe.safety(self.eager) == Safety::Unsafe {
            self.state = State::Off;
            lines.push(format!(
                "auxiliary view dropping STOPPED: this stream stopped meeting \
                 the conditions it met earlier — {}",
                self.probe.verdict()
            ));
            return (Cow::Borrowed(text), lines);
        }

        if self.state == State::Deciding {
            let safety = self.probe.safety(self.eager);
            let unproven = safety == Safety::Unproven;

            match safety {
                Safety::Undecided => return (Cow::Borrowed(text), lines),
                Safety::Unproven if !self.unproven => {
                    self.state = State::Off;
                    lines.push(format!(
                        "auxiliary view will NOT be dropped on this stream: the \
                         slice headers cannot prove it, and the one stream of \
                         this shape measured corrupted when it was dropped \
                         (RUSTGUAC_H264_AUX_DROP=unproven to try again) — {}",
                        self.probe.verdict()
                    ));
                    return (Cow::Borrowed(text), lines);
                }
                Safety::Safe | Safety::Unproven => {
                    self.state = State::Dropping;
                    lines.push(format!(
                        "auxiliary view {} on this stream — {}",
                        if unproven {
                            "is being dropped, UNPROVEN — the headers cannot \
                             rule out a reference to it, so watch for drift \
                             between keyframes"
                        } else {
                            "is being dropped"
                        },
                        self.probe.verdict()
                    ));
                }
                Safety::Unsafe => {
                    self.state = State::Off;
                    lines.push(format!(
                        "auxiliary view will NOT be dropped on this stream — {}",
                        self.probe.verdict()
                    ));
                    return (Cow::Borrowed(text), lines);
                }
            }
        }

        (self.filter(text), lines)
    }

    /// Rewrites one chunk, borrowing it unchanged when nothing needed doing --
    /// which is most chunks even while dropping, since only some carry an
    /// auxiliary view.
    fn filter<'a>(&mut self, text: &'a str) -> Cow<'a, str> {
        let mut out: Option<String> = None;
        // Start of text not yet copied into `out`.
        let mut pending = 0usize;
        let mut pos = 0usize;

        while pos < text.len() {
            let start = pos;

            // Only the three opcodes this touches are parsed past their first
            // element; everything else is stepped over without collecting
            // anything, which is most of the stream.
            let Some((opcode, mut next, mut terminator)) = crate::binary_blob::element(text, pos)
            else {
                // Malformed or truncated. Copy the remainder verbatim and
                // stop: a blob that cannot be parsed is passed through, never
                // dropped, because losing one loses a picture.
                break;
            };

            let interesting = matches!(opcode, "h264" | "blob" | "end");
            let mut args: Vec<&str> = Vec::new();

            while terminator == b',' {
                let Some((value, after, term)) = crate::binary_blob::element(text, next) else {
                    // Truncated mid-instruction. Everything from here is
                    // copied verbatim by the tail below.
                    next = text.len();
                    break;
                };
                if interesting {
                    args.push(value);
                }
                next = after;
                terminator = term;
            }

            pos = next;

            let action = if interesting {
                self.classify(opcode, &args)
            } else {
                Action::Keep
            };

            if matches!(action, Action::Keep) {
                continue;
            }

            // First edit in this chunk: copy everything before it.
            let buf = out.get_or_insert_with(|| String::with_capacity(text.len()));
            buf.push_str(&text[pending..start]);
            if let Action::Replace(ref s) = action {
                buf.push_str(s);
            }
            pending = pos;
        }

        match out {
            Some(mut buf) => {
                buf.push_str(&text[pending..]);
                Cow::Owned(buf)
            }
            None => Cow::Borrowed(text),
        }
    }

    /// What to do with one instruction, given its opcode and arguments.
    fn classify(&mut self, opcode: &str, args: &[&str]) -> Action {
        match opcode {
            "h264" => self.classify_h264(args),

            "blob" => {
                let Some(index) = args.first().and_then(|v| v.parse::<u32>().ok()) else {
                    return Action::Keep;
                };
                if !self.dropped_streams.contains(&index) {
                    return Action::Keep;
                }
                // Counted from the base64 length rather than by decoding: the
                // saving is what is not sent, and that is this.
                if let Some(payload) = args.get(1) {
                    self.dropped_bytes += (payload.len() / 4 * 3) as u64;
                }
                Action::Drop
            }

            "end" => {
                let Some(index) = args.first().and_then(|v| v.parse::<u32>().ok()) else {
                    return Action::Keep;
                };
                if self.dropped_streams.remove(&index) {
                    Action::Drop
                } else {
                    Action::Keep
                }
            }

            _ => Action::Keep,
        }
    }

    /// `h264,<stream>,<layer>,<keyframe>,<x>,<y>,<w>,<h>,<view>,<numrects>,
    /// [<x> <y> <w> <h>]...,<paired>`
    fn classify_h264(&mut self, args: &[&str]) -> Action {
        // Indices, counted from the first element after the opcode:
        //   0 stream, 1 layer, 2 keyframe, 3 x, 4 y, 5 width, 6 height,
        //   7 view, 8 numrects, then 4 per rect, then paired.
        if args.len() < 9 {
            return Action::Keep;
        }

        let Ok(index) = args[0].parse::<u32>() else {
            return Action::Keep;
        };
        let keyframe = args[2] == "1";
        let view: u8 = args[7].parse().unwrap_or(0);

        if view != 0 {
            if keyframe {
                // Deliberately kept; see the module documentation.
                self.kept_idrs += 1;
                return Action::Keep;
            }
            if self.state != State::Dropping {
                return Action::Keep;
            }
            if self.dropped_streams.len() >= MAX_DROPPED_STREAMS {
                self.dropped_streams.clear();
                self.orphan_clears += 1;
            }
            self.dropped_streams.insert(index);
            self.dropped_pictures += 1;
            return Action::Drop;
        }

        if self.state != State::Dropping {
            return Action::Keep;
        }

        // `<paired>` promises an auxiliary view that is no longer coming, and
        // a client that believes it holds the main view's paint waiting for
        // one. It trails the rects, which vary in number.
        let Ok(num_rects) = args[8].parse::<usize>() else {
            return Action::Keep;
        };
        let paired_at = 9 + num_rects * 4;
        if args.get(paired_at).copied() != Some("1") {
            return Action::Keep;
        }

        let mut rewritten = args.to_vec();
        rewritten[paired_at] = "0";
        self.unpaired += 1;
        Action::Replace(encode_instruction("h264", &rewritten))
    }

    /// What the session saved, for the disconnect log.
    pub fn summary(&self) -> Option<String> {
        if self.switched_off {
            // Nothing was asked of this stream, so there is nothing to say
            // about what it did not do.
            return None;
        }
        if self.dropped_pictures == 0 {
            // Nothing was dropped. If it never decided, say what it was short
            // of: the gate is silent until it makes up its mind, so otherwise
            // a session that never decides leaves nothing to read at all.
            return self
                .probe
                .undecided_reason(self.eager)
                .map(|reason| format!("auxiliary view was never dropped: {}", reason));
        }
        Some(format!(
            "dropped {} auxiliary pictures ({} KiB), kept {} auxiliary \
             keyframes, unpaired {} main views, {} in flight{}",
            self.dropped_pictures,
            self.dropped_bytes / 1024,
            self.kept_idrs,
            self.unpaired,
            self.dropped_streams.len(),
            if self.orphan_clears > 0 {
                format!(
                    ", OVERFLOWED {} times — streams were left in flight and \
                     their blobs may have leaked through",
                    self.orphan_clears
                )
            } else {
                String::new()
            }
        ))
    }

    /// Whether an SPS crossing now should be given permission to skip
    /// `frame_num` values.
    ///
    /// True from the first instruction of the session, not from the moment the
    /// stream proves itself. The flag has to be older than the first gap, and
    /// an SPS only rides a keyframe: Windows sends three in its connect-time
    /// burst and then can go minutes without one, so waiting to set it meant
    /// waiting for a keyframe that might never come, with the auxiliary view
    /// still on the wire the whole time.
    ///
    /// Setting it on a stream that never gets dropped from costs nothing. The
    /// flag only permits a decoder to infer pictures for `frame_num` values it
    /// never saw (8.2.5.2); with no gaps in the stream there is nothing to
    /// infer and nothing behaves differently.
    pub fn wants_frame_num_gaps(&self) -> bool {
        self.state != State::Off
    }

    /// Whether the auxiliary view is being removed from the wire right now.
    ///
    /// Read once per chunk so the browser can be told, because the browser
    /// cannot work it out. It switches 4:4:4 combining on at the first
    /// auxiliary view it sees and off at nothing in particular, and auxiliary
    /// IDRs are deliberately kept -- so one of those arms the combine, and
    /// every main view after it then pays a plane read-back, six texture
    /// uploads and a shader pass to produce the ordinary 4:2:0 picture a
    /// `drawImage` would have produced for nothing, waiting for a view that
    /// will never come. Inferring it from a quiet stretch instead would be
    /// guessing: a Windows desktop sends chroma in about one picture in eight
    /// and the xrdp fork's `CHROMA_INTERVAL` sends it rarer still, so a
    /// silence long enough to be evidence is also long enough to have cost
    /// the session, and a wrong guess costs a whole-plane resync each way.
    pub fn dropping(&self) -> bool {
        self.state == State::Dropping
    }
}

/// Writes the summary on the way out, however the session ended.
///
/// Written here rather than by the caller after `guacd_to_ws`'s read loop,
/// which is reached only when guacd closes first. A session normally ends the
/// other way round -- the browser goes, `run_proxy`'s select! resolves on the
/// browser-side task and drops the guacd-side future where it stands -- and
/// the line would then be the instrument that is silently absent: a stream the
/// gate never decides about says nothing at all until this reports what it was
/// short of, and the overflow warning for leaked in-flight streams would never
/// be in a position to fire.
///
/// Drop runs on every one of those paths, including cancellation.
impl Drop for AuxDropper {
    fn drop(&mut self) {
        let Some(summary) = self.summary() else {
            return;
        };
        match self.session {
            Some(session) => tracing::info!(session_id = %session, "H.264: {}", summary),
            None => tracing::info!("H.264: {}", summary),
        }
    }
}

enum Action {
    Keep,
    Drop,
    Replace(String),
}

fn encode_instruction(opcode: &str, args: &[&str]) -> String {
    let mut out = String::with_capacity(16 + args.iter().map(|a| a.len() + 6).sum::<usize>());
    out.push_str(&format!("{}.{}", opcode.len(), opcode));
    for arg in args {
        out.push_str(&format!(",{}.{}", arg.len(), arg));
    }
    out.push(';');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One `h264` instruction, built as guac_h264_write_arg() builds it.
    fn h264(index: u32, keyframe: bool, view: u8, rects: usize, paired: bool) -> String {
        let mut args = vec![
            index.to_string(),
            "0".into(),
            u8::from(keyframe).to_string(),
            "0".into(),
            "0".into(),
            "1920".into(),
            "1080".into(),
            view.to_string(),
            rects.to_string(),
        ];
        for r in 0..rects {
            args.extend([r.to_string(), "0".into(), "16".into(), "16".into()]);
        }
        args.push(u8::from(paired).to_string());
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        encode_instruction("h264", &refs)
    }

    fn blob(index: u32, payload: &str) -> String {
        encode_instruction("blob", &[&index.to_string(), payload])
    }

    fn end(index: u32) -> String {
        encode_instruction("end", &[&index.to_string()])
    }

    /// A dropper already past its gate, so the filtering can be tested without
    /// feeding it a session's worth of real bitstream.
    fn dropping() -> AuxDropper {
        let mut d = AuxDropper::new();
        d.state = State::Dropping;
        d
    }

    /// The entry setting decides from less evidence; it does not decide
    /// differently, and it does not switch the gate off.
    #[test]
    fn an_entry_setting_is_eager_not_unchecked() {
        let d = AuxDropper::for_session(Some(true));
        assert!(d.eager);
        assert_eq!(d.state, State::Deciding, "still has to prove the stream");
    }

    /// An entry that says no is never examined.
    #[test]
    fn an_entry_can_refuse_outright() {
        let mut d = AuxDropper::for_session(Some(false));
        assert_eq!(d.state, State::Off);
        assert!(!d.wants_frame_num_gaps());

        let text = h264(1, false, 2, 0, false);
        let (out, _) = d.process(&text);
        assert_eq!(out, text.as_str());
    }

    /// Unset waits for the corroborated sample rather than the minimum.
    #[test]
    fn an_unset_entry_waits_for_corroboration() {
        let d = AuxDropper::for_session(None);
        assert_eq!(d.state, State::Deciding);
        assert!(!d.eager);
    }

    #[test]
    fn an_auxiliary_picture_goes_with_its_blobs_and_its_end() {
        let mut d = dropping();
        let text = format!(
            "{}{}{}{}{}{}",
            h264(7, false, 0, 0, false),
            blob(7, "bWFpbg=="),
            end(7),
            h264(8, false, 2, 0, false),
            blob(8, "YXV4"),
            end(8)
        );

        let (out, _) = d.process(&text);
        assert!(out.contains("4.h264,1.7"), "{}", out);
        assert!(out.contains("bWFpbg=="), "{}", out);
        assert!(!out.contains("4.h264,1.8"), "{}", out);
        assert!(!out.contains("YXV4"), "{}", out);
        assert_eq!(out.matches("3.end").count(), 1, "{}", out);
        assert_eq!(d.dropped_pictures, 1);
    }

    /// A main view promising a pair that will not arrive would be held unpainted
    /// forever, so the flag has to be cleared -- past the rects, which vary.
    #[test]
    fn the_paired_flag_is_cleared_past_the_rects() {
        for rects in [0, 1, 9] {
            let mut d = dropping();
            let text = h264(3, false, 0, rects, true);
            let (out, _) = d.process(&text);

            assert_ne!(out, text.as_str(), "{} rects: not rewritten", rects);
            assert_eq!(d.unpaired, 1, "{} rects", rects);

            // The rects themselves must survive the rebuild untouched.
            let expected = h264(3, false, 0, rects, false);
            assert_eq!(out, expected.as_str(), "{} rects", rects);
        }
    }

    /// An auxiliary keyframe is a buffer reset the surviving stream is written
    /// against, and the interaction is unresolved. It stays.
    #[test]
    fn an_auxiliary_keyframe_is_kept() {
        let mut d = dropping();
        let text = format!(
            "{}{}{}",
            h264(9, true, 2, 0, false),
            blob(9, "aQ=="),
            end(9)
        );

        let (out, _) = d.process(&text);
        assert_eq!(out, text.as_str());
        assert_eq!(d.kept_idrs, 1);
        assert_eq!(d.dropped_pictures, 0);
    }

    /// Nothing is touched before the stream has proved itself.
    #[test]
    fn nothing_is_dropped_while_deciding() {
        let mut d = AuxDropper::new();
        let text = format!(
            "{}{}{}",
            h264(4, false, 2, 0, false),
            blob(4, "eA=="),
            end(4)
        );

        let (out, _) = d.process(&text);
        assert!(matches!(out, Cow::Borrowed(_)), "should not even copy");
        assert_eq!(out, text.as_str());
    }

    /// Permission to skip frame_num values is asked for from the first
    /// instruction, not from the moment the stream proves itself.
    ///
    /// An SPS only rides a keyframe, and Windows sends three at connect and
    /// then can go minutes without one — so a flag set at the decision would
    /// wait for a keyframe that might never come, with the auxiliary view on
    /// the wire throughout. Setting it on a stream that never gets dropped
    /// from is inert: it permits inferring pictures for frame_num values never
    /// seen, and there are none.
    #[test]
    fn gaps_are_permitted_before_anything_is_decided() {
        let d = AuxDropper::new();
        assert_eq!(d.state, State::Deciding);
        assert!(d.wants_frame_num_gaps(), "from the very first chunk");
    }

    /// And a stream that proves itself unsafe stops asking, since it will
    /// never open a gap.
    #[test]
    fn a_stream_that_will_not_be_dropped_stops_asking_for_gaps() {
        let mut d = AuxDropper::new();
        d.state = State::Off;
        assert!(!d.wants_frame_num_gaps());
    }

    /// Dropping starts as soon as the gate clears, with no keyframe in
    /// between.
    #[test]
    fn dropping_needs_no_keyframe_to_begin() {
        let mut d = dropping();
        let aux = h264(4, false, 2, 0, false);
        let (out, _) = d.process(&aux);

        assert_eq!(out, "", "{}", out);
        assert_eq!(d.dropped_pictures, 1);
    }

    /// Instructions this knows nothing about pass through byte for byte, and a
    /// chunk needing no edit is never copied.
    #[test]
    fn unrelated_instructions_are_untouched() {
        let mut d = dropping();
        let text = format!(
            "4.sync,13.1700000000000;{}5.blob2,3.abc;",
            h264(5, false, 0, 2, false)
        );

        let (out, _) = d.process(&text);
        assert!(matches!(out, Cow::Borrowed(_)), "no edit, no copy");
        assert_eq!(out, text.as_str());
    }

    /// An unproven stream is left alone by default: the one stream of that
    /// shape measured corrupted when its auxiliary views were dropped.
    #[test]
    fn unproven_streams_are_left_alone_by_default() {
        assert!(!AuxDropper::new().unproven);
    }

    /// A stream that stops meeting the conditions stops being dropped from.
    ///
    /// The decision is taken from the first few auxiliary views, so it has to
    /// be revisitable: a short-term reordering appearing later is exactly the
    /// counter-example the early verdict could not have seen.
    #[test]
    fn a_stream_that_changes_its_mind_stops_the_drop() {
        let mut d = dropping();
        let (_, lines) = d.process(&h264(1, false, 2, 0, false));
        assert!(lines.is_empty(), "nothing wrong yet");
        assert_eq!(d.state, State::Dropping);
        assert_eq!(d.dropped_pictures, 1);

        // The probe is real, so rather than fabricate a bitstream that turns
        // unsafe, the state is driven directly: what is under test is that a
        // verdict of Unsafe while dropping stops it, not how one is reached.
        d.state = State::Off;
        let text = format!("{}{}", h264(2, false, 2, 0, false), blob(2, "eA=="));
        let (out, _) = d.process(&text);
        assert_eq!(out, text.as_str(), "passes through once stopped");
        assert_eq!(d.dropped_pictures, 1, "and drops nothing more");
    }

    /// A non-ASCII instruction must not shift the instruction boundaries.
    ///
    /// Guacamole element lengths count UTF-16 code units, not bytes. The first
    /// version of this filter parsed them as bytes, which is identical for
    /// ASCII and wrong the moment a clipboard, a name or an error string
    /// carries anything else -- and because this rewrites the wire rather than
    /// only reading it, a mis-sliced instruction desynchronises the client's
    /// parser for the rest of the session. The stream has no resynchronisation
    /// point, so that is a hang rather than a glitch.
    #[test]
    fn non_ascii_instructions_do_not_shift_the_boundaries() {
        for text in [
            "9.clipboard,1.1,10.text/plain;",
            // Three characters, six bytes: a byte-length reader stops short.
            "4.name,3.héé;",
            // Outside the BMP. guacd counts codepoints when it writes the
            // length (guac_utf8_strlen), so this is 1 and not the 2 that
            // Guacamole's Java and JavaScript ends would write from
            // String.length(). The parser follows the producer, since that is
            // what is being read here; do not "fix" this to 2.
            "4.name,1.😀;",
            "5.error,5.wonky,4.0512;",
        ] {
            let mut d = dropping();
            let aux = h264(9, false, 2, 0, false);
            let combined = format!("{}{}{}", text, aux, text);

            let (out, _) = d.process(&combined);
            assert_eq!(
                out,
                format!("{}{}", text, text).as_str(),
                "boundaries shifted around {:?}",
                text
            );
            assert_eq!(d.dropped_pictures, 1, "for {:?}", text);
        }
    }

    /// And one that needs no edit is passed through untouched rather than
    /// re-encoded, so a chunk of clipboard traffic costs nothing.
    #[test]
    fn non_ascii_with_nothing_to_drop_is_not_copied() {
        let mut d = dropping();
        let text = "9.clipboard,1.1,10.text/plain;4.blob,1.1,8.w6nDqcOp;3.end,1.1;";

        let (out, _) = d.process(text);
        assert!(matches!(out, Cow::Borrowed(_)), "no edit, no copy");
        assert_eq!(out, text);
    }

    /// A blob whose `h264` was never seen belongs to some other stream and is
    /// not ours to touch.
    #[test]
    fn blobs_of_unknown_streams_pass_through() {
        let mut d = dropping();
        let text = format!("{}{}", blob(77, "YQ=="), end(77));

        let (out, _) = d.process(&text);
        assert_eq!(out, text.as_str());
        assert_eq!(d.orphan_clears, 0);
    }

    /// Runs the real dropper over a real recording and checks that what comes
    /// out is a stream a client could follow.
    ///
    /// Ignored by default because it needs a capture:
    ///
    /// ```text
    /// RUSTGUAC_AUX_DROP_RECORDING=/tmp/xrdp.guac \
    ///     cargo test aux_drop_over_a_recording -- --ignored --nocapture
    /// ```
    ///
    /// `tests/aux-drop-replay.mjs` proves the *bitstream* survives the drop;
    /// it decodes pictures and cannot see the instruction framing at all. This
    /// is the other half, and the half that hangs a client: an `h264` whose
    /// blobs never arrive leaves the browser holding an open stream forever,
    /// and a `blob` for a stream that was never announced is dropped on the
    /// floor. Neither shows up as corruption -- the display simply stops.
    ///
    /// Chunked at several sizes because `guacd_to_ws` hands over whatever one
    /// read produced, cut at the last instruction boundary, so the filter must
    /// not care where the cuts fall.
    #[test]
    #[ignore]
    fn aux_drop_over_a_recording() {
        let Ok(path) = std::env::var("RUSTGUAC_AUX_DROP_RECORDING") else {
            panic!("set RUSTGUAC_AUX_DROP_RECORDING to a .guac recording");
        };
        let recording = std::fs::read_to_string(&path).expect("readable recording");

        for chunk_target in [4096usize, 65536, usize::MAX] {
            let mut dropper = AuxDropper::for_session(Some(true));
            let mut output = String::new();

            // Cut on instruction boundaries, as guacd_to_ws does.
            let mut pos = 0usize;
            while pos < recording.len() {
                let mut end = pos;
                while end < recording.len() {
                    let Some((_, next, term)) = crate::binary_blob::element(&recording, end) else {
                        end = recording.len();
                        break;
                    };
                    end = next;
                    if term == b';' && end - pos >= chunk_target.min(recording.len()) {
                        break;
                    }
                }
                let (out, _) = dropper.process(&recording[pos..end]);
                output.push_str(&out);
                assert!(end > pos, "chunker made no progress at {}", pos);
                pos = end;
            }

            // Only H.264 streams are checked: a recording carries clipboard,
            // image and audio streams too, whose blobs this never announces
            // and must not touch. Indices are recycled across all of them, so
            // membership is tracked as the walk goes rather than by index
            // alone.
            let mut open: HashSet<u32> = HashSet::new();
            let mut blobs: std::collections::HashMap<u32, u32> = Default::default();
            let mut empty = 0u32;
            let mut reopened = 0u32;
            let mut instructions = 0u32;
            let mut h264s = 0u32;

            let mut at = 0usize;
            while at < output.len() {
                let Some((opcode, mut next, mut term)) = crate::binary_blob::element(&output, at)
                else {
                    panic!(
                        "chunk {}: output stops parsing at byte {} of {} — the \
                         client's parser would stop here too",
                        chunk_target,
                        at,
                        output.len()
                    );
                };
                let mut args: Vec<&str> = Vec::new();
                while term == b',' {
                    let Some((v, a, t)) = crate::binary_blob::element(&output, next) else {
                        panic!("chunk {}: truncated instruction at {}", chunk_target, at);
                    };
                    args.push(v);
                    next = a;
                    term = t;
                }
                instructions += 1;
                assert!(next > at, "verification made no progress at {}", at);
                at = next;

                let index = args.first().and_then(|v| v.parse::<u32>().ok());
                match (opcode, index) {
                    ("h264", Some(i)) => {
                        h264s += 1;
                        if !open.insert(i) {
                            reopened += 1;
                        }
                        blobs.insert(i, 0);
                    }
                    ("blob", Some(i)) if open.contains(&i) => {
                        *blobs.entry(i).or_default() += 1;
                    }
                    ("end", Some(i))
                        if open.remove(&i) && blobs.get(&i).copied().unwrap_or(0) == 0 =>
                    {
                        empty += 1;
                    }
                    _ => {}
                }
            }

            println!(
                "chunk {:>10}: {} instructions out, {} h264, {} dropped \
                 pictures, {} unpaired, {} in flight",
                chunk_target,
                instructions,
                h264s,
                dropper.dropped_pictures,
                dropper.unpaired,
                dropper.dropped_streams.len()
            );

            assert_eq!(
                empty, 0,
                "chunk {}: an h264 stream was announced and carried no blobs — \
                 the client opens a stream that never receives data",
                chunk_target
            );
            assert_eq!(
                reopened, 0,
                "chunk {}: an h264 index was announced twice without closing",
                chunk_target
            );
            assert_eq!(
                open.len(),
                0,
                "chunk {}: {} h264 streams left open — the client waits forever",
                chunk_target,
                open.len()
            );
        }
    }

    /// A host that only ever sends AVC420 is passed through untouched, and
    /// not merely left undropped.
    ///
    /// There is no auxiliary view to drop, so the gate can never leave
    /// `Undecided` and the filter is never entered -- the chunk is borrowed,
    /// not rebuilt. Worth pinning because dropping is the default, so this path
    /// carries every AVC420 host -- stock xrdp among them.
    #[test]
    fn an_avc420_only_stream_is_passed_through_untouched() {
        for entry in [None, Some(true)] {
            let mut d = AuxDropper::for_session(entry);

            // Far more pictures than any threshold asks for.
            let mut text = String::new();
            for i in 0..120u32 {
                text.push_str(&h264(i, i % 30 == 0, 0, i as usize % 3, false));
                text.push_str(&blob(i, "bWFpbg=="));
                text.push_str(&end(i));
            }

            let (out, lines) = d.process(&text);
            assert!(
                matches!(out, Cow::Borrowed(_)),
                "{:?}: an AVC420 stream should not even be copied",
                entry
            );
            assert_eq!(out, text.as_str(), "{:?}", entry);
            assert_eq!(d.dropped_pictures, 0, "{:?}", entry);
            assert_eq!(d.state, State::Deciding, "{:?}: never decides", entry);
            assert!(lines.is_empty(), "{:?}: and says nothing", entry);
        }
    }

    /// Even an entry that refuses outright leaves it alone, which is the other
    /// AVC420 case: `avc444` off on the entry, so the server sends one view.
    #[test]
    fn an_avc420_only_stream_is_untouched_when_refused() {
        let mut d = AuxDropper::for_session(Some(false));
        let text = format!(
            "{}{}{}",
            h264(1, true, 0, 2, false),
            blob(1, "YQ=="),
            end(1)
        );

        let (out, _) = d.process(&text);
        assert_eq!(out, text.as_str());
        assert!(!d.wants_frame_num_gaps(), "and no SPS is edited either");
    }

    /// A session that never decides says what it was short of.
    ///
    /// The gate is otherwise silent until it makes up its mind, so "it seems
    /// slow to start dropping" had nothing to read against it.
    #[test]
    fn a_session_that_never_decides_says_why() {
        let mut d = AuxDropper::for_session(None);

        // Main views only: the commonest reason, and the one an AVC420 host
        // hits for the whole session.
        let mut text = String::new();
        for i in 0..12u32 {
            text.push_str(&h264(i, i == 0, 0, 0, false));
            text.push_str(&blob(i, "bWFpbg=="));
            text.push_str(&end(i));
        }
        d.process(&text);

        let summary = d.summary().expect("a reason, since nothing was dropped");
        assert!(
            summary.contains("never dropped") && summary.contains("no auxiliary view"),
            "{}",
            summary
        );
    }

    /// And a session that dropped reports the drop, not a reason.
    #[test]
    fn a_session_that_dropped_reports_the_drop() {
        let mut d = dropping();
        d.process(&h264(1, false, 2, 0, false));

        let summary = d.summary().expect("a summary");
        assert!(summary.starts_with("dropped 1 auxiliary"), "{}", summary);
    }

    /// And it is written on the way out, however the session ended.
    ///
    /// Written from `Drop` because the tail of `guacd_to_ws`'s read loop is
    /// reached only when guacd closes first; a browser closing -- the normal
    /// case -- drops that future where it stands. The two tests above cover
    /// what the summary *says*; this is the one that covers its being said at
    /// all, which is the half they cannot see.
    #[test]
    fn the_summary_is_written_when_the_dropper_is_dropped() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);

        impl Write for Buffer {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(data);
                Ok(data.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buffer {
            type Writer = Self;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let buffer = Buffer(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buffer.clone())
            .with_ansi(false)
            .finish();

        let session = uuid::Uuid::new_v4();

        tracing::subscriber::with_default(subscriber, || {
            let mut d = dropping().reporting_as(session);
            d.process(&h264(1, false, 2, 0, false));
            // No explicit summary() call: only the drop below may write it.
        });

        let written = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert!(
            written.contains("dropped 1 auxiliary"),
            "the summary was not written on drop: {:?}",
            written
        );
        assert!(
            written.contains(&session.to_string()),
            "the summary lost its session id: {:?}",
            written
        );
    }

    /// A session the drop was switched off for says nothing on the way out.
    ///
    /// State::Off is reached two ways -- switched off, or examined and refused
    /// -- and only the second has anything to report. Reporting both writes
    /// "no auxiliary view has arrived in 0 pictures" for a gate that was never
    /// waiting, on every never-drop session.
    #[test]
    fn a_dropper_that_was_switched_off_writes_nothing() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};

        let sink = Arc::new(Mutex::new(Vec::new()));
        struct W(Arc<Mutex<Vec<u8>>>);
        impl Write for W {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(data);
                Ok(data.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let made = sink.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || W(made.clone()))
            .with_ansi(false)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            // Switched off: no verdict, nothing dropped, no reason to give.
            let mut d = AuxDropper::for_session(Some(false));
            d.process(&h264(1, false, 2, 0, false));
        });

        let written = String::from_utf8(sink.lock().unwrap().clone()).unwrap();
        assert!(
            written.is_empty(),
            "wrote a summary it had nothing for: {:?}",
            written
        );
    }

    /// A session that carried no H.264 at all has nothing to report: no
    /// stream was waited on, so "never dropped" would describe nothing.
    #[test]
    fn a_session_without_h264_has_no_summary() {
        let mut d = AuxDropper::for_session(None);
        d.process("4.sync,4.1000;4.size,1.0,4.1920,4.1080;");
        assert_eq!(d.summary(), None);
    }

    /// The env var is the kill switch, and off means never looking.
    #[test]
    fn the_kill_switch_disables_it() {
        let mut d = AuxDropper::new();
        d.state = State::Off;

        let text = format!("{}{}", h264(6, false, 2, 0, false), blob(6, "eA=="));
        let (out, _) = d.process(&text);
        assert_eq!(out, text.as_str());
        assert_eq!(d.dropped_pictures, 0);
    }

    /// Several instructions in one chunk, with the edit in the middle: the
    /// prefix before the first edit has to be copied exactly once.
    #[test]
    fn an_edit_mid_chunk_keeps_both_sides() {
        let mut d = dropping();
        let text = format!(
            "{}{}{}{}{}",
            h264(1, false, 0, 0, false),
            blob(1, "YQ=="),
            h264(2, false, 2, 0, false),
            blob(2, "Yg=="),
            h264(3, false, 0, 0, false),
        );

        let (out, _) = d.process(&text);
        let expected = format!(
            "{}{}{}",
            h264(1, false, 0, 0, false),
            blob(1, "YQ=="),
            h264(3, false, 0, 0, false),
        );
        assert_eq!(out, expected.as_str());
    }
}
