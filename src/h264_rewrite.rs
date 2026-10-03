//! Makes an RDP host's colour range legible to the browser.
//!
//! An SPS that declares `video_full_range_flag = 1` and no colour description
//! is honoured by Chrome's software decoder and ignored by its hardware one.
//! Measured on one browser against two hosts, both decoding to NV12:
//!
//! | host | SPS | reported |
//! |---|---|---|
//! | xrdp fork | `full_range=1`, primaries/transfer/matrix all BT.709 | full |
//! | Windows | `full_range=1`, no description | **limited** |
//!
//! Same client, same hardware path; the description is the only difference.
//! A Windows session therefore renders with blacks crushed to zero and chroma
//! over-saturated by 255/224, and neither end can see it: the host declared
//! the range, and the browser reports limited.
//!
//! This gives Windows the shape xrdp already has, by splicing a BT.709
//! description into the SPS on its way past. That fixes both render paths at
//! once — including `drawImage()`, which no client-side flag can reach — and
//! every client, including third-party ones. See `crate::h264_sps` for the
//! bit-level work and the measurements.
//!
//! Recordings are teed upstream of this and keep the host's original stream,
//! which is what a recording should be. Playback of a Windows recording is
//! subject to the same fault, and `?h264FullRange=on` is the lever there.

use base64::Engine as _;
use std::collections::HashSet;

/// What has been decided about this session's stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// No SPS seen yet, so every video blob is examined.
    Undecided,
    /// This stream's SPS needs a description, and each one is rewritten.
    Rewriting,
    /// This stream needs no colour work. Unless it also needs its reordering
    /// bounded or the gaps flag set, nothing is examined again — which is the
    /// case for xrdp, for any host that already describes its colour, and for
    /// every session with no passthrough at all.
    PassThrough,
}

/// One of the two edits `SpsRewriter` makes, for the caller to report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edit {
    /// A colour description spliced in beside a range the host declared bare.
    ColourDescription,
    /// `gaps_in_frame_num_value_allowed_flag` set, ahead of the auxiliary
    /// view being dropped.
    FrameNumGaps,
    /// `bitstream_restriction` added, declaring no picture reordering on a
    /// stream whose POC type already guarantees it.
    NoReordering,
}

impl Edit {
    /// What to say the first time this edit is made. Phrased for the journal,
    /// where it sits beside the `H.264 colour:` line describing what the host
    /// sent and, later, the browser's own report of what it made of it.
    pub fn describe(self) -> &'static str {
        match self {
            Edit::ColourDescription => concat!(
                "splicing a BT.709 description into the SPS, which Chrome's ",
                "hardware decoder needs before it will act on the range the ",
                "host declared"
            ),
            Edit::FrameNumGaps => concat!(
                "permitting frame_num gaps in the SPS, so a decoder accounts ",
                "for the pictures the auxiliary view drop removes rather than ",
                "failing on the holes they leave"
            ),
            Edit::NoReordering => concat!(
                "declaring max_num_reorder_frames=0 in the SPS: the stream's ",
                "POC type 2 already means output order is decode order, but ",
                "without bitstream_restriction Chrome's decoder holds a whole ",
                "DPB of pictures before painting any"
            ),
        }
    }
}

/// Edits the SPS of one session's H.264 stream, in flight.
///
/// Three independent edits share this pass because all need the same thing --
/// the SPS located inside a base64 video blob -- and decoding every keyframe's
/// blob once per edit would be work for nothing:
///
/// * a colour description, where the host declares a range without one
///   (`crate::h264_sps`),
/// * a bound of zero on picture reordering, where the POC type guarantees it
///   and the VUI does not say so (`crate::h264_sps::declare_no_reordering`),
///   and
/// * permission to skip `frame_num` values, when `crate::h264_aux_drop` is
///   about to start removing pictures that consume them.
pub struct SpsRewriter {
    state: State,
    /// What the stream's first SPS declared about colour, as the host sent
    /// it, until the caller takes it to log. See `take_wire_colour`.
    wire_colour: Option<String>,
    /// Whether this stream's SPS leaves reordering unbounded where it could
    /// say otherwise. Decided at the first SPS, beside `state`, and kept
    /// separate from it: the colour and the reorder bound are independent,
    /// and NVENC needs the second with the first already complete.
    bound_reordering: bool,
    /// Whether to set `gaps_in_frame_num_value_allowed_flag`. Driven per chunk
    /// by the dropper, which turns it on before it drops anything.
    allow_gaps: bool,
    /// Edits actually made and not yet reported.
    ///
    /// Held rather than inferred from `rewrite()` returning `Some`: with
    /// independent edits sharing the pass that answers "something changed",
    /// not "the colour description was added". A host whose SPS already
    /// describes its colour and needs only the gaps flag or the reorder bound
    /// would be logged as having a description spliced into it -- a line that
    /// is false, about the one subject where the wire log and the browser's
    /// report are meant to be read against each other.
    pending_edits: Vec<Edit>,
    /// Edits already reported once, so a stream carrying a keyframe a minute
    /// does not repeat them.
    made: Vec<Edit>,
    /// Stream indices opened by an `h264` instruction. `audio` is deliberately
    /// not tracked: its blobs are not video and decoding them to look for a
    /// start code would be work for nothing.
    h264_streams: HashSet<u32>,
}

impl Default for SpsRewriter {
    fn default() -> Self {
        Self::new()
    }
}

impl SpsRewriter {
    pub fn new() -> Self {
        Self {
            state: State::Undecided,
            wire_colour: None,
            bound_reordering: false,
            allow_gaps: false,
            pending_edits: Vec::new(),
            made: Vec::new(),
            h264_streams: HashSet::new(),
        }
    }

    /// What the stream's first SPS declared about its colour, once: `Some` on
    /// the first call after that SPS has been examined, `None` before and
    /// ever after. Read from the SPS as the host sent it, before any edit, so
    /// a log line built from it describes the wire rather than what was made
    /// of it.
    pub fn take_wire_colour(&mut self) -> Option<String> {
        self.wire_colour.take()
    }

    /// The edits made since this was last called, each reported once for the
    /// life of the session. Empty on all but a couple of chunks.
    pub fn take_edits(&mut self) -> Vec<Edit> {
        std::mem::take(&mut self.pending_edits)
    }

    /// Records an edit the first time it is made, so the caller can say what
    /// happened rather than that something did.
    fn note(&mut self, edit: Edit) {
        if !self.made.contains(&edit) {
            self.made.push(edit);
            self.pending_edits.push(edit);
        }
    }

    /// Asks for `gaps_in_frame_num_value_allowed_flag` on every SPS from now
    /// on. Idempotent, and called on every chunk while the dropper is armed.
    pub fn set_allow_frame_num_gaps(&mut self, allow: bool) {
        self.allow_gaps = allow;
    }

    /// Rewrites the SPS in any video blob in `text`, returning the new run of
    /// instructions — or `None` when nothing needed changing, which is the
    /// common case and copies nothing.
    ///
    /// `text` must end on an instruction boundary, as `guacd_to_ws`
    /// guarantees. Anything malformed stops the scan and leaves the remainder
    /// untouched: a blob that cannot be parsed is passed through, never
    /// dropped, since losing one loses a picture.
    pub fn rewrite(&mut self, text: &str) -> Option<String> {
        // PassThrough means no colour work, which is not the same as no work:
        // a stream needing no colour fix may still need its reordering bounded
        // or the gaps flag set.
        if self.state == State::PassThrough && !self.bound_reordering && !self.allow_gaps {
            return None;
        }

        let mut out: Option<String> = None;
        // Start of text not yet copied into `out`.
        let mut pending = 0usize;
        let mut pos = 0usize;

        while pos < text.len() {
            let instruction_start = pos;

            let Some((opcode, mut next, mut terminator)) = crate::binary_blob::element(text, pos)
            else {
                break;
            };

            let mut args: Vec<&str> = Vec::new();
            while terminator == b',' && args.len() < 2 {
                match crate::binary_blob::element(text, next) {
                    Some((value, after, term)) => {
                        args.push(value);
                        next = after;
                        terminator = term;
                    }
                    None => break,
                }
            }

            // Walk off the end: an `h264` instruction carries region rects
            // beyond the arguments read above.
            while terminator == b',' {
                match crate::binary_blob::element(text, next) {
                    Some((_, after, term)) => {
                        next = after;
                        terminator = term;
                    }
                    None => break,
                }
            }

            if terminator != b';' {
                break;
            }
            let instruction_end = next;
            pos = instruction_end;

            let index = args.first().and_then(|a| a.parse::<u32>().ok());

            match (opcode, index) {
                ("h264", Some(index)) => {
                    self.h264_streams.insert(index);
                }
                ("end", Some(index)) => {
                    self.h264_streams.remove(&index);
                }
                ("blob", Some(index)) if self.h264_streams.contains(&index) => {
                    let Some(payload) = args.get(1) else { continue };
                    let Some(replacement) = self.rewritten_payload(payload) else {
                        continue;
                    };

                    let out = out.get_or_insert_with(String::new);
                    out.push_str(&text[pending..instruction_start]);
                    out.push_str(&format!(
                        "4.blob,{}.{},{}.{};",
                        args[0].len(),
                        args[0],
                        replacement.len(),
                        replacement
                    ));
                    pending = instruction_end;
                }
                _ => {}
            }
        }

        let mut out = out?;
        out.push_str(&text[pending..]);
        Some(out)
    }

    /// Returns the base64 of a rewritten access unit, or `None` to leave the
    /// blob alone.
    fn rewritten_payload(&mut self, payload: &str) -> Option<String> {
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(payload) else {
            // The browser's decoder is no worse at this than ours.
            return None;
        };

        let Some(sps) = crate::h264_sps::find_sps_range(&bytes) else {
            // No SPS in this blob: a non-keyframe, or a continuation. Says
            // nothing about the stream, so the state is left as it is.
            return None;
        };

        if self.state == State::Undecided {
            let signal = crate::h264_sps::parse_sps(&bytes[sps.clone()])?;
            self.wire_colour = Some(signal.describe());
            self.state = if signal.needs_description() {
                State::Rewriting
            } else {
                State::PassThrough
            };
            self.bound_reordering = crate::h264_sps::reordering_unbounded(&bytes[sps.clone()]);
        }

        // Every edit, in any combination. Each returns None when it has
        // nothing to do -- an SPS that already describes its colour, bounds
        // its reordering or permits gaps -- so an SPS needing none of them
        // rebuilds nothing.
        let mut edited: Option<Vec<u8>> = None;

        if self.state == State::Rewriting {
            edited = crate::h264_sps::complete_colour_signalling(&bytes[sps.clone()]);
            if edited.is_some() {
                self.note(Edit::ColourDescription);
            }
        }

        if self.bound_reordering {
            let current = edited.as_deref().unwrap_or(&bytes[sps.clone()]);
            if let Some(bounded) = crate::h264_sps::declare_no_reordering(current) {
                edited = Some(bounded);
                self.note(Edit::NoReordering);
            }
        }

        if self.allow_gaps {
            let current = edited.as_deref().unwrap_or(&bytes[sps.clone()]);
            if let Some(with_gaps) = crate::h264_sps::allow_frame_num_gaps(current) {
                edited = Some(with_gaps);
                self.note(Edit::FrameNumGaps);
            }
        }

        let spliced = edited?;

        let mut rebuilt = Vec::with_capacity(bytes.len() + spliced.len());
        rebuilt.extend_from_slice(&bytes[..sps.start]);
        rebuilt.extend_from_slice(&spliced);
        rebuilt.extend_from_slice(&bytes[sps.end..]);

        Some(base64::engine::general_purpose::STANDARD.encode(&rebuilt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An access unit whose SPS declares full range and no colour description
    /// — the Windows shape.
    const BARE: &str = "AAAAAWdkAAus2UGCabIAAAMAAgAAAwBkHihTLAAAAAABaOvjywAAAAFliIQA";

    /// The same with a BT.709 description already present — the xrdp shape.
    const COMPLETE: &str = "AAAAAWdkAAus2UGCabgICAoAAAMAAgAAAwBkHihTLAAAAAABaOvjywAAAAFliIQA";

    fn blob(index: u32, payload: &str) -> String {
        format!(
            "4.blob,{}.{},{}.{};",
            index.to_string().len(),
            index,
            payload.len(),
            payload
        )
    }

    /// Pulls the blob payload back out of a run of instructions.
    fn payload_of(text: &str) -> String {
        let at = text.find("4.blob,").expect("a blob");
        let (_, next, _) = crate::binary_blob::element(text, at).unwrap();
        let (_, after, _) = crate::binary_blob::element(text, next).unwrap();
        let (payload, _, _) = crate::binary_blob::element(text, after).unwrap();
        payload.to_string()
    }

    fn decoded_signal(payload: &str) -> crate::h264_sps::ColourSignal {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .expect("valid base64");
        crate::h264_sps::find_sps(&bytes).expect("an SPS")
    }

    /// The two edits are independent, and the caller reports what was
    /// actually done. Inferring it from "something changed" told an xrdp
    /// session -- whose SPS describes its colour completely and needs only the
    /// gaps flag -- that a BT.709 description was being spliced into it, which
    /// points whoever reads the journal at a colour fault that is not there.
    #[test]
    fn it_says_which_edit_it_made() {
        let mut r = SpsRewriter::new();
        r.set_allow_frame_num_gaps(true);
        r.rewrite("4.h264,1.7,1.0,1.0;");
        assert!(
            r.rewrite(&blob(7, COMPLETE)).is_some(),
            "the gaps bit is set"
        );
        assert_eq!(
            r.take_edits(),
            vec![Edit::FrameNumGaps],
            "a complete description is not spliced into"
        );

        let mut r = SpsRewriter::new();
        r.rewrite("4.h264,1.7,1.0,1.0;");
        assert!(
            r.rewrite(&blob(7, BARE)).is_some(),
            "the description is added"
        );
        assert_eq!(r.take_edits(), vec![Edit::ColourDescription]);

        let mut r = SpsRewriter::new();
        r.set_allow_frame_num_gaps(true);
        r.rewrite("4.h264,1.7,1.0,1.0;");
        r.rewrite(&blob(7, BARE));
        let both = r.take_edits();
        assert!(
            both.contains(&Edit::ColourDescription) && both.contains(&Edit::FrameNumGaps),
            "a Windows host needs both: {:?}",
            both
        );

        // Said once, however many keyframes follow.
        r.rewrite(&blob(7, BARE));
        assert!(
            r.take_edits().is_empty(),
            "each edit is reported once a session"
        );
    }

    /// The head of an NVENC keyframe (SPS, PPS, the start of an IDR slice):
    /// colour complete, POC type 2, no `bitstream_restriction`.
    const NVENC: &str = "AAAAAWdNQDKVkALwDR5awFuAgICgAAB9AAAdTBCAAAAAAWjrjyAAAAABZbgEJ/5vXw==";

    /// A stream needing no colour work is still examined for the reorder
    /// bound, and every keyframe's SPS gets it -- a decoder rebuilt at a later
    /// keyframe reads that SPS, not the first.
    #[test]
    fn an_nvenc_stream_is_bounded_on_every_keyframe() {
        let mut r = SpsRewriter::new();
        r.rewrite("4.h264,1.7,1.0,1.0;");

        let first = r.rewrite(&blob(7, NVENC)).expect("rewritten");
        assert_eq!(r.take_edits(), vec![Edit::NoReordering]);

        let bytes = base64::engine::general_purpose::STANDARD
            .decode(payload_of(&first))
            .unwrap();
        let sps = crate::h264_sps::find_sps_range(&bytes).unwrap();
        assert!(!crate::h264_sps::reordering_unbounded(&bytes[sps]));
        assert_eq!(decoded_signal(&payload_of(&first)), decoded_signal(NVENC));
        assert!(
            bytes.ends_with(&[0, 0, 0, 1, 0x65, 0xb8, 0x04, 0x27, 0xfe, 0x6f, 0x5f]),
            "the slice after the SPS is untouched"
        );

        assert!(
            r.rewrite(&blob(7, NVENC)).is_some(),
            "and the next keyframe"
        );
        assert!(r.take_edits().is_empty());
    }

    /// A stream that already bounds its reordering, or cannot, is left alone.
    #[test]
    fn a_stream_needing_nothing_is_still_passed_through() {
        let mut r = SpsRewriter::new();
        r.rewrite("4.h264,1.7,1.0,1.0;");
        assert_eq!(r.rewrite(&blob(7, COMPLETE)), None, "x264, POC type 0");
        assert_eq!(r.state, State::PassThrough);
        assert!(!r.bound_reordering);
    }

    #[test]
    fn splices_a_description_into_a_bare_sps() {
        let mut r = SpsRewriter::new();
        assert_eq!(
            r.rewrite("4.h264,1.7,1.0,1.0;"),
            None,
            "nothing to rewrite yet"
        );

        let out = r.rewrite(&blob(7, BARE)).expect("rewritten");
        let signal = decoded_signal(&payload_of(&out));

        assert!(signal.full_range, "the declared range survives");
        assert_eq!(signal.primaries, Some(1));
        assert_eq!(signal.transfer, Some(1));
        assert_eq!(signal.matrix, Some(1));
        assert!(signal.is_actionable(), "which is the point");
    }

    /// The other NALs of the access unit must come through untouched: the
    /// slice data is the picture, and losing a byte of it loses the frame.
    #[test]
    fn the_rest_of_the_access_unit_is_preserved() {
        let mut r = SpsRewriter::new();
        r.rewrite("4.h264,1.7,1.0,1.0;");
        let out = r.rewrite(&blob(7, BARE)).expect("rewritten");

        let before = base64::engine::general_purpose::STANDARD
            .decode(BARE)
            .unwrap();
        let after = base64::engine::general_purpose::STANDARD
            .decode(payload_of(&out))
            .unwrap();

        // Everything from the PPS start code onward is byte-identical.
        let pps = before
            .windows(5)
            .position(|w| w == [0, 0, 0, 1, 0x68])
            .unwrap();
        let pps_after = after
            .windows(5)
            .position(|w| w == [0, 0, 0, 1, 0x68])
            .unwrap();
        assert_eq!(before[pps..], after[pps_after..], "PPS and slice survive");
    }

    /// An xrdp stream must not be touched, and must stop being examined.
    #[test]
    fn a_described_stream_is_passed_through_and_then_ignored() {
        let mut r = SpsRewriter::new();
        r.rewrite("4.h264,1.7,1.0,1.0;");

        assert_eq!(r.rewrite(&blob(7, COMPLETE)), None, "nothing to do");
        assert_eq!(r.state, State::PassThrough);
        // And the decision sticks: a later blob is not decoded at all.
        assert_eq!(
            r.rewrite(&blob(7, BARE)),
            None,
            "decided, and not revisited"
        );
    }

    /// Keyframes recur, so the rewrite has to keep applying.
    #[test]
    fn every_later_keyframe_is_rewritten_too() {
        let mut r = SpsRewriter::new();
        r.rewrite("4.h264,1.7,1.0,1.0;");
        r.rewrite(&blob(7, BARE)).expect("first");

        let out = r.rewrite(&blob(7, BARE)).expect("and the next");
        assert!(decoded_signal(&payload_of(&out)).is_actionable());
    }

    #[test]
    fn blobs_of_other_streams_are_left_alone() {
        let mut r = SpsRewriter::new();
        // An img stream carrying bytes that would parse as an access unit.
        let text = format!("3.img,1.4,1.1,1.0,9.image/png,1.0,1.0;{}", blob(4, BARE));
        assert_eq!(r.rewrite(&text), None);
    }

    /// Indices are reused once a stream ends.
    #[test]
    fn a_recycled_index_is_no_longer_video() {
        let mut r = SpsRewriter::new();
        r.rewrite("4.h264,1.7,1.0,1.0;3.end,1.7;");
        assert_eq!(r.rewrite(&blob(7, BARE)), None);
    }

    /// Neighbouring instructions must survive the splice intact, since the
    /// rewrite rebuilds the run around the blob it replaces.
    #[test]
    fn surrounding_instructions_are_preserved() {
        let mut r = SpsRewriter::new();
        r.rewrite("4.h264,1.7,1.0,1.0;");

        let text = format!("4.sync,3.123;{}5.mouse,1.4,1.5;", blob(7, BARE));
        let out = r.rewrite(&text).expect("rewritten");

        assert!(out.starts_with("4.sync,3.123;"), "{out}");
        assert!(out.ends_with("5.mouse,1.4,1.5;"), "{out}");
        assert!(decoded_signal(&payload_of(&out)).is_actionable());
    }

    /// The splice must leave a stream a decoder still accepts. A bad bit
    /// offset or a missed emulation-prevention byte does not fail loudly --
    /// the picture simply stops, with both ends looking healthy.
    ///
    /// Checked against ffmpeg's own `h264_metadata` bitstream filter doing the
    /// same edit, which is an implementation that shares no code and no
    /// author with this one: if the two write the same SPS byte for byte, the
    /// splice is right. Then both are decoded, to confirm the result is a
    /// stream and not merely a plausible one. Skipped where ffmpeg is absent.
    ///
    /// Note that the edit legitimately *changes the decode*: with
    /// `matrix_coefficients` absent a decoder falls back to BT.601, and
    /// writing 1 declares BT.709. That is the correct value here -- MS-RDPEGFX
    /// defines the transform as BT.709, and Chrome already reports `bt709` for
    /// these streams, so it is a no-op for the client this serves -- but it is
    /// why the pixels are not asserted equal.
    #[test]
    fn the_splice_matches_ffmpegs_own_rewrite() {
        use std::process::Command;

        let ffmpeg = |args: &[&str]| -> bool {
            Command::new("ffmpeg")
                .args(args)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        };

        if !ffmpeg(&["-version"]) {
            eprintln!("SKIP: needs ffmpeg");
            return;
        }

        let dir = std::env::temp_dir().join(format!("rustguac-splice-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = |name: &str| dir.join(name).to_string_lossy().into_owned();

        // Full-range samples declaring the range and nothing else: the shape
        // this exists to repair.
        assert!(
            ffmpeg(&[
                "-v",
                "error",
                "-y",
                "-f",
                "lavfi",
                "-i",
                "testsrc=size=1280x720:rate=10:duration=1",
                "-c:v",
                "libx264",
                "-profile:v",
                "high",
                "-pix_fmt",
                "yuv420p",
                "-color_range",
                "pc",
                "-x264-params",
                "fullrange=on",
                "-bsf:v",
                "h264_metadata=video_full_range_flag=1",
                &path("original.h264"),
            ]),
            "encode failed"
        );

        // The same edit, by ffmpeg.
        assert!(
            ffmpeg(&[
                "-v",
                "error",
                "-y",
                "-i",
                &path("original.h264"),
                "-c:v",
                "copy",
                "-bsf:v",
                "h264_metadata=colour_primaries=1:transfer_characteristics=1:\
matrix_coefficients=1",
                &path("reference.h264"),
            ]),
            "reference rewrite failed"
        );

        let original = std::fs::read(path("original.h264")).expect("read");
        let reference = std::fs::read(path("reference.h264")).expect("read");

        let ours = {
            let range = crate::h264_sps::find_sps_range(&original).expect("an SPS");
            let before = crate::h264_sps::parse_sps(&original[range.clone()]).expect("parses");
            assert!(
                before.full_range && before.needs_description(),
                "the fixture is the shape under test: {before:?}"
            );
            crate::h264_sps::complete_colour_signalling(&original[range]).expect("rewritten")
        };

        let theirs = {
            let range = crate::h264_sps::find_sps_range(&reference).expect("an SPS");
            reference[range].to_vec()
        };

        assert_eq!(
            ours, theirs,
            "our SPS differs from ffmpeg's:\n  ours   {ours:02x?}\n  theirs {theirs:02x?}"
        );

        let spliced = crate::h264_sps::parse_sps(&ours).expect("parses");
        assert!(spliced.full_range, "the declared range survives");
        assert!(
            spliced.is_actionable(),
            "which is the point of the exercise"
        );

        // And it is still a decodable stream, not merely a plausible one.
        for name in ["original.h264", "reference.h264"] {
            assert!(
                ffmpeg(&[
                    "-v",
                    "error",
                    "-y",
                    "-i",
                    &path(name),
                    "-frames:v",
                    "3",
                    "-pix_fmt",
                    "rgb24",
                    "-f",
                    "rawvideo",
                    &path("out.rgb")
                ]),
                "decode failed for {name}"
            );
            let pixels = std::fs::read(path("out.rgb")).expect("pixels");
            assert_eq!(pixels.len(), 1280 * 720 * 3 * 3, "three 720p frames");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The stock-xrdp shape: x264 with no VUI parameters set, so the whole
    /// video_signal_type block is absent. Checked against ffmpeg's
    /// h264_metadata writing the same three fields plus the range, which is an
    /// implementation sharing no code with this one. Skipped without ffmpeg.
    #[test]
    fn writing_the_whole_signal_type_matches_ffmpeg() {
        use std::process::Command;

        let ffmpeg = |args: &[&str]| -> bool {
            Command::new("ffmpeg")
                .args(args)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        };

        if !ffmpeg(&["-version"]) {
            eprintln!("SKIP: needs ffmpeg");
            return;
        }

        let dir = std::env::temp_dir().join(format!("rustguac-signal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = |name: &str| dir.join(name).to_string_lossy().into_owned();

        // No colour options at all -- x264's defaults, which is what stock
        // xrdp 0.10.6 hands it.
        assert!(
            ffmpeg(&[
                "-v",
                "error",
                "-y",
                "-f",
                "lavfi",
                "-i",
                "testsrc=size=640x480:rate=10:duration=1",
                "-c:v",
                "libx264",
                "-profile:v",
                "high",
                "-pix_fmt",
                "yuv420p",
                &path("plain.h264"),
            ]),
            "encode failed"
        );

        assert!(
            ffmpeg(&[
                "-v",
                "error",
                "-y",
                "-i",
                &path("plain.h264"),
                "-c:v",
                "copy",
                "-bsf:v",
                "h264_metadata=video_full_range_flag=1:colour_primaries=1:\
transfer_characteristics=1:matrix_coefficients=1",
                &path("reference.h264"),
            ]),
            "reference rewrite failed"
        );

        let plain = std::fs::read(path("plain.h264")).expect("read");
        let reference = std::fs::read(path("reference.h264")).expect("read");

        let range = crate::h264_sps::find_sps_range(&plain).expect("an SPS");
        let before = crate::h264_sps::parse_sps(&plain[range.clone()]).expect("parses");
        assert!(
            before.vui_present && !before.video_signal_type_present,
            "the fixture is the shape under test: {before:?}"
        );

        let ours = crate::h264_sps::complete_colour_signalling(&plain[range]).expect("rewritten");
        let theirs = {
            let range = crate::h264_sps::find_sps_range(&reference).expect("an SPS");
            reference[range].to_vec()
        };

        assert_eq!(
            ours, theirs,
            "our SPS differs from ffmpeg's:\n  ours   {ours:02x?}\n  theirs {theirs:02x?}"
        );

        let spliced = crate::h264_sps::parse_sps(&ours).expect("parses");
        assert!(spliced.full_range);
        assert!(spliced.is_actionable());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn undecodable_payloads_are_passed_through_not_dropped() {
        let mut r = SpsRewriter::new();
        r.rewrite("4.h264,1.7,1.0,1.0;");
        let text = blob(7, "!!!not base64!!!");
        assert_eq!(r.rewrite(&text), None, "left for the browser to reject");
    }

    /// A blob carrying no SPS says nothing about the stream, so it must not
    /// settle the decision -- the first blob of a session is often a
    /// continuation, and deciding on it would leave every keyframe unrewritten.
    #[test]
    fn a_blob_without_an_sps_does_not_decide_the_stream() {
        let mut r = SpsRewriter::new();
        r.rewrite("4.h264,1.7,1.0,1.0;");

        let slice =
            base64::engine::general_purpose::STANDARD.encode([0, 0, 0, 1, 0x41, 0x9a, 0x12, 0x34]);
        assert_eq!(r.rewrite(&blob(7, &slice)), None);
        assert_eq!(r.state, State::Undecided, "still undecided");

        let out = r
            .rewrite(&blob(7, BARE))
            .expect("and the keyframe still lands");
        assert!(decoded_signal(&payload_of(&out)).is_actionable());
    }

    /// The wire colour is reported once, from the first SPS, and describes
    /// what the host sent -- not the description spliced into it.
    #[test]
    fn it_reports_the_wire_colour_once() {
        let mut r = SpsRewriter::new();
        r.rewrite("4.h264,1.7,1.0,1.0;");
        assert_eq!(r.take_wire_colour(), None, "no SPS seen yet");

        r.rewrite(&blob(7, BARE));
        let line = r.take_wire_colour().expect("reported at the first SPS");
        assert!(
            line.contains("NO DESCRIPTION"),
            "describes the host's SPS: {line}"
        );

        r.rewrite(&blob(7, BARE));
        assert_eq!(r.take_wire_colour(), None, "once a session");
    }
}
