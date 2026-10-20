//! Converts base64 blob payloads into binary WebSocket frames.
//!
//! Base64 sends four bytes for every three, so a quarter of everything on the
//! wire is encoding overhead — 27MB of a 167-second video session, measured.
//! This rewrites the blobs of streams whose consumer wants bytes anyway into
//! binary frames, and leaves every other instruction exactly as it was.
//!
//! Only `h264` and `audio` streams are converted. Both reach
//! `Guacamole.ArrayBufferReader` in the browser, which decodes base64 to an
//! ArrayBuffer only to hand over the bytes. `img` is deliberately excluded:
//! its blobs reach `DataURIReader`, which concatenates base64 straight into a
//! `data:` URI and genuinely wants the encoded form.
//!
//! The conversion happens here rather than in a guacd patch because rustguac
//! tees the raw guacd stream to disk as the session recording. Converting
//! upstream of that tee would turn every recording binary and take the
//! recording format, `SessionRecording.js` and the playback page with it. The
//! guacd → rustguac hop is loopback, so nothing is lost by leaving it as text.
//!
//! See `docs/binary-blobs.md`.

use base64::Engine;
use std::collections::HashSet;

/// Wire format version, byte 0 of every binary frame. Present so a client can
/// reject a frame shape it does not know rather than misread one.
pub const FRAME_VERSION: u8 = 1;

/// Frame type: a blob payload for a stream. Byte 1.
pub const FRAME_TYPE_BLOB: u8 = 0;

/// Header bytes preceding the payload. Eight rather than six so the payload
/// starts on an 8-byte boundary.
pub const HEADER_LEN: usize = 8;

/// One frame to write to the browser's WebSocket.
#[derive(Debug, PartialEq, Eq)]
pub enum OutFrame {
    /// Instructions to send unchanged, as a text frame.
    Text(String),
    /// A blob payload, as a binary frame with an 8-byte header.
    Binary(Vec<u8>),
}

/// Parses one wire element starting at byte offset `at`.
///
/// Returns the element's value, the offset just past its terminator, and the
/// terminator itself (`,` or `;`). Returns `None` on anything malformed or
/// truncated, which the caller treats as "stop converting and pass the rest
/// through untouched" — never as a reason to drop data.
///
/// The length prefix counts UTF-8 *characters*, per `guac_utf8_strlen` in
/// libguac, so a clipboard instruction carrying an emoji does not desynchronise
/// the scan and take every instruction after it along.
pub(crate) fn element(text: &str, at: usize) -> Option<(&str, usize, u8)> {
    let bytes = text.as_bytes();
    let digits_start = at;
    let mut pos = at;

    while pos < bytes.len() && bytes[pos].is_ascii_digit() {
        pos += 1;
    }
    if pos == digits_start || pos >= bytes.len() || bytes[pos] != b'.' {
        return None;
    }
    let len: usize = text[digits_start..pos].parse().ok()?;
    pos += 1;

    let value_start = pos;
    let mut chars = 0;
    while chars < len {
        if pos >= bytes.len() {
            return None;
        }
        let b = bytes[pos];
        let width = if b < 0x80 {
            1
        } else if b < 0xC0 {
            return None; // lone continuation byte
        } else if b < 0xE0 {
            2
        } else if b < 0xF0 {
            3
        } else {
            4
        };
        if pos + width > bytes.len() {
            return None;
        }
        pos += width;
        chars += 1;
    }

    if pos >= bytes.len() {
        return None;
    }
    let terminator = bytes[pos];
    if terminator != b',' && terminator != b';' {
        return None;
    }
    Some((&text[value_start..pos], pos + 1, terminator))
}

/// Builds a binary blob frame for `index` carrying `payload`.
fn frame(index: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.push(FRAME_VERSION);
    out.push(FRAME_TYPE_BLOB);
    out.extend_from_slice(&[0, 0]); // reserved
    out.extend_from_slice(&index.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// Rewrites blob instructions of binary-consumer streams into binary frames.
///
/// Stream membership has to persist across reads, since the `h264` instruction
/// that opens a stream and the `blob` instructions that fill it routinely land
/// in different reads from guacd.
#[derive(Default)]
pub struct BlobSplitter {
    /// Stream indices opened by `h264` or `audio`.
    binary_streams: HashSet<u32>,
}

impl BlobSplitter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Splits a run of complete instructions into the frames to send.
    ///
    /// `text` must end on an instruction boundary, which is what
    /// `guacd_to_ws` already guarantees before sending anything.
    ///
    /// WebSocket delivers text and binary frames in one order, so a blob
    /// lifted out of the text still arrives between the same neighbours it
    /// had. Nothing here can reorder the stream.
    pub fn split(&mut self, text: &str) -> Vec<OutFrame> {
        let mut out = Vec::new();

        // Start of text not yet emitted. Everything between here and the next
        // converted blob is passed through verbatim.
        let mut pending = 0usize;
        let mut pos = 0usize;

        while pos < text.len() {
            let instruction_start = pos;

            let Some((opcode, mut next, mut terminator)) = element(text, pos) else {
                break;
            };

            // Only the first two arguments are ever needed: a stream index,
            // and for `blob` its payload.
            let mut args: Vec<&str> = Vec::new();
            while terminator == b',' && args.len() < 2 {
                match element(text, next) {
                    Some((value, after, term)) => {
                        args.push(value);
                        next = after;
                        terminator = term;
                    }
                    None => break,
                }
            }

            // Walk off the end of the instruction. An `h264` instruction
            // carries region rects beyond what is read above.
            while terminator == b',' {
                match element(text, next) {
                    Some((_, after, term)) => {
                        next = after;
                        terminator = term;
                    }
                    None => break,
                }
            }

            if terminator != b';' {
                break; // malformed or truncated: pass the remainder through
            }
            let instruction_end = next;
            pos = instruction_end;

            let index = args.first().and_then(|a| a.parse::<u32>().ok());

            match (opcode, index) {
                ("h264" | "audio", Some(index)) => {
                    self.binary_streams.insert(index);
                }
                ("end", Some(index)) => {
                    self.binary_streams.remove(&index);
                }
                ("blob", Some(index)) if self.binary_streams.contains(&index) => {
                    let Some(payload) = args.get(1) else { continue };
                    // A payload that will not decode is left as text rather
                    // than dropped: the browser's base64 decoder is no worse
                    // at it than ours, and losing a blob loses a picture.
                    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(payload)
                    else {
                        continue;
                    };

                    if pending < instruction_start {
                        out.push(OutFrame::Text(text[pending..instruction_start].to_string()));
                    }
                    out.push(OutFrame::Binary(frame(index, &decoded)));
                    pending = instruction_end;
                }
                _ => {}
            }
        }

        if pending < text.len() {
            out.push(OutFrame::Text(text[pending..].to_string()));
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Instruction;

    fn text(s: &str) -> OutFrame {
        OutFrame::Text(s.to_string())
    }

    /// Base64 of the three bytes 0x01 0x02 0x03.
    const B64: &str = "AQID";
    const BYTES: [u8; 3] = [1, 2, 3];

    #[test]
    fn converts_blobs_of_h264_streams() {
        let mut s = BlobSplitter::new();
        let input = format!("4.h264,1.7,1.0,1.0;4.blob,1.7,4.{};3.end,1.7;", B64);
        let out = s.split(&input);

        assert_eq!(out.len(), 3);
        assert_eq!(out[0], text("4.h264,1.7,1.0,1.0;"));
        assert_eq!(out[1], OutFrame::Binary(frame(7, &BYTES)));
        assert_eq!(out[2], text("3.end,1.7;"));
    }

    #[test]
    fn converts_blobs_of_audio_streams() {
        let mut s = BlobSplitter::new();
        let input = format!("5.audio,1.3,9.audio/L16;4.blob,1.3,4.{};", B64);
        let out = s.split(&input);
        assert_eq!(out[1], OutFrame::Binary(frame(3, &BYTES)));
    }

    #[test]
    fn leaves_img_blobs_as_base64() {
        // DataURIReader concatenates base64 straight into a data: URI, so
        // converting an img blob would only have to be undone.
        let mut s = BlobSplitter::new();
        let input = format!(
            "3.img,1.4,1.1,1.0,9.image/png,1.0,1.0;4.blob,1.4,4.{};",
            B64
        );
        let out = s.split(&input);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], text(&input));
    }

    #[test]
    fn stream_membership_survives_across_reads() {
        // The h264 instruction and its blobs routinely arrive in different
        // reads from guacd, so the splitter has to remember the stream.
        let mut s = BlobSplitter::new();
        assert_eq!(
            s.split("4.h264,1.9,1.0,1.0;"),
            vec![text("4.h264,1.9,1.0,1.0;")]
        );
        let out = s.split(&format!("4.blob,1.9,4.{};", B64));
        assert_eq!(out, vec![OutFrame::Binary(frame(9, &BYTES))]);
    }

    #[test]
    fn end_releases_the_stream_index() {
        // Indices are reused. A blob on a recycled index must not be
        // converted just because the previous owner was an h264 stream.
        let mut s = BlobSplitter::new();
        s.split("4.h264,1.2,1.0,1.0;3.end,1.2;");
        let input = format!(
            "3.img,1.2,1.1,1.0,9.image/png,1.0,1.0;4.blob,1.2,4.{};",
            B64
        );
        let out = s.split(&input);
        assert_eq!(out, vec![text(&input)]);
    }

    #[test]
    fn passes_untouched_streams_through_whole() {
        let mut s = BlobSplitter::new();
        let input = "4.sync,3.100;5.mouse,3.640,3.480;";
        assert_eq!(s.split(input), vec![text(input)]);
    }

    #[test]
    fn multibyte_elements_do_not_desynchronise_the_scan() {
        // The length prefix counts codepoints, not bytes, per guac_utf8_strlen
        // in libguac -- so an emoji four bytes wide has a length of 1 and an
        // e-acute two bytes wide has a length of 1. Counting bytes here would
        // run off the end of the element and take every instruction after the
        // clipboard with it.
        let mut s = BlobSplitter::new();
        let input = format!(
            "4.h264,1.1,1.0,1.0;9.clipboard,1.0,1.\u{1F600};9.clipboard,1.0,1.\u{e9};\
             4.blob,1.1,4.{};",
            B64
        );
        let out = s.split(&input);
        assert_eq!(out.len(), 2);
        assert_eq!(
            out[0],
            text("4.h264,1.1,1.0,1.0;9.clipboard,1.0,1.\u{1F600};9.clipboard,1.0,1.\u{e9};")
        );
        assert_eq!(out[1], OutFrame::Binary(frame(1, &BYTES)));
    }

    #[test]
    fn embedded_semicolon_in_a_payload_is_not_a_boundary() {
        let mut s = BlobSplitter::new();
        let input = "4.h264,1.1,1.0,1.0;9.clipboard,1.0,3.a;b;4.sync,3.100;";
        assert_eq!(s.split(input), vec![text(input)]);
    }

    #[test]
    fn undecodable_payload_is_left_as_text_rather_than_dropped() {
        let mut s = BlobSplitter::new();
        let input = "4.h264,1.5,1.0,1.0;4.blob,1.5,3.!!!;";
        assert_eq!(s.split(input), vec![text(input)]);
    }

    #[test]
    fn malformed_tail_is_passed_through_not_swallowed() {
        let mut s = BlobSplitter::new();
        let input = format!("4.h264,1.1,1.0,1.0;4.blob,1.1,4.{};garbage", B64);
        let out = s.split(&input);
        assert_eq!(out[1], OutFrame::Binary(frame(1, &BYTES)));
        assert_eq!(out[2], text("garbage"));
    }

    #[test]
    fn several_blobs_in_one_read_each_become_a_frame() {
        let mut s = BlobSplitter::new();
        let input = format!(
            "4.h264,1.1,1.0,1.0;4.blob,1.1,4.{b};4.blob,1.1,4.{b};3.end,1.1;",
            b = B64
        );
        let out = s.split(&input);
        assert_eq!(out.len(), 4);
        assert_eq!(out[1], OutFrame::Binary(frame(1, &BYTES)));
        assert_eq!(out[2], OutFrame::Binary(frame(1, &BYTES)));
        assert_eq!(out[3], text("3.end,1.1;"));
    }

    /// Round-trips a real recording through the splitter and reconstructs the
    /// original stream from the frames, asserting it comes back byte for byte.
    ///
    /// The unit tests above check hand-written instructions; this checks the
    /// thing that actually goes over the wire, including whatever guacd emits
    /// that nobody thought to write a case for. Ignored by default because it
    /// needs a recording:
    ///
    ///     RUSTGUAC_TEST_RECORDING=/path/to.guac \
    ///         cargo test --  --ignored round_trips_a_real_recording --nocapture
    #[test]
    #[ignore = "needs RUSTGUAC_TEST_RECORDING"]
    fn round_trips_a_real_recording() {
        let path = std::env::var("RUSTGUAC_TEST_RECORDING")
            .expect("set RUSTGUAC_TEST_RECORDING to a .guac file");
        let original = std::fs::read_to_string(&path).expect("readable recording");

        let mut splitter = BlobSplitter::new();
        let mut rebuilt = String::with_capacity(original.len());
        let mut text_bytes = 0usize;
        let mut binary_bytes = 0usize;
        let mut frames = 0usize;

        // Fed in 64KiB reads split at instruction boundaries, exactly as
        // guacd_to_ws does, so the cross-read stream tracking is exercised
        // rather than assumed.
        let bytes = original.as_bytes();
        let mut at = 0usize;
        while at < bytes.len() {
            let want = (at + 65536).min(bytes.len());
            let end = match crate::protocol::last_instruction_boundary(&bytes[at..want]) {
                Some(e) => at + e,
                None => match crate::protocol::last_instruction_boundary(&bytes[at..]) {
                    Some(e) => at + e,
                    None => break,
                },
            };
            let chunk = &original[at..end];
            at = end;

            for out in splitter.split(chunk) {
                match out {
                    OutFrame::Text(t) => {
                        text_bytes += t.len();
                        rebuilt.push_str(&t);
                    }
                    OutFrame::Binary(b) => {
                        frames += 1;
                        binary_bytes += b.len();
                        let index = u32::from_le_bytes(b[4..8].try_into().unwrap());
                        let payload =
                            base64::engine::general_purpose::STANDARD.encode(&b[HEADER_LEN..]);
                        rebuilt.push_str(
                            &Instruction::new("blob", vec![index.to_string(), payload]).encode(),
                        );
                    }
                }
            }
        }

        assert_eq!(
            rebuilt.len(),
            original[..at].len(),
            "reconstructed length differs"
        );
        assert!(
            rebuilt == original[..at],
            "reconstructed stream differs from original"
        );

        let before = original[..at].len();
        let after = text_bytes + binary_bytes;
        println!(
            "  {} frames converted; {:.1} MB -> {:.1} MB on the wire ({:.1}% saved)",
            frames,
            before as f64 / 1e6,
            after as f64 / 1e6,
            100.0 * (before - after) as f64 / before as f64
        );
    }

    #[test]
    fn saving_matches_what_base64_would_have_cost() {
        // The reported saving has to be the real one, since it is what tells
        // an operator the feature is working. base64 emits four characters per
        // three bytes, padded.
        for len in [0usize, 1, 2, 3, 4, 100, 4096] {
            let encoded = base64::engine::general_purpose::STANDARD
                .encode(vec![0u8; len])
                .len();
            assert_eq!(len.div_ceil(3) * 4, encoded, "len {}", len);
        }
    }

    #[test]
    fn frame_header_is_the_documented_shape() {
        let f = frame(0x01020304, &[0xAA, 0xBB]);
        assert_eq!(f[0], FRAME_VERSION);
        assert_eq!(f[1], FRAME_TYPE_BLOB);
        assert_eq!(&f[2..4], &[0, 0]);
        assert_eq!(&f[4..8], &0x01020304u32.to_le_bytes());
        assert_eq!(&f[HEADER_LEN..], &[0xAA, 0xBB]);
    }
}
