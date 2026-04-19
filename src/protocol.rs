//! Guacamole protocol instruction encoding and decoding.
//!
//! Wire format: `LENGTH.ELEMENT,LENGTH.ELEMENT,...;`
//! Example: `4.size,3.800,3.600;`

use std::fmt;

/// A single Guacamole protocol instruction.
#[derive(Debug, Clone, PartialEq)]
pub struct Instruction {
    pub opcode: String,
    pub args: Vec<String>,
}

impl Instruction {
    pub fn new(opcode: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            opcode: opcode.into(),
            args,
        }
    }

    /// Encode this instruction into Guacamole wire format.
    pub fn encode(&self) -> String {
        let mut out = encode_element(&self.opcode);
        for arg in &self.args {
            out.push(',');
            out.push_str(&encode_element(arg));
        }
        out.push(';');
        out
    }

    /// Parse a single instruction from a complete instruction string (including the trailing `;`).
    pub fn parse(data: &str) -> Result<Self, ParseError> {
        let data = data.trim_end_matches(';');
        if data.is_empty() {
            return Err(ParseError::Empty);
        }

        let mut elements = Vec::new();
        let mut remaining = data;

        loop {
            // Parse length
            let dot_pos = remaining.find('.').ok_or(ParseError::MalformedElement)?;
            let len: usize = remaining[..dot_pos]
                .parse()
                .map_err(|_| ParseError::InvalidLength)?;
            remaining = &remaining[dot_pos + 1..];

            // Extract element value (length is in bytes per Guacamole spec)
            if remaining.len() < len {
                return Err(ParseError::Truncated);
            }
            if !remaining.is_char_boundary(len) {
                return Err(ParseError::Truncated);
            }
            elements.push(remaining[..len].to_string());
            remaining = &remaining[len..];

            // Check for separator or end
            if remaining.is_empty() {
                break;
            }
            if remaining.starts_with(',') {
                remaining = &remaining[1..];
            } else {
                return Err(ParseError::UnexpectedChar);
            }
        }

        if elements.is_empty() {
            return Err(ParseError::Empty);
        }

        let opcode = elements.remove(0);
        Ok(Instruction {
            opcode,
            args: elements,
        })
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.encode())
    }
}

fn encode_element(s: &str) -> String {
    // Length is the number of UTF-8 bytes (matching guacamole-common-js behavior
    // for the server-side protocol; the JS side counts UTF-16 code units but
    // guacd uses byte length).
    format!("{}.{}", s.len(), s)
}

#[derive(Debug)]
pub enum ParseError {
    Empty,
    MalformedElement,
    InvalidLength,
    Truncated,
    UnexpectedChar,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Empty => write!(f, "empty instruction"),
            ParseError::MalformedElement => write!(f, "malformed element (missing '.')"),
            ParseError::InvalidLength => write!(f, "invalid length prefix"),
            ParseError::Truncated => write!(f, "instruction truncated"),
            ParseError::UnexpectedChar => write!(f, "unexpected character in instruction"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Streaming parser that accumulates data and yields complete instructions.
#[derive(Default)]
pub struct InstructionParser {
    buffer: String,
}

impl InstructionParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed data into the parser and return any complete instructions.
    pub fn receive(&mut self, data: &str) -> Vec<Result<Instruction, ParseError>> {
        self.buffer.push_str(data);

        if self.buffer.len() > 1_048_576 {
            self.buffer.clear();
            return vec![];
        }

        let mut results = Vec::new();

        while let Some(semi_pos) = self.buffer.find(';') {
            let instruction_str = self.buffer[..semi_pos].to_string();
            self.buffer = self.buffer[semi_pos + 1..].to_string();
            results.push(Instruction::parse(&instruction_str));
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_simple() {
        let inst = Instruction::new("size", vec!["800".into(), "600".into()]);
        assert_eq!(inst.encode(), "4.size,3.800,3.600;");
    }

    #[test]
    fn test_encode_no_args() {
        let inst = Instruction::new("nop", vec![]);
        assert_eq!(inst.encode(), "3.nop;");
    }

    #[test]
    fn test_encode_select() {
        let inst = Instruction::new("select", vec!["ssh".into()]);
        assert_eq!(inst.encode(), "6.select,3.ssh;");
    }

    #[test]
    fn test_parse_simple() {
        let inst = Instruction::parse("4.size,3.800,3.600").unwrap();
        assert_eq!(inst.opcode, "size");
        assert_eq!(inst.args, vec!["800", "600"]);
    }

    #[test]
    fn test_parse_with_semicolon() {
        let inst = Instruction::parse("4.size,3.800,3.600;").unwrap();
        assert_eq!(inst.opcode, "size");
        assert_eq!(inst.args, vec!["800", "600"]);
    }

    #[test]
    fn test_parse_no_args() {
        let inst = Instruction::parse("3.nop").unwrap();
        assert_eq!(inst.opcode, "nop");
        assert!(inst.args.is_empty());
    }

    #[test]
    fn test_roundtrip() {
        let original = Instruction::new(
            "connect",
            vec![
                "10.0.0.5".into(),
                "22".into(),
                "admin".into(),
                "password123".into(),
            ],
        );
        let encoded = original.encode();
        let parsed = Instruction::parse(&encoded).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_streaming_parser() {
        let mut parser = InstructionParser::new();

        // Feed partial data
        let results = parser.receive("4.size,3.80");
        assert!(results.is_empty());

        // Complete the instruction and start another
        let results = parser.receive("0,3.600;3.nop;");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].as_ref().unwrap().opcode, "size");
        assert_eq!(results[1].as_ref().unwrap().opcode, "nop");
    }

    // ── Adversarial parser cases ───────────────────────────────────────────
    // guacd is a trust boundary: even under compromise, the rustguac parser
    // must refuse to panic, must reject malformed frames cleanly, and must
    // bound memory. Every negative case here should produce a ParseError or
    // be dropped by the 1 MiB buffer cap — never a panic or OOM.

    #[test]
    fn parse_rejects_length_longer_than_data() {
        // Claims 10 bytes but only 3 are present.
        let err = Instruction::parse("10.abc").unwrap_err();
        assert!(matches!(err, ParseError::Truncated));
    }

    #[test]
    fn parse_rejects_non_numeric_length() {
        let err = Instruction::parse("x.size").unwrap_err();
        assert!(matches!(err, ParseError::InvalidLength));
    }

    #[test]
    fn parse_rejects_negative_length() {
        // `-1` is not valid usize — must be rejected, not cast.
        let err = Instruction::parse("-1.x").unwrap_err();
        assert!(matches!(err, ParseError::InvalidLength));
    }

    #[test]
    fn parse_rejects_overflow_length() {
        // 2^65 overflows usize on every platform and must be a clean error.
        let err = Instruction::parse("36893488147419103232.x").unwrap_err();
        assert!(matches!(err, ParseError::InvalidLength));
    }

    #[test]
    fn parse_rejects_missing_dot() {
        let err = Instruction::parse("4size").unwrap_err();
        assert!(matches!(err, ParseError::MalformedElement));
    }

    #[test]
    fn parse_rejects_unexpected_separator() {
        // After the element body we must see `,` or end. A bare letter
        // should produce UnexpectedChar, not silently continue.
        let err = Instruction::parse("4.sizeX3.800").unwrap_err();
        assert!(matches!(err, ParseError::UnexpectedChar));
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(matches!(
            Instruction::parse("").unwrap_err(),
            ParseError::Empty
        ));
        assert!(matches!(
            Instruction::parse(";").unwrap_err(),
            ParseError::Empty
        ));
    }

    #[test]
    fn parse_rejects_split_multibyte_char() {
        // '€' is three bytes (E2 82 AC). Claiming length 2 would split the
        // char on a non-boundary — parser must reject rather than panic.
        let bad = "2.€";
        let err = Instruction::parse(bad).unwrap_err();
        assert!(matches!(err, ParseError::Truncated));
    }

    #[test]
    fn parse_accepts_correct_multibyte_length() {
        // Correct byte-length for '€' is 3.
        let inst = Instruction::parse("3.€").unwrap();
        assert_eq!(inst.opcode, "€");
    }

    #[test]
    fn parse_accepts_zero_length_element() {
        let inst = Instruction::parse("3.nop,0.,3.foo").unwrap();
        assert_eq!(inst.opcode, "nop");
        assert_eq!(inst.args, vec!["", "foo"]);
    }

    #[test]
    fn parse_accepts_embedded_semicolon_within_length() {
        // Length includes the `;` so it's part of the element, not a
        // terminator. The caller's framing must respect length; this test
        // proves parse() honours the length over the semicolon.
        let inst = Instruction::parse("5.a;b;c").unwrap();
        assert_eq!(inst.opcode, "a;b;c");
    }

    #[test]
    fn streaming_parser_caps_buffer_at_1_mib() {
        // Feed > 1 MiB in a single receive with no terminator. The buffer
        // must clear in-place rather than grow unbounded, and the call
        // must return cleanly without panicking. After the clear, a fresh
        // well-formed frame parses normally.
        let mut parser = InstructionParser::new();
        let huge = "x".repeat(1_100_000);
        let out = parser.receive(&huge);
        // Over-cap input is dropped entirely (no partial instruction yield).
        assert!(out.is_empty());
        // Fresh input parses correctly — buffer is empty, no residue.
        let out2 = parser.receive("3.nop;");
        assert_eq!(out2.len(), 1);
        assert_eq!(out2[0].as_ref().unwrap().opcode, "nop");
    }

    #[test]
    fn streaming_parser_split_at_every_boundary() {
        // Feed a well-formed frame byte-by-byte; the parser must assemble
        // correctly regardless of where chunks break.
        let full = "4.size,3.800,3.600;3.nop;";
        let mut parser = InstructionParser::new();
        let mut all = Vec::new();
        for ch in full.chars() {
            let mut buf = [0u8; 4];
            let s = ch.encode_utf8(&mut buf);
            all.extend(parser.receive(s));
        }
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].as_ref().unwrap().opcode, "size");
        assert_eq!(all[1].as_ref().unwrap().opcode, "nop");
    }

    #[test]
    fn streaming_parser_emits_error_for_malformed_frame() {
        // A malformed-but-terminated frame yields a Result::Err, not a panic.
        let mut parser = InstructionParser::new();
        let out = parser.receive("not-a-valid-instruction;3.nop;");
        assert_eq!(out.len(), 2);
        assert!(out[0].is_err());
        assert_eq!(out[1].as_ref().unwrap().opcode, "nop");
    }
}
