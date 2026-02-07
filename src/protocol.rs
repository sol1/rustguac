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
}
