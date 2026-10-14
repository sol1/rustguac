//! Reading the Guacamole instruction stream as `guacd_to_ws` sees it.
//!
//! Elements are `LENGTH.VALUE`, separated by `,` and terminated by `;`. These
//! walk them by their declared lengths, which is both correct -- a value may
//! itself contain `;`, clipboard text for one -- and cheap, since a large blob
//! payload is skipped in one step rather than scanned.

/// Yield each instruction start in `text` as a slice running to the end of the
/// buffer (callers only ever inspect the opcode and the first few arguments).
///
/// Instruction boundaries are found by walking element length prefixes rather
/// than by splitting on `;`, because an element *value* may contain a `;` —
/// clipboard text, for instance. Walking is also the cheaper option: each
/// element is skipped by its declared length, so a multi-megabyte blob payload
/// costs one jump rather than a scan.
///
/// `text` always ends on an instruction boundary (see `guacd_to_ws`). If a
/// malformed element is hit anyway, iteration stops rather than guessing.
pub(crate) fn instruction_starts(text: &str) -> impl Iterator<Item = &str> {
    InstructionStarts { rest: text }
}

struct InstructionStarts<'a> {
    rest: &'a str,
}

impl<'a> Iterator for InstructionStarts<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        if self.rest.is_empty() {
            return None;
        }

        let start = self.rest;
        let mut cursor = start;
        loop {
            match split_element(cursor) {
                Some((_, rest, b';')) => {
                    self.rest = rest;
                    break;
                }
                Some((_, rest, _)) => cursor = rest,
                None => {
                    // Malformed or truncated: yield what we have and stop,
                    // rather than looping.
                    self.rest = "";
                    break;
                }
            }
        }

        Some(start)
    }
}

/// Split one `LENGTH.VALUE` element off the front, returning the value, the
/// remainder past the separator, and the separator itself (`,` or `;`).
/// `None` if the element is malformed or truncated.
fn split_element(data: &str) -> Option<(&str, &str, u8)> {
    let dot = data.find('.')?;
    let len: usize = data[..dot].parse().ok()?;
    let value_start = dot + 1;
    let value_end = value_start.checked_add(len)?;
    if value_end > data.len() || !data.is_char_boundary(value_end) {
        return None;
    }
    let terminator = match data.as_bytes().get(value_end) {
        Some(&sep @ (b',' | b';')) => sep,
        _ => return None,
    };
    Some((
        &data[value_start..value_end],
        &data[value_end + 1..],
        terminator,
    ))
}

/// The value and remainder of the leading element, discarding the separator.
fn next_element(data: &str) -> Option<(&str, &str)> {
    split_element(data).map(|(value, rest, _)| (value, rest))
}

/// The elements of one instruction, in order, stopping at the first malformed
/// or truncated one.
///
pub(crate) fn elements(data: &str) -> impl Iterator<Item = &str> {
    let mut rest = data;
    std::iter::from_fn(move || {
        let (value, remainder) = next_element(rest)?;
        rest = remainder;
        Some(value)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `;` inside a value is data, not the end of the instruction.
    #[test]
    fn a_semicolon_in_a_value_does_not_split_an_instruction() {
        let text = "9.clipboard,3.a;b;4.sync,1.5;";
        let starts: Vec<&str> = instruction_starts(text).collect();
        assert_eq!(starts.len(), 2);
        assert!(starts[0].starts_with("9.clipboard,"));
        assert!(starts[1].starts_with("4.sync,"));
        // Each start runs to the end of the buffer; callers read only the
        // leading elements.
        assert_eq!(
            elements(starts[0]).take(2).collect::<Vec<_>>(),
            vec!["clipboard", "a;b"]
        );
    }

    /// A malformed element ends the walk instead of guessing past it.
    #[test]
    fn a_malformed_element_stops_iteration() {
        assert_eq!(elements("4.h264,x.bad;").collect::<Vec<_>>(), vec!["h264"]);
        assert_eq!(instruction_starts("4.sync,9.12;").count(), 1);
    }
}
