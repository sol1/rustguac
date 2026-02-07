#![no_main]
use libfuzzer_sys::fuzz_target;
use rustguac::protocol::Instruction;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz single-instruction parsing
        let _ = Instruction::parse(s);
    }
});
