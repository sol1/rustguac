#![no_main]
use libfuzzer_sys::fuzz_target;
use rustguac::protocol::InstructionParser;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz the streaming parser: split input into random-sized chunks
        // to exercise buffer accumulation and boundary handling
        let mut parser = InstructionParser::new();
        let bytes = s.as_bytes();
        let mut pos = 0;
        let mut chunk_size = 1;
        while pos < bytes.len() {
            let end = (pos + chunk_size).min(bytes.len());
            if let Ok(chunk) = std::str::from_utf8(&bytes[pos..end]) {
                for result in parser.receive(chunk) {
                    // Exercise encode on successfully parsed instructions
                    if let Ok(inst) = result {
                        let _ = inst.encode();
                    }
                }
            }
            pos = end;
            // Vary chunk sizes: 1, 2, 4, 8, ... then wrap back
            chunk_size = if chunk_size >= 64 { 1 } else { chunk_size * 2 };
        }
    }
});
