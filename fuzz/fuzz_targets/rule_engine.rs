#![no_main]

//! Fuzz target: run every rule on arbitrary parsed input.
//! Asserts: no panic, bounded runtime (via fuzzer -timeout and input cap).
//! Offline and deterministic: no network, clock, RNG, or filesystem access.

use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(parsed) = CRATE::PARSE_FN(source) else {
        return;
    };
    // Output ignored on purpose: this target never constructs findings or edges.
    let _ = CRATE::RULES_FN(&parsed);
});