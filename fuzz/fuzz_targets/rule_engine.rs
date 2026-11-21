#![no_main]

//! Fuzz target: run every rule on arbitrary parsed input.
//! Asserts: no panic, bounded runtime (via fuzzer -timeout and input cap).
//! Offline and deterministic: no network, clock, RNG, or filesystem access.

use libfuzzer_sys::fuzz_target;
use soroban_scan_core::{config::ScanConfig, engine, registry::RuleRegistry};

const MAX_INPUT_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let source = String::from_utf8_lossy(data);
    let loaded = engine::synthetic_loaded(&source, "src/lib.rs");
    let _ = engine::scan(
        &loaded,
        &RuleRegistry::with_default_rules(),
        &ScanConfig::default(),
    );
});