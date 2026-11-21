#![no_main]

//! Fuzz target: run every rule on arbitrary parsed input.
//! Asserts: no panic, bounded runtime (via fuzzer -timeout and input cap).
//! Offline and deterministic: no network, clock, RNG, or filesystem access.

use libfuzzer_sys::fuzz_target;

use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::engine;
use soroban_scan_core::registry::RuleRegistry;

const MAX_INPUT_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };
    let registry = RuleRegistry::with_default_rules();
    let config = ScanConfig::default();
    // Output ignored on purpose: this target never constructs findings or edges.
    let _ = engine::scan_source_str(source, "fuzz.rs", &config, &registry);
});
