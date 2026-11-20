//! Frontend conformance suite (#386).
//!
//! The suite pins the behaviours every `Frontend` must provide: stable name,
//! deterministic discovery inside the scan root, non-fatal diagnostics, item
//! extraction, and valid source spans. A future frontend runs the same harness
//! by including `conformance/mod.rs` and passing its own fixtures.

mod conformance;

use std::path::PathBuf;

use soroban_scan_core::frontend::default_frontend;

fn fixture(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/projects")
        .join(relative)
}

#[test]
fn rust_frontend_conforms_to_the_trait_contract() {
    let frontend = default_frontend();
    let failures = conformance::check(&conformance::Case {
        frontend: &frontend,
        expected_name: "rust",
        root: &fixture("soroban-confirmed"),
        broken_root: &fixture("parse-error"),
    });

    assert!(
        failures.is_empty(),
        "Rust frontend conformance failures:\n{}",
        failures.join("\n")
    );
}
