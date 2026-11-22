//! Soroban Security Scanner — core analysis engine.
//!
//! Deterministic, evidence-based security analysis for Stellar Soroban smart
//! contracts and Soroban-related Rust projects.
//!
//! # Design principles
//!
//! * **Deterministic** — identical input produces identical output. No
//!   wall-clock, randomness, or environment-specific ordering is allowed to
//!   influence findings.
//! * **Evidence-based** — every finding cites concrete source evidence. Rules
//!   may not fabricate findings or source locations.
//! * **Non-executing** — the scanner never compiles, executes, deploys, signs,
//!   or mutates the code it analyzes. Scanned repositories are treated as
//!   hostile input.
//! * **AI-optional** — the deterministic engine is authoritative. Any future AI
//!   assistance is advisory only.

pub mod ai;
pub mod analysis;
pub mod api_auth;
pub mod baseline;
pub mod category;
pub mod compare;
pub mod confidence;
pub mod config;
pub mod context;
pub mod corpus;
pub mod correlation;
pub mod detection;
pub mod discovery;
pub mod engine;
pub mod error;
pub mod finding;
pub mod fingerprint;
pub mod frontend;
pub mod imports;
pub mod manifest;
pub mod model;
pub mod monorepo;
pub mod pack;
pub mod policy;
pub mod project;
pub mod redaction;
pub mod registry;
pub mod report;
pub mod rule;
pub mod rules;
pub mod sdk_matrix;
pub mod service;
pub mod severity;
pub mod soroban;
pub mod source;
pub mod suppression;
pub mod target;
pub mod telemetry;
pub mod unsupported;

/// Crate version, sourced from Cargo at compile time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Stable tool name used in reports and exit banners.
pub const TOOL_NAME: &str = "soroban-scan";

/// Returns the scanner name and version as a display string.
pub fn version_string() -> String {
    format!("{TOOL_NAME} {VERSION}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_string_contains_name_and_version() {
        let v = version_string();
        assert!(v.starts_with(TOOL_NAME));
        assert!(v.contains(VERSION));
    }
}
