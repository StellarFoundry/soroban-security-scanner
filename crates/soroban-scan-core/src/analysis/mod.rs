//! Shared, bounded program analyses used by rules.
//!
//! Everything in this module is deterministic and data-only: descriptors are
//! plain values and no analysis executes code from the scanned project. When a
//! flow cannot be followed, the analysis records an explicit unknown marker
//! instead of inventing a source, sink, or edge.

pub mod cfg;
pub mod storage;
pub mod taint;
pub mod types;
