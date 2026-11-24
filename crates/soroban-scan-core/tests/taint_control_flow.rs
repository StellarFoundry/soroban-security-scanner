//! Path-insensitive propagation and conservative joins (#285).
//!
//! The analysis claims only that a value may carry taint: it never asserts that
//! a branch, loop body, or return path is feasible. These tests pin the two
//! behaviours that make the claim safe: taint follows return values, and an
//! ambiguous join is reported as `Unknown` rather than silently untainted.

use std::path::PathBuf;

use soroban_scan_core::analysis::taint::{transfer_amount_flows, TaintPath};
use soroban_scan_core::rules::util::{contract_entry_functions, ContractFn};

fn fixture(name: &str) -> syn::File {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/taint")
        .join(name);
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    syn::parse_file(&source).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn entry<'a>(file: &'a syn::File) -> ContractFn<'a> {
    contract_entry_functions(file)
        .into_iter()
        .find(|function| function.name == "payout")
        .expect("fixture has a `payout` entry point")
}

#[test]
fn taint_from_one_branch_merges_conservatively() {
    let file = fixture("branch_merge.rs");
    let flows = transfer_amount_flows(&file, &entry(&file));
    assert_eq!(flows.len(), 1, "branch join must not clear taint");
    assert_eq!(flows[0].path.source_name(), Some("amount"));
}

#[test]
fn taint_from_a_loop_body_merges_conservatively() {
    let file = fixture("loop_merge.rs");
    let flows = transfer_amount_flows(&file, &entry(&file));
    assert_eq!(flows.len(), 1, "loop join must not clear taint");
    assert_eq!(flows[0].path.source_name(), Some("amount"));
}

#[test]
fn taint_propagates_through_a_helper_return() {
    let file = fixture("return_taint.rs");
    let flows = transfer_amount_flows(&file, &entry(&file));
    assert_eq!(flows.len(), 1, "helper return must carry taint");
    assert_eq!(flows[0].path.source_name(), Some("amount"));
}

#[test]
fn incompatible_early_and_tail_returns_merge_to_unknown() {
    let file = fixture("early_return_merge.rs");
    let flows = transfer_amount_flows(&file, &entry(&file));
    assert_eq!(
        flows.len(),
        1,
        "an ambiguous join is reported, never silently untainted"
    );
    assert!(
        matches!(flows[0].path, TaintPath::Unknown { .. }),
        "two tainted returns must merge to Unknown, got {:?}",
        flows[0].path
    );
}
