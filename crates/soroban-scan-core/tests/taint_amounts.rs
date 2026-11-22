//! Fixture-driven transfer-amount taint tests (#282).
//!
//! Samples live in `fixtures/taint/` so rule authors can reuse them. They are
//! intentionally not part of `fixtures/corpus`, which is reserved for detector
//! findings.

use std::path::PathBuf;

use soroban_scan_core::analysis::taint::{
    transfer_amount_flows, AmountFlow, TaintPath, AMOUNT_SANITIZERS,
};
use soroban_scan_core::rules::util::{contract_entry_functions, ContractFn};

fn fixture(name: &str) -> syn::File {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/taint")
        .join(name);
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    syn::parse_file(&source).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn entry<'a>(file: &'a syn::File, name: &str) -> ContractFn<'a> {
    contract_entry_functions(file)
        .into_iter()
        .find(|function| function.name == name)
        .unwrap_or_else(|| panic!("fixture has no entry point `{name}`"))
}

fn flows(name: &str) -> Vec<AmountFlow> {
    let file = fixture(name);
    transfer_amount_flows(&file, &entry(&file, "payout"))
}

#[test]
fn direct_amount_flow_is_reported() {
    let flows = flows("amount_direct.rs");
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].path.source_name(), Some("amount"));
    assert_eq!(flows[0].transformation(), None);
}

#[test]
fn arithmetic_amount_flow_keeps_the_expression_visible() {
    let flows = flows("amount_arithmetic.rs");
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].path.source_name(), Some("amount"));
    assert!(flows[0]
        .transformation()
        .is_some_and(|text| text.contains("amount - 100")));
}

#[test]
fn validated_amount_flow_is_not_reported() {
    assert!(flows("amount_validated.rs").is_empty());
}

#[test]
fn every_documented_amount_sanitizer_clears_taint() {
    let file = fixture("sanitizers_amount.rs");
    let entries = contract_entry_functions(&file);
    assert_eq!(
        entries.len(),
        AMOUNT_SANITIZERS.len(),
        "one fixture entry per documented sanitizer"
    );
    for entry in &entries {
        assert!(
            transfer_amount_flows(&file, entry).is_empty(),
            "`{}` must clear taint",
            entry.name
        );
    }
    let mut covered: Vec<&str> = entries
        .iter()
        .map(|entry| entry.name.trim_end_matches("_case"))
        .collect();
    covered.sort_unstable();
    let mut expected = AMOUNT_SANITIZERS.to_vec();
    expected.sort_unstable();
    assert_eq!(covered, expected);
}

#[test]
fn bare_comparison_is_not_a_sanitizer() {
    let file = fixture("amount_guarded.rs");
    let flows = transfer_amount_flows(&file, &entry(&file, "payout"));
    assert_eq!(
        flows.len(),
        1,
        "only documented sanitizer names stop amount taint"
    );
}

#[test]
fn conditional_amount_validation_is_not_silently_cleared() {
    let file = fixture("amount_conditional_sanitized.rs");
    let flows = transfer_amount_flows(&file, &entry(&file, "payout"));
    assert_eq!(flows.len(), 1, "conditional validation must stay visible");
    assert!(
        matches!(flows[0].path, TaintPath::Unknown { .. }),
        "conditional validation must be recorded as unknown, got {:?}",
        flows[0].path
    );
}
