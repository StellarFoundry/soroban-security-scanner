//! Fixture-driven transfer-amount taint tests (#282).
//!
//! Samples live in `fixtures/taint/` so rule authors can reuse them. They are
//! intentionally not part of `fixtures/corpus`, which is reserved for detector
//! findings.

use std::path::PathBuf;

use soroban_scan_core::analysis::taint::{transfer_amount_flows, AmountFlow};
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
