//! Fixture-driven privileged-address taint tests (#283).
//!
//! Samples live in `fixtures/taint/` so rule authors can reuse them. Address
//! provenance is separate from authorization subjects: a documented validation
//! helper is the only thing that clears it, never an `Address` type.

use std::path::PathBuf;

use soroban_scan_core::analysis::taint::{
    address_argument_flows, AddressFlow, TaintPath, ADDRESS_SANITIZERS,
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

fn flows(name: &str) -> Vec<AddressFlow> {
    let file = fixture(name);
    address_argument_flows(&file, &entry(&file, "payout"))
}

#[test]
fn direct_address_flow_is_reported() {
    let flows = flows("address_direct.rs");
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].path.source_name(), Some("to"));
    assert_eq!(flows[0].sink.name, "transfer");
    assert_eq!(flows[0].sink.argument, Some(1));
}

#[test]
fn decoded_address_flow_keeps_the_decoded_source() {
    let flows = flows("address_decoded.rs");
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].path.source_name(), Some("raw"));
}

#[test]
fn validated_address_flow_is_not_reported() {
    assert!(flows("address_validated.rs").is_empty());
}

#[test]
fn every_documented_address_sanitizer_clears_taint() {
    let file = fixture("sanitizers_address.rs");
    let entries = contract_entry_functions(&file);
    assert_eq!(
        entries.len(),
        ADDRESS_SANITIZERS.len(),
        "one fixture entry per documented sanitizer"
    );
    for entry in &entries {
        assert!(
            address_argument_flows(&file, entry).is_empty(),
            "`{}` must clear address taint",
            entry.name
        );
    }
    let mut covered: Vec<&str> = entries
        .iter()
        .map(|entry| entry.name.trim_end_matches("_case"))
        .collect();
    covered.sort_unstable();
    let mut expected = ADDRESS_SANITIZERS.to_vec();
    expected.sort_unstable();
    assert_eq!(covered, expected);
}

#[test]
fn conditional_address_validation_stays_visible() {
    let file = fixture("address_conditional_sanitized.rs");
    let flows = address_argument_flows(&file, &entry(&file, "payout"));
    assert_eq!(flows.len(), 1, "conditional validation must stay visible");
    assert!(
        matches!(flows[0].path, TaintPath::Unknown { .. }),
        "conditional validation must be recorded as unknown, got {:?}",
        flows[0].path
    );
}
