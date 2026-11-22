//! Fixture-driven auth-subject taint tests (#281).
//!
//! Samples live in `fixtures/taint/` so rule authors can reuse them. They are
//! intentionally not part of `fixtures/corpus`, which is reserved for detector
//! findings.

use std::path::PathBuf;

use soroban_scan_core::analysis::taint::{auth_subject_flows, AuthFlow};
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

fn flows(name: &str) -> Vec<AuthFlow> {
    let file = fixture(name);
    auth_subject_flows(&file, &entry(&file, "withdraw"))
}

#[test]
fn direct_auth_flow_is_reported() {
    let flows = flows("auth_direct.rs");
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].path.source_name(), Some("owner"));
}

#[test]
fn helper_auth_flow_is_reported_with_a_path() {
    let flows = flows("auth_helper.rs");
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].path.source_name(), Some("owner"));
    assert!(flows[0].path.description().contains("authorize::subject"));
}

#[test]
fn sanitized_auth_flow_is_not_reported() {
    assert!(flows("auth_sanitized.rs").is_empty());
}
