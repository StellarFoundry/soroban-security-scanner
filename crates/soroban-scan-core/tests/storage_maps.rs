//! `Map` storage key/value type resolution (#275).
//!
//! Only visible types are resolved; an unclassifiable key stays `Unknown`.

use std::path::PathBuf;

use soroban_scan_core::analysis::storage::{map_storage_accesses, MapKeyType};
use soroban_scan_core::rules::util::contract_entry_functions;

fn fixture(name: &str) -> syn::File {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/storage-maps")
        .join(name);
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    syn::parse_file(&source).expect("map fixture must parse")
}

fn key_types(name: &str) -> Vec<MapKeyType> {
    let file = fixture(name);
    let entry = contract_entry_functions(&file)
        .into_iter()
        .find(|function| function.is_public)
        .expect("fixture needs a public entry point");
    map_storage_accesses(entry.block)
        .into_iter()
        .map(|access| access.key_type)
        .collect()
}

#[test]
fn resolves_symbol_keys() {
    assert_eq!(key_types("symbol.rs"), vec![MapKeyType::Symbol]);
}

#[test]
fn resolves_address_keys() {
    assert_eq!(key_types("address.rs"), vec![MapKeyType::Address]);
}

#[test]
fn resolves_tuple_keys() {
    assert_eq!(
        key_types("tuple.rs"),
        vec![MapKeyType::Tuple(vec![
            MapKeyType::Symbol,
            MapKeyType::Address
        ])]
    );
}

#[test]
fn unclassifiable_keys_stay_unknown() {
    let keys = key_types("unknown.rs");
    assert_eq!(keys, vec![MapKeyType::Unknown]);
    assert!(keys[0].is_unknown());
}
