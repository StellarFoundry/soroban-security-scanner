//! Integer cast type tracking (#274).
//!
//! The cast analysis reports the source and destination integer types and marks
//! truncating or signedness-changing casts. Unknown operands stay unknown.

use std::path::PathBuf;

use soroban_scan_core::rules::util::{cast_facts, contract_entry_functions, IntegerType};

fn fixture(name: &str) -> syn::File {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/casts")
        .join(name);
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    syn::parse_file(&source).expect("cast fixture must parse")
}

fn casts(file: &syn::File) -> Vec<soroban_scan_core::rules::util::CastFact> {
    let entry = contract_entry_functions(file)
        .into_iter()
        .find(|function| function.is_public)
        .expect("fixture needs a public entry point");
    let params = entry.param_types.into_iter().collect();
    cast_facts(entry.block, &params)
}

#[test]
fn widening_casts_are_lossless() {
    let casts = casts(&fixture("widening.rs"));
    assert_eq!(casts.len(), 2);
    for cast in &casts {
        assert!(cast.integer_cast().is_some());
        assert!(!cast.is_potentially_lossy(), "unexpected lossy: {cast:?}");
    }
}

#[test]
fn narrowing_casts_are_marked_lossy() {
    let casts = casts(&fixture("narrowing.rs"));
    assert_eq!(casts.len(), 2);
    for cast in &casts {
        let integer = cast.integer_cast().expect("known integer types");
        assert!(integer.is_truncating());
        assert!(cast.is_potentially_lossy());
    }
}

#[test]
fn signedness_changes_are_marked_lossy() {
    let casts = casts(&fixture("signed_unsigned.rs"));
    assert_eq!(casts.len(), 2);
    for cast in &casts {
        let integer = cast.integer_cast().expect("known integer types");
        assert!(integer.changes_signedness());
        assert!(cast.is_potentially_lossy());
    }
}

#[test]
fn cast_types_are_exposed_for_rules() {
    let cast = &casts(&fixture("narrowing.rs"))[0];
    assert_eq!(cast.source_integer, IntegerType::parse("i128"));
    assert_eq!(cast.target_integer, IntegerType::parse("u32"));
    assert_eq!(cast.source_type, "i128");
    assert_eq!(cast.target_type, "u32");
}
