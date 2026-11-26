//! Registry-backed sanitizer tests (#284).
//!
//! Sanitizers are recognized only when a registered call or early-exit guard
//! appears in source. Comments, unknown helpers, and bare comparisons must
//! never suppress a taint flow.

use std::path::PathBuf;

use soroban_scan_core::analysis::taint::{
    address_argument_flows, auth_subject_flows, transfer_amount_flows, Sanitizer, SanitizerError,
    SanitizerForm, SanitizerKind, SanitizerRegistry, ADDRESS_SANITIZERS, AMOUNT_SANITIZERS,
    AUTH_SANITIZERS, MAX_SANITIZERS, SANITIZER_REGISTRY,
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

#[test]
fn built_in_registry_is_valid_and_bounded() {
    assert_eq!(SANITIZER_REGISTRY.validate(), Ok(()));
    assert!(!SANITIZER_REGISTRY.entries().is_empty());
    assert!(SANITIZER_REGISTRY.entries().len() <= MAX_SANITIZERS);
    for entry in SANITIZER_REGISTRY.entries() {
        assert!(!entry.assumption.trim().is_empty());
        assert!(!entry.name.is_empty());
    }
    for name in AUTH_SANITIZERS.iter().chain(ADDRESS_SANITIZERS) {
        assert!(
            SANITIZER_REGISTRY
                .entries()
                .iter()
                .any(|entry| entry.name == *name && entry.form == SanitizerForm::Call),
            "compatibility name `{name}` must be in the registry"
        );
    }
    for name in AMOUNT_SANITIZERS {
        assert!(
            SANITIZER_REGISTRY
                .entries()
                .iter()
                .any(|entry| entry.name == *name && entry.form == SanitizerForm::Call),
            "compatibility name `{name}` must be in the registry"
        );
    }
}

#[test]
fn registry_rejects_invalid_entries() {
    const DUPLICATE: &[Sanitizer] = &[
        Sanitizer {
            name: "same",
            kind: SanitizerKind::AuthSubject,
            form: SanitizerForm::Call,
            assumption: "first",
        },
        Sanitizer {
            name: "same",
            kind: SanitizerKind::AuthSubject,
            form: SanitizerForm::Call,
            assumption: "second",
        },
    ];
    assert_eq!(
        SanitizerRegistry::from_static(DUPLICATE).validate(),
        Err(SanitizerError::Duplicate {
            name: "same",
            kind: SanitizerKind::AuthSubject,
        })
    );

    const EMPTY_ASSUMPTION: &[Sanitizer] = &[Sanitizer {
        name: "unchecked",
        kind: SanitizerKind::TransferAmount,
        form: SanitizerForm::Call,
        assumption: "",
    }];
    assert_eq!(
        SanitizerRegistry::from_static(EMPTY_ASSUMPTION).validate(),
        Err(SanitizerError::EmptyAssumption)
    );

    const INVALID_NAME: &[Sanitizer] = &[Sanitizer {
        name: "",
        kind: SanitizerKind::AuthSubject,
        form: SanitizerForm::Guard,
        assumption: "valid assumption",
    }];
    assert_eq!(
        SanitizerRegistry::from_static(INVALID_NAME).validate(),
        Err(SanitizerError::InvalidName)
    );

    let oversized: Vec<Sanitizer> = (0..=MAX_SANITIZERS)
        .map(|_| Sanitizer {
            name: "valid_name",
            kind: SanitizerKind::AuthSubject,
            form: SanitizerForm::Call,
            assumption: "valid assumption",
        })
        .collect();
    let leaked: &'static [Sanitizer] = Box::leak(oversized.into_boxed_slice());
    assert_eq!(
        SanitizerRegistry::from_static(leaked).validate(),
        Err(SanitizerError::TooMany)
    );
}

#[test]
fn registered_guards_clear_only_their_matching_categories() {
    let file = fixture("sanitizer_guards.rs");
    let entries = contract_entry_functions(&file);
    assert_eq!(entries.len(), 3, "one fixture entry per guard category");

    let auth = auth_subject_flows(&file, &entry(&file, "auth_guard_case"));
    assert!(auth.is_empty(), "registered auth guard must clear taint");

    let amount = transfer_amount_flows(&file, &entry(&file, "amount_guard_case"));
    assert!(
        amount.is_empty(),
        "registered amount guard must clear taint"
    );

    let address = address_argument_flows(&file, &entry(&file, "address_guard_case"));
    assert!(
        address.is_empty(),
        "registered address guard must clear taint"
    );
}

#[test]
fn comments_and_unknown_validation_do_not_clear_auth_taint() {
    let file = fixture("sanitizer_negative.rs");
    for name in [
        "comment_case",
        "unknown_call_case",
        "unknown_guard_case",
        "non_exit_guard_case",
    ] {
        let flows = auth_subject_flows(&file, &entry(&file, name));
        assert_eq!(flows.len(), 1, "`{name}` must remain a tainted auth flow");
        assert_eq!(flows[0].path.source_name(), Some("owner"));
    }
}

#[test]
fn comments_and_unknown_validation_do_not_clear_amount_or_address_taint() {
    let file = fixture("sanitizer_negative.rs");

    for name in ["amount_unknown_case", "amount_bare_case"] {
        let flows = transfer_amount_flows(&file, &entry(&file, name));
        assert_eq!(flows.len(), 1, "`{name}` must remain a tainted amount flow");
        assert_eq!(flows[0].path.source_name(), Some("amount"));
    }

    let flows = address_argument_flows(&file, &entry(&file, "address_unknown_case"));
    assert_eq!(
        flows.len(),
        1,
        "unknown address helper must not clear taint"
    );
    assert_eq!(flows[0].path.source_name(), Some("to"));
}
