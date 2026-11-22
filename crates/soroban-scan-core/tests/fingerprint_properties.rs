//! Property tests for the finding fingerprint contract.
//!
//! Fingerprints are load-bearing for baselines, so their stability rules are
//! asserted as properties rather than examples:
//!
//! * shifting a finding to another line never changes its fingerprint;
//! * whitespace-only changes to evidence never change a fingerprint;
//! * changing the rule id or the file always changes a fingerprint.

use std::path::Path;

use proptest::prelude::*;
use soroban_scan_core::analysis::cfg::Reachability;
use soroban_scan_core::category::Category;
use soroban_scan_core::confidence::Confidence;
use soroban_scan_core::finding::{fingerprint_of, Finding, SourceLocation};
use soroban_scan_core::severity::Severity;

/// Builds a finding with an explicit line and the fingerprint implied by its
/// rule id, file, and evidence.
fn finding(rule_id: &str, file: &str, line: usize, evidence: &str) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        title: String::new(),
        description: String::new(),
        severity: Severity::Info,
        confidence: Confidence::Low,
        category: Category::Authorization,
        location: SourceLocation::new(file, line),
        evidence: evidence.to_string(),
        remediation: String::new(),
        references: Vec::new(),
        fingerprint: fingerprint_of(rule_id, Path::new(file), evidence),
        reachability: Reachability::Unknown,
    }
}

fn rule_id() -> impl Strategy<Value = String> {
    "[A-Z]{2}-[0-9]{3}".prop_map(|value| value)
}

/// Path-shaped strings without backslashes, so normalization cannot collapse
/// two distinct generated values into the same fingerprint input.
fn file_path() -> impl Strategy<Value = String> {
    prop::collection::vec("[a-z][a-z0-9_]{0,7}", 1..5).prop_map(|segments| segments.join("/"))
}

/// Non-whitespace evidence tokens. Whitespace is added separately so the
/// property can vary it without changing the token sequence.
fn evidence_token() -> impl Strategy<Value = String> {
    prop_oneof![
        "[A-Za-z0-9_]{1,12}".prop_map(|value| value),
        "require_auth|transfer|invoke|panic|unwrap|allow|deny".prop_map(|value| value.to_string()),
    ]
}

fn evidence() -> impl Strategy<Value = String> {
    prop::collection::vec(evidence_token(), 0..8).prop_map(|tokens| tokens.join(" "))
}

fn whitespace() -> impl Strategy<Value = String> {
    prop::collection::vec(prop::sample::select(vec![' ', '\t', '\n', '\r']), 1..5)
        .prop_map(|chars| chars.into_iter().collect())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn line_changes_never_change_a_fingerprint(
        rule_id in rule_id(),
        file in file_path(),
        evidence in evidence(),
        line in 1usize..100_000,
        shift in 1usize..10_000,
    ) {
        let original = finding(&rule_id, &file, line, &evidence);
        let shifted = finding(&rule_id, &file, line.saturating_add(shift), &evidence);

        prop_assert_eq!(original.location.line, line);
        prop_assert!(shifted.location.line > original.location.line);
        prop_assert_eq!(original.fingerprint, shifted.fingerprint);
    }

    #[test]
    fn whitespace_only_evidence_changes_never_change_a_fingerprint(
        rule_id in rule_id(),
        file in file_path(),
        tokens in prop::collection::vec(evidence_token(), 0..8),
        separators in prop::collection::vec(whitespace(), 0..9),
        leading in whitespace(),
        trailing in whitespace(),
    ) {
        // Build two evidence strings with the same token sequence but different
        // whitespace runs, leading whitespace, and trailing whitespace.
        let mut left = String::new();
        let mut right = String::new();
        for (index, token) in tokens.iter().enumerate() {
            if index > 0 {
                left.push(' ');
                right.push_str(
                    separators
                        .get((index - 1) % separators.len().max(1))
                        .map(String::as_str)
                        .unwrap_or(" "),
                );
            }
            left.push_str(token);
            right.push_str(token);
        }
        left = format!("{leading}{left}{trailing}");

        let left_fingerprint = fingerprint_of(&rule_id, Path::new(&file), &left);
        let right_fingerprint = fingerprint_of(&rule_id, Path::new(&file), &right);
        prop_assert_eq!(left_fingerprint, right_fingerprint);
    }

    #[test]
    fn changing_rule_or_file_always_changes_a_fingerprint(
        rule_id in rule_id(),
        file in file_path(),
        evidence in evidence(),
    ) {
        let base = fingerprint_of(&rule_id, Path::new(&file), &evidence);

        // Distinct rule ids and file names cannot produce the same fingerprint.
        let other_rule = format!("{rule_id}-ALT");
        let other_file = format!("{file}/alt.rs");
        prop_assert_ne!(&base, &fingerprint_of(&other_rule, Path::new(&file), &evidence));
        prop_assert_ne!(&base, &fingerprint_of(&rule_id, Path::new(&other_file), &evidence));
    }
}
