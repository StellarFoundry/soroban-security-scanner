//! Related-findings correlation.
//!
//! Rules are evaluated independently, so two rules can report the same concrete
//! construct as unrelated findings. This module links findings that share
//! concrete evidence:
//!
//! * the same file and an overlapping source span, or
//! * the same file and the same symbol (a backtick-quoted identifier in the
//!   finding evidence), reported by different rules.
//!
//! Links are deterministic, bounded, and explainable. When a symbol is shared
//! by more than two findings, or a finding has more candidates than
//! [`MAX_RELATED`], the finding is marked ambiguous instead of guessing an
//! ordering. Correlation never adds or removes findings.

use std::collections::{BTreeMap, BTreeSet};

use crate::finding::Finding;

/// Maximum number of related ids attached to one finding.
pub const MAX_RELATED: usize = 8;

/// Identifier-shaped backtick content shorter than this is ignored.
const MIN_SYMBOL_LEN: usize = 3;

/// Related finding ids for every finding, keyed by fingerprint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CorrelationIndex {
    related: BTreeMap<String, Vec<String>>,
    ambiguous: BTreeSet<String>,
}

impl CorrelationIndex {
    /// Related finding fingerprints, sorted and bounded.
    pub fn related_ids(&self, id: &str) -> &[String] {
        self.related.get(id).map(Vec::as_slice).unwrap_or(&[])
    }

    /// True when a relation was deliberately not chosen for this finding.
    pub fn is_ambiguous(&self, id: &str) -> bool {
        self.ambiguous.contains(id)
    }
}

/// Correlates a set of findings.
pub fn correlate(findings: &[Finding]) -> CorrelationIndex {
    let mut related: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut ambiguous: BTreeSet<String> = BTreeSet::new();

    // Only compare findings in the same file. Each pair is considered once.
    let mut by_file: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (index, finding) in findings.iter().enumerate() {
        by_file
            .entry(normalized_file(finding))
            .or_default()
            .push(index);
    }

    for indices in by_file.values() {
        for (position, &left) in indices.iter().enumerate() {
            for &right in &indices[position + 1..] {
                if findings[left].rule_id == findings[right].rule_id {
                    continue;
                }
                if spans_overlap(&findings[left], &findings[right]) {
                    link(&mut related, &findings[left], &findings[right]);
                }
            }
        }
    }

    let mut by_symbol: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
    for (index, finding) in findings.iter().enumerate() {
        if let Some(symbol) = symbol_of(&finding.evidence) {
            by_symbol
                .entry((normalized_file(finding), symbol))
                .or_default()
                .push(index);
        }
    }
    for indices in by_symbol.values() {
        if indices.len() == 2 {
            let (left, right) = (indices[0], indices[1]);
            if findings[left].rule_id != findings[right].rule_id {
                link(&mut related, &findings[left], &findings[right]);
            }
        } else if indices.len() > 2 {
            // The shared symbol is not enough to say which findings form a
            // pair, so record the ambiguity instead of inventing edges.
            for &index in indices {
                ambiguous.insert(findings[index].fingerprint.clone());
            }
        }
    }

    let mut bounded: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (id, ids) in related {
        if ids.len() > MAX_RELATED {
            // A finding with more evidence than the cap is not fully explained.
            // Mark it so consumers do not treat the list as exhaustive.
            ambiguous.insert(id.clone());
        }
        let ids: Vec<String> = ids.into_iter().take(MAX_RELATED).collect();
        bounded.insert(id, ids);
    }

    CorrelationIndex {
        related: bounded,
        ambiguous,
    }
}

fn link(related: &mut BTreeMap<String, BTreeSet<String>>, left: &Finding, right: &Finding) {
    related
        .entry(left.fingerprint.clone())
        .or_default()
        .insert(right.fingerprint.clone());
    related
        .entry(right.fingerprint.clone())
        .or_default()
        .insert(left.fingerprint.clone());
}

fn normalized_file(finding: &Finding) -> String {
    finding.location.file.to_string_lossy().replace('\\', "/")
}

fn spans_overlap(left: &Finding, right: &Finding) -> bool {
    if normalized_file(left) != normalized_file(right) {
        return false;
    }
    let left_end = left
        .location
        .end_line
        .unwrap_or(left.location.line)
        .max(left.location.line);
    let right_end = right
        .location
        .end_line
        .unwrap_or(right.location.line)
        .max(right.location.line);
    left.location.line <= right_end && right.location.line <= left_end
}

/// Returns the identifier the finding names as the affected item.
///
/// Rules write the affected function or type after a phrase such as `in` or
/// `entry point` and in backticks, so this is concrete evidence rather than a
/// guess. Without such a phrase, the last identifier-shaped backtick token is
/// used. Evidence with no identifier backticks yields `None`, and only span
/// relations apply.
fn symbol_of(evidence: &str) -> Option<String> {
    const MARKERS: [&str; 5] = [" in ", "entry point ", "function ", "method ", "for "];

    let mut preferred = None;
    let mut fallback = None;
    let mut offset = 0;
    while let Some(open_rel) = evidence[offset..].find('`') {
        let open = offset + open_rel;
        let after = &evidence[open + 1..];
        let Some(close) = after.find('`') else {
            break;
        };
        let candidate = &after[..close];
        if is_identifier(candidate) && candidate.len() >= MIN_SYMBOL_LEN {
            fallback = Some(candidate.to_string());
            let before = &evidence[..open];
            if MARKERS.iter().any(|marker| before.ends_with(marker)) {
                preferred = Some(candidate.to_string());
            }
        }
        offset = open + 1 + close + 1;
    }
    preferred.or(fallback)
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Category;
    use crate::confidence::Confidence;
    use crate::finding::SourceLocation;
    use crate::rule::RuleMetadata;
    use crate::severity::Severity;

    fn finding(rule: &str, file: &str, line: usize, evidence: &str) -> Finding {
        let meta = RuleMetadata::new(
            Box::leak(rule.to_string().into_boxed_str()),
            "title",
            "description",
            Category::Authorization,
            Severity::High,
            Confidence::Medium,
            "remediation",
        );
        Finding::new(&meta, SourceLocation::new(file, line), evidence)
    }

    #[test]
    fn same_span_across_rules_is_related() {
        let findings = vec![
            finding("SS-001", "src/lib.rs", 10, "`persistent` storage mutation"),
            finding("SS-008", "src/lib.rs", 10, "unchecked `+` arithmetic"),
        ];
        let index = correlate(&findings);
        assert_eq!(
            index.related_ids(&findings[0].fingerprint),
            &[findings[1].fingerprint.clone()]
        );
        assert_eq!(
            index.related_ids(&findings[1].fingerprint),
            &[findings[0].fingerprint.clone()]
        );
    }

    #[test]
    fn same_symbol_across_rules_is_related() {
        let findings = vec![
            finding("SS-001", "src/lib.rs", 10, "mutation in `transfer`"),
            finding("SS-008", "src/lib.rs", 30, "arithmetic in `transfer`"),
        ];
        let index = correlate(&findings);
        assert_eq!(
            index.related_ids(&findings[0].fingerprint),
            &[findings[1].fingerprint.clone()]
        );
    }

    #[test]
    fn unrelated_findings_have_no_edges() {
        let findings = vec![
            finding("SS-001", "src/lib.rs", 10, "mutation in `store`"),
            finding("SS-008", "src/lib.rs", 30, "arithmetic in `add`"),
        ];
        let index = correlate(&findings);
        assert!(index.related_ids(&findings[0].fingerprint).is_empty());
        assert!(index.related_ids(&findings[1].fingerprint).is_empty());
        assert!(!index.is_ambiguous(&findings[0].fingerprint));
    }

    #[test]
    fn ambiguous_symbol_is_recorded_not_linked() {
        let findings = vec![
            finding("SS-001", "src/lib.rs", 10, "mutation in `transfer`"),
            finding("SS-008", "src/lib.rs", 20, "arithmetic in `transfer`"),
            finding("SS-009", "src/lib.rs", 30, "cast in `transfer`"),
        ];
        let index = correlate(&findings);
        for finding in &findings {
            assert!(index.is_ambiguous(&finding.fingerprint));
        }
        // No span overlap, so no edges from the ambiguous symbol group.
        assert!(index.related_ids(&findings[0].fingerprint).is_empty());
    }

    #[test]
    fn related_list_is_bounded_and_marked_ambiguous() {
        let findings: Vec<Finding> = (0..MAX_RELATED + 2)
            .map(|index| {
                finding(
                    &format!("SS-{:03}", index + 1),
                    "src/lib.rs",
                    10,
                    "same construct",
                )
            })
            .collect();
        let index = correlate(&findings);
        let ids = index.related_ids(&findings[0].fingerprint);
        assert_eq!(ids.len(), MAX_RELATED);
        assert!(index.is_ambiguous(&findings[0].fingerprint));
        assert!(ids.windows(2).all(|pair| pair[0] <= pair[1]));
    }

    #[test]
    fn same_rule_findings_are_not_linked() {
        let findings = vec![
            finding("SS-001", "src/lib.rs", 10, "mutation in `transfer`"),
            finding("SS-001", "src/lib.rs", 10, "mutation in `transfer`"),
        ];
        let index = correlate(&findings);
        assert!(index.related_ids(&findings[0].fingerprint).is_empty());
    }
}
