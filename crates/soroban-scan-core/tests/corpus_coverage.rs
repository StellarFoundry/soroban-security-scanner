//! Corpus coverage contract (#140): every rule has fixtures, docs, and a
//! must-trigger sample.

use soroban_scan_core::corpus::{coverage, render_markdown, render_terminal, repository_root};
use soroban_scan_core::registry::RuleRegistry;

#[test]
fn every_rule_has_a_complete_corpus_entry() {
    let registry = RuleRegistry::with_default_rules();
    let rows = coverage(&repository_root(), &registry);
    assert_eq!(rows.len(), registry.metadata_sorted().len());
    for row in &rows {
        assert!(
            row.documented,
            "{}: missing detector documentation",
            row.rule_id
        );
        assert!(
            row.positives >= 1,
            "{}: missing positive fixture",
            row.rule_id
        );
        assert!(
            row.negatives >= 3,
            "{}: fewer than three negative fixtures",
            row.rule_id
        );
        assert!(
            row.must_trigger,
            "{}: missing must-trigger sample",
            row.rule_id
        );
        assert!(row.complete(), "{}: incomplete corpus entry", row.rule_id);
    }

    let terminal = render_terminal(&rows);
    let markdown = render_markdown(&rows);
    for row in &rows {
        assert!(terminal.contains(&row.rule_id));
        assert!(markdown.contains(&row.rule_id));
    }
}
