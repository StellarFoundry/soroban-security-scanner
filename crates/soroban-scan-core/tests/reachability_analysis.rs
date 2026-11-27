//! Entry-point reachability is conservative, rule-visible, and confidence-aware.

use soroban_scan_core::analysis::reachability::FunctionReachability;
use soroban_scan_core::category::Category;
use soroban_scan_core::confidence::Confidence;
use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::context::AnalysisContext;
use soroban_scan_core::engine::{self, ScanOutcome};
use soroban_scan_core::finding::{Finding, SourceLocation};
use soroban_scan_core::model::DiagnosticCode;
use soroban_scan_core::registry::RuleRegistry;
use soroban_scan_core::rule::{Rule, RuleMetadata};
use soroban_scan_core::severity::Severity;

fn scan(source: &str) -> ScanOutcome {
    engine::scan_source_str(
        source,
        "lib.rs",
        &ScanConfig::default(),
        &RuleRegistry::with_default_rules(),
    )
}

fn scan_with_rule(source: &str, rule: Box<dyn Rule>) -> ScanOutcome {
    let mut registry = RuleRegistry::new();
    registry
        .register(rule)
        .expect("test-only rule id must be valid");
    engine::scan_source_str(source, "lib.rs", &ScanConfig::default(), &registry)
}

fn unsafe_finding(outcome: &ScanOutcome) -> &Finding {
    outcome
        .findings
        .iter()
        .find(|finding| finding.rule_id == "SS-005")
        .expect("fixture must trigger SS-005")
}

#[test]
fn helper_only_finding_is_retained_with_low_confidence() {
    let outcome = scan(include_str!(
        "../../../fixtures/reachability/helper_only.rs"
    ));
    let finding = unsafe_finding(&outcome);
    let context = finding
        .exploitability
        .as_ref()
        .expect("complete CFG and call graph yield context");

    assert_eq!(context.reachability, "unreachable");
    assert_eq!(context.entry_point, None, "an unreached helper has no root");
    assert_eq!(
        finding.confidence,
        Confidence::Low,
        "proven-unreachable findings are demoted, not dropped"
    );
}

#[test]
fn entry_reachable_helper_keeps_rule_confidence() {
    let outcome = scan(include_str!(
        "../../../fixtures/reachability/entry_reachable.rs"
    ));
    let finding = unsafe_finding(&outcome);
    let context = finding
        .exploitability
        .as_ref()
        .expect("reachable line yields context");

    assert_eq!(context.reachability, "reachable");
    assert!(
        context
            .entry_point
            .as_deref()
            .is_some_and(|entry| entry.ends_with("set")),
        "got: {context:?}"
    );
    assert_eq!(finding.confidence, Confidence::High);
}

#[test]
fn incomplete_cfg_is_ambiguity_not_unreachable() {
    let outcome = scan(include_str!(
        "../../../fixtures/reachability/incomplete_cfg.rs"
    ));
    let finding = unsafe_finding(&outcome);

    assert_eq!(finding.confidence, Confidence::High);
    assert!(
        finding.exploitability.is_none(),
        "an ambiguous line must not be labelled: {finding:?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == DiagnosticCode::ReachabilityIncomplete }),
        "ambiguity must be recorded: {:#?}",
        outcome.diagnostics
    );
}

const EXPOSE_METADATA: RuleMetadata = RuleMetadata {
    id: "SS-901",
    title: "Test-only reachability exposure",
    description: "Reports the entry-point reachability state of each function.",
    category: Category::Authorization,
    default_severity: Severity::Info,
    default_confidence: Confidence::High,
    remediation: "No action; test-only rule.",
    references: &[],
};

struct ExposeReachability;

impl Rule for ExposeReachability {
    fn metadata(&self) -> &RuleMetadata {
        &EXPOSE_METADATA
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>, out: &mut Vec<Finding>) {
        let analysis = ctx.reachability_analysis();
        for source in ctx.sources() {
            for function in &source.functions {
                let state = analysis
                    .reachability_for_summary(source, function)
                    .unwrap_or(FunctionReachability::Ambiguous);
                out.push(Finding::new(
                    &EXPOSE_METADATA,
                    SourceLocation::new(ctx.relative_path(&source.path), function.line),
                    format!("{}:{}", function.name, state.as_str()),
                ));
            }
        }
    }
}

#[test]
fn reachability_is_exposed_to_rules() {
    let helper_only = scan_with_rule(
        include_str!("../../../fixtures/reachability/helper_only.rs"),
        Box::new(ExposeReachability),
    );
    let helper_only = &helper_only.findings;
    assert!(
        helper_only
            .iter()
            .any(|finding| finding.evidence == "unused:unreachable"),
        "got: {helper_only:#?}"
    );
    assert!(
        helper_only
            .iter()
            .any(|finding| finding.evidence == "set:reachable"),
        "got: {helper_only:#?}"
    );

    let entry_reachable = scan_with_rule(
        include_str!("../../../fixtures/reachability/entry_reachable.rs"),
        Box::new(ExposeReachability),
    );
    let entry_reachable = &entry_reachable.findings;
    assert!(
        entry_reachable
            .iter()
            .any(|finding| finding.evidence == "store:reachable"),
        "got: {entry_reachable:#?}"
    );
}
