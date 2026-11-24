//! Test-only helpers for exercising rules without touching the filesystem.
//!
//! [`RuleHarness`] runs one rule against inline sources through the real engine
//! path and reports every expectation failure at once. It exists so a rule
//! author can state positive, negative, and ambiguous cases next to the rule
//! without hand-rolling a registry and assertion for each one.

use crate::confidence::Confidence;
use crate::config::ScanConfig;
use crate::engine;
use crate::project::LoadedProject;
use crate::registry::RuleRegistry;
use crate::rule::Rule;
use crate::severity::Severity;

/// A flat summary of a finding, convenient for assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingSummary {
    /// Rule id.
    pub rule_id: String,
    /// Title.
    pub title: String,
    /// Severity.
    pub severity: Severity,
    /// Confidence.
    pub confidence: Confidence,
    /// Evidence text.
    pub evidence: String,
    /// 1-based line.
    pub line: usize,
}

/// Builds an in-memory loaded project from a single source string.
pub fn build_loaded(src: &str) -> LoadedProject {
    engine::synthetic_loaded(src, "src/lib.rs")
}

fn summarize(registry: &RuleRegistry, src: &str) -> Vec<FindingSummary> {
    let loaded = build_loaded(src);
    let outcome = engine::scan(&loaded, registry, &ScanConfig::default());
    outcome
        .findings
        .iter()
        .map(|f| FindingSummary {
            rule_id: f.rule_id.clone(),
            title: f.title.clone(),
            severity: f.severity,
            confidence: f.confidence,
            evidence: f.evidence.clone(),
            line: f.location.line,
        })
        .collect()
}

/// Scans a source string with a single rule.
pub fn scan_rule(src: &str, rule: Box<dyn Rule>) -> Vec<FindingSummary> {
    let mut registry = RuleRegistry::new();
    registry
        .register(rule)
        .expect("test rule must have a valid id");
    summarize(&registry, src)
}

/// Scans a source string with all built-in rules.
pub fn scan_all(src: &str) -> Vec<FindingSummary> {
    summarize(&RuleRegistry::with_default_rules(), src)
}

/// What a harness case expects from the rule.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Expectation {
    /// The rule must report exactly this many findings.
    Positive { count: usize },
    /// The rule must not report anything.
    Negative,
    /// The input is ambiguous under the rule's model. The rule must not guess,
    /// so it must report nothing; the reason is shown if it does.
    Ambiguous { reason: String },
}

struct Case {
    name: String,
    source: String,
    expectation: Expectation,
}

/// Runs one rule against inline sources and asserts all expectations.
///
/// Each case runs through the real engine (`engine::scan`), never a mocked
/// rule. `run` panics once with every failed case, including the case name,
/// expected outcome, actual findings, and a line-numbered copy of the source.
///
/// ```ignore
/// let mut harness = RuleHarness::new(Box::new(MyRule));
/// harness.positive("bare call", SRC, 1);
/// harness.negative("handled with ?", HANDLED_SRC);
/// harness.ambiguous("callee is not in this file", UNKNOWN_SRC, "the helper is undefined");
/// harness.run();
/// ```
pub struct RuleHarness {
    rule: Option<Box<dyn Rule>>,
    cases: Vec<Case>,
}

impl RuleHarness {
    /// Creates a harness for one rule.
    pub fn new(rule: Box<dyn Rule>) -> Self {
        RuleHarness {
            rule: Some(rule),
            cases: Vec::new(),
        }
    }

    /// Adds a case that must produce exactly `count` findings.
    pub fn positive(&mut self, name: &str, source: &str, count: usize) -> &mut Self {
        self.cases.push(Case {
            name: name.to_string(),
            source: source.to_string(),
            expectation: Expectation::Positive { count },
        });
        self
    }

    /// Adds a case that must produce no findings.
    pub fn negative(&mut self, name: &str, source: &str) -> &mut Self {
        self.cases.push(Case {
            name: name.to_string(),
            source: source.to_string(),
            expectation: Expectation::Negative,
        });
        self
    }

    /// Adds a case the rule cannot decide. It must not guess, so it must
    /// produce no findings.
    pub fn ambiguous(&mut self, name: &str, source: &str, reason: &str) -> &mut Self {
        self.cases.push(Case {
            name: name.to_string(),
            source: source.to_string(),
            expectation: Expectation::Ambiguous {
                reason: reason.to_string(),
            },
        });
        self
    }

    /// Runs every case and panics with all failures, or returns silently.
    pub fn run(self) {
        let rule = self
            .rule
            .expect("a harness must be created with a rule and run once");
        let mut registry = RuleRegistry::new();
        registry
            .register(rule)
            .expect("test rule must have a valid id");

        let mut failures = Vec::new();
        for case in &self.cases {
            let findings = summarize(&registry, &case.source);
            if let Some(failure) = check(case, &findings) {
                failures.push(failure);
            }
        }

        assert!(
            failures.is_empty(),
            "rule authoring harness: {} of {} case(s) failed\n\n{}",
            failures.len(),
            self.cases.len(),
            failures.join("\n\n")
        );
    }
}

fn check(case: &Case, findings: &[FindingSummary]) -> Option<String> {
    let (ok, expectation) = match &case.expectation {
        Expectation::Positive { count } => (
            findings.len() == *count,
            format!("expected exactly {count} finding(s)"),
        ),
        Expectation::Negative => (findings.is_empty(), "expected no findings".to_string()),
        Expectation::Ambiguous { reason } => (
            findings.is_empty(),
            format!("expected no finding because the case is ambiguous: {reason}"),
        ),
    };
    if ok {
        return None;
    }

    let mut message = format!(
        "[FAIL] {} ({})\n  {expectation}, got {}\n",
        case.name,
        case_kind(case),
        findings.len()
    );
    if findings.is_empty() {
        message.push_str("  findings: none\n");
    } else {
        message.push_str("  findings:\n");
        for finding in findings {
            message.push_str(&format!(
                "    {} line {}: {}\n",
                finding.rule_id, finding.line, finding.evidence
            ));
        }
    }
    message.push_str("  source:\n");
    for (index, line) in case.source.lines().enumerate() {
        message.push_str(&format!("    {:4} | {line}\n", index + 1));
    }
    Some(message)
}

fn case_kind(case: &Case) -> &'static str {
    match case.expectation {
        Expectation::Positive { .. } => "positive",
        Expectation::Negative => "negative",
        Expectation::Ambiguous { .. } => "ambiguous",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Category;
    use crate::context::AnalysisContext;
    use crate::finding::Finding;
    use crate::rule::RuleMetadata;

    /// Flags a call to `bad()` in an entry point; ignores `good()`.
    struct FlagBad;

    const METADATA: RuleMetadata = RuleMetadata {
        id: "SS-900",
        title: "Test-only bad call",
        description: "A test-only rule that flags calls named `bad` in an entry point.",
        category: Category::Authorization,
        default_severity: Severity::Low,
        default_confidence: Confidence::High,
        remediation: "Call `good` instead.",
        references: &["https://example.com"],
    };

    impl Rule for FlagBad {
        fn metadata(&self) -> &RuleMetadata {
            &METADATA
        }

        fn analyze(&self, ctx: &AnalysisContext<'_>, out: &mut Vec<Finding>) {
            for source in ctx.sources() {
                let Some(file) = &source.syntax else {
                    continue;
                };
                for entry in crate::rules::util::contract_entry_functions(file) {
                    let mut visitor = BadCall {
                        findings: &mut *out,
                        file: source.path.clone(),
                    };
                    syn::visit::Visit::visit_block(&mut visitor, entry.block);
                }
            }
        }
    }

    struct BadCall<'a> {
        findings: &'a mut Vec<Finding>,
        file: std::path::PathBuf,
    }

    impl<'ast> syn::visit::Visit<'ast> for BadCall<'_> {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*node.func {
                if path.path.is_ident("bad") {
                    let start = syn::spanned::Spanned::span(node).start();
                    self.findings.push(Finding::new(
                        &METADATA,
                        crate::finding::SourceLocation {
                            file: self.file.clone(),
                            line: start.line,
                            column: Some(start.column + 1),
                            end_line: None,
                            end_column: None,
                        },
                        "bad() is called",
                    ));
                }
            }
            syn::visit::visit_expr_call(self, node);
        }
    }

    fn source(body: &str) -> String {
        format!("#[contractimpl]\nimpl C {{\n    pub fn run() {{\n        {body}\n    }}\n}}\n")
    }

    #[test]
    fn passing_cases_do_not_panic() {
        let mut harness = RuleHarness::new(Box::new(FlagBad));
        harness.positive("bad call", &source("bad();"), 1);
        harness.negative("good call", &source("good();"));
        harness.ambiguous(
            "unknown helper",
            &source("mystery();"),
            "the helper is not defined",
        );
        harness.run();
    }

    #[test]
    fn wrong_expectations_report_every_case_with_context() {
        let mut harness = RuleHarness::new(Box::new(FlagBad));
        harness.positive("missing finding", &source("good();"), 1);
        harness.negative("unexpected finding", &source("bad();"));
        harness.ambiguous(
            "ambiguous but flagged",
            &source("bad();"),
            "the callee may not be a real sink",
        );

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| harness.run()));
        let message = panic_message(result);

        assert!(message.contains("3 of 3 case(s) failed"), "{message}");
        assert!(message.contains("missing finding (positive)"), "{message}");
        assert!(
            message.contains("expected exactly 1 finding(s), got 0"),
            "{message}"
        );
        assert!(
            message.contains("unexpected finding (negative)"),
            "{message}"
        );
        assert!(message.contains("expected no findings, got 1"), "{message}");
        assert!(
            message.contains("expected no finding because the case is ambiguous"),
            "{message}"
        );
        assert!(message.contains("bad() is called"), "{message}");
        assert!(message.contains("1 | #[contractimpl]"), "{message}");
    }

    #[test]
    fn positive_expectation_is_an_exact_count() {
        let mut harness = RuleHarness::new(Box::new(FlagBad));
        harness.positive("two bad calls", &source("bad();\n        bad();"), 2);
        harness.run();
    }

    fn panic_message(result: std::thread::Result<()>) -> String {
        match result {
            Ok(()) => panic!("harness should have failed"),
            Err(payload) => payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|text| text.to_string()))
                .unwrap_or_else(|| "non-string panic payload".to_string()),
        }
    }
}
