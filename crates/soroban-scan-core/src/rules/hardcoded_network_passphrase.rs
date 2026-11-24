//! SS-043: hardcoded Stellar network passphrase or network constant.

use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::location_for;

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-043",
    title: "Hardcoded Stellar network passphrase",
    description: "A source file embeds a canonical Stellar network passphrase \
or selects a known network constant. Pinning a network in code can cause \
signing or submission against an unintended network when the same deployment \
is used in multiple environments.",
    category: Category::Configuration,
    default_severity: Severity::Medium,
    default_confidence: Confidence::High,
    remediation: "Read the network passphrase from deployment configuration \
or an environment variable, validate it against the intended network, and \
keep environment-specific values out of shared source.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/network",
        "https://developers.stellar.org/docs/tools/stellar-cli",
    ],
};

const KNOWN_PASSPHRASES: &[&str] = &[
    "Public Global Stellar Network ; September 2015",
    "Test SDF Network ; September 2015",
    "Test SDF Future Network ; October 2022",
    "Standalone Network ; February 2017",
];

const KNOWN_NETWORKS: &[&str] = &["PUBLIC", "TESTNET", "FUTURENET", "STANDALONE"];

/// Detects hardcoded Stellar network passphrases and fully qualified network
/// constants from the Stellar SDK.
pub struct HardcodedNetworkPassphrase;

#[derive(Debug)]
struct NetworkReference {
    line: usize,
    column: usize,
    evidence: String,
}

struct NetworkVisitor {
    references: Vec<NetworkReference>,
}

impl<'ast> Visit<'ast> for NetworkVisitor {
    fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
        let value = literal.value();
        if KNOWN_PASSPHRASES.contains(&value.as_str()) {
            let start = literal.span().start();
            self.references.push(NetworkReference {
                line: start.line,
                column: start.column + 1,
                evidence: format!("hardcoded Stellar network passphrase: {value}"),
            });
        }
        visit::visit_lit_str(self, literal);
    }

    fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
        let segments: Vec<_> = expression
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        if is_known_network_constant(&segments) {
            let start = expression.span().start();
            let path = segments.join("::");
            self.references.push(NetworkReference {
                line: start.line,
                column: start.column + 1,
                evidence: format!("hardcoded Stellar network constant: {path}"),
            });
        }
        visit::visit_expr_path(self, expression);
    }
}

fn is_known_network_constant(segments: &[String]) -> bool {
    if segments.first().map(String::as_str) != Some("stellar_sdk") {
        return false;
    }

    let Some(network_name) = segments.last() else {
        return false;
    };
    if !KNOWN_NETWORKS.contains(&network_name.as_str()) {
        return false;
    }

    segments
        .iter()
        .any(|segment| matches!(segment.as_str(), "Network" | "Networks"))
}

impl Rule for HardcodedNetworkPassphrase {
    fn metadata(&self) -> &RuleMetadata {
        &METADATA
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>, out: &mut Vec<Finding>) {
        for source in ctx.sources() {
            let Some(file) = &source.syntax else {
                continue;
            };
            let mut visitor = NetworkVisitor {
                references: Vec::new(),
            };
            visitor.visit_file(file);
            for reference in visitor.references {
                let location = location_for(ctx, source, reference.line, reference.column);
                out.push(Finding::new(&METADATA, location, reference.evidence));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_known_passphrase_literals() {
        for passphrase in KNOWN_PASSPHRASES {
            let source = format!("const PASSPHRASE: &str = {passphrase:?};");
            let findings = scan_rule(&source, Box::new(HardcodedNetworkPassphrase));
            assert_eq!(findings.len(), 1, "{passphrase}");
            assert_eq!(findings[0].rule_id, "SS-043");
            assert!(findings[0].evidence.contains(passphrase));
        }
    }

    #[test]
    fn flags_qualified_known_network_constant() {
        let findings = scan_rule(
            "fn network() { let _ = stellar_sdk::networks::Networks::TESTNET; }",
            Box::new(HardcodedNetworkPassphrase),
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.contains("Networks::TESTNET"));
    }

    #[test]
    fn ignores_configuration_and_unrelated_paths() {
        for source in [
            "let passphrase = std::env::var(\"STELLAR_NETWORK_PASSPHRASE\");",
            "const PASSPHRASE: &str = \"custom deployment network\";",
            "let network = my_app::Networks::TESTNET;",
            "let network = stellar_sdk::Network::Custom;",
        ] {
            let findings = scan_rule(source, Box::new(HardcodedNetworkPassphrase));
            assert!(findings.is_empty(), "unexpected finding for {source}");
        }
    }
}
