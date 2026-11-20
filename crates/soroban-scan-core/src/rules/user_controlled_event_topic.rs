//! SS-031: event topic derived from a caller-controlled parameter.

use std::collections::BTreeSet;

use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, location_for};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-031",
    title: "Event topic derived from a caller-controlled parameter",
    description: "A contract publishes an event whose topic list includes a \
function parameter, so the caller influences which topic the event appears under. \
Off-chain indexers that group or trust events by topic can be fed spoofed, \
trusted-looking events (for example a fake `transfer` or `admin` event). Topics \
should identify the event type; caller-controlled values belong in the event data \
payload. This is a heuristic and reports low confidence.",
    category: Category::Events,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Low,
    remediation: "Use a constant topic (`symbol_short!(\"transfer\")` or \
`Symbol::new(&env, \"transfer\")`) and put caller-controlled values in the event \
data payload. If a parameter must appear in a topic, document why and validate it \
against an allowlist of expected topic values.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/events",
        "https://developers.stellar.org/docs/learn/encyclopedia/security",
    ],
};

/// Detects event topics built from caller-controlled parameters.
pub struct UserControlledEventTopic;

/// A publish call whose topic list references at least one caller parameter.
struct TopicFact {
    params: BTreeSet<String>,
    line: usize,
    column: usize,
    text: String,
}

struct PublishVisitor<'a> {
    caller_params: &'a BTreeSet<String>,
    publishes: Vec<TopicFact>,
}

impl<'ast, 'a> Visit<'ast> for PublishVisitor<'a> {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let receiver = node
            .receiver
            .to_token_stream()
            .to_string()
            .to_ascii_lowercase();
        if node.method == "publish" && receiver.contains("event") {
            if let Some(topics) = node.args.first() {
                let params = referenced_params(topics, self.caller_params);
                if !params.is_empty() {
                    let start = node.span().start();
                    self.publishes.push(TopicFact {
                        params,
                        line: start.line,
                        column: start.column + 1,
                        text: node.to_token_stream().to_string(),
                    });
                }
            }
        }
        visit::visit_expr_method_call(self, node);
    }
}

/// Collects caller parameters referenced anywhere in a topic expression.
fn referenced_params(expr: &syn::Expr, params: &BTreeSet<String>) -> BTreeSet<String> {
    struct RefVisitor<'a> {
        params: &'a BTreeSet<String>,
        found: BTreeSet<String>,
    }

    impl<'ast> Visit<'ast> for RefVisitor<'_> {
        fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
            if node.qself.is_none() {
                if let Some(ident) = node.path.get_ident() {
                    let name = ident.to_string();
                    if self.params.contains(&name) {
                        self.found.insert(name);
                    }
                }
            }
            visit::visit_expr_path(self, node);
        }
    }

    let mut visitor = RefVisitor {
        params,
        found: BTreeSet::new(),
    };
    visitor.visit_expr(expr);
    visitor.found
}

impl Rule for UserControlledEventTopic {
    fn metadata(&self) -> &RuleMetadata {
        &METADATA
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>, out: &mut Vec<Finding>) {
        if !ctx.is_confirmed_soroban() {
            return;
        }
        for source in ctx.sources() {
            let Some(file) = &source.syntax else {
                continue;
            };
            for func in contract_entry_functions(file) {
                if !func.is_public {
                    continue;
                }
                // The `Env` parameter is framework state, not caller input.
                let caller_params: BTreeSet<String> = func
                    .param_types
                    .iter()
                    .filter(|(_, ty)| !ty.trim().trim_start_matches('&').trim().starts_with("Env"))
                    .map(|(name, _)| name.clone())
                    .collect();
                let mut visitor = PublishVisitor {
                    caller_params: &caller_params,
                    publishes: Vec::new(),
                };
                visitor.visit_block(func.block);
                for publish in visitor.publishes {
                    let location = location_for(ctx, source, publish.line, publish.column);
                    let params = publish.params.into_iter().collect::<Vec<_>>().join("`, `");
                    let evidence = format!(
                        "event topic derived from caller-controlled parameter(s) `{params}` \
                         in entry point `{}`: {}",
                        func.name,
                        truncate(&publish.text, 160)
                    );
                    out.push(Finding::new(&METADATA, location, evidence));
                }
            }
        }
    }
}

/// Truncates rendered source without splitting a UTF-8 code point.
fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_topic_from_parameter() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, symbol_short, Address, Env};

            #[contractimpl]
            impl C {
                pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
                    env.events().publish((symbol_short!("transfer"), to), amount);
                }
            }
            "#,
            Box::new(UserControlledEventTopic),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-031");
        assert!(findings[0]
            .evidence
            .contains("caller-controlled parameter(s) `to`"));
    }

    #[test]
    fn flags_referenced_and_computed_parameter_topics() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, symbol_short, Address, Env};

            #[contractimpl]
            impl C {
                pub fn publish(env: Env, account: Address) {
                    env.events().publish((symbol_short!("tag"), &account), 0);
                    env.events().publish(tag_of(account), 0);
                }
            }
            "#,
            Box::new(UserControlledEventTopic),
        );
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn does_not_flag_constant_topics() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, symbol_short, Address, Env, Symbol};

            #[contractimpl]
            impl C {
                pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
                    env.events().publish(
                        (symbol_short!("transfer"), Symbol::new(&env, "v1"), TOPIC),
                        (from, to, amount),
                    );
                }
            }
            "#,
            Box::new(UserControlledEventTopic),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_parameters_in_the_data_payload() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, symbol_short, Address, Env};

            #[contractimpl]
            impl C {
                pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
                    env.events().publish(symbol_short!("transfer"), (from, to, amount));
                }
            }
            "#,
            Box::new(UserControlledEventTopic),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_private_helpers_or_other_publish_methods() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, symbol_short, Address, Env};

            #[contractimpl]
            impl C {
                pub fn entry(env: Env, to: Address) {
                    bus.publish(to);
                }
                fn helper(env: Env, to: Address) {
                    env.events().publish(to, 0);
                }
            }
            "#,
            Box::new(UserControlledEventTopic),
        );
        assert!(findings.is_empty());
    }
}
