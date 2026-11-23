//! SS-046: the same storage key constructed for values with different shapes.

use std::collections::{BTreeMap, BTreeSet};

use quote::ToTokens;
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
    id: "SS-046",
    title: "Duplicate storage key construction",
    description: "A contract writes different logical records through the same \
storage key construction. When the key is a literal or a constructor whose \
arguments do not fully separate the records, one write can overwrite or be \
mistaken for another record with a different field set. The detector compares \
the field sets of struct literals written to the same key in the same storage \
class and reports only when they differ, with low confidence.",
    category: Category::Storage,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Low,
    remediation: "Give each logical record its own namespaced key, for example \
`DataKey::Balance(user)` and `DataKey::BalanceMeta(user)`, or store a single \
versioned value type per key. Do not rely on the value's field set to tell two \
records apart; the key must identify exactly one record shape.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/storage/persisting-data",
        "https://developers.stellar.org/docs/learn/encyclopedia/security",
    ],
};

/// Detects one key construction used for values with different field sets.
pub struct DuplicateStorageKeyConstruction;

struct KeyUse {
    class: &'static str,
    key: String,
    fields: BTreeSet<String>,
    line: usize,
    column: usize,
}

#[derive(Default)]
struct KeyVisitor {
    uses: Vec<KeyUse>,
}

impl<'ast> Visit<'ast> for KeyVisitor {
    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if !has_attribute(&node.attrs, "contractimpl") {
            return;
        }
        for item in &node.items {
            visit::visit_impl_item(self, item);
        }
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "set" && node.args.len() >= 2 {
            if let (Some(key), Some(value)) = (node.args.first(), node.args.get(1)) {
                if let Some(record) = key_use(&node.receiver, key, value) {
                    self.uses.push(record);
                }
            }
        }
        visit::visit_expr_method_call(self, node);
    }
}

fn has_attribute(attrs: &[syn::Attribute], name: &str) -> bool {
    attrs.iter().any(|attribute| {
        attribute
            .path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == name)
    })
}

/// Builds a key use when the call is a storage write and the value is a struct
/// literal without a rest pattern, whose field set is therefore visible.
fn key_use(receiver: &syn::Expr, key: &syn::Expr, value: &syn::Expr) -> Option<KeyUse> {
    let receiver = receiver.to_token_stream().to_string();
    if !receiver.contains("storage") {
        return None;
    }
    let class = ["persistent", "temporary", "instance"]
        .into_iter()
        .find(|class| receiver.contains(class))?;
    let fields = struct_fields(value)?;
    let start = key.span().start();
    Some(KeyUse {
        class,
        key: key.to_token_stream().to_string(),
        fields,
        line: start.line,
        column: start.column + 1,
    })
}

fn struct_fields(expr: &syn::Expr) -> Option<BTreeSet<String>> {
    let expr = unwrap_ref(expr);
    match expr {
        syn::Expr::Struct(data) => {
            if data.rest.is_some() || data.fields.is_empty() {
                return None;
            }
            Some(
                data.fields
                    .iter()
                    .map(|field| match &field.member {
                        syn::Member::Named(name) => name.to_string(),
                        syn::Member::Unnamed(index) => index.index.to_string(),
                    })
                    .collect(),
            )
        }
        _ => None,
    }
}

fn unwrap_ref(expr: &syn::Expr) -> &syn::Expr {
    match expr {
        syn::Expr::Reference(reference) => unwrap_ref(&reference.expr),
        syn::Expr::Paren(paren) => unwrap_ref(&paren.expr),
        syn::Expr::Group(group) => unwrap_ref(&group.expr),
        _ => expr,
    }
}

impl Rule for DuplicateStorageKeyConstruction {
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
            let mut visitor = KeyVisitor::default();
            visitor.visit_file(file);

            // First visible field set per storage class and key construction.
            let mut seen: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
            let mut reported: BTreeSet<String> = BTreeSet::new();
            for usage in visitor.uses {
                let identity = format!("{}:{}", usage.class, usage.key);
                let Some(first) = seen.get(&identity) else {
                    seen.insert(identity, usage.fields);
                    continue;
                };
                if first == &usage.fields || !reported.insert(identity.clone()) {
                    continue;
                }
                let first_fields = join_fields(first);
                let later_fields = join_fields(&usage.fields);
                let location = location_for(ctx, source, usage.line, usage.column);
                let evidence = format!(
                    "storage key `{}` in {} storage is used for values with different field \
                     sets ({{{first_fields}}} and {{{later_fields}}})",
                    usage.key, usage.class
                );
                out.push(Finding::new(&METADATA, location, evidence));
            }
        }
    }
}

fn join_fields(fields: &BTreeSet<String>) -> String {
    fields.iter().cloned().collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_same_key_with_different_struct_fields() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn set_balance(env: Env, user: Address, amount: i128) {
                    env.storage()
                        .persistent()
                        .set(&DataKey::Balance(user.clone()), &Balance { amount });
                }

                pub fn set_balance_locked(env: Env, user: Address, amount: i128, unlock: u64) {
                    env.storage()
                        .persistent()
                        .set(&DataKey::Balance(user.clone()), &Balance { amount, unlock });
                }
            }
            "#,
            Box::new(DuplicateStorageKeyConstruction),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-046");
        assert!(findings[0].evidence.contains("DataKey :: Balance"));
        assert!(findings[0].evidence.contains("amount, unlock"));
    }

    #[test]
    fn does_not_flag_the_same_field_set() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn set_a(env: Env, user: Address) {
                    env.storage().persistent().set(&DataKey::Balance(user), &Balance { amount: 1 });
                }
                pub fn set_b(env: Env, user: Address) {
                    env.storage().persistent().set(&DataKey::Balance(user), &Balance { amount: 2 });
                }
            }
            "#,
            Box::new(DuplicateStorageKeyConstruction),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_different_keys() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn set_a(env: Env, user: Address) {
                    env.storage().persistent().set(&DataKey::Balance(user), &Balance { amount: 1 });
                }
                pub fn set_b(env: Env, user: Address) {
                    env.storage().persistent().set(&DataKey::Meta(user), &Meta { owner: 2 });
                }
            }
            "#,
            Box::new(DuplicateStorageKeyConstruction),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_ambiguous_non_struct_values() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn set_a(env: Env, user: Address, amount: i128) {
                    env.storage().persistent().set(&DataKey::Balance(user), &amount);
                }
                pub fn set_b(env: Env, user: Address, locked: bool) {
                    env.storage().persistent().set(&DataKey::Balance(user), &locked);
                }
            }
            "#,
            Box::new(DuplicateStorageKeyConstruction),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_struct_update_syntax() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn set_a(env: Env, user: Address, current: Balance) {
                    env.storage().persistent().set(&DataKey::Balance(user), &Balance { amount: 1, ..current });
                }
                pub fn set_b(env: Env, user: Address, current: Balance) {
                    env.storage().persistent().set(&DataKey::Balance(user), &Balance { amount: 1, unlock: 2, ..current });
                }
            }
            "#,
            Box::new(DuplicateStorageKeyConstruction),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn separates_storage_classes() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn set_a(env: Env, user: Address) {
                    env.storage().persistent().set(&DataKey::Balance(user), &Balance { amount: 1 });
                }
                pub fn set_b(env: Env, user: Address) {
                    env.storage().temporary().set(&DataKey::Balance(user), &Balance { amount: 1, unlock: 2 });
                }
            }
            "#,
            Box::new(DuplicateStorageKeyConstruction),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }
}
