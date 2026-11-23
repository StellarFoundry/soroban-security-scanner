//! SS-024: missing `#[contracttype]` on boundary types.

use std::collections::{BTreeMap, BTreeSet};

use quote::ToTokens;

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, location_for};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-024",
    title: "Missing contracttype on boundary types",
    description: "An entry point accepts or returns a local struct or enum that \
is not annotated with `#[contracttype]`. Soroban requires boundary types to be \
XDR-serializable; a missing attribute usually fails at runtime (or when the \
contract is invoked) rather than at compile time, so it is easy to miss in \
review.",
    category: Category::Configuration,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Medium,
    remediation: "Annotate every local struct and enum used in a public entry \
point signature with `#[contracttype]` (and derive the required traits), or \
replace it with an SDK type such as `Address`, `Bytes`, or a primitive.",
    references: &["https://developers.stellar.org/docs/learn/encyclopedia/contract-development/types/custom-types"],
};

/// Detects boundary types without `#[contracttype]`.
pub struct MissingContracttypeOnBoundaryTypes;

impl Rule for MissingContracttypeOnBoundaryTypes {
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
            let mut declared: BTreeSet<String> = BTreeSet::new();
            for item in &file.items {
                match item {
                    syn::Item::Struct(item) => {
                        declared.insert(item.ident.to_string());
                    }
                    syn::Item::Enum(item) => {
                        declared.insert(item.ident.to_string());
                    }
                    _ => {}
                }
            }
            // `contract_types` only contains annotated types, so it is the
            // authoritative set of boundary types that already have
            // `#[contracttype]` or `#[contracterror]`.
            let typed: BTreeSet<String> = source
                .contract_types
                .iter()
                .map(|item| item.name.clone())
                .collect();
            let untyped: BTreeSet<String> = declared.difference(&typed).cloned().collect();
            if untyped.is_empty() {
                continue;
            }

            let return_types = local_return_types(file);
            for func in contract_entry_functions(file) {
                if !func.is_public {
                    continue;
                }
                let mut problems = Vec::new();
                for (parameter, ty) in &func.param_types {
                    if let Some(name) = mentions_untyped(ty, &untyped) {
                        problems.push(format!("parameter `{parameter}` uses `{name}`"));
                    }
                }
                if let Some(return_type) = return_types.get(&func.name) {
                    if let Some(name) = mentions_untyped(return_type, &untyped) {
                        problems.push(format!("returns `{name}`"));
                    }
                }
                if !problems.is_empty() {
                    let location = location_for(ctx, source, func.line, func.column);
                    let evidence = format!(
                        "entry point `{}` uses local types without #[contracttype]: {}",
                        func.name,
                        problems.join("; ")
                    );
                    out.push(Finding::new(&METADATA, location, evidence));
                }
            }
        }
    }
}

fn local_return_types(file: &syn::File) -> BTreeMap<String, String> {
    let mut return_types = BTreeMap::new();
    for item in &file.items {
        let syn::Item::Impl(imp) = item else {
            continue;
        };
        for impl_item in &imp.items {
            let syn::ImplItem::Fn(function) = impl_item else {
                continue;
            };
            if let syn::ReturnType::Type(_, ty) = &function.sig.output {
                return_types.insert(
                    function.sig.ident.to_string(),
                    ty.to_token_stream().to_string(),
                );
            }
        }
    }
    return_types
}

fn mentions_untyped(ty: &str, untyped: &BTreeSet<String>) -> Option<String> {
    let tokens: BTreeSet<&str> = ty
        .split(|character: char| !(character.is_alphanumeric() || character == '_'))
        .filter(|token| !token.is_empty())
        .collect();
    untyped
        .iter()
        .find(|name| tokens.contains(name.as_str()))
        .map(|name| (*name).clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_untyped_parameter_and_return() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn store(env: Env, value: Payload) -> Receipt {
                    let _ = (&env, &value);
                    Receipt { ok: true }
                }
            }
            pub struct Payload { pub amount: i128 }
            pub struct Receipt { pub ok: bool }
            "#,
            Box::new(MissingContracttypeOnBoundaryTypes),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-024");
        assert!(findings[0].evidence.contains("parameter"));
        assert!(findings[0].evidence.contains("returns"));
    }

    #[test]
    fn does_not_flag_contracttype_types() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn store(env: Env, value: Payload) {
                    let _ = (&env, &value);
                }
            }
            #[contracttype]
            pub struct Payload { pub amount: i128 }
            "#,
            Box::new(MissingContracttypeOnBoundaryTypes),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_sdk_and_primitive_types() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn transfer(env: Env, from: Address, amount: i128) -> bool {
                    let _ = (&env, &from, &amount);
                    true
                }
            }
            "#,
            Box::new(MissingContracttypeOnBoundaryTypes),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_private_helpers() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn entry(env: Env) { let _ = &env; }
                fn helper(value: Payload) { let _ = &value; }
            }
            pub struct Payload { pub amount: i128 }
            "#,
            Box::new(MissingContracttypeOnBoundaryTypes),
        );
        assert!(findings.is_empty());
    }
}
