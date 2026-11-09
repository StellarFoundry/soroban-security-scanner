//! SS-024: missing `#[contracttype]` on a boundary struct or enum.

use std::collections::BTreeMap;

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;
use crate::source::{ItemKind, ItemSummary};

use super::util::location_for;

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-024",
    title: "Missing #[contracttype] on boundary struct or enum",
    description: "A user-defined `struct` or `enum` appears in the parameter or \
return type of a public `#[contractimpl]` entry point, or in a storage write, \
without being annotated with `#[contracttype]` or `#[contracterror]`. Types \
that cross the Soroban host boundary without `#[contracttype]` lack generated \
`Val` conversion implementations and fail host serialization.",
    category: Category::Configuration,
    default_severity: Severity::Medium,
    default_confidence: Confidence::High,
    remediation: "Annotate every custom struct or enum that crosses the contract \
boundary or is persisted in contract storage with `#[contracttype]` (or \
`#[contracterror]` for error enums).",
    references: &["https://developers.stellar.org/docs/learn/encyclopedia/contract-development/types/custom-types"],
};

/// Detects structs and enums used in contract entry point signatures without `#[contracttype]`.
pub struct MissingContracttypeBoundary;

fn has_soroban_type_attr(item: &ItemSummary) -> bool {
    item.attributes.iter().any(|attr| {
        let last = attr.rsplit("::").next().unwrap_or(attr.as_str());
        matches!(
            last,
            "contract" | "contracttype" | "contracterror" | "contractclient"
        )
    })
}

fn type_mentions_ident(rendered_type: &str, ident: &str) -> bool {
    rendered_type
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|token| token == ident)
}

impl Rule for MissingContracttypeBoundary {
    fn metadata(&self) -> &RuleMetadata {
        &METADATA
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>, out: &mut Vec<Finding>) {
        if !ctx.is_confirmed_soroban() {
            return;
        }
        for source in ctx.sources() {
            let mut unannotated: BTreeMap<&str, &ItemSummary> = BTreeMap::new();
            for item in &source.items {
                if matches!(item.kind, ItemKind::Struct | ItemKind::Enum)
                    && !has_soroban_type_attr(item)
                {
                    unannotated.entry(item.name.as_str()).or_insert(item);
                }
            }
            if unannotated.is_empty() {
                continue;
            }
            for func in source.contract_entry_points() {
                for (type_name, item) in &unannotated {
                    let used_in_params = func
                        .params
                        .iter()
                        .any(|p| type_mentions_ident(&p.ty, type_name));
                    let used_in_return = func
                        .return_type
                        .as_deref()
                        .is_some_and(|ret| type_mentions_ident(ret, type_name));
                    if used_in_params || used_in_return {
                        let location = location_for(ctx, source, item.line, item.column);
                        let evidence = format!(
                            "{} `{}` used in entry point `{}` without `#[contracttype]`",
                            item.kind.as_str(),
                            item.name,
                            func.name
                        );
                        out.push(Finding::new(&METADATA, location, evidence));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_unannotated_struct_in_entry_point() {
        let findings = scan_rule(
            r#"
            #[derive(Clone)]
            pub struct TransferParams {
                pub amount: i128,
            }

            #[contractimpl]
            impl Token {
                pub fn transfer(env: Env, caller: Address, params: TransferParams) {
                    caller.require_auth();
                }
            }
            "#,
            Box::new(MissingContracttypeBoundary),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-024");
    }

    #[test]
    fn does_not_flag_contracttype_or_contracterror() {
        let findings = scan_rule(
            r#"
            #[contracttype]
            #[derive(Clone)]
            pub struct TransferParams {
                pub amount: i128,
            }

            #[contracterror]
            #[derive(Copy, Clone, Eq, PartialEq, Debug)]
            pub enum Error {
                Unauthorized = 1,
            }

            #[contractimpl]
            impl Token {
                pub fn transfer(env: Env, caller: Address, params: TransferParams) -> Result<(), Error> {
                    caller.require_auth();
                    Ok(())
                }
            }
            "#,
            Box::new(MissingContracttypeBoundary),
        );
        assert!(findings.is_empty());
    }
}
