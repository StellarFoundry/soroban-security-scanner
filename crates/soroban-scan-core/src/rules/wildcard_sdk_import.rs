//! SS-033: wildcard import from the Soroban SDK.
//!
//! `use soroban_sdk::*;` (or a nested glob such as
//! `use soroban_sdk::token::*;`) pulls every public item into scope. The import
//! hides which SDK APIs the contract actually relies on, makes deprecated or
//! unsafe APIs harder to review, and makes future static analysis less precise.
//!
//! This is an informational source-hygiene rule, not evidence of a
//! vulnerability. It only inspects `use` trees in parsed contract sources and
//! never expands macros or resolves modules.

use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::{Finding, SourceLocation};
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-033",
    title: "Wildcard import from the Soroban SDK",
    description: "A source file imports everything from `soroban_sdk` with a \
glob (`use soroban_sdk::*;` or a nested glob). Wildcard imports obscure which \
SDK items are used and can silently include deprecated or unsafe APIs when the \
SDK changes. This is a readability and reviewability signal, not proof of a \
security defect.",
    category: Category::Dependencies,
    default_severity: Severity::Low,
    default_confidence: Confidence::High,
    remediation: "Replace the glob with the specific `soroban_sdk` items the \
contract uses (for example `use soroban_sdk::{Address, Env};`). Nested module \
imports should likewise name each item instead of ending in `*`.",
    references: &[
        "https://doc.rust-lang.org/book/ch07-04-bringing-paths-into-scope-with-the-use-keyword.html",
        "https://developers.stellar.org/docs",
    ],
    deprecated: false,
};

/// Detects wildcard imports rooted at `soroban_sdk`.
pub struct WildcardSdkImport;

/// A glob found in a `use` tree, with its 1-based source position.
#[derive(Debug, Clone, PartialEq, Eq)]
struct GlobImport {
    path: String,
    line: usize,
    column: usize,
}

/// Collects every glob terminal in a `use` tree with its path prefix.
fn collect_globs(tree: &syn::UseTree, prefix: &mut Vec<String>, out: &mut Vec<String>) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_globs(&path.tree, prefix, out);
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            // `use soroban_sdk::{self, ...}` imports the module itself, not a glob.
            let _ = name;
        }
        syn::UseTree::Rename(rename) => {
            let _ = rename;
        }
        syn::UseTree::Glob(_) => {
            out.push(prefix.join("::"));
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_globs(item, prefix, out);
            }
        }
    }
}

fn glob_imports(item: &syn::ItemUse) -> Vec<String> {
    let mut prefix = Vec::new();
    let mut globs = Vec::new();
    collect_globs(&item.tree, &mut prefix, &mut globs);
    globs
}

struct UseVisitor {
    globs: Vec<GlobImport>,
}

impl<'ast> Visit<'ast> for UseVisitor {
    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        let start = node.span().start();
        for path in glob_imports(node) {
            if path == "soroban_sdk" || path.starts_with("soroban_sdk::") {
                self.globs.push(GlobImport {
                    path,
                    line: start.line,
                    column: start.column,
                });
            }
        }
        // Continue into inline modules so nested `use` statements are covered.
        visit::visit_item_use(self, node);
    }
}

impl Rule for WildcardSdkImport {
    fn metadata(&self) -> &RuleMetadata {
        &METADATA
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>, out: &mut Vec<Finding>) {
        for source in ctx.sources() {
            let Some(file) = &source.syntax else {
                continue;
            };
            let mut visitor = UseVisitor { globs: Vec::new() };
            visitor.visit_file(file);
            for glob in visitor.globs {
                let location = SourceLocation::with_column(
                    ctx.relative_path(&source.path),
                    glob.line,
                    glob.column,
                );
                let evidence = format!(
                    "wildcard import `use {}::*` hides which Soroban SDK items are used",
                    glob.path
                );
                out.push(Finding::new(&METADATA, location, evidence));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    fn code(body: &str) -> String {
        format!(
            "#[contract]\npub struct Contract;\n\n#[contractimpl]\nimpl Contract {{\n    pub fn ping() {{}}\n}}\n\n{body}"
        )
    }

    #[test]
    fn flags_a_root_glob_import() {
        let findings = scan_rule(&code("use soroban_sdk::*;"), Box::new(WildcardSdkImport));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-033");
        assert!(findings[0].evidence.contains("soroban_sdk"));
        assert_eq!(findings[0].line, 9);
    }

    #[test]
    fn flags_a_nested_glob_import() {
        let findings = scan_rule(
            &code("use soroban_sdk::token::*;"),
            Box::new(WildcardSdkImport),
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.contains("soroban_sdk::token"));
    }

    #[test]
    fn flags_a_glob_inside_a_group() {
        let findings = scan_rule(
            &code("use soroban_sdk::{Address, Env, *};"),
            Box::new(WildcardSdkImport),
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.contains("soroban_sdk"));
    }

    #[test]
    fn ignores_explicit_and_unrelated_imports() {
        for body in [
            "use soroban_sdk::{Address, Env, Symbol};",
            "use std::collections::*;",
            "use soroban_sdk::token::TokenClient;",
        ] {
            let findings = scan_rule(&code(body), Box::new(WildcardSdkImport));
            assert!(findings.is_empty(), "unexpected finding for {body}");
        }
    }
}
