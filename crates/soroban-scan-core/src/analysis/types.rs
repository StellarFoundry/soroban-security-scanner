//! Bounded diagnostics for type references the scanner cannot resolve.
//!
//! Type-aware rules rely on syntactically visible type names. When a name is
//! not owned by any `use` import, or a glob makes it ambiguous, those rules may
//! silently decline to fire. This module surfaces that limit as aggregated
//! `TYPE-001` diagnostics with the construct and span of the first occurrence.
//!
//! The pass is deliberately small: it inspects public `#[contractimpl]` entry
//! points (the same scope as the type-aware rules) and stops after a fixed
//! number of checks. It never echoes source text beyond the type identifier and
//! never guesses a resolution.

use std::collections::BTreeMap;
use std::path::Path;

use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::imports::{ImportMap, Resolution};
use crate::model::{Diagnostic, DiagnosticCode};
use crate::rules::util::{contract_entry_functions, ContractFn};
use crate::source::ParsedSource;

/// Maximum number of aggregated diagnostics emitted for one source file.
pub const MAX_TYPE_DIAGNOSTICS: usize = 8;
/// Maximum number of type constructs inspected per source file.
pub const MAX_TYPE_CHECKS: usize = 256;
/// Maximum length of a recorded type name.
pub const MAX_TYPE_NAME_LEN: usize = 64;

/// Types that need no import to resolve.
///
/// Includes Rust prelude types and the Soroban SDK types the scanner already
/// understands by name. Treating the latter as known keeps `TYPE-001` focused on
/// project-local names a type-aware rule could not reason about.
const BUILTIN_TYPES: &[&str] = &[
    "bool", "char", "str", "String", "Self", "Vec", "Option", "Result", "Box", "Rc", "Arc", "Cell",
    "RefCell", "usize", "isize", "u8", "u16", "u32", "u64", "u128", "u256", "i8", "i16", "i32",
    "i64", "i128", "i256", "f32", "f64", "Env", "Address", "Symbol", "Bytes", "BytesN", "Map",
    "Val", "I128", "U128", "I256", "U256",
];

/// Path roots that are always considered resolved.
const QUALIFIED_ROOTS: &[&str] = &["crate", "self", "super", "std", "core", "alloc"];

#[derive(Debug, Clone)]
struct FoundType {
    name: String,
    construct: &'static str,
    ambiguous: bool,
    line: usize,
    column: usize,
}

#[derive(Debug, Default)]
struct Group {
    count: usize,
    line: usize,
    column: usize,
}

/// Returns bounded `TYPE-001` diagnostics for unresolved type references in a
/// parsed source file.
///
/// `relative_path` is the scan-root-relative path used in diagnostics, so no
/// absolute path is exposed.
pub fn unresolved_type_diagnostics(source: &ParsedSource, relative_path: &Path) -> Vec<Diagnostic> {
    let Some(file) = &source.syntax else {
        return Vec::new();
    };
    let local_types = local_type_names(&file.items);
    let mut checks = 0usize;
    let mut found: Vec<FoundType> = Vec::new();

    for function in contract_entry_functions(file) {
        if !function.is_public {
            continue;
        }
        for (index, (_, type_text)) in function.param_types.iter().enumerate() {
            if checks >= MAX_TYPE_CHECKS {
                break;
            }
            checks += 1;
            let (line, column) = function
                .param_spans
                .get(index)
                .copied()
                .unwrap_or((function.line, function.column));
            scan_type_text(
                type_text,
                "parameter type",
                &source.imports,
                &local_types,
                line,
                column,
                &mut found,
            );
        }
        collect_block_types(
            &function,
            &source.imports,
            &local_types,
            &mut found,
            &mut checks,
        );
    }

    aggregate(found, relative_path)
}

fn collect_block_types(
    function: &ContractFn<'_>,
    imports: &ImportMap,
    local_types: &BTreeMap<String, ()>,
    out: &mut Vec<FoundType>,
    checks: &mut usize,
) {
    struct TypeVisitor<'a> {
        imports: &'a ImportMap,
        local_types: &'a BTreeMap<String, ()>,
        out: &'a mut Vec<FoundType>,
        checks: &'a mut usize,
    }

    impl TypeVisitor<'_> {
        fn scan(&mut self, ty: &syn::Type, construct: &'static str) {
            if *self.checks >= MAX_TYPE_CHECKS {
                return;
            }
            *self.checks += 1;
            scan_type(
                ty,
                construct,
                self.imports,
                self.local_types,
                None,
                self.out,
            );
        }
    }

    impl<'ast> Visit<'ast> for TypeVisitor<'_> {
        fn visit_local(&mut self, node: &'ast syn::Local) {
            if let syn::Pat::Type(typed) = &node.pat {
                self.scan(&typed.ty, "local type annotation");
            }
            visit::visit_local(self, node);
        }

        fn visit_expr_cast(&mut self, node: &'ast syn::ExprCast) {
            self.scan(&node.ty, "cast target");
            visit::visit_expr_cast(self, node);
        }
    }

    let mut visitor = TypeVisitor {
        imports,
        local_types,
        out,
        checks,
    };
    visitor.visit_block(function.block);
}

fn scan_type_text(
    type_text: &str,
    construct: &'static str,
    imports: &ImportMap,
    local_types: &BTreeMap<String, ()>,
    line: usize,
    column: usize,
    out: &mut Vec<FoundType>,
) {
    // Parameter types reach this module as rendered text. Parse them back into a
    // `syn::Type`; unparseable text is skipped rather than reported.
    let Ok(ty) = syn::parse_str::<syn::Type>(type_text) else {
        return;
    };
    scan_type(
        &ty,
        construct,
        imports,
        local_types,
        Some((line, column)),
        out,
    );
}

fn scan_type(
    ty: &syn::Type,
    construct: &'static str,
    imports: &ImportMap,
    local_types: &BTreeMap<String, ()>,
    span_override: Option<(usize, usize)>,
    out: &mut Vec<FoundType>,
) {
    struct PathVisitor<'a> {
        imports: &'a ImportMap,
        local_types: &'a BTreeMap<String, ()>,
        construct: &'static str,
        out: &'a mut Vec<FoundType>,
    }

    impl<'ast> Visit<'ast> for PathVisitor<'_> {
        fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
            if node.qself.is_none() {
                if let Some(first) = node.path.segments.first() {
                    let name = first.ident.to_string();
                    if !QUALIFIED_ROOTS.contains(&name.as_str())
                        && !is_builtin(&name)
                        && !self.local_types.contains_key(&name)
                        && !is_conventional_generic(&name)
                    {
                        match self.imports.resolve(&name) {
                            Resolution::Resolved(_) => {}
                            Resolution::Ambiguous(_) => self.out.push(FoundType {
                                name: truncate(&name, MAX_TYPE_NAME_LEN),
                                construct: self.construct,
                                ambiguous: true,
                                line: 0,
                                column: 0,
                            }),
                            Resolution::Unresolved => self.out.push(FoundType {
                                name: truncate(&name, MAX_TYPE_NAME_LEN),
                                construct: self.construct,
                                ambiguous: false,
                                line: 0,
                                column: 0,
                            }),
                        }
                    }
                }
            }
            visit::visit_type_path(self, node);
        }
    }

    let span = span_override.unwrap_or_else(|| {
        let start = ty.span().start();
        (start.line, start.column + 1)
    });
    let before = out.len();
    let mut visitor = PathVisitor {
        imports,
        local_types,
        construct,
        out,
    };
    visitor.visit_type(ty);
    // Attach the precise span of this type node to everything it produced.
    for found in out[before..].iter_mut() {
        found.line = span.0;
        found.column = span.1;
    }
}

fn is_builtin(name: &str) -> bool {
    BUILTIN_TYPES.contains(&name)
}

/// Single upper-case letters (optionally numbered) are conventionally generic
/// parameters. Without a type checker this is the conservative way to avoid
/// flagging `T`/`K`/`V` while still reporting unresolved project types.
fn is_conventional_generic(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_uppercase())
        && chars.all(|character| character.is_ascii_digit())
}

fn local_type_names(items: &[syn::Item]) -> BTreeMap<String, ()> {
    let mut names = BTreeMap::new();
    collect_local_types(items, &mut names);
    names
}

fn collect_local_types(items: &[syn::Item], out: &mut BTreeMap<String, ()>) {
    for item in items {
        match item {
            syn::Item::Struct(item) => {
                out.insert(item.ident.to_string(), ());
            }
            syn::Item::Enum(item) => {
                out.insert(item.ident.to_string(), ());
            }
            syn::Item::Union(item) => {
                out.insert(item.ident.to_string(), ());
            }
            syn::Item::Type(item) => {
                out.insert(item.ident.to_string(), ());
            }
            syn::Item::Trait(item) => {
                out.insert(item.ident.to_string(), ());
            }
            syn::Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    collect_local_types(nested, out);
                }
            }
            _ => {}
        }
    }
}

fn aggregate(found: Vec<FoundType>, relative_path: &Path) -> Vec<Diagnostic> {
    if found.is_empty() {
        return Vec::new();
    }
    let mut groups: BTreeMap<(String, &'static str, bool), Group> = BTreeMap::new();
    for item in found {
        let group = groups
            .entry((item.name, item.construct, item.ambiguous))
            .or_default();
        group.count += 1;
        if group.line == 0 || (item.line, item.column) < (group.line, group.column) {
            group.line = item.line;
            group.column = item.column;
        }
    }

    let total = groups.len();
    let limit = if total > MAX_TYPE_DIAGNOSTICS {
        MAX_TYPE_DIAGNOSTICS - 1
    } else {
        MAX_TYPE_DIAGNOSTICS
    };
    let mut entries: Vec<_> = groups.into_iter().collect();
    entries.sort_by(|(a_key, a), (b_key, b)| {
        (a.line, a.column, a_key.0.as_str(), a_key.1).cmp(&(
            b.line,
            b.column,
            b_key.0.as_str(),
            b_key.1,
        ))
    });

    let mut diagnostics = Vec::new();
    for ((name, construct, ambiguous), group) in entries.into_iter().take(limit) {
        let detail = if ambiguous { "ambiguous" } else { "unresolved" };
        let occurrences = if group.count == 1 {
            String::new()
        } else {
            format!(" ({} occurrences)", group.count)
        };
        let message = format!(
            "{detail} type `{name}` in {construct}{occurrences}; \
             type-aware rules may not apply"
        );
        diagnostics.push(
            Diagnostic::warning(
                DiagnosticCode::UnresolvedType,
                message,
                Some(relative_path.to_path_buf()),
            )
            .with_span(group.line, group.column),
        );
    }
    if total > limit {
        diagnostics.push(
            Diagnostic::info(
                DiagnosticCode::UnresolvedType,
                format!(
                    "{} additional unresolved type group(s) omitted",
                    total - limit
                ),
                Some(relative_path.to_path_buf()),
            )
            .with_span(1, 1),
        );
    }
    diagnostics
}

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
    use std::path::PathBuf;

    fn parsed(path: &str, source: &str) -> ParsedSource {
        crate::source::parse_source(Path::new(path), Path::new("."), source)
    }

    fn diagnostics(source: &str) -> Vec<Diagnostic> {
        unresolved_type_diagnostics(&parsed("src/lib.rs", source), Path::new("src/lib.rs"))
    }

    #[test]
    fn reports_unresolved_parameter_and_local_types() {
        let found = diagnostics(
            r#"
            use soroban_sdk::{contractimpl, Env};

            #[contractimpl]
            impl C {
                pub fn set(env: Env, amount: Amount) {
                    let limit: Limit = amount;
                    let _ = limit;
                }
            }
            "#,
        );
        assert!(found.iter().any(|diagnostic| {
            diagnostic.code == DiagnosticCode::UnresolvedType
                && diagnostic.message.contains("unresolved type `Amount`")
                && diagnostic.message.contains("parameter type")
        }));
        assert!(found.iter().any(|diagnostic| {
            diagnostic.message.contains("unresolved type `Limit`")
                && diagnostic.message.contains("local type annotation")
        }));
    }

    #[test]
    fn aggregates_repeated_types_and_reports_the_first_span() {
        let found = diagnostics(
            r#"
            use soroban_sdk::{contractimpl, Env};

            #[contractimpl]
            impl C {
                pub fn set(env: Env) {
                    let a: Mystery = 1;
                    let b: Mystery = 2;
                    let _ = (a, b);
                }
            }
            "#,
        );
        let mystery: Vec<_> = found
            .iter()
            .filter(|diagnostic| diagnostic.message.contains("Mystery"))
            .collect();
        assert_eq!(mystery.len(), 1);
        assert!(mystery[0].message.contains("2 occurrences"));
        assert_eq!(mystery[0].line, Some(7));
        assert!(mystery[0].column.unwrap_or(0) > 0);
        assert_eq!(mystery[0].path, Some(PathBuf::from("src/lib.rs")));
    }

    #[test]
    fn reports_cast_target_span_accurately() {
        let found = diagnostics(
            r#"
            use soroban_sdk::{contractimpl, Env};

            #[contractimpl]
            impl C {
                pub fn set(env: Env, value: u32) {
                    let _ = value as Target;
                }
            }
            "#,
        );
        let target: Vec<_> = found
            .iter()
            .filter(|diagnostic| diagnostic.message.contains("`Target`"))
            .collect();
        assert_eq!(target.len(), 1);
        assert_eq!(target[0].line, Some(7));
        assert!(target[0].column.unwrap_or(0) > 0);
        assert!(target[0].message.contains("cast target"));
    }

    #[test]
    fn ambiguous_glob_type_is_reported_as_ambiguous() {
        let found = diagnostics(
            r#"
            use soroban_sdk::*;

            #[contractimpl]
            impl C {
                pub fn set(env: Env, amount: Token) {
                    let _ = amount;
                }
            }
            "#,
        );
        assert!(
            found
                .iter()
                .any(|diagnostic| diagnostic.message.contains("ambiguous type `Token`")),
            "got: {found:#?}"
        );
    }

    #[test]
    fn ignores_builtins_locals_generics_and_qualified_paths() {
        let found = diagnostics(
            r#"
            use soroban_sdk::{contractimpl, Env};

            struct Local;

            #[contractimpl]
            impl C {
                pub fn set(env: Env, count: u32, local: Local, optional: Option<Local>) -> Vec<u8> {
                    let _ = (count, local, optional);
                    let _: crate::Local = Local;
                    Vec::new()
                }
            }
            "#,
        );
        assert!(found.is_empty(), "got: {found:#?}");
    }

    #[test]
    fn output_is_bounded() {
        let mut body = String::new();
        for index in 0..(MAX_TYPE_DIAGNOSTICS + 4) {
            body.push_str(&format!(
                "                    let value_{index}: Missing{index} = 1;\n"
            ));
        }
        let source = format!(
            "use soroban_sdk::{{contractimpl, Env}};\n\n\
             #[contractimpl]\n\
             impl C {{\n\
                 pub fn set(env: Env) {{\n{body}                }}\n\
             }}\n"
        );
        let found = diagnostics(&source);
        assert!(found.len() <= MAX_TYPE_DIAGNOSTICS, "got {}", found.len());
        assert!(found
            .iter()
            .any(|diagnostic| diagnostic.message.contains("omitted")));
    }
}
