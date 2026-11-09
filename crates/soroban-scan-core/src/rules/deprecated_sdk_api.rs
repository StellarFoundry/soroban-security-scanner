//! SS-036: deprecated Soroban SDK API usage in contract source code.

use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{ExprCall, ExprMethodCall};

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::deprecated_sdk::parse_version;
use super::util::location_for;

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-036",
    title: "Deprecated Soroban SDK API usage",
    description: "Contract source code invokes a Soroban SDK method or associated \
function that was deprecated or replaced across SDK releases (such as \
`storage().bump`, `env.current_contract_id()`, `Address::from_contract_id`, \
`deployer().with_source_account`, `deployer().deploy`, or `env.register_contract`). \
Relying on deprecated SDK APIs risks build failures on SDK upgrades and can mask \
stale security assumptions around TTL extension, contract identity, or constructor \
initialization.",
    category: Category::Dependencies,
    default_severity: Severity::Low,
    default_confidence: Confidence::Medium,
    remediation: "Replace deprecated Soroban SDK calls with their modern \
equivalents documented for your target SDK release (for example, use \
`extend_ttl(threshold, extend_to)` instead of `bump`, \
`env.current_contract_address()` instead of `env.current_contract_id()`, \
`deployer().deploy_v2(...)` instead of `deploy(...)`, and `env.register(...)` \
instead of `env.register_contract(...)`).",
    references: &[
        "https://developers.stellar.org/docs/build/smart-contracts",
        "https://docs.rs/soroban-sdk/latest/soroban_sdk/",
    ],
};

/// How a deprecated API entry is matched against the Rust AST.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiMatchKind {
    /// Method call whose receiver text (case-insensitive, whitespace-stripped)
    /// contains the required substring.
    MethodWithReceiver {
        method: &'static str,
        receiver_contains: &'static str,
    },
    /// Method call matched by name on an `Env`-like receiver (`env` or `e`).
    EnvMethod { method: &'static str },
    /// Associated function / path call whose path ends with `type_segment::fn_name`.
    AssociatedFunction {
        type_segment: &'static str,
        function: &'static str,
    },
}

/// Versioned entry in the deprecated Soroban SDK API table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeprecatedSdkApi {
    /// Human-readable canonical API path.
    pub api: &'static str,
    /// AST matching rule.
    pub kind: ApiMatchKind,
    /// First `soroban-sdk` release in which the API was deprecated or replaced.
    pub deprecated_since: &'static str,
    /// Recommended modern replacement API.
    pub replacement: &'static str,
    /// Security or upgrade rationale.
    pub rationale: &'static str,
}

/// Data-driven table of deprecated Soroban SDK APIs across SDK versions.
pub const DEPRECATED_SDK_APIS: &[DeprecatedSdkApi] = &[
    DeprecatedSdkApi {
        api: "storage().<tier>().bump",
        kind: ApiMatchKind::MethodWithReceiver {
            method: "bump",
            receiver_contains: "storage(",
        },
        deprecated_since: "20.0.0",
        replacement: "storage().<tier>().extend_ttl(threshold, extend_to)",
        rationale: "Replaced by `extend_ttl` with explicit threshold and extension ledgers to prevent silent TTL under-extension.",
    },
    DeprecatedSdkApi {
        api: "Env::current_contract_id",
        kind: ApiMatchKind::EnvMethod {
            method: "current_contract_id",
        },
        deprecated_since: "20.0.0",
        replacement: "Env::current_contract_address",
        rationale: "Raw `BytesN<32>` contract identifiers were replaced by unified `Address` values.",
    },
    DeprecatedSdkApi {
        api: "Address::from_contract_id",
        kind: ApiMatchKind::AssociatedFunction {
            type_segment: "Address",
            function: "from_contract_id",
        },
        deprecated_since: "20.0.0",
        replacement: "Address::from_str(&env, ...) or direct Address parameters",
        rationale: "Legacy contract ID conversion was removed when `Address` unified account and contract identities.",
    },
    DeprecatedSdkApi {
        api: "Deployer::with_source_account",
        kind: ApiMatchKind::MethodWithReceiver {
            method: "with_source_account",
            receiver_contains: "deployer(",
        },
        deprecated_since: "20.0.0",
        replacement: "Deployer::with_address(address, salt)",
        rationale: "Deployer source-account scoping was generalized to any `Address` via `with_address`.",
    },
    DeprecatedSdkApi {
        api: "Env::register_contract",
        kind: ApiMatchKind::EnvMethod {
            method: "register_contract",
        },
        deprecated_since: "22.0.0",
        replacement: "Env::register(contract, constructor_args)",
        rationale: "`register_contract` bypasses `__constructor` argument passing introduced in SDK 22.",
    },
    DeprecatedSdkApi {
        api: "Env::register_contract_wasm",
        kind: ApiMatchKind::EnvMethod {
            method: "register_contract_wasm",
        },
        deprecated_since: "22.0.0",
        replacement: "Env::register(wasm, constructor_args)",
        rationale: "`register_contract_wasm` was superseded by `Env::register` with constructor support in SDK 22.",
    },
    DeprecatedSdkApi {
        api: "DeployerWithAddress::deploy",
        kind: ApiMatchKind::MethodWithReceiver {
            method: "deploy",
            receiver_contains: "deployer(",
        },
        deprecated_since: "22.0.0",
        replacement: "DeployerWithAddress::deploy_v2(wasm_hash, constructor_args)",
        rationale: "`deploy` does not pass contract constructor arguments; `deploy_v2` is required from SDK 22 onward.",
    },
];

/// Detects usage of deprecated Soroban SDK APIs in contract source files.
pub struct DeprecatedSdkApiUsage;

impl Rule for DeprecatedSdkApiUsage {
    fn metadata(&self) -> &RuleMetadata {
        &METADATA
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>, out: &mut Vec<Finding>) {
        if !ctx.is_confirmed_soroban() {
            return;
        }
        let detected_sdk_version = detect_project_sdk_version(ctx);

        for source in ctx.sources() {
            let Some(file) = &source.syntax else {
                continue;
            };
            let mut visitor = DeprecatedApiVisitor {
                detected_sdk_version,
                matches: Vec::new(),
            };
            visitor.visit_file(file);

            for hit in visitor.matches {
                let location = location_for(ctx, source, hit.line, hit.column);
                let evidence = format!(
                    "deprecated SDK API `{}` (deprecated since soroban-sdk {}, use `{}` instead): {}",
                    hit.entry.api, hit.entry.deprecated_since, hit.entry.replacement, hit.snippet
                );
                out.push(Finding::new(&METADATA, location, evidence));
            }
        }
    }
}

struct ApiHit {
    entry: &'static DeprecatedSdkApi,
    line: usize,
    column: usize,
    snippet: String,
}

struct DeprecatedApiVisitor {
    detected_sdk_version: Option<(u64, u64, u64)>,
    matches: Vec<ApiHit>,
}

impl DeprecatedApiVisitor {
    fn is_entry_applicable(&self, entry: &DeprecatedSdkApi) -> bool {
        let Some(project_ver) = self.detected_sdk_version else {
            return true;
        };
        let Some(dep_ver) = parse_version(entry.deprecated_since) else {
            return true;
        };
        project_ver >= dep_ver
    }
}

impl<'ast> Visit<'ast> for DeprecatedApiVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method_name = node.method.to_string();
        let receiver = &node.receiver;
        let receiver_raw = quote::quote!(#receiver).to_string();
        let receiver_compact = receiver_raw.replace(' ', "").to_ascii_lowercase();

        for entry in DEPRECATED_SDK_APIS {
            if !self.is_entry_applicable(entry) {
                continue;
            }
            let matched = match entry.kind {
                ApiMatchKind::MethodWithReceiver {
                    method,
                    receiver_contains,
                } => {
                    method_name == method
                        && receiver_compact.contains(&receiver_contains.to_ascii_lowercase())
                }
                ApiMatchKind::EnvMethod { method } => {
                    method_name == method && is_env_like_receiver(&receiver_compact)
                }
                ApiMatchKind::AssociatedFunction { .. } => false,
            };

            if matched {
                let span = node.method.span();
                let start = span.start();
                self.matches.push(ApiHit {
                    entry,
                    line: start.line.max(1),
                    column: start.column + 1,
                    snippet: compact_snippet(&quote::quote!(#node).to_string()),
                });
                break;
            }
        }

        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let syn::Expr::Path(expr_path) = &*node.func {
            let segments: Vec<String> = expr_path
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            if segments.len() >= 2 {
                let func_name = &segments[segments.len() - 1];
                let type_seg = &segments[segments.len() - 2];
                for entry in DEPRECATED_SDK_APIS {
                    if !self.is_entry_applicable(entry) {
                        continue;
                    }
                    if let ApiMatchKind::AssociatedFunction {
                        type_segment,
                        function,
                    } = entry.kind
                    {
                        if type_seg == type_segment && func_name == function {
                            let span = expr_path.span();
                            let start = span.start();
                            self.matches.push(ApiHit {
                                entry,
                                line: start.line.max(1),
                                column: start.column + 1,
                                snippet: compact_snippet(&quote::quote!(#node).to_string()),
                            });
                            break;
                        }
                    }
                }
            }
        }

        visit::visit_expr_call(self, node);
    }
}

fn is_env_like_receiver(receiver_compact: &str) -> bool {
    let trimmed = receiver_compact.trim_start_matches('&');
    trimmed == "env" || trimmed == "e" || trimmed.ends_with(".env") || trimmed.ends_with("env()")
}

fn compact_snippet(raw: &str) -> String {
    let collapsed: String = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.len() > 120 {
        format!("{}...", &collapsed[..117])
    } else {
        collapsed
    }
}

fn detect_project_sdk_version(ctx: &AnalysisContext<'_>) -> Option<(u64, u64, u64)> {
    let mut best: Option<(u64, u64, u64)> = None;
    for manifest in &ctx.project().manifests {
        let Some(dep) = manifest.dependency("soroban-sdk") else {
            continue;
        };
        if let Some(req) = dep.version.as_deref() {
            if let Some(ver) = parse_version(req) {
                best = Some(match best {
                    Some(current) if current >= ver => current,
                    _ => ver,
                });
            }
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn table_entries_have_valid_semver_and_metadata() {
        assert!(!DEPRECATED_SDK_APIS.is_empty());
        for entry in DEPRECATED_SDK_APIS {
            assert!(!entry.api.is_empty());
            assert!(
                parse_version(entry.deprecated_since).is_some(),
                "invalid semver in table: {}",
                entry.deprecated_since
            );
            assert!(!entry.replacement.is_empty());
            assert!(!entry.rationale.is_empty());
        }
    }

    #[test]
    fn flags_storage_bump() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn touch(env: Env) {
                    env.storage().persistent().bump(&symbol_short!("KEY"), 100, 1000);
                }
            }
            "#,
            Box::new(DeprecatedSdkApiUsage),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-036");
        assert!(findings[0].evidence.contains("storage().<tier>().bump"));
        assert!(findings[0].evidence.contains("extend_ttl"));
    }

    #[test]
    fn flags_current_contract_id_and_from_contract_id() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Legacy {
                pub fn me(env: Env, raw_id: BytesN<32>) -> Address {
                    let _self_id = env.current_contract_id();
                    Address::from_contract_id(&env, &raw_id)
                }
            }
            "#,
            Box::new(DeprecatedSdkApiUsage),
        );
        assert_eq!(findings.len(), 2);
        assert!(findings
            .iter()
            .any(|f| f.evidence.contains("Env::current_contract_id")));
        assert!(findings
            .iter()
            .any(|f| f.evidence.contains("Address::from_contract_id")));
    }

    #[test]
    fn flags_deprecated_register_contract_and_deployer_apis() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Factory {
                pub fn spawn(env: Env, user: Address, salt: BytesN<32>, wasm: BytesN<32>) {
                    let _ = env.deployer().with_source_account(&user);
                    let _ = env.deployer().with_current_contract(salt).deploy(wasm);
                    let _ = env.register_contract(None, Factory);
                }
            }
            "#,
            Box::new(DeprecatedSdkApiUsage),
        );
        assert_eq!(findings.len(), 3);
    }

    #[test]
    fn does_not_flag_modern_sdk_equivalents() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Modern {
                pub fn run(env: Env, admin: Address, salt: BytesN<32>, wasm: BytesN<32>) -> Address {
                    admin.require_auth();
                    let key = symbol_short!("KEY");
                    env.storage().persistent().extend_ttl(&key, 100, 1000);
                    let _me = env.current_contract_address();
                    env.deployer().with_address(admin, salt).deploy_v2(wasm, ())
                }
            }
            "#,
            Box::new(DeprecatedSdkApiUsage),
        );
        assert!(findings.is_empty());
    }
}
