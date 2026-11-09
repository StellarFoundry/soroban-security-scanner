//! Security rule scaffolding (`cargo xtask rule`).
//!
//! Generates a detector module, corpus fixtures (`positive.rs`, `negative.rs`,
//! `negative2.rs`, `negative3.rs`), detector documentation stub, and registration
//! lines in `crates/soroban-scan-core/src/rules/mod.rs`.

use std::fs;
use std::path::{Component, Path, PathBuf};

/// Options for scaffolding a new security rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleScaffoldOptions {
    /// Stable rule id (`SS-###`).
    pub id: String,
    /// Short human-readable title.
    pub title: String,
    /// Optional snake_case Rust module name (derived from title if omitted).
    pub module: Option<String>,
    /// Rule category (defaults to `authorization`).
    pub category: String,
    /// Default severity (defaults to `medium`).
    pub severity: String,
    /// Default confidence (defaults to `medium`).
    pub confidence: String,
    /// Overwrite scaffold files if they already exist.
    pub force: bool,
}

/// Paths written by [`scaffold`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaffoldedRule {
    /// Rule module file (`crates/soroban-scan-core/src/rules/<module>.rs`).
    pub module_file: PathBuf,
    /// Registration file (`crates/soroban-scan-core/src/rules/mod.rs`).
    pub rules_mod_file: PathBuf,
    /// Detector documentation (`docs/rules/detectors/<ID>.md`).
    pub doc_file: PathBuf,
    /// Corpus fixture directory (`fixtures/corpus/<ID>`).
    pub corpus_dir: PathBuf,
}

/// Scaffolds a new security rule under `root`.
///
/// Refuses to overwrite any existing file unless `options.force` is true, and
/// rejects any input that could escape `root`.
pub fn scaffold(root: &Path, options: &RuleScaffoldOptions) -> Result<ScaffoldedRule, String> {
    if !root.is_dir() {
        return Err(format!(
            "repository root is not a directory: {}",
            root.display()
        ));
    }

    let id = validate_rule_id(&options.id)?;
    let title = validate_title(&options.title)?;
    let module_name = match &options.module {
        Some(custom) => validate_module_name(custom)?,
        None => derive_module_name(&title, &id)?,
    };
    let (category_variant, category_slug) = parse_category(&options.category)?;
    let (severity_variant, severity_slug) = parse_severity(&options.severity)?;
    let (confidence_variant, confidence_slug) = parse_confidence(&options.confidence)?;
    let struct_name = format!("{}Rule", to_pascal_case(&module_name));

    let rel_module = PathBuf::from("crates")
        .join("soroban-scan-core")
        .join("src")
        .join("rules")
        .join(format!("{module_name}.rs"));
    let rel_rules_mod = PathBuf::from("crates")
        .join("soroban-scan-core")
        .join("src")
        .join("rules")
        .join("mod.rs");
    let rel_doc = PathBuf::from("docs")
        .join("rules")
        .join("detectors")
        .join(format!("{id}.md"));
    let rel_corpus = PathBuf::from("fixtures").join("corpus").join(&id);

    let module_file = safe_join(root, &rel_module)?;
    let rules_mod_file = safe_join(root, &rel_rules_mod)?;
    let doc_file = safe_join(root, &rel_doc)?;
    let corpus_dir = safe_join(root, &rel_corpus)?;

    let fixture_files = [
        corpus_dir.join("positive.rs"),
        corpus_dir.join("negative.rs"),
        corpus_dir.join("negative2.rs"),
        corpus_dir.join("negative3.rs"),
    ];

    if !options.force {
        for target in [&module_file, &doc_file]
            .into_iter()
            .chain(fixture_files.iter())
        {
            if target.exists() {
                return Err(format!(
                    "refusing to overwrite existing file: {} (pass --force to overwrite)",
                    target.display()
                ));
            }
        }
        if rules_mod_file.exists() {
            let existing_mod = fs::read_to_string(&rules_mod_file)
                .map_err(|err| format!("failed to read {}: {err}", rules_mod_file.display()))?;
            if existing_mod.contains(&format!("pub mod {module_name};"))
                || existing_mod.contains(&format!("{module_name}::{struct_name}"))
            {
                return Err(format!(
                    "rule module '{module_name}' is already registered in {}",
                    rules_mod_file.display()
                ));
            }
        }
    }

    let description = format!(
        "{title} in a Soroban contract entry point can undermine contract invariants and security."
    );
    let escaped_title = title.replace('\\', "\\\\").replace('"', "\\\"");
    let escaped_desc = description.replace('\\', "\\\\").replace('"', "\\\"");

    let module_source = format!(
        "//! {id} — {title}.\n\
         \n\
         use crate::category::Category;\n\
         use crate::confidence::Confidence;\n\
         use crate::context::AnalysisContext;\n\
         use crate::finding::Finding;\n\
         use crate::rule::{{Rule, RuleMetadata}};\n\
         use crate::severity::Severity;\n\
         \n\
         /// Metadata for {id}.\n\
         pub const METADATA: RuleMetadata = RuleMetadata {{\n\
         \x20   id: \"{id}\",\n\
         \x20   title: \"{escaped_title}\",\n\
         \x20   description: \"{escaped_desc}\",\n\
         \x20   category: Category::{category_variant},\n\
         \x20   default_severity: Severity::{severity_variant},\n\
         \x20   default_confidence: Confidence::{confidence_variant},\n\
         \x20   remediation: \"Review the flagged construct and enforce explicit validation or authorization before continuing.\",\n\
         \x20   references: &[\"https://developers.stellar.org/docs/build/smart-contracts\"],\n\
         }};\n\
         \n\
         /// Detector for {id}.\n\
         pub struct {struct_name};\n\
         \n\
         impl Rule for {struct_name} {{\n\
         \x20   fn metadata(&self) -> &RuleMetadata {{\n\
         \x20       &METADATA\n\
         \x20   }}\n\
         \n\
         \x20   fn analyze(&self, ctx: &AnalysisContext<'_>, _out: &mut Vec<Finding>) {{\n\
         \x20       if !ctx.is_confirmed_soroban() {{\n\
         \x20           return;\n\
         \x20       }}\n\
         \x20       for source in ctx.sources() {{\n\
         \x20           let Some(_file) = &source.syntax else {{\n\
         \x20               continue;\n\
         \x20           }};\n\
         \x20           // TODO({id}): inspect AST facts and push Finding::new(&METADATA, location, evidence).\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n\
         \n\
         #[cfg(test)]\n\
         mod tests {{\n\
         \x20   use super::*;\n\
         \x20   use crate::rules::test_support::scan_rule;\n\
         \n\
         \x20   #[test]\n\
         \x20   fn metadata_is_valid() {{\n\
         \x20       assert!(METADATA.validate().is_ok());\n\
         \x20   }}\n\
         \n\
         \x20   #[test]\n\
         \x20   fn clean_contract_produces_no_findings() {{\n\
         \x20       let src = r#\"\n\
         \x20           use soroban_sdk::{{contract, contractimpl, Env}};\n\
         \x20           #[contract]\n\
         \x20           pub struct Demo;\n\
         \x20           #[contractimpl]\n\
         \x20           impl Demo {{\n\
         \x20               pub fn ping(_env: Env) -> u32 {{ 1 }}\n\
         \x20           }}\n\
         \x20       \"#;\n\
         \x20       let findings = scan_rule(src, Box::new({struct_name}));\n\
         \x20       assert!(findings.is_empty());\n\
         \x20   }}\n\
         }}\n"
    );

    let doc_source = format!(
        "# {id} — {title}\n\
         \n\
         - **Severity:** {severity_slug}\n\
         - **Confidence:** {confidence_slug}\n\
         - **Category:** {category_slug}\n\
         \n\
         ## Problem\n\
         \n\
         {description}\n\
         \n\
         ## How it is detected\n\
         \n\
         Describe the concrete syntactic or structural evidence observed by `{struct_name}`.\n\
         \n\
         ## Limitations\n\
         \n\
         Analysis is purely syntactic and intra-file; helper functions in external modules are not resolved.\n\
         \n\
         ## False positives\n\
         \n\
         Document legitimate patterns that must not trigger `{id}`.\n\
         \n\
         ## Remediation\n\
         \n\
         Explain how to remediate findings reported by `{id}`.\n\
         \n\
         ## References\n\
         \n\
         - <https://developers.stellar.org/docs/build/smart-contracts>\n"
    );

    let positive_fixture = format!(
        "// Positive fixture for {id}: {title}.\n\
         use soroban_sdk::{{contract, contractimpl, Env}};\n\
         \n\
         #[contract]\n\
         pub struct VulnerableContract;\n\
         \n\
         #[contractimpl]\n\
         impl VulnerableContract {{\n\
         \x20   pub fn trigger(_env: Env) {{\n\
         \x20       // Replace with a minimal snippet that triggers {id}.\n\
         \x20   }}\n\
         }}\n"
    );

    let negative_fixture = format!(
        "// Negative fixture for {id}: safe pattern that must not trigger.\n\
         use soroban_sdk::{{contract, contractimpl, Env}};\n\
         \n\
         #[contract]\n\
         pub struct SafeContract;\n\
         \n\
         #[contractimpl]\n\
         impl SafeContract {{\n\
         \x20   pub fn safe_op(_env: Env) -> u32 {{\n\
         \x20       1\n\
         \x20   }}\n\
         }}\n"
    );

    if let Some(parent) = module_file.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    if let Some(parent) = doc_file.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    fs::create_dir_all(&corpus_dir)
        .map_err(|err| format!("failed to create {}: {err}", corpus_dir.display()))?;

    fs::write(&module_file, &module_source)
        .map_err(|err| format!("failed to write {}: {err}", module_file.display()))?;
    fs::write(&doc_file, &doc_source)
        .map_err(|err| format!("failed to write {}: {err}", doc_file.display()))?;
    fs::write(&fixture_files[0], &positive_fixture)
        .map_err(|err| format!("failed to write {}: {err}", fixture_files[0].display()))?;
    for neg in &fixture_files[1..] {
        fs::write(neg, &negative_fixture)
            .map_err(|err| format!("failed to write {}: {err}", neg.display()))?;
    }

    register_in_rules_mod(&rules_mod_file, &module_name, &struct_name)?;

    Ok(ScaffoldedRule {
        module_file,
        rules_mod_file,
        doc_file,
        corpus_dir,
    })
}

fn register_in_rules_mod(
    rules_mod_file: &Path,
    module_name: &str,
    struct_name: &str,
) -> Result<(), String> {
    let mod_line = format!("pub mod {module_name};");
    let reg_line = format!("        Box::new({module_name}::{struct_name}),");

    if !rules_mod_file.exists() {
        let initial = format!(
            "//! Built-in Soroban security detectors.\n\
             \n\
             {mod_line}\n\
             \n\
             use crate::error::ScanError;\n\
             use crate::registry::RuleRegistry;\n\
             use crate::rule::Rule;\n\
             \n\
             pub fn register_default_rules(registry: &mut RuleRegistry) -> Result<(), ScanError> {{\n\
             \x20   let rules: Vec<Box<dyn Rule>> = vec![\n\
             {reg_line}\n\
             \x20   ];\n\
             \x20   for rule in rules {{\n\
             \x20       registry.register(rule)?;\n\
             \x20   }}\n\
             \x20   Ok(())\n\
             }}\n"
        );
        return fs::write(rules_mod_file, initial)
            .map_err(|err| format!("failed to write {}: {err}", rules_mod_file.display()));
    }

    let mut content = fs::read_to_string(rules_mod_file)
        .map_err(|err| format!("failed to read {}: {err}", rules_mod_file.display()))?;

    if !content.contains(&mod_line) {
        if let Some(pos) = content.find("pub mod util;") {
            content.insert_str(pos, &format!("{mod_line}\n"));
        } else {
            content = format!("{mod_line}\n{content}");
        }
    }

    if !content.contains(&format!("{module_name}::{struct_name}")) {
        if let Some(vec_start) = content.find("let rules: Vec<Box<dyn Rule>> = vec![") {
            if let Some(rel_end) = content[vec_start..].find("    ];") {
                let insert_at = vec_start + rel_end;
                content.insert_str(insert_at, &format!("{reg_line}\n"));
            }
        }
    }

    fs::write(rules_mod_file, content)
        .map_err(|err| format!("failed to write {}: {err}", rules_mod_file.display()))
}

fn safe_join(root: &Path, relative: &Path) -> Result<PathBuf, String> {
    if relative.is_absolute() {
        return Err(format!(
            "refusing to write outside repository root: {}",
            relative.display()
        ));
    }
    for component in relative.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "refusing path with parent or root traversal: {}",
                    relative.display()
                ));
            }
        }
    }
    Ok(root.join(relative))
}

fn validate_rule_id(id: &str) -> Result<String, String> {
    let trimmed = id.trim().to_ascii_uppercase();
    if trimmed.len() == 6
        && trimmed.starts_with("SS-")
        && trimmed[3..].chars().all(|c| c.is_ascii_digit())
        && &trimmed[3..] != "000"
    {
        Ok(trimmed)
    } else {
        Err(format!(
            "invalid rule id {id:?}: expected 'SS-###' (three non-zero digits, e.g. SS-042)"
        ))
    }
}

fn validate_title(title: &str) -> Result<String, String> {
    let trimmed = title.trim();
    if trimmed.is_empty() {
        return Err("rule title must not be empty".to_string());
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err("rule title must not contain control characters or newlines".to_string());
    }
    Ok(trimmed.to_string())
}

fn validate_module_name(name: &str) -> Result<String, String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("module name must not be empty".to_string());
    }
    let mut chars = trimmed.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_lowercase() {
        return Err(format!(
            "invalid module name {name:?}: must start with a lowercase ASCII letter"
        ));
    }
    if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
        return Err(format!(
            "invalid module name {name:?}: use only lowercase ASCII letters, digits, and '_'"
        ));
    }
    if matches!(trimmed, "mod" | "util" | "test_support") {
        return Err(format!("module name {name:?} is reserved"));
    }
    Ok(trimmed.to_string())
}

fn derive_module_name(title: &str, id: &str) -> Result<String, String> {
    let mut out = String::new();
    let mut prev_underscore = false;
    for ch in title.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_underscore = false;
        } else if !out.is_empty() && !prev_underscore {
            out.push('_');
            prev_underscore = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    if out.is_empty() || !out.chars().next().unwrap().is_ascii_lowercase() {
        out = format!("rule_{}", id.to_ascii_lowercase().replace('-', "_"));
    }
    validate_module_name(&out)
}

fn to_pascal_case(snake: &str) -> String {
    snake
        .split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

fn parse_category(input: &str) -> Result<(&'static str, &'static str), String> {
    match input.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "authorization" => Ok(("Authorization", "authorization")),
        "authentication" => Ok(("Authentication", "authentication")),
        "access-control" => Ok(("AccessControl", "access-control")),
        "cross-contract" => Ok(("CrossContract", "cross-contract")),
        "token" => Ok(("Token", "token")),
        "storage" => Ok(("Storage", "storage")),
        "arithmetic" => Ok(("Arithmetic", "arithmetic")),
        "error-handling" => Ok(("ErrorHandling", "error-handling")),
        "events" => Ok(("Events", "events")),
        "resource-usage" => Ok(("ResourceUsage", "resource-usage")),
        "configuration" => Ok(("Configuration", "configuration")),
        "dependencies" => Ok(("Dependencies", "dependencies")),
        "unsafe" => Ok(("Unsafe", "unsafe")),
        other => Err(format!("unknown category '{other}'")),
    }
}

fn parse_severity(input: &str) -> Result<(&'static str, &'static str), String> {
    match input.trim().to_ascii_lowercase().as_str() {
        "info" => Ok(("Info", "info")),
        "low" => Ok(("Low", "low")),
        "medium" => Ok(("Medium", "medium")),
        "high" => Ok(("High", "high")),
        "critical" => Ok(("Critical", "critical")),
        other => Err(format!("unknown severity '{other}'")),
    }
}

fn parse_confidence(input: &str) -> Result<(&'static str, &'static str), String> {
    match input.trim().to_ascii_lowercase().as_str() {
        "low" => Ok(("Low", "low")),
        "medium" => Ok(("Medium", "medium")),
        "high" => Ok(("High", "high")),
        other => Err(format!("unknown confidence '{other}'")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("xtask-rules-{label}-{nanos}"));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn default_options(id: &str, title: &str) -> RuleScaffoldOptions {
        RuleScaffoldOptions {
            id: id.to_string(),
            title: title.to_string(),
            module: None,
            category: "authorization".to_string(),
            severity: "medium".to_string(),
            confidence: "medium".to_string(),
            force: false,
        }
    }

    #[test]
    fn scaffolds_rule_module_fixtures_docs_and_registration_in_temp_dir() {
        let root = temp_root("scaffold");
        let rules_dir = root.join("crates/soroban-scan-core/src/rules");
        fs::create_dir_all(&rules_dir).unwrap();
        fs::write(
            rules_dir.join("mod.rs"),
            "pub mod util;\n\npub fn register_default_rules(registry: &mut RuleRegistry) -> Result<(), ScanError> {\n    let rules: Vec<Box<dyn Rule>> = vec![\n    ];\n    Ok(())\n}\n",
        )
        .unwrap();

        let created = scaffold(
            &root,
            &default_options("SS-042", "Unchecked ledger timestamp drift"),
        )
        .unwrap();

        assert!(created.module_file.is_file());
        assert!(created.doc_file.is_file());
        assert!(created.corpus_dir.join("positive.rs").is_file());
        assert!(created.corpus_dir.join("negative.rs").is_file());
        assert!(created.corpus_dir.join("negative2.rs").is_file());
        assert!(created.corpus_dir.join("negative3.rs").is_file());

        let module_text = fs::read_to_string(&created.module_file).unwrap();
        assert!(module_text.contains("id: \"SS-042\""));
        assert!(module_text.contains("pub struct UncheckedLedgerTimestampDriftRule;"));
        assert!(module_text.contains("impl Rule for UncheckedLedgerTimestampDriftRule"));

        let mod_rs = fs::read_to_string(&created.rules_mod_file).unwrap();
        assert!(mod_rs.contains("pub mod unchecked_ledger_timestamp_drift;"));
        assert!(mod_rs.contains(
            "Box::new(unchecked_ledger_timestamp_drift::UncheckedLedgerTimestampDriftRule)"
        ));

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn refuses_to_overwrite_existing_files_without_force() {
        let root = temp_root("overwrite");
        let opts = default_options("SS-043", "Duplicate claim window");
        scaffold(&root, &opts).unwrap();

        let err = scaffold(&root, &opts).unwrap_err();
        assert!(err.contains("refusing to overwrite"), "got: {err}");

        let mut forced = opts;
        forced.force = true;
        assert!(scaffold(&root, &forced).is_ok());

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rejects_invalid_ids_and_path_traversal() {
        let root = temp_root("traversal");
        for bad_id in ["../SS-001", "SS-1", "SS-000", "XX-001", "SS-01A", ""] {
            let opts = default_options(bad_id, "Valid title");
            assert!(scaffold(&root, &opts).is_err(), "accepted bad id {bad_id:?}");
        }
        for bad_mod in ["../escape", "a/b", "a\\b", "Upper", "mod", "util", ""] {
            let mut opts = default_options("SS-044", "Valid title");
            opts.module = Some(bad_mod.to_string());
            assert!(
                scaffold(&root, &opts).is_err(),
                "accepted bad module {bad_mod:?}"
            );
        }
        fs::remove_dir_all(&root).unwrap();
    }
}
