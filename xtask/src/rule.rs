//! Rule scaffold generation.
//!
//! `cargo xtask rule SS-034 "Title"` creates the files a new detector needs:
//! the rule module, corpus and adversarial fixtures, a documentation stub, and
//! the two registration edits in `rules/mod.rs`. Existing files are never
//! overwritten and the command is idempotent: running it twice changes nothing.

use std::fs;
use std::path::{Path, PathBuf};

/// Categories accepted by the scaffold. Kept small on purpose; the contributor
/// edits the generated constant after choosing the real category.
const RULE_KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn", "for",
    "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
    "self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where",
    "while", "async", "await", "dyn",
];

/// Generates the scaffold for a new rule and returns the rule module path.
///
/// Missing files are created; existing files are left untouched. The module
/// list and registration call in `rules/mod.rs` are inserted only when absent,
/// so a second run is a no-op.
pub fn scaffold(root: &Path, id: &str, title: &str) -> Result<PathBuf, String> {
    validate_id(id)?;
    validate_title(title)?;

    let slug = slugify(title)?;
    if RULE_KEYWORDS.contains(&slug.as_str()) {
        return Err(format!(
            "title produces the Rust keyword {slug:?} as its module name; choose another title"
        ));
    }
    let struct_name = struct_name(&slug);

    let rules_dir = root
        .join("crates")
        .join("soroban-scan-core")
        .join("src")
        .join("rules");
    let mod_path = rules_dir.join("mod.rs");
    if !mod_path.is_file() {
        return Err(format!(
            "not a scanner repository root: missing {}",
            mod_path.display()
        ));
    }

    let module_path = rules_dir.join(format!("{slug}.rs"));
    let corpus_dir = root.join("fixtures").join("corpus").join(id);
    let adversarial_dir = root.join("fixtures").join("adversarial").join(id);
    let docs_path = root
        .join("docs")
        .join("rules")
        .join("detectors")
        .join(format!("{id}.md"));

    create_if_missing(&module_path, &module_source(id, title, &struct_name))?;
    create_if_missing(
        &corpus_dir.join("positive.rs"),
        &fixture_source(id, title, "positive"),
    )?;
    for name in ["negative.rs", "negative2.rs", "negative3.rs"] {
        create_if_missing(&corpus_dir.join(name), &fixture_source(id, title, name))?;
    }
    create_if_missing(
        &adversarial_dir.join("sample.rs"),
        &fixture_source(id, title, "adversarial"),
    )?;
    add_expectation(&root.join("fixtures/adversarial/expectations.toml"), id)?;
    create_if_missing(&docs_path, &docs_source(id, title))?;
    register_module(&mod_path, &slug, &struct_name)?;

    Ok(module_path)
}

fn validate_id(id: &str) -> Result<(), String> {
    let Some(rest) = id.strip_prefix("SS-") else {
        return Err(format!("invalid rule id {id:?}: expected SS-###"));
    };
    if rest.len() != 3 || !rest.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("invalid rule id {id:?}: expected SS-###"));
    }
    Ok(())
}

/// Restricts titles to characters that are safe in a Rust string literal,
/// comment, file name, and documentation heading.
fn validate_title(title: &str) -> Result<(), String> {
    if title.trim().is_empty() {
        return Err("rule title must not be empty".to_string());
    }
    if title.len() > 80 {
        return Err("rule title must be at most 80 characters".to_string());
    }
    if !title
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || " -_,.:()/&".contains(c))
    {
        return Err(format!(
            "invalid rule title {title:?}: use ASCII letters, digits, spaces, and - _ , . : ( ) / &"
        ));
    }
    if !title
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
        || !title
            .chars()
            .last()
            .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        return Err(format!(
            "invalid rule title {title:?}: must start and end with a letter or digit"
        ));
    }
    Ok(())
}

fn slugify(title: &str) -> Result<String, String> {
    let mut slug = String::new();
    for c in title.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
        } else if !slug.ends_with('_') {
            slug.push('_');
        }
    }
    let slug = slug.trim_matches('_').to_string();
    if slug.is_empty() {
        return Err(format!(
            "title {title:?} cannot be turned into a module name"
        ));
    }
    Ok(slug)
}

fn struct_name(slug: &str) -> String {
    let mut name: String = slug
        .split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect();
    if name.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        name.insert_str(0, "Rule");
    }
    name
}

fn module_source(id: &str, title: &str, struct_name: &str) -> String {
    format!(
        "//! {id}: {title}.\n\
         //!\n\
         //! TODO: replace the placeholder implementation and tighten the metadata.\n\
         \n\
         use crate::category::Category;\n\
         use crate::confidence::Confidence;\n\
         use crate::context::AnalysisContext;\n\
         use crate::finding::Finding;\n\
         use crate::rule::{{Rule, RuleMetadata}};\n\
         use crate::severity::Severity;\n\
         \n\
         /// Rule metadata.\n\
         pub const METADATA: RuleMetadata = RuleMetadata {{\n\
         \x20   id: \"{id}\",\n\
         \x20   title: \"{title}\",\n\
         \x20   description: \"TODO: describe the security problem addressed by \
         {title} and its impact.\",\n\
         \x20   category: Category::Storage,\n\
         \x20   default_severity: Severity::Low,\n\
         \x20   default_confidence: Confidence::Low,\n\
         \x20   remediation: \"TODO: explain the safe pattern that avoids this issue.\",\n\
         \x20   references: &[\"https://developers.stellar.org/docs/learn/encyclopedia/security\"],\n\
         }};\n\
         \n\
         /// Detects {title}.\n\
         pub struct {struct_name};\n\
         \n\
         impl Rule for {struct_name} {{\n\
         \x20   fn metadata(&self) -> &RuleMetadata {{\n\
         \x20       &METADATA\n\
         \x20   }}\n\
         \n\
         \x20   fn analyze(&self, _ctx: &AnalysisContext<'_>, _out: &mut Vec<Finding>) {{\n\
         \x20       // TODO: use `rules::util` facts and only report concrete evidence.\n\
         \x20   }}\n\
         }}\n"
    )
}

fn fixture_source(id: &str, title: &str, name: &str) -> String {
    format!(
        "// {id} {name} fixture: {title}.\n\
         // TODO: keep this fixture minimal and make it trigger (or not trigger)\n\
         // the detector exactly as its name promises.\n\
         \n\
         #![no_std]\n\
         \n\
         use soroban_sdk::{{contractimpl, Env}};\n\
         \n\
         pub struct Contract;\n\
         \n\
         #[contractimpl]\n\
         impl Contract {{\n\
         \x20   pub fn entry(_env: Env) {{}}\n\
         }}\n"
    )
}

fn docs_source(id: &str, title: &str) -> String {
    format!(
        "# {id} — {title}\n\
         \n\
         - **Severity:** low\n\
         - **Confidence:** low\n\
         - **Category:** storage\n\
         \n\
         ## Problem\n\
         \n\
         TODO: describe the security problem, who is affected, and the impact if the\n\
         issue is real.\n\
         \n\
         ## How it is detected\n\
         \n\
         TODO: name the exact AST evidence the detector observes.\n\
         \n\
         ## Limitations\n\
         \n\
         TODO: state what the detector cannot determine.\n\
         \n\
         ## False positives\n\
         \n\
         TODO: list the legitimate patterns that must not trigger the rule.\n\
         \n\
         ## Remediation\n\
         \n\
         TODO: explain the safe pattern, with a small example.\n\
         \n\
         ## References\n\
         \n\
         - <https://developers.stellar.org/docs/learn/encyclopedia/security>\n"
    )
}

fn create_if_missing(path: &Path, contents: &str) -> Result<(), String> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    fs::write(path, contents).map_err(|err| format!("failed to write {}: {err}", path.display()))
}

fn add_expectation(path: &Path, id: &str) -> Result<(), String> {
    let mut text = if path.exists() {
        fs::read_to_string(path).map_err(|err| format!("cannot read {}: {err}", path.display()))?
    } else {
        String::from("# Adversarial fixture expectations. See fixtures/adversarial/README.md.\n")
    };
    if text.lines().any(|line| line.trim() == format!("[{id}]")) {
        return Ok(());
    }
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&format!(
        "\n[{id}]\n\
         file = \"{id}/sample.rs\"\n\
         expect = \"no-trigger\"\n\
         why = \"Placeholder scaffold sample; update the expectation after implementing the detector.\"\n"
    ));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    fs::write(path, text).map_err(|err| format!("failed to write {}: {err}", path.display()))
}

/// Adds the `mod` declaration and registration call when they are absent.
fn register_module(mod_path: &Path, slug: &str, struct_name: &str) -> Result<(), String> {
    let text = fs::read_to_string(mod_path)
        .map_err(|err| format!("cannot read {}: {err}", mod_path.display()))?;
    let mut text = text;

    let mod_decl = format!("mod {slug};");
    if !text.lines().any(|line| line.trim() == mod_decl) {
        // Append after the existing module declarations, before the
        // `#[cfg(test)]` helper module. Searching for the last `mod ` line
        // would match `mod tests {` at the end of the file.
        let marker = "\n#[cfg(test)]";
        let Some(at) = text.find(marker) else {
            return Err(format!(
                "cannot find the module declaration block in {}",
                mod_path.display()
            ));
        };
        let insert_at = text[..at].trim_end().len();
        text.insert_str(insert_at, &format!("\n{mod_decl}"));
    }

    let register_line = format!("    registry.register(Box::new({slug}::{struct_name}))?;\n");
    if !text.contains(register_line.trim()) {
        let marker = "\n    Ok(())\n}";
        let Some(at) = text.rfind(marker) else {
            return Err(format!(
                "cannot find the registration block in {}",
                mod_path.display()
            ));
        };
        text.insert_str(at + 1, &register_line);
    }

    fs::write(mod_path, text)
        .map_err(|err| format!("failed to write {}: {err}", mod_path.display()))
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
        let root = std::env::temp_dir().join(format!("xtask-rule-{label}-{nanos}"));
        fs::create_dir_all(&root).unwrap();
        root
    }

    /// Seeds the files `scaffold` edits, copied from the real repository so the
    /// test exercises the same `mod.rs` shape contributors will see.
    fn seed(root: &Path) {
        let rules_dir = root.join("crates/soroban-scan-core/src/rules");
        fs::create_dir_all(&rules_dir).unwrap();
        let real_mod = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../crates/soroban-scan-core/src/rules/mod.rs");
        fs::copy(real_mod, rules_dir.join("mod.rs")).unwrap();
        let adversarial = root.join("fixtures/adversarial");
        fs::create_dir_all(&adversarial).unwrap();
        fs::write(
            adversarial.join("expectations.toml"),
            "[SS-001]\nfile = \"SS-001/x.rs\"\n",
        )
        .unwrap();
    }

    #[test]
    fn scaffolds_a_complete_rule_and_is_idempotent() {
        let root = temp_root("complete");
        seed(&root);
        let module = scaffold(&root, "SS-034", "User-controlled event topic").unwrap();
        assert_eq!(
            module.file_name().unwrap(),
            "user_controlled_event_topic.rs"
        );

        let source = fs::read_to_string(&module).unwrap();
        assert!(source.contains("id: \"SS-034\""));
        assert!(source.contains("User-controlled event topic"));
        assert!(source.contains("pub struct UserControlledEventTopic;"));
        assert!(source.contains("impl Rule for UserControlledEventTopic"));

        for file in [
            "fixtures/corpus/SS-034/positive.rs",
            "fixtures/corpus/SS-034/negative.rs",
            "fixtures/corpus/SS-034/negative2.rs",
            "fixtures/corpus/SS-034/negative3.rs",
            "fixtures/adversarial/SS-034/sample.rs",
            "docs/rules/detectors/SS-034.md",
        ] {
            assert!(root.join(file).is_file(), "missing {file}");
        }

        let mod_rs =
            fs::read_to_string(root.join("crates/soroban-scan-core/src/rules/mod.rs")).unwrap();
        assert_eq!(
            mod_rs.matches("mod user_controlled_event_topic;").count(),
            1
        );
        assert!(
            mod_rs.find("mod user_controlled_event_topic;").unwrap()
                < mod_rs.find("#[cfg(test)]").unwrap(),
            "the module declaration must stay in the top-level list"
        );
        let registration =
            "registry.register(Box::new(user_controlled_event_topic::UserControlledEventTopic))?;";
        assert_eq!(mod_rs.matches(registration).count(), 1);
        assert!(
            mod_rs.find(registration).unwrap() < mod_rs.rfind("Ok(())").unwrap(),
            "the registration must run before register_all returns"
        );
        let expectations =
            fs::read_to_string(root.join("fixtures/adversarial/expectations.toml")).unwrap();
        assert!(expectations.contains("[SS-034]"));

        let before = fs::read_to_string(&module).unwrap();
        let mod_before = mod_rs.clone();
        scaffold(&root, "SS-034", "User-controlled event topic").unwrap();
        assert_eq!(fs::read_to_string(&module).unwrap(), before);
        assert_eq!(
            fs::read_to_string(root.join("crates/soroban-scan-core/src/rules/mod.rs")).unwrap(),
            mod_before
        );

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rejects_invalid_ids_and_titles() {
        let root = temp_root("invalid");
        seed(&root);
        for id in [
            "",
            "SS-1",
            "SS-1234",
            "ss-034",
            "SS-03a",
            "../escape",
            "SS-034\n",
        ] {
            assert!(scaffold(&root, id, "Title").is_err(), "accepted {id:?}");
        }
        for title in [
            "",
            "   ",
            "quote\"title",
            "line\nbreak",
            "back\\slash",
            "-leading",
        ] {
            assert!(
                scaffold(&root, "SS-034", title).is_err(),
                "accepted {title:?}"
            );
        }
        assert!(!root.join("fixtures/corpus/SS-034").exists());
        assert!(!root.join("docs/rules/detectors/SS-034.md").exists());
        fs::remove_dir_all(&root).unwrap();
    }
}
