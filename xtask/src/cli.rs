//! Command-line surface for repository automation.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Repository automation for the Soroban Security Scanner.
///
/// Every command is offline and non-destructive by default.
#[derive(Debug, Parser)]
#[command(name = "xtask", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Supported automation commands.
#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum Command {
    /// Check relative links in every Markdown file.
    Docs(DocsArgs),
    /// Scaffold a project fixture under fixtures/projects/.
    Fixtures(FixturesArgs),
    /// Scaffold a new security rule module, corpus fixtures, and detector docs.
    #[command(visible_alias = "new-rule")]
    Rule(RuleArgs),
    /// Render the contributor backlog from tools/backlog/*.json.
    Backlog(BacklogArgs),
}

/// Arguments for `xtask docs`.
#[derive(Debug, Args, PartialEq, Eq)]
pub struct DocsArgs {
    /// Repository root (defaults to the workspace root).
    #[arg(long, value_name = "DIR")]
    pub root: Option<PathBuf>,
}

/// Arguments for `xtask fixtures`.
#[derive(Debug, Args, PartialEq, Eq)]
pub struct FixturesArgs {
    /// Fixture name (letters, digits, `-`, and `_`).
    pub name: String,
    /// Repository root (defaults to the workspace root).
    #[arg(long, value_name = "DIR")]
    pub root: Option<PathBuf>,
    /// Overwrite the scaffold files if the fixture already exists.
    #[arg(long)]
    pub force: bool,
}

/// Arguments for `xtask rule` / `xtask new-rule`.
#[derive(Debug, Args, PartialEq, Eq)]
pub struct RuleArgs {
    /// Rule identifier (for example `SS-042`).
    pub id: String,
    /// Short rule title.
    pub title: String,
    /// Optional Rust module name (derived from title when omitted).
    #[arg(long, value_name = "MODULE")]
    pub module: Option<String>,
    /// Rule category (defaults to `authorization`).
    #[arg(long, default_value = "authorization", value_name = "CATEGORY")]
    pub category: String,
    /// Default severity (`info`, `low`, `medium`, `high`, `critical`).
    #[arg(long, default_value = "medium", value_name = "SEVERITY")]
    pub severity: String,
    /// Default confidence (`low`, `medium`, `high`).
    #[arg(long, default_value = "medium", value_name = "CONFIDENCE")]
    pub confidence: String,
    /// Repository root (defaults to the workspace root).
    #[arg(long, value_name = "DIR")]
    pub root: Option<PathBuf>,
    /// Overwrite existing scaffold files if present.
    #[arg(long)]
    pub force: bool,
}

/// Arguments for `xtask backlog`.
#[derive(Debug, Args, PartialEq, Eq)]
pub struct BacklogArgs {
    /// Output directory (defaults to target/backlog).
    #[arg(long, value_name = "DIR")]
    pub output: Option<PathBuf>,
    /// Repository root (defaults to the workspace root).
    #[arg(long, value_name = "DIR")]
    pub root: Option<PathBuf>,
    /// Validate the backlog without writing files.
    #[arg(long)]
    pub check: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_docs_with_defaults() {
        let cli = Cli::try_parse_from(["xtask", "docs"]).unwrap();
        assert_eq!(cli.command, Command::Docs(DocsArgs { root: None }));
    }

    #[test]
    fn parses_fixture_scaffolding() {
        let cli = Cli::try_parse_from(["xtask", "fixtures", "nested-call", "--force"]).unwrap();
        assert_eq!(
            cli.command,
            Command::Fixtures(FixturesArgs {
                name: "nested-call".to_string(),
                root: None,
                force: true,
            })
        );
    }

    #[test]
    fn fixture_name_is_required() {
        let err = Cli::try_parse_from(["xtask", "fixtures"]).unwrap_err();
        assert!(err.to_string().contains("NAME"), "unexpected error: {err}");
    }

    #[test]
    fn parses_backlog_check() {
        let cli = Cli::try_parse_from(["xtask", "backlog", "--check"]).unwrap();
        assert_eq!(
            cli.command,
            Command::Backlog(BacklogArgs {
                output: None,
                root: None,
                check: true,
            })
        );
    }

    #[test]
    fn rejects_unknown_subcommands() {
        let err = Cli::try_parse_from(["xtask", "deploy"]).unwrap_err();
        assert!(err.to_string().contains("unrecognized subcommand"));
    }

    #[test]
    fn parses_rule_scaffolding_and_new_rule_alias() {
        let cli = Cli::try_parse_from([
            "xtask",
            "new-rule",
            "SS-042",
            "Unchecked ledger timestamp drift",
            "--category",
            "arithmetic",
        ])
        .unwrap();
        assert_eq!(
            cli.command,
            Command::Rule(RuleArgs {
                id: "SS-042".to_string(),
                title: "Unchecked ledger timestamp drift".to_string(),
                module: None,
                category: "arithmetic".to_string(),
                severity: "medium".to_string(),
                confidence: "medium".to_string(),
                root: None,
                force: false,
            })
        );
    }
}
