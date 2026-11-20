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
    /// Render the contributor backlog from tools/backlog/*.json.
    Backlog(BacklogArgs),
    /// Scaffold a new security rule and its fixtures.
    Rule(RuleArgs),
}

/// Arguments for `xtask rule`.
#[derive(Debug, Args, PartialEq, Eq)]
pub struct RuleArgs {
    /// Rule id (`SS-###`).
    pub id: String,
    /// Human-readable rule title.
    pub title: String,
    /// Repository root (defaults to the workspace root).
    #[arg(long, value_name = "DIR")]
    pub root: Option<PathBuf>,
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
    fn parses_rule_scaffolding() {
        let cli = Cli::try_parse_from(["xtask", "rule", "SS-034", "User-controlled event topic"])
            .unwrap();
        assert_eq!(
            cli.command,
            Command::Rule(RuleArgs {
                id: "SS-034".to_string(),
                title: "User-controlled event topic".to_string(),
                root: None,
            })
        );
    }

    #[test]
    fn rule_arguments_are_required() {
        let err = Cli::try_parse_from(["xtask", "rule", "SS-034"]).unwrap_err();
        assert!(err.to_string().contains("TITLE"), "unexpected error: {err}");
    }
}
