//! Command-line surface for repository automation.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::corpus::ReportFormat;

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
    /// Report per-rule corpus fixture counts, docs presence, and validation status.
    #[command(visible_alias = "coverage")]
    Corpus(CorpusArgs),
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

/// Arguments for `xtask corpus`.
#[derive(Debug, Args, PartialEq, Eq)]
pub struct CorpusArgs {
    /// Repository root (defaults to the workspace root).
    #[arg(long, value_name = "DIR")]
    pub root: Option<PathBuf>,
    /// Output format (`terminal` or `markdown`).
    #[arg(long, value_enum, default_value_t = ReportFormat::Terminal)]
    pub format: ReportFormat,
    /// Fail with a non-zero exit code if any rule has a corpus or docs gap.
    #[arg(long)]
    pub check: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_corpus_with_defaults_and_markdown() {
        let cli = Cli::try_parse_from(["xtask", "corpus"]).unwrap();
        assert_eq!(
            cli.command,
            Command::Corpus(CorpusArgs {
                root: None,
                format: ReportFormat::Terminal,
                check: false,
            })
        );

        let md =
            Cli::try_parse_from(["xtask", "corpus", "--format", "markdown", "--check"]).unwrap();
        assert_eq!(
            md.command,
            Command::Corpus(CorpusArgs {
                root: None,
                format: ReportFormat::Markdown,
                check: true,
            })
        );
    }

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
}
