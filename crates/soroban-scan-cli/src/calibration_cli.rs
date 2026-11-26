//! CLI entry point for deterministic calibration reports.

use std::fs;
use std::path::PathBuf;

use clap::{Args, ValueEnum};
use soroban_scan_core::corpus;
use soroban_scan_core::registry::RuleRegistry;
use soroban_scan_core::report::calibration;

use crate::{CliError, CliResult, EXIT_SUCCESS};

/// Output format for a calibration report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(super) enum CalibrationFormatArg {
    /// Aggregate Markdown report.
    Markdown,
    /// Aggregate machine-readable JSON report.
    Json,
}

/// Arguments for `soroban-scan calibrate`.
#[derive(Debug, Args)]
#[command(after_help = "Examples:\n  \
    soroban-scan calibrate\n  \
    soroban-scan calibrate --format json --output calibration.json\n  \
    soroban-scan calibrate --per-rule-dir docs/rules/calibration")]
pub(super) struct CalibrateArgs {
    /// Repository root containing `fixtures/corpus` and `docs/rules`.
    #[arg(long, value_name = "DIR")]
    root: Option<PathBuf>,

    /// Aggregate output format.
    #[arg(long, value_enum, default_value_t = CalibrationFormatArg::Markdown)]
    format: CalibrationFormatArg,

    /// Write the aggregate report to a file instead of stdout.
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Write one deterministic Markdown report per rule into this directory.
    #[arg(long, value_name = "DIR")]
    per_rule_dir: Option<PathBuf>,
}

/// Generates advisory calibration evidence without changing ratings.
pub(super) fn run(args: CalibrateArgs, registry: &RuleRegistry) -> CliResult<u8> {
    let root = args.root.unwrap_or_else(corpus::repository_root);
    if !root.is_dir() {
        return Err(CliError::Runtime(format!(
            "calibration root `{}` is not a directory",
            root.display()
        )));
    }

    let report = calibration::evaluate_calibration(&root, registry)
        .map_err(|error| CliError::Runtime(error.to_string()))?;

    if let Some(dir) = &args.per_rule_dir {
        fs::create_dir_all(dir).map_err(|error| {
            CliError::Runtime(format!("cannot create `{}`: {error}", dir.display()))
        })?;
        for rule in &report.rules {
            let path = dir.join(format!("{}.md", rule.rule_id));
            let rendered = calibration::render_rule_markdown(rule);
            fs::write(&path, rendered).map_err(|error| {
                CliError::Runtime(format!("cannot write `{}`: {error}", path.display()))
            })?;
        }
    }

    let rendered = match args.format {
        CalibrationFormatArg::Json => calibration::render_json(&report)
            .map_err(|error| CliError::Runtime(format!("cannot serialize calibration: {error}")))?,
        CalibrationFormatArg::Markdown => calibration::render_markdown(&report),
    };

    match &args.output {
        Some(path) => fs::write(path, rendered).map_err(|error| {
            CliError::Runtime(format!("cannot write `{}`: {error}", path.display()))
        })?,
        None => print!("{rendered}"),
    }

    Ok(EXIT_SUCCESS)
}
