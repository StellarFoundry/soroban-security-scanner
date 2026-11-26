//! Offline command for recording false-positive feedback.

use std::fs;
use std::path::{Path, PathBuf};

use clap::Args;
use soroban_scan_core::feedback::{
    normalize_fingerprint, normalize_reason, FeedbackEntry, FeedbackStore, MAX_FEEDBACK_BYTES,
    MAX_FEEDBACK_ENTRIES,
};
use soroban_scan_core::registry::RuleRegistry;

use crate::{CliError, CliResult, EXIT_SUCCESS};

/// Arguments for `soroban-scan feedback`.
#[derive(Debug, Args)]
pub(super) struct FeedbackArgs {
    /// Rule id to report, for example `SS-001`.
    #[arg(long, value_name = "RULE")]
    rule: String,

    /// Stable finding fingerprint; `--fingerprint` is accepted as an alias.
    #[arg(long, value_name = "HASH", visible_alias = "fingerprint")]
    span_hash: String,

    /// Short local note explaining why the finding is a false positive.
    #[arg(long, value_name = "TEXT")]
    reason: Option<String>,

    /// Directory containing the local feedback document.
    #[arg(long, value_name = "DIR", default_value = ".soroban-scan")]
    dir: PathBuf,
}

/// Record feedback locally without network access or source retention.
pub(super) fn run(args: FeedbackArgs, registry: &RuleRegistry) -> CliResult<u8> {
    if registry.by_id(&args.rule).is_none() {
        return Err(CliError::Usage(format!("unknown rule id: {}", args.rule)));
    }

    let fingerprint = normalize_fingerprint(&args.span_hash).map_err(CliError::Usage)?;
    let reason = args
        .reason
        .as_deref()
        .map(normalize_reason)
        .transpose()
        .map_err(CliError::Usage)?;

    let path = args
        .dir
        .join(soroban_scan_core::feedback::FEEDBACK_FILE_NAME);
    let mut store = load_store(&path)?;
    let added = store.add(FeedbackEntry {
        rule_id: args.rule.clone(),
        fingerprint: fingerprint.clone(),
        reason,
    });
    if store.entries.len() > MAX_FEEDBACK_ENTRIES {
        return Err(CliError::Usage(format!(
            "feedback document would exceed {MAX_FEEDBACK_ENTRIES} entries"
        )));
    }

    let json = store
        .to_json()
        .map_err(|error| CliError::Runtime(error.to_string()))?;
    fs::create_dir_all(&args.dir).map_err(|error| {
        CliError::Runtime(format!("cannot create `{}`: {error}", args.dir.display()))
    })?;
    fs::write(&path, json).map_err(|error| {
        CliError::Runtime(format!("cannot write `{}`: {error}", path.display()))
    })?;

    if added {
        println!(
            "recorded false-positive feedback for {} {}",
            args.rule, fingerprint
        );
    } else {
        println!(
            "false-positive feedback already recorded for {} {}",
            args.rule, fingerprint
        );
    }
    Ok(EXIT_SUCCESS)
}

fn load_store(path: &Path) -> CliResult<FeedbackStore> {
    if !path.exists() {
        return Ok(FeedbackStore::new());
    }
    let metadata = fs::metadata(path)
        .map_err(|error| CliError::Runtime(format!("cannot read `{}`: {error}", path.display())))?;
    if metadata.len() > MAX_FEEDBACK_BYTES as u64 {
        return Err(CliError::Runtime(format!(
            "feedback document `{}` exceeds the {} byte limit",
            path.display(),
            MAX_FEEDBACK_BYTES
        )));
    }
    let text = fs::read_to_string(path)
        .map_err(|error| CliError::Runtime(format!("cannot read `{}`: {error}", path.display())))?;
    FeedbackStore::from_json(&text).map_err(|error| CliError::Runtime(error.to_string()))
}
