//! Additive pipeline stages and observer hooks (#113).
//!
//! Hooks observe the discovery, parsing, analysis, and post-processing stages.
//! They must not change findings or statistics, and repeated runs must report
//! the same stages in the same order.

use std::path::PathBuf;
use std::sync::Mutex;

use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::engine::{self, PipelineHook, PipelineHooks, PipelineStage, StageSummary};
use soroban_scan_core::frontend;
use soroban_scan_core::registry::RuleRegistry;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/projects/soroban-confirmed")
}

#[derive(Default)]
struct Recorder {
    summaries: Mutex<Vec<StageSummary>>,
}

impl PipelineHook for Recorder {
    fn on_stage(&self, summary: &StageSummary) {
        self.summaries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(*summary);
    }
}

fn stages(recorder: &Recorder) -> Vec<PipelineStage> {
    recorder
        .summaries
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .map(|summary| summary.stage)
        .collect()
}

#[test]
fn hooks_observe_all_four_stages_in_order() {
    let root = fixture();
    let config = ScanConfig::default();
    let registry = RuleRegistry::with_default_rules();
    let recorder = Recorder::default();
    let mut hooks = PipelineHooks::new();
    hooks.add(&recorder);

    let outcome = engine::run_scan_with_frontend_and_hooks(
        &root,
        &config,
        &registry,
        &frontend::default_frontend(),
        &hooks,
    )
    .expect("scan succeeds");

    assert!(!outcome.findings.is_empty() || outcome.stats.rules_run > 0);
    assert_eq!(
        stages(&recorder),
        vec![
            PipelineStage::Discovery,
            PipelineStage::Parsing,
            PipelineStage::Analysis,
            PipelineStage::PostProcessing,
        ]
    );

    let summaries = recorder
        .summaries
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert_eq!(summaries[0].stage.as_str(), "discovery");
    assert_eq!(summaries[1].stage.as_str(), "parsing");
    assert_eq!(summaries[2].stage.as_str(), "analysis");
    assert_eq!(summaries[3].stage.as_str(), "post_processing");
    assert_eq!(summaries[2].files, outcome.stats.files_analyzed);
    assert_eq!(summaries[2].findings, outcome.stats.findings_raw);
    assert_eq!(summaries[3].findings, outcome.findings.len());
}

#[test]
fn hooks_do_not_change_findings_or_stats() {
    let root = fixture();
    let config = ScanConfig::default();
    let registry = RuleRegistry::with_default_rules();

    let plain = engine::run_scan(&root, &config, &registry).expect("scan succeeds");
    let recorder = Recorder::default();
    let mut hooks = PipelineHooks::new();
    hooks.add(&recorder);
    let observed = engine::run_scan_with_frontend_and_hooks(
        &root,
        &config,
        &registry,
        &frontend::default_frontend(),
        &hooks,
    )
    .expect("scan succeeds");

    assert_eq!(
        serde_json::to_string(&plain.findings).unwrap(),
        serde_json::to_string(&observed.findings).unwrap()
    );
    assert_eq!(plain.stats.rules_run, observed.stats.rules_run);
    assert_eq!(plain.stats.findings_raw, observed.stats.findings_raw);
    assert_eq!(plain.stats.files_analyzed, observed.stats.files_analyzed);
    assert_eq!(plain.stats.files_parsed, observed.stats.files_parsed);
}

#[test]
fn hook_order_is_deterministic_across_runs() {
    let root = fixture();
    let config = ScanConfig::default();
    let registry = RuleRegistry::with_default_rules();

    let first = Recorder::default();
    let second = Recorder::default();
    let mut first_hooks = PipelineHooks::new();
    first_hooks.add(&first);
    let mut second_hooks = PipelineHooks::new();
    second_hooks.add(&second);

    engine::run_scan_with_frontend_and_hooks(
        &root,
        &config,
        &registry,
        &frontend::default_frontend(),
        &first_hooks,
    )
    .expect("scan succeeds");
    engine::run_scan_with_frontend_and_hooks(
        &root,
        &config,
        &registry,
        &frontend::default_frontend(),
        &second_hooks,
    )
    .expect("scan succeeds");

    assert_eq!(
        *first.summaries.lock().unwrap(),
        *second.summaries.lock().unwrap()
    );
}

#[test]
fn scan_with_hooks_reports_analysis_and_post_processing() {
    let root = fixture();
    let config = ScanConfig::default();
    let registry = RuleRegistry::with_default_rules();
    let loaded = soroban_scan_core::project::load(&root, &config.discovery_options())
        .expect("project loads");
    let recorder = Recorder::default();
    let mut hooks = PipelineHooks::new();
    hooks.add(&recorder);

    let outcome = engine::scan_with_hooks(&loaded, &registry, &config, &hooks);

    assert_eq!(
        stages(&recorder),
        vec![PipelineStage::Analysis, PipelineStage::PostProcessing]
    );
    assert_eq!(
        recorder.summaries.lock().unwrap()[1].findings,
        outcome.findings.len()
    );
}
