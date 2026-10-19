//! Command-line interface for the Soroban Security Scanner.
//!
//! Exit codes (stable):
//! * `0` — success, no findings at or above the configured failure threshold.
//! * `1` — findings at or above the configured failure threshold.
//! * `2` — usage error (bad arguments, unknown rule, invalid configuration).
//! * `3` — runtime error (I/O failure, unreadable scan root).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};

use soroban_scan_core::ai::{self, Assistant};
use soroban_scan_core::baseline::{self, Baseline};
use soroban_scan_core::category::Category;
use soroban_scan_core::confidence::Confidence;
use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::engine;
use soroban_scan_core::project;
use soroban_scan_core::registry::RuleRegistry;
use soroban_scan_core::report::{self, OutputFormat};
use soroban_scan_core::severity::Severity;

const EXIT_SUCCESS: u8 = 0;
const EXIT_FINDINGS: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_ERROR: u8 = 3;

const DEFAULT_CONFIG_FILE: &str = "soroban-scan.toml";

/// Terminal reports at least this large may be paged when stdout is a TTY.
const DEFAULT_PAGE_THRESHOLD_BYTES: usize = 64 * 1024;

const CONFIG_TEMPLATE: &str = r#"# Soroban Security Scanner configuration
# See https://github.com/AyinkxLab/soroban-security-scanner

# Minimum severity to report: info, low, medium, high, critical
min_severity = "info"

# Minimum confidence to report: low, medium, high
min_confidence = "low"

# Glob patterns (relative to the scan root) to exclude.
exclude = []

# Skip #[cfg(test)] items and test directories.
exclude_tests = false

# Follow symbolic links during discovery (disabled by default for safety).
follow_symlinks = false

[rules]
# Rule ids to disable.
disabled = []
# If non-empty, only these rule ids run.
enabled = []
# Categories to disable, for example: ["resource-usage", "configuration"].
# See docs/configuration.md for the complete list.
# disabled_categories = []
# If non-empty, only rules in these categories run.
# enabled_categories = []
# Per-rule severity overrides, for example: { "SS-001" = "critical" }
# severity_overrides = {}
# Per-rule confidence overrides, for example: { "SS-007" = "low" }
# confidence_overrides = {}

[ai]
# Optional assistance layer. Disabled by default.
# The deterministic scanner is authoritative; assistance never changes findings.
enabled = false
# provider = "none"
# model = "none"
"#;

/// Argument value for `--format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FormatArg {
    Terminal,
    Json,
    Sarif,
    Markdown,
    Github,
}

impl From<FormatArg> for OutputFormat {
    fn from(value: FormatArg) -> Self {
        match value {
            FormatArg::Terminal => OutputFormat::Terminal,
            FormatArg::Json => OutputFormat::Json,
            FormatArg::Sarif => OutputFormat::Sarif,
            FormatArg::Markdown => OutputFormat::Markdown,
            FormatArg::Github => OutputFormat::Github,
        }
    }
}

/// Argument value for `--color`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ColorArg {
    /// Color only when stdout is an interactive terminal and `NO_COLOR` is unset.
    Auto,
    /// Always color human-readable terminal output.
    Always,
    /// Never emit ANSI escapes.
    Never,
}

/// Argument value for `--fail-on`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FailOnArg {
    None,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl FailOnArg {
    fn threshold(self) -> Option<Severity> {
        match self {
            FailOnArg::None => None,
            FailOnArg::Info => Some(Severity::Info),
            FailOnArg::Low => Some(Severity::Low),
            FailOnArg::Medium => Some(Severity::Medium),
            FailOnArg::High => Some(Severity::High),
            FailOnArg::Critical => Some(Severity::Critical),
        }
    }
}

/// Argument value for `--pager`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum PagerArg {
    /// Page long terminal reports when stdout is a terminal.
    Auto,
    /// Never page; always write output verbatim.
    Never,
    /// Always page terminal reports, even when redirected.
    Always,
}

/// Deterministic security analysis for Stellar Soroban smart contracts.
#[derive(Debug, Parser)]
#[command(
    name = "soroban-scan",
    version,
    about = "Deterministic security analysis for Stellar Soroban smart contracts",
    long_about = "Statically analyzes Soroban/Rust source code and reports \
security findings with stable rule ids, severity, confidence, source locations, \
and remediation guidance. The scanner never executes, deploys, or mutates the \
code it analyzes.",
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
// CLI argument structs differ in size by design; boxing them would hurt readability.
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Scan a directory or file for security findings.
    Scan(ScanArgs),
    /// List the available security rules.
    Rules(RulesArgs),
    /// Explain a rule in detail.
    Explain(ExplainArgs),
    /// Print the scanner name and version.
    Version,
    /// Write a starter configuration file.
    Init(InitArgs),
    /// Inspect the scanner configuration.
    Config(ConfigArgs),
}

#[derive(Debug, Args)]
struct ScanArgs {
    /// Directory or file(s) to scan. Repeatable; results are merged.
    #[arg(default_value = ".", num_args = 1..)]
    paths: Vec<PathBuf>,

    /// Read a single source from stdin, using NAME as its logical path.
    ///
    /// When set, the positional PATH is ignored, the scan root is the current
    /// directory, and reported locations use NAME. Input is capped so a large
    /// or endless pipe cannot exhaust memory.
    #[arg(
        long,
        value_name = "NAME",
        conflicts_with_all = ["paths", "files_from"]
    )]
    stdin_filename: Option<String>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = FormatArg::Terminal)]
    format: FormatArg,

    /// Write the report to a file instead of stdout.
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Only report findings at or above this severity.
    #[arg(long, value_name = "LEVEL")]
    min_severity: Option<Severity>,

    /// Only report findings at or above this confidence.
    #[arg(long, value_name = "LEVEL")]
    min_confidence: Option<Confidence>,

    /// Report at most N findings, after sorting. The exit gate still considers
    /// every finding, and the report states how many were omitted.
    #[arg(long, value_name = "N")]
    max_findings: Option<usize>,

    /// Exclude a glob (relative to the scan root). Repeatable.
    #[arg(long = "exclude", value_name = "GLOB")]
    exclude: Vec<String>,

    /// Skip items gated behind `#[cfg(test)]` and test directories.
    #[arg(long)]
    exclude_tests: bool,

    /// Configuration file to use.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Ignore discovered configuration and run with built-in defaults.
    #[arg(long, conflicts_with = "config")]
    no_config: bool,

    /// Read a newline-separated list of files to scan, relative to PATH.
    #[arg(long, value_name = "FILE")]
    files_from: Option<PathBuf>,

    /// Disable a rule by id. Repeatable.
    #[arg(long = "disable", value_name = "RULE")]
    disable: Vec<String>,

    /// Run only the given rule(s), by id. Repeatable.
    #[arg(long = "rule", value_name = "RULE")]
    rule: Vec<String>,

    /// Exit with code 1 if a finding at or above this severity is present.
    #[arg(long, value_enum, default_value_t = FailOnArg::High)]
    fail_on: FailOnArg,

    /// Compare against a baseline file, marking findings as new or existing.
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,

    /// Write current findings to a baseline file and exit successfully.
    #[arg(long, value_name = "FILE")]
    write_baseline: Option<PathBuf>,

    /// With --baseline, report only findings that are new.
    #[arg(long, requires = "baseline")]
    new_only: bool,

    /// Incremental scan: do not report resolved findings.
    #[arg(long, requires = "baseline")]
    incremental: bool,

    /// After the report, print offline guidance for the findings (labeled).
    #[arg(long)]
    guidance: bool,

    /// Suppress the report header and diagnostics.
    #[arg(long, short = 'q', conflicts_with = "verbose")]
    quiet: bool,

    /// Include diagnostics in the report.
    #[arg(long, short = 'v')]
    verbose: bool,

    /// Page long terminal reports through `$PAGER` (never affects JSON, SARIF,
    /// Markdown, or GitHub annotations).
    #[arg(long, value_enum, default_value_t = PagerArg::Auto)]
    pager: PagerArg,

    /// Colorize human-readable terminal output. Machine formats never contain
    /// ANSI escapes; `auto` respects `NO_COLOR` and non-TTY output.
    #[arg(long, value_enum, default_value_t = ColorArg::Auto)]
    color: ColorArg,
}

#[derive(Debug, Args)]
struct RulesArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = FormatArg::Terminal)]
    format: FormatArg,

    /// Filter by category.
    #[arg(long, value_name = "CATEGORY")]
    category: Option<String>,

    /// Filter by minimum default severity.
    #[arg(long, value_name = "LEVEL")]
    min_severity: Option<Severity>,

    /// Case-insensitive search over rule id, title, description, and category.
    #[arg(long, value_name = "TEXT")]
    search: Option<String>,
}

#[derive(Debug, Args)]
struct ExplainArgs {
    /// Rule id (for example SS-001).
    rule: String,

    /// Output format.
    #[arg(long, value_enum, default_value_t = FormatArg::Terminal)]
    format: FormatArg,
}

#[derive(Debug, Args)]
struct InitArgs {
    /// Directory in which to create the configuration file.
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Overwrite an existing configuration file.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct ConfigArgs {
    #[command(subcommand)]
    command: ConfigCommand,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Print the effective configuration as TOML.
    Show {
        /// Configuration file to load.
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
    },
    /// Validate a configuration file.
    Validate {
        /// Configuration file to validate.
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
    },
}

/// A CLI error, distinguishing usage errors from runtime errors.
#[derive(Debug)]
enum CliError {
    Usage(String),
    Runtime(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Usage(message) | CliError::Runtime(message) => f.write_str(message),
        }
    }
}

impl CliError {
    fn exit_code(&self) -> u8 {
        match self {
            CliError::Usage(_) => EXIT_USAGE,
            CliError::Runtime(_) => EXIT_ERROR,
        }
    }
}

type CliResult<T> = Result<T, CliError>;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

fn run(cli: Cli) -> CliResult<u8> {
    let registry = RuleRegistry::with_default_rules();
    match cli.command {
        Command::Version => {
            println!("{}", soroban_scan_core::version_string());
            Ok(EXIT_SUCCESS)
        }
        Command::Scan(args) => run_scan(args, &registry),
        Command::Rules(args) => run_rules(args, &registry),
        Command::Explain(args) => run_explain(args, &registry),
        Command::Init(args) => run_init(args),
        Command::Config(args) => run_config(args),
    }
}

fn run_scan(args: ScanArgs, registry: &RuleRegistry) -> CliResult<u8> {
    let stdin_mode = args.stdin_filename.is_some();
    let multiple = args.paths.len() > 1;

    if !stdin_mode {
        for path in &args.paths {
            if !path.exists() {
                return Err(CliError::Runtime(format!(
                    "path does not exist: {}",
                    path.display()
                )));
            }
        }
    }

    // With several roots, configuration is discovered once from the current
    // directory so every root is scanned with identical settings.
    let scan_root = if stdin_mode || multiple {
        PathBuf::from(".")
    } else {
        args.paths[0].clone()
    };

    let mut config = load_config(args.config.as_deref(), &scan_root, !args.no_config)?;

    if let Some(severity) = args.min_severity {
        config.min_severity = severity;
    }
    if let Some(confidence) = args.min_confidence {
        config.min_confidence = confidence;
    }
    config.exclude.extend(args.exclude.iter().cloned());
    config.exclude_tests |= args.exclude_tests;
    config.rules.disabled.extend(args.disable.iter().cloned());
    config.rules.enabled.extend(args.rule.iter().cloned());

    validate_rule_ids(&config, registry)?;

    let mut outcome = if let Some(name) = &args.stdin_filename {
        let file_name = validate_logical_filename(name)?;
        let source = read_stdin_bounded()?;
        engine::scan_source_str(&source, &file_name, &config, registry)
    } else if let Some(list) = &args.files_from {
        let path = single_path(&args.paths, "--files-from")?;
        if path.is_file() {
            return Err(CliError::Usage(
                "--files-from requires PATH to be a directory".to_string(),
            ));
        }
        let files = read_file_list(list, path)?;
        let loaded = project::load_files_with_options(path, &files, &config.discovery_options())
            .map_err(runtime)?;
        engine::scan(&loaded, registry, &config)
    } else if multiple {
        let mut labels = Vec::with_capacity(args.paths.len());
        let mut outcomes = Vec::with_capacity(args.paths.len());
        for path in &args.paths {
            labels.push(relative_label(path)?);
            outcomes.push(scan_path(path, registry, &config)?);
        }
        engine::merge(outcomes, &labels)
    } else {
        scan_path(&args.paths[0], registry, &config)?
    };

    if let Some(path) = &args.write_baseline {
        let baseline = Baseline::from_findings(&outcome.findings);
        let text = baseline.to_json().map_err(runtime)?;
        std::fs::write(path, text)
            .map_err(|e| CliError::Runtime(format!("cannot write {}: {e}", path.display())))?;
        if !args.quiet {
            eprintln!(
                "wrote baseline with {} finding(s) to {}",
                baseline.findings.len(),
                path.display()
            );
        }
        return Ok(EXIT_SUCCESS);
    }

    let mut new_indices: Option<Vec<usize>> = None;
    if let Some(path) = &args.baseline {
        let text = std::fs::read_to_string(path).map_err(|e| {
            CliError::Runtime(format!("cannot read baseline {}: {e}", path.display()))
        })?;
        let baseline = Baseline::from_json(&text).map_err(runtime)?;
        let comparison = baseline::compare(&outcome.findings, &baseline);
        let resolved = if args.incremental {
            0
        } else {
            comparison.resolved_count()
        };
        if !args.quiet {
            eprintln!(
                "baseline: {} new, {} existing, {} resolved{}",
                comparison.new_count(),
                comparison.existing_count(),
                resolved,
                if args.incremental {
                    " (incremental)"
                } else {
                    ""
                }
            );
        }
        new_indices = Some(comparison.new);
    }

    // The failure gate only considers new findings when a baseline is supplied.
    let threshold = args.fail_on.threshold();
    let failed = match threshold {
        None => false,
        Some(threshold) => match &new_indices {
            Some(indices) => indices
                .iter()
                .any(|&index| outcome.findings[index].severity.meets(threshold)),
            None => outcome
                .findings
                .iter()
                .any(|finding| finding.severity.meets(threshold)),
        },
    };

    if args.new_only {
        if let Some(indices) = &new_indices {
            let keep: std::collections::BTreeSet<usize> = indices.iter().copied().collect();
            outcome.findings = outcome
                .findings
                .into_iter()
                .enumerate()
                .filter(|(index, _)| keep.contains(index))
                .map(|(_, finding)| finding)
                .collect();
        }
    }

    // Truncate only after the gate has been evaluated against every finding and
    // after `--new-only` has selected the report's rows. Findings are already
    // sorted, so the retained prefix is deterministic.
    outcome.truncate_findings(args.max_findings);

    let color = report::TerminalColor::new(resolve_color(
        args.color,
        args.format,
        args.output.is_some(),
    ));
    let rendered = if args.quiet && matches!(args.format, FormatArg::Terminal) {
        report::render_terminal_compact_with_color(&outcome, color)
    } else if matches!(args.format, FormatArg::Terminal) {
        report::render_terminal_with_color(&outcome, color)
    } else {
        report::render(&outcome, registry, args.format.into())
    };

    match &args.output {
        Some(path) => {
            std::fs::write(path, rendered)
                .map_err(|e| CliError::Runtime(format!("cannot write {}: {e}", path.display())))?;
            if !args.quiet {
                eprintln!("report written to {}", path.display());
            }
        }
        None => print_report(&rendered, args.format, args.pager)?,
    }

    if args.verbose && !args.quiet {
        for diagnostic in &outcome.diagnostics {
            eprintln!("diagnostic: [{}] {}", diagnostic.code, diagnostic.message);
        }
    }

    if args.guidance {
        let base = ai::assistant(&config.ai).map_err(|e| {
            CliError::Usage(format!("assistance is unavailable: {e} (see docs/ai.md)"))
        })?;
        let provider = config
            .ai
            .provider
            .clone()
            .unwrap_or_else(|| base.name().to_string());
        let model = config
            .ai
            .model
            .clone()
            .unwrap_or_else(|| "offline".to_string());
        let cache =
            ai::AssistanceCache::new(assistance_cache_root(&scan_root), ai::DEFAULT_MAX_ENTRIES);
        let assistant = ai::CachedAssistant::new(base, cache, provider, model);

        let explanation = assistant.summarize(&outcome.findings);
        eprintln!("{}", explanation.render());
        for finding in &outcome.findings {
            let rule = registry.by_id(&finding.rule_id).map(|rule| rule.metadata());
            let explanation = assistant.explain_finding(finding, rule);
            eprintln!("{}", explanation.render());
        }
    }

    Ok(if failed { EXIT_FINDINGS } else { EXIT_SUCCESS })
}

/// Returns the assistance cache directory for a scan root.
///
/// For a single-file scan the cache sits next to the file's directory; for a
/// directory (or stdin/multi-root scan rooted at `.`) it sits under the scan
/// root. Discovery excludes `.scanner-cache`, so cached entries are never
/// treated as source.
fn assistance_cache_root(scan_root: &Path) -> PathBuf {
    let root = if scan_root.is_dir() {
        scan_root
    } else {
        scan_root.parent().unwrap_or_else(|| Path::new("."))
    };
    root.join(ai::CACHE_DIR)
}

/// Writes a rendered report to stdout, optionally through a pager.
///
/// Only terminal output is ever paged; JSON, SARIF, and Markdown are written
/// verbatim so piping stays byte-for-byte predictable. When a pager is selected
/// but cannot be launched, the report is written directly instead.
fn print_report(rendered: &str, format: FormatArg, pager: PagerArg) -> CliResult<()> {
    use std::io::IsTerminal;

    let is_terminal = std::io::stdout().is_terminal();
    if should_page(pager, format, is_terminal, rendered.len(), page_threshold())
        && run_pager(rendered).is_ok()
    {
        return Ok(());
    }
    print!("{rendered}");
    Ok(())
}

/// Decides whether ANSI colors should be emitted for this invocation.
///
/// Colors are restricted to the human-readable terminal format. `auto` also
/// requires an interactive stdout, a report that is not being written to a
/// file, and the absence of `NO_COLOR`. `always` is an explicit override.
fn resolve_color(choice: ColorArg, format: FormatArg, to_file: bool) -> bool {
    if format != FormatArg::Terminal {
        return false;
    }
    match choice {
        ColorArg::Always => true,
        ColorArg::Never => false,
        ColorArg::Auto => {
            use std::io::IsTerminal;
            !to_file && std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
        }
    }
}

/// Decides whether a rendered report should be paged.
fn should_page(
    pager: PagerArg,
    format: FormatArg,
    is_terminal: bool,
    bytes: usize,
    threshold: usize,
) -> bool {
    if format != FormatArg::Terminal || threshold == 0 {
        return false;
    }
    match pager {
        PagerArg::Never => false,
        PagerArg::Always => true,
        PagerArg::Auto => is_terminal && bytes >= threshold,
    }
}

/// The paging threshold, honouring the `SOROBAN_SCAN_PAGE_THRESHOLD` override.
///
/// A value of `0` disables automatic paging. The override lets the long-output
/// behaviour be exercised deterministically in tests.
fn page_threshold() -> usize {
    std::env::var("SOROBAN_SCAN_PAGE_THRESHOLD")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_PAGE_THRESHOLD_BYTES)
}

/// Streams `content` to the pager's stdin and waits for it to exit.
fn run_pager(content: &str) -> std::io::Result<()> {
    use std::io::Write;

    let mut child = pager_command()
        .stdin(std::process::Stdio::piped())
        .spawn()?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(content.as_bytes())?;
    }
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other("pager exited unsuccessfully"))
    }
}

/// The pager to use: `$PAGER`, else `less -R` (unix) or `more` (windows).
fn pager_command() -> std::process::Command {
    if let Some(pager) = std::env::var_os("PAGER").filter(|value| !value.is_empty()) {
        let pager = pager.to_string_lossy().into_owned();
        let mut parts = pager.split_whitespace();
        if let Some(program) = parts.next() {
            let mut command = std::process::Command::new(program);
            command.args(parts);
            return command;
        }
    }
    #[cfg(windows)]
    {
        std::process::Command::new("more")
    }
    #[cfg(not(windows))]
    {
        let mut command = std::process::Command::new("less");
        command.arg("-R");
        command
    }
}

fn run_rules(args: RulesArgs, registry: &RuleRegistry) -> CliResult<u8> {
    let category = match &args.category {
        Some(value) => Some(value.parse::<Category>().map_err(CliError::Usage)?),
        None => None,
    };

    let search = args.search.as_ref().map(|s| s.to_ascii_lowercase());

    let metas: Vec<_> = match category {
        Some(category) => registry.metadata_by_category(category),
        None => registry.metadata_sorted(),
    }
    .into_iter()
    .filter(|meta| match args.min_severity {
        Some(min) => meta.default_severity.meets(min),
        None => true,
    })
    .filter(|meta| match &search {
        Some(query) => {
            meta.id.to_ascii_lowercase().contains(query)
                || meta.title.to_ascii_lowercase().contains(query)
                || meta.description.to_ascii_lowercase().contains(query)
                || meta.category.as_str().contains(query.as_str())
        }
        None => true,
    })
    .collect();

    print!("{}", report::render_rule_list(&metas, args.format.into()));
    Ok(EXIT_SUCCESS)
}

fn run_explain(args: ExplainArgs, registry: &RuleRegistry) -> CliResult<u8> {
    let rule = registry
        .by_id(&args.rule)
        .ok_or_else(|| CliError::Usage(format!("unknown rule id: {}", args.rule)))?;
    print!(
        "{}",
        report::render_rule_detail(rule.metadata(), args.format.into())
    );
    Ok(EXIT_SUCCESS)
}

fn run_init(args: InitArgs) -> CliResult<u8> {
    if !args.path.exists() {
        return Err(CliError::Runtime(format!(
            "directory does not exist: {}",
            args.path.display()
        )));
    }
    let target = if args.path.is_dir() {
        args.path.join(DEFAULT_CONFIG_FILE)
    } else {
        args.path.clone()
    };
    if target.exists() && !args.force {
        return Err(CliError::Usage(format!(
            "{} already exists (use --force to overwrite)",
            target.display()
        )));
    }
    std::fs::write(&target, CONFIG_TEMPLATE)
        .map_err(|e| CliError::Runtime(format!("cannot write {}: {e}", target.display())))?;
    println!("wrote {}", target.display());
    Ok(EXIT_SUCCESS)
}

fn run_config(args: ConfigArgs) -> CliResult<u8> {
    match args.command {
        ConfigCommand::Show { config } => {
            let effective = load_config(config.as_deref(), Path::new("."), true)?;
            let text = toml::to_string_pretty(&effective)
                .map_err(|e| CliError::Runtime(format!("cannot serialize config: {e}")))?;
            print!("{text}");
            Ok(EXIT_SUCCESS)
        }
        ConfigCommand::Validate { config } => {
            let effective = load_config(config.as_deref(), Path::new("."), true)?;
            let registry = RuleRegistry::with_default_rules();
            validate_rule_ids(&effective, &registry)?;
            println!(
                "configuration is valid (min severity: {}, min confidence: {})",
                effective.min_severity, effective.min_confidence
            );
            Ok(EXIT_SUCCESS)
        }
    }
}

fn load_config(explicit: Option<&Path>, root: &Path, discover: bool) -> CliResult<ScanConfig> {
    if let Some(path) = explicit {
        let text = std::fs::read_to_string(path)
            .map_err(|e| CliError::Runtime(format!("cannot read {}: {e}", path.display())))?;
        return ScanConfig::from_toml(&text).map_err(|e| CliError::Usage(e.to_string()));
    }

    if !discover {
        return Ok(ScanConfig::default());
    }

    let candidates = [
        root.join(DEFAULT_CONFIG_FILE),
        PathBuf::from(DEFAULT_CONFIG_FILE),
    ];
    for candidate in candidates {
        if candidate.is_file() {
            let text = std::fs::read_to_string(&candidate).map_err(|e| {
                CliError::Runtime(format!("cannot read {}: {e}", candidate.display()))
            })?;
            return ScanConfig::from_toml(&text).map_err(|e| CliError::Usage(e.to_string()));
        }
    }

    Ok(ScanConfig::default())
}

fn read_file_list(list: &Path, root: &Path) -> CliResult<Vec<PathBuf>> {
    let text = std::fs::read_to_string(list)
        .map_err(|e| CliError::Runtime(format!("cannot read file list {}: {e}", list.display())))?;
    let mut files = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let candidate = Path::new(line);
        if candidate
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(CliError::Usage(format!(
                "file list entry escapes the scan root: {line}"
            )));
        }
        let resolved = if candidate.is_absolute() {
            candidate.to_path_buf()
        } else {
            root.join(candidate)
        };
        files.push(resolved);
    }
    if files.is_empty() {
        return Err(CliError::Usage("file list is empty".to_string()));
    }
    Ok(files)
}

/// Returns the single allowed path, or a usage error naming the offending flag.
fn single_path<'a>(paths: &'a [PathBuf], flag: &str) -> CliResult<&'a Path> {
    match paths {
        [only] => Ok(only.as_path()),
        _ => Err(CliError::Usage(format!("{flag} requires exactly one PATH"))),
    }
}

/// Loads and scans a single path, which may be a file or a directory.
fn scan_path(
    path: &Path,
    registry: &RuleRegistry,
    config: &ScanConfig,
) -> CliResult<engine::ScanOutcome> {
    if path.is_file() {
        let file = path.to_path_buf();
        let root = file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let loaded = project::load_files_with_options(&root, &[file], &config.discovery_options())
            .map_err(runtime)?;
        Ok(engine::scan(&loaded, registry, config))
    } else {
        engine::run_scan(path, config, registry).map_err(runtime)
    }
}

/// Converts a scan path into a root-relative prefix for reported locations.
///
/// When several roots are scanned, each must live inside the current directory
/// so every location stays a safe relative path and remains unambiguous. The
/// check runs on the input components as well as the resolved path so it
/// behaves identically on every platform.
fn relative_label(path: &Path) -> CliResult<String> {
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(outside_working_directory(path));
    }

    let cwd = std::env::current_dir()
        .map_err(|e| CliError::Runtime(format!("cannot read the current directory: {e}")))?;
    let absolute = std::path::absolute(path)
        .map_err(|e| CliError::Runtime(format!("cannot resolve {}: {e}", path.display())))?;
    let relative = absolute
        .strip_prefix(&cwd)
        .map_err(|_| outside_working_directory(path))?;
    if relative.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_)
        )
    }) {
        return Err(outside_working_directory(path));
    }

    let label = relative.to_string_lossy().replace('\\', "/");
    Ok(label.trim_end_matches('/').to_string())
}

/// The usage error for a path that is not inside the working directory.
fn outside_working_directory(path: &Path) -> CliError {
    CliError::Usage(format!(
        "when scanning multiple paths, every PATH must be inside the current directory: {}",
        path.display()
    ))
}

/// Upper bound on the number of bytes read from stdin.
///
/// Scanning source from a pipe must not buffer unbounded input in memory, so
/// reads are capped and oversized input is rejected with a usage error rather
/// than being silently truncated.
const MAX_STDIN_BYTES: usize = 8 * 1024 * 1024;

/// Reads all of stdin, rejecting input larger than [`MAX_STDIN_BYTES`].
fn read_stdin_bounded() -> CliResult<String> {
    use std::io::Read;

    let mut buffer = String::new();
    let stdin = std::io::stdin();
    let mut handle = stdin.lock().take((MAX_STDIN_BYTES + 1) as u64);
    handle
        .read_to_string(&mut buffer)
        .map_err(|e| CliError::Runtime(format!("cannot read stdin: {e}")))?;
    if buffer.len() > MAX_STDIN_BYTES {
        return Err(CliError::Usage(format!(
            "stdin exceeds the {MAX_STDIN_BYTES} byte limit"
        )));
    }
    Ok(buffer)
}

/// Validates the logical filename supplied alongside `--stdin-filename`.
///
/// A non-empty, relative, root-respecting path keeps reported locations stable
/// and stops the synthetic file from claiming to live outside the scan root.
fn validate_logical_filename(name: &str) -> CliResult<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(CliError::Usage(
            "--stdin-filename must not be empty".to_string(),
        ));
    }
    let path = Path::new(trimmed);
    if path.is_absolute() {
        return Err(CliError::Usage(
            "--stdin-filename must be a relative path".to_string(),
        ));
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(CliError::Usage(
            "--stdin-filename must not escape the scan root".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

fn validate_rule_ids(config: &ScanConfig, registry: &RuleRegistry) -> CliResult<()> {
    let mut referenced: Vec<&String> = Vec::new();
    referenced.extend(&config.rules.disabled);
    referenced.extend(&config.rules.enabled);
    for id in referenced {
        if registry.by_id(id).is_none() {
            return Err(CliError::Usage(format!("unknown rule id: {id}")));
        }
    }
    for id in config
        .rules
        .severity_overrides
        .keys()
        .chain(config.rules.confidence_overrides.keys())
    {
        if registry.by_id(id).is_none() {
            return Err(CliError::Usage(format!("unknown rule id: {id}")));
        }
    }
    Ok(())
}

fn runtime(error: soroban_scan_core::error::ScanError) -> CliError {
    CliError::Runtime(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paging_only_affects_large_terminal_output() {
        assert!(should_page(
            PagerArg::Auto,
            FormatArg::Terminal,
            true,
            100,
            10
        ));
        assert!(!should_page(
            PagerArg::Auto,
            FormatArg::Terminal,
            true,
            5,
            10
        ));
        assert!(!should_page(
            PagerArg::Auto,
            FormatArg::Terminal,
            false,
            100,
            10
        ));
        assert!(!should_page(
            PagerArg::Auto,
            FormatArg::Terminal,
            true,
            100,
            0
        ));
        assert!(!should_page(
            PagerArg::Never,
            FormatArg::Terminal,
            true,
            100,
            10
        ));
        assert!(should_page(
            PagerArg::Always,
            FormatArg::Terminal,
            false,
            1,
            10
        ));
    }

    #[test]
    fn machine_formats_are_never_paged() {
        for format in [
            FormatArg::Json,
            FormatArg::Sarif,
            FormatArg::Markdown,
            FormatArg::Github,
        ] {
            assert!(!should_page(PagerArg::Always, format, true, 1_000_000, 1));
        }
    }

    #[test]
    fn color_is_restricted_to_terminal_output() {
        assert!(resolve_color(ColorArg::Always, FormatArg::Terminal, false));
        assert!(!resolve_color(ColorArg::Never, FormatArg::Terminal, false));
        assert!(!resolve_color(ColorArg::Auto, FormatArg::Terminal, true));
        for format in [
            FormatArg::Json,
            FormatArg::Sarif,
            FormatArg::Markdown,
            FormatArg::Github,
        ] {
            assert!(!resolve_color(ColorArg::Always, format, false));
        }
    }
}
