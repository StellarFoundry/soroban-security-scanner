# Configuration

The scanner reads configuration from `soroban-scan.toml` in the scan root or the
current directory, unless `--config` selects a specific file. Command-line
options override the file.

`--no-config` skips discovery entirely and runs with the built-in defaults. Use it
when debugging, or when scanning an untrusted repository whose own
`soroban-scan.toml` must not influence the scan. It is mutually exclusive
with `--config`.

Generate a starter file:

```bash
soroban-scan init
```

Use `--interactive` to answer a few questions about minimum severity, enabled
categories, and exclude globs; the wizard then writes a valid configuration
file. Piped input is supported for scripted setup.

```bash
soroban-scan init --interactive
```

Inspect the effective configuration and validate it:

```bash
soroban-scan config show
soroban-scan config validate
```

## Reference

```toml
# Minimum severity to report: info, low, medium, high, critical
min_severity = "info"

# Minimum confidence to report: low, medium, high
min_confidence = "low"

# Glob patterns (relative to the scan root) to exclude from discovery
exclude = ["vendor/**", "target/**"]

# Skip #[cfg(test)] items and test directories
exclude_tests = false

# Analyze #[cfg(test)] items too (they are skipped by default)
include_cfg_test = false

# Follow symbolic links during discovery (disabled by default for safety)
follow_symlinks = false

# Minimum supported soroban-sdk version for SS-015
minimum_soroban_sdk = "21.0.0"

[rules]
# Rule ids to disable
disabled = ["SS-006"]

# If non-empty, only these rule ids run
enabled = []

# Categories to disable. Category names are validated when the file is loaded;
# an unknown category is a usage error. Accepts kebab-case or snake_case.
disabled_categories = ["resource-usage"]

# If non-empty, only rules in these categories run
enabled_categories = []

# Per-rule severity overrides
severity_overrides = { "SS-007" = "low" }

# Per-rule confidence overrides
confidence_overrides = { }

# Best-effort per-rule execution budget in milliseconds (disabled by default).
# A rule that overruns is reported with RULE-005 and its findings are discarded.
# time_budget_ms = 5000

[ai]
# Optional assistance layer. Disabled by default; the deterministic scanner is
# authoritative. See docs/ai.md.
enabled = false
# provider = "openai"
# model = "..."
# Sampling temperature, 0.0-1.0 (finite). Lower is more deterministic.
temperature = 0.0
# Maximum tokens the provider may return, 1-8192.
max_output_tokens = 1024
# Requests per scan; AI calls stop (fail closed) when exhausted.
# max_requests = 50
# Per-request retry limit and exponential backoff.
# max_retries = 2
# backoff_ms = 250
# max_backoff_ms = 4000
# Consecutive provider failures before assistance is disabled for the run.
# failure_threshold = 3
```

### Fields

| Field | Type | Default | Meaning |
| ----- | ---- | ------- | ------- |
| `min_severity` | severity | `info` | Minimum severity to report. |
| `min_confidence` | confidence | `low` | Minimum confidence to report. |
| `exclude` | array of globs | `[]` | Paths excluded from discovery. |
| `exclude_tests` | bool | `false` | Skip `#[cfg(test)]` items and directories named `tests`. |
| `include_cfg_test` | bool | `false` | Analyze items gated behind `#[cfg(test)]`. They are skipped by default. |
| `follow_symlinks` | bool | `false` | Follow symlinks (off by default for safety). |
| `minimum_soroban_sdk` | string | `21.0.0` | Minimum supported `soroban-sdk` version for SS-015. |
| `rules.disabled` | array of ids | `[]` | Rules never run. |
| `rules.enabled` | array of ids | `[]` | If non-empty, the only rules that run. |
| `rules.disabled_categories` | array of categories | `[]` | Rules in these categories never run. |
| `rules.enabled_categories` | array of categories | `[]` | If non-empty, only rules in these categories run. |
| `rules.severity_overrides` | map id→severity | `{}` | Replace a rule's default severity. |
| `rules.confidence_overrides` | map id→confidence | `{}` | Replace a rule's default confidence. |
| `rules.time_budget_ms` | integer | *(disabled)* | Best-effort per-rule wall-clock budget in milliseconds. Overrunning rules are reported with `RULE-005` and their findings are discarded. The budget cannot preempt a rule already running, so a pathological rule still consumes its own runtime; it only bounds what the rule contributes to the scan. |
| `ai.enabled` | bool | `false` | Enable the optional assistance layer (fails closed without a provider). |
| `ai.provider` | string | *(none)* | Provider name; none is bundled. |
| `ai.model` | string | *(none)* | Model identifier. |
| `ai.temperature` | float | `0.0` | Sampling temperature; must be finite and in `0.0..=1.0`. Out-of-range values are rejected during configuration loading. |
| `ai.max_output_tokens` | integer | `1024` | Maximum provider output tokens; must be in `1..=8192`. Bounds latency and runaway cost. |
| `ai.max_requests` | integer | `50` | Hard per-scan request budget. `0` disables assistant calls; exhaustion emits `AI-001` and continues without assistance. |
| `ai.max_retries` | integer | `2` | Bounded retries per provider request. |
| `ai.backoff_ms` | integer | `250` | Base exponential backoff delay. |
| `ai.max_backoff_ms` | integer | `4000` | Maximum single backoff delay. |
| `ai.failure_threshold` | integer | `3` | Consecutive provider failures before assistance is disabled for the rest of the run (`1`–`100`). The scan still completes and emits `AI-002`. |

Unknown fields and category names are rejected. An unknown rule id in
`disabled` or `enabled` is a usage error. An override that targets an unknown or
disabled rule does not abort the scan; it emits a `CONFIG-001` diagnostic so the
ineffective setting is visible.

Category filters are applied before per-rule severity and confidence overrides.
A rule is skipped when it is individually disabled, when it belongs to a
disabled category, or when `enabled_categories` is non-empty and does not list
its category. The valid categories are:

`authorization`, `authentication`, `access-control`, `cross-contract`, `token`,
`storage`, `arithmetic`, `error-handling`, `events`, `resource-usage`,
`configuration`, `dependencies`, `unsafe`.

For example, this disables all resource-usage heuristics while keeping the rest
of the default rule set:

```toml
[rules]
disabled_categories = ["resource-usage"]
```

JSON reports include this effective configuration (after precedence below) in
the `effective_config` object, so a report can be reproduced from its own
contents. The object contains no environment data, credentials, or absolute
user paths.

## Precedence

1. Built-in defaults.
2. Configuration file (`--config`, scan root, or current directory); skipped
   entirely with `--no-config`.
3. Command-line flags (`--min-severity`, `--min-confidence`, `--exclude`,
   `--disable`, `--rule`, `--rule-time-budget-ms`).

## Example: strict CI policy

```toml
min_severity = "medium"
min_confidence = "medium"
exclude = ["tests/**", "examples/**"]

[rules]
disabled = ["SS-006"]
severity_overrides = { "SS-002" = "high" }
```

Combined with `--fail-on high`, medium findings are reported but only high and
critical findings fail the build.

## Security

Configuration files are untrusted data. No option can enable code execution,
network access, or access to secrets. See
[Security Model](security/security-model.md).
