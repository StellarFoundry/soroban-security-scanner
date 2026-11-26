# Opt-in telemetry and crash reporting

Telemetry is **off by default**. The scanner does not transmit, write, or store
any telemetry unless the embedding caller explicitly enables it.

The event contract lives in `soroban-scan-core`. The CLI has no telemetry flag
and the default build contains no telemetry transport. See
[Current scope](#current-scope) before relying on it.

## Current scope

| Piece | Status |
| ----- | ------ |
| Event schema and redaction guarantees (`soroban_scan_core::telemetry`) | Implemented |
| Explicit opt-in gate | Implemented (`TelemetryConfig`) |
| Payload size bound | Implemented |
| Network transport or collector | **Not implemented** |
| CLI flag | **Not implemented** |

The module gives an embedding service a single, reviewable payload it may send
to a collector it operates. The scanner never sends it on its own, and the
default build performs no network access. The `feedback` command is also
local-only: it writes a bounded JSON file and never transmits its contents.

## Enabling

```rust
use soroban_scan_core::telemetry::{TelemetryConfig, TelemetryEvent};

let config = TelemetryConfig::from_toml("[telemetry]\nenabled = true\n")?;
if config.enabled {
    let payload = config.encode(&TelemetryEvent::scan_completed(&outcome))?;
    // Hand the payload to a collector you operate. The scanner does not.
}
```

The equivalent configuration table is:

```toml
[telemetry]
enabled = true
```

`enabled` defaults to `false`, and every key inside `[telemetry]` is validated;
unknown keys are rejected. Other top-level tables in the same document are
ignored, so a deployment configuration can keep telemetry settings beside other
service settings.

`TelemetryConfig::encode` returns `TelemetryError::Disabled` while telemetry is
off, so a caller cannot emit an event by forgetting a check.

## Event schema

One event is a compact JSON object. It has no extension point for free-form
text.

```json
{
  "schema_version": 1,
  "kind": "scan_completed",
  "tool_version": "0.2.0",
  "scan": {
    "project_kind": "confirmed_soroban",
    "analysis_mode": "soroban",
    "files_analyzed": 12,
    "files_failed": 0,
    "rules_run": 24,
    "rules_failed": 0,
    "rules_timed_out": 0,
    "findings": {
      "info": 0,
      "low": 1,
      "medium": 2,
      "high": 0,
      "critical": 0
    }
  }
}
```

`kind` is one of:

- `scan_completed`: a scan finished; `scan` holds counters.
- `scan_failed`: a scan could not finish; `crash` holds a coarse error class.
- `crash`: the process crashed or aborted; `crash` holds a coarse error class.

Crash and failure events contain only one of `io`, `parse`, `config`,
`baseline`, `unknown_rule`, or `unsafe_path`. Error messages, panic text,
backtraces, rule ids, and file paths are not part of the schema.

## What is never included

The schema has no field for, and the implementation never adds:

- source code, snippets, identifiers, or rule evidence;
- file names, directory names, repository names, or absolute paths;
- finding titles, messages, remediation text, or fingerprints;
- environment variables, command-line arguments, user names, or host names;
- tokens, keys, or any configuration values other than `enabled`.

Counters and enum values are the only scan-derived data. Unit tests
(`crates/soroban-scan-core/src/telemetry.rs`) build a scan whose path and source
contain unique markers and assert that none of them appear in the encoded
event. Separate tests assert the same for crash messages.

## Payload bounds

- One serialized event is capped at **4 KiB**
  (`MAX_TELEMETRY_EVENT_BYTES`). Larger events are rejected with
  `TelemetryError::PayloadTooLarge` rather than truncated.
- A telemetry configuration document is capped at **64 KiB**
  (`MAX_TELEMETRY_CONFIG_BYTES`).
- Events are objects of enums and `usize` counters, so they do not grow with
  the size of the scanned project.

## Retention

The scanner stores no telemetry, so it has nothing to retain or delete. If you
operate a collector:

- keep raw events for at most 30 days, then aggregate counters;
- do not attach repository identifiers, IP addresses, or user agents;
- delete events on a documented schedule and publish that schedule;
- treat telemetry as operational data, not audit evidence.

These are recommendations for a collector you own; no collector ships with this
repository.

## Related

- [AI privacy and data flow](ai-privacy.md) - the separate, opt-in AI transport.
- [Security model](security/security-model.md) - the default no-network policy.
- [API stability](api-stability.md) - `telemetry` is an unstable module.
