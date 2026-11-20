# Operations runbook

This runbook covers the failure modes an operator is most likely to hit when
running the scanner in CI or on a schedule. Every command is read-only and was
run against a local checkout; nothing here needs production credentials.

The scanner is a short-lived process, not a daemon. "Queue backlog" therefore
refers to the jobs in front of it (CI runners, scheduled workflows, or a job
system) rather than an internal worker queue.

## 1. Health checks

Start with the cheapest checks, then move to a full scan.

```bash
# Is the binary the expected build?
soroban-scan --version

# Did the project classify as expected, and which rules will run?
soroban-scan doctor ./contracts

# Does the configuration parse and validate?
soroban-scan scan ./contracts --fail-on none --format json > /dev/null
```

`doctor` is the first stop for "the scan found nothing": it reports the scan
root, manifests, classification evidence, excludes, and the effective rule set.

## 2. Logs

- `--log-level info|warn|error` emits structured JSON log lines to **stderr**.
  Stdout stays reserved for the requested report, so redirect them separately:

  ```bash
  soroban-scan scan ./contracts --format json --log-level info \
    > report.json 2> scan.log
  ```

- Diagnostics inside the report use stable codes such as `PARSE-001`,
  `CONFIG-002`, and `BASELINE-002`. See [diagnostics](diagnostics.md) for the
  full list.
- `--verbose` prints diagnostics to stderr; `--quiet` suppresses the header.

Logs never include source text, environment values, or secrets.

## 3. Metrics

Enable bounded metrics with `--metrics`. They are printed to stderr in
Prometheus text format and are safe to scrape:

```bash
soroban-scan scan ./contracts --format json --metrics \
  > report.json 2> metrics.prom
```

- `soroban_scan_scan_duration_seconds` and
  `soroban_scan_rule_duration_seconds` are the latency signals.
- `soroban_scan_rules_failed_total` and the `panicked` status count indicate a
  rule that was isolated; the scan still completed.
- `soroban_scan_rules_skipped_total` rising after an upgrade usually means a
  rule was deprecated or disabled by configuration.

See [metrics](metrics.md) for names, buckets, and cardinality guarantees.

## 4. Queue backlog

If scheduled or CI scans are not starting:

1. Check the runner or scheduler, not the scanner. The scanner does not queue
   work and exits after one invocation.
2. Inspect workflow concurrency. Two workflows that share a concurrency group
   run one at a time; a stuck run blocks the next.
3. Confirm the job is not waiting on a dependency install or checkout step.
4. Bound the work: scan the changed paths first, or reduce scope with
   `--exclude`/`--exclude-tests`. A full scan of a large repository is expected
   to take longer than a pull-request scan.

If a single scan is slow, use `--timings` to see per-rule wall-clock time. The
timing output is presentation-only and never changes findings.

## 5. Rollback

Reports and baselines are artifacts; rolling back is a matter of restoring the
previous artifact and the matching binary.

1. Identify the last known-good binary version and report from the artifact
   store. Reports are named deterministically; see [retention](retention.md).
2. Re-run the scan with the previous binary and the previous baseline to confirm
   the expected finding count.
3. If a rule change caused the regression, disable it explicitly instead of
   silently dropping findings:

   ```toml
   [rules]
   disabled = ["SS-0NN"]
   ```

4. Record the reason and the removal date in the change ticket. A deprecated or
   disabled rule keeps its id, so the baseline still resolves.

Never delete a baseline to make a gate pass; that hides accepted findings. Use
`--write-baseline` only after reviewing the new entries.

## 6. Escalation

Escalate when:

- the scanner exits with a usage or internal error (`2` or `3`) and the config
  validates locally;
- a rule panics repeatedly (`RULE-004`, `panicked` metric);
- SARIF or JSON cannot be parsed by a downstream consumer;
- findings contradict a manual review in a way that suggests a detector bug.

Attach the tool version, the report diagnostics, the relevant artifact name, and
the exact command. Do not attach scanned source unless it is already public.

## 7. Data retention

- Keep reports for at least the retention window required by your policy; the
  default recommendation in [retention](retention.md) is 90 days for pull-request
  scans and 1 year for release scans.
- Store reports and baselines outside the repository.
- Baselines contain rule ids, file paths, severities, titles, and fingerprints,
  but never source text or secrets. Apply `--redact` if paths are sensitive.
- Delete expired artifacts on a schedule. Retention is the artifact store's
  responsibility; the scanner does not delete files.
