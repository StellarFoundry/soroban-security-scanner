#!/usr/bin/env python3
"""End-to-end CLI benchmark for `soroban-scan`.

The in-process `benchmark` example (see docs/development/benchmarks.md) measures
parsing and detection on synthetic sources. This script measures the *combined*
system end to end — project discovery, parsing, scanning and report generation —
by timing the real release binary over a target directory.

It is dependency-free (standard library only) and deterministic in what it
measures: the same target, the same number of runs, the same profile.

Every run writes a static dashboard artifact (`benchmark.json` and
`index.html`) under `target/benchmark-dashboard/`. The dashboard is
self-contained: the HTML uses inline CSS, loads no scripts or external
resources, and neither file contains source text or absolute paths.

Usage:
    python tools/benchmark.py --target examples/vulnerable-contract --runs 10

The release binary is built automatically if it is missing.
"""

from __future__ import annotations

import argparse
import html
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "target" / "release" / (
    "soroban-scan.exe" if sys.platform.startswith("win") else "soroban-scan"
)
OUT = ROOT / "target" / "benchmark-report.json"
DEFAULT_BASELINE = ROOT / "tools" / "benchmark_baseline.json"
DEFAULT_THRESHOLD_FACTOR = 6.0
DEFAULT_ARTIFACT_DIR = ROOT / "target" / "benchmark-dashboard"
ARTIFACT_JSON = "benchmark.json"
ARTIFACT_HTML = "index.html"
DASHBOARD_SCHEMA_VERSION = 1


def summarize_samples(samples: list[float]) -> dict:
    """Return deterministic benchmark statistics for a list of millisecond samples."""
    ordered = sorted(samples)
    return {
        "runs": len(ordered),
        "min_ms": round(ordered[0], 3),
        "median_ms": round(statistics.median(ordered), 3),
        "mean_ms": round(statistics.mean(ordered), 3),
        "max_ms": round(ordered[-1], 3),
    }


def load_baseline(path: Path) -> dict:
    """Load and validate a benchmark baseline file."""
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if data.get("schema_version") != 1:
        raise ValueError("unsupported benchmark baseline schema_version")
    if data.get("metric") != "median_ms":
        raise ValueError("only the median_ms benchmark metric is supported")
    baseline = data.get("baseline_median_ms")
    if not isinstance(baseline, (int, float)) or baseline <= 0:
        raise ValueError("baseline_median_ms must be a positive number")
    factor = data.get("threshold_factor", DEFAULT_THRESHOLD_FACTOR)
    if not isinstance(factor, (int, float)) or factor <= 1:
        raise ValueError("threshold_factor must be greater than 1")
    return data


def regression_errors(stats: dict, baseline: dict, factor: float | None = None) -> list[str]:
    """Return human-readable regression messages for a benchmark result.

    The comparison is intentionally one-sided: faster results never fail. A
    regression is reported only when the median exceeds
    ``baseline_median_ms * threshold_factor``.
    """
    allowed_factor = factor if factor is not None else baseline.get(
        "threshold_factor", DEFAULT_THRESHOLD_FACTOR
    )
    if allowed_factor <= 1:
        raise ValueError("threshold factor must be greater than 1")
    baseline_ms = float(baseline["baseline_median_ms"])
    limit_ms = baseline_ms * allowed_factor
    median_ms = float(stats["median_ms"])
    if median_ms <= limit_ms:
        return []
    return [
        (
            f"benchmark regression: median {median_ms:.1f} ms exceeds "
            f"{baseline_ms:.1f} ms baseline x {allowed_factor:g} "
            f"= {limit_ms:.1f} ms"
        )
    ]


def relative_target_label(target: Path, root: Path = ROOT) -> str:
    """Return a repository-relative path, never an absolute one.

    Targets outside the repository fall back to their final component so the
    dashboard can be published without leaking a machine-specific path.
    """
    try:
        return target.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return target.name


def effective_factor(baseline: dict, factor: float | None = None) -> float:
    """Return the threshold factor that applies to this run."""
    return float(
        factor
        if factor is not None
        else baseline.get("threshold_factor", DEFAULT_THRESHOLD_FACTOR)
    )


def dashboard_payload(
    stats: dict,
    baseline: dict,
    target_label: str,
    limit_ms: float,
    factor: float,
    errors: list[str],
) -> dict:
    """Build the dashboard JSON document for one benchmark run.

    Only metrics and labels are recorded; no source text, file contents, or
    absolute paths are included.
    """
    return {
        "schema_version": DASHBOARD_SCHEMA_VERSION,
        "metric": "median_ms",
        "target": target_label,
        "runner": str(baseline.get("runner", "unspecified")),
        "status": "fail" if errors else "pass",
        "stats": dict(stats),
        "baseline": {
            "median_ms": round(float(baseline["baseline_median_ms"]), 3),
            "threshold_factor": factor,
            "limit_ms": round(float(limit_ms), 3),
        },
        "regressions": list(errors),
    }


def _bar_width(value_ms: float, limit_ms: float) -> float:
    """Clamp a millisecond value to a percentage of the failure limit."""
    if limit_ms <= 0:
        return 0.0
    return max(0.0, min(100.0, value_ms / limit_ms * 100.0))


def render_html(payload: dict) -> str:
    """Render a self-contained HTML summary from a dashboard payload.

    The page has no scripts, no external stylesheets, and no network
    references, so it renders offline from a single file.
    """
    stats = payload["stats"]
    baseline = payload["baseline"]
    status = payload["status"]
    status_label = "Regression detected" if status == "fail" else "Within threshold"
    status_class = "fail" if status == "fail" else "pass"

    median_bar = _bar_width(float(stats["median_ms"]), float(baseline["limit_ms"]))
    baseline_bar = _bar_width(float(baseline["median_ms"]), float(baseline["limit_ms"]))
    limit_bar = 100.0

    regressions = payload.get("regressions", [])
    if regressions:
        regression_items = "\n".join(
            f"        <li>{html.escape(message)}</li>" for message in regressions
        )
        regression_block = (
            "      <section>\n"
            "        <h2>Regressions</h2>\n"
            "        <ul class=\"problems\">\n"
            f"{regression_items}\n"
            "        </ul>\n"
            "      </section>"
        )
    else:
        regression_block = (
            "      <section>\n"
            "        <h2>Regressions</h2>\n"
            "        <p>None.</p>\n"
            "      </section>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Benchmark dashboard</title>
  <style>
    :root {{ color-scheme: light dark; }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      padding: 2rem 1rem;
      font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
      line-height: 1.5;
      color: #1b1f24;
      background: #f6f8fa;
    }}
    main {{ max-width: 46rem; margin: 0 auto; }}
    h1 {{ font-size: 1.5rem; margin: 0 0 0.25rem; }}
    h2 {{ font-size: 1rem; margin: 2rem 0 0.5rem; }}
    .meta {{ margin: 0 0 1.5rem; color: #57606a; }}
    .status {{
      display: inline-block;
      margin: 0 0 1.5rem;
      padding: 0.25rem 0.75rem;
      border-radius: 999px;
      font-weight: 600;
    }}
    .status.pass {{ background: #dafbe1; color: #116329; }}
    .status.fail {{ background: #ffebe9; color: #a40e26; }}
    .panel {{
      background: #ffffff;
      border: 1px solid #d0d7de;
      border-radius: 8px;
      padding: 1rem 1.25rem;
    }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 0.4rem 0; text-align: left; }}
    th {{ font-weight: 600; color: #57606a; }}
    td.value {{ text-align: right; font-variant-numeric: tabular-nums; }}
    .chart {{ margin: 0.5rem 0 0; padding: 0; list-style: none; }}
    .chart li {{ margin: 0.75rem 0; }}
    .chart .row {{ display: flex; justify-content: space-between; font-size: 0.875rem; }}
    .track {{ height: 0.6rem; margin-top: 0.25rem; border-radius: 999px; background: #eaeef2; }}
    .fill {{ height: 100%; border-radius: 999px; }}
    .fill.median {{ background: #0969da; }}
    .fill.baseline {{ background: #8c959f; }}
    .fill.limit {{ background: #cf222e; }}
    .problems {{ margin: 0; padding-left: 1.25rem; color: #a40e26; }}
    footer {{ margin-top: 2rem; color: #57606a; font-size: 0.8125rem; }}
    @media (prefers-color-scheme: dark) {{
      body {{ color: #e6edf3; background: #0d1117; }}
      .meta, th, footer {{ color: #8d96a0; }}
      .panel {{ background: #161b22; border-color: #30363d; }}
      .status.pass {{ background: #12261a; color: #7ee787; }}
      .status.fail {{ background: #2d1214; color: #ff7b72; }}
      .track {{ background: #21262d; }}
      .fill.median {{ background: #58a6ff; }}
      .fill.baseline {{ background: #6e7681; }}
      .fill.limit {{ background: #f85149; }}
      .problems {{ color: #ff7b72; }}
    }}
  </style>
</head>
<body>
  <main>
    <h1>Benchmark dashboard</h1>
    <p class="meta">
      Target <code>{html.escape(payload["target"])}</code> on
      <code>{html.escape(payload["runner"])}</code>.
    </p>
    <p class="status {status_class}">{html.escape(status_label)}</p>

    <section class="panel">
      <h2>Run statistics</h2>
      <table>
        <tr><th scope="row">Runs</th><td class="value">{int(stats["runs"])}</td></tr>
        <tr><th scope="row">Minimum</th><td class="value">{float(stats["min_ms"]):.1f} ms</td></tr>
        <tr><th scope="row">Median</th><td class="value">{float(stats["median_ms"]):.1f} ms</td></tr>
        <tr><th scope="row">Mean</th><td class="value">{float(stats["mean_ms"]):.1f} ms</td></tr>
        <tr><th scope="row">Maximum</th><td class="value">{float(stats["max_ms"]):.1f} ms</td></tr>
      </table>
      <ul class="chart">
        <li>
          <div class="row"><span>Median</span><span>{float(stats["median_ms"]):.1f} ms</span></div>
          <div class="track"><div class="fill median" style="width: {median_bar:.1f}%"></div></div>
        </li>
        <li>
          <div class="row"><span>Baseline</span><span>{float(baseline["median_ms"]):.1f} ms</span></div>
          <div class="track"><div class="fill baseline" style="width: {baseline_bar:.1f}%"></div></div>
        </li>
        <li>
          <div class="row"><span>Failure limit</span><span>{float(baseline["limit_ms"]):.1f} ms</span></div>
          <div class="track"><div class="fill limit" style="width: {limit_bar:.1f}%"></div></div>
        </li>
      </ul>
    </section>

    <section class="panel">
      <h2>Comparison</h2>
      <table>
        <tr><th scope="row">Baseline median</th><td class="value">{float(baseline["median_ms"]):.1f} ms</td></tr>
        <tr><th scope="row">Threshold factor</th><td class="value">{float(baseline["threshold_factor"]):g}&times;</td></tr>
        <tr><th scope="row">Failure limit</th><td class="value">{float(baseline["limit_ms"]):.1f} ms</td></tr>
        <tr><th scope="row">Result</th><td class="value">{html.escape(status)}</td></tr>
      </table>
    </section>

{regression_block}

    <footer>
      Generated by <code>tools/benchmark.py</code>. Self-contained: no scripts,
      external resources, source text, or absolute paths.
    </footer>
  </main>
</body>
</html>
"""


def write_dashboard(directory: Path, payload: dict) -> tuple[Path, Path]:
    """Write the dashboard JSON and HTML files, creating the directory."""
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / ARTIFACT_JSON
    html_path = directory / ARTIFACT_HTML
    json_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    html_path.write_text(render_html(payload), encoding="utf-8")
    return json_path, html_path


def ensure_binary() -> None:
    if BIN.exists():
        return
    subprocess.run(
        ["cargo", "build", "--release", "-p", "soroban-scan-cli"],
        cwd=ROOT,
        check=True,
    )


def run_once(target: Path) -> float:
    start = time.perf_counter()
    subprocess.run(
        [
            str(BIN),
            "scan",
            str(target),
            "--format",
            "json",
            "--output",
            str(OUT),
            "--fail-on",
            "none",
            "--quiet",
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return time.perf_counter() - start


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        default="examples/vulnerable-contract",
        help="directory to scan, relative to the repository root",
    )
    parser.add_argument(
        "--runs", type=int, default=10, help="measured runs after a warm-up"
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=DEFAULT_BASELINE,
        help="recorded benchmark baseline JSON (default: tools/benchmark_baseline.json)",
    )
    parser.add_argument(
        "--threshold-factor",
        type=float,
        default=None,
        help="override the baseline threshold factor (must be > 1)",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="also write the measured statistics as JSON",
    )
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR,
        help=(
            "directory for the dashboard artifacts "
            f"(default: {relative_target_label(DEFAULT_ARTIFACT_DIR)})"
        ),
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="write the measured median into the baseline file (same runner only)",
    )
    args = parser.parse_args()

    target = (ROOT / args.target).resolve()
    target_label = relative_target_label(target)
    if not target.exists():
        print(f"error: target not found: {target_label}", file=sys.stderr)
        return 2
    if args.runs < 1:
        print("error: --runs must be >= 1", file=sys.stderr)
        return 2
    if args.threshold_factor is not None and args.threshold_factor <= 1:
        print("error: --threshold-factor must be > 1", file=sys.stderr)
        return 2

    try:
        baseline = load_baseline(args.baseline)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: invalid benchmark baseline: {exc}", file=sys.stderr)
        return 2

    ensure_binary()
    run_once(target)  # warm-up
    samples = sorted(run_once(target) * 1000 for _ in range(args.runs))
    stats = summarize_samples(samples)

    print(f"target: {target_label}")
    print(f"runs:   {stats['runs']}")
    print(f"min:    {stats['min_ms']:.1f} ms")
    print(f"median: {stats['median_ms']:.1f} ms")
    print(f"mean:   {stats['mean_ms']:.1f} ms")
    print(f"max:    {stats['max_ms']:.1f} ms")

    factor = effective_factor(baseline, args.threshold_factor)
    limit_ms = float(baseline["baseline_median_ms"]) * factor
    print(
        f"baseline: {float(baseline['baseline_median_ms']):.1f} ms "
        f"(fail above {limit_ms:.1f} ms)"
    )

    errors = regression_errors(stats, baseline, args.threshold_factor)
    payload = dashboard_payload(stats, baseline, target_label, limit_ms, factor, errors)
    json_path, html_path = write_dashboard(args.artifact_dir, payload)
    json_label = relative_target_label(json_path)
    html_label = relative_target_label(html_path)
    print(f"dashboard: {json_label}")
    print(f"dashboard: {html_label}")

    if args.update_baseline:
        baseline["baseline_median_ms"] = stats["median_ms"]
        baseline["target"] = target_label
        baseline["runner"] = "ubuntu-latest"
        if args.threshold_factor is not None:
            baseline["threshold_factor"] = args.threshold_factor
        args.baseline.write_text(
            json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"updated baseline: {args.baseline}")
        return 0

    if args.json_out is not None:
        payload_stats = dict(stats)
        payload_stats["baseline_median_ms"] = baseline["baseline_median_ms"]
        payload_stats["threshold_factor"] = factor
        payload_stats["limit_ms"] = limit_ms
        args.json_out.write_text(
            json.dumps(payload_stats, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
