/** Finding severity. Unknown future values are preserved as plain strings. */
export type Severity = "info" | "low" | "medium" | "high" | "critical" | (string & {});

export interface ReportTool {
  name: string;
  version: string;
  information_uri: string;
  [key: string]: unknown;
}

export interface ReportProject {
  root: string;
  kind: "generic_rust" | "likely_soroban" | "confirmed_soroban";
  source_files: number;
  soroban_sdk_versions: string[];
  [key: string]: unknown;
}

export interface ReportStats {
  files_analyzed: number;
  rules_run: number;
  rules_skipped: number;
  findings_raw: number;
  findings_rejected: number;
  mode?: "soroban" | "generic";
  suppressions_detected?: number;
  findings_suppressed?: number;
  [key: string]: unknown;
}

export interface FindingLocation {
  file: string;
  line?: number;
  [key: string]: unknown;
}

export interface Finding {
  rule_id: string;
  severity: Severity;
  title?: string;
  confidence?: string;
  description?: string;
  evidence?: string;
  remediation?: string;
  location?: FindingLocation;
  [key: string]: unknown;
}

/**
 * The JSON report described by docs/integration/report.schema.json
 * (`schema_version` "1"). Unknown extra fields are preserved.
 */
export interface Report {
  schema_version: "1";
  tool: ReportTool;
  project: ReportProject;
  stats: ReportStats;
  effective_config: Record<string, unknown>;
  findings: Finding[];
  diagnostics: unknown[];
  [key: string]: unknown;
}

/** Job lifecycle from docs/service-api.md: queued -> running -> completed | failed. */
export type JobStatus = "queued" | "running" | "completed" | "failed";

/** Structured error body: `{"error": {"code", "message"}}`. */
export interface ApiErrorBody {
  code: string;
  message: string;
  details?: unknown;
}

/** Body of `POST /v1/scans`. `file` defaults to `input.rs` on the server. */
export interface SubmitScanRequest {
  /** Rust source to scan. */
  source: string;
  /** A plain `.rs` file name such as `lib.rs` (no directories). */
  file?: string;
}

/** Response of `POST /v1/scans` (HTTP 202). */
export interface ScanSubmission {
  job_id: string;
  status: JobStatus;
}

/** Response of `GET /v1/jobs/{id}`. */
export interface Job {
  job_id: string;
  status: JobStatus;
  /** Present when `status` is `completed`. */
  report?: Report;
  /** Present when `status` is `failed`. */
  error?: ApiErrorBody;
}

export interface CompletedJob extends Job {
  status: "completed";
  report: Report;
}

export type TokenProvider = () => string | Promise<string>;

export interface ClientOptions {
  /** API base URL. HTTPS only, except loopback hosts. No credentials, query or fragment. */
  baseUrl: string;
  /** Bearer token, or a function returning one (called before every request). */
  token: string | TokenProvider;
  /** Per-request timeout in milliseconds (default 30000, max 300000). */
  timeoutMs?: number;
  /** Maximum response body size in bytes (default 10 MiB, max 100 MiB). */
  maxResponseBytes?: number;
  /** Maximum request body size in bytes (default 1 MiB, the service default; max 100 MiB). */
  maxRequestBytes?: number;
  /** Custom fetch implementation (defaults to the global fetch). */
  fetch?: typeof fetch;
}

export interface PollOptions {
  /** Initial delay between polls in milliseconds (default 1000, max 60000). */
  intervalMs?: number;
  /** Total time to wait in milliseconds (default 600000, max 3600000). */
  timeoutMs?: number;
  /** Aborts polling. */
  signal?: AbortSignal;
}
