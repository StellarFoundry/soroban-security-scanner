import { InvalidResponseError } from "./errors.js";
import type { Report } from "./types.js";
import { isRecord } from "./validate.js";

export const SUPPORTED_REPORT_SCHEMA_VERSION = "1";

/**
 * Checks that a value has the shape of a report (`schema_version` "1") and
 * returns it typed. This is a structural sanity check of the required
 * top-level fields, not a full JSON Schema validation.
 */
export function parseReport(value: unknown): Report {
  if (!isRecord(value)) {
    throw new InvalidResponseError("report must be a JSON object");
  }
  if (value.schema_version !== SUPPORTED_REPORT_SCHEMA_VERSION) {
    throw new InvalidResponseError("unsupported report schema_version");
  }
  for (const key of ["tool", "project", "stats", "effective_config"] as const) {
    if (!isRecord(value[key])) {
      throw new InvalidResponseError(`report is missing the "${key}" object`);
    }
  }
  const findings = value.findings;
  if (!Array.isArray(findings)) {
    throw new InvalidResponseError('report is missing the "findings" array');
  }
  if (!("diagnostics" in value)) {
    throw new InvalidResponseError('report is missing "diagnostics"');
  }
  for (const finding of findings) {
    if (!isRecord(finding) || typeof finding.rule_id !== "string" || typeof finding.severity !== "string") {
      throw new InvalidResponseError("report contains a malformed finding");
    }
  }
  return value as unknown as Report;
}
