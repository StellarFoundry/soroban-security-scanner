"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { SorobanScanClient, ApiError, validateBaseUrl } = require("soroban-scan-client");
const { startServer, json } = require("./mock-server.cjs");

const report = {
  schema_version: "1",
  tool: { name: "soroban-scan", version: "0.1.0", information_uri: "https://example.com" },
  project: { root: ".", kind: "confirmed_soroban", source_files: 1, soroban_sdk_versions: [] },
  stats: { files_analyzed: 1, rules_run: 1, rules_skipped: 0, findings_raw: 0, findings_rejected: 0 },
  effective_config: {},
  findings: [],
  diagnostics: [],
};

test("CommonJS entry point works end to end", async () => {
  const server = await startServer((req, res) => {
    if (req.method === "POST") {
      return json(res, 202, { job_id: "job-1", status: "queued" });
    }
    if (req.url === "/v1/jobs/missing") {
      return json(res, 404, { error: { code: "not_found", message: "no such job" } });
    }
    return json(res, 200, { job_id: "job-1", status: "completed", report });
  });
  try {
    const client = new SorobanScanClient({ baseUrl: server.baseUrl, token: "cjs-token", timeoutMs: 2000 });
    const submission = await client.submitScan({ source: "pub fn f() {}", file: "lib.rs" });
    assert.equal(submission.job_id, "job-1");
    assert.equal((await client.getJob("job-1")).status, "completed");
    await assert.rejects(client.getJob("missing"), ApiError);
    assert.equal(validateBaseUrl("https://scan.example.com/"), "https://scan.example.com");
  } finally {
    await server.close();
  }
});
