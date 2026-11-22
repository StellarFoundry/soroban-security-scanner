"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { SorobanScanClient, ApiError, validateBaseUrl } = require("soroban-scan-client");
const { startServer, json } = require("./mock-server.cjs");

test("CommonJS entry point works end to end", async () => {
  const server = await startServer((req, res) => {
    if (req.method === "POST") {
      return json(res, 202, { id: "scan-1", status: "queued" });
    }
    if (req.url === "/v1/scans/missing") {
      return json(res, 404, { error: { code: "not_found", message: "no such scan" } });
    }
    return json(res, 200, { id: "scan-1", status: "succeeded" });
  });
  try {
    const client = new SorobanScanClient({ baseUrl: server.baseUrl, token: "cjs-token", timeoutMs: 2000 });
    const submission = await client.submitScan({ sources: [{ path: "src/lib.rs", content: "// x" }] });
    assert.equal(submission.id, "scan-1");
    assert.equal((await client.getScan("scan-1")).status, "succeeded");
    await assert.rejects(client.getScan("missing"), ApiError);
    assert.equal(validateBaseUrl("https://scan.example.com/"), "https://scan.example.com");
  } finally {
    await server.close();
  }
});
