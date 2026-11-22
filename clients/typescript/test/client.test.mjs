import test from "node:test";
import assert from "node:assert/strict";
import {
  ApiError,
  ClientTimeoutError,
  InvalidBaseUrlError,
  InvalidResponseError,
  PollTimeoutError,
  ResponseTooLargeError,
  ScanFailedError,
  SorobanScanClient,
  SorobanScanError,
  parseReport,
  validateBaseUrl,
} from "soroban-scan-client";
import mock from "./mock-server.cjs";

const { startServer, json } = mock;
const TOKEN = "test-token-123";
const REQUEST = { source: "pub fn f() {}", file: "lib.rs" };

function sampleReport() {
  return {
    schema_version: "1",
    tool: { name: "soroban-scan", version: "0.1.0", information_uri: "https://example.com" },
    project: { root: ".", kind: "confirmed_soroban", source_files: 1, soroban_sdk_versions: ["21.7.7"] },
    stats: { files_analyzed: 1, rules_run: 1, rules_skipped: 0, findings_raw: 1, findings_rejected: 0 },
    effective_config: {},
    findings: [
      { rule_id: "SS-001", severity: "high", title: "Missing authorization", location: { file: "lib.rs", line: 3 } },
    ],
    diagnostics: [],
  };
}

async function withServer(handler, run) {
  const server = await startServer(handler);
  try {
    await run(server);
  } finally {
    await server.close();
  }
}

function newClient(server, extra = {}) {
  return new SorobanScanClient({ baseUrl: server.baseUrl, token: TOKEN, timeoutMs: 2000, ...extra });
}

test("validateBaseUrl accepts https and loopback http and normalizes", () => {
  assert.equal(validateBaseUrl("https://scan.example.com"), "https://scan.example.com");
  assert.equal(validateBaseUrl("https://scan.example.com/"), "https://scan.example.com");
  assert.equal(validateBaseUrl("https://scan.example.com/api/"), "https://scan.example.com/api");
  assert.equal(validateBaseUrl("  https://Scan.Example.com:8443  "), "https://scan.example.com:8443");
  assert.equal(validateBaseUrl("http://localhost:8080"), "http://localhost:8080");
  assert.equal(validateBaseUrl("http://127.0.0.1:9000"), "http://127.0.0.1:9000");
  assert.equal(validateBaseUrl("http://[::1]:9000"), "http://[::1]:9000");
});

test("validateBaseUrl rejects unsafe or malformed URLs", () => {
  const bad = [
    "",
    "   ",
    undefined,
    42,
    "scan.example.com",
    "ftp://scan.example.com",
    "javascript:alert(1)",
    "http://scan.example.com",
    "http://localhost.evil.com",
    "http://127.0.0.1.evil.com",
    "https://user:pass@scan.example.com",
    "https://scan.example.com?x=1",
    "https://scan.example.com/#frag",
    "https://scan example.com",
    "https://" + "a".repeat(3000) + ".com",
  ];
  for (const value of bad) {
    assert.throws(() => validateBaseUrl(value), InvalidBaseUrlError, String(value));
  }
});

test("validateBaseUrl errors never include the URL", () => {
  assert.throws(
    () => validateBaseUrl("https://user:s3cr3t@scan.example.com"),
    (error) => error instanceof InvalidBaseUrlError && !error.message.includes("s3cr3t"),
  );
});

test("constructor validates its options", () => {
  const base = { baseUrl: "https://scan.example.com" };
  assert.throws(() => new SorobanScanClient({ ...base, token: "" }), SorobanScanError);
  assert.throws(() => new SorobanScanClient({ ...base, token: "has space" }), SorobanScanError);
  assert.throws(() => new SorobanScanClient({ ...base, token: "line\nbreak" }), SorobanScanError);
  assert.throws(() => new SorobanScanClient({ ...base, token: 5 }), SorobanScanError);
  assert.throws(() => new SorobanScanClient({ ...base, token: TOKEN, timeoutMs: 0 }), SorobanScanError);
  assert.throws(() => new SorobanScanClient({ ...base, token: TOKEN, maxResponseBytes: -1 }), SorobanScanError);
  assert.throws(() => new SorobanScanClient({ baseUrl: "http://scan.example.com", token: TOKEN }), InvalidBaseUrlError);
});

test("submitScan posts source and file with bearer auth", async () => {
  await withServer(
    (req, res) => json(res, 202, { job_id: "job-1", status: "queued" }),
    async (server) => {
      const submission = await newClient(server).submitScan(REQUEST);
      assert.deepEqual(submission, { job_id: "job-1", status: "queued" });
      const [request] = server.requests;
      assert.equal(request.method, "POST");
      assert.equal(request.url, "/v1/scans");
      assert.equal(request.headers.authorization, `Bearer ${TOKEN}`);
      assert.match(request.headers["content-type"], /application\/json/);
      assert.deepEqual(request.body, { source: "pub fn f() {}", file: "lib.rs" });
    },
  );
});

test("submitScan omits file when it is not given", async () => {
  await withServer(
    (req, res) => json(res, 202, { job_id: "job-1", status: "queued" }),
    async (server) => {
      await newClient(server).submitScan({ source: "pub fn f() {}" });
      assert.deepEqual(server.requests[0].body, { source: "pub fn f() {}" });
    },
  );
});

test("submitScan rejects bad requests without sending anything", async () => {
  await withServer(
    (req, res) => json(res, 202, { job_id: "job-1", status: "queued" }),
    async (server) => {
      const client = newClient(server, { maxRequestBytes: 64 });
      const bad = [
        undefined,
        {},
        { source: "" },
        { source: 5 },
        { source: "x", file: "../a.rs" },
        { source: "x", file: "a/b.rs" },
        { source: "x", file: "a\\b.rs" },
        { source: "x", file: "notes.txt" },
        { source: "x", file: "a..b.rs" },
        { source: "x", file: 5 },
        { source: "x".repeat(500) },
      ];
      for (const request of bad) {
        await assert.rejects(client.submitScan(request), SorobanScanError);
      }
      assert.equal(server.requests.length, 0);
    },
  );
});

test("getJob rejects unsafe ids locally", async () => {
  await withServer(
    (req, res) => json(res, 200, {}),
    async (server) => {
      const client = newClient(server);
      for (const id of ["../etc", "a/b", "", "x".repeat(200), "a b"]) {
        await assert.rejects(client.getJob(id), SorobanScanError);
      }
      assert.equal(server.requests.length, 0);
    },
  );
});

test("API errors become ApiError and never leak the token", async () => {
  await withServer(
    (req, res) => json(res, 401, { error: { code: "unauthorized", message: "missing or invalid bearer token" } }),
    async (server) => {
      await assert.rejects(newClient(server).getJob("job-1"), (error) => {
        assert.ok(error instanceof ApiError);
        assert.equal(error.status, 401);
        assert.equal(error.code, "unauthorized");
        assert.ok(!error.message.includes(TOKEN));
        return true;
      });
    },
  );
});

test("documented error codes map to ApiError", async () => {
  const cases = [
    [400, "invalid_request"],
    [413, "payload_too_large"],
    [503, "store_full"],
    [503, "authentication_not_configured"],
    [404, "not_found"],
  ];
  for (const [status, code] of cases) {
    await withServer(
      (req, res) => json(res, status, { error: { code, message: "x" } }),
      async (server) => {
        await assert.rejects(newClient(server).submitScan(REQUEST), (error) => {
          assert.ok(error instanceof ApiError);
          assert.equal(error.status, status);
          assert.equal(error.code, code);
          return true;
        });
      },
    );
  }
});

test("non-JSON error bodies fall back to a status-based error", async () => {
  await withServer(
    (req, res) => {
      res.writeHead(502, { "content-type": "text/html" });
      res.end("<html>bad gateway</html>");
    },
    async (server) => {
      await assert.rejects(newClient(server).getJob("job-1"), (error) => {
        assert.ok(error instanceof ApiError);
        assert.equal(error.code, "http_502");
        assert.ok(!error.message.includes("<html>"));
        return true;
      });
    },
  );
});

test("getJob reads queued, running and completed jobs", async () => {
  let polls = 0;
  await withServer(
    (req, res) => {
      polls += 1;
      if (polls === 1) return json(res, 202, { job_id: "job-1", status: "queued" });
      if (polls === 2) return json(res, 202, { job_id: "job-1", status: "running" });
      return json(res, 200, { job_id: "job-1", status: "completed", report: sampleReport() });
    },
    async (server) => {
      const client = newClient(server);
      assert.equal((await client.getJob("job-1")).status, "queued");
      assert.equal((await client.getJob("job-1")).status, "running");
      const done = await client.getJob("job-1");
      assert.equal(done.status, "completed");
      assert.equal(done.report.findings[0].rule_id, "SS-001");
      assert.equal(server.requests[0].url, "/v1/jobs/job-1");
    },
  );
});

test("a 202 response without a status is treated as still running", async () => {
  await withServer(
    (req, res) => json(res, 202, { job_id: "job-1" }),
    async (server) => {
      assert.equal((await newClient(server).getJob("job-1")).status, "running");
    },
  );
});

test("a report delivered as a JSON string is parsed", async () => {
  await withServer(
    (req, res) => json(res, 200, { job_id: "job-1", status: "completed", report: JSON.stringify(sampleReport()) }),
    async (server) => {
      const job = await newClient(server).getJob("job-1");
      assert.equal(job.report.schema_version, "1");
    },
  );
});

test("job responses with a mismatched id or missing report are rejected", async () => {
  await withServer(
    (req, res) => json(res, 200, { job_id: "other", status: "running" }),
    async (server) => {
      await assert.rejects(newClient(server).getJob("job-1"), InvalidResponseError);
    },
  );
  await withServer(
    (req, res) => json(res, 200, { job_id: "job-1", status: "completed" }),
    async (server) => {
      await assert.rejects(newClient(server).getJob("job-1"), InvalidResponseError);
    },
  );
  await withServer(
    (req, res) => json(res, 200, { job_id: "job-1", status: "weird" }),
    async (server) => {
      await assert.rejects(newClient(server).getJob("job-1"), InvalidResponseError);
    },
  );
});

test("waitForJob polls until the job completes", async () => {
  let polls = 0;
  await withServer(
    (req, res) => {
      polls += 1;
      if (polls === 1) return json(res, 202, { job_id: "job-1", status: "queued" });
      if (polls === 2) return json(res, 202, { job_id: "job-1", status: "running" });
      return json(res, 200, { job_id: "job-1", status: "completed", report: sampleReport() });
    },
    async (server) => {
      const job = await newClient(server).waitForJob("job-1", { intervalMs: 10, timeoutMs: 5000 });
      assert.equal(job.status, "completed");
      assert.equal(job.report.findings.length, 1);
      assert.equal(polls, 3);
    },
  );
});

test("waitForJob throws ScanFailedError for a failed job", async () => {
  await withServer(
    (req, res) => json(res, 200, { job_id: "job-1", status: "failed", error: { code: "analysis_failed", message: "boom" } }),
    async (server) => {
      await assert.rejects(newClient(server).waitForJob("job-1", { intervalMs: 10 }), (error) => {
        assert.ok(error instanceof ScanFailedError);
        assert.equal(error.job.error.code, "analysis_failed");
        return true;
      });
    },
  );
});

test("waitForJob times out with PollTimeoutError", async () => {
  await withServer(
    (req, res) => json(res, 202, { job_id: "job-1", status: "running" }),
    async (server) => {
      await assert.rejects(
        newClient(server).waitForJob("job-1", { intervalMs: 10, timeoutMs: 80 }),
        PollTimeoutError,
      );
    },
  );
});

test("waitForJob can be aborted", async () => {
  await withServer(
    (req, res) => json(res, 202, { job_id: "job-1", status: "running" }),
    async (server) => {
      const controller = new AbortController();
      const promise = newClient(server).waitForJob("job-1", { intervalMs: 50, timeoutMs: 5000, signal: controller.signal });
      setTimeout(() => controller.abort(), 20);
      await assert.rejects(promise, SorobanScanError);
    },
  );
});

test("getReport returns the report of a completed job and rejects unfinished ones", async () => {
  await withServer(
    (req, res) => json(res, 200, { job_id: "job-1", status: "completed", report: sampleReport() }),
    async (server) => {
      const report = await newClient(server).getReport("job-1");
      assert.equal(report.schema_version, "1");
    },
  );
  await withServer(
    (req, res) => json(res, 202, { job_id: "job-1", status: "running" }),
    async (server) => {
      await assert.rejects(newClient(server).getReport("job-1"), SorobanScanError);
    },
  );
});

test("parseReport rejects malformed reports", () => {
  const broken = [
    { ...sampleReport(), schema_version: "2" },
    { ...sampleReport(), findings: "nope" },
    { ...sampleReport(), findings: [{ title: "no rule id" }] },
    { schema_version: "1" },
  ];
  for (const report of broken) {
    assert.throws(() => parseReport(report), InvalidResponseError);
  }
  assert.throws(() => parseReport("text"), InvalidResponseError);
});

test("scan() submits, waits, and returns the report", async () => {
  let polls = 0;
  await withServer(
    (req, res) => {
      if (req.method === "POST" && req.url === "/v1/scans") {
        return json(res, 202, { job_id: "job-9", status: "queued" });
      }
      if (req.url === "/v1/jobs/job-9") {
        polls += 1;
        return polls < 2
          ? json(res, 202, { job_id: "job-9", status: "running" })
          : json(res, 200, { job_id: "job-9", status: "completed", report: sampleReport() });
      }
      return json(res, 404, { error: { code: "not_found", message: "no such route" } });
    },
    async (server) => {
      const report = await newClient(server).scan(REQUEST, { intervalMs: 10 });
      assert.equal(report.findings.length, 1);
      assert.deepEqual(
        server.requests.map((request) => `${request.method} ${request.url}`),
        ["POST /v1/scans", "GET /v1/jobs/job-9", "GET /v1/jobs/job-9"],
      );
      assert.ok(server.requests.every((request) => request.headers.authorization === `Bearer ${TOKEN}`));
    },
  );
});

test("a token provider function is called for every request", async () => {
  let calls = 0;
  await withServer(
    (req, res) => json(res, 202, { job_id: "job-1", status: "running" }),
    async (server) => {
      const client = newClient(server, {
        token: async () => {
          calls += 1;
          return `token-${calls}`;
        },
      });
      await client.getJob("job-1");
      await client.getJob("job-1");
      assert.equal(calls, 2);
      assert.equal(server.requests[0].headers.authorization, "Bearer token-1");
      assert.equal(server.requests[1].headers.authorization, "Bearer token-2");
    },
  );
});

test("oversized responses are rejected", async () => {
  await withServer(
    (req, res) => json(res, 202, { job_id: "job-1", status: "running", pad: "x".repeat(1000) }),
    async (server) => {
      await assert.rejects(newClient(server, { maxResponseBytes: 100 }).getJob("job-1"), ResponseTooLargeError);
    },
  );
});

test("requests time out with ClientTimeoutError", async () => {
  await withServer(
    () => {
      // Never respond.
    },
    async (server) => {
      await assert.rejects(newClient(server, { timeoutMs: 50 }).getJob("job-1"), ClientTimeoutError);
    },
  );
});

test("redirects are refused so the token cannot leak", async () => {
  await withServer(
    (req, res) => {
      res.writeHead(302, { location: "http://127.0.0.1:1/elsewhere" });
      res.end();
    },
    async (server) => {
      await assert.rejects(newClient(server).getJob("job-1"), SorobanScanError);
      assert.equal(server.requests.length, 1);
    },
  );
});

test("an invalid JSON success body is an InvalidResponseError", async () => {
  await withServer(
    (req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end("not json");
    },
    async (server) => {
      await assert.rejects(newClient(server).getJob("job-1"), InvalidResponseError);
    },
  );
});
