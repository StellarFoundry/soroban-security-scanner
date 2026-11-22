import {
  ApiError,
  ClientTimeoutError,
  InvalidResponseError,
  PollTimeoutError,
  ResponseTooLargeError,
  ScanFailedError,
  SorobanScanError,
} from "./errors.js";
import { parseReport } from "./report.js";
import type {
  ClientOptions,
  PollOptions,
  Report,
  ScanState,
  ScanStatus,
  ScanSubmission,
  SubmitScanRequest,
  TokenProvider,
} from "./types.js";
import { isRecord, validateBaseUrl } from "./validate.js";

const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_TIMEOUT_MS = 300_000;
const DEFAULT_MAX_BYTES = 10 * 1024 * 1024;
const MAX_BYTES_LIMIT = 100 * 1024 * 1024;
const DEFAULT_POLL_INTERVAL_MS = 1_000;
const MAX_POLL_INTERVAL_MS = 60_000;
const DEFAULT_POLL_TIMEOUT_MS = 600_000;
const MAX_POLL_TIMEOUT_MS = 3_600_000;
const MAX_TOKEN_LENGTH = 4096;
const MAX_SOURCES = 5000;
const MAX_PATH_LENGTH = 1024;
const SCAN_STATES: readonly string[] = ["queued", "running", "succeeded", "failed"];
const ID_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;
const TOKEN_UNSAFE = /[\s\u0000-\u001f\u007f]/;

function boundedInteger(
  name: string,
  value: number | undefined,
  fallback: number,
  min: number,
  max: number,
): number {
  if (value === undefined) {
    return fallback;
  }
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new SorobanScanError(`${name} must be an integer between ${min} and ${max}`);
  }
  return value;
}

function assertToken(token: unknown): asserts token is string {
  if (
    typeof token !== "string" ||
    token.length === 0 ||
    token.length > MAX_TOKEN_LENGTH ||
    TOKEN_UNSAFE.test(token)
  ) {
    throw new SorobanScanError(
      "token must be a non-empty string without whitespace or control characters (max 4096 characters)",
    );
  }
}

function assertId(id: unknown): asserts id is string {
  if (typeof id !== "string" || !ID_PATTERN.test(id)) {
    throw new SorobanScanError("scan id must be 1-128 characters of A-Z, a-z, 0-9, '.', '_' or '-'");
  }
}

function truncate(text: string, max: number): string {
  return text.length > max ? text.slice(0, max) : text;
}

function parseState(value: unknown): ScanState {
  if (typeof value === "string" && SCAN_STATES.includes(value)) {
    return value as ScanState;
  }
  throw new InvalidResponseError("response contains an unknown scan status");
}

function validateSubmitRequest(request: SubmitScanRequest): void {
  const candidate: unknown = request;
  if (!isRecord(candidate)) {
    throw new SorobanScanError("scan request must be an object");
  }
  const sources = candidate.sources;
  if (!Array.isArray(sources) || sources.length === 0 || sources.length > MAX_SOURCES) {
    throw new SorobanScanError(`sources must be an array of 1 to ${MAX_SOURCES} files`);
  }
  for (const entry of sources) {
    if (!isRecord(entry)) {
      throw new SorobanScanError("each source must be an object with a path and content");
    }
    const path = entry.path;
    const content = entry.content;
    if (typeof path !== "string" || typeof content !== "string") {
      throw new SorobanScanError("each source must have a string path and string content");
    }
    if (
      path.length === 0 ||
      path.length > MAX_PATH_LENGTH ||
      path.startsWith("/") ||
      path.includes("\\") ||
      path.includes("\u0000") ||
      path.split("/").includes("..")
    ) {
      throw new SorobanScanError("source paths must be relative, use '/', and not contain '..'");
    }
  }
  const options = candidate.options;
  if (options !== undefined) {
    if (!isRecord(options)) {
      throw new SorobanScanError("options must be an object");
    }
    if (options.fail_on !== undefined && typeof options.fail_on !== "string") {
      throw new SorobanScanError("options.fail_on must be a string");
    }
  }
}

function parseSubmission(data: unknown): ScanSubmission {
  if (!isRecord(data)) {
    throw new InvalidResponseError("submission response must be a JSON object");
  }
  const id = data.id;
  if (typeof id !== "string" || !ID_PATTERN.test(id)) {
    throw new InvalidResponseError("submission response has an invalid scan id");
  }
  return { id, status: parseState(data.status) };
}

function parseScanStatus(data: unknown, expectedId: string): ScanStatus {
  if (!isRecord(data)) {
    throw new InvalidResponseError("scan status must be a JSON object");
  }
  if (data.id !== expectedId) {
    throw new InvalidResponseError("scan status id does not match the request");
  }
  const scan: ScanStatus = { id: expectedId, status: parseState(data.status) };
  if (typeof data.created_at === "string") {
    scan.created_at = data.created_at;
  }
  if (typeof data.updated_at === "string") {
    scan.updated_at = data.updated_at;
  }
  const err = data.error;
  if (isRecord(err) && typeof err.code === "string" && typeof err.message === "string") {
    scan.error = {
      code: truncate(err.code, 100),
      message: truncate(err.message, 500),
      details: err.details,
    };
  }
  return scan;
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal && signal.aborted) {
      reject(new SorobanScanError("polling was aborted"));
      return;
    }
    const onAbort = () => {
      clearTimeout(timer);
      reject(new SorobanScanError("polling was aborted"));
    };
    const timer = setTimeout(() => {
      if (signal) {
        signal.removeEventListener("abort", onAbort);
      }
      resolve();
    }, ms);
    if (signal) {
      signal.addEventListener("abort", onAbort, { once: true });
    }
  });
}

/**
 * Client for the soroban-scan service API described in
 * docs/integration/api.md: submit a scan, poll it, and fetch its report.
 */
export class SorobanScanClient {
  private readonly baseUrl: string;
  private readonly tokenProvider: TokenProvider;
  private readonly timeoutMs: number;
  private readonly maxResponseBytes: number;
  private readonly maxRequestBytes: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: ClientOptions) {
    if (typeof options !== "object" || options === null) {
      throw new SorobanScanError("client options are required");
    }
    this.baseUrl = validateBaseUrl(options.baseUrl);

    const token = options.token;
    if (typeof token === "string") {
      assertToken(token);
      this.tokenProvider = () => token;
    } else if (typeof token === "function") {
      this.tokenProvider = token;
    } else {
      throw new SorobanScanError("token must be a string or a function returning one");
    }

    this.timeoutMs = boundedInteger("timeoutMs", options.timeoutMs, DEFAULT_TIMEOUT_MS, 1, MAX_TIMEOUT_MS);
    this.maxResponseBytes = boundedInteger(
      "maxResponseBytes",
      options.maxResponseBytes,
      DEFAULT_MAX_BYTES,
      1,
      MAX_BYTES_LIMIT,
    );
    this.maxRequestBytes = boundedInteger(
      "maxRequestBytes",
      options.maxRequestBytes,
      DEFAULT_MAX_BYTES,
      1,
      MAX_BYTES_LIMIT,
    );

    if (options.fetch) {
      this.fetchImpl = options.fetch;
    } else if (typeof globalThis.fetch === "function") {
      this.fetchImpl = (input, init) => globalThis.fetch(input, init);
    } else {
      throw new SorobanScanError("no fetch implementation available (Node 18+ or pass options.fetch)");
    }
  }

  /** Submits sources for scanning. Returns the scan id and initial status. */
  async submitScan(request: SubmitScanRequest): Promise<ScanSubmission> {
    validateSubmitRequest(request);
    return parseSubmission(await this.request("POST", "/v1/scans", request));
  }

  /** Fetches the current status of a scan. */
  async getScan(id: string): Promise<ScanStatus> {
    assertId(id);
    return parseScanStatus(await this.request("GET", `/v1/scans/${id}`), id);
  }

  /** Fetches the report of a finished scan. */
  async getReport(id: string): Promise<Report> {
    assertId(id);
    return parseReport(await this.request("GET", `/v1/scans/${id}/report`));
  }

  /**
   * Polls until the scan succeeds, with a growing delay between polls.
   * Throws {@link ScanFailedError} if it fails and {@link PollTimeoutError} if
   * it does not finish within `timeoutMs`.
   */
  async waitForScan(id: string, options: PollOptions = {}): Promise<ScanStatus> {
    assertId(id);
    const interval = boundedInteger(
      "intervalMs",
      options.intervalMs,
      DEFAULT_POLL_INTERVAL_MS,
      1,
      MAX_POLL_INTERVAL_MS,
    );
    const timeout = boundedInteger(
      "timeoutMs",
      options.timeoutMs,
      DEFAULT_POLL_TIMEOUT_MS,
      1,
      MAX_POLL_TIMEOUT_MS,
    );
    const deadline = Date.now() + timeout;
    let delay = interval;

    for (;;) {
      const scan = await this.getScan(id);
      if (scan.status === "succeeded") {
        return scan;
      }
      if (scan.status === "failed") {
        throw new ScanFailedError(scan);
      }
      if (Date.now() + delay > deadline) {
        throw new PollTimeoutError(`scan ${id} did not finish within ${timeout} ms`);
      }
      await sleep(delay, options.signal);
      delay = Math.min(Math.ceil(delay * 1.5), MAX_POLL_INTERVAL_MS);
    }
  }

  /** Convenience: submit, wait for completion, and return the report. */
  async scan(request: SubmitScanRequest, poll?: PollOptions): Promise<Report> {
    const submission = await this.submitScan(request);
    await this.waitForScan(submission.id, poll);
    return this.getReport(submission.id);
  }

  private async request(method: "GET" | "POST", path: string, body?: unknown): Promise<unknown> {
    const token = await this.tokenProvider();
    assertToken(token);

    let payload: string | undefined;
    if (body !== undefined) {
      payload = JSON.stringify(body);
      if (new TextEncoder().encode(payload).byteLength > this.maxRequestBytes) {
        throw new SorobanScanError("request body exceeds the configured size limit");
      }
    }

    const headers: Record<string, string> = {
      Accept: "application/json",
      Authorization: `Bearer ${token}`,
    };
    if (payload !== undefined) {
      headers["Content-Type"] = "application/json";
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      let response: Response;
      try {
        response = await this.fetchImpl(`${this.baseUrl}${path}`, {
          method,
          headers,
          body: payload,
          signal: controller.signal,
          // Never follow redirects: they could carry the bearer token elsewhere.
          redirect: "error",
        });
      } catch (error) {
        throw this.transportError(error, controller);
      }

      let text: string;
      try {
        text = await this.readBody(response);
      } catch (error) {
        if (error instanceof SorobanScanError) {
          throw error;
        }
        throw this.transportError(error, controller);
      }

      if (!response.ok) {
        throw this.apiError(response.status, text);
      }
      if (text.length === 0) {
        throw new InvalidResponseError("response body is empty");
      }
      try {
        return JSON.parse(text) as unknown;
      } catch {
        throw new InvalidResponseError("response body is not valid JSON");
      }
    } finally {
      clearTimeout(timer);
    }
  }

  private transportError(error: unknown, controller: AbortController): SorobanScanError {
    if (controller.signal.aborted) {
      return new ClientTimeoutError(`request timed out after ${this.timeoutMs} ms`);
    }
    return new SorobanScanError("request failed", { cause: error });
  }

  private async readBody(response: Response): Promise<string> {
    const declared = Number(response.headers.get("content-length"));
    if (Number.isFinite(declared) && declared > this.maxResponseBytes) {
      await this.discard(response);
      throw new ResponseTooLargeError("response body exceeds the configured size limit");
    }
    if (!response.body) {
      return "";
    }
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const result = await reader.read();
      if (result.done) {
        break;
      }
      const chunk = result.value;
      total += chunk.byteLength;
      if (total > this.maxResponseBytes) {
        await reader.cancel();
        throw new ResponseTooLargeError("response body exceeds the configured size limit");
      }
      chunks.push(chunk);
    }
    const merged = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      merged.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return new TextDecoder("utf-8").decode(merged);
  }

  private async discard(response: Response): Promise<void> {
    try {
      if (response.body) {
        await response.body.cancel();
      }
    } catch {
      // Nothing useful to do if the stream cannot be cancelled.
    }
  }

  private apiError(status: number, text: string): ApiError {
    let code = `http_${status}`;
    let message = `HTTP ${status}`;
    let details: unknown;
    try {
      const parsed: unknown = JSON.parse(text);
      if (isRecord(parsed)) {
        const err = parsed.error;
        if (isRecord(err)) {
          if (typeof err.code === "string" && err.code.length > 0) {
            code = truncate(err.code, 100);
          }
          if (typeof err.message === "string" && err.message.length > 0) {
            message = truncate(err.message, 500);
          }
          details = err.details;
        }
      }
    } catch {
      // Not JSON: keep the generic status-based error.
    }
    return new ApiError(status, { code, message, details });
  }
}
