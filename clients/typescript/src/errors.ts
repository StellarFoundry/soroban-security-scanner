import type { ApiErrorBody, ScanStatus } from "./types.js";

/** Base class for every error thrown by this package. */
export class SorobanScanError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message);
    this.name = new.target.name;
    if (options && options.cause !== undefined) {
      Object.defineProperty(this, "cause", {
        value: options.cause,
        enumerable: false,
        writable: true,
        configurable: true,
      });
    }
  }
}

export class InvalidBaseUrlError extends SorobanScanError {}

export class InvalidResponseError extends SorobanScanError {}

export class ClientTimeoutError extends SorobanScanError {}

export class ResponseTooLargeError extends SorobanScanError {}

export class PollTimeoutError extends SorobanScanError {}

/** The server answered with a non-2xx status. */
export class ApiError extends SorobanScanError {
  readonly status: number;
  readonly code: string;
  readonly details: unknown;

  constructor(status: number, body: ApiErrorBody) {
    super(`${body.code}: ${body.message} (HTTP ${status})`);
    this.status = status;
    this.code = body.code;
    this.details = body.details;
  }
}

/** The scan reached the `failed` state. */
export class ScanFailedError extends SorobanScanError {
  readonly scan: ScanStatus;

  constructor(scan: ScanStatus) {
    super(
      scan.error
        ? `scan ${scan.id} failed: ${scan.error.code}: ${scan.error.message}`
        : `scan ${scan.id} failed`,
    );
    this.scan = scan;
  }
}
