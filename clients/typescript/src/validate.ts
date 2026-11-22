import { InvalidBaseUrlError } from "./errors.js";

const MAX_URL_LENGTH = 2048;
const UNSAFE_CHARS = /[\s\u0000-\u001f\u007f]/;

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isLoopback(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname === "[::1]" ||
    /^127(?:\.\d{1,3}){3}$/.test(hostname)
  );
}

/**
 * Validates an API base URL and returns its normalized form (no trailing slash).
 *
 * Accepted: `https` URLs, plus plain `http` for loopback hosts only (local mock
 * servers). Rejected: other schemes, embedded credentials, query strings,
 * fragments, whitespace/control characters and URLs over 2048 characters.
 * Error messages never include the URL, so a secret pasted into it by mistake
 * cannot leak into logs.
 */
export function validateBaseUrl(value: unknown): string {
  if (typeof value !== "string") {
    throw new InvalidBaseUrlError("base URL must be a string");
  }
  const raw = value.trim();
  if (raw.length === 0) {
    throw new InvalidBaseUrlError("base URL must not be empty");
  }
  if (raw.length > MAX_URL_LENGTH) {
    throw new InvalidBaseUrlError("base URL is too long");
  }
  if (UNSAFE_CHARS.test(raw)) {
    throw new InvalidBaseUrlError("base URL must not contain whitespace or control characters");
  }
  if (raw.includes("?") || raw.includes("#")) {
    throw new InvalidBaseUrlError("base URL must not contain a query string or fragment");
  }

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new InvalidBaseUrlError("base URL is not a valid absolute URL");
  }

  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new InvalidBaseUrlError("base URL must use https");
  }
  if (url.protocol === "http:" && !isLoopback(url.hostname)) {
    throw new InvalidBaseUrlError("base URL must use https (http is allowed only for loopback hosts)");
  }
  if (url.username !== "" || url.password !== "") {
    throw new InvalidBaseUrlError("base URL must not embed credentials");
  }

  const path = url.pathname.replace(/\/+$/, "");
  return `${url.origin}${path}`;
}
