"""Client tests against a real loopback HTTP server (stdlib unittest only)."""

from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path
from typing import Any, Callable, Dict, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from soroban_scan_client import (  # noqa: E402
    ApiError,
    ClientTimeoutError,
    InvalidBaseUrlError,
    InvalidResponseError,
    JobNotFinishedError,
    PollTimeoutError,
    RedirectError,
    ResponseTooLargeError,
    ScanFailedError,
    SorobanScanClient,
    SorobanScanError,
    TransportError,
    validate_base_url,
)

from mock_server import MockServer, RecordedRequest  # noqa: E402

TOKEN = "test-token-123"
Response = Tuple[int, Any, Dict[str, str]]
Handler = Callable[[RecordedRequest], Response]


def sample_report() -> Dict[str, Any]:
    return {
        "schema_version": "1",
        "tool": {"name": "soroban-scan", "version": "0.1.0", "information_uri": "https://example.com"},
        "project": {"root": ".", "kind": "confirmed_soroban", "source_files": 1, "soroban_sdk_versions": []},
        "stats": {"files_analyzed": 1, "rules_run": 1, "rules_skipped": 0, "findings_raw": 1, "findings_rejected": 0},
        "effective_config": {},
        "findings": [{"rule_id": "SS-001", "severity": "high", "title": "Missing authorization"}],
        "diagnostics": [],
    }


def scripted(*responses: Response) -> Handler:
    iterator = iter(responses)

    def handler(_: RecordedRequest) -> Response:
        return next(iterator)

    return handler


def error_body(code: str, message: str) -> Dict[str, Any]:
    return {"error": {"code": code, "message": message}}


class ClientTestCase(unittest.TestCase):
    def make_client(self, server: MockServer, **options: Any) -> SorobanScanClient:
        defaults: Dict[str, Any] = {
            "timeout": 2.0,
            "retry_backoff": 0.001,
            "max_retry_delay": 0.01,
        }
        defaults.update(options)
        return SorobanScanClient(server.base_url, TOKEN, **defaults)


class ValidationTests(unittest.TestCase):
    def test_base_url_validation(self) -> None:
        self.assertEqual(validate_base_url("https://scan.example.com"), "https://scan.example.com")
        self.assertEqual(validate_base_url("https://scan.example.com/"), "https://scan.example.com")
        self.assertEqual(validate_base_url("https://scan.example.com/api/"), "https://scan.example.com/api")
        self.assertEqual(validate_base_url("http://127.0.0.1:9000"), "http://127.0.0.1:9000")
        self.assertEqual(validate_base_url("http://[::1]:9000"), "http://[::1]:9000")
        bad = [
            "",
            None,
            42,
            "scan.example.com",
            "ftp://scan.example.com",
            "http://scan.example.com",
            "http://localhost.evil.com",
            "http://127.0.0.1.evil.com",
            "https://user:s3cr3t@scan.example.com",
            "https://scan.example.com?x=1",
            "https://scan.example.com/#frag",
            "https://scan example.com",
            "https://" + "a" * 3000 + ".com",
        ]
        for value in bad:
            with self.subTest(value=str(value)[:40]), self.assertRaises(InvalidBaseUrlError):
                validate_base_url(value)

    def test_base_url_errors_never_include_the_secret(self) -> None:
        with self.assertRaises(InvalidBaseUrlError) as caught:
            validate_base_url("https://user:s3cr3t@scan.example.com")
        self.assertNotIn("s3cr3t", str(caught.exception))

    def test_constructor_rejects_unsafe_options(self) -> None:
        base = "https://scan.example.com"
        for token in ("", "has space", "line\nbreak", 5):
            with self.subTest(token=token), self.assertRaises(SorobanScanError):
                SorobanScanClient(base, token)  # type: ignore[arg-type]
        with self.assertRaises(SorobanScanError):
            SorobanScanClient(base, TOKEN, timeout=0)
        with self.assertRaises(SorobanScanError):
            SorobanScanClient(base, TOKEN, max_retries=6)
        with self.assertRaises(SorobanScanError):
            SorobanScanClient(base, TOKEN, max_response_bytes=-1)
        with self.assertRaises(SorobanScanError):
            SorobanScanClient(base, TOKEN, retry_backoff=10.0)


class ServiceApiTests(ClientTestCase):
    def test_submit_scan_posts_source_with_bearer_auth(self) -> None:
        with MockServer(scripted((202, {"job_id": "job-1", "status": "queued"}, {}))) as server:
            submission = self.make_client(server).submit_scan(
                {"source": "pub fn f() {}", "file": "lib.rs"}
            )
            self.assertEqual(submission, {"job_id": "job-1", "status": "queued"})
            self.assertEqual(len(server.requests), 1)
            request = server.requests[0]
            self.assertEqual((request.method, request.path), ("POST", "/v1/scans"))
            self.assertEqual(request.authorization, f"Bearer {TOKEN}")
            self.assertEqual(request.body, {"source": "pub fn f() {}", "file": "lib.rs"})

    def test_submit_scan_rejects_unsafe_requests_without_sending(self) -> None:
        with MockServer(scripted((202, {"job_id": "job-1"}, {}))) as server:
            client = self.make_client(server, max_request_bytes=64)
            bad = [
                None,
                {},
                {"source": ""},
                {"source": "x", "file": "../a.rs"},
                {"source": "x", "file": "a/b.rs"},
                {"source": "x", "file": "notes.txt"},
                {"source": "x" * 500},
            ]
            for request in bad:
                with self.subTest(request=str(request)[:30]), self.assertRaises(SorobanScanError):
                    client.submit_scan(request)  # type: ignore[arg-type]
            self.assertEqual(server.requests, [])

    def test_get_job_reads_queued_running_and_completed(self) -> None:
        responses = [
            (202, {"job_id": "job-1", "status": "queued"}, {}),
            (202, {"job_id": "job-1", "status": "running"}, {}),
            (200, {"job_id": "job-1", "status": "completed", "report": sample_report()}, {}),
        ]
        with MockServer(scripted(*responses)) as server:
            client = self.make_client(server)
            self.assertEqual(client.get_job("job-1")["status"], "queued")
            self.assertEqual(client.get_job("job-1")["status"], "running")
            done = client.get_job("job-1")
            self.assertEqual(done["status"], "completed")
            self.assertEqual(done["report"]["findings"][0]["rule_id"], "SS-001")
            self.assertTrue(all(r.path == "/v1/jobs/job-1" for r in server.requests))

    def test_job_ids_are_validated_before_a_request(self) -> None:
        with MockServer(scripted((200, {}, {}))) as server:
            client = self.make_client(server)
            for job_id in ("../etc", "a/b", "", "x" * 200, "a b"):
                with self.subTest(job_id=job_id), self.assertRaises(SorobanScanError):
                    client.get_job(job_id)
            self.assertEqual(server.requests, [])

    def test_wait_for_job_polls_until_complete(self) -> None:
        responses = [
            (202, {"job_id": "job-1", "status": "queued"}, {}),
            (202, {"job_id": "job-1", "status": "running"}, {}),
            (200, {"job_id": "job-1", "status": "completed", "report": sample_report()}, {}),
        ]
        with MockServer(scripted(*responses)) as server:
            completed = self.make_client(server).wait_for_job(
                "job-1", interval_ms=5, timeout_ms=2000
            )
            self.assertEqual(completed["status"], "completed")
            self.assertEqual(len(completed["report"]["findings"]), 1)
            self.assertEqual(len(server.requests), 3)

    def test_wait_for_job_times_out(self) -> None:
        handler: Handler = lambda _: (202, {"job_id": "job-1", "status": "running"}, {})
        with MockServer(handler) as server:
            with self.assertRaises(PollTimeoutError):
                self.make_client(server).wait_for_job("job-1", interval_ms=5, timeout_ms=20)

    def test_failed_job_raises_typed_error(self) -> None:
        failed = error_body("analysis_failed", "boom")
        with MockServer(scripted((200, {"job_id": "job-1", "status": "failed", "error": failed["error"]}, {}))) as server:
            with self.assertRaises(ScanFailedError) as caught:
                self.make_client(server).wait_for_job("job-1", interval_ms=5)
            self.assertEqual(caught.exception.job["error"]["code"], "analysis_failed")

    def test_get_report_rejects_unfinished_job(self) -> None:
        with MockServer(scripted((202, {"job_id": "job-1", "status": "running"}, {}))) as server:
            with self.assertRaises(JobNotFinishedError):
                self.make_client(server).get_report("job-1")

    def test_get_report_falls_back_to_dedicated_route(self) -> None:
        responses = [
            (200, {"job_id": "job-1", "status": "done", "created_at": "x", "expires_at": "y"}, {}),
            (200, sample_report(), {}),
        ]
        with MockServer(scripted(*responses)) as server:
            report = self.make_client(server).get_report("job-1")
            self.assertEqual(report["schema_version"], "1")
            self.assertEqual(
                [r.path for r in server.requests],
                ["/v1/jobs/job-1", "/v1/jobs/job-1/report"],
            )


class ErrorAndRetryTests(ClientTestCase):
    def test_api_error_is_typed_and_never_leaks_the_token(self) -> None:
        message = f"missing or invalid bearer token: {TOKEN}"
        with MockServer(scripted((401, error_body("unauthorized", message), {}))) as server:
            with self.assertRaises(ApiError) as caught:
                self.make_client(server).get_job("job-1")
            error = caught.exception
            self.assertEqual(error.status, 401)
            self.assertEqual(error.code, "unauthorized")
            self.assertNotIn(TOKEN, str(error))

    def test_document_error_codes(self) -> None:
        for status, code in (
            (400, "invalid_request"),
            (404, "job_not_found"),
            (413, "payload_too_large"),
            (503, "store_full"),
            (429, "rate_limited"),
        ):
            with self.subTest(code=code):
                with MockServer(scripted((status, error_body(code, "x"), {}))) as server:
                    with self.assertRaises(ApiError) as caught:
                        self.make_client(server).submit_scan({"source": "x"})
                    self.assertEqual(caught.exception.code, code)

    def test_non_json_error_body_uses_status_code(self) -> None:
        with MockServer(scripted((502, b"<html>bad gateway</html>", {}))) as server:
            with self.assertRaises(ApiError) as caught:
                self.make_client(server, max_retries=0).get_job("job-1")
            self.assertEqual(caught.exception.code, "http_502")
            self.assertNotIn("<html>", str(caught.exception))

    def test_idempotent_get_retries_but_post_does_not(self) -> None:
        responses = [
            (503, error_body("store_full", "busy"), {}),
            (200, {"job_id": "job-1", "status": "queued"}, {}),
        ]
        with MockServer(scripted(*responses)) as server:
            job = self.make_client(server, max_retries=1).get_job("job-1")
            self.assertEqual(job["status"], "queued")
            self.assertEqual(len(server.requests), 2)
            self.assertTrue(all(r.method == "GET" for r in server.requests))

            server.handler = scripted((503, error_body("store_full", "busy"), {}))
            server.reset()
            with self.assertRaises(ApiError):
                self.make_client(server, max_retries=3).submit_scan({"source": "x"})
            self.assertEqual(len(server.requests), 1)

    def test_retry_exhaustion_raises_last_error(self) -> None:
        with MockServer(scripted((503, error_body("store_full", "busy"), {}), (503, error_body("store_full", "busy"), {}))) as server:
            with self.assertRaises(ApiError) as caught:
                self.make_client(server, max_retries=1).get_job("job-1")
            self.assertEqual(caught.exception.status, 503)
            self.assertEqual(len(server.requests), 2)

    def test_retries_can_be_disabled(self) -> None:
        with MockServer(scripted((503, error_body("store_full", "busy"), {}))) as server:
            with self.assertRaises(ApiError):
                self.make_client(server, max_retries=0).get_job("job-1")
            self.assertEqual(len(server.requests), 1)

    def test_retry_after_header_is_bounded(self) -> None:
        responses = [
            (429, error_body("rate_limited", "slow down"), {"Retry-After": "100"}),
            (200, {"job_id": "job-1", "status": "queued"}, {}),
        ]
        started = time.monotonic()
        with MockServer(scripted(*responses)) as server:
            self.assertEqual(self.make_client(server).get_job("job-1")["status"], "queued")
            self.assertEqual(len(server.requests), 2)
        self.assertLess(time.monotonic() - started, 1.0)

    def test_redirects_are_refused(self) -> None:
        def handler(_: RecordedRequest) -> Response:
            return 302, b"", {"Location": "http://127.0.0.1:1/elsewhere"}

        with MockServer(handler) as server:
            with self.assertRaises(RedirectError):
                self.make_client(server).get_job("job-1")
            self.assertEqual(len(server.requests), 1)

    def test_oversized_response_is_rejected(self) -> None:
        body = {"job_id": "job-1", "status": "running", "pad": "x" * 1000}
        with MockServer(scripted((200, body, {}))) as server:
            with self.assertRaises(ResponseTooLargeError):
                self.make_client(server, max_response_bytes=100).get_job("job-1")

    def test_request_timeout_is_typed(self) -> None:
        def handler(_: RecordedRequest) -> Response:
            time.sleep(0.3)
            return 200, {"job_id": "job-1", "status": "queued"}, {}

        with MockServer(handler) as server:
            with self.assertRaises(ClientTimeoutError):
                self.make_client(server, timeout=0.02).get_job("job-1")

    def test_token_provider_is_called_for_every_request(self) -> None:
        calls = []

        def token_provider() -> str:
            calls.append(1)
            return f"token-{len(calls)}"

        responses = [
            (200, {"job_id": "job-1", "status": "queued"}, {}),
            (200, {"job_id": "job-1", "status": "queued"}, {}),
        ]
        with MockServer(scripted(*responses)) as server:
            client = SorobanScanClient(
                server.base_url,
                token_provider,
                timeout=2.0,
                retry_backoff=0.001,
                max_retry_delay=0.01,
            )
            client.get_job("job-1")
            self.assertEqual(len(calls), 1)
            client.get_job("job-1")
            self.assertEqual(len(calls), 2)
            self.assertEqual(server.requests[-1].authorization, "Bearer token-2")

    def test_invalid_success_bodies_are_typed(self) -> None:
        with MockServer(scripted((200, {"job_id": "other", "status": "queued"}, {}))) as server:
            with self.assertRaises(InvalidResponseError):
                self.make_client(server).get_job("job-1")
        with MockServer(scripted((200, {"job_id": "job-1", "status": "weird"}, {}))) as server:
            with self.assertRaises(InvalidResponseError):
                self.make_client(server).get_job("job-1")
        with MockServer(scripted((200, {**sample_report(), "schema_version": "2"}, {}))) as server:
            with self.assertRaises(InvalidResponseError):
                self.make_client(server).fetch_report("job-1")


class OpenApiSurfaceTests(ClientTestCase):
    def test_all_documented_openapi_routes(self) -> None:
        def handler(request: RecordedRequest) -> Response:
            path = request.path
            if path == "/v1/health":
                return 200, {"status": "ok", "tool": "soroban-scan", "version": "0.1.0"}, {}
            if path == "/v1/scan":
                return 200, sample_report(), {}
            if path == "/v1/jobs" and request.method == "POST":
                return 202, {
                    "job_id": "job-1",
                    "status": "queued",
                    "created_at": "2026-01-01T00:00:00Z",
                    "expires_at": "2026-01-02T00:00:00Z",
                }, {}
            if path == "/v1/jobs/job-1" and request.method == "GET":
                return 200, {
                    "job_id": "job-1",
                    "status": "done",
                    "created_at": "2026-01-01T00:00:00Z",
                    "expires_at": "2026-01-02T00:00:00Z",
                }, {}
            if path == "/v1/jobs/job-1/report":
                return 200, sample_report(), {}
            if path == "/v1/rules":
                return 200, {"rules": [self.rule()]}, {}
            if path == "/v1/rules/SS-001":
                return 200, self.rule(), {}
            return 404, error_body("not_found", "no such route"), {}

        scan_request = {"files": [{"path": "src/lib.rs", "content": "pub fn f() {}"}]}
        with MockServer(handler) as server:
            client = self.make_client(server)
            self.assertEqual(client.health()["status"], "ok")
            self.assertEqual(client.scan(scan_request)["schema_version"], "1")
            self.assertEqual(client.submit_job({"scan": scan_request, "ttl_seconds": 120})["status"], "queued")
            self.assertEqual(client.get_job_status("job-1")["job_id"], "job-1")
            self.assertEqual(client.fetch_report("job-1")["schema_version"], "1")
            self.assertEqual(len(client.list_rules()), 1)
            self.assertEqual(client.get_rule("SS-001")["id"], "SS-001")
            self.assertEqual(
                [r.path for r in server.requests],
                [
                    "/v1/health",
                    "/v1/scan",
                    "/v1/jobs",
                    "/v1/jobs/job-1",
                    "/v1/jobs/job-1/report",
                    "/v1/rules",
                    "/v1/rules/SS-001",
                ],
            )
            self.assertIsNone(server.requests[0].authorization)
            self.assertTrue(all(r.authorization == f"Bearer {TOKEN}" for r in server.requests[1:]))

    def test_openapi_inputs_are_validated(self) -> None:
        with MockServer(scripted((200, {}, {}))) as server:
            client = self.make_client(server)
            bad_scans = [
                {"files": []},
                {"files": [{"path": "../lib.rs", "content": "x"}]},
                {"files": [{"path": "lib.rs", "content": "x" * 300000}]},
                {"files": [{"path": "lib.rs", "content": "x"}], "mode": "magic"},
            ]
            for request in bad_scans:
                with self.subTest(request=str(request)[:30]), self.assertRaises(SorobanScanError):
                    client.scan(request)
            with self.assertRaises(SorobanScanError):
                client.submit_job({"scan": {"files": [{"path": "lib.rs", "content": "x"}]}, "ttl_seconds": 1})
            with self.assertRaises(SorobanScanError):
                client.get_rule("SS-ABCD")
            self.assertEqual(server.requests, [])

    @staticmethod
    def rule() -> Dict[str, Any]:
        return {
            "id": "SS-001",
            "title": "Missing authorization",
            "description": "A check is missing.",
            "default_severity": "high",
            "default_confidence": "high",
            "category": "authorization",
            "remediation": "Add a check.",
            "references": [],
        }


if __name__ == "__main__":
    unittest.main()
