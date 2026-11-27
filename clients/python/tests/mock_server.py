"""Small loopback HTTP server used by the client tests (stdlib only)."""

from __future__ import annotations

import json
import sys
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

Response = Tuple[int, Any, Dict[str, str]]
Handler = Callable[["RecordedRequest"], Response]


@dataclass(frozen=True)
class RecordedRequest:
    """One request received by the mock server."""

    method: str
    path: str
    headers: Dict[str, str]
    body: Any

    @property
    def authorization(self) -> Optional[str]:
        return self.headers.get("authorization")


class _QuietServer(ThreadingHTTPServer):
    """Ignores write failures caused by clients that time out mid-response."""

    daemon_threads = True

    def handle_error(self, request: Any, client_address: Any) -> None:
        error = sys.exc_info()[1]
        if isinstance(error, (ConnectionAbortedError, ConnectionResetError, BrokenPipeError)):
            return
        super().handle_error(request, client_address)


class MockServer:
    """A bounded, in-process HTTP server bound to ``127.0.0.1``."""

    def __init__(self, handler: Handler) -> None:
        self.handler = handler
        self.requests: List[RecordedRequest] = []
        self._lock = threading.Lock()
        outer = self

        class RequestHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
                outer._handle(self)

            def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
                outer._handle(self)

            def log_message(self, format: str, *args: Any) -> None:
                return

        self._httpd = _QuietServer(("127.0.0.1", 0), RequestHandler)
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )

    def __enter__(self) -> "MockServer":
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)

    @property
    def base_url(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"

    def reset(self) -> None:
        with self._lock:
            self.requests.clear()

    def _handle(self, handler: BaseHTTPRequestHandler) -> None:
        length = int(handler.headers.get("Content-Length", "0"))
        raw = handler.rfile.read(length) if length else b""
        body: Any = None
        if raw:
            body = json.loads(raw.decode("utf-8"))
        headers = {key.lower(): value for key, value in handler.headers.items()}
        recorded = RecordedRequest(
            method=handler.command,
            path=urlsplit(handler.path).path,
            headers=headers,
            body=body,
        )
        with self._lock:
            self.requests.append(recorded)

        status, payload, extra = self.handler(recorded)
        if isinstance(payload, bytes):
            content = payload
        else:
            content = json.dumps(payload).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(content)))
        for key, value in extra.items():
            handler.send_header(key, value)
        handler.end_headers()
        handler.wfile.write(content)
