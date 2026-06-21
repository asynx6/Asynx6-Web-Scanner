"""Collaborator HTTP server — listens for OOB callbacks from SSRF.

This is a minimal in-memory implementation. For production use, deploy behind
a real public domain with proper DNS records (a wildcard A record pointing
to this server).

Routes:
    GET /<token>/             -> 200 OK (always responds, records token)
    GET /<token>/<path>       -> 200 OK
    GET /__poll__/<token>     -> 200 if hit, 404 if not
"""

from __future__ import annotations

import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

log = logging.getLogger(__name__)


class _CollaboratorState:
    """Thread-safe shared state for the server."""

    def __init__(self) -> None:
        self._hits: dict[str, list[dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def record_hit(self, token: str, source: str, path: str) -> None:
        with self._lock:
            self._hits.setdefault(token, []).append({
                "source": source,
                "path": path,
                "timestamp": time.time(),
            })

    def was_hit(self, token: str) -> bool:
        with self._lock:
            return token in self._hits and bool(self._hits[token])

    def hits(self, token: str) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._hits.get(token, []))


class _Handler(BaseHTTPRequestHandler):
    """HTTP handler that logs every incoming request as a potential SSRF hit."""

    # Class-level shared state, injected by the server factory.
    state: _CollaboratorState = _CollaboratorState()  # type: ignore[assignment]

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # Silence stderr noise; hits are already logged.
        return

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.lstrip("/")
        parts = path.split("/", 1)
        token = parts[0] if parts else ""
        if not token:
            self._send(404, b"missing token")
            return
        if token == "__poll__":
            target = parts[1] if len(parts) > 1 else ""
            if self.state.was_hit(target):
                self._send(200, b"hit")
            else:
                self._send(404, b"miss")
            return
        # Real callback — record the hit.
        self.state.record_hit(token, source=self.client_address[0], path=self.path)
        log.info("Collaborator hit: token=%s source=%s path=%s",
                 token, self.client_address[0], self.path)
        self._send(200, b"ok")

    def _send(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)


class CollaboratorServer:
    """Self-contained HTTP collaborator server for OOB SSRF detection."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8089) -> None:
        self.host = host
        self.port = port
        self.state = _CollaboratorState()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the server in a background thread."""
        if self._server is not None:
            return
        # Share state with the handler class
        _Handler.state = self.state

        class _BoundHandler(_Handler):
            pass

        self._server = ThreadingHTTPServer((self.host, self.port), _BoundHandler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="asynx6-collaborator",
            daemon=True,
        )
        self._thread.start()
        log.info("Collaborator listening on %s:%d", self.host, self.port)

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
            self._thread = None
        log.info("Collaborator stopped")

    def __enter__(self) -> "CollaboratorServer":
        self.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()