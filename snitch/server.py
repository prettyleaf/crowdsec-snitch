"""Webhook receiver. It only persists alerts; the worker does the slow work."""

from __future__ import annotations

import hmac
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .config import Config
from .store import Store

log = logging.getLogger("snitch")

MAX_BODY = 16 * 1024 * 1024


def make_server(cfg: Config) -> ThreadingHTTPServer:
    local = threading.local()

    def store() -> Store:
        if not hasattr(local, "store"):
            local.store = Store(cfg.db_path)
        return local.store

    class Handler(BaseHTTPRequestHandler):
        timeout = 30

        def _reply(self, code: int) -> None:
            self.send_response(code)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True

        def do_GET(self):
            self._reply(200 if self.path == "/healthz" else 404)

        def do_POST(self):
            if self.path != "/alert":
                return self._reply(404)
            supplied = self.headers.get("Authorization", "").encode()
            expected = f"Bearer {cfg.token}".encode()
            if not hmac.compare_digest(supplied, expected):
                return self._reply(401)
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                return self._reply(411)
            if not 0 <= length <= MAX_BODY:
                return self._reply(413)
            try:
                alerts = json.loads(self.rfile.read(length))
            except ValueError:
                return self._reply(400)
            if not isinstance(alerts, list) or not all(isinstance(a, dict) for a in alerts):
                return self._reply(400)
            now = int(time.time())
            for alert in alerts:
                store().add_inbox(json.dumps(alert), now)
            log.info("received %d alert(s)", len(alerts))
            self._reply(202)

        def log_message(self, format, *args):
            pass  # Accepted alerts are logged above; no request details in logs.

    return ThreadingHTTPServer((cfg.listen_host, cfg.listen_port), Handler)
