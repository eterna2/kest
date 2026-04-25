"""
VaultHTTPServer — REST vault service over HTTP (stdlib http.server).

Endpoints::

    POST   /handles                  → seal
    POST   /handles/{id}/unseal      → unseal
    DELETE /handles/{id}             → invalidate
    GET    /handles/{id}/safe_view   → get_safe_view

All request/response bodies are JSON.  Error format: ``{"error": "<message>"}``.

HTTP status codes:
  201 — sealed successfully
  200 — ok
  400 — bad request (missing fields)
  403 — access denied
  404 — handle not found
  410 — handle expired
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional
from urllib.parse import urlparse

from kest.core.vault import HandleVault
from kest.core.vault.errors import (
    HandleAccessDeniedError,
    HandleExpiredError,
    HandleNotFoundError,
)
from kest.core.vault.server._codec import handle_to_dict


class _VaultHTTPHandler(BaseHTTPRequestHandler):
    """Request handler — vault is injected as a class attribute."""

    vault: HandleVault

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass  # suppress default stderr logging

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length))

    def _send_json(self, status: int, data: object) -> None:
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, message: str) -> None:
        self._send_json(status, {"error": message})

    # ------------------------------------------------------------------
    # Route dispatch
    # ------------------------------------------------------------------

    def do_POST(self) -> None:
        path = urlparse(self.path).path.rstrip("/")

        # POST /handles → seal
        if path == "/handles":
            try:
                body = self._read_body()
                handle = self.vault.seal(
                    data=body["data"],
                    owner_principal=body["owner_principal"],
                    safe_view=body["safe_view"],
                    ttl_seconds=int(body.get("ttl_seconds", 300)),
                    granted_principals=tuple(body.get("granted_principals", [])),
                )
                self._send_json(201, handle_to_dict(handle))
            except (KeyError, TypeError) as exc:
                self._error(400, f"Bad request: {exc}")
            return

        # POST /handles/{id}/unseal → unseal
        parts = path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "handles" and parts[2] == "unseal":
            handle_id = parts[1]
            try:
                body = self._read_body()
                data = self.vault.unseal(handle_id, body["requesting_principal"])
                self._send_json(200, {"data": data})
            except HandleNotFoundError:
                self._error(404, "Handle not found")
            except HandleExpiredError:
                self._error(410, "Handle expired")
            except HandleAccessDeniedError:
                self._error(403, "Access denied")
            except (KeyError, TypeError) as exc:
                self._error(400, f"Bad request: {exc}")
            return

        self._error(404, "Not found")

    def do_GET(self) -> None:
        parts = urlparse(self.path).path.strip("/").split("/")
        # GET /handles/{id}/safe_view
        if len(parts) == 3 and parts[0] == "handles" and parts[2] == "safe_view":
            handle_id = parts[1]
            try:
                sv = self.vault.get_safe_view(handle_id)
                self._send_json(200, {"safe_view": sv})
            except HandleNotFoundError:
                self._error(404, "Handle not found")
            except HandleExpiredError:
                self._error(410, "Handle expired")
            return
        self._error(404, "Not found")

    def do_DELETE(self) -> None:
        parts = urlparse(self.path).path.strip("/").split("/")
        # DELETE /handles/{id}
        if len(parts) == 2 and parts[0] == "handles":
            self.vault.invalidate(parts[1])
            self._send_json(200, {"ok": True})
            return
        self._error(404, "Not found")


class VaultHTTPServer:
    """
    Embeddable HTTP vault server.

    Args:
        vault: The ``HandleVault`` to expose. A new default vault is created
            if not provided.
        host: Bind address (default ``"localhost"``).
        port: TCP port (default ``8421``).

    Example::

        srv = VaultHTTPServer(port=8421)
        srv.start()
        # ... handle requests ...
        srv.stop()
    """

    def __init__(
        self,
        vault: Optional[HandleVault] = None,
        host: str = "localhost",
        port: int = 8421,
    ) -> None:
        self._vault = vault if vault is not None else HandleVault()
        self._host = host
        self._port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def vault(self) -> HandleVault:
        return self._vault

    def start(self) -> None:
        """Start serving in a daemon thread."""
        Handler = type("Handler", (_VaultHTTPHandler,), {"vault": self._vault})
        self._server = HTTPServer((self._host, self._port), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True, name="VaultHTTPServer"
        )
        self._thread.start()

    def stop(self) -> None:
        """Shut down the server."""
        if self._server is not None:
            self._server.shutdown()
            self._server = None
