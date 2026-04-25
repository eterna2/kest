"""
VaultSocketServer — JSON-RPC 2.0 vault service over TCP or Unix socket.

Protocol: 4-byte big-endian length prefix + UTF-8 JSON body.

Request::

    {"method": "seal", "params": {...}, "id": 1}

Response::

    {"result": {...}, "id": 1}
    {"error": {"code": -32001, "message": "..."}, "id": 1}

Error codes:
  -32001 — HandleNotFoundError
  -32002 — HandleExpiredError
  -32003 — HandleAccessDeniedError
  -32600 — Invalid request / unexpected error
"""

from __future__ import annotations

import json
import os
import socket
import socketserver
import struct
import threading
from typing import Any, Optional, Union

from kest.core.vault import HandleVault
from kest.core.vault.errors import (
    HandleAccessDeniedError,
    HandleExpiredError,
    HandleNotFoundError,
)
from kest.core.vault.server._codec import handle_to_dict

_LENGTH_FMT = ">I"  # 4-byte big-endian unsigned int


def _send_msg(sock: socket.socket, data: dict) -> None:
    body = json.dumps(data).encode()
    sock.sendall(struct.pack(_LENGTH_FMT, len(body)) + body)


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed")
        buf.extend(chunk)
    return bytes(buf)


def _recv_msg(sock: socket.socket) -> dict:
    header = _recv_exactly(sock, 4)
    length = struct.unpack(_LENGTH_FMT, header)[0]
    return json.loads(_recv_exactly(sock, length))


class _VaultSocketHandler(socketserver.BaseRequestHandler):
    """Connection handler — vault injected as class attribute."""

    vault: HandleVault

    def handle(self) -> None:
        while True:
            try:
                msg = _recv_msg(self.request)  # type: ignore[arg-type]
            except (ConnectionError, struct.error, json.JSONDecodeError):
                break
            response = self._dispatch(msg)
            try:
                _send_msg(self.request, response)  # type: ignore[arg-type]
            except Exception:
                break

    def _dispatch(self, msg: dict) -> dict:
        req_id = msg.get("id")
        method = msg.get("method", "")
        params = msg.get("params", {})
        try:
            result = self._call(method, params)
            return {"result": result, "id": req_id}
        except HandleNotFoundError as exc:
            return {"error": {"code": -32001, "message": str(exc)}, "id": req_id}
        except HandleExpiredError as exc:
            return {"error": {"code": -32002, "message": str(exc)}, "id": req_id}
        except HandleAccessDeniedError as exc:
            return {"error": {"code": -32003, "message": str(exc)}, "id": req_id}
        except Exception as exc:
            return {"error": {"code": -32600, "message": str(exc)}, "id": req_id}

    def _call(self, method: str, params: dict) -> Any:
        vault = self.vault
        if method == "seal":
            handle = vault.seal(
                data=params["data"],
                owner_principal=params["owner_principal"],
                safe_view=params["safe_view"],
                ttl_seconds=int(params.get("ttl_seconds", 300)),
                granted_principals=tuple(params.get("granted_principals", [])),
            )
            return handle_to_dict(handle)
        elif method == "unseal":
            return vault.unseal(params["handle_id"], params["requesting_principal"])
        elif method == "invalidate":
            vault.invalidate(params["handle_id"])
            return True
        elif method == "get_safe_view":
            return vault.get_safe_view(params["handle_id"])
        else:
            raise ValueError(f"Unknown method: {method!r}")


class VaultSocketServer:
    """
    Embeddable vault server over TCP or Unix domain socket.

    Args:
        vault: The ``HandleVault`` to expose. A new default vault is created
            if not provided.
        address: ``(host, port)`` tuple for TCP, or a filesystem path string
            for a Unix domain socket (Linux/macOS only).

    Examples::

        # TCP
        srv = VaultSocketServer(address=("localhost", 8423))

        # Unix domain socket
        srv = VaultSocketServer(address="/tmp/kest-vault.sock")

        srv.start()
        # ... srv.stop()
    """

    def __init__(
        self,
        vault: Optional[HandleVault] = None,
        address: Union[tuple, str] = ("localhost", 8423),
    ) -> None:
        self._vault = vault if vault is not None else HandleVault()
        self._address = address
        self._server: Optional[socketserver.BaseServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def vault(self) -> HandleVault:
        return self._vault

    def start(self) -> None:
        """Start serving in a daemon thread."""
        Handler = type("Handler", (_VaultSocketHandler,), {"vault": self._vault})
        if isinstance(self._address, str):
            self._server = socketserver.UnixStreamServer(self._address, Handler)
        else:
            server = socketserver.TCPServer(self._address, Handler)
            server.allow_reuse_address = True
            self._server = server

        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True, name="VaultSocketServer"
        )
        self._thread.start()

    def stop(self) -> None:
        """Shut down the server and remove the socket file if Unix mode."""
        if self._server is not None:
            self._server.shutdown()
            if isinstance(self._address, str):
                try:
                    os.unlink(self._address)
                except FileNotFoundError:
                    pass
            self._server = None
