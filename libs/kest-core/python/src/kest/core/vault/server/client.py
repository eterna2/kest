"""
VaultClient — unified client for all three vault service transports.

Usage::

    from kest.core.vault.server import VaultClient

    client = VaultClient.http("http://localhost:8421")
    client = VaultClient.rpc("localhost", 8422)
    client = VaultClient.socket(("localhost", 8423))       # TCP
    client = VaultClient.socket("/tmp/kest-vault.sock")   # Unix

    handle = client.seal(data=..., owner_principal=..., safe_view=...)
    data   = client.unseal(handle["id"], requesting_principal=...)
    client.invalidate(handle["id"])
    sv     = client.get_safe_view(handle["id"])
"""

from __future__ import annotations

import json
import socket
import struct
import urllib.error
import urllib.request
import xmlrpc.client
from typing import Any, NoReturn, Union

from kest.core.vault.errors import (
    HandleAccessDeniedError,
    HandleExpiredError,
    HandleNotFoundError,
)

_LENGTH_FMT = ">I"


def _map_http_error(status: int, message: str) -> NoReturn:
    if status == 404:
        raise HandleNotFoundError(message)
    if status == 410:
        raise HandleExpiredError(message)
    if status == 403:
        raise HandleAccessDeniedError(message)
    raise RuntimeError(f"HTTP {status}: {message}")


def _map_rpc_fault(fault: xmlrpc.client.Fault) -> NoReturn:
    if fault.faultCode == 404:
        raise HandleNotFoundError(fault.faultString)
    if fault.faultCode == 410:
        raise HandleExpiredError(fault.faultString)
    if fault.faultCode == 403:
        raise HandleAccessDeniedError(fault.faultString)
    raise RuntimeError(f"RPC fault {fault.faultCode}: {fault.faultString}")


def _map_socket_error(code: int, message: str) -> NoReturn:
    if code == -32001:
        raise HandleNotFoundError(message)
    if code == -32002:
        raise HandleExpiredError(message)
    if code == -32003:
        raise HandleAccessDeniedError(message)
    raise RuntimeError(f"Socket error {code}: {message}")


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class VaultClient:
    """Base client — use the factory classmethods to select a transport."""

    def seal(
        self,
        data: Any,
        owner_principal: str,
        safe_view: str,
        ttl_seconds: int = 300,
        granted_principals: Union[list, tuple] = (),
    ) -> dict:
        raise NotImplementedError

    def unseal(self, handle_id: str, requesting_principal: str) -> Any:
        raise NotImplementedError

    def invalidate(self, handle_id: str) -> None:
        raise NotImplementedError

    def get_safe_view(self, handle_id: str) -> str:
        raise NotImplementedError

    @classmethod
    def http(cls, base_url: str) -> "VaultClient":
        """Create an HTTP transport client."""
        return _HTTPVaultClient(base_url)

    @classmethod
    def rpc(cls, host: str, port: int) -> "VaultClient":
        """Create an XML-RPC transport client."""
        return _RPCVaultClient(host, port)

    @classmethod
    def socket(cls, address: Union[str, tuple]) -> "VaultClient":
        """Create a socket transport client (TCP or Unix domain)."""
        return _SocketVaultClient(address)


# ---------------------------------------------------------------------------
# HTTP client (stdlib urllib)
# ---------------------------------------------------------------------------


class _HTTPVaultClient(VaultClient):
    def __init__(self, base_url: str) -> None:
        self._base = base_url.rstrip("/")

    def _request(self, method: str, path: str, body: Any = None) -> Any:
        url = f"{self._base}{path}"
        data = json.dumps(body).encode() if body is not None else b""
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("Content-Length", str(len(data)))
        try:
            with urllib.request.urlopen(req) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            error_body = json.loads(exc.read())
            _map_http_error(exc.code, error_body.get("error", "Unknown"))

    def seal(  # type: ignore[override]
        self, data, owner_principal, safe_view, ttl_seconds=300, granted_principals=()
    ) -> dict:
        return self._request(
            "POST",
            "/handles",
            {
                "data": data,
                "owner_principal": owner_principal,
                "safe_view": safe_view,
                "ttl_seconds": ttl_seconds,
                "granted_principals": list(granted_principals),
            },
        )

    def unseal(self, handle_id, requesting_principal):
        result = self._request(
            "POST",
            f"/handles/{handle_id}/unseal",
            {"requesting_principal": requesting_principal},
        )
        return result["data"]

    def invalidate(self, handle_id):
        self._request("DELETE", f"/handles/{handle_id}")

    def get_safe_view(self, handle_id) -> str:
        result = self._request("GET", f"/handles/{handle_id}/safe_view")
        return result["safe_view"]  # type: ignore[index]


# ---------------------------------------------------------------------------
# XML-RPC client (stdlib xmlrpc.client)
# ---------------------------------------------------------------------------


class _RPCVaultClient(VaultClient):
    def __init__(self, host: str, port: int) -> None:
        self._proxy = xmlrpc.client.ServerProxy(
            f"http://{host}:{port}", allow_none=True
        )

    def _call(self, fn, *args):
        try:
            return fn(*args)
        except xmlrpc.client.Fault as exc:
            _map_rpc_fault(exc)

    def seal(
        self, data, owner_principal, safe_view, ttl_seconds=300, granted_principals=()
    ):
        return self._call(
            self._proxy.seal,
            data,
            owner_principal,
            safe_view,
            ttl_seconds,
            list(granted_principals),
        )

    def unseal(self, handle_id, requesting_principal):
        return self._call(self._proxy.unseal, handle_id, requesting_principal)

    def invalidate(self, handle_id):
        self._call(self._proxy.invalidate, handle_id)

    def get_safe_view(self, handle_id) -> str:
        result = self._call(self._proxy.get_safe_view, handle_id)
        return result  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Socket client (stdlib socket)
# ---------------------------------------------------------------------------


class _SocketVaultClient(VaultClient):
    def __init__(self, address: Union[str, tuple]) -> None:
        self._address = address
        self._counter = 0

    def _connect(self) -> socket.socket:
        if isinstance(self._address, str):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(self._address)
        return sock

    def _call(self, method: str, params: dict) -> Any:
        self._counter += 1
        req = {"method": method, "params": params, "id": self._counter}
        sock = self._connect()
        try:
            body = json.dumps(req).encode()
            sock.sendall(struct.pack(_LENGTH_FMT, len(body)) + body)
            header = self._recv_exactly(sock, 4)
            length = struct.unpack(_LENGTH_FMT, header)[0]
            resp = json.loads(self._recv_exactly(sock, length))
        finally:
            sock.close()

        if "error" in resp:
            err = resp["error"]
            _map_socket_error(err["code"], err["message"])
        return resp["result"]

    @staticmethod
    def _recv_exactly(sock: socket.socket, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Connection closed")
            buf.extend(chunk)
        return bytes(buf)

    def seal(
        self, data, owner_principal, safe_view, ttl_seconds=300, granted_principals=()
    ):
        return self._call(
            "seal",
            {
                "data": data,
                "owner_principal": owner_principal,
                "safe_view": safe_view,
                "ttl_seconds": ttl_seconds,
                "granted_principals": list(granted_principals),
            },
        )

    def unseal(self, handle_id, requesting_principal):
        return self._call(
            "unseal",
            {
                "handle_id": handle_id,
                "requesting_principal": requesting_principal,
            },
        )

    def invalidate(self, handle_id):
        self._call("invalidate", {"handle_id": handle_id})

    def get_safe_view(self, handle_id):
        return self._call("get_safe_view", {"handle_id": handle_id})
