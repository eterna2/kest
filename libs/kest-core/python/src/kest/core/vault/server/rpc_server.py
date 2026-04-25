"""
VaultRPCServer — XML-RPC vault service (stdlib xmlrpc.server).

Registered methods::

    vault.seal(data, owner_principal, safe_view, ttl_seconds, granted_principals)
    vault.unseal(handle_id, requesting_principal)
    vault.invalidate(handle_id)
    vault.get_safe_view(handle_id)

Errors are returned as ``xmlrpc.client.Fault``:
  404 — handle not found
  410 — handle expired
  403 — access denied
  400 — bad request
"""

from __future__ import annotations

import threading
import xmlrpc.client
from typing import Any, Optional
from xmlrpc.server import SimpleXMLRPCServer

from kest.core.vault import HandleVault
from kest.core.vault.errors import (
    HandleAccessDeniedError,
    HandleExpiredError,
    HandleNotFoundError,
)
from kest.core.vault.server._codec import handle_to_dict


class _VaultRPCMethods:
    """Registered instance for the XML-RPC server."""

    def __init__(self, vault: HandleVault) -> None:
        self._vault = vault

    def seal(
        self,
        data: Any,
        owner_principal: str,
        safe_view: str,
        ttl_seconds: int = 300,
        granted_principals: Optional[list] = None,
    ) -> dict:
        handle = self._vault.seal(
            data=data,
            owner_principal=owner_principal,
            safe_view=safe_view,
            ttl_seconds=int(ttl_seconds),
            granted_principals=tuple(granted_principals or []),
        )
        return handle_to_dict(handle)

    def unseal(self, handle_id: str, requesting_principal: str) -> Any:
        try:
            return self._vault.unseal(handle_id, requesting_principal)
        except HandleNotFoundError as exc:
            raise xmlrpc.client.Fault(404, str(exc)) from exc
        except HandleExpiredError as exc:
            raise xmlrpc.client.Fault(410, str(exc)) from exc
        except HandleAccessDeniedError as exc:
            raise xmlrpc.client.Fault(403, str(exc)) from exc

    def invalidate(self, handle_id: str) -> bool:
        self._vault.invalidate(handle_id)
        return True

    def get_safe_view(self, handle_id: str) -> str:
        try:
            return self._vault.get_safe_view(handle_id)
        except HandleNotFoundError as exc:
            raise xmlrpc.client.Fault(404, str(exc)) from exc
        except HandleExpiredError as exc:
            raise xmlrpc.client.Fault(410, str(exc)) from exc


class VaultRPCServer:
    """
    Embeddable XML-RPC vault server.

    Args:
        vault: The ``HandleVault`` to expose. A new default vault is created
            if not provided.
        host: Bind address (default ``"localhost"``).
        port: TCP port (default ``8422``).

    Example::

        srv = VaultRPCServer(port=8422)
        srv.start()
        # ... use xmlrpc.client.ServerProxy to call methods ...
        srv.stop()
    """

    def __init__(
        self,
        vault: Optional[HandleVault] = None,
        host: str = "localhost",
        port: int = 8422,
    ) -> None:
        self._vault = vault if vault is not None else HandleVault()
        self._host = host
        self._port = port
        self._server: Optional[SimpleXMLRPCServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def vault(self) -> HandleVault:
        return self._vault

    def start(self) -> None:
        """Start serving in a daemon thread."""
        self._server = SimpleXMLRPCServer(
            (self._host, self._port),
            logRequests=False,
            allow_none=True,
        )
        self._server.register_instance(_VaultRPCMethods(self._vault))
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True, name="VaultRPCServer"
        )
        self._thread.start()

    def stop(self) -> None:
        """Shut down the server."""
        if self._server is not None:
            self._server.shutdown()
            self._server = None
