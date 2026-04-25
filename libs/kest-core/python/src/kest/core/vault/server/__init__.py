"""
kest.core.vault.server — Vault service transports.

Three embeddable servers expose a ``HandleVault`` over the network:

- ``VaultHTTPServer`` — REST/JSON over HTTP (stdlib ``http.server``)
- ``VaultRPCServer``  — XML-RPC (stdlib ``xmlrpc.server``)
- ``VaultSocketServer`` — JSON-RPC 2.0 over TCP or Unix domain socket

``VaultClient`` provides a unified client API for all three transports::

    from kest.core.vault.server import VaultClient, VaultHTTPServer

    srv = VaultHTTPServer(port=8421)
    srv.start()

    client = VaultClient.http("http://localhost:8421")
    handle = client.seal(data=..., owner_principal=..., safe_view=...)
    data   = client.unseal(handle["id"], requesting_principal=...)
    srv.stop()
"""

from kest.core.vault.server.client import VaultClient
from kest.core.vault.server.http_server import VaultHTTPServer
from kest.core.vault.server.rpc_server import VaultRPCServer
from kest.core.vault.server.socket_server import VaultSocketServer

__all__ = [
    "VaultHTTPServer",
    "VaultRPCServer",
    "VaultSocketServer",
    "VaultClient",
]
