"""TDD tests for vault server transports — written before implementation."""

import time

import pytest

from kest.core.vault import HandleVault
from kest.core.vault.errors import (
    HandleAccessDeniedError,
    HandleNotFoundError,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _free_port() -> int:
    import socket

    with socket.socket() as s:
        s.bind(("localhost", 0))
        return s.getsockname()[1]


def _make_vault() -> HandleVault:
    return HandleVault()


# ---------------------------------------------------------------------------
# HTTP Server tests
# ---------------------------------------------------------------------------


class TestVaultHTTPServer:
    @pytest.fixture()
    def server_and_client(self):
        from kest.core.vault.server import VaultClient, VaultHTTPServer

        port = _free_port()
        vault = _make_vault()
        srv = VaultHTTPServer(vault=vault, host="localhost", port=port)
        srv.start()
        time.sleep(0.05)
        client = VaultClient.http(f"http://localhost:{port}")
        yield vault, client
        srv.stop()

    def test_seal_returns_handle(self, server_and_client):
        _, client = server_and_client
        h = client.seal(
            data={"ssn": "123"},
            owner_principal="svc-a",
            safe_view="PII record",
        )
        assert h["id"].startswith("hdl_")
        assert h["safe_view"] == "PII record"

    def test_unseal_round_trip(self, server_and_client):
        _, client = server_and_client
        h = client.seal(data={"x": 42}, owner_principal="svc", safe_view="num")
        assert client.unseal(h["id"], requesting_principal="svc") == {"x": 42}

    def test_unseal_wrong_principal_raises(self, server_and_client):
        _, client = server_and_client
        h = client.seal(data="secret", owner_principal="svc-a", safe_view="s")
        with pytest.raises(HandleAccessDeniedError):
            client.unseal(h["id"], requesting_principal="svc-b")

    def test_unseal_missing_raises(self, server_and_client):
        _, client = server_and_client
        with pytest.raises(HandleNotFoundError):
            client.unseal("hdl_nonexistent", requesting_principal="svc")

    def test_invalidate_then_unseal_raises(self, server_and_client):
        _, client = server_and_client
        h = client.seal(data="v", owner_principal="svc", safe_view="s")
        client.invalidate(h["id"])
        with pytest.raises(HandleNotFoundError):
            client.unseal(h["id"], requesting_principal="svc")

    def test_get_safe_view(self, server_and_client):
        _, client = server_and_client
        h = client.seal(data="v", owner_principal="svc", safe_view="my safe view")
        assert client.get_safe_view(h["id"]) == "my safe view"

    def test_get_safe_view_missing_raises(self, server_and_client):
        _, client = server_and_client
        with pytest.raises(HandleNotFoundError):
            client.get_safe_view("hdl_nope")

    def test_seal_with_granted_principals(self, server_and_client):
        _, client = server_and_client
        h = client.seal(
            data="secret",
            owner_principal="svc-a",
            safe_view="s",
            granted_principals=["svc-b"],
        )
        assert client.unseal(h["id"], requesting_principal="svc-b") == "secret"


# ---------------------------------------------------------------------------
# RPC Server tests
# ---------------------------------------------------------------------------


class TestVaultRPCServer:
    @pytest.fixture()
    def server_and_client(self):
        from kest.core.vault.server import VaultClient, VaultRPCServer

        port = _free_port()
        vault = _make_vault()
        srv = VaultRPCServer(vault=vault, host="localhost", port=port)
        srv.start()
        time.sleep(0.05)
        client = VaultClient.rpc("localhost", port)
        yield vault, client
        srv.stop()

    def test_seal_returns_handle(self, server_and_client):
        _, client = server_and_client
        h = client.seal(data={"k": "v"}, owner_principal="svc", safe_view="kv")
        assert h["id"].startswith("hdl_")

    def test_unseal_round_trip(self, server_and_client):
        _, client = server_and_client
        h = client.seal(data={"n": 7}, owner_principal="svc", safe_view="num")
        assert client.unseal(h["id"], requesting_principal="svc") == {"n": 7}

    def test_wrong_principal_raises(self, server_and_client):
        _, client = server_and_client
        h = client.seal(data="x", owner_principal="svc-a", safe_view="x")
        with pytest.raises(HandleAccessDeniedError):
            client.unseal(h["id"], requesting_principal="svc-b")

    def test_missing_handle_raises(self, server_and_client):
        _, client = server_and_client
        with pytest.raises(HandleNotFoundError):
            client.unseal("hdl_ghost", requesting_principal="svc")

    def test_invalidate_and_unseal_raises(self, server_and_client):
        _, client = server_and_client
        h = client.seal(data="v", owner_principal="svc", safe_view="v")
        client.invalidate(h["id"])
        with pytest.raises(HandleNotFoundError):
            client.unseal(h["id"], requesting_principal="svc")

    def test_get_safe_view(self, server_and_client):
        _, client = server_and_client
        h = client.seal(data="v", owner_principal="svc", safe_view="rpc safe view")
        assert client.get_safe_view(h["id"]) == "rpc safe view"


# ---------------------------------------------------------------------------
# Socket Server tests (TCP)
# ---------------------------------------------------------------------------


class TestVaultSocketServer:
    @pytest.fixture()
    def server_and_client(self):
        from kest.core.vault.server import VaultClient, VaultSocketServer

        port = _free_port()
        vault = _make_vault()
        srv = VaultSocketServer(vault=vault, address=("localhost", port))
        srv.start()
        time.sleep(0.05)
        client = VaultClient.socket(("localhost", port))
        yield vault, client
        srv.stop()

    def test_seal_returns_handle(self, server_and_client):
        _, client = server_and_client
        h = client.seal(data={"k": "v"}, owner_principal="svc", safe_view="kv")
        assert h["id"].startswith("hdl_")

    def test_unseal_round_trip(self, server_and_client):
        _, client = server_and_client
        h = client.seal(data={"x": 99}, owner_principal="svc", safe_view="num")
        assert client.unseal(h["id"], requesting_principal="svc") == {"x": 99}

    def test_wrong_principal_raises(self, server_and_client):
        _, client = server_and_client
        h = client.seal(data="s", owner_principal="a", safe_view="s")
        with pytest.raises(HandleAccessDeniedError):
            client.unseal(h["id"], requesting_principal="b")

    def test_missing_handle_raises(self, server_and_client):
        _, client = server_and_client
        with pytest.raises(HandleNotFoundError):
            client.unseal("hdl_none", requesting_principal="svc")

    def test_invalidate_and_get_raises(self, server_and_client):
        _, client = server_and_client
        h = client.seal(data="v", owner_principal="svc", safe_view="v")
        client.invalidate(h["id"])
        with pytest.raises(HandleNotFoundError):
            client.get_safe_view(h["id"])

    def test_get_safe_view(self, server_and_client):
        _, client = server_and_client
        h = client.seal(data="v", owner_principal="svc", safe_view="socket safe")
        assert client.get_safe_view(h["id"]) == "socket safe"
