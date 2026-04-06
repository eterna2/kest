import pytest
from kest.core.identity.providers.spiffe import SPIREProvider, HAS_SPIFFE


def test_spire_provider_fail_secure():
    """
    Ensure provider raises appropriate errors if SPIRE is missing.
    """
    if not HAS_SPIFFE:
        with pytest.raises(RuntimeError):
            SPIREProvider(socket_path="/tmp/non-existent-socket-path.sock")
    else:
        # Point to a non-existent socket
        provider = SPIREProvider(socket_path="/tmp/non-existent-socket-path.sock")

        with pytest.raises(Exception):
            provider.get_identity()
