import pytest
import os
from kest.core import SPIREProvider


# This test requires a live SPIRE Agent socket to be available.
# It should be run with: pytest -m live
@pytest.mark.live
def test_spire_provider_live_identity():
    """
    Requirement: SPIRE Agent must be running and socket accessible.
    """
    # Default path matches SPIFFE standard and our container setup.
    default_socket = "/var/run/spire/agent/public/api.sock"
    socket_path = os.getenv("SPIFFE_ENDPOINT_SOCKET", f"unix://{default_socket}")

    if not socket_path.startswith("unix://"):
        socket_path = f"unix://{socket_path}"

    # We check for existence using the raw path (no unix:// scheme)
    raw_path = socket_path.replace("unix://", "")
    if not os.path.exists(raw_path):
        pytest.fail(
            f"SPIRE socket not found at {raw_path}. \n"
            "Ensure this test is running inside a Kest-Lab container (e.g. hop1)."
        )

    provider = SPIREProvider(socket_path=socket_path)

    # 1. Test real identity fetching
    identity = provider.get_identity()
    assert identity.startswith("spiffe://kest.internal/")
    print(f"Live Workload ID: {identity}")

    # 2. Test real cryptographic signing
    payload = b"live-test-payload"
    jws = provider.sign(payload)

    parts = jws.split(".")
    assert len(parts) == 3
    print("Live Signing Successful.")
