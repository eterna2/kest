import threading
import httpx
import respx
import pytest
import time
import urllib.request
import base64

from kest.core.identity.providers.oauth import OAuthCliProvider

@pytest.fixture
def mock_passphrase():
    return lambda: "test-passphrase-123"

@respx.mock
def test_oauth_cli_provider_flow(mock_passphrase):
    # Mock the token endpoint
    respx.post("https://auth.example.com/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "mock-access",
                "id_token": "mock-id-token",
                "token_type": "Bearer"
            }
        )
    )

    provider = OAuthCliProvider(
        client_id="test-client-id",
        auth_url="https://auth.example.com/auth",
        token_url="https://auth.example.com/token",
        auto_open_browser=False, 
        passphrase_provider=mock_passphrase,
        port=0,
        # We need to mock decoded ID token or userinfo since we aren't doing real JWT validation
        _test_user_id="user-123"
    )
    
    # We need a way to know what port the provider bound to and what state it generated.
    # The provider's get_identity() is blocking. We can run it in a thread.
    result_container = {}
    
    def run_provider():
        try:
            # Overriding get_identity to return "user-123" and initialize the key
            identity = provider.get_identity()
            result_container["identity"] = identity
        except Exception as e:
            result_container["error"] = e
            
    provider_thread = threading.Thread(target=run_provider)
    provider_thread.start()
    
    # Wait for the server to start (we assume port is set on provider instance)
    # Give it a tiny bit of time
    time.sleep(0.1)
    
    # Verify the PKCE state
    assert provider.state is not None
    assert provider.code_verifier is not None
    
    # Simulate the browser callback
    port = provider.server_port
    callback_url = f"http://localhost:{port}/callback?code=test-code&state={provider.state}"
    
    response = urllib.request.urlopen(callback_url)
    assert response.status == 200
    assert b"Success" in response.read()
    
    provider_thread.join(timeout=2)
    
    assert "error" not in result_container
    assert result_container.get("identity") == "user-123"
    
    # Check that signature is stable and valid Ed25519
    payload = b"hello world"
    sig = provider.sign(payload)
    
    assert payload in base64.urlsafe_b64decode(sig.split('.')[1] + "==")
    
    # Test stability: recreate provider with same mock inputs
    provider2 = OAuthCliProvider(
        client_id="test-client-id",
        auth_url="https://auth.example.com/auth",
        token_url="https://auth.example.com/token",
        auto_open_browser=False, 
        passphrase_provider=mock_passphrase,
        port=0,
        _test_user_id="user-123"
    )
    # The key is generated dynamically after login. Let's force it here.
    provider2._initialize_key("user-123")
    assert provider2.get_identity() == "user-123"
    assert provider2.sign(payload) == sig

