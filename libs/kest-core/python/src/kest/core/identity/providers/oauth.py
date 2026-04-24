import base64
import getpass
import json
import secrets
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable, Optional
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from kest.core.identity.base import IdentityProvider


class KestOAuthServer(HTTPServer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.kest_code: Optional[str] = None
        self.kest_state: Optional[str] = None


class OAuthCallbackHandler(BaseHTTPRequestHandler):
    """Handles the local redirect callback for the OAuth Authorization Code flow."""

    def do_GET(self) -> None:
        query_components = parse_qs(urlparse(self.path).query)

        if "code" in query_components and "state" in query_components:
            server = getattr(self, "server")
            server.kest_code = query_components["code"][0]
            server.kest_state = query_components["state"][0]

            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><body><h1>Success!</h1><p>You can close this window now.</p></body></html>"
            )
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Missing code or state")

    def log_message(self, format: str, *args) -> None:
        pass  # Suppress HTTP server logging


class OAuthCliProvider(IdentityProvider):
    """
    An Identity Engine that performs an Authorization Code Flow + PKCE local OAuth callback.

    Determines the root Ed25519 identity key deterministically by hashing the OAuth identity's
    unique identifier combined with a user-provided passphrase using PBKDF2HMAC.
    """

    def __init__(
        self,
        client_id: str,
        auth_url: str,
        token_url: str,
        auto_open_browser: bool = True,
        passphrase_provider: Callable[[], str] = getpass.getpass,
        port: int = 8080,
        _test_user_id: Optional[str] = None,
    ):
        self.client_id = client_id
        self.auth_url = auth_url
        self.token_url = token_url
        self.auto_open_browser = auto_open_browser
        self.passphrase_provider = passphrase_provider

        self.server_port = port
        self.state = None
        self.code_verifier = None

        self._test_user_id = _test_user_id

        self._identity: Optional[str] = None
        self._private_key: Optional[ed25519.Ed25519PrivateKey] = None

    def _generate_pkce(self) -> tuple[str, str]:
        """Generates PKCE code verifier and challenge."""
        verifier = secrets.token_urlsafe(32)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(verifier.encode("ascii"))
        challenge = (
            base64.urlsafe_b64encode(digest.finalize()).decode("ascii").rstrip("=")
        )
        return verifier, challenge

    def _get_user_id_from_token(self, id_token: str) -> str:
        """Extracts the 'sub' claim from an ID token (bypassing strict JWT verification)."""
        if self._test_user_id:
            return self._test_user_id

        # JWT structure: header.payload.signature
        parts = id_token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid ID Token format.")

        payload_padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_padded).decode("utf-8"))

        sub = payload.get("sub")
        if not sub:
            raise ValueError("ID Token is missing the 'sub' claim.")
        return sub

    def _initialize_key(self, user_id: str) -> None:
        """Deterministically generates the Ed25519 key using PBKDF2 on user_id + passphrase."""
        passphrase = self.passphrase_provider()

        # We use the user_id as a salt (in a real scenario, a static realm/app salt could also be added)
        salt = user_id.encode("utf-8")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key_material = kdf.derive(passphrase.encode("utf-8"))

        self._identity = user_id
        self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_material)

    def _authenticate(self) -> None:
        """Runs the local server to capture the OAuth flow."""
        self.state = secrets.token_urlsafe(16)
        self.code_verifier, code_challenge = self._generate_pkce()

        server = KestOAuthServer(("localhost", self.server_port), OAuthCallbackHandler)
        self.server_port = server.server_address[
            1
        ]  # Update to actual bound port (useful if port=0)

        redirect_uri = f"http://localhost:{self.server_port}/callback"

        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "state": self.state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "scope": "openid profile email",
        }

        url = f"{self.auth_url}?{urlencode(params)}"

        if self.auto_open_browser:
            webbrowser.open(url)
        else:
            print(f"Please visit the following URL to authenticate:\n{url}")

        # We wait for 1 request
        server.kest_code = None
        server.kest_state = None

        while server.kest_code is None:
            server.handle_request()

        code = server.kest_code
        state = server.kest_state
        server.server_close()

        if state != self.state:
            raise ValueError("OAuth state mismatch.")

        # Exchange code for token
        token_data = {
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": self.code_verifier,
        }

        resp = httpx.post(self.token_url, data=token_data)
        resp.raise_for_status()

        tokens = resp.json()

        # Test override hook
        if self._test_user_id:
            user_id = self._test_user_id
        else:
            if "id_token" not in tokens:
                raise ValueError(
                    "Response missing id_token. Cannot extract user identity."
                )
            user_id = self._get_user_id_from_token(tokens["id_token"])

        self._initialize_key(user_id)

    def get_identity(self) -> str:
        """Returns the OAuth principal ID (the `sub` claim). Triggers login if necessary."""
        if not self._identity:
            self._authenticate()
        return self._identity  # type: ignore

    def sign(self, payload: bytes) -> str:
        """Signs the payload using the deterministically derived Ed25519 private key."""
        if not self._private_key or not self._identity:
            self._authenticate()

        # Ensure it's not None for type checker
        assert self._private_key is not None
        assert self._identity is not None

        header = {"alg": "EdDSA", "typ": "JWS", "kid": self._identity}
        header_b64 = (
            base64.urlsafe_b64encode(
                json.dumps(header, separators=(",", ":"), sort_keys=True).encode()
            )
            .decode()
            .rstrip("=")
        )
        payload_b64 = base64.urlsafe_b64encode(payload).decode().rstrip("=")

        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = self._private_key.sign(signing_input)
        sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        return f"{header_b64}.{payload_b64}.{sig_b64}"
