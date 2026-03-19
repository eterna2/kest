import base64
import json

import pytest

from kest.core.crypto import (
    LocalJWKStore,
    compute_dag_hash,
    generate_keypair,
    sign_passport,
    verify_signature,
)
from kest.core.models import KestPassport, PassportOrigin, PassportOriginPolicies


def test_compute_dag_hash_deterministic_sorting():
    """Verify that parent hashes are sorted deterministically before hashing."""
    hash1 = compute_dag_hash(
        parent_entry_hashes=["hash_B", "hash_A"],
        payload_hash="payload_hash",
        annotations={"pii": "true"},
    )
    hash2 = compute_dag_hash(
        parent_entry_hashes=["hash_A", "hash_B"],
        payload_hash="payload_hash",
        annotations={"pii": "true"},
    )
    assert hash1 == hash2


def test_sign_and_verify_passport():
    """Verify EdDSA JWS signatures work on passport objects."""
    private_key, public_key = generate_keypair()

    passport = KestPassport(
        origin=PassportOrigin(
            user_id="test", session_id="test", policies=PassportOriginPolicies()
        ),
        history={},
    )

    kid = "spiffe://kest.internal/worker-1"

    # Sign it
    jws_token = sign_passport(private_key, passport, kid=kid)
    assert isinstance(jws_token, str)
    assert len(jws_token.split(".")) == 3

    # Verify it
    verified_passport = verify_signature(public_key, jws_token)
    assert verified_passport.origin.user_id == "test"


def test_verify_signature_failure():
    """Verify tampered passport fails JWS authentication."""
    private_key, public_key = generate_keypair()

    passport = KestPassport(
        origin=PassportOrigin(
            user_id="test", session_id="test", policies=PassportOriginPolicies()
        ),
        history={},
    )

    jws_token = sign_passport(private_key, passport, kid="test_key")

    # Tamper with the token (modify payload)
    header, payload, sig = jws_token.split(".")

    # Decode, tamper, re-encode payload
    # Pad payload for correct base64 decoding
    padding_needed = 4 - (len(payload) % 4)
    if padding_needed and padding_needed != 4:
        payload += "=" * padding_needed

    decoded_payload = json.loads(base64.urlsafe_b64decode(payload))
    decoded_payload["origin"]["user_id"] = "hacker"

    tampered_payload = (
        base64.urlsafe_b64encode(json.dumps(decoded_payload).encode())
        .decode()
        .rstrip("=")
    )

    tampered_token = f"{header}.{tampered_payload}.{sig}"

    with pytest.raises(ValueError, match="Invalid signature or token"):
        verify_signature(public_key, tampered_token)


def test_local_jwk_store():
    """Verify LocalJWKStore securely manages key discovery."""
    _, pub_key1 = generate_keypair()
    _, pub_key2 = generate_keypair()

    store = LocalJWKStore(keys={"key1": pub_key1, "key2": pub_key2})

    assert store.get_public_key("key1") == pub_key1
    assert store.get_public_key("key2") == pub_key2

    with pytest.raises(KeyError):
        store.get_public_key("unknown")
