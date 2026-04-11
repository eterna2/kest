import os
import pytest
from kest.core import KestEntry, sign_entry, RustEd25519Provider, LocalEd25519Provider

def test_rust_ed25519_provider_signing():
    private_key = os.urandom(32)
    provider = RustEd25519Provider(private_key, principal="spiffe://test")

    entry = KestEntry(
        entry_id="test-1",
        operation="test-op",
        classification="system",
        trust_score=100
    )

    # This calls the Rust sign_entry, which should take the GIL-free path
    jws = sign_entry(entry, provider)

    assert jws is not None
    assert len(jws.split(".")) == 3

    # Verify it's a valid JWS format
    header_b64, payload_b64, sig_b64 = jws.split(".")
    assert header_b64 is not None
    assert payload_b64 is not None
    assert sig_b64 is not None

def test_rust_vs_python_provider_compatibility():
    # Use a fixed key for comparison
    private_key = b"\x00" * 32
    rust_provider = RustEd25519Provider(private_key, principal="spiffe://test")

    # LocalEd25519Provider generates its own key, so we can't easily compare signatures
    # but we can check if they both produce valid JWS for the same entry.

    entry = KestEntry(
        entry_id="test-1",
        operation="test-op",
        classification="system",
        trust_score=100
    )

    jws_rust = sign_entry(entry, rust_provider)

    # For LocalEd25519Provider, it uses cryptography.hazmat.primitives.asymmetric.ed25519
    # which we can also use to verify the signature.
    from cryptography.hazmat.primitives.asymmetric import ed25519
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)

    header_b64, payload_b64, sig_b64 = jws_rust.split(".")
    signing_input = f"{header_b64}.{payload_b64}".encode()

    import base64
    sig_bytes = base64.urlsafe_b64decode(sig_b64 + "=" * ((4 - len(sig_b64) % 4) % 4))

    # Verify the signature produced by Rust using Python's cryptography library
    priv.public_key().verify(sig_bytes, signing_input)

def test_rust_native_provider_fallback():
    # Test that a regular Python provider still works (the fallback path)
    python_provider = LocalEd25519Provider(principal="spiffe://test-python")

    entry = KestEntry(
        entry_id="test-1",
        operation="test-op",
        classification="system",
        trust_score=100
    )

    jws = sign_entry(entry, python_provider)
    assert jws is not None
    assert len(jws.split(".")) == 3
