import os

from hypothesis import given
from hypothesis import strategies as st

from kest.core import LocalEd25519Provider, RustEd25519Provider, sign_entry


def test_rust_ed25519_provider_signing():
    private_key = os.urandom(32)
    provider = RustEd25519Provider(private_key, principal="spiffe://test")

    from kest.core._core import KestEntry as RustEntry

    entry = RustEntry(
        entry_id="test-1", operation="test-op", classification="system", trust_score=100
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

    from kest.core._core import KestEntry as RustEntry

    entry = RustEntry(
        entry_id="test-1", operation="test-op", classification="system", trust_score=100
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

    # Use the 'canonical' KestEntry and sign_entry for the current backend
    from kest.core import KestEntry
    from kest.core import sign_entry as canonical_sign_entry

    entry = KestEntry(
        entry_id="test-1", operation="test-op", classification="system", trust_score=100
    )

    jws = canonical_sign_entry(entry, python_provider)
    assert jws is not None
    assert len(jws.split(".")) == 3


@given(
    entry_id=st.uuids().map(str),
    # Full Unicode except lone surrogates (Cs), which are invalid per RFC 8785 / I-JSON.
    operation=st.text(
        st.characters(blacklist_categories=("Cs",)), min_size=1, max_size=20
    ),
    classification=st.sampled_from(
        ["system", "data", "critic", "snapshot", "sanitizer"]
    ),
    trust_score=st.integers(min_value=0, max_value=100),
    labels=st.dictionaries(
        st.text(st.characters(blacklist_categories=("Cs",)), min_size=1, max_size=10),
        st.text(st.characters(blacklist_categories=("Cs",)), max_size=10),
        max_size=5,
    ),
    added_taints=st.lists(
        st.text(st.characters(blacklist_categories=("Cs",)), min_size=1, max_size=10),
        max_size=3,
    ),
)
def test_rust_vs_python_signing_equivalence_hypothesis(
    entry_id, operation, classification, trust_score, labels, added_taints
):
    """
    Property-based test to ensure Rust and Python backends remain bit-for-bit identical
    across a wide range of input data.
    """
    private_key = b"\x00" * 32
    rust_provider = RustEd25519Provider(private_key, principal="spiffe://test")

    # 1. Setup Rust Backend
    from kest.core import sign_entry as sign_rust
    from kest.core._core import KestEntry as RustEntry

    rust_entry = RustEntry(
        entry_id=entry_id,
        operation=operation,
        classification=classification,
        trust_score=trust_score,
        labels=labels,
        added_taints=added_taints,
        timestamp_ms=1712880000000,  # Synced timestamp
    )

    # 2. Setup Python Backend
    from kest.core._core_py import KestEntry as PyEntry
    from kest.core._core_py import sign_entry as py_sign_entry

    py_entry = PyEntry(
        entry_id=entry_id,
        operation=operation,
        classification=classification,
        trust_score=trust_score,
        labels=labels,
        added_taints=added_taints,
    )
    py_entry._timestamp_ms = 1712880000000  # Synced timestamp

    # 3. Sign using both backends
    jws_rust = sign_rust(rust_entry, rust_provider)
    jws_python = py_sign_entry(py_entry, rust_provider)

    assert jws_rust == jws_python, (
        f"Mismatch for ID {entry_id}: Rust and Python JWS outputs MUST be identical"
    )
