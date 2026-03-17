from kest.core.crypto import (
    compute_dag_hash,
    generate_keypair,
    sign_passport,
    verify_signature,
)
from kest.core.models import KestPassport, PassportOrigin


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
    """Verify Ed25519 signatures work on passport objects."""
    private_key, public_key = generate_keypair()

    passport = KestPassport(
        origin=PassportOrigin(user_id="test", session_id="test", policies={}),
        history={},
        signature="",
        public_key_id="test_key",
    )

    # Sign it (mutates signature field or returns a new instance)
    signed_passport = sign_passport(private_key, passport)
    assert signed_passport.signature != ""

    # Verify it
    assert verify_signature(public_key, signed_passport) is True


def test_verify_signature_failure():
    """Verify tampered passport fails signature authentication."""
    private_key, public_key = generate_keypair()

    passport = KestPassport(
        origin=PassportOrigin(user_id="test", session_id="test", policies={}),
        history={},
        signature="",
        public_key_id="test_key",
    )

    signed = sign_passport(private_key, passport)

    # Tamper with the passport
    signed.origin.user_id = "hacker"

    assert verify_signature(public_key, signed) is False
