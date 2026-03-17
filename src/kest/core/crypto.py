import base64
import hashlib
import json
from typing import Any, Dict, List, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from kest.core.models import KestPassport


def compute_dag_hash(
    parent_entry_hashes: List[str], payload_hash: str, annotations: Dict[str, Any]
) -> str:
    """
    Deterministically computes a DAG hash binding by securely folding
    sorted parent hashes, payload state, and environment annotations.
    """
    sorted_parents = sorted(parent_entry_hashes)
    struct = {
        "parents": sorted_parents,
        "payload": payload_hash,
        "annotations": annotations,
    }

    # Strict, deterministic JSON serialization
    serialized = json.dumps(struct, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(serialized).hexdigest()


def generate_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generates an Ed25519 keypair for test/demonstration scaffolding."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


def _serialize_for_signature(passport: KestPassport) -> bytes:
    """
    Strips out the `signature` field and generates a strictly deterministic
    JSON payload suitable for cryptographic signing and verification.
    """
    # model_dump with `mode="json"` converts inner Enums/timestamps cleanly
    data = passport.model_dump(exclude={"signature"}, mode="json")
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_passport(
    private_key: ed25519.Ed25519PrivateKey, passport: KestPassport
) -> KestPassport:
    """Signs the passport payload using the Ed25519 private key."""
    payload = _serialize_for_signature(passport)
    sig_bytes = private_key.sign(payload)
    sig_base64 = base64.b64encode(sig_bytes).decode("utf-8")

    # Clone the passport to avoid mutating inputs
    signed_passport = passport.model_copy()
    signed_passport.signature = sig_base64
    return signed_passport


def verify_signature(
    public_key: ed25519.Ed25519PublicKey, passport: KestPassport
) -> bool:
    """Strictly validates the Ed25519 signature of the passport structure."""
    if not passport.signature:
        return False

    payload = _serialize_for_signature(passport)
    try:
        sig_bytes = base64.b64decode(passport.signature)
        public_key.verify(sig_bytes, payload)
        return True
    except (InvalidSignature, ValueError):
        return False
