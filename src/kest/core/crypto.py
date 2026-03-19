import hashlib
import json
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Tuple

import jwt
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


def sign_passport(
    private_key: ed25519.Ed25519PrivateKey, passport: KestPassport, kid: str
) -> str:
    """Signs the passport payload using EdDSA and returns a JWS string."""
    payload = passport.model_dump(mode="json")

    # jwt.encode supports cryptography key objects directly
    token = jwt.encode(payload, private_key, algorithm="EdDSA", headers={"kid": kid})
    return token


def verify_signature(
    public_key: ed25519.Ed25519PublicKey, jws_token: str
) -> KestPassport:
    """
    Strictly validates the EdDSA signature of the JWS token.
    Returns the parsed KestPassport if valid, raises ValueError otherwise.
    """
    try:
        decoded_payload = jwt.decode(jws_token, public_key, algorithms=["EdDSA"])
        return KestPassport.model_validate(decoded_payload)
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Invalid signature or token: {e}")


class KeyRegistry(ABC):
    """Abstract interface for JWS Key Discovery mechanisms."""

    @abstractmethod
    def get_public_key(self, kid: str) -> ed25519.Ed25519PublicKey:
        pass


class LocalJWKStore(KeyRegistry):
    """Local, in-memory implementation of KeyRegistry for dev/testing."""

    def __init__(self, keys: Dict[str, ed25519.Ed25519PublicKey]):
        self._keys = keys

    def get_public_key(self, kid: str) -> ed25519.Ed25519PublicKey:
        if kid not in self._keys:
            raise KeyError(f"Key ID '{kid}' not found in local registry.")
        return self._keys[kid]
