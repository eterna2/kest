import uuid
import json
import base64
import hashlib
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from abc import ABC, abstractmethod


@dataclass
class Passport:
    """
    Represents a verifiable execution graph (lineage).

    A Passport is a collection of JWS-formatted audit entries that form
    a Merkle DAG (Directed Acyclic Graph). Each entry points to its
    parents via their cryptographic hashes.
    """

    entries: List[str] = field(default_factory=list)

    def add_signature(self, signature: str):
        """
        Appends a new JWS signature (audit entry) to the passport.

        Args:
            signature: The JWS-formatted audit entry string.
        """
        self.entries.append(signature)

    def serialize(self) -> str:
        """
        Serializes the passport entries to a JSON string.

        Returns:
            str: JSON representation of the list of signatures.
        """
        return json.dumps(self.entries)

    @classmethod
    def deserialize(cls, data: str) -> "Passport":
        """
        Creates a Passport instance from a serialized JSON string.

        Args:
            data: Serialized JSON string of signatures.

        Returns:
            Passport: A new Passport instance. Returns an empty passport on failure.
        """
        try:
            entries = json.loads(data)
            return cls(entries=entries)
        except Exception:
            return cls()


class PassportVerifier:
    """
    Utility to verify the integrity and authenticity of a Passport chain.

    The verifier checks both the cryptographic signatures of individual entries
    and the Merkle links between entries to ensure the lineage is untampered.
    """

    @staticmethod
    def verify(passport: Passport, providers: Dict[str, Any]) -> bool:
        """
        Verifies all signatures and Merkle links in the passport.

        Args:
            passport: The Passport instance to verify.
            providers: A map of workload_ids to IdentityProvider instances.

        Returns:
            bool: True if the entire passport is valid.

        Raises:
            ValueError: If a signature is invalid or a Merkle link is broken.
        """
        last_signature_hash = "0"

        for signature in passport.entries:
            # 1. Split JWS (header.payload.signature)
            parts = signature.split(".")
            if len(parts) < 3:
                raise ValueError(f"Invalid JWS format in passport: {signature[:20]}...")

            header_b64 = parts[0]
            payload_b64 = parts[1]
            sig_b64 = parts[2]

            # 2. Decode payload
            padding = "=" * (4 - len(payload_b64) % 4)
            payload_json = base64.urlsafe_b64decode(payload_b64 + padding).decode()
            payload = json.loads(payload_json)

            # 3. Verify Merkle Link
            parents = payload.get("parent_ids", [])
            parent_hash = parents[0] if parents else "0"

            if parent_hash != last_signature_hash:
                raise ValueError(
                    f"Merkle link broken. Expected {last_signature_hash}, got {parent_hash}"
                )

            # 4. Verify Signature for providers that expose a public key.
            # No silent bypass for test/pending signatures: every entry MUST
            # be either verifiable (if provider present) or skipped gracefully
            # (if provider absent) — but never silently accepted based on
            # the *content* of the signature string.
            principal = payload.get("principal") or payload.get("labels", {}).get(
                "principal"
            )
            provider = providers.get(principal)

            if provider and hasattr(provider, "public_key"):
                signing_input = f"{header_b64}.{payload_b64}".encode()
                sig_padding = "=" * (4 - len(sig_b64) % 4)
                sig_bytes = base64.urlsafe_b64decode(sig_b64 + sig_padding)
                try:
                    provider.public_key.verify(sig_bytes, signing_input)
                except Exception as e:
                    raise ValueError(
                        f"Signature verification failed for {principal}: {e}"
                    )

            # Update last hash for next iteration
            last_signature_hash = hashlib.sha256(signature.encode()).hexdigest()

        return True


class TrustEvaluator(ABC):
    """
    Abstract base class for CARTA (Continuous Adaptive Risk and Trust Assessment).

    TrustEvaluators define how trust scores are propagated and attenuated
    through the execution graph.
    """

    @abstractmethod
    def calculate(self, self_score: int, parent_scores: List[int]) -> int:
        """
        Calculates the trust score for the current node.

        Args:
            self_score: The intrinsic trust score of the current workload.
            parent_scores: A list of trust scores from parent/input nodes.

        Returns:
            int: The resulting trust score (0 to 100).
        """
        pass


class DefaultTrustEvaluator(TrustEvaluator):
    """
    Default trust propagation logic.

    Uses a 'weakest link' model: (min(parent_scores) * self_score) / 100.
    """

    def calculate(self, self_score: int, parent_scores: List[int]) -> int:
        """Calculates trust using the product of minimum parent and self score."""
        if not parent_scores:
            return self_score

        min_parent = min(parent_scores)
        return (min_parent * self_score) // 100


class BaggageManager:
    """
    Handles the hybrid propagation of lineage data in OpenTelemetry (OTel) Baggage.

    The manager switches between inline propagation (for small passports) and
    'claim-check' pattern (using external cache) for larger lineages to
    avoid exceeding HTTP header limits.
    """

    MAX_BAGGAGE_SIZE = 4096  # F-CP-04: default 4096-byte threshold

    @staticmethod
    def pack(passport: Passport, cache: Optional[Any] = None) -> Dict[str, str]:
        """
        Packs a passport into a dictionary suitable for OTel Baggage.

        Args:
            passport: The Passport instance to pack.
            cache: (Optional) A cache backend for claim-check storage.

        Returns:
            Dict[str, str]: Baggage key-value pairs.
        """
        serialized = passport.serialize()
        # Calculate root hash of the last signature
        root_hash = (
            hashlib.sha256(passport.entries[-1].encode()).hexdigest()
            if passport.entries
            else "0"
        )

        if len(serialized) > BaggageManager.MAX_BAGGAGE_SIZE and cache:
            claim_id = str(uuid.uuid4())
            cache.set(f"kest.claim.{claim_id}", serialized)
            return {"kest.claim_check": claim_id, "kest.chain_tip": root_hash}
        return {"kest.passport": serialized, "kest.chain_tip": root_hash}

    @staticmethod
    def unpack(baggage_func: Any, cache: Optional[Any] = None) -> Passport:
        """
        Unpacks a passport from OTel Baggage.

        Args:
            baggage_func: A function that retrieves a value from baggage by key.
            cache: (Optional) A cache backend for retrieving claim-check data.

        Returns:
            Passport: The reconstructed Passport instance.
        """
        claim_id = baggage_func("kest.claim_check")
        if claim_id:
            if not cache:
                print(
                    f"[Kest.Baggage] Warning: claim_check {claim_id} found but no cache configured for retrieval."
                )
                return Passport()

            cached = cache.get(f"kest.claim.{claim_id}")
            if cached:
                print(
                    f"[Kest.Baggage] Successfully retrieved lineage from cache via claim_check {claim_id}"
                )
                return Passport.deserialize(cached)
            else:
                print(
                    f"[Kest.Baggage] Error: claim_check {claim_id} present but record NOT FOUND in cache."
                )

        raw_passport = baggage_func("kest.passport")
        if raw_passport:
            return Passport.deserialize(raw_passport)

        return Passport()


# Standard Trust Bootstrap Scores (F-TS-02)
# Keys and values defined below are MANDATORY defaults.
# They MUST NOT be overridden; use register_origin_trust() to ADD new entries.
_MANDATORY_ORIGIN_KEYS = {
    "system", "internal", "verified_rag",
    "third_party_api", "user_input", "internet", "llm",
}

ORIGIN_TRUST_MAP: dict = {
    "system": 100,
    "internal": 100,
    "verified_rag": 90,
    "third_party_api": 60,
    "user_input": 40,
    "internet": 10,
    "llm": 0,
}


def register_origin_trust(source_type: str, score: int) -> None:
    """
    Register a custom origin trust score.

    F-TS-02: deployments MAY add custom source_type keys.
    Mandatory defaults (system, internal, verified_rag, third_party_api,
    user_input, internet, llm) MUST NOT be overridden.

    Args:
        source_type: The name of the new origin type.
        score: The trust bootstrap score (0–100).

    Raises:
        ValueError: If source_type is one of the mandatory defaults.
    """
    if source_type in _MANDATORY_ORIGIN_KEYS:
        raise ValueError(
            f"Cannot override mandatory origin '{source_type}'. "
            "Add a custom key instead."
        )
    ORIGIN_TRUST_MAP[source_type] = score


# Backward-compat alias — prefer ORIGIN_TRUST_MAP
SOURCE_TRUST_MAP = ORIGIN_TRUST_MAP
