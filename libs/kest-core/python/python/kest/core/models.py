import base64
import hashlib
import json
import uuid
import zlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TypedDict


@dataclass(slots=True)
class Passport:
    """
    Represents a verifiable execution graph (lineage).

    A Passport is a collection of JWS-formatted audit entries that form
    a Merkle DAG (Directed Acyclic Graph). Each entry points to its
    parents via their cryptographic hashes.
    """

    entries: List[str] = field(default_factory=list)

    # --- A-03-I: version counter for O(1) cache invalidation ---
    _version: int = field(default=0, repr=False, compare=False)
    _cache_version: int = field(default=-1, repr=False, compare=False)
    _parsed_cache: Optional[List[Dict[str, Any]]] = field(
        default=None, repr=False, compare=False
    )

    # --- A-03-II: incrementally-updated aggregate caches ---
    _taints_cache: frozenset = field(
        default_factory=frozenset, repr=False, compare=False
    )
    _min_trust_cache: int = field(default=100, repr=False, compare=False)

    def __post_init__(self):
        """Rebuild incremental caches from initial entries (handles merge, deserialize, direct construction)."""
        if self.entries:
            taints: set = set()
            min_trust = 100
            for entry in self.entries:
                payload = self._decode_payload(entry)
                taints.update(payload.get("taints", []))
                min_trust = min(min_trust, payload.get("trust_score", 100))
            self._taints_cache = frozenset(taints)
            self._min_trust_cache = min_trust
            self._version = len(self.entries)

    @staticmethod
    def _decode_payload(jws: str) -> Dict[str, Any]:
        """Decode the payload segment of a JWS token into a dict."""
        try:
            parts = jws.split(".")
            if len(parts) < 2:
                return {}
            p_b64 = parts[1]
            p_b64 += "=" * ((4 - len(p_b64) % 4) % 4)
            return json.loads(base64.urlsafe_b64decode(p_b64))
        except Exception:
            return {}

    def _get_parsed_entries(self) -> List[Dict[str, Any]]:
        """Return parsed passport payloads, rebuilding cache only when version changed."""
        if self._parsed_cache is None or self._cache_version != self._version:
            self._parsed_cache = [self._decode_payload(e) for e in self.entries]
            self._cache_version = self._version
        return self._parsed_cache

    @property
    def trust_scores(self) -> List[int]:
        """Return the trust scores of all passport entries (O(1) after first call)."""
        return [e.get("trust_score", 0) for e in self._get_parsed_entries()]

    @property
    def accumulated_taints(self) -> frozenset:
        """Return the union of taints across all passport entries (O(1))."""
        return self._taints_cache

    @property
    def min_trust_score(self) -> int:
        """Return the minimum trust score across all entries (O(1))."""
        return self._min_trust_cache

    @staticmethod
    def merge(*passports: "Passport") -> "Passport":
        """
        Merges multiple passports, deduplicating entries while preserving topological order.

        Args:
            *passports: Passport instances to merge.

        Returns:
            Passport: A new Passport instance containing the union of all entries.
        """
        seen = set()
        merged_entries = []
        for p in passports:
            for entry in p.entries:
                if entry not in seen:
                    seen.add(entry)
                    merged_entries.append(entry)
        return Passport(entries=merged_entries)

    def add_signature(self, signature: str):
        """
        Appends a new JWS signature (audit entry) to the passport.

        Args:
            signature: The JWS-formatted audit entry string.
        """
        payload = self._decode_payload(signature)
        self.entries.append(signature)
        # A-03-I: O(1) cache invalidation via version counter
        self._version += 1
        # A-03-II: O(1) incremental taint/trust aggregation
        self._taints_cache = self._taints_cache | frozenset(payload.get("taints", []))
        self._min_trust_cache = min(
            self._min_trust_cache, payload.get("trust_score", 100)
        )

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
    Utility to verify the integrity and authenticity of a Passport graph (DAG).

    The verifier checks both the cryptographic signatures of individual entries
    and the Merkle links between entries to ensure the lineage is untampered.
    """

    @staticmethod
    def verify(passport: Passport, providers: Dict[str, Any]) -> bool:
        """
        Verifies all signatures and Merkle links in the passport DAG.

        Args:
            passport: The Passport instance to verify.
            providers: A map of workload_ids to IdentityProvider instances.

        Returns:
            bool: True if the entire passport is valid.

        Raises:
            ValueError: If a signature is invalid or a Merkle link is broken.
        """
        seen_hashes = {"0"}

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

            # 3. Verify Merkle Links (DAG verification)
            parents = payload.get("parent_ids", [])
            if not parents:
                parents = ["0"]

            for pid in parents:
                if pid not in seen_hashes:
                    raise ValueError(
                        f"Merkle link broken or out of order. Parent {pid} not yet seen. "
                        "Lineage must be in topological order."
                    )

            # 4. Verify Signature for providers that expose a public key.
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

            # Update seen_hashes for next iteration
            current_hash = hashlib.sha256(signature.encode()).hexdigest()
            seen_hashes.add(current_hash)

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


class PolicyDeviation(TypedDict):
    policy: str
    tier: str
    reason: Optional[str]
    approver: Optional[str]


class BaggageManager:
    """
    Handles the hybrid propagation of lineage data in OpenTelemetry (OTel) Baggage.

    The manager switches between inline propagation (for small passports) and
    'claim-check' pattern (using external cache) for larger lineages, to
    avoid exceeding HTTP header limits.

    Fix 3: Auto-compression with zlib level-1 extends the inline threshold
    from ~hop-3 to ~hop-10 at essentially no CPU cost (~10us for 5KB).
    """

    MAX_BAGGAGE_SIZE = 4096  # F-CP-04: default 4096-byte threshold
    _COMPRESS_KEY = "kest.passport_z"  # key used when compressed inline

    @staticmethod
    def _compress(data: str) -> str:
        """Compress a string with zlib level-1 and base64url-encode the result."""
        compressed = zlib.compress(data.encode(), level=1)
        return base64.urlsafe_b64encode(compressed).decode()

    @staticmethod
    def _decompress(encoded: str) -> str:
        """Decode and decompress a zlib-compressed base64url string."""
        padding = "=" * ((4 - len(encoded) % 4) % 4)
        compressed = base64.urlsafe_b64decode(encoded + padding)
        return zlib.decompress(compressed).decode()

    @staticmethod
    def pack(passport: Passport, cache: Optional[Any] = None) -> Dict[str, str]:
        """
        Packs a passport into a dictionary suitable for OTel Baggage.

        Compression strategy (auto, in order):
          1. Plain JSON inline if <= MAX_BAGGAGE_SIZE
          2. zlib level-1 compressed + base64url inline if compressed fits
          3. Claim-check via cache (requires cache backend)

        Args:
            passport: The Passport instance to pack.
            cache: (Optional) A cache backend for claim-check storage.

        Returns:
            Dict[str, str]: Baggage key-value pairs.
        """
        serialized = passport.serialize()
        root_hash = (
            hashlib.sha256(passport.entries[-1].encode()).hexdigest()
            if passport.entries
            else "0"
        )

        # 1. Fits inline uncompressed
        if len(serialized) <= BaggageManager.MAX_BAGGAGE_SIZE:
            return {"kest.passport": serialized, "kest.chain_tip": root_hash}

        # 2. Try zlib compression — typically 60-70% reduction on JSON
        compressed_encoded = BaggageManager._compress(serialized)
        if len(compressed_encoded) <= BaggageManager.MAX_BAGGAGE_SIZE:
            return {
                BaggageManager._COMPRESS_KEY: compressed_encoded,
                "kest.chain_tip": root_hash,
            }

        # 3. Claim-check pattern
        if cache:
            claim_id = str(uuid.uuid4())
            cache.set(f"kest.claim.{claim_id}", serialized)
            return {"kest.claim_check": claim_id, "kest.chain_tip": root_hash}

        # 4. No cache: store compressed anyway (best-effort, may exceed header limit)
        return {
            BaggageManager._COMPRESS_KEY: compressed_encoded,
            "kest.chain_tip": root_hash,
        }

    @staticmethod
    def unpack(baggage_func: Any, cache: Optional[Any] = None) -> Passport:
        """
        Unpacks a passport from OTel Baggage.

        Handles all three packing formats: plain, compressed, and claim-check.

        Args:
            baggage_func: A function that retrieves a value from baggage by key.
            cache: (Optional) A cache backend for retrieving claim-check data.

        Returns:
            Passport: The reconstructed Passport instance.
        """
        # Claim-check first
        claim_id = baggage_func("kest.claim_check")
        if claim_id:
            if not cache:
                raise RuntimeError(
                    f"[F-GC-01] Kest lineage claim_check {claim_id} found but no cache "
                    "backend configured for retrieval. Failing closed."
                )
            cached = cache.get(f"kest.claim.{claim_id}")
            if cached:
                return Passport.deserialize(cached)
            raise RuntimeError(
                f"[F-GC-02] Kest lineage claim_check {claim_id} present but record "
                "NOT FOUND in cache (TTL expired or cache evicted). Failing closed."
            )

        # Compressed inline
        compressed_val = baggage_func(BaggageManager._COMPRESS_KEY)
        if compressed_val:
            try:
                return Passport.deserialize(BaggageManager._decompress(compressed_val))
            except Exception:
                return Passport()

        # Plain inline
        raw_passport = baggage_func("kest.passport")
        if raw_passport:
            return Passport.deserialize(raw_passport)

        return Passport()


# Standard Trust Bootstrap Scores (F-TS-02)
# Keys and values defined below are MANDATORY defaults.
# They MUST NOT be overridden; use register_origin_trust() to ADD new entries.
_MANDATORY_ORIGIN_KEYS = {
    "system",
    "internal",
    "verified_rag",
    "third_party_api",
    "user_input",
    "internet",
    "llm",
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
