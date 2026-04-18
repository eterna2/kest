import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import rfc8785

# Ensure version matches Cargo.toml
VERSION = "0.3.0"


def version() -> str:
    return VERSION


@dataclass
class KestEntry:
    entry_id: str
    operation: str
    classification: str
    trust_score: int
    parent_ids: Optional[List[str]] = None
    labels: Optional[Dict[str, str]] = None
    added_taints: Optional[List[str]] = None
    removed_taints: Optional[List[str]] = None
    taints: Optional[List[str]] = None
    schema_version: Optional[str] = None
    runtime_name: Optional[str] = None
    runtime_version: Optional[str] = None
    policy_context: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        c = self.classification.lower()
        if c not in ("system", "data", "critic", "snapshot", "sanitizer"):
            raise ValueError(f"Invalid classification: {self.classification}")
        self.classification = c

        self.parent_ids = self.parent_ids or []
        self.labels = self.labels or {}
        self.added_taints = self.added_taints or []
        self.removed_taints = self.removed_taints or []
        self.taints = self.taints or []

        self.schema_version = self.schema_version or "0.3.0"
        self.runtime_name = self.runtime_name or "kest-python"
        self.runtime_version = self.runtime_version or version()

        pc = self.policy_context or {}
        self.policy_context = {
            "enterprise_policies": pc.get("enterprise_policies", []),
            "platform_policies": pc.get("platform_policies", []),
            "app_policies": pc.get("app_policies", []),
            "function_policies": pc.get("function_policies", []),
            "deviations": pc.get("deviations", []),
        }

        # Internal initialized fields (similar to Rust)
        self._timestamp_ms = int(time.time() * 1000)
        self._input_hash = ""
        self._content_hash = ""
        self._environment = {}
        self._otel_context = {}
        self._metadata = None

    @property
    def timestamp_ms(self) -> int:
        return self._timestamp_ms

    @property
    def input_hash(self) -> str:
        return self._input_hash

    @property
    def content_hash(self) -> str:
        return self._content_hash

    @property
    def environment(self) -> Dict[str, str]:
        return self._environment

    @property
    def otel_context(self) -> Dict[str, str]:
        return self._otel_context

    @property
    def metadata(self) -> Optional[Any]:
        return self._metadata


def sign_entry(entry: KestEntry, provider: Any) -> str:
    payload_dict = {
        "added_taints": entry.added_taints,
        "classification": entry.classification,
        "content_hash": entry.content_hash,
        "entry_id": entry.entry_id,
        "environment": entry.environment,
        "input_hash": entry.input_hash,
        "labels": entry.labels,
        "metadata": entry.metadata,
        "operation": entry.operation,
        "otel_context": entry.otel_context,
        "parent_ids": entry.parent_ids,
        "policy_context": entry.policy_context,
        "removed_taints": entry.removed_taints,
        "runtime": {"name": entry.runtime_name, "version": entry.runtime_version},
        "schema_version": entry.schema_version,
        "taints": entry.taints,
        "timestamp_ms": entry.timestamp_ms,
        "trust_score": entry.trust_score,
    }

    # Canonicalize and b64 encode payload
    canonical_payload = rfc8785.dumps(payload_dict)
    # Use the public `sign` method of the identity provider
    # By contract, IdentityProvider.sign takes the raw canonical bytes
    # and returns a complete JWS string (header.payload.signature)
    return provider.sign(canonical_payload)
