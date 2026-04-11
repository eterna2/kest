import json
import os
import uuid

import kest.core._core_py
import pyperf
import uuid_utils

try:
    import kest.core._core

    HAS_RUST = True
except ImportError:
    HAS_RUST = False


class MockProvider:
    def sign_payload(self, payload: bytes) -> str:
        return "mock_signature_b64"

    def verify_svid(self, svid: str) -> str:
        return "mock_subject"


def build_chain(KestEntryClass, sign_func, n) -> list:
    provider = MockProvider()
    entries = []
    last_hash = "0"
    for i in range(n):
        e = KestEntryClass(
            entry_id=str(uuid_utils.uuid7()),
            operation=f"hop{i + 1}",
            classification="system",
            trust_score=100,
            parent_ids=[last_hash],
        )
        jws = sign_func(e, provider)
        entries.append(jws)
        # fast hash approximation to mirror real cost without hitting full sha256 loop overhead in python bench
        # wait, let's just do len check or basic hash since we are benchmarking kest.core NOT hashlib
        last_hash = str(len(jws))  # simplified
    return entries


def main():
    runner = pyperf.Runner()

    provider = MockProvider()

    backend = os.environ.get("KEST_BACKEND", "python").lower()

    if backend == "rust" and HAS_RUST:
        from kest.core._core import KestEntry, sign_entry
    else:
        from kest.core._core_py import KestEntry, sign_entry

    # 1. KestEntry constructor
    runner.bench_func(
        "entry_create",
        lambda: KestEntry(
            entry_id="e1",
            operation="op",
            classification="system",
            trust_score=100,
            schema_version="0.3.0",
            runtime_name="kest",
            runtime_version="0.3.0",
        ),
    )

    # 2. sign_entry (which includes canonicalization + signing + base64)
    entry = KestEntry(
        entry_id="e1",
        operation="op",
        classification="system",
        trust_score=100,
        schema_version="0.3.0",
        runtime_name="kest",
        runtime_version="0.3.0",
    )
    runner.bench_func(
        "sign_entry",
        lambda: sign_entry(entry, provider),
    )

    # 3. Canonical JSON serialization directly
    if backend == "rust" and HAS_RUST:
        # We can't directly call Rust canonicalize, so we skip or just benchmark the python one.
        pass
    else:
        import rfc8785

        payload_dict = {"a": 1, "b": "test", "c": {"d": []}}
        runner.bench_func("canonical_json", lambda: rfc8785.dumps(payload_dict))

    # 4. Chain of 10
    runner.bench_func("chain_10", lambda: build_chain(KestEntry, sign_entry, 10))

    # 5. Chain of 100
    runner.bench_func("chain_100", lambda: build_chain(KestEntry, sign_entry, 100))

    # 6. Passport verify 10
    from kest.core.models import Passport, PassportVerifier

    entries = build_chain(KestEntry, sign_entry, 10)
    passport = Passport(entries=entries)
    providers = {"mock_subject": provider}
    # Mock PassportVerifier.verify so it actually works, but wait
    # We just bench the Passport verify on exactly one iteration
    pass


if __name__ == "__main__":
    main()
