import base64
import hashlib
import json
import uuid

import pytest
from opentelemetry import baggage
from opentelemetry import context as otel_context

from kest.core import (
    LocalEd25519Provider,
    MockIdentityProvider,
    MockPolicyEngine,
    configure,
    kest_verified,
)
from kest.core import KestEntry
from kest.core.models import BaggageManager, Passport, PassportVerifier


# Helpers for testing
def _decode_payload(jws: str) -> dict:
    parts = jws.split(".")
    padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def _get_hash(sig: str) -> str:
    return hashlib.sha256(sig.encode()).hexdigest()


@pytest.fixture(autouse=True)
def setup_kest():
    """Setup a fresh Kest configuration for each test."""
    configure(engine=MockPolicyEngine(), identity=MockIdentityProvider(), clear=True)


# ===========================================================================
# 1. PASSPORT MERGE TESTS
# ===========================================================================


def test_passport_merge_uniqueness_and_order():
    """Verify that merging passports deduplicates entries and preserves order."""
    p1 = Passport(entries=["sig1", "sig2"])
    p2 = Passport(entries=["sig2", "sig3"])
    p3 = Passport(entries=["sig1", "sig4"])

    merged = Passport.merge(p1, p2, p3)
    assert merged.entries == ["sig1", "sig2", "sig3", "sig4"]


# ===========================================================================
# 2. DAG VERIFICATION TESTS (Unit Level)
# ===========================================================================


def test_verify_fan_in_topology():
    """
    Test a Fan-In scenario where C depends on both A and B.
    A -> C
    B -> C
    """
    provider = LocalEd25519Provider(principal="spiffe://test/dag")
    from kest.core import sign_entry

    # 1. Create Root A
    e_a = KestEntry(
        entry_id=str(uuid.uuid4()),
        operation="A",
        classification="system",
        trust_score=100,
        parent_ids=["0"],
    )
    sig_a = sign_entry(e_a, provider)
    hash_a = _get_hash(sig_a)

    # 2. Create Root B
    e_b = KestEntry(
        entry_id=str(uuid.uuid4()),
        operation="B",
        classification="system",
        trust_score=100,
        parent_ids=["0"],
    )
    sig_b = sign_entry(e_b, provider)
    hash_b = _get_hash(sig_b)

    # 3. Create Child C merging A and B
    # Note: entries must be in topological order for verification to succeed.
    e_c = KestEntry(
        entry_id=str(uuid.uuid4()),
        operation="C",
        classification="system",
        trust_score=100,
        parent_ids=[hash_a, hash_b],
    )
    sig_c = sign_entry(e_c, provider)

    passport = Passport(entries=[sig_a, sig_b, sig_c])
    providers = {"spiffe://test/dag": provider}

    assert PassportVerifier.verify(passport, providers) is True


def test_verify_diamond_topology():
    """
    A -> B -> D
    A -> C -> D
    """
    provider = LocalEd25519Provider(principal="spiffe://test/diamond")
    from kest.core import sign_entry

    # A
    e_a = KestEntry(
        entry_id=str(uuid.uuid4()),
        operation="A",
        classification="system",
        trust_score=100,
        parent_ids=["0"],
    )
    sig_a = sign_entry(e_a, provider)
    hash_a = _get_hash(sig_a)

    # B (parent A)
    e_b = KestEntry(
        entry_id=str(uuid.uuid4()),
        operation="B",
        classification="system",
        trust_score=100,
        parent_ids=[hash_a],
    )
    sig_b = sign_entry(e_b, provider)
    hash_b = _get_hash(sig_b)

    # C (parent A)
    e_c = KestEntry(
        entry_id=str(uuid.uuid4()),
        operation="C",
        classification="system",
        trust_score=100,
        parent_ids=[hash_a],
    )
    sig_c = sign_entry(e_c, provider)
    hash_c = _get_hash(sig_c)

    # D (parents B, C)
    e_d = KestEntry(
        entry_id=str(uuid.uuid4()),
        operation="D",
        classification="system",
        trust_score=100,
        parent_ids=[hash_b, hash_c],
    )
    sig_d = sign_entry(e_d, provider)

    passport = Passport(entries=[sig_a, sig_b, sig_c, sig_d])
    providers = {"spiffe://test/diamond": provider}
    assert PassportVerifier.verify(passport, providers) is True


def test_verify_skip_connection():
    """
    A -> B -> C
    A -> C
    """
    provider = LocalEd25519Provider(principal="spiffe://test/skip")
    from kest.core import sign_entry

    e_a = KestEntry(
        entry_id=str(uuid.uuid4()),
        operation="A",
        classification="system",
        trust_score=100,
        parent_ids=["0"],
    )
    sig_a = sign_entry(e_a, provider)
    hash_a = _get_hash(sig_a)

    e_b = KestEntry(
        entry_id=str(uuid.uuid4()),
        operation="B",
        classification="system",
        trust_score=100,
        parent_ids=[hash_a],
    )
    sig_b = sign_entry(e_b, provider)
    hash_b = _get_hash(sig_b)

    # C depends on B and A directly
    e_c = KestEntry(
        entry_id=str(uuid.uuid4()),
        operation="C",
        classification="system",
        trust_score=100,
        parent_ids=[hash_b, hash_a],
    )
    sig_c = sign_entry(e_c, provider)

    passport = Passport(entries=[sig_a, sig_b, sig_c])
    providers = {"spiffe://test/skip": provider}
    assert PassportVerifier.verify(passport, providers) is True


# ===========================================================================
# 3. DECORATOR MULTI-PARENT TESTS
# ===========================================================================


def test_decorator_merges_multiple_tips():
    """
    Test that @kest_verified handles comma-separated chain tips in baggage.
    """
    # 1. Create two independent signatures to act as tips
    provider = LocalEd25519Provider(principal="spiffe://test/decorator")
    from kest.core import sign_entry

    e1 = KestEntry(
        entry_id=str(uuid.uuid4()),
        operation="Tip1",
        classification="system",
        trust_score=100,
        parent_ids=["0"],
    )
    sig1 = sign_entry(e1, provider)
    hash1 = _get_hash(sig1)

    e2 = KestEntry(
        entry_id=str(uuid.uuid4()),
        operation="Tip2",
        classification="system",
        trust_score=100,
        parent_ids=["0"],
    )
    sig2 = sign_entry(e2, provider)
    hash2 = _get_hash(sig2)

    # 2. Mock a context where both tips are present
    passport = Passport(entries=[sig1, sig2])
    bag = BaggageManager.pack(passport)

    ctx = otel_context.get_current()
    if bag.get("kest.passport"):
        ctx = baggage.set_baggage("kest.passport", bag["kest.passport"], context=ctx)
    ctx = baggage.set_baggage("kest.chain_tip", f"{hash1}, {hash2}", context=ctx)

    captured_passports = []

    token = otel_context.attach(ctx)
    try:

        @kest_verified(policy="test")
        def merged_step():
            captured_passports.append(BaggageManager.unpack(baggage.get_baggage))
            return "ok"

        merged_step()

        # Check that inside the function, we saw 3 entries (including the new one)
        assert len(captured_passports) == 1
        final_passport = captured_passports[0]
        assert len(final_passport.entries) == 3

        last_sig = final_passport.entries[-1]
        payload = _decode_payload(last_sig)
        assert sorted(payload["parent_ids"]) == sorted([hash1, hash2])

    finally:
        otel_context.detach(token)


def test_decorator_fan_out_isolated_lineage():
    """
    Test that Fan-Out works (parallel branches don't bleed into each other).
    """
    captured_state = {}

    @kest_verified(policy="branch")
    def branch(name):
        captured_state[name] = {
            "tip": baggage.get_baggage("kest.chain_tip"),
            "passport": BaggageManager.unpack(baggage.get_baggage),
        }
        return f"branch_{name}"

    @kest_verified(policy="root")
    def run_parallel():
        branch("A")
        branch("B")

    run_parallel()

    state_a = captured_state["A"]
    state_b = captured_state["B"]

    assert state_a["tip"] is not None
    assert state_b["tip"] is not None
    assert state_a["tip"] != state_b["tip"]

    pass_a = state_a["passport"]
    pass_b = state_b["passport"]

    # run_parallel is parent for both
    # lineage: [run_parallel, branchA] vs [run_parallel, branchB]
    assert len(pass_a.entries) == 2
    assert len(pass_b.entries) == 2

    # The first entry should be same (run_parallel)
    assert pass_a.entries[0] == pass_b.entries[0]

    # The last entries should be different
    assert pass_a.entries[1] != pass_b.entries[1]
    assert pass_b.entries[1] not in pass_a.entries
    assert pass_a.entries[1] not in pass_b.entries

    # Now merge them back
    merged_pass = Passport.merge(pass_a, pass_b)
    assert len(merged_pass.entries) == 3  # run_parallel, branchA, branchB

    # Verify Merkle links
    providers = {"spiffe://test/mock": MockIdentityProvider()}
    assert PassportVerifier.verify(merged_pass, providers) is True
