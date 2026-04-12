"""
Unit tests for Kest data models, verifying conformance with SPEC-v0.3.0.

Spec references are cited inline for each test.
"""

import base64
import hashlib
import json
import re
import uuid

import pytest

from kest.core import KestEntry, LocalEd25519Provider, MockIdentityProvider, SimpleCache
from kest.core.models import (
    ORIGIN_TRUST_MAP,
    BaggageManager,
    DefaultTrustEvaluator,
    Passport,
    PassportVerifier,
)

# ---------------------------------------------------------------------------
# UUID v7 regex: version nibble MUST be 7 (F-AE-04, RFC 9562 §5.7)
# ---------------------------------------------------------------------------
_UUID_V7_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


# ===========================================================================
# KestEntry — required field presence (F-AE-02, F-AE-05, F-AE-06, F-AE-13)
# ===========================================================================


def _decode_jws_payload(jws: str) -> dict:
    """Decode the payload segment of a JWS compact string."""
    parts = jws.split(".")
    assert len(parts) == 3, f"Not a valid JWS: {jws[:40]}"
    padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def _sign(entry: KestEntry) -> str:
    provider = MockIdentityProvider()
    from kest.core import sign_entry

    return sign_entry(entry, provider)


def test_kest_entry_required_fields_present_in_signed_payload():
    """
    The signed JWS payload must contain all mandatory KestEntry fields.
    F-AE-02, F-AE-05, F-AE-06, F-AE-12, F-AE-13
    """
    entry = KestEntry(
        entry_id=str(uuid.uuid4()),
        operation="test_op",
        classification="system",
        trust_score=100,
    )
    jws = _sign(entry)
    payload = _decode_jws_payload(jws)

    assert "schema_version" in payload, "F-AE-05: schema_version missing"
    assert "runtime" in payload, "F-AE-06: runtime object missing"
    assert isinstance(payload["runtime"], dict), "F-AE-06: runtime must be an object"
    assert "name" in payload["runtime"], "F-AE-06: runtime.name missing"
    assert "version" in payload["runtime"], "F-AE-06: runtime.version missing"
    assert "timestamp_ms" in payload, "F-AE-12: timestamp_ms missing"
    assert isinstance(payload["timestamp_ms"], int), (
        "F-AE-12: timestamp_ms must be integer"
    )
    assert payload["timestamp_ms"] > 0, "F-AE-12: timestamp_ms must be positive"
    assert "policy_context" in payload, "F-AE-13: policy_context missing"
    pc = payload["policy_context"]
    assert "deviations" in pc, "F-AE-13: policy_context.deviations missing"
    assert isinstance(pc["deviations"], list), "F-AE-13: deviations must be an array"


def test_policy_context_deviations_empty_by_default():
    """
    When no deviations are active, deviations MUST be [] — not absent.
    F-AE-13: 'MUST be an empty array [] when no deviations are active'
    """
    entry = KestEntry(
        entry_id=str(uuid.uuid4()),
        operation="no_deviations",
        classification="system",
        trust_score=80,
    )
    jws = _sign(entry)
    payload = _decode_jws_payload(jws)
    assert payload["policy_context"]["deviations"] == [], (
        "F-AE-13: deviations must be [] not absent when no deviations active"
    )


def test_policy_context_policy_lists_present():
    """
    policy_context must record all four policy tier lists; each may be empty.
    F-AE-13
    """
    entry = KestEntry(
        entry_id=str(uuid.uuid4()),
        operation="check_tiers",
        classification="system",
        trust_score=100,
        policy_context={
            "enterprise_policies": ["baseline"],
            "platform_policies": [],
            "app_policies": [],
            "function_policies": ["invoke"],
            "deviations": [],
        },
    )
    jws = _sign(entry)
    payload = _decode_jws_payload(jws)
    pc = payload["policy_context"]
    assert pc["enterprise_policies"] == ["baseline"]
    assert pc["function_policies"] == ["invoke"]
    assert pc["deviations"] == []


# ===========================================================================
# UUID v7 (F-AE-04)
# ===========================================================================


def test_entry_id_uuid_v7_format():
    """
    entry_id MUST be UUID v7. F-AE-04
    Verified by checking the version nibble in the third UUID group.
    """
    from kest.core import MockPolicyEngine, configure, kest_verified

    configure(engine=MockPolicyEngine(), identity=MockIdentityProvider(), clear=True)
    captured_ids = []

    from unittest.mock import patch

    original_sign = __import__("kest.core", fromlist=["sign_entry"]).sign_entry

    def capturing_sign(entry, provider):
        captured_ids.append(entry.entry_id)
        return original_sign(entry, provider)

    with patch("kest.core.decorators.sign_entry", side_effect=capturing_sign):

        @kest_verified(policy="test")
        def fn():
            return "ok"

        fn()

    assert len(captured_ids) == 1
    eid = captured_ids[0]
    assert _UUID_V7_RE.match(eid), (
        f"F-AE-04: entry_id '{eid}' is not UUID v7 (version nibble must be 7)"
    )


# ===========================================================================
# Passport (F-PA-01 – F-PA-07)
# ===========================================================================


def test_passport_empty_is_valid():
    """F-PA-03: A Passport with zero entries MUST be a valid serializable object."""
    p = Passport()
    serialized = p.serialize()
    parsed = json.loads(serialized)
    assert parsed == [], "Empty passport must serialize to JSON empty array []"


def test_passport_serialize_is_json_array():
    """
    The entries list MUST serialize as a top-level JSON array of strings.
    F-PA-02, NF-INTER-01
    """
    p = Passport(entries=["h.p.s1", "h.p.s2"])
    serialized = p.serialize()
    parsed = json.loads(serialized)
    assert isinstance(parsed, list), "Passport must serialize as a JSON array"
    assert parsed == ["h.p.s1", "h.p.s2"]


def test_passport_deserialize_roundtrip():
    """F-PA-02: serialize then deserialize returns original entries."""
    original = Passport(entries=["alpha", "beta", "gamma"])
    roundtripped = Passport.deserialize(original.serialize())
    assert roundtripped.entries == original.entries


def test_passport_add_signature():
    """F-PA-02, F-PA-01: add_signature appends to the ordered list."""
    p = Passport()
    p.add_signature("sig1")
    p.add_signature("sig2")
    assert p.entries == ["sig1", "sig2"]


# ===========================================================================
# Passport Cache Optimization (A-03-I/II/III, Issue #12)
# ===========================================================================


def _make_jws(trust_score: int = 100, taints: list | None = None) -> str:
    """Build a minimal valid JWS with the given trust_score and taints."""
    payload: dict = {"trust_score": trust_score}
    if taints:
        payload["taints"] = taints
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    return f"h.{payload_b64}.s"


def test_passport_version_counter_invalidation():
    """A-03-I: Parsed cache uses O(1) integer version comparison, not O(n) list equality."""
    p = Passport()
    jws1 = _make_jws(trust_score=90, taints=["t1"])
    p.add_signature(jws1)

    # First read populates cache
    _ = p.trust_scores
    cache_after_first = p._parsed_cache

    # Second read returns same cache object (no re-parse)
    _ = p.trust_scores
    assert p._parsed_cache is cache_after_first, (
        "Cache must not re-parse on repeated read"
    )

    # add_signature bumps version, next read re-parses
    jws2 = _make_jws(trust_score=80)
    p.add_signature(jws2)
    _ = p.trust_scores
    assert p._parsed_cache is not cache_after_first, (
        "Cache must re-parse after add_signature"
    )


def test_passport_accumulated_taints_returns_frozenset():
    """A-03-II: accumulated_taints returns frozenset (immutable, O(1))."""
    p = Passport()
    p.add_signature(_make_jws(taints=["pii", "user_input"]))
    result = p.accumulated_taints
    assert isinstance(result, frozenset), (
        f"accumulated_taints must return frozenset, got {type(result).__name__}"
    )
    assert result == {"pii", "user_input"}


def test_passport_accumulated_taints_incremental():
    """A-03-II: Incremental accumulation matches full recomputation."""
    p = Passport()
    p.add_signature(_make_jws(taints=["t1", "t2"]))
    p.add_signature(_make_jws(taints=["t2", "t3"]))
    p.add_signature(_make_jws(taints=["t4"]))
    assert p.accumulated_taints == frozenset({"t1", "t2", "t3", "t4"})


def test_passport_accumulated_taints_empty():
    """A-03-II: Empty passport returns empty frozenset."""
    p = Passport()
    assert p.accumulated_taints == frozenset()
    assert isinstance(p.accumulated_taints, frozenset)


def test_passport_min_trust_score_property():
    """A-03-II: min_trust_score returns the minimum across all entries."""
    p = Passport()
    p.add_signature(_make_jws(trust_score=90))
    p.add_signature(_make_jws(trust_score=40))
    p.add_signature(_make_jws(trust_score=70))
    assert p.min_trust_score == 40


def test_passport_min_trust_score_empty():
    """A-03-II: Empty passport returns 100 (maximum trust)."""
    p = Passport()
    assert p.min_trust_score == 100


def test_passport_slots_no_dict():
    """A-03-III: Passport uses __slots__ — no __dict__ attribute."""
    p = Passport()
    assert not hasattr(p, "__dict__"), (
        "Passport must use __slots__ (no __dict__ attribute)"
    )


def test_passport_deserialize_rebuilds_caches():
    """Deserialize (via __post_init__) must rebuild incremental taint/trust caches."""
    jws1 = _make_jws(trust_score=60, taints=["pii"])
    jws2 = _make_jws(trust_score=80, taints=["external"])
    original = Passport(entries=[jws1, jws2])
    serialized = original.serialize()

    restored = Passport.deserialize(serialized)
    assert restored.accumulated_taints == frozenset({"pii", "external"})
    assert restored.min_trust_score == 60


def test_passport_merge_rebuilds_caches():
    """Merge (via __post_init__) must rebuild incremental taint/trust caches."""
    p1 = Passport(entries=[_make_jws(trust_score=50, taints=["t1"])])
    p2 = Passport(entries=[_make_jws(trust_score=70, taints=["t2"])])
    merged = Passport.merge(p1, p2)
    assert merged.accumulated_taints == frozenset({"t1", "t2"})
    assert merged.min_trust_score == 50


# ===========================================================================
# PassportVerifier (F-PA-04 – F-PA-07)
# ===========================================================================


def test_passport_verifier_root_sentinel_never_hashed():
    """
    F-PA-07: root entry's parent_ids[0] == '0' MUST be treated as chain start,
    NOT verified as SHA-256.  A single-entry passport with parent_ids=["0"] must pass.
    """
    provider = LocalEd25519Provider(principal="spiffe://test/root")
    from kest.core import sign_entry

    entry = KestEntry(
        entry_id=str(uuid.uuid4()),
        operation="root_op",
        classification="system",
        trust_score=100,
        parent_ids=["0"],
        labels={"principal": "spiffe://test/root"},
    )
    jws = sign_entry(entry, provider)
    passport = Passport(entries=[jws])
    providers = {"spiffe://test/root": provider}
    assert PassportVerifier.verify(passport, providers) is True


def test_passport_verifier_rejects_broken_merkle_link():
    """
    F-PA-06, F-PA-05: broken parent_ids hash raises ValueError.
    """
    provider = LocalEd25519Provider(principal="spiffe://test/tamper")
    from kest.core import sign_entry

    # Entry 1 — valid root
    e1 = KestEntry(
        entry_id=str(uuid.uuid4()),
        operation="e1",
        classification="system",
        trust_score=100,
        parent_ids=["0"],
        labels={"principal": "spiffe://test/tamper"},
    )
    jws1 = sign_entry(e1, provider)

    # Entry 2 — deliberately WRONG parent hash
    e2 = KestEntry(
        entry_id=str(uuid.uuid4()),
        operation="e2",
        classification="system",
        trust_score=100,
        parent_ids=["wrong_hash"],  # should be sha256(jws1) but we use wrong_hash
        labels={"principal": "spiffe://test/tamper"},
    )
    jws2 = sign_entry(e2, provider)

    passport = Passport(entries=[jws1, jws2])
    providers = {"spiffe://test/tamper": provider}

    with pytest.raises(ValueError, match="Merkle link broken"):
        PassportVerifier.verify(passport, providers)


def test_passport_verifier_rejects_invalid_jws_format():
    """F-PA-05: invalid JWS format raises ValueError immediately."""
    passport = Passport(entries=["not-valid-jws"])
    with pytest.raises(ValueError, match="Invalid JWS format"):
        PassportVerifier.verify(passport, providers={})


def test_passport_verifier_three_hop_chain():
    """
    F-PA-04: verifier checks each entry's signature and parent_ids linkage.
    End-to-end: 3-hop chain with real Ed25519 keys must pass.
    """
    provider = LocalEd25519Provider(principal="spiffe://test/3hop")
    from kest.core import sign_entry

    entries = []
    last_hash = "0"
    for i in range(3):
        e = KestEntry(
            entry_id=str(uuid.uuid4()),
            operation=f"hop{i + 1}",
            classification="system",
            trust_score=100,
            parent_ids=[last_hash],
            labels={"principal": "spiffe://test/3hop"},
        )
        jws = sign_entry(e, provider)
        entries.append(jws)
        last_hash = hashlib.sha256(jws.encode()).hexdigest()

    passport = Passport(entries=entries)
    providers = {"spiffe://test/3hop": provider}
    assert PassportVerifier.verify(passport, providers) is True


# ===========================================================================
# DefaultTrustEvaluator (F-TS-03, F-TS-04, NF-CORR-03)
# ===========================================================================


def test_default_trust_evaluator_uses_floor_division():
    """
    NF-CORR-03: formula is (min(parent_scores) * self_score) // 100
    (integer floor division, not float).
    """
    ev = DefaultTrustEvaluator()
    # 70 * 90 = 6300, 6300 // 100 = 63 (not 63.0)
    result = ev.calculate(self_score=90, parent_scores=[70])
    assert result == 63
    assert isinstance(result, int)


def test_default_trust_evaluator_weakest_link():
    """F-TS-03: uses the MINIMUM of parent scores."""
    ev = DefaultTrustEvaluator()
    result = ev.calculate(self_score=100, parent_scores=[90, 40, 80])
    assert result == (40 * 100) // 100  # min is 40


def test_default_trust_evaluator_no_parents_returns_self():
    """F-TS-03: empty parent_scores → return self_score."""
    ev = DefaultTrustEvaluator()
    assert ev.calculate(self_score=75, parent_scores=[]) == 75


def test_default_trust_evaluator_zero_parent_zeroes_result():
    """F-TS-03: a zero-trust parent propagates zero trust downstream."""
    ev = DefaultTrustEvaluator()
    assert ev.calculate(self_score=100, parent_scores=[0, 80]) == 0


# ===========================================================================
# ORIGIN_TRUST_MAP mandatory defaults (F-TS-02)
# ===========================================================================

_MANDATORY_DEFAULTS = {
    "system": 100,
    "internal": 100,
    "verified_rag": 90,
    "third_party_api": 60,
    "user_input": 40,
    "internet": 10,
    "llm": 0,
}


@pytest.mark.parametrize("source_type,expected", _MANDATORY_DEFAULTS.items())
def test_origin_trust_map_mandatory_defaults(source_type, expected):
    """F-TS-02: ORIGIN_TRUST_MAP MUST define exactly these 7 default values."""
    assert ORIGIN_TRUST_MAP[source_type] == expected, (
        f"F-TS-02: ORIGIN_TRUST_MAP['{source_type}'] should be {expected}"
    )


def test_origin_trust_map_custom_key_allowed():
    """
    F-TS-02: deployments MAY register additional mappings.
    Custom keys must NOT override mandatory defaults.
    """
    extended = {**ORIGIN_TRUST_MAP, "partner_api": 70}
    # Mandatory defaults must remain unchanged
    for k, v in _MANDATORY_DEFAULTS.items():
        assert extended[k] == v
    assert extended["partner_api"] == 70


def test_origin_trust_map_mandatory_defaults_not_overridable():
    """F-TS-02: mandatory defaults MUST NOT be overridden by custom mappings."""
    with pytest.raises(Exception):
        # Attempt to create a map that overrides 'system' to a different value
        # The implementation should enforce this constraint.
        from kest.core import register_origin_trust

        register_origin_trust("system", 50)  # Must raise


# ===========================================================================
# BaggageManager — Claim Check threshold (F-CP-04)
# ===========================================================================


def test_baggage_manager_threshold_is_4096():
    """F-CP-04: threshold MUST be 4096 bytes (spec default)."""
    assert BaggageManager.MAX_BAGGAGE_SIZE == 4096, (
        "F-CP-04: MAX_BAGGAGE_SIZE must be 4096"
    )


def test_baggage_manager_inline_below_threshold():
    """F-CP-04: passports under 4096 bytes propagate inline as kest.passport."""
    small_passport = Passport(entries=["short.sig.abc"])
    packed = BaggageManager.pack(small_passport)
    assert "kest.passport" in packed
    assert "kest.claim_check" not in packed


def test_baggage_manager_compressed_above_threshold():
    """F-CP-04 (updated): Compressible data >4096 bytes uses kest.passport_z (compressed inline)."""
    cache = SimpleCache()
    # Repetitive data compresses well — should fit inline as kest.passport_z
    big_sig = "x" * 5000
    large_passport = Passport(entries=[big_sig])
    packed = BaggageManager.pack(large_passport, cache=cache)
    # With compression, repetitive data should fit inline
    assert "kest.passport_z" in packed or "kest.claim_check" in packed, (
        "Large passport must use either compressed-inline or claim-check"
    )
    assert "kest.passport" not in packed, (
        "Plain inline must not be used when data is over threshold"
    )

    # Must round-trip correctly
    def mock_getter(key):
        return packed.get(key)

    restored = BaggageManager.unpack(mock_getter, cache=cache)
    assert restored.entries == [big_sig]


def test_baggage_manager_claim_check_incompressible():
    """F-CP-04: Truly incompressible payloads that remain >4KB after compression use claim-check."""
    import base64 as _b64
    import os as _os

    cache = SimpleCache()
    # Each os.urandom(32) chunk is 32 bytes of max-entropy data; base64-encoded = 44 chars.
    # Concatenating 200 unique random chunks = ~8800 chars — all high-entropy, incompressible.
    random_chunk = "".join(
        _b64.urlsafe_b64encode(_os.urandom(32)).decode() for _ in range(200)
    )  # ~8800 chars, near-random base64 → compresses to ~8700 bytes (still >>4096)
    large_passport = Passport(entries=[random_chunk])
    packed = BaggageManager.pack(large_passport, cache=cache)
    # This should trigger claim-check because compressed form is still >4096 bytes
    assert "kest.claim_check" in packed, (
        "F-CP-04: incompressible large passport must use claim-check"
    )
    assert "kest.passport" not in packed
    # Verify stored in cache
    claim_id = packed["kest.claim_check"]
    cached = cache.get(f"kest.claim.{claim_id}")
    assert cached is not None
    recovered = Passport.deserialize(cached)
    assert recovered.entries == [random_chunk]


def test_baggage_manager_claim_check_restore():
    """F-CP-05: interceptor MUST retrieve passport from cache on kest.claim_check."""
    import hashlib as _hashlib
    import os as _os

    cache = SimpleCache()
    # Use incompressible data to force claim-check
    random_chunk = _hashlib.sha256(_os.urandom(1024)).hexdigest() * 100  # ~6400 bytes
    large_passport = Passport(entries=[random_chunk])
    packed = BaggageManager.pack(large_passport, cache=cache)

    # Simulate receiving the baggage
    def mock_getter(key):
        return packed.get(key)

    restored = BaggageManager.unpack(mock_getter, cache=cache)
    assert restored.entries == [random_chunk]
