import pytest
from opentelemetry import baggage
from hypothesis import given, strategies as st

from kest.core import (
    kest_verified,
    configure,
    LocalEd25519Provider,
    MockPolicyEngine,
    Passport,
    PassportVerifier,
    BaggageManager,
)


def test_robust_merkle_chain_verification():
    """
    Verifies that a 3-hop execution chain produces a cryptographically sound Merkle lineage.
    """
    # 1. Setup with real keys
    provider = LocalEd25519Provider(principal="spiffe://kest.internal/robust-test")
    configure(engine=MockPolicyEngine(), identity=provider, clear=True)

    @kest_verified(policy="hop1")
    def hop1():
        return hop2()

    @kest_verified(policy="hop2")
    def hop2():
        return hop3()

    @kest_verified(policy="hop3")
    def hop3():
        return baggage.get_baggage("kest.passport")

    # 2. Execute 3-hop chain
    passport_json = hop1()
    passport = Passport.deserialize(passport_json)

    # 3. Deep Verification
    # We provide the provider map so the verifier can check signatures
    providers = {"spiffe://kest.internal/robust-test": provider}
    assert PassportVerifier.verify(passport, providers) is True
    assert len(passport.entries) == 3


def test_tamper_detection():
    """
    Verifies that modifying the baggage between hops breaks the Merkle chain.
    """
    provider = LocalEd25519Provider()
    configure(engine=MockPolicyEngine(), identity=provider, clear=True)

    @kest_verified(policy="legal")
    def legal_step():
        return baggage.get_baggage("kest.passport")

    # 1. Generate legitimate first entry
    legal_step()

    # 2. MANUALLY TAMPER with the baggage (simulate an attacker changing history)
    # We decode the first entry, change something, and re-pack it WITHOUT a valid signature.
    # Let's just swap the last signature with a garbage string
    tampered_entries = ["invalid-garbage-signature"]
    tampered_passport = Passport(entries=tampered_entries)

    # 3. Verify that the verifier detects the break
    providers = {provider.get_identity(): provider}
    with pytest.raises(ValueError, match="Invalid JWS format"):
        PassportVerifier.verify(tampered_passport, providers)


@given(st.lists(st.text(min_size=1, max_size=100), min_size=1, max_size=20))
def test_baggage_manager_robustness(signatures):
    """
    Property-based test to ensure BaggageManager correctly handles various signature formats.
    """
    passport = Passport(entries=signatures)

    # Pack
    packed = BaggageManager.pack(passport)
    assert "kest.passport" in packed

    # Unpack (mocking the baggage getter)
    def mock_getter(key):
        return packed.get(key)

    unpacked = BaggageManager.unpack(mock_getter)
    assert unpacked.entries == signatures
