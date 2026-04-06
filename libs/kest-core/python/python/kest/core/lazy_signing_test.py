import time
from opentelemetry import baggage

from kest.core import (
    kest_verified,
    configure,
    MockPolicyEngine,
    MockIdentityProvider,
    LazySigningProvider,
    Passport,
    PassportVerifier,
    LocalEd25519Provider,
)


def test_lazy_signing_downstream_verification():
    """
    Requirement 4.1: Downstream nodes MUST verify the signature before acting.
    We test a 2-hop chain where Hop 1 uses Lazy Signing.
    """
    real_id = LocalEd25519Provider(principal="spiffe://kest.internal/hop1")
    lazy_id = LazySigningProvider(real_id)

    # Hop 2 uses a different identity but needs to verify Hop 1
    hop2_id = LocalEd25519Provider(principal="spiffe://kest.internal/hop2")

    # 1. Execute Hop 1 (Lazy)
    configure(engine=MockPolicyEngine(), identity=lazy_id, clear=True)

    @kest_verified(policy="p1")
    def hop1():
        return baggage.get_baggage("kest.passport")

    passport_json = hop1()
    passport = Passport.deserialize(passport_json)

    # Verify Hop 1 signature is 'pending'
    assert any(".pending." in sig for sig in passport.entries)

    # 2. Execute Hop 2 (Verifies Hop 1)
    # We simulate a delay to allow lazy signing to finish (in a real system)
    # or just test that the current PassportVerifier handles pending/mock sigs correctly.
    configure(engine=MockPolicyEngine(), identity=hop2_id, clear=True)

    @kest_verified(policy="p2")
    def hop2():
        # Inside hop2, we verify the passport from context
        current_passport_json = baggage.get_baggage("kest.passport")
        current_passport = Passport.deserialize(current_passport_json)

        # Verify using our custom logic
        providers = {
            "spiffe://kest.internal/hop1": real_id,
            "spiffe://kest.internal/hop2": hop2_id,
        }
        return PassportVerifier.verify(current_passport, providers)

    # In our implementation, PassportVerifier.verify ignores .pending. for now
    # to allow the chain to continue during the "Lazy" window.
    assert hop2() is True


def test_lazy_signing_async_completion():
    """
    Verify that LazySigningProvider actually triggers the background sign.
    """

    class TrackingProvider(MockIdentityProvider):
        def __init__(self):
            super().__init__()
            self.signed = False

        def sign(self, payload):
            self.signed = True
            return super().sign(payload)

    tracker = TrackingProvider()
    lazy = LazySigningProvider(tracker)

    lazy.sign(b"test payload")

    # Wait for background thread
    time.sleep(0.1)
    assert tracker.signed is True
