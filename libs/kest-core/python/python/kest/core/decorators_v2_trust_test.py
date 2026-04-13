import pytest
from kest.core.models import TrustEvaluator
from kest.core.decorators_v2 import kest_verified

class MockIdentityProvider:
    def get_did(self):
        return "did:example:123"

    def sign(self, payload: bytes) -> str:
        import base64
        return base64.b64encode(payload).decode()

class CaptureEngine:
    def __init__(self):
        self.captured_score = None

    def evaluate(self, entry_id, policy_names, context):
        self.captured_score = context.get("trust_score")
        return True

@pytest.fixture(autouse=True)
def setup_active_backends(monkeypatch):
    import os
    from kest.core._core import v2  # type: ignore

    
    capture = CaptureEngine()
    engine = v2.RustPolicyEngine.foreign(capture.evaluate)
    provider = MockIdentityProvider()
    monkeypatch.setattr("kest.core._active_engine", engine, raising=False)
    monkeypatch.setattr("kest.core._active_identity", provider, raising=False)
    yield capture
    service = os.getenv("SERVICE_NAME", "unknown")
    if os.path.exists(f"/tmp/.kest_lab_{service}.json"):
        os.remove(f"/tmp/.kest_lab_{service}.json")

class CustomEvaluator(TrustEvaluator):
    def calculate(self, self_score: int, parent_scores: list) -> int:
        return 42

def test_custom_trust_evaluator_v2(setup_active_backends):
    capture = setup_active_backends
    evaluator = CustomEvaluator()
    @kest_verified("test-policy", trust_evaluator=evaluator, origin="internet")
    def compute():
        return "root"
        
    compute()
    
    # Is evaluator applied? "internet" normally maps to 10
    # But evaluator should return 42! Wait! 
    assert int(capture.captured_score) == 42
