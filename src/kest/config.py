from typing import Any, Optional


class KestConfig:
    """
    Global configuration object for Kest.
    Configure policy_engine to enable inline OPA evaluations during decorator executions.
    """

    def __init__(self):
        self.policy_engine: Optional[Any] = None
        self.verification_key: Optional[Any] = None


config = KestConfig()
