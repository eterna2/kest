"""
Tests for kest-deepagents LangChain plugin.

Mock boundary: only FakeListChatModel (LLM response) is mocked.
All kest infrastructure runs for real: HardcodedRuleEngine, MockIdentityProvider,
kest_verified, OTel baggage propagation.
"""

import pytest
from opentelemetry import baggage
import opentelemetry.context as otel_context
from langchain_core.language_models.fake_chat_models import FakeListChatModel
from langchain_core.messages import HumanMessage
from langchain_core.tools import BaseTool, tool

from kest.core import (
    configure,
    invalidate_policy_cache,
    kest_verified,
    MockPolicyEngine,
)
from kest.core.identity import MockIdentityProvider

from kest.deepagents.plugins.langchain import (
    KestChatModel,
    configure_langchain,
    kest_langchain_scope,
    patch_model,
    unconfigure_langchain,
    unpatch_model,
)


# ---------------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------------


class HardcodedRuleEngine(MockPolicyEngine):
    """
    A simple rule-based policy engine with deterministic, hardcoded rules.

    Rules (evaluated in priority order, first match wins):

    1. Any policy name in ``blocked_policies``
       → DENY regardless of trust or caller.
       Use in tests by decorating with a matching policy name.

    2. ``trust_score < min_trust``
       → DENY; the operation's trust is too low for this engine.
       Use in tests by setting ``trust_override`` below the threshold.

    3. All other combinations → ALLOW.

    Args:
        blocked_policies: Set of policy names that are always denied.
                          Defaults to ``{"blocked_policy"}``.
        min_trust:        Minimum trust score required to allow an operation.
                          Defaults to ``50``.
    """

    def __init__(
        self,
        blocked_policies: frozenset[str] = frozenset({"blocked_policy"}),
        min_trust: int = 50,
    ) -> None:
        self.blocked_policies = blocked_policies
        self.min_trust = min_trust

    def evaluate(self, entry_id: str, policy_names: list, context: dict) -> bool:
        # Rule 1: explicitly blocked policy name
        if any(p in self.blocked_policies for p in policy_names):
            return False

        # Rule 2: insufficient trust score
        trust = int(context.get("trust_score", 100))
        if trust < self.min_trust:
            return False

        # Rule 3: allow everything else
        return True


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def kest_env():
    """Provide a clean kest environment for each test."""
    invalidate_policy_cache()
    configure(
        engine=HardcodedRuleEngine(
            blocked_policies=frozenset({"blocked_policy"}),
            min_trust=50,
        ),
        identity=MockIdentityProvider(),
    )
    yield
    configure(clear=True)
    invalidate_policy_cache()


def _fake_llm(*responses: str) -> FakeListChatModel:
    return FakeListChatModel(responses=list(responses))


# ---------------------------------------------------------------------------
# @tool + @kest_verified stacking — the idiomatic decoration pattern
# ---------------------------------------------------------------------------


class TestToolDecoratorStacking:
    """
    Verify that @tool applied over @kest_verified produces a valid LangChain
    BaseTool that enforces zero-trust policy enforcement.

    The pattern is:
        @tool
        @kest_verified(policy="...")
        def my_func(...): ...
    """

    def test_stacked_decorators_produce_basetool(self):
        @tool
        @kest_verified(policy="test_policy")
        def greet(name: str) -> str:
            """Greet someone."""
            return f"Hello, {name}"

        assert isinstance(greet, BaseTool)

    def test_stacked_tool_name_and_description_preserved(self):
        @tool
        @kest_verified(policy="test_policy")
        def calculate(x: int, y: int) -> int:
            """Add two numbers together."""
            return x + y

        assert calculate.name == "calculate"
        assert "Add two numbers" in calculate.description

    def test_stacked_tool_executes_on_allow(self):
        @tool
        @kest_verified(policy="test_policy")
        def double(n: int) -> int:
            """Double an integer."""
            return n * 2

        assert double.invoke({"n": 5}) == 10

    def test_stacked_tool_raises_on_blocked_policy(self):
        """
        A tool declared with ``policy="blocked_policy"`` must be denied by
        HardcodedRuleEngine Rule 1 (policy-name check), regardless of trust.
        """

        @tool
        @kest_verified(policy="blocked_policy")
        def secret(key: str) -> str:
            """Access a secret."""
            return key

        with pytest.raises(PermissionError, match="denied execution"):
            secret.invoke({"key": "value"})

    def test_stacked_tool_raises_on_low_trust(self):
        """
        A tool with ``trust_override=0`` must be denied by HardcodedRuleEngine
        Rule 2 (trust_score < MIN_TRUST), even under an otherwise-allowed policy.
        """

        @tool
        @kest_verified(policy="test_policy", trust_override=0)
        def risky(x: str) -> str:
            """A low-trust operation."""
            return x

        with pytest.raises(PermissionError, match="denied execution"):
            risky.invoke({"x": "payload"})

    def test_stacked_tool_propagates_chain_tip_into_nested_call(self):
        """
        When a tool is called, the chain_tip baggage key must be updated,
        proving the kest execution lineage grows with each tool invocation.
        """
        tips: list[str] = []

        @tool
        @kest_verified(policy="test_policy")
        def capture_tip(dummy: str) -> str:
            """Capture the current chain tip from OTel baggage."""
            ctx = otel_context.get_current()
            tips.append(str(baggage.get_baggage("kest.chain_tip", context=ctx) or ""))
            return "ok"

        # Call twice — tips must differ (chain advances)
        capture_tip.invoke({"dummy": "a"})
        capture_tip.invoke({"dummy": "b"})
        assert len(tips) == 2
        assert tips[0] != tips[1], (
            "chain_tip must advance after each kest_verified invocation"
        )

    def test_stacked_tool_context_map_forwarded_to_policy(self):
        """
        context_map kwarg on @kest_verified must surface the mapped argument
        value in the policy context (verified indirectly via engine intercept).

        Uses a local InspectEngine to capture what the engine sees during
        evaluation, verifying that context_map feeds the right keys through.
        """
        received_contexts: list[dict] = []

        class InspectEngine(HardcodedRuleEngine):
            def evaluate(self, entry_id, policy_names, context):
                received_contexts.append(dict(context))
                return super().evaluate(entry_id, policy_names, context)

        configure(engine=InspectEngine(
            blocked_policies=frozenset({"blocked_policy"}),
            min_trust=50,
        ))

        @tool
        @kest_verified(policy="test_policy", context_map={"url": "target_url"})
        def fetch(url: str) -> str:
            """Fetch a URL."""
            return f"fetched:{url}"

        fetch.invoke({"url": "https://example.com"})
        assert received_contexts, "Engine.evaluate must have been called"
        assert received_contexts[0].get("target_url") == "https://example.com"


# ---------------------------------------------------------------------------
# KestChatModel — wraps BaseChatModel.invoke with @kest_verified
# ---------------------------------------------------------------------------


class TestKestChatModel:
    """
    Verify that KestChatModel enforces zero-trust policy on every LLM
    invocation while transparently returning the underlying AIMessage.
    """

    def test_returns_ai_message_on_allow(self):
        model = KestChatModel(
            _fake_llm("Hello from the LLM!"),
            policy="llm_policy",
        )
        resp = model.invoke([HumanMessage(content="hi")])
        assert resp.content == "Hello from the LLM!"

    def test_blocks_llm_on_blocked_policy(self):
        """
        KestChatModel with ``policy="blocked_policy"`` must be denied by
        HardcodedRuleEngine Rule 1 before the LLM is ever invoked.
        """
        model = KestChatModel(
            _fake_llm("Should never reach here"),
            policy="blocked_policy",
        )
        with pytest.raises(PermissionError, match="denied execution"):
            model.invoke([HumanMessage(content="hi")])

    def test_llm_not_called_when_policy_blocked(self):
        """The underlying LLM must not be invoked at all when the policy is denied."""
        call_log: list[str] = []

        class SpyLLM(FakeListChatModel):
            responses: list[str] = ["response"]

            def _call(self, *args, **kwargs) -> str:  # type: ignore[override]
                call_log.append("called")
                return super()._call(*args, **kwargs)

        model = KestChatModel(SpyLLM(), policy="blocked_policy")
        with pytest.raises(PermissionError):
            model.invoke([HumanMessage(content="hi")])

        assert len(call_log) == 0, "LLM must not be called when kest denies"

    def test_blocks_llm_on_insufficient_trust(self):
        """
        ``trust_override=0`` must trigger HardcodedRuleEngine Rule 2
        (trust_score < MIN_TRUST) and block the LLM call.
        """
        model = KestChatModel(
            _fake_llm("blocked reply"),
            policy="llm_policy",
            trust_override=0,
        )
        with pytest.raises(PermissionError, match="denied execution"):
            model.invoke([HumanMessage(content="hello")])

    def test_trust_at_min_threshold_is_allowed(self):
        """
        ``trust_override=50`` (exactly at MIN_TRUST) must be allowed by
        HardcodedRuleEngine, proving the boundary is inclusive.
        """
        model = KestChatModel(
            _fake_llm("boundary reply"),
            policy="llm_policy",
            trust_override=HardcodedRuleEngine().min_trust,
        )
        resp = model.invoke([HumanMessage(content="hello")])
        assert resp.content == "boundary reply"

    def test_trust_below_threshold_is_denied(self):
        """
        ``trust_override=49`` (one below MIN_TRUST=50) must be denied,
        verifying the boundary is exclusive on the lower side.
        """
        model = KestChatModel(
            _fake_llm("should not appear"),
            policy="llm_policy",
            trust_override=HardcodedRuleEngine().min_trust - 1,
        )
        with pytest.raises(PermissionError, match="denied execution"):
            model.invoke([HumanMessage(content="hello")])

    def test_chain_tip_updated_after_llm_invocation(self):
        """
        After a KestChatModel.invoke call, the chain_tip baggage inside the
        function body must be different from the empty root (proving the
        kest entry was recorded).
        """
        chain_tips: list[str] = []

        class RecordingLLM(FakeListChatModel):
            responses: list[str] = ["recorded"]

            def _call(self, *args, **kwargs) -> str:  # type: ignore[override]
                ctx = otel_context.get_current()
                tip = baggage.get_baggage("kest.chain_tip", context=ctx)
                chain_tips.append(str(tip or ""))
                return super()._call(*args, **kwargs)

        model = KestChatModel(RecordingLLM(), policy="llm_policy")
        model.invoke([HumanMessage(content="hello")])

        assert len(chain_tips) == 1
        assert chain_tips[0] != "", "chain_tip must be set inside the LLM invocation"

    def test_sequential_invocations_advance_chain(self):
        """Each KestChatModel.invoke must advance the Merkle chain tip."""
        chain_tips: list[str] = []

        class TipCapturingLLM(FakeListChatModel):
            responses: list[str] = ["a", "b"]

            def _call(self, *args, **kwargs) -> str:  # type: ignore[override]
                ctx = otel_context.get_current()
                chain_tips.append(
                    str(baggage.get_baggage("kest.chain_tip", context=ctx) or "")
                )
                return super()._call(*args, **kwargs)

        model = KestChatModel(TipCapturingLLM(), policy="llm_policy")
        model.invoke([HumanMessage(content="first")])
        model.invoke([HumanMessage(content="second")])

        assert len(chain_tips) == 2
        assert chain_tips[0] != chain_tips[1], "chain must advance across invocations"

    def test_config_arg_accepted(self):
        """KestChatModel.invoke must accept an optional config argument (Runnable compat)."""
        model = KestChatModel(_fake_llm("ok"), policy="llm_policy")
        resp = model.invoke([HumanMessage(content="test")], config=None)
        assert resp.content == "ok"


# ---------------------------------------------------------------------------
# configure_langchain — global class-level patch of BaseChatModel.invoke
# ---------------------------------------------------------------------------


class TestConfigureLangchain:
    """
    configure_langchain monkey-patches BaseChatModel.invoke at the class level.
    Every model instance in the process is affected without per-model wrapping.

    Teardown: each test is responsible for calling unconfigure_langchain() in
    a finally block so the class-level patch is always restored even on failure.
    """

    def test_globally_intercepts_all_model_instances(self):
        """After configure_langchain, every BaseChatModel.invoke goes through kest."""
        model_a = _fake_llm("response_a")
        model_b = _fake_llm("response_b")

        configure_langchain(policy="test_policy")
        try:
            assert model_a.invoke([HumanMessage(content="hi")]).content == "response_a"
            assert model_b.invoke([HumanMessage(content="hi")]).content == "response_b"
        finally:
            unconfigure_langchain()

    def test_global_blocked_policy_raises_on_any_model(self):
        """configure_langchain with a blocked policy must deny all model invocations."""
        model_a = _fake_llm("a")
        model_b = _fake_llm("b")

        configure_langchain(policy="blocked_policy")
        try:
            with pytest.raises(PermissionError, match="denied execution"):
                model_a.invoke([HumanMessage(content="hi")])
            with pytest.raises(PermissionError, match="denied execution"):
                model_b.invoke([HumanMessage(content="hi")])
        finally:
            unconfigure_langchain()

    def test_global_low_trust_raises(self):
        """configure_langchain with trust_override below min_trust must deny all models."""
        model = _fake_llm("blocked")

        configure_langchain(policy="test_policy", trust_override=0)
        try:
            with pytest.raises(PermissionError, match="denied execution"):
                model.invoke([HumanMessage(content="hi")])
        finally:
            unconfigure_langchain()

    def test_unconfigure_restores_normal_behaviour(self):
        """After unconfigure_langchain, models must invoke normally without kest."""
        model = _fake_llm("normal_response")

        configure_langchain(policy="blocked_policy")
        with pytest.raises(PermissionError):
            model.invoke([HumanMessage(content="blocked")])
        # LLM was never called → index still at 0
        unconfigure_langchain()

        resp = model.invoke([HumanMessage(content="restored")])
        assert resp.content == "normal_response"

    def test_double_configure_raises(self):
        """A second configure_langchain call while one is active must raise RuntimeError."""
        configure_langchain(policy="test_policy")
        try:
            with pytest.raises(RuntimeError, match="already globally configured"):
                configure_langchain(policy="another_policy")
        finally:
            unconfigure_langchain()

    def test_unconfigure_is_idempotent(self):
        """Calling unconfigure_langchain when no patch is active must be a no-op."""
        unconfigure_langchain()  # nothing to undo — should not raise
        unconfigure_langchain()  # second call equally safe

    def test_context_manager_scope_restores_on_exit(self):
        """kest_langchain_scope must patch on entry and unpatch on exit."""
        model = _fake_llm("inside_response")

        with kest_langchain_scope(policy="blocked_policy"):
            with pytest.raises(PermissionError):
                model.invoke([HumanMessage(content="blocked")])

        # Out of scope: invoke must work normally again
        resp = model.invoke([HumanMessage(content="after_scope")])
        assert resp.content == "inside_response"  # index never advanced inside scope

    def test_context_manager_scope_restores_even_on_exception(self):
        """kest_langchain_scope must restore normal behaviour even if the body raises."""
        model = _fake_llm("after_error")

        try:
            with kest_langchain_scope(policy="test_policy"):
                raise RuntimeError("simulated error inside scope")
        except RuntimeError:
            pass  # expected

        # Global patch must have been cleaned up despite the exception
        resp = model.invoke([HumanMessage(content="hi")])
        assert resp.content == "after_error"

    def test_chain_tip_advances_for_globally_patched_model(self):
        """Each globally patched invoke must record a kest entry and advance the chain."""
        chain_tips: list[str] = []

        class TipCapturingModel(FakeListChatModel):
            responses: list[str] = ["a", "b"]

            def _call(self, *args, **kwargs) -> str:  # type: ignore[override]
                ctx = otel_context.get_current()
                chain_tips.append(
                    str(baggage.get_baggage("kest.chain_tip", context=ctx) or "")
                )
                return super()._call(*args, **kwargs)

        model = TipCapturingModel()
        configure_langchain(policy="test_policy")
        try:
            model.invoke([HumanMessage(content="first")])
            model.invoke([HumanMessage(content="second")])
        finally:
            unconfigure_langchain()

        assert len(chain_tips) == 2
        assert chain_tips[0] != "", "chain_tip must be set inside globally patched invoke"
        assert chain_tips[0] != chain_tips[1], "chain must advance across invocations"


# ---------------------------------------------------------------------------
# patch_model — instance-level patch of a single BaseChatModel
# ---------------------------------------------------------------------------


class TestPatchModel:
    """
    patch_model enforces kest on a specific model instance only.
    All other models are unaffected.
    """

    def test_only_target_model_is_intercepted(self):
        """patch_model must only affect the patched instance — not other models."""
        patched = _fake_llm("patched_response")
        untouched = _fake_llm("untouched_response")

        patch_model(patched, policy="blocked_policy")
        try:
            with pytest.raises(PermissionError, match="denied execution"):
                patched.invoke([HumanMessage(content="blocked")])
            # untouched model must work normally
            resp = untouched.invoke([HumanMessage(content="ok")])
            assert resp.content == "untouched_response"
        finally:
            unpatch_model(patched)

    def test_unpatch_restores_instance_to_normal(self):
        """After unpatch_model, the instance must invoke normally without kest."""
        model = _fake_llm("restored")

        patch_model(model, policy="blocked_policy")
        with pytest.raises(PermissionError):
            model.invoke([HumanMessage(content="blocked")])

        unpatch_model(model)
        resp = model.invoke([HumanMessage(content="hi")])
        assert resp.content == "restored"  # index never advanced during block

    def test_double_patch_raises(self):
        """Calling patch_model twice on the same instance must raise RuntimeError."""
        model = _fake_llm("r")
        patch_model(model, policy="test_policy")
        try:
            with pytest.raises(RuntimeError, match="already kest-patched"):
                patch_model(model, policy="test_policy")
        finally:
            unpatch_model(model)

    def test_unpatch_is_idempotent(self):
        """Calling unpatch_model on an unpatched model must be a no-op."""
        model = _fake_llm("r")
        unpatch_model(model)  # nothing to undo — must not raise

    def test_low_trust_blocks_patched_instance(self):
        """patch_model with trust_override below min_trust must deny the instance."""
        model = _fake_llm("blocked")
        patch_model(model, policy="test_policy", trust_override=0)
        try:
            with pytest.raises(PermissionError, match="denied execution"):
                model.invoke([HumanMessage(content="hi")])
        finally:
            unpatch_model(model)

    def test_instance_patch_coexists_with_global_configure(self):
        """
        When both configure_langchain and patch_model are active, the instance
        patch must take precedence for the patched model (not double-intercepted),
        while the global patch still applies to all other models.
        """
        globally_blocked = _fake_llm("global_response")
        instance_blocked = _fake_llm("instance_response")
        instance_allowed = _fake_llm("allowed_response")

        configure_langchain(policy="blocked_policy")
        patch_model(instance_blocked, policy="blocked_policy")
        patch_model(instance_allowed, policy="test_policy")
        try:
            # Global patch blocks this one
            with pytest.raises(PermissionError):
                globally_blocked.invoke([HumanMessage(content="hi")])

            # Instance patch (also blocked) blocks this one
            with pytest.raises(PermissionError):
                instance_blocked.invoke([HumanMessage(content="hi")])

            # Instance patch (allowed policy) overrides the global blocked policy
            resp = instance_allowed.invoke([HumanMessage(content="hi")])
            assert resp.content == "allowed_response"
        finally:
            unpatch_model(instance_blocked)
            unpatch_model(instance_allowed)
            unconfigure_langchain()

    def test_chain_tip_advances_for_instance_patched_model(self):
        """Each instance-patched invoke must advance the Merkle chain tip."""
        chain_tips: list[str] = []

        class TipLLM(FakeListChatModel):
            responses: list[str] = ["x", "y"]

            def _call(self, *args, **kwargs) -> str:  # type: ignore[override]
                ctx = otel_context.get_current()
                chain_tips.append(
                    str(baggage.get_baggage("kest.chain_tip", context=ctx) or "")
                )
                return super()._call(*args, **kwargs)

        model = TipLLM()
        patch_model(model, policy="test_policy")
        try:
            model.invoke([HumanMessage(content="first")])
            model.invoke([HumanMessage(content="second")])
        finally:
            unpatch_model(model)

        assert len(chain_tips) == 2
        assert chain_tips[0] != "", "chain_tip must be set during instance-patched invoke"
        assert chain_tips[0] != chain_tips[1], "chain must advance across invocations"
