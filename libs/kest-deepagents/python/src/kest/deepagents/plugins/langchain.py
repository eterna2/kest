"""
LangChain integration for kest-deepagents.

Provides three complementary ways to enforce zero-trust policy on LLM calls:

──────────────────────────────────────────────────────────────────────────────
1. Explicit wrapper  –  KestChatModel
──────────────────────────────────────────────────────────────────────────────
Wrap an individual model at construction time:

    from kest.deepagents.plugins.langchain import KestChatModel

    llm = KestChatModel(real_model, policy="llm_policy", trust_override=70)
    response = llm.invoke(messages)

──────────────────────────────────────────────────────────────────────────────
2. Global configure  –  configure_langchain / unconfigure_langchain
──────────────────────────────────────────────────────────────────────────────
Monkey-patches BaseChatModel.invoke at the *class* level so that every model
instance in the process is automatically intercepted — no per-model wrapping
needed:

    from kest.deepagents.plugins.langchain import (
        configure_langchain,
        unconfigure_langchain,
        kest_langchain_scope,
    )

    configure_langchain(policy="llm_policy", trust_override=70)
    # ... every model.invoke() call is now kest-verified ...
    unconfigure_langchain()

    # Or, scoped to a block via context manager:
    with kest_langchain_scope(policy="llm_policy", trust_override=70):
        response = any_model.invoke(messages)

──────────────────────────────────────────────────────────────────────────────
3. Instance-level patch  –  patch_model / unpatch_model
──────────────────────────────────────────────────────────────────────────────
Enforce policy on a *specific* model instance, leaving all others unaffected:

    from kest.deepagents.plugins.langchain import patch_model, unpatch_model

    patch_model(my_model, policy="llm_policy", trust_override=70)
    # ... only my_model.invoke() is kest-verified ...
    unpatch_model(my_model)

──────────────────────────────────────────────────────────────────────────────
Tools (no wrapper needed — stack the decorators):
──────────────────────────────────────────────────────────────────────────────
    from langchain_core.tools import tool
    from kest.core import kest_verified

    @tool
    @kest_verified(policy="my_policy", trust_override=80)
    def my_agent_tool(query: str) -> str:
        \"\"\"Search for information.\"\"\"
        return search(query)
"""

import contextlib
from typing import Any, Generator, List, Optional, Union

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import BaseMessage

from kest.core import kest_verified
from kest.core.engines.engine import PolicyEngine
from kest.core.identity import IdentityProvider
from kest.core.models.passport import TrustEvaluator


# ---------------------------------------------------------------------------
# Internal state
# ---------------------------------------------------------------------------

# Global class-level patch state: {"original": <original invoke method>}
_global_patch: dict[str, Any] = {}

# Per-instance patch registry: id(model) -> (had_instance_attr, previous_attr)
_instance_patches: dict[int, tuple[bool, Any]] = {}


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _build_kest_kwargs(
    policy: Union[str, List[str]],
    engine: Optional[PolicyEngine],
    identity: Optional[IdentityProvider],
    trust_evaluator: Optional[TrustEvaluator],
    origin: Optional[str],
    added_taints: Optional[List[str]],
    removed_taints: Optional[List[str]],
    trust_override: Optional[int],
    context_map: Optional[dict],
) -> dict:
    return dict(
        policy=policy,
        engine=engine,
        identity=identity,
        trust_evaluator=trust_evaluator,
        origin=origin,
        added_taints=added_taints,
        removed_taints=removed_taints,
        trust_override=trust_override,
        context_map=context_map,
    )


# ---------------------------------------------------------------------------
# 1. Explicit wrapper — KestChatModel
# ---------------------------------------------------------------------------


class KestChatModel:
    """
    A zero-trust wrapper around any LangChain BaseChatModel.

    Every call to .invoke() is intercepted by kest_verified, which:
    1. Evaluates the configured policy against the current execution context.
    2. Records the LLM invocation as a signed entry in the Merkle audit passport.
    3. Propagates the updated chain tip via OTel baggage to downstream tools.

    The underlying LLM is never called if the policy denies, ensuring that
    unapproved LLM reasoning steps are blocked at the zero-trust boundary.

    Args:
        model:           Any LangChain BaseChatModel instance.
        policy:          Policy name(s) to evaluate before each LLM call.
        engine:          Override the globally configured PolicyEngine.
        identity:        Override the globally configured IdentityProvider.
        trust_evaluator: Custom TrustEvaluator for chain trust propagation.
        origin:          Trust origin annotation for this node.
        added_taints:    Taints to add to the execution chain.
        removed_taints:  Taints to remove from the execution chain.
        trust_override:  Hard-set the trust score for the LLM node.
                         LLM-generated content is typically lower-trust (e.g. 60–80)
                         than deterministic tool calls (typically 90–100).
        context_map:     Map of invoke kwargs to OTel baggage keys for policy eval.
    """

    def __init__(
        self,
        model: BaseChatModel,
        policy: Union[str, List[str]],
        *,
        engine: Optional[PolicyEngine] = None,
        identity: Optional[IdentityProvider] = None,
        trust_evaluator: Optional[TrustEvaluator] = None,
        origin: Optional[str] = None,
        added_taints: Optional[List[str]] = None,
        removed_taints: Optional[List[str]] = None,
        trust_override: Optional[int] = None,
        context_map: Optional[dict] = None,
    ) -> None:
        self._model = model

        # Build the verified invoke once at construction time.
        # kest_verified wraps _do_invoke; the LLM is only reached if policy allows.
        def _do_invoke(messages: List[BaseMessage], **kwargs: Any) -> Any:
            return self._model.invoke(messages, **kwargs)

        self._verified_invoke = kest_verified(
            **_build_kest_kwargs(
                policy, engine, identity, trust_evaluator,
                origin, added_taints, removed_taints, trust_override, context_map,
            )
        )(_do_invoke)

    def invoke(
        self,
        input: Any,  # noqa: A002  mirrors BaseChatModel.invoke signature
        config: Any = None,
        **kwargs: Any,
    ) -> Any:
        """
        Invoke the LLM with zero-trust policy enforcement.

        The `config` argument is accepted for drop-in compatibility with
        LangChain Runnable pipelines (e.g. RunnableSequence) but is not
        forwarded to the inner LLM — chain configuration should be applied
        directly to the underlying model before passing it to KestChatModel.

        Raises:
            PermissionError: If the configured kest policy denies the invocation.
        """
        return self._verified_invoke(input, **kwargs)


# ---------------------------------------------------------------------------
# 2. Global configure — patches BaseChatModel.invoke at the class level
# ---------------------------------------------------------------------------


def configure_langchain(
    policy: Union[str, List[str]],
    *,
    engine: Optional[PolicyEngine] = None,
    identity: Optional[IdentityProvider] = None,
    trust_evaluator: Optional[TrustEvaluator] = None,
    origin: Optional[str] = None,
    added_taints: Optional[List[str]] = None,
    removed_taints: Optional[List[str]] = None,
    trust_override: Optional[int] = None,
    context_map: Optional[dict] = None,
) -> None:
    """
    Globally enforce kest policy on **all** BaseChatModel.invoke calls.

    After calling this, every ``model.invoke()`` in the process goes through
    kest_verified with the configured policy — no per-model wrapping needed.

    The interception is applied at the *class* level, so all existing and
    future model instances are covered. Instance-level patches (``patch_model``)
    take precedence over the global patch for their specific instances.

    Call ``unconfigure_langchain()`` (or use ``kest_langchain_scope()`` as a
    context manager) to restore normal behaviour.

    Raises:
        RuntimeError: If called while a global patch is already active.
    """
    if _global_patch:
        raise RuntimeError(
            "LangChain is already globally configured for kest. "
            "Call unconfigure_langchain() first."
        )

    original = BaseChatModel.invoke
    _global_patch["original"] = original

    kw = _build_kest_kwargs(
        policy, engine, identity, trust_evaluator,
        origin, added_taints, removed_taints, trust_override, context_map,
    )

    def _global_patched_invoke(self: BaseChatModel, input: Any, config: Any = None, **kwargs: Any) -> Any:  # noqa: A002
        # Build a fresh verified wrapper per call.
        # LLM calls are dominated by I/O latency — this setup overhead is negligible.
        def _bound(inp: Any, **kw_inner: Any) -> Any:
            return original(self, inp, **kw_inner)

        return kest_verified(**kw)(_bound)(input, **kwargs)

    BaseChatModel.invoke = _global_patched_invoke  # type: ignore[method-assign]


def unconfigure_langchain() -> None:
    """
    Restore ``BaseChatModel.invoke`` to its original unpatched implementation.

    Safe to call even if no global patch is active (no-op).
    """
    original = _global_patch.pop("original", None)
    _global_patch.clear()
    if original is not None:
        BaseChatModel.invoke = original  # type: ignore[method-assign]


@contextlib.contextmanager
def kest_langchain_scope(
    policy: Union[str, List[str]],
    **kest_kwargs: Any,
) -> Generator[None, None, None]:
    """
    Context manager that globally enforces kest policy for the duration of
    the ``with`` block, then automatically restores the original behaviour.

    Example::

        with kest_langchain_scope(policy="llm_policy", trust_override=70):
            response = any_model.invoke(messages)  # verified
        response = any_model.invoke(messages)      # unverified, as normal
    """
    configure_langchain(policy, **kest_kwargs)
    try:
        yield
    finally:
        unconfigure_langchain()


# ---------------------------------------------------------------------------
# 3. Instance-level patch — patches a single model instance
# ---------------------------------------------------------------------------


def patch_model(
    model: BaseChatModel,
    policy: Union[str, List[str]],
    *,
    engine: Optional[PolicyEngine] = None,
    identity: Optional[IdentityProvider] = None,
    trust_evaluator: Optional[TrustEvaluator] = None,
    origin: Optional[str] = None,
    added_taints: Optional[List[str]] = None,
    removed_taints: Optional[List[str]] = None,
    trust_override: Optional[int] = None,
    context_map: Optional[dict] = None,
) -> None:
    """
    Enforce kest policy on a **specific** model instance, leaving all other
    models in the process unaffected.

    If a global patch (``configure_langchain``) is already active, this instance
    patch takes precedence for the target model: it calls the *original*
    unpatched invoke, preventing double-interception.

    Call ``unpatch_model(model)`` to restore the instance to its previous state.

    Raises:
        RuntimeError: If the model is already patched with ``patch_model``.
    """
    key = id(model)
    if key in _instance_patches:
        raise RuntimeError(
            f"{model!r} is already kest-patched. Call unpatch_model() first."
        )

    # If the global patch is active, use the saved *original* class invoke to
    # avoid wrapping through kest twice.
    real_class_invoke = _global_patch.get("original", BaseChatModel.invoke)

    # Record whether the instance already had its own 'invoke' attribute
    # (e.g. a previous patch_model call — though that would have raised above).
    # We look directly in __dict__ to avoid going through Pydantic's descriptor.
    instance_dict = object.__getattribute__(model, "__dict__")
    had_attr = "invoke" in instance_dict
    _instance_patches[key] = (had_attr, instance_dict.get("invoke"))

    kw = _build_kest_kwargs(
        policy, engine, identity, trust_evaluator,
        origin, added_taints, removed_taints, trust_override, context_map,
    )

    # Build the verified wrapper once — captured in the instance closure.
    def _bound_original(inp: Any, **kwargs: Any) -> Any:
        return real_class_invoke(model, inp, **kwargs)

    _verified = kest_verified(**kw)(_bound_original)

    def _instance_patched_invoke(input: Any, config: Any = None, **kwargs: Any) -> Any:  # noqa: A002
        return _verified(input, **kwargs)

    # BaseChatModel is a Pydantic v2 model; its __setattr__ rejects arbitrary
    # attribute names that are not declared fields. Bypass it using
    # object.__setattr__ so the instance dict gets the shadowing attribute.
    object.__setattr__(model, "invoke", _instance_patched_invoke)


def unpatch_model(model: BaseChatModel) -> None:
    """
    Remove kest policy enforcement from a specific model instance.

    Restores the instance's ``invoke`` attribute to whatever it was before
    ``patch_model`` was called. Safe to call even if the model is not patched
    (no-op).
    """
    key = id(model)
    restore_info = _instance_patches.pop(key, None)
    if restore_info is None:
        return
    had_attr, prev_attr = restore_info
    instance_dict = object.__getattribute__(model, "__dict__")
    if had_attr:
        object.__setattr__(model, "invoke", prev_attr)
    else:
        instance_dict.pop("invoke", None)
