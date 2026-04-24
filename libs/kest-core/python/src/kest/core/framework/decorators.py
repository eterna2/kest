import asyncio
import concurrent.futures
import functools
import hashlib
import inspect
import json
import os
import time
from threading import Lock
from typing import Any, Callable, List, Optional, Union

import opentelemetry.context as otel_context
import uuid_utils
from opentelemetry import baggage, trace

from kest.core import KestEntry, sign_entry
from kest.core.engines.engine import PolicyEngine
from kest.core.framework.context import get_current_jwt
from kest.core.identity import IdentityProvider
from kest.core.models.passport import (
    ORIGIN_TRUST_MAP,
    BaggageManager,
    DefaultTrustEvaluator,
    TrustEvaluator,
)

tracer = trace.get_tracer(__name__)


# ---------------------------------------------------------------------------
# Fix 2: Policy Decision Cache
# ---------------------------------------------------------------------------


class _PolicyDecisionCache:
    """
    Thread-safe TTL-based LRU cache for policy decisions.

    Key: (principal, trust_score, classification, tuple(sorted policy names),
          principal_user, principal_agent, principal_scope)

    The key includes all Keycloak identity attributes to prevent cross-request
    cache collisions: e.g., the same SPIRE workload serving requests from different
    Keycloak users, different scopes, or with/without a bearer token, will each
    maintain a separate cached decision.

    TTL defaults to 5 seconds -- appropriate for real-time enforcement while
    avoiding evaluation on every call.
    """

    def __init__(self, maxsize: int = 1024, ttl_seconds: float = 5.0):
        self._cache: dict = {}
        self._maxsize = maxsize
        self._ttl = ttl_seconds
        self._lock = Lock()

    def _make_key(self, context: dict, policy_names: list) -> tuple:
        return (
            context.get("principal", ""),
            context.get("trust_score", 0),
            context.get("classification", ""),
            tuple(sorted(policy_names)),
            # Include per-request identity context so that requests from the same
            # workload (same SPIRE SVID) but different Keycloak users, agents, or scopes
            # — or with/without a JWT — do not share a cached policy decision.
            # Keys use spec-compliant names (SPEC-v0.3.0 §8.4).
            context.get("user", ""),
            context.get("agent", ""),
            context.get("task", ""),
            # ABAC resource axis — MUST be in cache key to prevent cross-resource
            # collisions where different resource IDs share a cached allow decision.
            context.get("object", {}).get("id", "") or "",
        )

    def get_or_evaluate(
        self,
        engine: PolicyEngine,
        entry_id: str,
        policy_names: list,
        context: dict,
    ) -> bool:
        key = self._make_key(context, policy_names)
        now = time.monotonic()

        with self._lock:
            cached = self._cache.get(key)
            if cached is not None:
                decision, ts = cached
                if (now - ts) < self._ttl:
                    return decision

        # Cache miss or expired: evaluate
        result = engine.evaluate(entry_id, list(policy_names), context)

        with self._lock:
            if len(self._cache) >= self._maxsize:
                # Evict oldest entry
                oldest = next(iter(self._cache))
                del self._cache[oldest]
            self._cache[key] = (result, now)

        return result

    def invalidate(self) -> None:
        """Clear all cached decisions (e.g., after policy reload)."""
        with self._lock:
            self._cache.clear()


# Module-level cache instance, shared across all decorated functions.
# TTL is configurable via KEST_POLICY_CACHE_TTL env var (default 5s).
_POLICY_CACHE = _PolicyDecisionCache(
    maxsize=1024,
    ttl_seconds=float(os.getenv("KEST_POLICY_CACHE_TTL", "5.0")),
)


# Fix 6: Bounded Signing Thread Pool
# ---------------------------------------------------------------------------

# Singleton executor for CPU-bound signing and packing work, shared across all @kest_verified calls.
_SIGN_EXECUTOR: Optional[concurrent.futures.ThreadPoolExecutor] = None
_SIGN_EXECUTOR_LOCK = Lock()


def _get_sign_executor() -> concurrent.futures.ThreadPoolExecutor:
    """
    Get or create the bounded thread pool for signing operations.

    Worker count defaults to min(4, cpu_count) but can be overridden via KEST_SIGN_WORKERS.
    """
    global _SIGN_EXECUTOR
    if _SIGN_EXECUTOR is not None:
        return _SIGN_EXECUTOR

    with _SIGN_EXECUTOR_LOCK:
        if _SIGN_EXECUTOR is None:
            env_workers = os.getenv("KEST_SIGN_WORKERS")
            if env_workers:
                try:
                    workers = int(env_workers)
                except ValueError:
                    workers = min(4, os.cpu_count() or 1)
            else:
                workers = min(4, os.cpu_count() or 1)

            _SIGN_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
                max_workers=workers,
                thread_name_prefix="kest-sign",
            )
        return _SIGN_EXECUTOR


def invalidate_policy_cache() -> None:
    """
    Invalidate all cached policy decisions.

    Call this after hot-reloading policies or in tests to ensure a clean state.
    """
    _POLICY_CACHE.invalidate()


# Lab fallback: filesystem-backed Merkle chain tracking.
# ONLY active when KEST_LAB_FALLBACK=true — MUST NOT be set in production.
# See spec/learnings/v0.3.0/LEARNINGS.md §D-04 for context.
_LAB_FALLBACK_ENABLED = os.getenv("KEST_LAB_FALLBACK", "").lower() in (
    "1",
    "true",
    "yes",
)
_LAB_AUDIT_FILE = "/workspace/app/lab_audit.json"


def _get_baggage(key: str) -> Any:
    """
    Read a value from the current OTel Baggage context.

    This is the canonical way to read Kest identity/context keys within core.
    It replaces the previous LabFallbackBaggageProvider.get_baggage() helper,
    which coupled core logic to the lab's global _LAB_BAGGAGE_STORE dict.

    All consumers of kest.user / kest.agent / kest.task etc. must use this.
    """
    return baggage.get_baggage(key, context=otel_context.get_current())


class LabFallbackBaggageProvider:
    """Internal helper to manage shared lab state and fallbacks for baggage propagation."""

    @staticmethod
    def append_audit(signature: str):
        if not _LAB_FALLBACK_ENABLED:
            return
        try:
            data = []
            if os.path.exists(_LAB_AUDIT_FILE):
                try:
                    with open(_LAB_AUDIT_FILE, "r") as f:
                        data = json.load(f)
                except Exception:
                    pass
            data.append(signature)
            with open(_LAB_AUDIT_FILE, "w") as f:
                json.dump(data, f)
        except Exception:
            pass

    @staticmethod
    def update_chain(service_name: str, sig_hash: str):
        if not _LAB_FALLBACK_ENABLED:
            return
        try:
            path = f"/workspace/app/last_hash_{service_name}.txt"
            with open(path, "w") as f:
                f.write(sig_hash)
        except Exception:
            pass

    @staticmethod
    def get_parent_hash(service_name: str) -> str:
        if not _LAB_FALLBACK_ENABLED:
            return "0"
        try:
            target = (
                "hop1"
                if service_name == "hop2"
                else "hop2"
                if service_name == "hop3"
                else None
            )
            if not target:
                return "0"
            path = f"/workspace/app/last_hash_{target}.txt"
            if not os.path.exists(path):
                return "0"
            with open(path, "r") as f:
                return f.read().strip()
        except Exception:
            return "0"

    @staticmethod
    def get_passport_entries() -> list:
        if not _LAB_FALLBACK_ENABLED:
            return []
        try:
            if os.path.exists(_LAB_AUDIT_FILE):
                with open(_LAB_AUDIT_FILE, "r") as f:
                    return json.load(f)
        except Exception:
            pass
        return []


def get_active_engine() -> Optional[PolicyEngine]:
    import kest.core

    return getattr(kest.core, "_active_engine", None)


def get_active_identity() -> Optional[IdentityProvider]:
    import kest.core

    return getattr(kest.core, "_active_identity", None)


def get_active_cache() -> Optional[Any]:
    import kest.core

    return getattr(kest.core, "_active_cache", None)


def get_active_enterprise_policies() -> List[str]:
    import kest.core

    return getattr(kest.core, "_active_enterprise_policies", [])


def get_active_deviations() -> List[Any]:
    import kest.core

    return getattr(kest.core, "_active_deviations", [])


def _build_resource_context(
    resource_id: Optional[Union[str, Callable]],
    resource_attr: Optional[Union[dict, Callable]],
    args: tuple,
    kwargs: dict,
) -> tuple:
    """
    Resolve resource_id and resource_attr at call time.

    If the value is callable, it is invoked with (*args, **kwargs) of the
    decorated function and must return the resolved value.  Static values
    are returned as-is.  None → None.

    Returns:
        (resolved_id, resolved_attr) where resolved_id is str|None and
        resolved_attr is dict|None.
    """
    resolved_id: Optional[str] = (
        resource_id(*args, **kwargs) if callable(resource_id) else resource_id
    )
    resolved_attr: Optional[dict] = (
        resource_attr(*args, **kwargs) if callable(resource_attr) else resource_attr
    )
    return resolved_id, resolved_attr


def _build_mapped_context(func, context_map, args, kwargs):
    mapped_context = {}
    mapped_labels = {}
    if context_map:
        sig = inspect.signature(func)
        bound_args = sig.bind(*args, **kwargs)
        bound_args.apply_defaults()
        for arg_name, config in context_map.items():
            if arg_name in bound_args.arguments:
                val = bound_args.arguments[arg_name]
                if isinstance(config, dict):
                    ctx_key = config.get("key", arg_name)
                    persist = config.get("persist", False)
                else:
                    ctx_key = config
                    persist = False
                mapped_context[ctx_key] = val
                if persist:
                    mapped_labels[ctx_key] = (
                        str(val)
                        if not isinstance(val, (int, float, bool, str))
                        else val
                    )
    return mapped_context, mapped_labels


def _execute_core_logic(
    func_name: str,
    policies: List[str],
    origin: Optional[str],
    trust_evaluator: Optional[TrustEvaluator],
    trust_override: Optional[int],
    added_taints: Optional[List[str]],
    removed_taints: Optional[List[str]],
    context_map: Optional[dict],
    args: tuple,
    kwargs: dict,
    engine: Optional[PolicyEngine],
    identity: Optional[IdentityProvider],
    resolved_resource_id: Optional[str] = None,
    resolved_resource_attr: Optional[dict] = None,
):
    """Shared core logic extracted to prevent duplication between sync and async execution paths."""
    active_id = identity or get_active_identity()
    active_eng = engine or get_active_engine()
    cache = get_active_cache()

    if not active_id:
        raise PermissionError("No IdentityProvider configured")
    if not active_eng:
        raise PermissionError("No PolicyEngine configured")

    raw_tips = _get_baggage("kest.chain_tip")
    parent_hashes = (
        [t.strip() for t in raw_tips.split(",")] if raw_tips and raw_tips != "0" else []
    )
    service_name = os.getenv("SERVICE_NAME", "unknown")
    if not parent_hashes:
        lab_parent = LabFallbackBaggageProvider.get_parent_hash(service_name)
        if lab_parent and lab_parent != "0":
            parent_hashes = [lab_parent]

    if not parent_hashes:
        parent_hashes = ["0"]

    passport = BaggageManager.unpack(_get_baggage, cache=cache)
    if not passport.entries and parent_hashes != ["0"]:
        passport.entries = LabFallbackBaggageProvider.get_passport_entries()

    is_root = (not passport.entries) and (parent_hashes == ["0"])
    evaluator = trust_evaluator or DefaultTrustEvaluator()
    self_score = ORIGIN_TRUST_MAP.get(origin, 100) if origin else 100
    current_node_trust = self_score if is_root else 100

    # Fix 1: Use cached passport properties instead of O(n) inline parsing
    parent_taints: frozenset = frozenset()
    if not is_root:
        parent_scores = passport.trust_scores
        parent_taints = passport.accumulated_taints
        if trust_override is None:
            current_node_trust = evaluator.calculate(self_score, parent_scores)

    if trust_override is not None:
        current_node_trust = trust_override

    # Calculate new accumulated taints (mutable copy for add/remove operations)
    current_accumulated = set(parent_taints)
    if added_taints:
        current_accumulated.update(added_taints)
    if removed_taints:
        current_accumulated.difference_update(removed_taints)

    principal = active_id.get_identity()
    entry_id = str(uuid_utils.uuid7())

    span = tracer.start_span(
        f"kest.verified.{func_name}",
        attributes={
            "kest.policy_ids": ",".join(policies),
            "kest.principal": principal,
            "kest.entry_id": entry_id,
            "kest.chain_tip": ",".join(parent_hashes),
            "kest.trust_score": current_node_trust,
        },
    )

    ctx_to_eval = {
        "principal": principal,
        "jwt": get_current_jwt(),
        "chain_tip": ",".join(parent_hashes),
        "is_root": is_root,
        "origin": origin,
        "trust_score": current_node_trust,
        # Spec-compliant keys (SPEC-v0.3.0 §9.2, §8.4)
        "user": _get_baggage("kest.user") or "",
        "agent": _get_baggage("kest.agent") or "",
        "task": _get_baggage("kest.task") or "",
        # Implementation extension: raw OAuth scope for Cedar ABAC checks
        "scope": _get_baggage("kest.scope") or "",
        # SPEC-v0.3.0 §9.2 — resource context for ABAC (F-IC-01, F-IC-02)
        "object": {
            "id": resolved_resource_id,
            "attributes": resolved_resource_attr or {},
        },
    }

    # Needs to be provided by caller logic:
    # We must actually evaluate engine here.
    return {
        "span": span,
        "ctx_to_eval": ctx_to_eval,
        "active_eng": active_eng,
        "entry_id": entry_id,
        "policies": policies,
        "principal": principal,
        "parent_hashes": parent_hashes,
        "current_node_trust": current_node_trust,
        "current_accumulated": current_accumulated,
        "active_id": active_id,
        "passport": passport,
        "cache": cache,
        "service_name": service_name,
    }


def _execute_core_post_auth(
    state,
    func_name,
    added_taints,
    removed_taints,
    mapped_labels,
    resource_attr: Optional[dict] = None,
):
    span = state["span"]
    labels = {"principal": state["principal"]}
    span_ctx = span.get_span_context()
    if span_ctx and span_ctx.is_valid:
        labels["trace_id"] = f"{span_ctx.trace_id:032x}"

    tracking_id = _get_baggage("kest.trace_id")
    if tracking_id:
        labels["kest.trace_id"] = tracking_id
    if mapped_labels:
        labels.update(mapped_labels)

    # Spec §2.7 F-IC-04: embed user/agent in labels as kest.identity JSON string
    principal_user = _get_baggage("kest.user")
    principal_agent = _get_baggage("kest.agent")
    if principal_user or principal_agent:
        labels["kest.identity"] = json.dumps(
            {"user": principal_user or "", "agent": principal_agent or ""}
        )

    # Spec §2.7 F-IC-04: embed resource_attr in labels as kest.resource_attr JSON string
    if resource_attr:
        labels["kest.resource_attr"] = json.dumps(resource_attr)

    entry = KestEntry(
        entry_id=state["entry_id"],
        operation=func_name,
        classification="system",
        trust_score=state["current_node_trust"],
        parent_ids=state["parent_hashes"],
        labels=labels,
        added_taints=added_taints or [],
        removed_taints=removed_taints or [],
        taints=list(state["current_accumulated"])
        if state["current_accumulated"]
        else [],
        policy_context={
            "enterprise_policies": get_active_enterprise_policies(),
            "platform_policies": [],
            "app_policies": [],
            "function_policies": state["policies"],
            "deviations": get_active_deviations(),
        },
    )

    signature = sign_entry(entry, state["active_id"])

    LabFallbackBaggageProvider.update_chain(
        state["service_name"], hashlib.sha256(signature.encode()).hexdigest()
    )
    LabFallbackBaggageProvider.append_audit(signature)

    state["passport"].add_signature(signature)

    packed_baggage = BaggageManager.pack(state["passport"], cache=state["cache"])
    new_tip = hashlib.sha256(signature.encode()).hexdigest()
    packed_baggage["kest.chain_tip"] = new_tip

    new_ctx = otel_context.get_current()
    for k, v in packed_baggage.items():
        new_ctx = baggage.set_baggage(k, v, context=new_ctx)

    span.set_attribute("kest.signature", signature)
    span.set_attribute("kest.chain_tip", new_tip)
    return new_ctx


def kest_verified(
    policy: Union[str, List[str]],
    engine: Optional[PolicyEngine] = None,
    identity: Optional[IdentityProvider] = None,
    trust_evaluator: Optional[TrustEvaluator] = None,
    origin: Optional[str] = None,
    added_taints: Optional[List[str]] = None,
    removed_taints: Optional[List[str]] = None,
    trust_override: Optional[int] = None,
    context_map: Optional[dict] = None,
    resource_id: Optional[Union[str, Callable]] = None,
    resource_attr: Optional[Union[dict, Callable]] = None,
):
    """
    Decorator that wraps a function with Kest zero-trust policy enforcement.

    Args:
        policy: Policy name(s) to evaluate (logical AND).
        engine: Per-invocation PolicyEngine override.
        identity: Per-invocation IdentityProvider override.
        trust_evaluator: Per-invocation TrustEvaluator override.
        origin: Source type for root-node trust bootstrapping.
        added_taints: Taint labels to introduce at this node.
        removed_taints: Taint labels to clear at this node.
        trust_override: Hard-set trust_score bypassing the evaluator (sanitizer).
        context_map: Map of function argument names to policy context keys.
        resource_id: Resource identifier for ABAC.  Accepts a static string or a
            callable (resolver) that receives the function's (*args, **kwargs) and
            returns a string.  Forwarded as ``object.id`` in the policy context
            (SPEC-v0.3.0 §9.2, F-IC-01).
        resource_attr: Resource attributes for ABAC.  Accepts a static dict or a
            callable (resolver) that receives (*args, **kwargs) and returns a dict.
            Forwarded as ``object.attributes`` in the policy context and serialized
            into ``KestEntry.labels["kest.resource_attr"]`` (F-IC-01, F-IC-04).
    """
    _raw_policies = [policy] if isinstance(policy, str) else policy
    policies = list(dict.fromkeys(_raw_policies))

    def decorator(func):
        is_coroutine = inspect.iscoroutinefunction(func)

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            mapped_context, mapped_labels = _build_mapped_context(
                func, context_map, args, kwargs
            )
            resolved_rid, resolved_rattr = _build_resource_context(
                resource_id, resource_attr, args, kwargs
            )
            state = _execute_core_logic(
                func.__name__,
                policies,
                origin,
                trust_evaluator,
                trust_override,
                added_taints,
                removed_taints,
                context_map,
                args,
                kwargs,
                engine,
                identity,
                resolved_resource_id=resolved_rid,
                resolved_resource_attr=resolved_rattr,
            )

            span = state["span"]
            with trace.use_span(span, end_on_exit=True):
                ctx_to_eval = state["ctx_to_eval"]
                ctx_to_eval.update(mapped_context)

                # Fix 2: Policy decision cache (TTL=5s, key=principal+trust_score+policies)
                allowed = _POLICY_CACHE.get_or_evaluate(
                    state["active_eng"],
                    entry_id=state["entry_id"],
                    policy_names=state["policies"],
                    context=ctx_to_eval,
                )
                span.set_attribute("kest.allowed", allowed)
                if not allowed:
                    span.set_status(
                        trace.Status(
                            trace.StatusCode.ERROR, "Kest policy denied execution"
                        )
                    )
                    raise PermissionError(f"Kest policies {policies} denied execution")

                import contextvars

                # Fix 6: Offload CPU-bound signing + baggage packing to thread pool
                # We use cv.run to ensure OTel ContextVars (baggage) propagate to the thread.
                loop = asyncio.get_running_loop()
                cv = contextvars.copy_context()
                new_ctx = await loop.run_in_executor(
                    _get_sign_executor(),
                    cv.run,
                    _execute_core_post_auth,
                    state,
                    func.__name__,
                    added_taints,
                    removed_taints,
                    mapped_labels,
                    resolved_rattr,
                )
                token = otel_context.attach(new_ctx)
                try:
                    return await func(*args, **kwargs)
                finally:
                    otel_context.detach(token)

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            mapped_context, mapped_labels = _build_mapped_context(
                func, context_map, args, kwargs
            )
            resolved_rid, resolved_rattr = _build_resource_context(
                resource_id, resource_attr, args, kwargs
            )
            state = _execute_core_logic(
                func.__name__,
                policies,
                origin,
                trust_evaluator,
                trust_override,
                added_taints,
                removed_taints,
                context_map,
                args,
                kwargs,
                engine,
                identity,
                resolved_resource_id=resolved_rid,
                resolved_resource_attr=resolved_rattr,
            )

            span = state["span"]
            with trace.use_span(span, end_on_exit=True):
                ctx_to_eval = state["ctx_to_eval"]
                ctx_to_eval.update(mapped_context)

                # Fix 2: Policy decision cache (TTL=5s, key=principal+trust_score+policies)
                allowed = _POLICY_CACHE.get_or_evaluate(
                    state["active_eng"],
                    entry_id=state["entry_id"],
                    policy_names=state["policies"],
                    context=ctx_to_eval,
                )
                span.set_attribute("kest.allowed", allowed)
                if not allowed:
                    span.set_status(
                        trace.Status(
                            trace.StatusCode.ERROR, "Kest policy denied execution"
                        )
                    )
                    raise PermissionError(f"Kest policies {policies} denied execution")

                new_ctx = _execute_core_post_auth(
                    state,
                    func.__name__,
                    added_taints,
                    removed_taints,
                    mapped_labels,
                    resolved_rattr,
                )
                token = otel_context.attach(new_ctx)
                try:
                    return func(*args, **kwargs)
                finally:
                    otel_context.detach(token)

        return async_wrapper if is_coroutine else sync_wrapper

    return decorator
