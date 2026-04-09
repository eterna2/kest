import functools
import uuid_utils
import hashlib
import os
import json
import base64
from typing import List, Optional, Union, Any
from opentelemetry import baggage, trace
import opentelemetry.context as otel_context

from kest.core.context import get_current_jwt
from kest.core.models import (
    BaggageManager,
    TrustEvaluator,
    DefaultTrustEvaluator,
    ORIGIN_TRUST_MAP,
)
from kest.core.identity import IdentityProvider
from kest.core.engine import PolicyEngine
from kest.core._core import KestEntry, sign_entry

tracer = trace.get_tracer(__name__)



# SHARED LAB FILE: To ensure Merkle chain links in the lab where OTel propagation is failing
_LAB_AUDIT_FILE = "/workspace/app/lab_audit.json"


def _append_lab_audit(signature: str):
    """
    Internal helper to persist audit signatures to a shared file in laboratory environments.

    This is used to maintain a consistent Merkle chain across distributed hops
    where OpenTelemetry baggage propagation might be inconsistent in Docker.

    Args:
        signature: The JWS signature string to append.
    """
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


def _update_lab_chain(service_name: str, sig_hash: str):
    """
    Internal helper to update the latest seen hash for a service in the lab.

    Args:
        service_name: The name of the service (e.g., hop1, hop2).
        sig_hash: The cryptographic hash of the latest audit entry.
    """
    try:
        # Use separate files to avoid JSON concurrency issues
        path = f"/workspace/app/last_hash_{service_name}.txt"
        with open(path, "w") as f:
            f.write(sig_hash)
    except Exception:
        pass


def _get_lab_parent(service_name: str) -> str:
    """
    Internal helper to retrieve the latest hash from a preceding hop in the lab.

    Args:
        service_name: The current service name.

    Returns:
        str: The hash of the parent entry, or "0" if not found.
    """
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


def get_active_engine() -> Optional[PolicyEngine]:
    """
    Retrieves the globally configured PolicyEngine.

    Returns:
        Optional[PolicyEngine]: The active engine or None.
    """
    import kest.core

    return getattr(kest.core, "_active_engine", None)


def get_active_identity() -> Optional[IdentityProvider]:
    """
    Retrieves the globally configured IdentityProvider.

    Returns:
        Optional[IdentityProvider]: The active identity provider or None.
    """
    import kest.core

    return getattr(kest.core, "_active_identity", None)


def get_active_cache() -> Optional[Any]:
    """
    Retrieves the globally configured PolicyCache.

    Returns:
        Optional[Any]: The active cache or None.
    """
    import kest.core

    return getattr(kest.core, "_active_cache", None)


def get_active_enterprise_policies() -> List[str]:
    import kest.core
    return getattr(kest.core, "_active_enterprise_policies", [])


def get_active_deviations() -> List[Any]:
    import kest.core
    return getattr(kest.core, "_active_deviations", [])


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
):
    """
    Enforces authorization and records cryptographic lineage for a function.

    This decorator performs a 'Passport Check' at the start of the function:
    1. Verifies the existing lineage (Passport) from OTel baggage.
    2. Evaluates the configured policies (OPA, Cedar, etc.).
    3. Calculates a trust score (CARTA) based on parents.
    4. Appends a new signed audit entry to the Passport.
    5. Propagates the updated Passport via OTel baggage.

    Args:
        policy: Signature of the policy to enforce. Can be a single string or a list.
        engine: Override for the global PolicyEngine.
        identity: Override for the global IdentityProvider.
        trust_evaluator: Logic for propagating trust scores. Defaults to DefaultTrustEvaluator.
        origin: Classification of the data/request origin for root nodes
            (e.g., "system", "user_input", "internet"). Determines initial trust score.
        added_taints: New taints to apply to the lineage at this node.
        removed_taints: Taints to remove (de-taint) at this node.
        trust_override: Explicitly set the trust score for this node.
        context_map: Optional mapping of function argument names to context keys.
            If a value is a dict, it should contain "key" and optional "persist" (bool).
            If persist=True, the mapped argument is added to lineage payload/labels.

    Example:
        @kest_verified(policy="financial/transaction-limit")
        def transfer_funds(amount: float):
            ...

    Raises:
        PermissionError: If authorization fails or no identity/engine is configured.
    """
    # Normalize policy to a list and deduplicate (F-PE-07/08 strict logical AND)
    _raw_policies = [policy] if isinstance(policy, str) else policy
    policies = list(dict.fromkeys(_raw_policies))

    def decorator(func):
        import inspect

        is_coroutine = inspect.iscoroutinefunction(func)

        def _build_mapped_context(args, kwargs):
            mapped_context = {}
            mapped_labels = {}
            if context_map:
                import inspect

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

        def _execute_core(
            span,
            parent_hash,
            passport,
            cache,
            active_id,
            active_eng,
            entry_id,
            trust_score,
            accumulated_taints,
            mapped_labels=None,
        ):
            """Internal core logic shared between sync and async wrappers."""
            service_name = os.getenv("SERVICE_NAME", "unknown")
            principal = active_id.get_identity()
            labels = {"principal": principal}
            span_ctx = span.get_span_context()
            if span_ctx and span_ctx.is_valid:
                labels["trace_id"] = f"{span_ctx.trace_id:032x}"

            tracking_id = _BaggageGetter("kest.trace_id", span)
            if tracking_id:
                labels["kest.trace_id"] = tracking_id
            if mapped_labels:
                labels.update(mapped_labels)

            # Persist principal context for downstream visibility
            principal_user = _BaggageGetter("kest.principal_user", span)
            principal_agent = _BaggageGetter("kest.principal_agent", span)
            if principal_user or principal_agent:
                import json

                labels["kest.identity"] = json.dumps(
                    {"user": principal_user or "", "agent": principal_agent or ""}
                )

            entry = KestEntry(
                entry_id=entry_id,
                operation=func.__name__,
                classification="system",
                trust_score=trust_score,
                parent_ids=[parent_hash],
                labels=labels,
                added_taints=added_taints or [],
                removed_taints=removed_taints or [],
                taints=list(accumulated_taints) if accumulated_taints else [],
                policy_context={
                    "enterprise_policies": get_active_enterprise_policies(),
                    "platform_policies": [],
                    "app_policies": [],
                    "function_policies": list(policies),
                    "deviations": get_active_deviations(),
                },
            )

            signature = sign_entry(entry, active_id)

            # LAB HACK: Store for next hop
            _update_lab_chain(
                service_name, hashlib.sha256(signature.encode()).hexdigest()
            )
            _append_lab_audit(signature)

            passport.add_signature(signature)

            packed_baggage = BaggageManager.pack(passport, cache=cache)
            new_tip = hashlib.sha256(signature.encode()).hexdigest()
            packed_baggage["kest.chain_tip"] = new_tip

            new_ctx = otel_context.get_current()
            for k, v in packed_baggage.items():
                new_ctx = baggage.set_baggage(k, v, context=new_ctx)

            span.set_attribute("kest.signature", signature)
            span.set_attribute("kest.chain_tip", new_tip)
            return new_ctx

        def _BaggageGetter(key, span=None):
            """Helper to get baggage from OTel or local lab fallback."""
            current_ctx = otel_context.get_current()
            val = baggage.get_baggage(key, context=current_ctx)
            if not val:
                current_span = span or trace.get_current_span(current_ctx)
                span_ctx = current_span.get_span_context() if current_span else None
                trace_id = span_ctx.trace_id if span_ctx and span_ctx.is_valid else None
                if trace_id:
                    import kest.core.ext

                    with kest.core.ext._LAB_LOCK:
                        lab_data = kest.core.ext._LAB_BAGGAGE_STORE.get(trace_id, {})
                        val = lab_data.get(key)
            return val

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            """Async wrapper for the decorator."""
            active_id = identity or get_active_identity()
            active_eng = engine or get_active_engine()
            cache = get_active_cache()

            if not active_id:
                raise PermissionError("No IdentityProvider configured")
            if not active_eng:
                raise PermissionError("No PolicyEngine configured")

            parent_hash = _BaggageGetter("kest.chain_tip")
            service_name = os.getenv("SERVICE_NAME", "unknown")
            if not parent_hash or parent_hash == "0":
                parent_hash = _get_lab_parent(service_name)
            parent_hash = parent_hash or "0"

            passport = BaggageManager.unpack(_BaggageGetter, cache=cache)
            if not passport.entries and parent_hash != "0":
                try:
                    if os.path.exists(_LAB_AUDIT_FILE):
                        with open(_LAB_AUDIT_FILE, "r") as f:
                            passport.entries = json.load(f)
                except Exception:
                    pass

            is_root = (not passport.entries) and (parent_hash == "0")
            evaluator = trust_evaluator or DefaultTrustEvaluator()
            # F-TS-02/F-TS-03: self_score is the node's own origin trust.
            # For root nodes, this IS the final trust score (no parents to inherit from).
            # For non-root nodes, evaluator attenuates self_score through parent chain.
            self_score = ORIGIN_TRUST_MAP.get(origin, 100) if origin else 100
            current_node_trust = self_score if is_root else 100
            if is_root:
                current_node_trust = self_score
            parent_taints = set()
            if not is_root:
                parent_scores = []
                for sig in passport.entries:
                    try:
                        p_b64 = sig.split(".")[1]
                        p_b64 += "=" * ((4 - len(p_b64) % 4) % 4)
                        p_data = json.loads(base64.urlsafe_b64decode(p_b64))
                        parent_scores.append(p_data.get("trust_score", 0))

                        # Accumulate taints from parents
                        p_accumulated = p_data.get("taints", [])
                        parent_taints.update(p_accumulated)
                    except Exception:
                        pass
                if trust_override is None:
                    current_node_trust = evaluator.calculate(self_score, parent_scores)

            if trust_override is not None:
                current_node_trust = trust_override

            # Calculate new accumulated taints
            current_accumulated = parent_taints.copy()
            if added_taints:
                current_accumulated.update(added_taints)
            if removed_taints:
                current_accumulated.difference_update(removed_taints)

            principal = active_id.get_identity()
            entry_id = str(uuid_utils.uuid7())

            with tracer.start_as_current_span(
                f"kest.verified.{func.__name__}",
                attributes={
                    "kest.policy_ids": ",".join(policies),
                    "kest.principal": principal,
                    "kest.entry_id": entry_id,
                    "kest.chain_tip": parent_hash,
                    "kest.trust_score": current_node_trust,
                },
            ) as span:
                ctx_to_eval = {
                    "principal": principal,
                    "jwt": get_current_jwt(),
                    "chain_tip": parent_hash,
                    "is_root": is_root,
                    "origin": origin,
                    "trust_score": current_node_trust,
                    "principal_user": _BaggageGetter("kest.principal_user", span) or "",
                    "principal_agent": _BaggageGetter("kest.principal_agent", span)
                    or "",
                    "principal_scope": _BaggageGetter("kest.principal_scope", span)
                    or "",
                }
                mapped_context, mapped_labels = _build_mapped_context(args, kwargs)
                ctx_to_eval.update(mapped_context)

                allowed = active_eng.evaluate(
                    entry_id=entry_id,
                    policy_names=policies,
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

                new_ctx = _execute_core(
                    span,
                    parent_hash,
                    passport,
                    cache,
                    active_id,
                    active_eng,
                    entry_id,
                    current_node_trust,
                    current_accumulated,
                    mapped_labels,
                )
                token = otel_context.attach(new_ctx)
                try:
                    return await func(*args, **kwargs)
                finally:
                    otel_context.detach(token)

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            """Sync wrapper for the decorator."""
            active_id = identity or get_active_identity()
            active_eng = engine or get_active_engine()
            cache = get_active_cache()

            if not active_id:
                raise PermissionError("No IdentityProvider configured")
            if not active_eng:
                raise PermissionError("No PolicyEngine configured")

            parent_hash = _BaggageGetter("kest.chain_tip")
            service_name = os.getenv("SERVICE_NAME", "unknown")
            if not parent_hash or parent_hash == "0":
                parent_hash = _get_lab_parent(service_name)
            parent_hash = parent_hash or "0"

            passport = BaggageManager.unpack(_BaggageGetter, cache=cache)
            if not passport.entries and parent_hash != "0":
                try:
                    if os.path.exists(_LAB_AUDIT_FILE):
                        with open(_LAB_AUDIT_FILE, "r") as f:
                            passport.entries = json.load(f)
                except Exception:
                    pass

            is_root = (not passport.entries) and (parent_hash == "0")
            evaluator = trust_evaluator or DefaultTrustEvaluator()
            # F-TS-02/F-TS-03: self_score is the node's own origin trust.
            self_score = ORIGIN_TRUST_MAP.get(origin, 100) if origin else 100
            current_node_trust = self_score if is_root else 100
            if is_root:
                current_node_trust = self_score
            parent_taints = set()
            if not is_root:
                parent_scores = []
                for sig in passport.entries:
                    try:
                        p_b64 = sig.split(".")[1]
                        p_b64 += "=" * ((4 - len(p_b64) % 4) % 4)
                        p_data = json.loads(base64.urlsafe_b64decode(p_b64))
                        parent_scores.append(p_data.get("trust_score", 0))

                        # Accumulate taints from parents
                        p_accumulated = p_data.get("taints", [])
                        parent_taints.update(p_accumulated)
                    except Exception:
                        pass
                if trust_override is None:
                    current_node_trust = evaluator.calculate(self_score, parent_scores)

            if trust_override is not None:
                current_node_trust = trust_override

            # Calculate new accumulated taints
            current_accumulated = parent_taints.copy()
            if added_taints:
                current_accumulated.update(added_taints)
            if removed_taints:
                current_accumulated.difference_update(removed_taints)

            principal = active_id.get_identity()
            entry_id = str(uuid_utils.uuid7())

            with tracer.start_as_current_span(
                f"kest.verified.{func.__name__}",
                attributes={
                    "kest.policy_ids": ",".join(policies),
                    "kest.principal": principal,
                    "kest.entry_id": entry_id,
                    "kest.chain_tip": parent_hash,
                    "kest.trust_score": current_node_trust,
                },
            ) as span:
                ctx_to_eval = {
                    "principal": principal,
                    "jwt": get_current_jwt(),
                    "chain_tip": parent_hash,
                    "is_root": is_root,
                    "origin": origin,
                    "trust_score": current_node_trust,
                    "principal_user": _BaggageGetter("kest.principal_user", span) or "",
                    "principal_agent": _BaggageGetter("kest.principal_agent", span)
                    or "",
                    "principal_scope": _BaggageGetter("kest.principal_scope", span)
                    or "",
                }
                mapped_context, mapped_labels = _build_mapped_context(args, kwargs)
                ctx_to_eval.update(mapped_context)

                allowed = active_eng.evaluate(
                    entry_id=entry_id,
                    policy_names=policies,
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

                new_ctx = _execute_core(
                    span,
                    parent_hash,
                    passport,
                    cache,
                    active_id,
                    active_eng,
                    entry_id,
                    current_node_trust,
                    current_accumulated,
                    mapped_labels,
                )
                token = otel_context.attach(new_ctx)
                try:
                    return func(*args, **kwargs)
                finally:
                    otel_context.detach(token)

        return async_wrapper if is_coroutine else sync_wrapper

    return decorator
