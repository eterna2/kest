import functools
import hashlib
import inspect
import json
import os
from typing import Any, List, Optional, Union

import opentelemetry.context as otel_context
from opentelemetry import baggage, trace

from kest.core._core import v2
from kest.core.models import ORIGIN_TRUST_MAP

tracer = trace.get_tracer(__name__)

# Lab fallback: filesystem-backed Merkle chain tracking.
# ONLY active when KEST_LAB_FALLBACK=true — MUST NOT be set in production.
# See spec/learnings/v0.3.0/LEARNINGS.md §D-04 for context.
_LAB_FALLBACK_ENABLED = os.getenv("KEST_LAB_FALLBACK", "").lower() in (
    "1",
    "true",
    "yes",
)
_LAB_AUDIT_FILE = "/workspace/app/lab_audit.json"


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


def get_active_engine() -> Optional[Any]:
    import kest.core

    return getattr(kest.core, "_active_engine", None)


def get_active_identity() -> Optional[Any]:
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
                mapped_context[ctx_key] = (
                    str(val) if not isinstance(val, (int, float, bool, str)) else val
                )
                if persist:
                    mapped_labels[ctx_key] = mapped_context[ctx_key]
    return mapped_context, mapped_labels


def _execute_v2_pipeline(
    func_name: str,
    policies: List[str],
    added_taints: Optional[List[str]],
    removed_taints: Optional[List[str]],
    mapped_context: dict,
    active_eng: Any,
    active_id: Any,
    origin: Optional[str],
    trust_override: Optional[int],
    trust_evaluator: Optional[Any],
):
    token = v2.context_create()
    try:
        current_baggage = baggage.get_all(context=otel_context.get_current())
        for k, v in current_baggage.items():
            v2.context_set(token, k, str(v) if not isinstance(v, str) else v)

        for k, v in mapped_context.items():
            v2.context_set(token, k, str(v) if not isinstance(v, str) else v)

        self_score = ORIGIN_TRUST_MAP.get(origin, 100) if origin else 100

        req_dict = {
            "classification": "System",
            "operation": func_name,
            "function_policies": policies,
            "enterprise_policies": get_active_enterprise_policies(),
            "deviations_json": json.dumps(get_active_deviations()),
            "origin_trust_score": self_score,
            "context": mapped_context,
        }
        
        if trust_override is not None:
            req_dict["trust_override"] = trust_override

        # Merge lab fallback
        service_name = os.getenv("SERVICE_NAME", "unknown")
        raw_tips = current_baggage.get("kest.chain_tip")
        parent_hashes = (
            [t.strip() for t in str(raw_tips).split(",")]
            if raw_tips and raw_tips != "0"
            else []
        )
        if not parent_hashes:
            lab_parent = LabFallbackBaggageProvider.get_parent_hash(service_name)
            if lab_parent and lab_parent != "0":
                parent_hashes = [lab_parent]

        if not parent_hashes:
            parent_hashes = ["0"]

        req_dict["parent_ids"] = parent_hashes

        if added_taints:
            req_dict["added_taints"] = added_taints
        if removed_taints:
            req_dict["removed_taints"] = removed_taints

        # Wrap Python PolicyEngines into RustPolicyEngine FFI
        if type(active_eng).__name__ == "MockPolicyEngine":
            active_eng = v2.RustPolicyEngine.mock(True)
        elif not getattr(active_eng, "__class__", None) or getattr(active_eng, "__class__").__name__ != "RustPolicyEngine":
            # For pure python engines like standard Cedar local implementations
            active_eng = v2.RustPolicyEngine.foreign(active_eng.evaluate)

        new_baggage_dict, signature = v2.pipeline_execute(
            active_eng, active_id, token, req_dict, trust_evaluator
        )

        # Push into lab fallback
        if _LAB_FALLBACK_ENABLED:
            LabFallbackBaggageProvider.update_chain(
                service_name, hashlib.sha256(signature.encode()).hexdigest()
            )
            LabFallbackBaggageProvider.append_audit(signature)

        return new_baggage_dict, signature
    finally:
        v2.context_destroy(token)


def kest_verified(
    policy: Union[str, List[str]],
    engine: Optional[Any] = None,
    identity: Optional[Any] = None,
    trust_evaluator: Optional[Any] = None,
    origin: Optional[str] = None,
    added_taints: Optional[List[str]] = None,
    removed_taints: Optional[List[str]] = None,
    trust_override: Optional[int] = None,
    context_map: Optional[dict] = None,
):
    _raw_policies = [policy] if isinstance(policy, str) else policy
    policies = list(dict.fromkeys(_raw_policies))

    def decorator(func):
        is_coroutine = inspect.iscoroutinefunction(func)

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            mapped_context, mapped_labels = _build_mapped_context(
                func, context_map, args, kwargs
            )

            active_id = identity or get_active_identity()
            active_eng = engine or get_active_engine()

            if not active_id:
                raise PermissionError("No IdentityProvider configured")
            if not active_eng:
                raise PermissionError("No PolicyEngine configured")

            new_baggage_dict, signature = _execute_v2_pipeline(
                func.__name__,
                policies,
                added_taints,
                removed_taints,
                mapped_context,
                active_eng,
                active_id,
                origin,
                trust_override,
                trust_evaluator,
            )

            new_ctx = otel_context.get_current()
            for k, v in new_baggage_dict.items():
                new_ctx = baggage.set_baggage(k, v, context=new_ctx)

            ctx_token = otel_context.attach(new_ctx)
            try:
                span_name = f"kest.verified.{func.__name__}"
                span = tracer.start_span(span_name)
                span.set_attribute("kest.signature", signature)
                span.set_attribute("kest.allowed", True)

                with trace.use_span(span, end_on_exit=True):
                    return func(*args, **kwargs)
            finally:
                otel_context.detach(ctx_token)

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            mapped_context, mapped_labels = _build_mapped_context(
                func, context_map, args, kwargs
            )

            active_id = identity or get_active_identity()
            active_eng = engine or get_active_engine()

            if not active_id:
                raise PermissionError("No IdentityProvider configured")
            if not active_eng:
                raise PermissionError("No PolicyEngine configured")

            import asyncio
            import contextvars

            loop = asyncio.get_running_loop()
            cv = contextvars.copy_context()

            def run_pipeline():
                return _execute_v2_pipeline(
                    func.__name__,
                    policies,
                    added_taints,
                    removed_taints,
                    mapped_context,
                    active_eng,
                    active_id,
                    origin,
                    trust_override,
                    trust_evaluator,
                )

            new_baggage_dict, signature = await loop.run_in_executor(
                None, cv.run, run_pipeline
            )

            new_ctx = otel_context.get_current()
            for k, v in new_baggage_dict.items():
                new_ctx = baggage.set_baggage(k, v, context=new_ctx)

            ctx_token = otel_context.attach(new_ctx)
            try:
                span_name = f"kest.verified.{func.__name__}"
                span = tracer.start_span(span_name)
                span.set_attribute("kest.signature", signature)
                span.set_attribute("kest.allowed", True)

                with trace.use_span(span, end_on_exit=True):
                    return await func(*args, **kwargs)
            finally:
                otel_context.detach(ctx_token)

        return async_wrapper if is_coroutine else sync_wrapper

    return decorator


def invalidate_policy_cache() -> None:
    pass  # Managed by rust v2 cache if provided
