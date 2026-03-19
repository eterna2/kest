import functools
import inspect
import logging
import time
import typing
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar

import uuid_utils
from opentelemetry import baggage
from opentelemetry.context import attach

from kest.config import config
from kest.core.crypto import compute_dag_hash, sign_passport, verify_signature
from kest.core.environment import EnvironmentCollector
from kest.core.models import (
    KestData,
    KestEntry,
    KestNodeType,
    KestPassport,
    PassportOrigin,
    PassportOriginPolicies,
)
from kest.core.telemetry import TelemetryExporter

R = TypeVar("R")


@dataclass
class _KestContext:
    entry_id: str
    node_id: str
    call_args: List[Any]
    call_kwargs: Dict[str, Any]
    passport: KestPassport
    parent_ids: List[str]
    parent_hashes: List[str]
    current_tag_accumulated: List[str]
    current_trust_score: float
    env_data: Dict[str, str]
    primary_wrapper_type: Any


def _kest_pre_execution(
    func: Callable,
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
    added_taint: List[str],
    env_collectors: List[EnvironmentCollector],
    node_trust_score: float,
    trust_score_updater: Optional[Callable],
    enforce_rules: Optional[List[str]],
    logger: Optional[logging.Logger],
) -> _KestContext:
    entry_id = str(uuid_utils.uuid7())
    node_id = getattr(func, "__qualname__", func.__name__)

    wrappers: List[Any] = []
    primary_wrapper_type = None
    call_args = list(args)
    call_kwargs = dict(kwargs)

    for i, arg in enumerate(args):
        if hasattr(arg, "data") and hasattr(arg, "passport"):
            wrappers.append(arg)
            call_args[i] = arg.data
            if primary_wrapper_type is None:
                primary_wrapper_type = type(arg)

    for k, v in kwargs.items():
        if hasattr(v, "data") and hasattr(v, "passport"):
            wrappers.append(v)
            call_kwargs[k] = v.data
            if primary_wrapper_type is None:
                primary_wrapper_type = type(v)

    parent_accumulated_taints = []
    parent_ids = []
    parent_hashes = []
    parent_trust_scores = []

    passport = None
    for w in wrappers:
        if w.passport:
            passport = w.passport
            break

    if not passport:
        jws_token = baggage.get_baggage("kest_passport")
        if isinstance(jws_token, str) and getattr(config, "verification_key", None):
            try:
                passport = verify_signature(config.verification_key, jws_token)  # type: ignore
            except Exception as e:
                if logger:
                    logger.warning(f"Failed to decode OTel Kest Baggage: {e}")

    if not passport:
        origin = PassportOrigin(
            user_id="system-implicit",
            session_id="local",
            policies=PassportOriginPolicies(curated_refs=[]),
        )
        passport = KestPassport(origin=origin)

    for w in wrappers:
        if not w.passport or not w.passport.history:
            continue
        p_id = list(w.passport.history.keys())[-1]
        p_entry = w.passport.history[p_id]

        parent_ids.append(p_id)
        parent_hashes.append(p_entry.content_hash)
        parent_accumulated_taints.extend(p_entry.accumulated_taint)
        parent_trust_scores.append(p_entry.trust_score)

        if w.passport != passport:
            for k_hist, v_hist in w.passport.history.items():
                if k_hist not in passport.history:
                    passport.history[k_hist] = v_hist

    current_tag_accumulated = list(set(parent_accumulated_taints + added_taint))

    if trust_score_updater:
        current_trust_score = trust_score_updater(node_trust_score, parent_trust_scores)
    else:
        current_trust_score = (
            min([node_trust_score] + parent_trust_scores)
            if parent_trust_scores
            else node_trust_score
        )

    env_data: Dict[str, str] = {}
    for collector in env_collectors:
        env_data.update(collector.collect())

    if config.policy_engine and enforce_rules:
        payload = {
            "node_id": node_id,
            "taints": list(set(parent_accumulated_taints)),
            "environment": env_data,
            "policy_refs": (
                passport.origin.policies.curated_refs if passport.origin else []
            ),
            "trust_score": current_trust_score,
        }
        for rule_path in enforce_rules:
            if not config.policy_engine.evaluate(payload, rule_path):
                raise PermissionError(
                    f"Kest Policy Violation: Execution blocked by rule '{rule_path}'"
                )

    return _KestContext(
        entry_id=entry_id,
        node_id=node_id,
        call_args=call_args,
        call_kwargs=call_kwargs,
        passport=passport,
        parent_ids=parent_ids,
        parent_hashes=parent_hashes,
        current_tag_accumulated=current_tag_accumulated,
        current_trust_score=current_trust_score,
        env_data=env_data,
        primary_wrapper_type=primary_wrapper_type,
    )


def _kest_post_execution(
    ctx: _KestContext,
    result: Any,
    caught_exception: Optional[Exception],
    added_taint: List[str],
    telemetry_exporters: List[TelemetryExporter],
) -> KestData[Any]:

    if caught_exception:
        added_taint.append("failed_execution")
        ctx.current_tag_accumulated.append("failed_execution")
        ctx.current_trust_score = 0.0

    input_state_hash = compute_dag_hash(ctx.parent_hashes, "input_hash", ctx.env_data)

    entry = KestEntry(
        entry_id=ctx.entry_id,
        parent_entry_ids=ctx.parent_ids,
        node_id=ctx.node_id,
        node_type=KestNodeType.SYSTEM,
        timestamp_ms=int(time.time() * 1000),
        input_state_hash=input_state_hash,
        content_hash="output_hash",
        environment=ctx.env_data,
        added_taint=added_taint,
        accumulated_taint=list(set(ctx.current_tag_accumulated)),
        trust_score=ctx.current_trust_score,
    )
    ctx.passport.history[ctx.entry_id] = entry

    for exporter in telemetry_exporters:
        exporter.export(ctx.passport)

    if getattr(config, "signing_key", None) and getattr(config, "signing_key_id", None):
        jws_token = sign_passport(
            config.signing_key, ctx.passport, kid=config.signing_key_id
        )  # type: ignore
        new_context = baggage.set_baggage("kest_passport", jws_token)
        attach(new_context)

    if caught_exception:
        raise caught_exception

    if ctx.primary_wrapper_type is None:
        return KestData(data=result, passport=ctx.passport)

    try:
        base_wrapper_type = getattr(
            ctx.primary_wrapper_type, "__origin__", ctx.primary_wrapper_type
        )
        return base_wrapper_type(data=result, passport=ctx.passport)
    except Exception:
        origin = typing.get_origin(ctx.primary_wrapper_type)
        if origin:
            return origin(data=result, passport=ctx.passport)
        elif hasattr(ctx.primary_wrapper_type, "model_construct"):
            return ctx.primary_wrapper_type.model_construct(
                data=result, passport=ctx.passport
            )
        raise ValueError(
            "Unable to wrap result with original Kest decorator wrapper type."
        )


def kest_verified(
    enforce_rules: Optional[List[str]] = None,
    added_taint: Optional[List[str]] = None,
    env_collectors: Optional[List[EnvironmentCollector]] = None,
    telemetry_exporters: Optional[List[TelemetryExporter]] = None,
    node_trust_score: float = 1.0,
    trust_score_updater: Optional[Callable[[float, List[float]], float]] = None,
    logger: Optional[logging.Logger] = None,
) -> Callable[[Callable[..., R]], Callable[..., KestData[R]]]:
    """
    Lifecycle decorator serving as Ingress Guard and Egress Sealer.
    Tracks lineage transparently using a data wrapper (e.g., KestData) and OTel Baggage.
    """
    if added_taint is None:
        added_taint = []
    if env_collectors is None:
        env_collectors = []
    if telemetry_exporters is None:
        telemetry_exporters = []

    def decorator(func: Callable[..., R]) -> Callable[..., KestData[R]]:
        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> KestData[R]:
                ctx = _kest_pre_execution(
                    func,
                    args,
                    kwargs,
                    added_taint,
                    env_collectors,
                    node_trust_score,
                    trust_score_updater,
                    enforce_rules,
                    logger,
                )
                caught_exception = None
                result = None
                try:
                    result = await func(*ctx.call_args, **ctx.call_kwargs)
                except Exception as e:
                    caught_exception = e

                return _kest_post_execution(
                    ctx, result, caught_exception, added_taint, telemetry_exporters
                )

            return async_wrapper  # type: ignore

        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> KestData[R]:
                ctx = _kest_pre_execution(
                    func,
                    args,
                    kwargs,
                    added_taint,
                    env_collectors,
                    node_trust_score,
                    trust_score_updater,
                    enforce_rules,
                    logger,
                )
                caught_exception = None
                result = None
                try:
                    result = func(*ctx.call_args, **ctx.call_kwargs)
                except Exception as e:
                    caught_exception = e

                return _kest_post_execution(
                    ctx, result, caught_exception, added_taint, telemetry_exporters
                )

            return sync_wrapper

    return decorator


def kest_sanitizer(
    removes_taint: str,
    env_collectors: Optional[List[EnvironmentCollector]] = None,
    logger: Optional[logging.Logger] = None,
) -> Callable[[Callable[..., R]], Callable[..., KestData[R]]]:
    """
    Decorator for specialized nodes that prove they have stripped a specific taint (e.g. PII).
    Implicitly maps to KestNodeType.SANITIZER.
    """
    if env_collectors is None:
        env_collectors = []

    def decorator(func: Callable[..., R]) -> Callable[..., KestData[R]]:
        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> KestData[R]:
                result = await func(*args, **kwargs)
                return KestData(data=result)

            return async_wrapper  # type: ignore
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> KestData[R]:
                result = func(*args, **kwargs)
                return KestData(
                    data=result
                )  # Mock implementation for v0.3.0 scaffolding

            return sync_wrapper

    return decorator
