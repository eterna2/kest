import functools
import logging
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, TypeVar

from kest.config import config
from kest.core.crypto import compute_dag_hash
from kest.core.environment import EnvironmentCollector
from kest.core.models import (
    KestData,
    KestEntry,
    KestPassport,
    PassportOrigin,
    PassportOriginPolicies,
)
from kest.core.telemetry import TelemetryExporter

R = TypeVar("R")


def kest_verified(
    enforce_rules: Optional[List[str]] = None,
    added_taint: Optional[List[str]] = None,
    env_collectors: Optional[List[EnvironmentCollector]] = None,
    telemetry_exporters: Optional[List[TelemetryExporter]] = None,
    trust_score_updater: Optional[Callable[[List[float]], float]] = None,
    logger: Optional[logging.Logger] = None,
) -> Callable[[Callable[..., R]], Callable[..., KestData[R]]]:
    """
    Lifecycle decorator serving as Ingress Guard and Egress Sealer.
    Tracks lineage transparently using a data wrapper (e.g., KestData).
    """
    if added_taint is None:
        added_taint = []
    if env_collectors is None:
        env_collectors = []
    if telemetry_exporters is None:
        telemetry_exporters = []

    def decorator(func: Callable[..., R]) -> Callable[..., KestData[R]]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> KestData[R]:
            entry_id = str(uuid.uuid4())
            node_id = getattr(func, "__qualname__", func.__name__)

            # Duck-type search for wrapper objects in arguments
            wrappers = []
            primary_wrapper_type = None

            call_args = list(args)
            call_kwargs = dict(kwargs)

            for i, arg in enumerate(args):
                if logger:
                    logger.debug(f"arg {i} type: {type(arg)}")
                if hasattr(arg, "data") and hasattr(arg, "passport"):
                    if logger:
                        logger.debug(f"arg {i} is a Kest wrapper")
                    wrappers.append(arg)
                    call_args[i] = arg.data
                    if primary_wrapper_type is None:
                        primary_wrapper_type = type(arg)

            for k, v in kwargs.items():
                if logger:
                    logger.debug(f"kwarg {k} type: {type(v)}")
                if hasattr(v, "data") and hasattr(v, "passport"):
                    if logger:
                        logger.debug(f"kwarg {k} is a Kest wrapper")
                    wrappers.append(v)
                    call_kwargs[k] = v.data
                    if primary_wrapper_type is None:
                        primary_wrapper_type = type(v)

            if logger:
                logger.debug(f"Total wrappers found: {len(wrappers)}")

            # Consolidate history from ALL provided wrappers
            parent_accumulated_taints = []
            parent_ids = []
            parent_hashes = []
            parent_trust_scores = []

            # We need a base passport to merge into. Pick the first one found, or create implicit.
            passport = None
            for w in wrappers:
                if w.passport:
                    passport = w.passport
                    break

            if not passport:
                origin = PassportOrigin(
                    user_id="system-implicit",
                    session_id="local",
                    policies=PassportOriginPolicies(curated_refs=[]),
                )
                passport = KestPassport(origin=origin, signature="", public_key_id="")

            # If verification key is set, actively reject any passports with tampered signatures
            if config.verification_key:
                from kest.core.crypto import verify_signature

                for w in wrappers:
                    if w.passport and w.passport.signature:
                        if not verify_signature(config.verification_key, w.passport):
                            raise ValueError(
                                "Invalid DAG Signature: Passport has been maliciously altered."
                            )

            for w in wrappers:
                if not w.passport or not w.passport.history:
                    continue

                # The last node in history is considered the direct parent for this wrapper branch
                p_id = list(w.passport.history.keys())[-1]
                p_entry = w.passport.history[p_id]

                parent_ids.append(p_id)
                parent_hashes.append(p_entry.content_hash)
                parent_accumulated_taints.extend(p_entry.accumulated_taint)
                parent_trust_scores.append(p_entry.trust_score)

                # Merge history branches
                if w.passport != passport:
                    for k, v in w.passport.history.items():
                        if k not in passport.history:
                            passport.history[k] = v

            # Current node's taints: union of parent accumulated taints + explicitly added taints
            current_tag_accumulated = list(set(parent_accumulated_taints + added_taint))

            # Trust Score Synthesis
            if trust_score_updater:
                current_trust_score = trust_score_updater(parent_trust_scores)
            else:
                if parent_trust_scores:
                    current_trust_score = min(parent_trust_scores)
                else:
                    current_trust_score = 0.0

            import typing

            def _wrap_result(res: Any, passp: Optional[KestPassport]) -> KestData[R]:
                if primary_wrapper_type is None:
                    return KestData[R](data=res, passport=passp)
                try:
                    base_wrapper_type = getattr(
                        primary_wrapper_type, "__origin__", primary_wrapper_type
                    )
                    return base_wrapper_type(data=res, passport=passp)
                except Exception:
                    origin = typing.get_origin(primary_wrapper_type)
                    if origin:
                        return origin(data=res, passport=passp)
                    elif hasattr(primary_wrapper_type, "model_construct"):
                        return primary_wrapper_type.model_construct(
                            data=res, passport=passp
                        )
                    raise

            # Environment collection
            env_data: Dict[str, str] = {}
            for collector in env_collectors:
                env_data.update(collector.collect())

            # Policy Engine Evaluation (MUST pass the taints seen at INGRESS)
            if config.policy_engine and enforce_rules:
                payload = {
                    "node_id": node_id,
                    "taints": list(
                        set(parent_accumulated_taints)
                    ),  # Input taints for ingress guard
                    "environment": env_data,
                    "policy_refs": (
                        passport.origin.policies.curated_refs if passport.origin else []
                    ),
                    "trust_score": current_trust_score,
                }
                if logger:
                    logger.debug(
                        f"OPA Eval for {node_id} with rule {enforce_rules} and taints {payload['taints']}"
                    )
                for rule_path in enforce_rules:
                    if not config.policy_engine.evaluate(payload, rule_path):
                        raise PermissionError(
                            f"Kest Policy Violation: Execution blocked by rule '{rule_path}'"
                        )

            # Execute Domain Logic
            result = func(*call_args, **call_kwargs)

            # Egress Sealer
            input_state_hash = compute_dag_hash(parent_hashes, "input_hash", env_data)

            # Prepare the entry and attach it to the DAG to allow children to link
            entry = KestEntry(
                entry_id=entry_id,
                parent_entry_ids=parent_ids,
                node_id=node_id,
                timestamp_ms=int(time.time() * 1000),
                input_state_hash=input_state_hash,
                content_hash="output_hash",
                environment=env_data,
                added_taint=added_taint,
                accumulated_taint=current_tag_accumulated,
                trust_score=current_trust_score,
            )
            passport.history[entry_id] = entry

            for exporter in telemetry_exporters:
                exporter.export(passport)

            # Return wrapped result
            return _wrap_result(result, passport)

        return wrapper

    return decorator
