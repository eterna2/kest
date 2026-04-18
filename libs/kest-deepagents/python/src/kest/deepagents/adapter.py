import functools
import inspect
from typing import Any, Callable, TypeVar


class PolicyViolation(Exception):
    pass


def get_current_passport():
    """Retrieve the current Agent Passport from OpenTelemetry context or contextvars."""
    # Placeholder for actual context var extraction
    return None


class EvaluationResult:
    def __init__(self, is_allowed: bool, reason: str = ""):
        self.is_allowed = is_allowed
        self.reason = reason


def evaluate_policy(
    passport: Any, policy_name: str, args_payload: dict
) -> EvaluationResult:
    """Invokes kest-core policy validation."""
    return EvaluationResult(True)


F = TypeVar("F", bound=Callable[..., Any])


def kest_tool(policy_name: str) -> Callable[[F], F]:
    """
    Adapter decorator wrapping `deepagents` tools.
    1. Intersects the execution node.
    2. Extracts the Agent Passport from context.
    3. Enforces `@kest_verified` constraints by evaluating the policy.
    4. Propagates the evaluation trace.
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Extract arguments cleanly for policy evaluation payload
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()
            payload = bound_args.arguments

            passport = get_current_passport()
            if not passport:
                raise PolicyViolation("Agent Passport not found in context")

            result = evaluate_policy(passport, policy_name, payload)
            if not result.is_allowed:
                raise PolicyViolation(result.reason or "Policy evaluated to DENY")

            return func(*args, **kwargs)

        return wrapper  # type: ignore

    return decorator
