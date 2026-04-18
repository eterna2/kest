import importlib.util
from typing import Optional

HAS_REGOPY = importlib.util.find_spec("regopy") is not None
HAS_CEDAR = importlib.util.find_spec("cedarpy") is not None


def is_allowed(res) -> bool:
    """
    Helper to check if the Rego query result means 'allow'.
    Uses res.results[0].expressions to avoid potential crashes in
    res.expressions() when the result is 'undefined' (e.g. for false results).
    """
    if not res.ok():
        return False

    # Each Result object contains 'expressions' (list of terms)
    # and 'bindings' (dict of variable mappings).
    # For a rule check, we care about the first result's expressions.
    if not res.results:
        return False

    exprs = res.results[0].expressions
    # If the rule evaluates to true, the first expression is typically True.
    # If it's false or undefined, expressions will be empty.
    return len(exprs) > 0 and exprs[0] is True


def is_cedar_allowed(
    policies: str,
    principal: str,
    action: str,
    resource: str,
    context: Optional[dict] = None,
) -> bool:
    """
    Helper to check if a Cedar request is authorized.
    """
    if not HAS_CEDAR:
        raise ImportError("cedarpy not installed")

    import cedarpy as _cedarpy

    # cedarpy.is_authorized expects a dict for the request
    request = {
        "principal": principal,
        "action": action,
        "resource": resource,
        "context": context or {},
    }

    # In this simple model testing, we don't use external entities
    entities: list = []

    res = _cedarpy.is_authorized(request, policies, entities)
    return res.decision == _cedarpy.Decision.Allow
