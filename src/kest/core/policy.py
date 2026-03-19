import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict

logger = logging.getLogger(__name__)

try:
    import lakera_regorus

    _HAS_REGORUS = True
except ImportError:
    lakera_regorus = None
    _HAS_REGORUS = False

try:
    from opa_client.opa import OpaClient

    _HAS_OPA_CLIENT = True
except ImportError:
    OpaClient = None
    _HAS_OPA_CLIENT = False


class OpaEngine(ABC):
    """Abstract base class for Kest OPA evaluation engines."""

    @abstractmethod
    def evaluate(self, payload: Dict[str, Any], rule_path: str) -> bool:
        """Evaluates the payload against the rule_path."""
        pass


class LocalOpaEngine(OpaEngine):
    """Wrapper around Microsoft's Regorus engine (via lakera_regorus) for evaluating Kest policies locally.
    Gracefully falls back to a RemoteOpaClient locally if lakera wheels are unsupported."""

    def __init__(self):
        if _HAS_REGORUS:
            self.mode = "lakera"
            self._engine = lakera_regorus.Engine()  # type: ignore
            self._compiled = False
        else:
            self.mode = "fallback"
            logger.warning(
                "lakera-regorus wheel unsupported for this Python version/OS. "
                "Falling back to LocalOpaEngine via RemoteOpaClient on localhost:8181."
            )
            self._remote_fallback = RemoteOpaClient(host="localhost", port=8181)

    def add_policy(self, name: str, rego_code: str) -> None:
        """Compiles and registers inline Rego policy code."""
        if self.mode == "fallback":
            logger.warning(
                f"Inline policies cannot be added dynamically in fallback mode. Skipping {name}."
            )
            return

        if not name.endswith(".rego"):
            name += ".rego"
        try:
            self._engine.add_policy(name, rego_code)  # type: ignore
            self._compiled = True
        except Exception as e:
            raise ValueError(f"Failed to compile Rego policy '{name}': {e}")

    def evaluate(self, payload: Dict[str, Any], rule_path: str) -> bool:
        """
        Evaluates the supplied JSON-serializable payload against the active policies.
        `rule_path` corresponds to a boolean Rego rule (e.g., "data.kest.policy.allow").
        """
        if self.mode == "fallback":
            return self._remote_fallback.evaluate(payload, rule_path)

        if not getattr(self, "_compiled", False):
            raise RuntimeError("No policies have been loaded into the OpaEngine.")

        try:
            input_json = json.dumps(payload)
            self._engine.set_input_json(input_json)  # type: ignore

            result_dict = self._engine.eval_query(rule_path)  # type: ignore

            results = result_dict.get("result", [])
            if not results:
                return False

            expressions = results[0].get("expressions", [])
            if not expressions:
                return False

            return bool(expressions[0].get("value"))

        except Exception as e:
            raise ValueError(f"Rego evaluation failed for query '{rule_path}': {e}")


class RemoteOpaClient(OpaEngine):
    """Wrapper around opa-python-client for evaluating Kest policies via a remote OPA server."""

    def __init__(self, host: str = "localhost", port: int = 8181, version: str = "v1"):
        if not _HAS_OPA_CLIENT:
            raise ImportError(
                "RemoteOpaClient requires 'opa-python-client'. Install with `pip install kest[opa-client]`."
            )
        assert OpaClient is not None
        self._client = OpaClient(host=host, port=port, version=version)

    def evaluate(self, payload: Dict[str, Any], rule_path: str) -> bool:
        """
        Evaluates the supplied JSON-serializable payload against the remote OPA server.
        `rule_path` corresponds to a boolean Rego rule (e.g., "data.kest.policy.allow").
        Note: The client's `check_policy_rule` or `check_connection` methods expect
        the package and rule components. We map `data.pkg.rule` to query it.
        """
        try:
            # opa-python-client typically wants input wrapped as dict
            # e.g., client.check_policy_rule(input_data=payload, package_path="kest/policy", rule_name="allow")
            # We'll need to parse `rule_path` to extract the package path and rule name.
            if rule_path.startswith("data."):
                rule_path = rule_path[5:]  # strip 'data.'

            parts = rule_path.split(".")
            if len(parts) < 2:
                raise ValueError(
                    f"Invalid rule path format: '{rule_path}'. Expected at least 'pkg.rule'"
                )

            rule_name = parts[-1]
            package_path = "/".join(parts[:-1])

            # The opa-python-client check_policy_rule method signature:
            # check_policy_rule(input_data, package_path, rule_name)

            result = self._client.check_policy_rule(  # type: ignore
                input_data=payload, package_path=package_path, rule_name=rule_name
            )

            # It generally returns a dict like {'result': True} or actual boolean depending on the policy.
            if isinstance(result, dict) and "result" in result:
                return bool(result.get("result", False))

            return bool(result)

        except Exception as e:
            raise ValueError(
                f"Remote OPA evaluation failed for query '{rule_path}': {e}"
            )
