import hashlib
from abc import ABC, abstractmethod
from typing import Any, Optional, List, Dict
import httpx


class PolicyEngine(ABC):
    """
    Abstract base class for all policy engines in Kest.

    A PolicyEngine identifies whether a specific action (entry_id) is authorized
    under a set of policies given a specific context.
    """

    @abstractmethod
    def evaluate(
        self, entry_id: str, policy_names: List[str], context: Dict[str, Any]
    ) -> bool:
        """
        Synchronously evaluates whether the request is authorized.

        Args:
            entry_id: The unique identifier for the execution node or resource.
            policy_names: A list of policy identifiers to evaluate against.
            context: A dictionary of context attributes (e.g., principal, trust_score).

        Returns:
            bool: True if authorized, False otherwise.
        """
        pass

    async def async_evaluate(
        self, entry_id: str, policy_names: List[str], context: Dict[str, Any]
    ) -> bool:
        """
        Asynchronously evaluates whether the request is authorized.

        Default implementation uses a thread pool to prevent blocking the
        event loop for synchronous implementations.

        Args:
            entry_id: The unique identifier for the execution node or resource.
            policy_names: A list of policy identifiers to evaluate against.
            context: A dictionary of context attributes.

        Returns:
            bool: True if authorized, False otherwise.
        """
        import asyncio

        return await asyncio.to_thread(self.evaluate, entry_id, policy_names, context)


class PolicyCache:
    """
    Caches compiled policy results or metadata to avoid redundant lookups.

    This is particularly useful for local engines that perform expensive
    compilation or for remote engines with high latency.
    """

    def __init__(self):
        """Initializes an empty policy cache."""
        self._cache = {}

    def get(self, policy_str: str) -> Optional[Any]:
        """
        Retrieves a cached object for a given policy string.

        Args:
            policy_str: The raw policy string or identifier.

        Returns:
            Optional[Any]: The cached object if found, else None.
        """
        key = hashlib.sha256(policy_str.encode()).hexdigest()
        return self._cache.get(key)

    def set(self, policy_str: str, compiled_obj: Any):
        """
        Caches an object for a given policy string.

        Args:
            policy_str: The raw policy string or identifier.
            compiled_obj: The object to cache.
        """
        key = hashlib.sha256(policy_str.encode()).hexdigest()
        self._cache[key] = compiled_obj


class OPAPolicyEngine(PolicyEngine):
    """
    Evaluates policies by delegating to an Open Policy Agent (OPA) sidecar.

    This engine communicates with OPA via its REST API (v1/data).
    """

    def __init__(
        self,
        url: str = "http://localhost:8181",
        timeout: float = 0.5,
        cache: Optional[PolicyCache] = None,
        decision_path: str = "result.allow",
    ):
        """
        Initializes the OPA policy engine.

        Args:
            url: The base URL of the OPA sidecar.
            timeout: Request timeout in seconds.
            cache: Optional PolicyCache instance.
            decision_path: The dot-separated path to the boolean decision in the OPA response.
        """
        self.url = url
        self.timeout = timeout
        self.cache = cache or PolicyCache()
        self.decision_path = decision_path
        self._sync_client = httpx.Client(timeout=timeout)
        self._async_client = httpx.AsyncClient(timeout=timeout)

    def _get_decision(self, response_json: dict) -> bool:
        """Extracts the boolean decision from the OPA JSON response."""
        parts = self.decision_path.split(".")
        current = response_json
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return False
        return bool(current)

    def evaluate(
        self, entry_id: str, policy_names: List[str], context: Dict[str, Any]
    ) -> bool:
        """
        Evaluates authorization via OPA synchronous API.

        Args:
            entry_id: Identifier for the evaluation resource.
            policy_names: List of Rego package/rule names to query.
            context: The input context for OPA.

        Returns:
            bool: True if OPA returns 'allow' for all policies.
        """
        try:
            for policy in policy_names:
                response = self._sync_client.post(
                    f"{self.url}/v1/data/kest/{policy}", json={"input": context}
                )

                if response.status_code != 200:
                    print(f"[Kest.OPA] Error: Sidecar returned {response.status_code}")
                    return False

                res_json = response.json()
                # If we queried a specific rule (e.g. /v1/data/kest/allow),
                # OPA returns {"result": true/false}.
                if "result" in res_json and not isinstance(res_json["result"], dict):
                    if not res_json.get("result"):
                        return False
                    continue

                if not self._get_decision(res_json):
                    return False

            return True
        except httpx.RequestError as e:
            print(f"[Kest.OPA] Network Error: {e}")
            return False
        except Exception as e:
            print(f"[Kest.OPA] Unexpected Error: {e}")
            return False

    async def async_evaluate(
        self, entry_id: str, policy_names: List[str], context: Dict[str, Any]
    ) -> bool:
        """
        Evaluates authorization via OPA non-blocking async API.

        Args:
            entry_id: Identifier for the evaluation resource.
            policy_names: List of Rego package/rule names to query.
            context: The input context for OPA.

        Returns:
            bool: True if OPA returns 'allow' for all policies.
        """
        try:
            for policy in policy_names:
                response = await self._async_client.post(
                    f"{self.url}/v1/data/kest/{policy}", json={"input": context}
                )

                if response.status_code != 200:
                    print(f"[Kest.OPA] Error: Sidecar returned {response.status_code}")
                    return False

                res_json = response.json()
                if "result" in res_json and not isinstance(res_json["result"], dict):
                    if not res_json.get("result"):
                        return False
                    continue

                if not self._get_decision(res_json):
                    return False

            return True
        except httpx.RequestError as e:
            print(f"[Kest.OPA] Network Error: {e}")
            return False
        except Exception as e:
            print(f"[Kest.OPA] Unexpected Error: {e}")
            return False


class CedarPolicyEngine(PolicyEngine):
    """
    Evaluates policies by delegating to a Cedar Agent / Sidecar.

    This engine assumes a sidecar implementing the `is_authorized` JSON interface.
    """

    def __init__(
        self,
        url: str = "http://localhost:8180",
        timeout: float = 0.5,
        cache: Optional[PolicyCache] = None,
    ):
        """
        Initializes the Cedar sidecar engine.

        Args:
            url: The base URL of the Cedar agent.
            timeout: Request timeout in seconds.
            cache: Optional PolicyCache instance.
        """
        self.url = url
        self.timeout = timeout
        self.cache = cache or PolicyCache()
        self._sync_client = httpx.Client(timeout=timeout)
        self._async_client = httpx.AsyncClient(timeout=timeout)

    def evaluate(
        self, entry_id: str, policy_names: List[str], context: Dict[str, Any]
    ) -> bool:
        """
        Evaluates authorization via Cedar sidecar synchronous API.

        Args:
            entry_id: The resource ID in Cedar syntax.
            policy_names: List of Cedar policy IDs.
            context: Principal, Action, Resource, and Context attributes.

        Returns:
            bool: True if Cedar returns 'Allow'.
        """
        try:
            for policy in policy_names:
                response = self._sync_client.post(
                    f"{self.url}/is_authorized",
                    json={
                        "principal": context.get("principal"),
                        "action": "execute",
                        "resource": entry_id,
                        "context": context,
                        "policy_id": policy,
                    },
                )
                if response.status_code != 200:
                    print(
                        f"[Kest.Cedar] Error: Sidecar returned {response.status_code}"
                    )
                    return False

                if response.json().get("decision") != "Allow":
                    return False
            return True
        except httpx.RequestError as e:
            print(f"[Kest.Cedar] Network Error: {e}")
            return False
        except Exception as e:
            print(f"[Kest.Cedar] Unexpected Error: {e}")
            return False

    async def async_evaluate(
        self, entry_id: str, policy_names: List[str], context: Dict[str, Any]
    ) -> bool:
        """
        Evaluates authorization via Cedar sidecar async API.

        Args:
            entry_id: The resource ID in Cedar syntax.
            policy_names: List of Cedar policy IDs.
            context: Principal, Action, Resource, and Context attributes.

        Returns:
            bool: True if Cedar returns 'Allow'.
        """
        try:
            for policy in policy_names:
                response = await self._async_client.post(
                    f"{self.url}/is_authorized",
                    json={
                        "principal": context.get("principal"),
                        "action": "execute",
                        "resource": entry_id,
                        "context": context,
                        "policy_id": policy,
                    },
                )
                if response.status_code != 200:
                    print(
                        f"[Kest.Cedar] Error: Sidecar returned {response.status_code}"
                    )
                    return False

                if response.json().get("decision") != "Allow":
                    return False
            return True
        except httpx.RequestError as e:
            print(f"[Kest.Cedar] Network Error: {e}")
            return False
        except Exception as e:
            print(f"[Kest.Cedar] Unexpected Error: {e}")
            return False


class CedarLocalEngine(PolicyEngine):
    """
    In-process Cedar engine using the official `cedarpy` bindings.

    This engine is ideal for edge environments or local testing where a
    sidecar is not available.
    """

    def __init__(self, policies: dict, entities: list):
        """
        Initializes the local Cedar engine.

        Args:
            policies: A dictionary of policy IDs to Cedar policy strings.
            entities: A list of Cedar entity dictionaries.

        Raises:
            ImportError: If `cedarpy` is not installed.
        """
        try:
            import cedarpy
        except ImportError:
            raise ImportError("cedarpy is not installed. Please install kest[cedar].")

        self.cedarpy = cedarpy
        self.policies = policies
        self.entities = entities
        self._policies_str = "\n".join(policies.values())

        import json

        self._entities_str = json.dumps(entities) if entities else "[]"
        self.cache = PolicyCache()

    def evaluate(
        self, entry_id: str, policy_names: List[str], context: Dict[str, Any]
    ) -> bool:
        """
        Evaluates authorization locally using Rust-backed cedarpy logic.

        Args:
            entry_id: Resource identifier.
            policy_names: (Not used for local evaluation logic which uses the full policy set).
            context: Context attributes for the request.

        Returns:
            bool: True if authorized.
        """
        principal_id = context.get("principal")
        principal = (
            f'Workload::"{principal_id}"' if principal_id else 'User::"anonymous"'
        )
        action = 'Action::"execute"'
        resource = f'Resource::"{entry_id}"'

        clean_context = {k: v for k, v in context.items() if v is not None}

        request = {
            "principal": principal,
            "action": action,
            "resource": resource,
            "context": clean_context,
        }

        # Evaluate only the requested policies to prevent cross-policy forbid collisions
        policies_to_eval = [
            self.policies[p] for p in policy_names if p in self.policies
        ]
        if not policies_to_eval:
            policies_to_eval = list(self.policies.values())
        policies_str = "\n".join(policies_to_eval)

        try:
            decision = self.cedarpy.is_authorized(
                request, policies_str, self._entities_str
            )
            return decision.decision == self.cedarpy.Decision.Allow
        except Exception as e:
            print(f"[Kest.CedarLocal] Error during evaluation: {e}")
            return False


class AVPPolicyEngine(PolicyEngine):
    """
    Evaluates policy by delegating to Amazon Verified Permissions (AVP).

    This engine leverages AWS's managed Cedar service. It supports both
    synchronous (boto3) and asynchronous (aioboto3) clients.
    """

    def __init__(
        self,
        policy_store_id: str,
        region_name: str = "us-east-1",
        cache: Optional[PolicyCache] = None,
    ):
        """
        Initializes the AVP engine.

        Args:
            policy_store_id: The AWS AVP Policy Store ID.
            region_name: AWS region (e.g., us-east-1).
            cache: Optional PolicyCache instance.
        """
        self.policy_store_id = policy_store_id
        self.region_name = region_name
        self.cache = cache or PolicyCache()

        try:
            import boto3

            self.boto3 = boto3
            self._sync_client = boto3.client(
                "verifiedpermissions", region_name=region_name
            )
        except ImportError:
            self.boto3 = None

        try:
            import aioboto3

            self.aioboto3 = aioboto3
            self._async_session = aioboto3.Session()
        except ImportError:
            self.aioboto3 = None

    def evaluate(
        self, entry_id: str, policy_names: List[str], context: Dict[str, Any]
    ) -> bool:
        """
        Evaluates authorization via AWS AVP IsAuthorized API.

        Args:
            entry_id: Resource ID in AVP.
            policy_names: Names of policies to evaluate.
            context: Request context attributes.

        Returns:
            bool: True if AVP returns ALLOW.
        """
        if not self.boto3:
            raise ImportError("boto3 is not installed. Please install kest[aws].")

        try:
            for policy in policy_names:
                response = self._sync_client.is_authorized(
                    policyStoreId=self.policy_store_id,
                    principal={
                        "entityType": "Workload",
                        "entityId": context.get("principal", "anonymous"),
                    },
                    action={"actionType": "Action", "actionId": "Execute"},
                    resource={
                        "entityType": "ExecutionNode",
                        "entityId": entry_id,
                    },
                    context={"contextMap": {"policy_name": {"string": policy}}},
                )

                if response.get("decision") != "ALLOW":
                    return False

            return True
        except Exception as e:
            print(f"[Kest.AVP] Error: {e}")
            return False

    async def async_evaluate(
        self, entry_id: str, policy_names: List[str], context: Dict[str, Any]
    ) -> bool:
        """
        Evaluates authorization via AWS AVP using non-blocking aioboto3.

        Args:
            entry_id: Resource ID in AVP.
            policy_names: Names of policies to evaluate.
            context: Request context attributes.

        Returns:
            bool: True if AVP returns ALLOW.
        """
        if not self.aioboto3:
            # Fall back to thread if aioboto3 is missing but boto3 is present
            if self.boto3:
                return await super().async_evaluate(entry_id, policy_names, context)
            raise ImportError("aioboto3 is not installed. Please install kest[aws].")

        try:
            async with self._async_session.client(
                "verifiedpermissions", region_name=self.region_name
            ) as client:
                for policy in policy_names:
                    response = await client.is_authorized(
                        policyStoreId=self.policy_store_id,
                        principal={
                            "entityType": "Workload",
                            "entityId": context.get("principal", "anonymous"),
                        },
                        action={"actionType": "Action", "actionId": "Execute"},
                        resource={
                            "entityType": "ExecutionNode",
                            "entityId": entry_id,
                        },
                        context={"contextMap": {"policy_name": {"string": policy}}},
                    )

                    if response.get("decision") != "ALLOW":
                        return False

                return True
        except Exception as e:
            print(f"[Kest.AVP] Error: {e}")
            return False


class MockPolicyEngine(PolicyEngine):
    """
    A simple policy engine that always returns a fixed decision.

    Useful for testing environments or initial development.
    """

    def __init__(self, allow_all: bool = True):
        """
        Initializes the mock engine.

        Args:
            allow_all: If True, all requests are allowed. If False, all are denied.
        """
        self.allow_all = allow_all

    def evaluate(
        self, entry_id: str, policy_names: List[str], context: Dict[str, Any]
    ) -> bool:
        """Returns the fixed decision regardless of inputs."""
        return self.allow_all


class RegoLocalEngine(PolicyEngine):
    """
    In-process Rego policy engine using ``regopy`` (Regorus — Rust-backed).

    Evaluates OPA-compatible Rego policies without requiring an OPA sidecar.
    Each named policy maps to a Rego module loaded into a shared ``Interpreter``
    instance.  The query rule is configurable (defaults to ``allow``).

    Requires the optional ``rego`` extra::

        pip install kest[rego]

    Example::

        engine = RegoLocalEngine(
            policies={
                "authz": '''
                    package kest.authz
                    default allow = false
                    allow { input.trust_score >= 50 }
                '''
            }
        )
    """

    def __init__(
        self,
        policies: Dict[str, str],
        query_rule: str = "allow",
        cache: Optional[PolicyCache] = None,
    ):
        """
        Initialise the local Rego engine.

        Args:
            policies: Mapping of policy names to raw Rego source strings.
                      The policy name is used as the module name; the package
                      declaration inside the Rego source is used to derive the
                      query path (``data.<package>.<query_rule>``).
            query_rule: The rule name to query within each policy's package.
                        Defaults to ``"allow"``.
            cache: Optional :class:`PolicyCache` for memoising repeated decisions.

        Raises:
            ImportError: If ``regopy`` is not installed.
        """
        try:
            from regopy import Interpreter  # noqa: F401
        except ImportError:
            raise ImportError(
                "regopy is not installed. Install it with: pip install kest[rego]"
            )

        self._policies = policies
        self._query_rule = query_rule
        self.cache = cache or PolicyCache()
        self._interpreters: Dict[str, Any] = {}
        self._packages: Dict[str, str] = {}
        self._load_policies()

    def _load_policies(self) -> None:
        """Pre-load all Rego modules and cache per-policy package paths."""
        from regopy import Interpreter

        for name, source in self._policies.items():
            interp = Interpreter()
            interp.add_module(name, source)
            self._interpreters[name] = interp
            self._packages[name] = self._parse_package(source, fallback=f"kest.{name}")

    @staticmethod
    def _parse_package(source: str, fallback: str) -> str:
        """Extract the dot-separated package path from a Rego source string."""
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith("package "):
                return stripped[len("package ") :].strip()
        return fallback

    @staticmethod
    def _is_allowed(output) -> bool:
        """
        Normalise a ``regopy`` ``Output`` object to a boolean allow decision.

        ``Output.results[0].expressions`` is ``[True]`` on allow,
        and ``[]`` (undefined) on deny.
        """
        try:
            results = output.results
            if not results:
                return False
            expressions = results[0].expressions
            return bool(expressions) and bool(expressions[0])
        except Exception:
            return False

    def evaluate(
        self, entry_id: str, policy_names: List[str], context: Dict[str, Any]
    ) -> bool:
        """
        Evaluate Rego policies synchronously in-process.

        Args:
            entry_id: Resource identifier injected into ``input.resource``.
            policy_names: Subset of named policies to run (all must allow).
            context: Arbitrary key/value pairs merged into the OPA ``input`` document.

        Returns:
            bool: ``True`` only if every named policy returns allow.
        """
        input_doc = {**context, "resource": entry_id}

        for name in policy_names:
            interp = self._interpreters.get(name)
            if interp is None:
                print(f"[Kest.RegoLocal] Unknown policy '{name}' — denying.")
                return False

            cache_key = str((name, entry_id, str(sorted(context.items()))))
            cached = self.cache.get(cache_key)
            if cached is not None:
                if not cached:
                    return False
                continue

            try:
                interp.set_input(input_doc)
                query = f"data.{self._packages[name]}.{self._query_rule}"
                result = interp.query(query)
                decision = self._is_allowed(result)
            except Exception as e:
                print(f"[Kest.RegoLocal] Error evaluating '{name}': {e}")
                decision = False

            self.cache.set(cache_key, decision)
            if not decision:
                return False

        return True
