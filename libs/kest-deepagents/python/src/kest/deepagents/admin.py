"""
KestAdminSubagent — Built-in subagent for policy management and trace inspection.

Satisfies ``SubagentProtocol`` so it can be registered with ``KestAgent``.

Capabilities:

1. **Trace inspection** — ``explain_limits`` looks up OTel traces to
   explain which policies were evaluated and their outcomes.

2. **Policy CRUD** — ``create_policy``, ``list_policies``, ``delete_policy``
   manage policy definitions in a ``PolicyStore``. ``apply_policy`` binds a
   stored policy to a tool or agent name.

All tool methods use the idiomatic ``@tool + @kest_verified`` stacking
pattern for zero-trust enforcement.

.. warning::

   The ``PolicyStore`` manages policy *definitions* only; it does **not**
   hot-swap the live ``kest.core`` policy engine. Callers must wire the
   store contents to the engine themselves (e.g. via ``kest.core.configure``).
   This preserves dependency-injection discipline and avoids hidden side
   effects inside the subagent.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Protocol

from langchain_core.tools import BaseTool, tool

from kest.core import kest_verified

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PolicyStore — pluggable backend for policy definitions
# ---------------------------------------------------------------------------


class PolicyStore(Protocol):
    """
    Protocol for a backend storing policy definitions.

    Implementations range from in-memory dicts to SQLite / remote stores.
    The admin subagent operates exclusively through this interface.
    """

    def create(self, policy_id: str, definition: Dict[str, Any]) -> None:
        """
        Create a new policy definition.

        Raises:
            ValueError: If *policy_id* already exists.
        """
        ...

    def list(self) -> List[Dict[str, Any]]:
        """Return all policy definitions as a list of dicts."""
        ...

    def get(self, policy_id: str) -> Optional[Dict[str, Any]]:
        """Return a single policy definition, or ``None`` if not found."""
        ...

    def delete(self, policy_id: str) -> None:
        """
        Delete a policy definition.

        Raises:
            KeyError: If *policy_id* does not exist.
        """
        ...


class InMemoryPolicyStore:
    """
    Default in-memory implementation of ``PolicyStore``.

    Useful for demos, tests, and ephemeral sessions. All data is lost when
    the process exits.
    """

    def __init__(self) -> None:
        self._store: Dict[str, Dict[str, Any]] = {}

    def create(self, policy_id: str, definition: Dict[str, Any]) -> None:
        if policy_id in self._store:
            raise ValueError(f"Policy '{policy_id}' already exists.")
        self._store[policy_id] = {"id": policy_id, **definition}

    def list(self) -> List[Dict[str, Any]]:
        return list(self._store.values())

    def get(self, policy_id: str) -> Optional[Dict[str, Any]]:
        return self._store.get(policy_id)

    def delete(self, policy_id: str) -> None:
        if policy_id not in self._store:
            raise KeyError(f"Policy '{policy_id}' not found.")
        del self._store[policy_id]


# ---------------------------------------------------------------------------
# TraceBackend — protocol for OTel trace lookup
# ---------------------------------------------------------------------------


class TraceBackend(Protocol):
    """Protocol defining the interface for the backend providing OTel traces."""

    def get_trace(self, trace_id: str) -> Dict[str, Any]:
        ...


# ---------------------------------------------------------------------------
# KestAdminSubagent
# ---------------------------------------------------------------------------


class KestAdminSubagent:
    """
    Built-in subagent for policy management and trace inspection.

    Satisfies ``SubagentProtocol`` — register it with ``KestAgent`` to make
    its tools available in the multi-agent tool roster.

    Args:
        trace_backend: Backend capable of returning structured trace spans.
        policy_store:  Pluggable policy store (defaults to
                       ``InMemoryPolicyStore``).
    """

    name: str = "admin"
    description: str = "Policy management and trace inspection"

    def __init__(
        self,
        trace_backend: TraceBackend,
        policy_store: Optional[PolicyStore] = None,
    ) -> None:
        self.trace_backend = trace_backend
        self.policy_store: PolicyStore = policy_store or InMemoryPolicyStore()

    # ------------------------------------------------------------------
    # SubagentProtocol.get_tools
    # ------------------------------------------------------------------

    def get_tools(self) -> List[BaseTool]:
        """Return all admin tools as a flat list."""
        return [
            self.get_explain_tool(),
            self.get_create_policy_tool(),
            self.get_list_policies_tool(),
            self.get_apply_policy_tool(),
            self.get_delete_policy_tool(),
        ]

    # ------------------------------------------------------------------
    # Domain helpers (pure, no kest_verified)
    # ------------------------------------------------------------------

    def parse_policy_decisions(self, spans: List[Dict[str, Any]]) -> List[str]:
        """
        Extracts evaluated Kest policy names from a list of trace spans.

        Args:
            spans: List of span dictionaries conforming to standard trace attributes.

        Returns:
            A list of policy names that were evaluated within the trace.
        """
        decisions = []
        for span in spans:
            attrs = span.get("attributes", {})
            if "kest.policy_ids" in attrs:
                # OTel attributes may store these as a comma-separated string
                for pol in attrs["kest.policy_ids"].split(","):
                    if pol:
                        decisions.append(pol.strip())
        return decisions

    # ------------------------------------------------------------------
    # Tool: explain_limits (existing)
    # ------------------------------------------------------------------

    def get_explain_tool(self) -> BaseTool:
        """
        Returns a kest-verified LangChain tool that looks up policy decisions in traces.

        Uses the idiomatic ``@tool + @kest_verified`` stacking pattern so that
        access to the trace backend is itself zero-trust enforced.

        Returns:
            A LangChain BaseTool instance that LLMs can use to query policies.
        """

        @tool
        @kest_verified(
            policy="admin_policy",
            trust_override=90,
            context_map={"trace_id": "trace_id"},
        )
        def explain_limits(trace_id: str) -> str:
            """Looks up a Zero-Trust distributed trace to explain what specific access limits or policies were encountered."""
            trace = self.trace_backend.get_trace(trace_id)
            if not trace:
                return f"Trace {trace_id} not found."

            spans = trace.get("spans", [])
            decisions = []
            for span in spans:
                attrs = span.get("attributes", {})
                if "kest.policy_ids" in attrs:
                    policies = attrs["kest.policy_ids"]
                    allowed = attrs.get("kest.allowed", "UNKNOWN")

                    status = "UNKNOWN"
                    if allowed is True:
                        status = "ALLOWED"
                    elif allowed is False:
                        status = "DENIED"

                    decisions.append(f"Policy '{policies}' evaluated to {status}.")

            if not decisions:
                return "No Kest policy limitations found in trace."

            return "Execution limits hit:\n" + "\n".join(decisions)

        return explain_limits

    # ------------------------------------------------------------------
    # Tool: create_policy
    # ------------------------------------------------------------------

    def get_create_policy_tool(self) -> BaseTool:
        """Create a new policy definition in the policy store."""

        @tool
        @kest_verified(
            policy="admin_policy",
            trust_override=90,
            context_map={"policy_id": "policy_id"},
        )
        def create_policy(policy_id: str, definition_json: str) -> str:
            """
            Create a named policy definition.

            Args:
                policy_id:       Unique identifier for the policy.
                definition_json: JSON string with the policy body.

            Note: This stores the definition only. To make it active, the
            caller must wire it to the kest.core policy engine via
            kest.core.configure(). See KestAdminSubagent docstring.
            """
            try:
                definition = json.loads(definition_json)
            except json.JSONDecodeError as exc:
                return f"Invalid JSON: {exc}"
            try:
                self.policy_store.create(policy_id, definition)
            except ValueError as exc:
                return str(exc)
            logger.info(
                "Policy '%s' created. WARNING: not yet wired to kest.core engine. "
                "Call kest.core.configure(engine=...) to activate.",
                policy_id,
            )
            return f"Policy '{policy_id}' created successfully."

        return create_policy

    # ------------------------------------------------------------------
    # Tool: list_policies
    # ------------------------------------------------------------------

    def get_list_policies_tool(self) -> BaseTool:
        """List all policy definitions in the store."""

        @tool
        @kest_verified(
            policy="admin_policy",
            trust_override=95,
        )
        def list_policies() -> str:
            """List all registered policy definitions."""
            policies = self.policy_store.list()
            if not policies:
                return "No policies registered."
            return json.dumps(policies, indent=2)

        return list_policies

    # ------------------------------------------------------------------
    # Tool: apply_policy
    # ------------------------------------------------------------------

    def get_apply_policy_tool(self) -> BaseTool:
        """Bind a stored policy to a target (tool or agent name)."""

        @tool
        @kest_verified(
            policy="admin_policy",
            trust_override=90,
            context_map={"policy_id": "policy_id", "target": "target"},
        )
        def apply_policy(policy_id: str, target: str) -> str:
            """
            Bind a stored policy definition to a target tool or agent.

            This records the binding in the policy store. The binding is NOT
            automatically wired to the live kest.core engine — the caller must
            invoke ``kest.core.configure(engine=...)`` to activate changes.

            Args:
                policy_id: ID of the policy to apply.
                target:    Name of the tool or agent to bind the policy to.
            """
            policy = self.policy_store.get(policy_id)
            if policy is None:
                return f"Policy '{policy_id}' not found."
            # Record the binding in the definition
            policy.setdefault("bindings", [])
            if target not in policy["bindings"]:
                policy["bindings"].append(target)
            logger.warning(
                "Policy '%s' bound to target '%s'. This is a store-only "
                "operation — call kest.core.configure(engine=...) to make "
                "it effective.",
                policy_id,
                target,
            )
            return (
                f"Policy '{policy_id}' bound to '{target}'. "
                f"NOTE: Call kest.core.configure(engine=...) to activate."
            )

        return apply_policy

    # ------------------------------------------------------------------
    # Tool: delete_policy
    # ------------------------------------------------------------------

    def get_delete_policy_tool(self) -> BaseTool:
        """Delete a policy definition from the store."""

        @tool
        @kest_verified(
            policy="admin_policy",
            trust_override=90,
            context_map={"policy_id": "policy_id"},
        )
        def delete_policy(policy_id: str) -> str:
            """
            Delete a policy definition by ID.

            Args:
                policy_id: ID of the policy to remove.
            """
            try:
                self.policy_store.delete(policy_id)
            except KeyError as exc:
                return str(exc)
            return f"Policy '{policy_id}' deleted."

        return delete_policy
