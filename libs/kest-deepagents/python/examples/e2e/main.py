"""
Kest + DeepAgents E2E Example: Zero-Trust Research Agent
=========================================================

Demonstrates how kest tracks and verifies every step of an LLM-driven
multi-step agent pipeline:

  1. An LLM call (KestChatModel) — the model decides which tools to use.
  2. Tool invocations decorated with @tool + @kest_verified — each tool call
     is zero-trust evaluated and added to the Merkle audit passport.
  3. A second LLM call (KestChatModel) — the model synthesises the results.
  4. At the end, the Merkle chain is printed showing the full execution lineage.

Mock boundary
-------------
Only the LLM responses are mocked (FakeListChatModel from langchain_core).
All kest infrastructure runs for real:
  - VerbosePolicyEngine shows every policy decision
  - MockIdentityProvider performs real Ed25519 signing
  - kest_verified intercepts every tool call and LLM invocation
  - OTel baggage propagation builds the real Merkle chain

Note on chain_tip visibility: kest follows OTel context semantics —
the updated baggage token is attached *inside* the verified function's scope
and detached on exit. The chain is captured from inside each call below.

Run:
    moon run kest-deepagents-python:run-e2e
or:
    uv run python examples/e2e/main.py
"""

import textwrap

import opentelemetry.context as otel_context
from langchain_core.language_models.fake_chat_models import FakeListChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.tools import tool
from opentelemetry import baggage

from kest.core import configure, invalidate_policy_cache, kest_verified, MockPolicyEngine
from kest.core.identity import MockIdentityProvider
from kest.deepagents import KestChatModel

# ---------------------------------------------------------------------------
# 1.  Configure kest
# ---------------------------------------------------------------------------

LLM_POLICY = "llm_invocation_policy"
SEARCH_POLICY = "web_search_policy"
SUMMARISE_POLICY = "summarise_policy"

# Shared audit log: each verified step appends a record here
audit_log: list[dict] = []


class VerbosePolicyEngine(MockPolicyEngine):
    """Passes every invocation and prints the policy context for inspection."""

    def evaluate(self, entry_id: str, policy_names: list, context: dict) -> bool:
        print(
            f"  🔒 POLICY CHECK | policies={policy_names} | "
            f"trust={context.get('trust_score', '?'):>3} | "
            f"principal={str(context.get('principal', '?'))[:20]}…"
        )
        return True  # Allow all for the demo; swap with a real engine for production


configure(
    engine=VerbosePolicyEngine(),
    identity=MockIdentityProvider(),
)
invalidate_policy_cache()

# ---------------------------------------------------------------------------
# 2.  Define zero-trust tools using the @tool + @kest_verified pattern
#
#     Decoration order matters:
#       @tool           ← LangChain makes it a BaseTool (outermost)
#       @kest_verified  ← kest intercepts on invocation (applied first)
#       def my_func     ← the actual function body
# ---------------------------------------------------------------------------


@tool
@kest_verified(
    policy=SEARCH_POLICY,
    origin="agent",
    added_taints=["external_data"],        # mark data from outside as tainted
    context_map={"query": "search_query"}, # expose 'query' to the policy engine
)
def web_search(query: str) -> str:
    """Search the web for information about the given query."""
    ctx = otel_context.get_current()
    tip = str(baggage.get_baggage("kest.chain_tip", context=ctx) or "root")
    audit_log.append({"step": "web_search", "chain_tip": tip[:16]})
    print(f"\n  🔍 TOOL: web_search(query={query!r})")
    print(f"     ↳ chain_tip inside call: {tip[:16]}…")

    # In production this would call a real search API / browser MCP tool.
    return (
        f"[Search results for '{query}']\n"
        "1. Kest is an open-source zero-trust toolkit for multi-agent workloads.\n"
        "2. It provides cryptographically verifiable execution lineage via Merkle DAGs.\n"
        "3. OPA, Cedar, and AWS AVP are supported as policy engines.\n"
    )


@tool
@kest_verified(
    policy=SUMMARISE_POLICY,
    origin="agent",
    removed_taints=["external_data"],   # summarisation cleanses the external-data taint
)
def summarise(text: str) -> str:
    """Summarise the provided text into a compact paragraph."""
    ctx = otel_context.get_current()
    tip = str(baggage.get_baggage("kest.chain_tip", context=ctx) or "root")
    audit_log.append({"step": "summarise", "chain_tip": tip[:16]})
    print(f"\n  📝 TOOL: summarise(text[:{min(40, len(text))}]…)")
    print(f"     ↳ chain_tip inside call: {tip[:16]}…")

    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("[")]
    return " ".join(lines[:3])


# ---------------------------------------------------------------------------
# 3.  Wrap the LLM with KestChatModel
#
#     trust_override=70 marks LLM-generated content as lower-trust than
#     deterministic tool output, reflecting the probabilistic nature of
#     language model reasoning in the execution graph.
# ---------------------------------------------------------------------------

# Simulate an LLM that decides to use web_search, then synthesises results.
_FAKE_RESPONSES = [
    # Turn 1: LLM instructs the agent to search
    "I will search for 'kest zero trust toolkit' to find information.",
    # Turn 2: LLM synthesises tool output into a final answer
    "Based on the search results, Kest is a zero-trust toolkit that provides "
    "cryptographically verifiable execution lineage for multi-agent AI workloads.",
]


class _InstrumentedFakeModel(FakeListChatModel):
    """FakeListChatModel that captures the chain tip from inside kest_verified."""

    def _call(self, *args, **kwargs) -> str:  # type: ignore[override]
        ctx = otel_context.get_current()
        tip = str(baggage.get_baggage("kest.chain_tip", context=ctx) or "root")
        audit_log.append({"step": f"llm_turn_{self.i + 1}", "chain_tip": tip[:16]})
        print(f"     ↳ chain_tip inside LLM call: {tip[:16]}…")
        return super()._call(*args, **kwargs)


llm = KestChatModel(
    _InstrumentedFakeModel(responses=_FAKE_RESPONSES),
    policy=LLM_POLICY,
    trust_override=70,    # LLMs are lower-trust nodes
    origin="llm",
)

# ---------------------------------------------------------------------------
# 4.  Run the agent loop
# ---------------------------------------------------------------------------

SEPARATOR = "─" * 64


def _section(title: str):
    print(f"\n{SEPARATOR}")
    print(f"  {title}")
    print(SEPARATOR)


_section("🚀 Zero-Trust Research Agent — kest-deepagents demo")

user_message = HumanMessage(content="Tell me about the Kest zero-trust toolkit.")
print(f"\n[User] {user_message.content}")

# Step 1: LLM decides what to do
print("\n[Step 1] LLM reasoning turn 1…")
llm_decision: AIMessage = llm.invoke([user_message])
print(f"[LLM Turn 1] {llm_decision.content}")

# Step 2: Execute the search tool
print("\n[Step 2] Calling web_search tool…")
search_results = web_search.invoke({"query": "kest zero trust toolkit"})

# Step 3: Summarise via another tool
print("\n[Step 3] Calling summarise tool…")
summary = summarise.invoke({"text": search_results})

# Step 4: LLM synthesises the final answer
print("\n[Step 4] LLM reasoning turn 2 (synthesis)…")
synthesis_msg = HumanMessage(content=f"Search results:\n{summary}\nProvide a final answer.")
final_response: AIMessage = llm.invoke([synthesis_msg])

# ---------------------------------------------------------------------------
# 5.  Final output + audit log
# ---------------------------------------------------------------------------

_section("✅ Final Agent Response")
print(textwrap.fill(final_response.content, width=72))  # type: ignore[arg-type]

_section("🔗 Execution Lineage — Merkle Chain Audit Log")
print(f"  {'Step':<20} {'Chain Tip (first 16 chars)'}")
print(f"  {'─'*20} {'─'*28}")
for entry in audit_log:
    print(f"  {entry['step']:<20} {entry['chain_tip']}…")

print(
    "\n  Each step above generated a signed KestEntry added to the\n"
    "  Merkle audit passport. The chain tip is the SHA-256 of the\n"
    "  last entry's JWS — a tamper-evident DAG across the full\n"
    "  agent interaction.\n"
    "\n"
    "  Trust scores per node:\n"
    "    LLM invocations  : trust_override=70  (probabilistic, lower-trust)\n"
    "    Tool invocations : trust=100           (deterministic, fully trusted)\n"
    "\n"
    "  Taints:\n"
    "    web_search adds 'external_data' taint to the chain.\n"
    "    summarise removes 'external_data' — cleansing the taint.\n"
)
print(SEPARATOR + "\n")

# Cleanup
configure(clear=True)
invalidate_policy_cache()
