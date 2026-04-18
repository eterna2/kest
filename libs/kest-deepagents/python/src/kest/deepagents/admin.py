class KestAdminSubagent:
    """Built-in reusable agent for querying traces and explaining policies."""

    def __init__(self, trace_backend):
        self.trace_backend = trace_backend

    def parse_policy_decisions(self, spans: list[dict]) -> list[str]:
        """Extracts policy names and results from a list of trace spans"""
        decisions = []
        for span in spans:
            attrs = span.get("attributes", {})
            if "kest.policy.name" in attrs:
                decisions.append(attrs["kest.policy.name"])
        return decisions

    def explain_limits(self, trace_id: str) -> str:
        """Looks up a trace and explains the access limits hit"""
        trace = self.trace_backend.get_trace(trace_id)
        if not trace:
            return f"Trace {trace_id} not found."

        spans = trace.get("spans", [])
        decisions = []
        for span in spans:
            attrs = span.get("attributes", {})
            if "kest.policy.name" in attrs:
                pol = attrs["kest.policy.name"]
                res = attrs.get("kest.result", "UNKNOWN")
                decisions.append(f"Policy '{pol}' evaluated to {res}.")

        if not decisions:
            return "No Kest policy limitations found in trace."

        return "Execution limits hit:\n" + "\n".join(decisions)
