// delegation_policy.cedar
//
// Evaluated by CedarLocalEngine (cedarpy, in-process).
//
// Permits OBO (On-Behalf-Of) delegation: an agent acting on behalf of
// a human user may execute if:
//   1. A valid delegated user identity is present (from act.sub via kest.user)
//   2. The agent identity is present and non-empty (from kest.agent)
//   3. Trust score is sufficient (>= 10 for internet entry point)
//
// Context keys (spec-compliant names per SPEC-v0.3.0 §8.4):
//   context["trust_score"] = int (e.g. 10 = 10% for internet/hop1 entry)
//   context["user"]        = original delegating user, from kest.user baggage
//   context["agent"]       = acting agent identity, from kest.agent baggage

permit(principal, action, resource) when {
    context["trust_score"] >= 10 &&
    context has "user" &&
    context["user"] != "" &&
    context has "agent" &&
    context["agent"] != ""
};
