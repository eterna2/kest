// delegation_policy.cedar
//
// Evaluated by CedarLocalEngine (cedarpy, in-process).
//
// Permits OBO (On-Behalf-Of) delegation: an agent acting on behalf of
// a human user may execute if:
//   1. A valid delegated user identity is present (principal_user from act.sub)
//   2. The agent identity is present and non-empty
//   3. Trust score is sufficient (>= 10 for internet entry point)
//
// Context keys (from CedarLocalEngine._flatten):
//   context["trust_score"]      = int (e.g. 10 = 10% for internet/hop1 entry)
//   context["principal_user"]   = original delegating user
//   context["principal_agent"]  = acting agent identity

permit(principal, action, resource) when {
    context["trust_score"] >= 10 &&
    context has "principal_user" &&
    context["principal_user"] != "" &&
    context has "principal_agent" &&
    context["principal_agent"] != ""
};
