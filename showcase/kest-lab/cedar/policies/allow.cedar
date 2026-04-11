// allow.cedar
//
// Base "allow" policy for hop1/hop2/hop3 app.py workload endpoints.
// Permits any request carrying a non-empty user identity with trust_score >= 10.
// This is the minimum bar for authenticated workload-to-workload calls.
//
// Evaluated by CedarLocalEngine (cedarpy, in-process, schema-less mode).
// Context keys (flat scalars, spec-compliant names per SPEC-v0.3.0 §8.4):
//   context["trust_score"]  = int (trust fraction * 100, e.g. 0.1 -> 10)
//   context["user"]         = string (Keycloak user sub / OBO subject, from kest.user baggage)

permit(principal, action, resource) when {
    10 <= context["trust_score"] &&
    context has "user" &&
    !(context["user"] == "")
};
