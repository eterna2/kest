// workload_user_policy.cedar
//
// Evaluated by CedarLocalEngine (cedarpy, in-process).
//
// Context keys provided by CedarLocalEngine._flatten (all scalar):
//   context["principal"]       = SPIFFE ID string
//   context["trust_score"]     = int (trust fraction * 100, e.g. 0.6 -> 60)
//   context["principal_user"]  = human caller (kest.principal_user baggage)
//   context["principal_agent"] = acting agent if OBO (kest.principal_agent baggage)
//   context["principal_roles"] = JSON roles string (kest.principal_roles baggage)
//   context["principal_scope"] = OAuth scope (kest.principal_scope baggage)
//
// Trust score mapping (ORIGIN_TRUST_MAP * 100):
//   system/internal  = 100    (fully trusted internal call)
//   third_party_api  = 60
//   user_input       = 40
//   internet         = 10     (Keycloak-authenticated user at hop1 entry)
//
// This policy permits any request with an authenticated user identity.
// trust_score >= 10 covers the internet entry point (hop1), while internal
// hops (hop2, hop3) benefit from the base kest.cedar policy (>= 50).

permit(principal, action, resource) when {
    context["trust_score"] >= 10 &&
    context has "principal_user" &&
    context["principal_user"] != ""
};
