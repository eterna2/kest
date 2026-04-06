// gateway_policy.cedar
//
// Evaluated by CedarLocalEngine (cedarpy, in-process) on kest-gateway /authorise.
//
// Permits the gateway to authorise an OBO delegation when:
//   1. A valid delegated user is present (from act.sub via KestIdentityMiddleware)
//   2. A valid acting agent is present (from sub)
//   3. Trust score >= 10 (OBO token from internet-originated flow)
//   4. The delegated scopes include "read:data" (minimum required scope)
//
// Context keys (from CedarLocalEngine._flatten):
//   context["trust_score"]      = int  (10 for internet entry, 100 for internal)
//   context["principal_user"]   = original delegating user (alice)
//   context["principal_agent"]  = acting agent identity (kest-agent)
//   context["principal_scope"]  = OAuth scope string from OBO token
//                                 (e.g. "openid profile roles read:data write:data")

// Permit if all conditions met: trust, user, agent, and required scope.
permit(principal, action, resource) when {
    context["trust_score"] >= 10 &&
    context has "principal_user" &&
    context["principal_user"] != "" &&
    context has "principal_agent" &&
    context["principal_agent"] != "" &&
    context has "principal_scope" &&
    context["principal_scope"] like "*read:data*"
};
