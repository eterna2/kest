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
// Context keys (spec-compliant names per SPEC-v0.3.0 §8.4):
//   context["trust_score"] = int  (10 for internet entry, 100 for internal)
//   context["user"]        = original delegating user (alice), from kest.user baggage
//   context["agent"]       = acting agent identity (kest-agent), from kest.agent baggage
//   context["scope"]       = raw OAuth scope string from OBO token (impl extension via kest.scope)
//                            e.g. "openid profile roles read:data write:data"
//   context["task"]        = same as scope (spec alias, from kest.task baggage)

// Permit if all conditions met: trust, user, agent, and required scope.
permit(principal, action, resource) when {
    context["trust_score"] >= 10 &&
    context has "user" &&
    context["user"] != "" &&
    context has "agent" &&
    context["agent"] != "" &&
    context has "scope" &&
    context["scope"] like "*read:data*"
};
