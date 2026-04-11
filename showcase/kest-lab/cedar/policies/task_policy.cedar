// task_policy.cedar
//
// Evaluated by CedarLocalEngine (cedarpy, in-process) on kest-gateway /execute-task.
//
// Permits execution of a gateway-minted narrow-scope task token.
// Only tasks carrying the exact scope "task:process-data" are permitted.
// This prevents task tokens from being re-used for other policy-protected endpoints.
//
// Context keys (spec-compliant names per SPEC-v0.3.0 §8.4):
//   context["trust_score"] = int  (>= 50 required — internal workload origin)
//   context["task"]        = exact task scope minted by the gateway
//                            must be "task:process-data"
//                            (from kest.task baggage, which carries the OAuth scope)

permit(principal, action, resource) when {
    context["trust_score"] >= 50 &&
    context has "task" &&
    context["task"] == "task:process-data"
};
