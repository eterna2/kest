// task_policy.cedar
//
// Evaluated by CedarLocalEngine (cedarpy, in-process) on kest-gateway /execute-task.
//
// Permits execution of a gateway-minted narrow-scope task token.
// Only tasks carrying the exact scope "task:process-data" are permitted.
// This prevents task tokens from being re-used for other policy-protected endpoints.
//
// Context keys:
//   context["trust_score"]      = int  (>=50 required — internal workload origin)
//   context["principal_scope"]  = exact task scope minted by the gateway
//                                 must be "task:process-data"

permit(principal, action, resource) when {
    context["trust_score"] >= 50 &&
    context has "principal_scope" &&
    context["principal_scope"] == "task:process-data"
};
