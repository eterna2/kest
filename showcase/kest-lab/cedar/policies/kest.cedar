// kest.cedar
//
// Base workload chain policy — permits any authenticated workload
// with sufficient trust score.
//
// Evaluated by CedarLocalEngine (cedarpy, in-process, schema-less mode).
// Context keys (flat scalars from CedarLocalEngine._flatten):
//   context["trust_score"] = int (trust fraction * 100, e.g. 0.6 -> 60)

permit(principal, action, resource) when {
    context["trust_score"] >= 50
};
