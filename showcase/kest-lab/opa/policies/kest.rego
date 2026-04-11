package kest

import future.keywords

# kest.rego
#
# OPA policy evaluated by OPAPolicyEngine (sidecar HTTP call).
# Input keys sent by the engine (from decorators.py ctx_to_eval).
# Uses spec-compliant names per SPEC-v0.3.0 §8.4, §9.2:
#   input.principal = SPIFFE ID (from get_identity())
#   input.trust_score = int (0-100 scale, from ORIGIN_TRUST_MAP)
#   input.origin    = string ("system", "internal", "internet", etc.)
#   input.chain_tip = parent entry hash
#   input.is_root   = bool
#   input.user      = human caller (from kest.user baggage, per spec §8.4)
#   input.agent     = acting agent (from kest.agent baggage, per spec §8.4)
#   input.task      = OAuth scope / task (from kest.task baggage, per spec §8.4)

default allow := false

allow if {
    valid_principal
}

# Machine-to-machine: SPIFFE identity with trust >= 50
valid_principal if {
    input.principal != ""
    input.trust_score >= 50
}

# Human-delegated: lower trust allowed when a user identity is present
valid_principal if {
    input.principal != ""
    input.trust_score >= 10
    input.user != ""
}
