package kest

import future.keywords

# kest.rego
#
# OPA policy evaluated by OPAPolicyEngine (sidecar HTTP call).
# Input keys sent by the engine (from decorators.py ctx_to_eval):
#   input.principal       = SPIFFE ID (from get_identity())
#   input.trust_score     = int (trust fraction * 100)
#   input.origin          = string ("system", "internal", "internet", etc.)
#   input.chain_tip       = parent entry hash
#   input.is_root         = bool
#   input.principal_user  = human caller (from kest.principal_user baggage)
#   input.principal_agent = acting agent (from kest.principal_agent baggage)
#   input.principal_scope = OAuth scope (from kest.principal_scope baggage)

default allow := false

allow if {
    valid_principal
}

valid_principal if {
    input.principal != ""
    input.trust_score >= 50
}

valid_principal if {
    input.principal != ""
    input.trust_score >= 10
    input.principal_user != ""
}
