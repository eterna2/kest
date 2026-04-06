package kest.advanced.goguen_meseguer

# Goguen-Meseguer: Non-interference
# High-side actions have no visibility/impact on low-side observability

default allow = false

# Allow if the action is in the same domain
allow {
    input.subject.domain == input.object.domain
}

# Allow cross-domain if explicitly permitted by non-interference mapping
allow {
    input.subject.domain != input.object.domain
    is_non_interfering
}

is_non_interfering {
    some i
    mapping := input.non_interference_mappings[i]
    mapping.from_domain == input.subject.domain
    mapping.to_domain == input.object.domain
}
