package kest.advanced.brewer_nash

# Brewer-Nash: Conflict of Interest (Chinese Wall)
# An agent cannot access data from competitor A if it has already accessed competitor B

default allow = false

# Allow access if the object is in the same conflict class as previously accessed objects,
# OR if the agent has not accessed any objects in this conflict class yet.
allow {
    # If the object belongs to a conflict class...
    input.object.conflict_class
    
    # Check if the subject's history allows access
    is_safe_access
}

# Allow if the object doesn't belong to any conflict class (public data)
allow {
    not input.object.conflict_class
}

is_safe_access {
    # Find what the subject has accessed in this conflict class
    accessed_in_class := [x | x := input.subject.history[_]; x.conflict_class == input.object.conflict_class]
    
    # If none accessed in this class, it's safe
    count(accessed_in_class) == 0
}

is_safe_access {
    # If accessed something in this class, it MUST be the exact same company/dataset
    accessed_in_class := [x | x := input.subject.history[_]; x.conflict_class == input.object.conflict_class]
    count(accessed_in_class) > 0
    
    all_same := [x | x := accessed_in_class[_]; x.company_id == input.object.company_id]
    count(all_same) == count(accessed_in_class)
}
