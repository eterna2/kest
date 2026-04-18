package kest.advanced.clark_wilson

# Clark-Wilson: Operational Integrity
# Subject-Program-Object Triples

default allow = false

# Check if the execution path is a certified triple
allow {
    some i
    triple := input.certified_triples[i]
    triple.subject == input.subject.id
    triple.program == input.program.id
    triple.object == input.object.id
}
