package kest.advanced.bell_lapadula

# Bell-LaPadula: Confidentiality
# No Read Up, No Write Down

default allow = false

allow {
    input.action == "read"
    input.subject.clearance >= input.object.classification # No Read Up
}

allow {
    input.action == "write"
    input.subject.clearance <= input.object.classification # No Write Down
}
