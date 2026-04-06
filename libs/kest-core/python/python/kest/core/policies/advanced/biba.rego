package kest.advanced.biba

# Biba: Integrity
# No Read Down, No Write Up

default allow = false

allow {
    input.action == "read"
    input.subject.integrity <= input.object.integrity # No Read Down
}

allow {
    input.action == "write"
    input.subject.integrity >= input.object.integrity # No Write Up
}
