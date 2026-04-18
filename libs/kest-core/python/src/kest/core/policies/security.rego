package kest.security

default allow = false

# Minimum trust score
allow {
    input.trust_score >= 80
}

# Geofence
deny {
    input.country == "restricted_country"
}

# Require admin for config changes
allow {
    input.action == "config_change"
    input.role == "admin"
}
