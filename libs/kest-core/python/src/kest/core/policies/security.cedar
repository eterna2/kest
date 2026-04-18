// Minimum trust score
permit (
    principal,
    action,
    resource
)
when {
    context.trust_score >= 80
};

// Geofencing
forbid (
    principal,
    action,
    resource
)
when {
    context.country == "restricted_country"
};

// Admin only for config changes
permit (
    principal,
    action == Action::"config_change",
    resource
)
when {
    context.role == "admin"
};
