// Clark-Wilson: Operational Integrity

// Ensure the request matches a certified triple
permit (
    principal,
    action,
    resource
)
when {
    context.is_certified_triple == true
};
