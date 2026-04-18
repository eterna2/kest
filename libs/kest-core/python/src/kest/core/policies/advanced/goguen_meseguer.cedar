// Goguen-Meseguer: Non-interference

// Allow same domain
permit (
    principal,
    action,
    resource
)
when {
    context.subject.domain == context.object.domain
};

// Allow cross-domain ONLY if explicitly declared non-interfering
permit (
    principal,
    action,
    resource
)
when {
    context.subject.domain != context.object.domain &&
    context.is_non_interfering == true
};
