// Biba: Integrity

// No Read Down
permit (
    principal,
    action == Action::"read",
    resource
)
when {
    context.subject.integrity <= context.object.integrity
};

// No Write Up
permit (
    principal,
    action == Action::"write",
    resource
)
when {
    context.subject.integrity >= context.object.integrity
};
