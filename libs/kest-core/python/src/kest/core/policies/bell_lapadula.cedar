// Bell-LaPadula: Confidentiality

// No Read Up
permit (
    principal,
    action == Action::"read",
    resource
)
when {
    context.subject.clearance >= context.object.classification
};

// No Write Down
permit (
    principal,
    action == Action::"write",
    resource
)
when {
    context.subject.clearance <= context.object.classification
};
