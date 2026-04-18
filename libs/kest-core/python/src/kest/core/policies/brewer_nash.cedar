// Brewer-Nash: Conflict of Interest (Chinese Wall)

// 1. Allow if data is public (no conflict class)
permit (
    principal,
    action,
    resource
)
when {
    !(context.object has conflict_class)
};

// 2. Allow if no history in this conflict class
permit (
    principal,
    action,
    resource
)
when {
    (context.object has conflict_class) &&
    context.subject.history_in_conflict_class == 0
};

// 3. Allow if history in this class matches the requested company exactly
permit (
    principal,
    action,
    resource
)
when {
    (context.object has conflict_class) &&
    context.subject.history_in_conflict_class > 0 &&
    context.subject.accessed_company_id == context.object.company_id
};
