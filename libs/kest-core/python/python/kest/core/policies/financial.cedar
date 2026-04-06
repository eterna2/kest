// Allow transfers under 1000
permit (
    principal,
    action == Action::"transfer",
    resource
)
when {
    context.amount <= 1000
};

// Allow withdrawals only with MFA
permit (
    principal,
    action == Action::"withdrawal",
    resource
)
when {
    context.mfa_present == true
};

// Forbid high risk (overrides permits)
forbid (
    principal,
    action,
    resource
)
when {
    context.risk_score == "high"
};
