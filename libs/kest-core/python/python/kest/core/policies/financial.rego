package kest.financial

default allow = false

# Allow transaction if amount <= 1000
allow {
    input.action == "transfer"
    input.amount <= 1000
}

# Require MFA for withdrawals
allow {
    input.action == "withdrawal"
    input.mfa_present == true
}

# Block high risk
deny {
    input.risk_score == "high"
}
