# Testing Rules for Kest

These rules govern the development and validation of all core toolkit components.

## 1. Test-Driven Development (TDD)
- **Always** write failing tests before implementing the logic.
- Ensure that the tests cover both the "happy path" and potential edge cases.

## 2. Mandatory Verification
- **Every** code change MUST pass all verification steps before being committed or marked as complete.
- Use the `@verify` workflow as the official sign-off mechanism.

## 3. Test Categories
### Unit Tests (Local)
- **Scope**: Pure logic, models, and cryptographic functions.
- **Command**: `moon run kest-core-python:test`

### Live Integration Tests (Lab)
- **Scope**: Real network/container components and PID-based attestation.
- **Command**: `moon run kest-core-python:test-live`

## 4. Policy for Failure
- Engines should follow a **Fail-Secure** model (default to DENY on errors).
- Tests must explicitly verify this behavior.
