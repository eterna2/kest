use super::foreign::ForeignPolicyEngine;
use super::mock::MockPolicyEngine;
use super::{PolicyEngine, PolicyError};
use std::collections::HashMap;

#[test]
fn test_mock_engine() {
    let allow = MockPolicyEngine::new(true);
    let deny = MockPolicyEngine::new(false);
    let ctx = HashMap::new();

    assert!(allow.evaluate("r1", &["p1".to_string()], &ctx).unwrap());
    assert!(!deny.evaluate("r1", &["p1".to_string()], &ctx).unwrap());
}

#[test]
fn test_foreign_engine() {
    let engine = ForeignPolicyEngine::new(|entry_id, policies, ctx| {
        if entry_id == "allow_me" {
            Ok(true)
        } else if entry_id == "deny_me" {
            Ok(false)
        } else {
            Err(PolicyError::Evaluation("Foreign error".to_string()))
        }
    });

    let ctx = HashMap::new();

    assert!(engine.is_foreign());
    assert!(engine.evaluate("allow_me", &[], &ctx).unwrap());
    assert!(!engine.evaluate("deny_me", &[], &ctx).unwrap());

    match engine.evaluate("error", &[], &ctx) {
        Err(PolicyError::Evaluation(e)) => assert_eq!(e, "Foreign error"),
        _ => panic!("Expected foreign error"),
    }
}
