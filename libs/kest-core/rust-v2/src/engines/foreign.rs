use super::{PolicyEngine, PolicyError};
use std::collections::HashMap;

/// A policy engine that delegates evaluation to a foreign language (e.g., Python)
/// via a callback function.
pub struct ForeignPolicyEngine {
    callback: Box<
        dyn Fn(&str, &[String], &HashMap<String, String>) -> Result<bool, PolicyError>
            + Send
            + Sync,
    >,
}

impl ForeignPolicyEngine {
    pub fn new<F>(callback: F) -> Self
    where
        F: Fn(&str, &[String], &HashMap<String, String>) -> Result<bool, PolicyError>
            + Send
            + Sync
            + 'static,
    {
        Self {
            callback: Box::new(callback),
        }
    }
}

impl PolicyEngine for ForeignPolicyEngine {
    fn evaluate(
        &self,
        entry_id: &str,
        policy_names: &[String],
        context: &HashMap<String, String>,
    ) -> Result<bool, PolicyError> {
        (self.callback)(entry_id, policy_names, context)
    }

    fn is_foreign(&self) -> bool {
        true
    }
}
