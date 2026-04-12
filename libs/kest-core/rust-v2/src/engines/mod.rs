use std::collections::HashMap;
use thiserror::Error;

pub mod opa;
pub mod cedar;
pub mod mock;
pub mod foreign;

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Evaluation error: {0}")]
    Evaluation(String),
    #[error("Engine unreachable: {0}")]
    Unreachable(String),
}

/// Represents the execution environment payload to be sent to a policy engine.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EvaluatorPayload {
    pub entry_id: String,
    pub policy_names: Vec<String>,
    pub context: HashMap<String, serde_json::Value>,
}

pub trait PolicyEngine: Send + Sync {
    /// Evaluates the policy context against the engine.
    /// Returns `true` if allowed, `false` otherwise.
    fn evaluate(
        &self,
        entry_id: &str,
        policy_names: &[String],
        context: &HashMap<String, String>,
    ) -> Result<bool, PolicyError>;

    /// Returns whether this engine holds the GIL (e.g. ForeignEngineAdapter).
    fn is_foreign(&self) -> bool {
        false
    }
}

impl PolicyEngine for Box<dyn PolicyEngine> {
    fn evaluate(&self, entry_id: &str, policy_names: &[String], context: &HashMap<String, String>) -> Result<bool, PolicyError> {
        (**self).evaluate(entry_id, policy_names, context)
    }
    fn is_foreign(&self) -> bool {
        (**self).is_foreign()
    }
}

impl<'a> PolicyEngine for &'a dyn PolicyEngine {
    fn evaluate(&self, entry_id: &str, policy_names: &[String], context: &HashMap<String, String>) -> Result<bool, PolicyError> {
        (**self).evaluate(entry_id, policy_names, context)
    }
    fn is_foreign(&self) -> bool {
        (**self).is_foreign()
    }
}

#[cfg(test)]
mod mod_test;
