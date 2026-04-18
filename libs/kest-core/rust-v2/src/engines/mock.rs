use super::{PolicyEngine, PolicyError};
use std::collections::HashMap;

pub struct MockPolicyEngine {
    allow_all: bool,
}

impl MockPolicyEngine {
    pub fn new(allow_all: bool) -> Self {
        Self { allow_all }
    }
}

impl PolicyEngine for MockPolicyEngine {
    fn evaluate(
        &self,
        _entry_id: &str,
        _policy_names: &[String],
        _context: &HashMap<String, String>,
    ) -> Result<bool, PolicyError> {
        Ok(self.allow_all)
    }
}
