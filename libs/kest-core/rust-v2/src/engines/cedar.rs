use super::{PolicyEngine, PolicyError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

pub struct CedarAgentPolicyEngine {
    client: reqwest::blocking::Client,
    base_url: String,
}

#[derive(Serialize)]
struct CedarInput {
    principal: String,
    action: String,
    resource: String,
    context: HashMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct CedarResponse {
    decision: String,
}

impl CedarAgentPolicyEngine {
    pub fn new(base_url: String, timeout_ms: u64) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .unwrap_or_default();
        Self { client, base_url }
    }
}

impl PolicyEngine for CedarAgentPolicyEngine {
    fn evaluate(
        &self,
        entry_id: &str,
        policy_names: &[String],
        context: &HashMap<String, String>,
    ) -> Result<bool, PolicyError> {
        // Find principal
        let principal = context
            .get("principal")
            .cloned()
            .unwrap_or_else(|| "anonymous".to_string());

        let mut json_ctx = HashMap::new();
        for (k, v) in context {
            if k == "trust_score" {
                if let Ok(num) = v.parse::<i32>() {
                    json_ctx.insert(k.clone(), serde_json::json!(num));
                    continue;
                }
            }
            json_ctx.insert(k.clone(), serde_json::json!(v));
        }

        for policy in policy_names {
            let mut eval_context = json_ctx.clone();
            eval_context.insert("policy_name".to_string(), serde_json::json!(policy.clone()));

            let payload = CedarInput {
                principal: format!("Workload::\"{}\"", principal),
                action: "Action::\"Execute\"".to_string(),
                resource: format!("ExecutionNode::\"{}\"", entry_id),
                context: eval_context,
            };

            let url = format!("{}/v1/is_authorized", self.base_url);

            let resp = self.client.post(&url).json(&payload).send().map_err(|e| {
                PolicyError::Unreachable(format!("Failed to reach Cedar Agent at {}: {}", url, e))
            })?;

            if !resp.status().is_success() {
                return Err(PolicyError::Evaluation(format!(
                    "Cedar Agent returned status {}",
                    resp.status()
                )));
            }

            let data: CedarResponse = resp.json().map_err(|e| {
                PolicyError::Evaluation(format!("Failed to parse Cedar response: {}", e))
            })?;

            if data.decision != "Allow" {
                return Ok(false);
            }
        }

        Ok(true)
    }
}
