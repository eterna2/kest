use super::{EvaluatorPayload, PolicyEngine, PolicyError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

pub struct OpaPolicyEngine {
    client: reqwest::blocking::Client,
    base_url: String,
}

#[derive(Serialize)]
struct OpaInput {
    input: EvaluatorPayload,
}

#[derive(Deserialize)]
struct OpaResponse {
    result: Option<bool>,
}

impl OpaPolicyEngine {
    pub fn new(base_url: String, timeout_ms: u64) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .unwrap_or_default();
        Self { client, base_url }
    }
}

impl PolicyEngine for OpaPolicyEngine {
    fn evaluate(
        &self,
        entry_id: &str,
        policy_names: &[String],
        context: &HashMap<String, String>,
    ) -> Result<bool, PolicyError> {
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

        let payload = OpaInput {
            input: EvaluatorPayload {
                entry_id: entry_id.to_string(),
                policy_names: policy_names.to_vec(),
                context: json_ctx,
            },
        };

        for policy in policy_names {
            // OPA convention: POST /v1/data/<policy_path>
            // Replace dots with slashes
            let path = policy.replace('.', "/");
            let url = format!("{}/v1/data/{}", self.base_url, path);

            let resp = self.client.post(&url).json(&payload).send().map_err(|e| {
                PolicyError::Unreachable(format!("Failed to reach OPA at {}: {}", url, e))
            })?;

            if !resp.status().is_success() {
                return Err(PolicyError::Evaluation(format!(
                    "OPA returned status {}",
                    resp.status()
                )));
            }

            let data: OpaResponse = resp.json().map_err(|e| {
                PolicyError::Evaluation(format!("Failed to parse OPA response: {}", e))
            })?;

            if !data.result.unwrap_or(false) {
                return Ok(false); // Any policy fail = entire evaluation fails
            }
        }

        Ok(true)
    }
}
