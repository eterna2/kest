use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum KestClassification {
    System,
    Data,
    Sanitizer,
    Critic,
    Snapshot,
}

// Keep old name as alias for internal backward compat during transition
pub type KestNodeType = KestClassification;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KestMetadata {
    pub model_profile: Option<String>,
    pub generation_config: Option<BTreeMap<String, serde_json::Value>>,
    pub system_prompt_hash: Option<String>,
    pub context_refs: Vec<String>,
    pub confidence_score: Option<f64>,
}

// Keep old name as alias
pub type KestCognition = KestMetadata;

/// Describes the Kest library implementation that produced this entry (F-AE-06).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KestRuntime {
    /// Library name, e.g. "kest-python"
    pub name: String,
    /// Semantic version of the library, e.g. "0.3.0"
    pub version: String,
}

/// A single policy deviation record (F-AE-13, F-PE-12).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyDeviation {
    /// Name of the deviated policy
    pub policy: String,
    /// Tier: "enterprise" | "platform" | "application"
    pub tier: String,
    /// Human-readable justification, if provided
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Identity of the approver, if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approver: Option<String>,
}

/// Policy context embedded in every KestEntry (F-AE-13).
/// All four policy lists and the deviations array MUST be present.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyContext {
    #[serde(default)]
    pub enterprise_policies: Vec<String>,
    #[serde(default)]
    pub platform_policies: Vec<String>,
    #[serde(default)]
    pub app_policies: Vec<String>,
    #[serde(default)]
    pub function_policies: Vec<String>,
    /// MUST be present; MUST be [] when no deviations are active.
    #[serde(default)]
    pub deviations: Vec<PolicyDeviation>,
}

impl Default for PolicyContext {
    fn default() -> Self {
        PolicyContext {
            enterprise_policies: vec![],
            platform_policies: vec![],
            app_policies: vec![],
            function_policies: vec![],
            deviations: vec![],
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct KestEntry {
    /// Schema version of this entry format (F-AE-05)
    pub schema_version: String,
    /// Runtime that produced this entry (F-AE-06)
    pub runtime: KestRuntime,
    pub entry_id: String,
    pub parent_ids: Vec<String>,
    pub classification: KestClassification,
    pub operation: String,
    pub timestamp_ms: u64,
    pub input_hash: String,
    pub content_hash: String,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    #[serde(default)]
    pub otel_context: BTreeMap<String, String>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub added_taints: Vec<String>,
    #[serde(default)]
    pub removed_taints: Vec<String>,
    #[serde(default)]
    pub taints: Vec<String>,
    pub trust_score: i32,
    pub metadata: Option<KestMetadata>,
    /// Policy context: tier lists + active deviations (F-AE-13)
    #[serde(default)]
    pub policy_context: PolicyContext,
}

impl serde::Serialize for KestEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        // BTreeMap ensures RFC 8785-compliant key ordering (lexicographic).
        let mut map = BTreeMap::new();

        map.insert("added_taints", serde_json::to_value(&self.added_taints).map_err(serde::ser::Error::custom)?);
        map.insert("classification", serde_json::to_value(&self.classification).map_err(serde::ser::Error::custom)?);
        map.insert("content_hash", serde_json::to_value(&self.content_hash).map_err(serde::ser::Error::custom)?);
        map.insert("entry_id", serde_json::to_value(&self.entry_id).map_err(serde::ser::Error::custom)?);
        map.insert("environment", serde_json::to_value(&self.environment).map_err(serde::ser::Error::custom)?);
        map.insert("input_hash", serde_json::to_value(&self.input_hash).map_err(serde::ser::Error::custom)?);
        map.insert("labels", serde_json::to_value(&self.labels).map_err(serde::ser::Error::custom)?);
        map.insert("metadata", serde_json::to_value(&self.metadata).map_err(serde::ser::Error::custom)?);
        map.insert("operation", serde_json::to_value(&self.operation).map_err(serde::ser::Error::custom)?);
        map.insert("otel_context", serde_json::to_value(&self.otel_context).map_err(serde::ser::Error::custom)?);
        map.insert("parent_ids", serde_json::to_value(&self.parent_ids).map_err(serde::ser::Error::custom)?);
        // New mandatory fields (SPEC-v0.3.0)
        map.insert("policy_context", serde_json::to_value(&self.policy_context).map_err(serde::ser::Error::custom)?);
        map.insert("removed_taints", serde_json::to_value(&self.removed_taints).map_err(serde::ser::Error::custom)?);
        map.insert("runtime", serde_json::to_value(&self.runtime).map_err(serde::ser::Error::custom)?);
        map.insert("schema_version", serde_json::to_value(&self.schema_version).map_err(serde::ser::Error::custom)?);
        map.insert("taints", serde_json::to_value(&self.taints).map_err(serde::ser::Error::custom)?);
        map.insert("timestamp_ms", serde_json::to_value(&self.timestamp_ms).map_err(serde::ser::Error::custom)?);
        map.insert("trust_score", serde_json::to_value(&self.trust_score).map_err(serde::ser::Error::custom)?);

        let mut ser_map = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            ser_map.serialize_entry(k, &v)?;
        }
        ser_map.end()
    }
}
