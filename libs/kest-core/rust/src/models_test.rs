#[cfg(test)]
mod tests {
    use crate::models::{KestEntry, KestClassification, KestMetadata};
    use std::collections::BTreeMap;

    #[test]
    fn test_kest_entry_canonical_serialization() {
        let mut otel_context = BTreeMap::new();
        otel_context.insert("trace_id".to_string(), "trace-123".to_string());
        otel_context.insert("span_id".to_string(), "span-456".to_string());

        let mut labels = BTreeMap::new();
        labels.insert("app".to_string(), "kest".to_string());
        labels.insert("env".to_string(), "prod".to_string());

        let entry = KestEntry {
            schema_version: "0.3.0".to_string(),
            runtime: crate::models::KestRuntime {
                name: "kest-rust".to_string(),
                version: "0.1.0".to_string(),
            },
            entry_id: "018e8a3a-1a3b-7000-8000-000000000001".to_string(),
            parent_ids: vec!["parent-1".to_string()],
            classification: KestClassification::System,
            operation: "node-123".to_string(),
            timestamp_ms: 1712150400000,
            input_hash: "input-hash".to_string(),
            content_hash: "content-hash".to_string(),
            environment: BTreeMap::new(),
            otel_context,
            policy_context: crate::models::PolicyContext::default(),
            labels,
            added_taints: vec!["taint-1".to_string()],
            removed_taints: vec![],
            taints: vec!["taint-1".to_string(), "taint-2".to_string()],
            trust_score: 95,
            metadata: Some(KestMetadata {
                model_profile: Some("gpt-4".to_string()),
                generation_config: None,
                system_prompt_hash: None,
                context_refs: vec![],
                confidence_score: Some(0.99),
            }),
        };

        let json = serde_json::to_string(&entry).unwrap();

        // Check alphabetical order of top-level keys
        let keys: Vec<&str> = vec![
            "added_taints",
            "classification",
            "content_hash",
            "entry_id",
            "environment",
            "input_hash",
            "labels",
            "metadata",
            "operation",
            "otel_context",
            "parent_ids",
            "policy_context",
            "removed_taints",
            "runtime",
            "schema_version",
            "taints",
            "timestamp_ms",
            "trust_score",
        ];

        for i in 0..keys.len()-1 {
            let pos_curr = json.find(&format!("\"{}\"", keys[i])).unwrap();
            let pos_next = json.find(&format!("\"{}\"", keys[i+1])).unwrap();
            assert!(pos_curr < pos_next, "Key {} should come before {}", keys[i], keys[i+1]);
        }
    }
}
