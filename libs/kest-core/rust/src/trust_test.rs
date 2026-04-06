#[cfg(test)]
mod tests {
    use crate::trust::{TrustEvaluator, DefaultTrustEvaluator};
    use crate::models::KestEntry;
    use std::collections::BTreeMap;

    fn mock_entry(trust_score: i32) -> KestEntry {
        KestEntry {
            entry_id: "id".to_string(),
            parent_ids: vec![],
            classification: crate::models::KestClassification::System,
            operation: "node".to_string(),
            timestamp_ms: 0,
            input_hash: "hash".to_string(),
            content_hash: "hash".to_string(),
            environment: BTreeMap::new(),
            otel_context: BTreeMap::new(),
            labels: BTreeMap::new(),
            added_taints: vec![],
            removed_taints: vec![],
            taints: vec![],
            trust_score,
            metadata: None,
        }
    }

    #[test]
    fn test_trust_fan_in_merging() {
        let evaluator = DefaultTrustEvaluator;
        let entry = mock_entry(90); // Self score
        
        // Multiplicative: (min(80, 70, 95) * 90) / 100 = (70 * 90) / 100 = 6300 / 100 = 63
        let parent_scores = vec![80, 70, 95];
        let score = evaluator.calculate_trust_score(&entry, &parent_scores);
        
        assert_eq!(score, 63);
    }

    #[test]
    fn test_taint_propagation() {
        let evaluator = DefaultTrustEvaluator;
        let mut entry = mock_entry(100);
        entry.added_taints = vec!["taint-C".to_string()];
        
        let parent_taints = vec![
            vec!["taint-A".to_string()],
            vec!["taint-B".to_string(), "taint-A".to_string()],
        ];
        
        let propagated = evaluator.propagate_taints(&entry, &parent_taints);
        
        // Should include A, B, and C (no duplicates, sorted)
        assert_eq!(propagated, vec!["taint-A", "taint-B", "taint-C"]);
    }
}
