use crate::models::KestEntry;

pub trait TrustEvaluator {
    fn calculate_trust_score(&self, entry: &KestEntry, parent_scores: &[i32]) -> i32;
    fn propagate_taints(&self, entry: &KestEntry, parent_taints: &[Vec<String>]) -> Vec<String>;
}

pub struct DefaultTrustEvaluator;

impl TrustEvaluator for DefaultTrustEvaluator {
    fn calculate_trust_score(&self, entry: &KestEntry, parent_scores: &[i32]) -> i32 {
        if parent_scores.is_empty() {
            return entry.trust_score; // Root node uses its own score
        }
        
        // Multiplicative model in integer space: (min_parent * self_score) / 100
        let min_parent = parent_scores.iter().fold(i32::MAX, |a, &b| a.min(b));
        (min_parent * entry.trust_score) / 100
    }

    fn propagate_taints(&self, entry: &KestEntry, parent_taints: &[Vec<String>]) -> Vec<String> {
        let mut accumulated: std::collections::BTreeSet<String> = parent_taints
            .iter()
            .flatten()
            .cloned()
            .collect();
        
        // Add new taints from this node
        for t in &entry.added_taints {
            accumulated.insert(t.clone());
        }
        
        // If it's a SANITIZER, it might remove taints (implementation-specific)
        // For the core, we implement the base "accumulate" logic.
        // Specialized sanitization would be in a custom TrustEvaluator.
        
        accumulated.into_iter().collect()
    }
}
