use crate::engines::{PolicyEngine, PolicyError as EngineError};
use crate::policy_cache::PolicyCache;
use crate::passport::{BaggageManager, Passport};
use crate::cache::CacheBackend;
use kest_core_rs::models::{KestEntry, KestClassification, KestRuntime, PolicyContext, KestMetadata};
use kest_core_rs::crypto::{IdentityProvider, sign_kest_entry, CryptoError};
use std::collections::{BTreeMap, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use sha2::{Sha256, Digest};

#[derive(thiserror::Error, Debug)]
pub enum PipelineError {
    #[error("Policy evaluation failed: {0}")]
    PolicyFailed(#[from] EngineError),
    #[error("Authentication/Signing failed: {0}")]
    CryptoFailed(#[from] CryptoError),
    #[error("Context error: {0}")]
    ContextError(String),
}

/// A request to execute the Kest pipeline.
pub struct PipelineRequest<'a> {
    pub classification: KestClassification,
    pub operation: String,
    pub input_hash: String,
    pub content_hash: String,
    pub environment: BTreeMap<String, String>,
    pub otel_context: BTreeMap<String, String>,
    pub labels: BTreeMap<String, String>,
    pub added_taints: Vec<String>,
    pub removed_taints: Vec<String>,
    pub metadata: Option<KestMetadata>,
    pub parent_ids: Vec<String>,
    pub function_policies: Vec<String>,
    pub enterprise_policies: Vec<String>,
    pub deviations_json: Option<String>,
    pub trust_override: Option<i32>,
    pub origin_trust_score: i32,
    pub trust_evaluator_func: Option<Box<dyn Fn(i32, Vec<i32>) -> i32 + Send + Sync + 'a>>,
    pub baggage_func: Box<dyn Fn(&str) -> Option<String> + Send + Sync + 'a>,
}

pub struct KestPipeline<'a, E: PolicyEngine + ?Sized, I: IdentityProvider + ?Sized> {
    policy_engine: &'a E,
    policy_cache: Option<&'a PolicyCache>,
    identity_provider: &'a I,
    claim_cache: Option<&'a dyn CacheBackend>,
}

impl<'a, E: PolicyEngine + ?Sized, I: IdentityProvider + ?Sized> KestPipeline<'a, E, I> {
    pub fn new(
        policy_engine: &'a E,
        identity_provider: &'a I,
    ) -> Self {
        Self {
            policy_engine,
            policy_cache: None,
            identity_provider,
            claim_cache: None,
        }
    }

    pub fn with_policy_cache(mut self, cache: &'a PolicyCache) -> Self {
        self.policy_cache = Some(cache);
        self
    }

    pub fn with_claim_cache(mut self, cache: &'a dyn CacheBackend) -> Self {
        self.claim_cache = Some(cache);
        self
    }

    pub fn execute(&self, req: PipelineRequest) -> Result<(HashMap<String, String>, String), PipelineError> {
        let parent_passport = BaggageManager::unpack(|k| (req.baggage_func)(k), self.claim_cache)
            .unwrap_or_else(|_| Passport::new());
        
        let mut resolved_parent_ids = req.parent_ids.clone();
        if resolved_parent_ids.is_empty() && !parent_passport.entries.is_empty() {
            if let Some(last_sig) = parent_passport.entries.last() {
                let mut hasher = Sha256::new();
                hasher.update(last_sig.as_bytes());
                resolved_parent_ids.push(hex::encode(hasher.finalize()));
            }
        }
        if resolved_parent_ids.is_empty() {
            resolved_parent_ids.push("0".to_string()); // root
        }

        let (parent_scores, parent_taints) = parent_passport.get_parent_scores_and_taints();

        let mut merged_taints = parent_taints;
        for t in &req.added_taints {
            merged_taints.insert(t.clone());
        }
        for t in &req.removed_taints {
            merged_taints.remove(t);
        }
        let mut final_taints: Vec<String> = merged_taints.into_iter().collect();
        final_taints.sort();
        
        let trust_score = if let Some(override_score) = req.trust_override {
            override_score
        } else {
             if let Some(ref eval) = req.trust_evaluator_func {
                 eval(req.origin_trust_score, parent_scores.clone())
             } else if parent_scores.is_empty() {
                 req.origin_trust_score
             } else {
                 let min_parent = parent_scores.iter().min().unwrap_or(&100);
                 (min_parent * req.origin_trust_score) / 100
             }
        };

        // 2. Construct Entry
        let mut labels = req.labels.clone();
        if let Some(user) = (req.baggage_func)("kest.user") {
             if let Some(agent) = (req.baggage_func)("kest.agent") {
                 labels.insert("kest.identity".to_string(), format!("{{\"user\":\"{}\",\"agent\":\"{}\"}}", user, agent));
             } else {
                 labels.insert("kest.identity".to_string(), format!("{{\"user\":\"{}\",\"agent\":\"\"}}", user));
             }
        } else if let Some(agent) = (req.baggage_func)("kest.agent") {
             labels.insert("kest.identity".to_string(), format!("{{\"user\":\"\",\"agent\":\"{}\"}}", agent));
        }

        let entry = KestEntry {
            schema_version: "0.3.0".to_string(),
            runtime: KestRuntime {
                name: "kest-runtime-rs".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            entry_id: Uuid::now_v7().to_string(),
            parent_ids: resolved_parent_ids.clone(),
            classification: req.classification.clone(),
            operation: req.operation.clone(),
            timestamp_ms: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
            input_hash: req.input_hash,
            content_hash: req.content_hash,
            environment: req.environment,
            otel_context: req.otel_context,
            labels,
            added_taints: req.added_taints,
            removed_taints: req.removed_taints,
            taints: final_taints.clone(),
            trust_score,
            metadata: req.metadata,
            policy_context: PolicyContext {
                enterprise_policies: req.enterprise_policies,
                platform_policies: vec![],
                app_policies: vec![],
                function_policies: req.function_policies,
                deviations: req.deviations_json.as_deref().map(|s| serde_json::from_str(s).unwrap_or_default()).unwrap_or_default(),
            },
        };

        // 3. Evaluate Policy (checking cache first if available)
        let cache_key = format!("{:?}:{}:{:?}", req.classification, req.operation, final_taints);
        
        let mut policy_ok = false;
        if let Some(cache) = self.policy_cache {
            if let Some(res) = cache.get(&cache_key) {
                policy_ok = res;
            }
        }

        if !policy_ok {
            let mut policy_names = Vec::new();
            policy_names.extend(entry.policy_context.enterprise_policies.clone());
            policy_names.extend(entry.policy_context.platform_policies.clone());
            policy_names.extend(entry.policy_context.app_policies.clone());
            policy_names.extend(entry.policy_context.function_policies.clone());

            let mut context_map = HashMap::new();
            for (k, v) in &entry.environment {
                context_map.insert(k.clone(), v.clone());
            }
            for (k, v) in &entry.otel_context {
                context_map.insert(k.clone(), v.clone());
            }
            if let Some(user) = (req.baggage_func)("kest.user") { context_map.insert("user".into(), user); }
            if let Some(agent) = (req.baggage_func)("kest.agent") { context_map.insert("agent".into(), agent); }
            if let Some(task) = (req.baggage_func)("kest.task") { context_map.insert("task".into(), task); }
            if let Some(scope) = (req.baggage_func)("kest.scope") { context_map.insert("scope".into(), scope); }
            context_map.insert("trust_score".into(), trust_score.to_string());
            context_map.insert("chain_tip".into(), resolved_parent_ids.join(","));
            context_map.insert("is_root".into(), parent_scores.is_empty().to_string());

            let policy_result = self.policy_engine.evaluate(
                &entry.entry_id,
                &policy_names,
                &context_map,
            ).map_err(PipelineError::PolicyFailed)?;
            
            if policy_result {
                // Handled successfully, continue iteration
                // Cache the success
                if let Some(cache) = self.policy_cache {
                    cache.insert(cache_key, true);
                }
            } else {
                return Err(PipelineError::PolicyFailed(EngineError::Evaluation("Policy denied".into())));
            }
        }

        // 4. Sign
        let signature = sign_kest_entry(&entry, self.identity_provider)?;

        // 5. Append to passport
        let mut new_passport = parent_passport;
        new_passport.entries.push(signature.clone());

        // 6. Pack baggage 
        let baggage_map = BaggageManager::pack(&new_passport, self.claim_cache);

        Ok((baggage_map, signature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestIdProvider;
    impl IdentityProvider for TestIdProvider {
        fn verify_svid(&self, _svid: &str) -> Result<String, CryptoError> {
            Ok("test-identity".to_string())
        }
        fn sign_payload(&self, _payload: &[u8]) -> Result<String, CryptoError> {
            Ok("mock-signature".to_string())
        }
    }

    struct TestPolicyEngine {
        allow: bool,
    }
    impl PolicyEngine for TestPolicyEngine {
        fn evaluate(&self, _entry_id: &str, _policy_names: &[String], _context: &HashMap<String, String>) -> Result<bool, EngineError> {
            if self.allow {
                Ok(true)
            } else {
                Err(EngineError::Evaluation("denied by test".into()))
            }
        }
    }

    #[test]
    fn test_pipeline_execution_allow() {
        let engine = TestPolicyEngine { allow: true };
        let id_provider = TestIdProvider;
        let pipeline = KestPipeline::new(&engine, &id_provider);

        let req = PipelineRequest {
            classification: KestClassification::Data,
            operation: "test-op".to_string(),
            input_hash: "hash1".to_string(),
            content_hash: "hash2".to_string(),
            environment: BTreeMap::new(),
            otel_context: BTreeMap::new(),
            labels: BTreeMap::new(),
            added_taints: vec!["foo".to_string()],
            removed_taints: vec![],
            metadata: None,
            parent_ids: vec![],
            function_policies: vec![],
            enterprise_policies: vec![],
            deviations_json: None,
            trust_override: None,
            origin_trust_score: 100,
            baggage_func: Box::new(|_| None),
        };

        let result = pipeline.execute(req);
        assert!(result.is_ok());
        let (baggage, sig) = result.unwrap();
        
        assert!(baggage.contains_key("kest.passport") || baggage.contains_key(crate::passport::COMPRESS_KEY));
        assert!(sig.contains("mock-signature"));
    }

    #[test]
    fn test_pipeline_execution_deny() {
        let engine = TestPolicyEngine { allow: false };
        let id_provider = TestIdProvider;
        let pipeline = KestPipeline::new(&engine, &id_provider);

        let req = PipelineRequest {
            classification: KestClassification::Data,
            operation: "test-op".to_string(),
            input_hash: "hash1".to_string(),
            content_hash: "hash2".to_string(),
            environment: BTreeMap::new(),
            otel_context: BTreeMap::new(),
            labels: BTreeMap::new(),
            added_taints: vec!["foo".to_string()],
            removed_taints: vec![],
            metadata: None,
            parent_ids: vec![],
            function_policies: vec![],
            enterprise_policies: vec![],
            deviations_json: None,
            trust_override: None,
            origin_trust_score: 100,
            baggage_func: Box::new(|_| None),
        };

        let result = pipeline.execute(req);
        assert!(result.is_err());
        match result.unwrap_err() {
            PipelineError::PolicyFailed(EngineError::Evaluation(msg)) => {
                assert_eq!(msg, "denied by test");
            },
            _ => panic!("Expected policy failure"),
        }
    }

    #[test]
    fn test_pipeline_with_caching() {
        let engine = TestPolicyEngine { allow: true };
        let id_provider = TestIdProvider;
        let cache = PolicyCache::new(std::time::Duration::from_secs(10), 10);
        let pipeline = KestPipeline::new(&engine, &id_provider).with_policy_cache(&cache);

        let req = PipelineRequest {
            classification: KestClassification::Data,
            operation: "test-op".to_string(),
            input_hash: "hash1".to_string(),
            content_hash: "hash2".to_string(),
            environment: BTreeMap::new(),
            otel_context: BTreeMap::new(),
            labels: BTreeMap::new(),
            added_taints: vec![],
            removed_taints: vec![],
            metadata: None,
            parent_ids: vec![],
            function_policies: vec![],
            enterprise_policies: vec![],
            deviations_json: None,
            trust_override: None,
            origin_trust_score: 100,
            baggage_func: Box::new(|_| None),
        };

        assert!(pipeline.execute(req).is_ok());

        let cache_key = format!("{:?}:{}:{:?}", KestClassification::Data, "test-op", Vec::<String>::new());
        assert_eq!(cache.get(&cache_key), Some(true));
    }
}

