use crate::models::KestEntry;
use thiserror::Error;
use base64::Engine;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    #[error("Key format error: {0}")]
    KeyFormatError(String),
}

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Policy evaluation failed: {0}")]
    EvaluationFailed(String),
    #[error("Invalid policy context: {0}")]
    InvalidContext(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyDecision {
    Allow,
    Deny(String),
    Uncertain,
}

#[derive(Debug, Clone)]
pub struct PolicyResult {
    pub decision: PolicyDecision,
    pub taints: Vec<String>,
    pub labels: std::collections::BTreeMap<String, String>,
}

pub trait IdentityProvider {
    fn verify_svid(&self, svid: &str) -> Result<String, CryptoError>;
    fn sign_payload(&self, payload: &[u8]) -> Result<String, CryptoError>;
}

pub trait PolicyEngine {
    fn evaluate(&self, entry: &KestEntry) -> Result<PolicyResult, PolicyError>;
}

pub fn sign_kest_entry(
    entry: &KestEntry,
    provider: &impl IdentityProvider,
) -> Result<String, CryptoError> {
    let json_val = serde_json::to_value(entry).map_err(|e| CryptoError::SigningFailed(e.to_string()))?;
    let canonical_json = crate::canonical::to_canonical_string(&json_val)
        .map_err(|e| CryptoError::SigningFailed(e))?;
    
    // For a real JWS, we would need to encode the header as well.
    // Here we focus on the core requirement: sign the canonical JSON.
    // In a compact JWS: header.payload.signature
    // Let's assume a simple EdDSA header: {"alg":"EdDSA","typ":"JWS"}
    let header = serde_json::json!({"alg":"EdDSA","typ":"JWS"});
    let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json_canonicalizer::to_vec(&header).unwrap());
    
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(canonical_json);
    
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature = provider.sign_payload(signing_input.as_bytes())?;
    
    Ok(format!("{}.{}", signing_input, signature))
}
