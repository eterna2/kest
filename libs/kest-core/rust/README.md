# Kest Core (Rust)

The primary cryptographic and data foundation for the Kest Zero Trust toolkit. This crate provides a side-effect-free, WebAssembly-compatible implementation of the Kest execution graph, passport structures, and trust evaluation logic.

## 🚀 Key Features

- **Deterministic Canonicalization**: Strict implementation of **RFC 8785 (JSON Canonicalization Scheme)** via `serde_jcs`, ensuring consistent hashing across polyglot environments.
- **Structural Integrity**: Hardened `KestEntry` structures with manual serialization to enforce alphabetical field ordering for cryptographic consistency.
- **Cryptographic Support**: Abstract traits for `IdentityProvider` and `PolicyEngine`, with built-in JWS (JSON Web Signature) signing helpers.
- **Trust Evaluation**: Pessimistic trust aggregation and taint propagation during execution graph traversal.
- **Wasm Ready**: Compiled for `wasm32-unknown-unknown`, making it suitable for browsers and edge environments.

## 🛠 Usage

### Common Commands
All tasks are orchestrated via `moon`:
- **Build**: `moon run kest-core-rs:check`
- **Unit Tests**: `moon run kest-core-rs:test`
- **Wasm Tests**: `moon run kest-core-rs:wasm-test`

## 🏗 Architecture

The crate is designed as a **Side-Effect-Free** library. All external integrations are injected via traits:
- **`IdentityProvider`**: Handles SVID verification and payload signing.
- **`PolicyEngine`**: Evaluates policies against the execution context.
- **`TrustEvaluator`**: Merges trust scores and manages taint propagation.

For detailed developer and AI agent interaction guidelines, refer to [README.agent.md](./README.agent.md).

## 📊 Data Structures & Interfaces

### Core Models

#### `KestEntry`
The primary unit of the execution graph.
```rust
pub struct KestEntry {
    pub entry_id: String,           // Unique identifier (UUID v7)
    pub parent_entry_ids: Vec<String>,
    pub node_type: KestNodeType,
    pub node_id: String,
    pub timestamp_ms: u64,
    pub input_state_hash: String,
    pub content_hash: String,
    pub environment: BTreeMap<String, String>,
    pub otel_context: BTreeMap<String, String>,
    pub labels: BTreeMap<String, String>,
    pub added_taint: Vec<String>,
    pub accumulated_taint: Vec<String>,
    pub trust_score: f64,
    pub cognition: Option<KestCognition>,
}
```

#### `KestCognition`
Metadata for AI-generated nodes.
```rust
pub struct KestCognition {
    pub model_profile: Option<String>,
    pub generation_config: Option<BTreeMap<String, serde_json::Value>>,
    pub system_prompt_hash: Option<String>,
    pub context_refs: Vec<String>,
    pub confidence_score: Option<f64>,
}
```

### Primary Traits

#### `IdentityProvider`
Handles cryptographic identity and signing.
```rust
pub trait IdentityProvider {
    fn verify_svid(&self, svid: &str) -> Result<String, CryptoError>;
    fn sign_payload(&self, payload: &[u8]) -> Result<String, CryptoError>;
}
```

#### `PolicyEngine`
Evaluates business logic and security policies.
```rust
pub trait PolicyEngine {
    fn evaluate(&self, entry: &KestEntry) -> Result<PolicyResult, PolicyError>;
}
```

#### `TrustEvaluator`
Manages trust propagation across the graph.
```rust
pub trait TrustEvaluator {
    fn calculate_trust_score(&self, entry: &KestEntry, parent_scores: &[f64]) -> f64;
    fn propagate_taints(&self, entry: &KestEntry, parent_taints: &[Vec<String>]) -> Vec<String>;
}
```

## 📜 Standards Compliance
- **RFC 8785**: JSON Canonicalization Scheme.
- **JWS**: JSON Web Signature (Compact Serialization).
- **SPIFFE**: SVID verification interfaces.
