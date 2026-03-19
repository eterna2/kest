# Kest (Key + Trust)

## Design & Implementation Specification v0.3.0

**Kest** is a distributed framework for **Attested Data Lineage**. It ensures that in a complex ecosystem of autonomous AI agents, every data point carries a "Passport"—a cryptographically signed, non-linear history (DAG) that proves provenance, system-path integrity, risk posture, and **Cognitive Lineage** (the reasoning, context, and configurations used by AI to generate the data).

As Kest evolves to v0.3.0, the framework transitions into a **platform-agnostic** architecture built on **open standards**, enabling seamless local testing for developers while scaling to highly secure, distributed production environments.

---

## 1. Core Principles

- **Identity-First Execution:** No system may modify data without a verified identity. (e.g., SPIFFE/SPIRE for production, predictable dummy identities for local testing).
- **Pessimistic Data Flow:** Trust is a decaying resource. Taints are infectious; Guarantees are consensus-based. Any uncertainty in the lineage downgrades trust.
- **Mathematical Non-Repudiation:** Every step in the DAG is bound by a Merkle-hash chain, securely signed at every transition using standard formats.
- **Sanitization Paths:** Taints are "sticky" but can be cleared through formal, explicitly authorized **Validator** or **Sanitizer** nodes.
- **Code-Binding (Binary Attestation):** Identity is tied not just to the service name, but to the **Binary Hash** of the running code (via Sigstore/TPM) to prevent compromised-workload signing.

---

## 2. Open Standards Integration

To ensure interoperability, Kest v0.3.0 adopts the following open standards:

| Requirement         | Standard Adopted | Rationale & Usage |
| :------------------ | :----------------- | :----------------- |
| **Identity**        | **SPIFFE** / **SPIRE** | Standardized workload identity generation. For testing, fallback to generic UID generation. |
| **Signatures**      | **JWS** (JSON Web Signature) | Replaces custom Base64 Ed25519 signing. JWS allows any language to verify the Kest Passport seamlessly using standard JWT/JWS libraries (e.g., `PyJWT`). |
| **Lineage Graph**   | **W3C PROV-O** (Concepts) | Maps Kest Nodes to PROV Entities and Activities, ensuring the terminology aligns with generic data provenance graphs. |
| **Policy Engine**   | **OPA / Rego** | Uses Open Policy Agent for deterministic policy enforcement. In v0.3.0, we support local inline execution (`lakera-regorus`) and remote external OPA clusters. |
| **Context Passing** | **OpenTelemetry Baggage** | Transports the Active Passport headers implicitly across gRPC or HTTP boundaries via standard OTel context propagation. Also aligns with OTel GenAI semantic conventions for agent tracing. |

---

## 3. Data Architecture: The Kest Passport

The Passport is a JSON-serialized Directed Acyclic Graph (DAG) consisting of **System Nodes** (Actors/Activities) and **Data Nodes** (Artifacts/Entities).

### **Node Specification (KestEntry)**

| Attribute             | Type       | Description                                                                                       |
| :-------------------- | :--------- | :------------------------------------------------------------------------------------------------ |
| `entry_id`            | String     | Unique identifier (UUIDv7 for time-sortability).                                                   |
| `node_type`           | Enum       | Categorization: `system`, `data`, `sanitizer`, `critic`, `snapshot`.                               |
| `parent_entry_ids`    | List[Str]  | Merkle-links to the previous nodes in the DAG.                                                  |
| `node_id`             | String     | The SPIFFE ID or localized namespace identifier of the actor.                                      |
| `timestamp_ms`        | Integer    | Epoch timestamp of execution.                                                                      |
| `input_state_hash`    | String     | SHA-256 hash of the incoming data and previous passport state.                                     |
| `content_hash`        | String     | SHA-256 hash of the generated output data payload.                                                 |
| `environment`         | Map        | Execution context (e.g., `{"hostname": "worker-01", "version": "1.2.0"}`).                           |
| `labels`              | Map        | Positive metadata/guarantees (e.g., `{"pii_checked": "true"}`).                                      |
| `added_taint`         | List[Str]  | New negative markers applied by this node (e.g., `["untrusted_network"]`).                           |
| `accumulated_taint`   | List[Str]  | Global union of all active taints inherited in the lineage branch.                                 |
| `trust_score`         | Float      | 0.0 to 1.0; represents the calculated probabilistic validity of the data.                          |
| `attestation`         | Object     | (Optional) Code-binary hash and signature references (e.g., Sigstore bundle).                      |
| `cognition`           | Object     | (Optional) AI tracking metadata (model version, temperature, system prompt hash, confidence score).|

### **The Cognition Object**

When the actor is an AI Agent, the `cognition` object traces *why* and *how* a decision was made.
- `model_profile`: Provider, model name, and version (e.g., `openai:gpt-4o:2024-05-13`).
- `generation_config`: Parameters impacting determinism (e.g., `temperature`, `top_p`).
- `system_prompt_hash`: SHA-256 hash of the system instructions governing the agent.
- `context_refs`: List of `entry_id`s representing the exact context chunks (e.g., RAG results, memories) used in the prompt.
- `confidence_score`: A self-evaluated or critic-evaluated score (0.0 to 1.0) of the output's correctness.

### **The JWS Passport Signature**

The final output is wrapped as a `JWS` string:
```json
{
  "alg": "EdDSA",
  "kid": "spiffe://kest.internal/worker-1/keys/1"
}
.
{
  "origin": { "user_id": "usr-123", "session": "xyz" },
  "history": { "<entry_id>": { /* KestEntry */ } }
}
.
<base64_url_signature>
```

### **The Trust Score Formula**

For an execution node $C$ with a set of parent inputs $P$:
$$T_C = \left( \frac{\sum_{p \in P} T_p \cdot W_p}{\sum W_p} \right) \cdot E_C$$

- **$T_p$**, **$W_p$**: The trust score and semantic weight of the parent input (Primary Fact vs. Contextual Noise).
- **$E_C$**: The deterministic tax (efficiency) of the current node's logic.

---

## 4. Operational Logic & Scenarios

Kest manages data transitions through interceptors/decorators that automatically track state.

### **The Merge Pattern (Fan-In)**
When an agent consumes multiple inputs ($A$ and $B$), Kest automatically resolves the security state before execution:
1. **Taints (Union):** Output inherits every taint: $Taint_C = Taint_A \cup Taint_B$
2. **Labels (Intersection):** Output retains only shared guarantees: $Label_C = Label_A \cap Label_B$
3. **Trust Score:** Recalculated using the weighted decay formula.

### **The Sanitizer Pattern**
To prevent permanent "taint poisoning" (e.g., data marked `pii_data` becoming unusable globally):
- Specialized `sanitizer` nodes (verified PII scrubbers) register to drop specific taints.
- The node proves execution, and Kest removes `pii_data` from `accumulated_taints` while leaving a permanent audit record of the sanitizer node in the graph.

### **The Exception Pattern (Implicit Tainting)**
If a critical error or unhandled exception occurs during domain logic execution:
- Kest mathematically catches the failure, appends a new `KestEntry`, and explicitly injects a `failed_execution` taint while forcing `trust_score = 0.0`.
- The exception is then re-raised, preserving standard Python failure modes while ensuring no failed AI loop goes unrecorded in the Passport.

---

## 5. AI & Cognition Lineage Use Cases

By embedding the `cognition` block and utilizing DAG mechanics, Kest tracks the full lifecycle of agentic reasoning across four critical dimensions: **Data** (what was read?), **Security** (is it safe?), **Trust** (is the system verified?), and **Cognition** (why did the AI conclude this?).

### **Use Case 1: Retrieval-Augmented Generation (RAG) and Grounding**
* **Scenario**: An agent queries a vector DB, retrieves two chunks of data (one public, one highly confidential), and generates a summarized answer.
* **Design Consideration**: The user needs to know if the summarized answer is safe to send via email, and what exact contextual sources were cited to minimize hallucination risks.
* **Kest Handling**: 
  - The context chunks are loaded as parent nodes. The output node inherits the `confidential` taint from the private chunk.
  - The `cognition.context_refs` records the exact chunk `entry_id`s.
  - *Result*: The system blocks the email (Pessimistic Data Flow) and the lineage proves exactly which private document triggered the block and how grounding was achieved.

### **Use Case 2: Tool Execution (Function Calling)**
* **Scenario**: An LLM agent decides to call a `SearchWeb` tool and an `ExecuteSQL` tool to answer a prompt.
* **Design Consideration**: Tools execute with different permission scopes, determinism, and reliability guarantees.
* **Kest Handling**:
  - The LLM node generates a "Tool Request" node.
  - The Tool Runtime executes the request, generating a "Tool Response" node (acting as a system node with its own attestation and trust score).
  - The LLM consumes the "Tool Response" as a parent pipeline to generate the final synthetic answer.
  - *Result*: The Passport shows the exact parameter generation, the tool's isolated execution, and the final synthesis as a verifiable chained sequence.

### **Use Case 3: Multi-Agent Debate & Critic Evaluation**
* **Scenario**: Agent A drafts a code snippet. Agent B (Critic) reviews it and scores it. Agent A refines it based on the critique.
* **Design Consideration**: Decisions made via consensus or critique must be auditable to understand the evolution and refinement of the output.
* **Kest Handling**:
  - Agent A writes Node 1. 
  - Agent B reads Node 1, runs its critique, and writes Node 2 (type: `critic`, `cognition.confidence_score: 0.4`), applying a `needs_revision` taint.
  - Agent A reads Node 2, outputs Node 3, overriding the taint and setting a newly evaluated `cognition.confidence_score: 0.9`. 
  - *Result*: The Kest `trust_score` dynamically adjusts during the flow. Consumers of Node 3 can traverse the DAG backward to see the initial failure, the exact critique, and the reasoning path that led to the fix.

---

## 6. Tiered Storage & Compaction

To maintain sub-millisecond latency over extremely long DAGs without hitting HTTP header size limits, Kest implements a **Tiered Passport** model using the `fsspec` Python interface, allowing testing to use local disk, and production to use S3/GCS seamlessly.

- **Tier 1: Active (In-Memory/Headers):** The last $N$ nodes + global Taint/Label summary. Carried in OpenTelemetry Baggage/HTTP Headers.
- **Tier 2: Shadow (Fast Cache):** Full Merkle-path to the root stored in a high-speed KV store (e.g., Redis, or local disk via `fsspec` for testing).
- **Tier 3: Deep (Audit Store):** Archival storage of partitioned, full-DAG histories in S3/GCS.

**Merkle Compaction (Scenario):** 
If the Active Graph exceeds 25 nodes, the runtime dynamically collapses the history into a single snapshot `<entry_id>`. It issues an asynchronous write to Tier 3 storage and replaces the 25 nodes in Tier 1 with a single reference: `{"type": "snapshot", "tier3_uri": "s3://kest-logs/passport-123.json", "root_hash": "..."}`.

---

## 7. Security & Policy Enforcement

Kest prevents unsafe execution via OPA policies enforced strictly *before* domain logic execution.

### **The Verification Loop**
1. **Ingress intercept:** Extract `KestPassport` from `KestData` or OTel Context.
2. **Key Discovery & Signature:** Resolve the public key using the header (`kid`) via a pluggable `KeyRegistry` (SPIRE Workload API, JWKS fetching, etc.), then assert JWS integrity.
3. **OPA Policy Gate:** Evaluate the node's `accumulated_taints` and requested action against local or remote Rego policies.
4. **Execution:** Run the actual Python function/domain logic.
5. **Egress capture:** Compute output hashes, append the new `KestEntry`, and sign the new Passport.

---

## 8. Execution Environments & Agnosticism (Design Decisions)

Kest v0.3.0 is designed to scale dynamically from a developer's laptop to an enterprise kubernetes cluster by injecting interfaces.

### **Scenario A: Local Development & CI Testing**
* **Design Consideration:** Developers need to write tests without deploying SPIRE, Redis, or an OPA server. 
* **Decision:** Out-of-the-box defaults use:
  - **Identity:** Environment variables or hostname fallback (`worker-01`).
  - **Keys:** Fast, locally generated Ed25519 ephemeral keypairs.
  - **Policy Engine:** `lakera-regorus` (Rust-based local Rego execution directly in Python process).
  - **Storage:** Local filesystem via `fsspec("file://.kest/cache")`.

### **Scenario B: Production Multi-Agent Pipeline**
* **Design Consideration:** Data moves across physical servers; trust relies on rigid infrastructure.
* **Decision:** Operations teams configure the Kest Singleton to use:
  - **Identity:** SPIRE Workload APIs to retrieve short-lived identity documents.
  - **Keys:** Cloud KMS (AWS KMS / Hashicorp Vault) for remote JWS signing.
  - **Policy Engine:** Remote `opa-python-client` connecting to an enterprise OPA cluster.
  - **Storage:** `fsspec("s3://kest-audit-logs")` for asynchronous graph compaction.

By relying strictly on explicit Dependency Injection internally and using `fsspec`, Kest satisfies both paradigms cleanly without modifying the domain code or test suites.

---

## 9. Tooling & CLI (`kest-cli`)

Optional dependencies (`kest[cli]`) provide tools to operate on Passports:
- `kest verify <passport.json>`: Strict parsing of the JWS signature.
- `kest hydrate <snapshot_id>`: Fetches historical nodes from Deep tier storage (using configured `fsspec`) to reconstruct the full DAG.
- `kest blast-radius --node <id>`: Analyzes Tier 3 storage to identify all downstream systems affected by a historically compromised system node.
