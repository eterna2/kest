# `kest-runtime-rs` (V2 Pipeline)
**The High-Throughput, Polyglot Native Runner for the Kest Verification Toolkit**

---

This README is an authoritative reference designed for both **Human Engineers** and **AI Agents** developing, extending, or debugging the Kest toolkit. It comprehensively details the architecture, data pathways, and internal implementation quirks of the `v2` pipeline execution layer.

> [!IMPORTANT]
> The principles of this crate exist to fulfill the normative requirements set out in `SPEC-v0.3.0.md` without suffering from the overhead of high-level interpreter locks.

---

## 🏗 Why `kest-runtime-rs` Exists

During load-testing of the standard Python implementation (V1), Kest experienced a "GIL Contention Cliff" when evaluating concurrent requests exceeding ~190 RPS. The fundamental bottleneck was the sequential locking caused by heavy I/O and CPU operations bound to the interpreter:
- **Trace Context Reads/Writes:** Constantly unpacking strings from OpenTelemetry Baggage over C-FFI.
- **REST/RPC Operations:** Calling out to Cedar or Open Policy Agent (OPA) validation engines. 
- **Cryptography:** JWS signing loops and payload canonicalization.

`kest-runtime-rs` moves *all* of these operations strictly into a native Rust orchestration pipeline. High-level runtime environments (like Python or JavaScript) only interact with Kest to initiate a standard `PipelineRequest`, after which the native code drops the interpreter lock, drives concurrency, and handles security resolution autonomously. Throughput successfully scales linearly past 3,000+ RPS.

---

## 🗺 Architecture Overview

The crate is structured strictly across distinct responsibilities:

1. **Pipeline Orchestrator (`src/pipeline.rs`)**: 
   The `KestPipeline` struct handles the data lifecycle. It takes a transient `PipelineRequest` and executes the standardized CARTA validation trace.
   - Decodes ambient OpenTelemetry baggage `kest.passport_z`.
   - Merges newly `added_taints` and deletes `removed_taints`.
   - Bootstraps or computes the weakest-link CARTA `trust_score` dynamic evaluation.
   - Synthesizes the exact payload requested by the external Verification Engines.
   - Signs the newly verified entry via the generic `IdentityProvider` trait interface.
   - Assembles and compresses the next inline baggage representation, reverting to `Claim-Check` persistence if standard HTTP header thresholds (> 4096 bytes) are breached.

2. **Policy Engines (`src/engines/`)**: 
   These are execution drivers adhering to the `PolicyEngine` Rust trait, capable of mapping the verification attributes against target deployment constraints.
   - `opa.rs`: Open Policy Agent driver (makes standard HTTP POSTs formatting the `EvaluatorPayload`).
   - `cedar.rs`: Cedar Local/Remote driver (constructs the AWS Cedar Principal/Action/Resource schema mapping).
   - `mock.rs`: Test engine that defaults to pass/fail primitives.
   - `foreign.rs`: A specific adapter utilizing *Inversion of Control*. It accepts callbacks from the calling environment (like Python via PyO3). The Rust pipeline acquires the lock, dips back into the foreign environment, receives evaluation output, and releases the lock back to native.

3. **External Implementations (`src/context.rs`, `src/lib.rs`)**: 
   Utility wrappers managing the generic interface for tracking Context Maps between polyglot boundaries, extracting parameters cleanly for native operations.

---

## 🔬 Deep Dive: Engine Adapters & Spec-Aware Type Coercion

### The Context Serialization Problem
Kest specification (`F-AE-13`) dictates that environments are carried globally downstream via OTel tracking tokens or local application environment structures natively represented as `BTreeMap<String, String>` mapping structures inside Rust. OpenTelemetry exclusively tracks `string` values.

However, Policy Engines expect constrained, strictly-typed schemas for logical evaluation operations (e.g. `trust_score > 50` natively in Cedar requires an Integer resolution).

### The Implementation Guardrails
To prevent constraint errors when interacting with Policy Engines across boundaries, **Spec-Aware Type Coercion** is implemented strictly within the Engine adapters (`opa.rs`, `cedar.rs`, `foreign.rs`). 

When `PolicyEngine::evaluate()` intercepts the execution context, it dynamically iterates the string entries in the payload. If it encounters a key predefined within spec as native-typed (like `trust_score`), it intercepts it (e.g. `v.parse::<i32>()`) and binds it as a direct native primitive inside the final emitted JSON `serde_json::Value` passed out to the engine.

> [!WARNING] 
> Do not attempt to map native JSON values generically directly onto the `kest-core-rs` structs inside the `KestEntry` declaration. String serialization validation guarantees must be strictly enforced at the Baggage layer. Rely on Engine layers for specialized decoding routines.

---

## 🔌 API Boundaries & FFI Injection

`kest-runtime-rs` expects to be utilized functionally under FFI wrappers. An explicit example is located inside `libs/kest-core/python/src/v2.rs`.

When initializing the pipeline from a host language:

- **Identity Provisioning:** Host languages should wrap their specific signing mechanisms inside generic `Box<dyn IdentityProvider>` struct pointers (which safely export a `sign(&[u8]) -> String` functional parameter).
- **Callbacks Hooking:** Dynamic properties that require custom processing (such as the `trust_evaluator_func` calculating new initial boundary scores) must explicitly implement `Send + Sync` references within the native interface declaration.

### Python Context
Python decorators instantiate these callbacks transparently. When integrating, guarantee the Python GIL boundaries map to the engine constraints, executing operations using PyO3 closure environments that capture and release the GIL safely during iterations to avoid memory fragmentation or locking conflicts.
