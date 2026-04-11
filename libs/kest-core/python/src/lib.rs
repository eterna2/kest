use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use kest_core_rs::models::{
    KestEntry as CoreEntry, KestClassification, KestRuntime, PolicyContext, PolicyDeviation,
};
use std::collections::BTreeMap;
use ed25519_dalek::{SigningKey, Signer};


/// Converts a Python dict representing a PolicyContext into the Rust PolicyContext struct.
fn py_dict_to_policy_context(_py: Python<'_>, dict: &Bound<'_, PyDict>) -> PolicyContext {
    let get_str_vec = |key: &str| -> Vec<String> {
        dict.get_item(key)
            .ok()
            .flatten()
            .and_then(|v| v.downcast::<PyList>().ok().map(|l| {
                l.iter()
                    .filter_map(|i| i.extract::<String>().ok())
                    .collect()
            }))
            .unwrap_or_default()
    };

    let deviations = dict
        .get_item("deviations")
        .ok()
        .flatten()
        .and_then(|v| v.downcast::<PyList>().ok().map(|l| {
            l.iter()
                .filter_map(|item| {
                    let d = item.downcast::<PyDict>().ok()?;
                    Some(PolicyDeviation {
                        policy: d.get_item("policy").ok().flatten()?.extract::<String>().ok()?,
                        tier: d.get_item("tier").ok().flatten()?.extract::<String>().ok()?,
                        reason: d.get_item("reason").ok().flatten().and_then(|v| v.extract::<String>().ok()),
                        approver: d.get_item("approver").ok().flatten().and_then(|v| v.extract::<String>().ok()),
                    })
                })
                .collect()
        }))
        .unwrap_or_default();

    PolicyContext {
        enterprise_policies: get_str_vec("enterprise_policies"),
        platform_policies: get_str_vec("platform_policies"),
        app_policies: get_str_vec("app_policies"),
        function_policies: get_str_vec("function_policies"),
        deviations,
    }
}

#[pyclass]
#[derive(Clone)]
pub struct KestEntry {
    pub inner: CoreEntry,
}

#[pyclass(subclass)]
pub struct RustNativeIdentityProvider {
    pub signing_key: SigningKey,
    #[pyo3(get)]
    pub principal: String,
}

#[pymethods]
impl RustNativeIdentityProvider {
    #[new]
    fn new(key_bytes: &[u8], principal: String) -> PyResult<Self> {
        let key_array: [u8; 32] = key_bytes.try_into()
            .map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Key must be 32 bytes"))?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&key_array),
            principal,
        })
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }

    fn sign_payload(&self, payload: &[u8]) -> String {
        use base64::Engine;
        let signature = self.signing_key.sign(payload);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes())
    }
}

#[pymethods]
impl KestEntry {
    #[new]
    #[pyo3(signature = (
        entry_id,
        operation,
        classification,
        trust_score,
        parent_ids=None,
        labels=None,
        added_taints=None,
        removed_taints=None,
        taints=None,
        schema_version=None,
        runtime_name=None,
        runtime_version=None,
        policy_context=None,
    ))]
    fn new(
        py: Python<'_>,
        entry_id: String,
        operation: String,
        classification: String,
        trust_score: i32,
        parent_ids: Option<Vec<String>>,
        labels: Option<BTreeMap<String, String>>,
        added_taints: Option<Vec<String>>,
        removed_taints: Option<Vec<String>>,
        taints: Option<Vec<String>>,
        schema_version: Option<String>,
        runtime_name: Option<String>,
        runtime_version: Option<String>,
        policy_context: Option<Bound<'_, PyDict>>,
    ) -> Self {
        let classification_enum = match classification.to_lowercase().as_str() {
            "system" => KestClassification::System,
            "data" => KestClassification::Data,
            "critic" => KestClassification::Critic,
            "snapshot" => KestClassification::Snapshot,
            _ => KestClassification::System,
        };

        let pc = policy_context
            .as_ref()
            .map(|d| py_dict_to_policy_context(py, d))
            .unwrap_or_default();

        let inner = CoreEntry {
            schema_version: schema_version.unwrap_or_else(|| "0.3.0".to_string()),
            runtime: KestRuntime {
                name: runtime_name.unwrap_or_else(|| "kest-python".to_string()),
                version: runtime_version.unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string()),
            },
            entry_id,
            parent_ids: parent_ids.unwrap_or_default(),
            classification: classification_enum,
            operation,
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            input_hash: "".to_string(),
            content_hash: "".to_string(),
            environment: BTreeMap::new(),
            otel_context: BTreeMap::new(),
            labels: labels.unwrap_or_default(),
            added_taints: added_taints.unwrap_or_default(),
            removed_taints: removed_taints.unwrap_or_default(),
            taints: taints.unwrap_or_default(),
            trust_score,
            metadata: None,
            policy_context: pc,
        };

        KestEntry { inner }
    }

    #[getter]
    fn entry_id(&self) -> String {
        self.inner.entry_id.clone()
    }

    #[getter]
    fn operation(&self) -> String {
        self.inner.operation.clone()
    }

    #[getter]
    fn schema_version(&self) -> String {
        self.inner.schema_version.clone()
    }

    #[getter]
    fn classification(&self) -> String {
        match self.inner.classification {
            kest_core_rs::models::KestClassification::System => "system".to_string(),
            kest_core_rs::models::KestClassification::Data => "data".to_string(),
            kest_core_rs::models::KestClassification::Critic => "critic".to_string(),
            kest_core_rs::models::KestClassification::Snapshot => "snapshot".to_string(),
            kest_core_rs::models::KestClassification::Sanitizer => "sanitizer".to_string(),
        }
    }

    #[getter]
    fn parent_ids(&self) -> Vec<String> {
        self.inner.parent_ids.clone()
    }

    #[getter]
    fn labels(&self) -> std::collections::BTreeMap<String, String> {
        self.inner.labels.clone()
    }

    #[getter]
    fn timestamp_ms(&self) -> u64 {
        self.inner.timestamp_ms
    }

    #[getter]
    fn input_hash(&self) -> String {
        self.inner.input_hash.clone()
    }

    #[getter]
    fn content_hash(&self) -> String {
        self.inner.content_hash.clone()
    }

    #[getter]
    fn environment(&self) -> std::collections::BTreeMap<String, String> {
        self.inner.environment.clone()
    }

    #[getter]
    fn otel_context(&self) -> std::collections::BTreeMap<String, String> {
        self.inner.otel_context.clone()
    }


    #[getter]
    fn trust_score(&self) -> i32 {
        self.inner.trust_score
    }

    #[getter]
    fn added_taints(&self) -> Vec<String> {
        self.inner.added_taints.clone()
    }

    #[getter]
    fn removed_taints(&self) -> Vec<String> {
        self.inner.removed_taints.clone()
    }

    #[getter]
    fn taints(&self) -> Vec<String> {
        self.inner.taints.clone()
    }

    /// Returns the policy_context as a Python dict.
    #[getter]
    fn policy_context(&self, py: Python<'_>) -> PyResult<PyObject> {
        let pc = &self.inner.policy_context;
        let d = PyDict::new(py);
        d.set_item("enterprise_policies", &pc.enterprise_policies)?;
        d.set_item("platform_policies", &pc.platform_policies)?;
        d.set_item("app_policies", &pc.app_policies)?;
        d.set_item("function_policies", &pc.function_policies)?;

        let dev_list: Vec<PyObject> = pc.deviations.iter().map(|dv| {
            let dd = PyDict::new(py);
            dd.set_item("policy", &dv.policy).unwrap();
            dd.set_item("tier", &dv.tier).unwrap();
            if let Some(r) = &dv.reason {
                dd.set_item("reason", r).unwrap();
            }
            if let Some(a) = &dv.approver {
                dd.set_item("approver", a).unwrap();
            }
            dd.into_pyobject(py).unwrap().into_any().unbind()
        }).collect();
        d.set_item("deviations", dev_list)?;
        Ok(d.into())
    }
}



fn build_signing_input(inner: &CoreEntry, principal: Option<&str>) -> Result<String, String> {
    use base64::Engine;
    let json_val = serde_json::to_value(inner)
        .map_err(|e| e.to_string())?;
    let canonical = kest_core_rs::canonical::to_canonical_string(&json_val)
        .map_err(|e| e)?;

    let header = if let Some(p) = principal {
        serde_json::json!({"alg":"EdDSA","typ":"JWS", "kid": p})
    } else {
        serde_json::json!({"alg":"EdDSA","typ":"JWS"})
    };

    let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_jcs::to_string(&header).unwrap());
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(canonical);
    Ok(format!("{}.{}", header_b64, payload_b64))
}

#[pyfunction]
fn sign_entry(py: Python<'_>, entry: &KestEntry, provider: PyObject) -> PyResult<String> {
    use base64::Engine;

    // Clone the inner Rust struct so we can drop the GIL safely.
    let inner = entry.inner.clone();

    // Check if provider is our native Rust provider (no GIL needed after this)
    let native_provider: Option<(SigningKey, String)> = provider.bind(py)
        .downcast::<RustNativeIdentityProvider>()
        .ok()
        .map(|p| {
            let p = p.borrow();
            (p.signing_key.clone(), p.principal.clone())
        });

    if let Some((signing_key, principal)) = native_provider {
        // Entirely GIL-free path: canonicalize + sign in one allow_threads block
        let jws = py.allow_threads(|| -> Result<String, String> {
            let signing_input = build_signing_input(&inner, Some(&principal))?;
            let sig = signing_key.sign(signing_input.as_bytes());
            let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());
            Ok(format!("{}.{}", signing_input, sig_b64))
        }).map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e))?;
        return Ok(jws);
    }

    // Fallback: Python provider path (GIL re-acquisition, existing behaviour)
    // Used for SPIREProvider and any custom Python providers.
    let signing_input = py.allow_threads(|| build_signing_input(&inner, None))
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e))?;

    // Re-acquire GIL to call the Python identity provider's sign_payload.
    let signature = Python::with_gil(|py2| {
        let py_bytes = pyo3::types::PyBytes::new(py2, signing_input.as_bytes());
        provider
            .call_method1(py2, "sign_payload", (py_bytes,))
            .and_then(|r| r.extract::<String>(py2))
    })?;

    if signature.contains('.') {
        Ok(signature)
    } else {
        Ok(format!("{}.{}", signing_input, signature))
    }
}


#[pyfunction]
fn version() -> PyResult<String> {
    Ok(env!("CARGO_PKG_VERSION").to_string())
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(sign_entry, m)?)?;
    m.add_class::<KestEntry>()?;
    m.add_class::<RustNativeIdentityProvider>()?;
    Ok(())
}
