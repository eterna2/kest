use pyo3::prelude::*;
use kest_core_rs::models::{KestEntry as CoreEntry, KestClassification};
use kest_core_rs::crypto::{IdentityProvider as CoreIdentityProvider, CryptoError};
use std::collections::BTreeMap;

#[pyclass]
#[derive(Clone)]
pub struct KestEntry {
    pub inner: CoreEntry,
}

#[pymethods]
impl KestEntry {
    #[new]
    #[pyo3(signature = (entry_id, operation, classification, trust_score, parent_ids=None, labels=None, added_taints=None, removed_taints=None, taints=None))]
    fn new(
        entry_id: String,
        operation: String,
        classification: String,
        trust_score: i32,
        parent_ids: Option<Vec<String>>,
        labels: Option<BTreeMap<String, String>>,
        added_taints: Option<Vec<String>>,
        removed_taints: Option<Vec<String>>,
        taints: Option<Vec<String>>,
    ) -> Self {
        let classification_enum = match classification.to_lowercase().as_str() {
            "system" => KestClassification::System,
            "data" => KestClassification::Data,
            "critic" => KestClassification::Critic,
            "snapshot" => KestClassification::Snapshot,
            _ => KestClassification::System,
        };

        let inner = CoreEntry {
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
}

// Internal adapter to use a Python object as a Rust IdentityProvider
struct PyIdentityProvider {
    inner: PyObject,
}

impl CoreIdentityProvider for PyIdentityProvider {
    fn verify_svid(&self, svid: &str) -> Result<String, CryptoError> {
        Python::with_gil(|py| {
            let res = self.inner.call_method1(py, "verify_svid", (svid,))
                .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;
            res.extract::<String>(py).map_err(|e| CryptoError::SigningFailed(e.to_string()))
        })
    }

    fn sign_payload(&self, payload: &[u8]) -> Result<String, CryptoError> {
        Python::with_gil(|py| {
            let res = self.inner.call_method1(py, "sign_payload", (payload,))
                .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;
            res.extract::<String>(py).map_err(|e| CryptoError::SigningFailed(e.to_string()))
        })
    }
}

#[pyfunction]
fn sign_entry(entry: &KestEntry, provider: PyObject) -> PyResult<String> {
    let adapter = PyIdentityProvider { inner: provider };
    kest_core_rs::crypto::sign_kest_entry(&entry.inner, &adapter)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
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
    Ok(())
}
