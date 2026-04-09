use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use kest_core_rs::models::{
    KestEntry as CoreEntry, KestClassification, KestRuntime, PolicyContext, PolicyDeviation,
};
use kest_core_rs::crypto::{IdentityProvider as CoreIdentityProvider, CryptoError};
use std::collections::BTreeMap;

/// Converts a Python dict representing a PolicyContext into the Rust PolicyContext struct.
fn py_dict_to_policy_context(py: Python<'_>, dict: &Bound<'_, PyDict>) -> PolicyContext {
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
            dd.to_object(py)
        }).collect();
        d.set_item("deviations", dev_list)?;
        Ok(d.into())
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
