use pyo3::prelude::*;
use pyo3::types::{PyDict, PyString, PyList};
use std::collections::{BTreeMap, HashMap};
use kest_runtime_rs::context;
use kest_runtime_rs::engines::PolicyEngine;
use kest_runtime_rs::engines::opa::OpaPolicyEngine;
use kest_runtime_rs::engines::cedar::CedarAgentPolicyEngine;
use kest_runtime_rs::engines::mock::MockPolicyEngine;
use kest_runtime_rs::engines::foreign::ForeignPolicyEngine;
use kest_runtime_rs::pipeline::{KestPipeline, PipelineRequest, PipelineError};
use kest_core_rs::models::KestClassification;
use kest_core_rs::crypto::{IdentityProvider, CryptoError};

// --- Context API ---

#[pyfunction]
fn context_create() -> u64 {
    context::create()
}

#[pyfunction]
fn context_destroy(token: u64) {
    context::destroy(token);
}

#[pyfunction]
fn context_get(token: u64, key: &str) -> Option<String> {
    context::get(token, key)
}

#[pyfunction]
fn context_set(token: u64, key: String, value: String) {
    context::set(token, key, value);
}

#[pyfunction]
fn context_set_batch(token: u64, entries: HashMap<String, String>) {
    context::set_batch(token, entries);
}

#[pyfunction]
fn context_get_all(token: u64) -> Option<HashMap<String, String>> {
    context::get_all(token)
}

#[pyfunction]
fn context_set_passport(token: u64, entries: Vec<String>) {
    context::set_passport(token, entries);
}

#[pyfunction]
fn context_get_passport(token: u64) -> Option<Vec<String>> {
    context::get_passport(token)
}

// --- Engines ---

#[pyclass(subclass)]
pub struct RustPolicyEngine {
    // Note: PyO3 requires trait objects to be threadsafe if they are put in PyClass.
    // Box<dyn PolicyEngine> is Send + Sync.
    pub engine: Box<dyn PolicyEngine>,
}

#[pymethods]
impl RustPolicyEngine {
    #[staticmethod]
    fn opa(url: String, _default_allow: bool, timeout_ms: u64) -> PyResult<Self> {
        let engine = OpaPolicyEngine::new(url, timeout_ms);
        Ok(Self { engine: Box::new(engine) })
    }

    #[staticmethod]
    fn cedar(url: String, _default_allow: bool, timeout_ms: u64) -> PyResult<Self> {
        let engine = CedarAgentPolicyEngine::new(url, timeout_ms);
        Ok(Self { engine: Box::new(engine) })
    }

    #[staticmethod]
    fn mock(allow: bool) -> PyResult<Self> {
        let engine = MockPolicyEngine::new(allow);
        Ok(Self { engine: Box::new(engine) })
    }

    #[staticmethod]
    fn foreign(_py: Python<'_>, evaluate_func: PyObject) -> PyResult<Self> {
        let engine = ForeignPolicyEngine::new(move |entry_id, policy_names, ctx| {
            Python::with_gil(|py| {
                let py_id = PyString::new(py, entry_id);
                let py_names = PyList::new(py, policy_names).unwrap();
                let py_ctx = PyDict::new(py);
                for (k, v) in ctx {
                    if k == "trust_score" {
                        if let Ok(val) = v.parse::<i32>() {
                            py_ctx.set_item(k, val).unwrap();
                            continue;
                        }
                    }
                    py_ctx.set_item(k, v).unwrap();
                }
                
                let res = evaluate_func.call1(py, (py_id, py_names, py_ctx)).map_err(|e| {
                    kest_runtime_rs::engines::PolicyError::Evaluation(e.to_string())
                })?;
                
                let b = res.extract::<bool>(py).map_err(|e| {
                    kest_runtime_rs::engines::PolicyError::Evaluation(e.to_string())
                })?;
                
                Ok(b)
            })
        });
        Ok(Self { engine: Box::new(engine) })
    }
}

// Struct to bridge Python provider back to Rust trait for non-native providers
struct PyIdentityProvider {
    provider: PyObject,
}

impl IdentityProvider for PyIdentityProvider {
    fn verify_svid(&self, _svid: &str) -> Result<String, CryptoError> {
        Ok("mock".into())
    }
    
    fn sign_payload(&self, payload: &[u8]) -> Result<String, CryptoError> {
        Python::with_gil(|py| {
            let py_bytes = pyo3::types::PyBytes::new(py, payload);
            let res = self.provider.call_method1(py, "sign", (py_bytes,)).map_err(|e| {
                CryptoError::SigningFailed(e.to_string())
            })?;
            res.extract::<String>(py).map_err(|e| CryptoError::SigningFailed(e.to_string()))
        })
    }
}


#[pyfunction]
#[pyo3(signature = (engine, provider, token, req_dict, trust_evaluator=None))]
fn pipeline_execute(
    py: Python<'_>,
    engine: &Bound<'_, RustPolicyEngine>,
    provider: PyObject,
    token: u64,
    req_dict: &Bound<'_, PyDict>,
    trust_evaluator: Option<PyObject>,
) -> PyResult<(HashMap<String, String>, String)> {
    
    let engine_ref = &*engine.borrow().engine;
    
    // We check if provider is a native provider or not.
    let is_native = provider.downcast_bound::<crate::RustNativeIdentityProvider>(py).is_ok();
    
    // Extract request args
    let classification_str: String = req_dict.get_item("classification")?.unwrap().extract()?;
    let classification = match classification_str.as_str() {
        "System" => KestClassification::System,
        "Data" => KestClassification::Data,
        "Sanitizer" => KestClassification::Sanitizer,
        "Critic" => KestClassification::Critic,
        "Snapshot" => KestClassification::Snapshot,
        _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid classification: {}", classification_str))),
    };
    
    let operation: String = req_dict.get_item("operation")?.map(|v| v.extract()).transpose()?.unwrap_or_default();
    let input_hash: String = req_dict.get_item("input_hash")?.map(|v| v.extract()).transpose()?.unwrap_or_default();
    let content_hash: String = req_dict.get_item("content_hash")?.map(|v| v.extract()).transpose()?.unwrap_or_default();
    let added_taints: Vec<String> = req_dict.get_item("added_taints")?.map(|v| v.extract()).transpose()?.unwrap_or_default();
    let removed_taints: Vec<String> = req_dict.get_item("removed_taints")?.map(|v| v.extract()).transpose()?.unwrap_or_default();
    let parent_ids: Vec<String> = req_dict.get_item("parent_ids")?.map(|v| v.extract()).transpose()?.unwrap_or_default();
    let function_policies: Vec<String> = req_dict.get_item("function_policies")?.map(|v| v.extract()).transpose()?.unwrap_or_default();
    let enterprise_policies: Vec<String> = req_dict.get_item("enterprise_policies")?.map(|v| v.extract()).transpose()?.unwrap_or_default();
    let deviations_json: Option<String> = req_dict.get_item("deviations_json")?.map(|v| v.extract()).transpose()?;
    let trust_override: Option<i32> = req_dict.get_item("trust_override")?.map(|v| v.extract()).transpose()?;
    let origin_trust_score: i32 = req_dict.get_item("origin_trust_score")?.map(|v| v.extract()).transpose()?.unwrap_or(100);
    
    let mut environment = BTreeMap::new();
    if let Some(ctx_dict) = req_dict.get_item("context")? {
        if let Ok(dict) = ctx_dict.downcast::<PyDict>() {
            for (k, v) in dict {
                if let Ok(ks) = k.extract::<String>() {
                    if let Ok(vs) = v.str().and_then(|s| s.extract::<String>()) {
                        environment.insert(ks, vs);
                    }
                }
            }
        }
    }

    let mut needs_gil = false;
    let trust_evaluator_func: Option<Box<dyn Fn(i32, Vec<i32>) -> i32 + Send + Sync + '_>> = if let Some(eval) = trust_evaluator {
        needs_gil = true;
        Some(Box::new(move |self_score, parent_scores| {
            Python::with_gil(|py| {
                 let args = (self_score, parent_scores);
                 eval.call_method1(py, "calculate", args)
                     .and_then(|r| r.extract::<i32>(py))
                     .unwrap_or_else(|e| {
                         println!("Python eval error: {:?}", e);
                         0
                     })
            })
        }))
    } else {
        None
    };
    
    let req = PipelineRequest {
        classification,
        operation,
        input_hash,
        content_hash,
        environment,
        otel_context: BTreeMap::new(),
        labels: BTreeMap::new(),
        added_taints,
        removed_taints,
        metadata: None,
        parent_ids,
        function_policies,
        enterprise_policies,
        deviations_json,
        trust_override,
        origin_trust_score,
        trust_evaluator_func,
        baggage_func: Box::new(move |key| context::get(token, key)),
    };
    
    // Run pipeline!
    let res = if is_native {
        let native = provider.downcast_bound::<crate::RustNativeIdentityProvider>(py).unwrap().borrow();
        let pipeline = KestPipeline::new(engine_ref, &*native);
        if needs_gil || engine_ref.is_foreign() {
            // Must hold GIL because engine_ref.evaluate or trust_evaluator will call Python
            pipeline.execute(req)
        } else {
            py.allow_threads(|| {
                pipeline.execute(req)
            })
        }
    } else {
        let py_prov = PyIdentityProvider { provider: provider.clone_ref(py) };
        let pipeline = KestPipeline::new(engine_ref, &py_prov);
        // We absolutely must hold GIL since engine_ref might be foreign OR the PyIdentityProvider requires GIL
        pipeline.execute(req)
    };
    
    match res {
        Ok((baggage, sig)) => Ok((baggage, sig)),
        Err(PipelineError::PolicyFailed(kest_runtime_rs::engines::PolicyError::Evaluation(e))) => {
            Err(PyErr::new::<pyo3::exceptions::PyPermissionError, _>(e))
        },
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string())),
    }
}

pub fn register_v2_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(context_create, m)?)?;
    m.add_function(wrap_pyfunction!(context_destroy, m)?)?;
    m.add_function(wrap_pyfunction!(context_get, m)?)?;
    m.add_function(wrap_pyfunction!(context_set, m)?)?;
    m.add_function(wrap_pyfunction!(context_set_batch, m)?)?;
    m.add_function(wrap_pyfunction!(context_get_all, m)?)?;
    m.add_function(wrap_pyfunction!(context_set_passport, m)?)?;
    m.add_function(wrap_pyfunction!(context_get_passport, m)?)?;
    
    m.add_function(wrap_pyfunction!(pipeline_execute, m)?)?;
    
    m.add_class::<RustPolicyEngine>()?;
    
    Ok(())
}
