use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

static CONTEXTS: once_cell::sync::Lazy<DashMap<u64, KestContext>> =
    once_cell::sync::Lazy::new(DashMap::new);

static TOKEN_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Default)]
pub struct KestContext {
    pub baggage: HashMap<String, String>,
    pub passport_entries: Vec<String>,
}

impl KestContext {
    pub fn new() -> Self {
        Self {
            baggage: HashMap::new(),
            passport_entries: Vec::new(),
        }
    }
}

/// Create a new context, returning a unique token.
pub fn create() -> u64 {
    let token = TOKEN_COUNTER.fetch_add(1, Ordering::Relaxed);
    CONTEXTS.insert(token, KestContext::new());
    token
}

/// Destroy a context (cleanup).
pub fn destroy(token: u64) {
    CONTEXTS.remove(&token);
}

/// Get a single value from the context baggage.
pub fn get(token: u64, key: &str) -> Option<String> {
    CONTEXTS.get(&token).and_then(|ctx| ctx.baggage.get(key).cloned())
}

/// Set a single value in the context baggage.
pub fn set(token: u64, key: String, value: String) {
    if let Some(mut ctx) = CONTEXTS.get_mut(&token) {
        ctx.baggage.insert(key, value);
    }
}

/// Set multiple values in the context baggage at once.
pub fn set_batch(token: u64, entries: HashMap<String, String>) {
    if let Some(mut ctx) = CONTEXTS.get_mut(&token) {
        ctx.baggage.extend(entries);
    }
}

/// Get all baggage values from the context.
pub fn get_all(token: u64) -> Option<HashMap<String, String>> {
    CONTEXTS.get(&token).map(|ctx| ctx.baggage.clone())
}

/// Set the passport entries for the context.
pub fn set_passport(token: u64, entries: Vec<String>) {
    if let Some(mut ctx) = CONTEXTS.get_mut(&token) {
        ctx.passport_entries = entries;
    }
}

/// Get the passport entries from the context.
pub fn get_passport(token: u64) -> Option<Vec<String>> {
    CONTEXTS.get(&token).map(|ctx| ctx.passport_entries.clone())
}

/// Get the number of active contexts (for testing/diagnostics).
pub fn active_contexts_count() -> usize {
    CONTEXTS.len()
}
