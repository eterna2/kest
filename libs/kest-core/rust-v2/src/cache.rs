pub trait CacheBackend: Send + Sync {
    fn set(&self, key: &str, value: &str);
    fn get(&self, key: &str) -> Option<String>;
}

pub struct InMemoryCache {
    map: dashmap::DashMap<String, String>,
}

impl InMemoryCache {
    pub fn new() -> Self {
        Self {
            map: dashmap::DashMap::new(),
        }
    }
}

impl Default for InMemoryCache {
    fn default() -> Self {
        Self::new()
    }
}

impl CacheBackend for InMemoryCache {
    fn set(&self, key: &str, value: &str) {
        self.map.insert(key.to_string(), value.to_string());
    }

    fn get(&self, key: &str) -> Option<String> {
        self.map.get(key).map(|v| v.clone())
    }
}
