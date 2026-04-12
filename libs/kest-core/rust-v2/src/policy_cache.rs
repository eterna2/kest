use std::time::{Duration, Instant};
use dashmap::DashMap;

#[derive(Clone)]
struct CacheEntry {
    result: bool,
    expires_at: Instant,
}

pub struct PolicyCache {
    map: DashMap<String, CacheEntry>,
    ttl: Duration,
    max_size: usize,
}

impl PolicyCache {
    pub fn new(ttl: Duration, max_size: usize) -> Self {
        Self {
            map: DashMap::new(),
            ttl,
            max_size,
        }
    }

    pub fn get(&self, key: &str) -> Option<bool> {
        if let Some(entry) = self.map.get(key) {
            if Instant::now() < entry.expires_at {
                Some(entry.result)
            } else {
                drop(entry);
                self.map.remove(key); // lazy eviction
                None
            }
        } else {
            None
        }
    }

    pub fn insert(&self, key: String, result: bool) {
        // Simple capacity management: if full, do a sweep of expired items.
        // If still full after sweep, clear entirely to prevent memory bloat.
        if self.map.len() >= self.max_size {
            self.map.retain(|_, entry| Instant::now() < entry.expires_at);
            if self.map.len() >= self.max_size {
                self.map.clear();
            }
        }
        self.map.insert(key, CacheEntry {
            result,
            expires_at: Instant::now() + self.ttl,
        });
    }

    pub fn invalidate(&self) {
        self.map.clear();
    }
}
