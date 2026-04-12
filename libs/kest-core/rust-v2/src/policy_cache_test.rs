use super::policy_cache::PolicyCache;
use std::time::Duration;
use std::thread;

#[test]
fn test_cache_hit_miss() {
    let cache = PolicyCache::new(Duration::from_secs(10), 100);
    assert_eq!(cache.get("key"), None);

    cache.insert("key".to_string(), true);
    assert_eq!(cache.get("key"), Some(true));
}

#[test]
fn test_ttl_expiry() {
    let cache = PolicyCache::new(Duration::from_millis(10), 100);
    cache.insert("key".to_string(), true);
    
    assert_eq!(cache.get("key"), Some(true));
    thread::sleep(Duration::from_millis(15));
    assert_eq!(cache.get("key"), None); // lazy eviction on get
}

#[test]
fn test_eviction_when_full() {
    // Capacity 3
    let cache = PolicyCache::new(Duration::from_secs(10), 3);
    
    cache.insert("k1".to_string(), true);
    cache.insert("k2".to_string(), true);
    cache.insert("k3".to_string(), true);
    
    // The next insert should trigger eviction (clearing all if nothing expired)
    cache.insert("k4".to_string(), true);
    
    assert_eq!(cache.get("k1"), None); // It was wiped
    assert_eq!(cache.get("k2"), None);
    assert_eq!(cache.get("k4"), Some(true)); // The new one is there
}

#[test]
fn test_invalidate() {
    let cache = PolicyCache::new(Duration::from_secs(10), 100);
    cache.insert("key".to_string(), true);
    cache.invalidate();
    assert_eq!(cache.get("key"), None);
}

#[test]
fn test_stress_concurrent_access() {
    let cache = std::sync::Arc::new(PolicyCache::new(Duration::from_secs(10), 1000));
    let mut handles = vec![];

    for i in 0..100 {
        let c = cache.clone();
        handles.push(thread::spawn(move || {
            let k = format!("k{}", i);
            c.insert(k.clone(), true);
            assert_eq!(c.get(&k), Some(true));
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}
