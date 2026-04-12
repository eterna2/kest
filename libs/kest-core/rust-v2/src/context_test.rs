use super::context::*;
use std::collections::HashMap;
use std::thread;

#[test]
fn test_token_isolation() {
    let t1 = create();
    let t2 = create();

    assert_ne!(t1, t2);

    set(t1, "user".to_string(), "alice".to_string());
    set(t2, "user".to_string(), "bob".to_string());

    assert_eq!(get(t1, "user"), Some("alice".to_string()));
    assert_eq!(get(t2, "user"), Some("bob".to_string()));

    destroy(t1);
    destroy(t2);
}

#[test]
fn test_batch_set() {
    let t = create();
    let mut batch = HashMap::new();
    batch.insert("kest.user".to_string(), "alice".to_string());
    batch.insert("kest.agent".to_string(), "bot".to_string());

    set_batch(t, batch);

    assert_eq!(get(t, "kest.user"), Some("alice".to_string()));
    assert_eq!(get(t, "kest.agent"), Some("bot".to_string()));

    destroy(t);
}

#[test]
fn test_destroy_cleanup() {
    let t = create();
    set(t, "key".to_string(), "val".to_string());
    assert_eq!(get(t, "key"), Some("val".to_string()));

    destroy(t);
    assert_eq!(get(t, "key"), None);
}

#[test]
fn test_passport_roundtrip() {
    let t = create();
    let entries = vec!["jws1".to_string(), "jws2".to_string()];
    set_passport(t, entries.clone());

    assert_eq!(get_passport(t), Some(entries));
    destroy(t);
}

#[test]
fn test_async_safety_simulation() {
    // We simulate async tasks running on multiple threads by spawning 100 threads,
    // each creating a context, working with it, and destroying it.
    let mut handles = vec![];

    // No global assertion

    for i in 0..100 {
        handles.push(thread::spawn(move || {
            let t = create();
            let val = format!("val-{}", i);
            set(t, "key".to_string(), val.clone());
            
            // Sleep to force overlapping execution
            thread::sleep(std::time::Duration::from_millis(5));

            assert_eq!(get(t, "key"), Some(val));
            destroy(t);
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }
}
