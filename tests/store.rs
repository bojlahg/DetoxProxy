use detox_proxy::store::MappingStore;
use detox_proxy::types::Mapping;
use std::time::Duration;

#[test]
fn insert_get() {
    let store = MappingStore::new(Duration::from_secs(60), 100, true);
    assert!(store.is_empty());
    store.insert(
        "id1",
        "masked".to_string(),
        vec![Mapping {
            type_id: "inn".into(),
            original: "7707083893".into(),
            masked: "<<INN_1>>".into(),
        }],
    );
    assert_eq!(store.len(), 1);
    assert!(!store.is_empty());
    let e = store.get("id1").expect("entry present");
    assert_eq!(e.masked_text, "masked");
    assert_eq!(e.mappings.len(), 1);
    assert_eq!(e.mappings[0].original, "7707083893");
}

#[test]
fn insert_overwrites() {
    let store = MappingStore::new(Duration::from_secs(60), 100, true);
    store.insert("id1", "first".to_string(), vec![]);
    store.insert("id1", "second".to_string(), vec![]);
    assert_eq!(store.len(), 1);
    assert_eq!(store.get("id1").unwrap().masked_text, "second");
}

#[test]
fn get_after_ttl_returns_none() {
    let store = MappingStore::new(Duration::from_millis(50), 100, true);
    store.insert("id1", "m".to_string(), vec![]);
    std::thread::sleep(Duration::from_millis(80));
    assert!(store.get("id1").is_none());
}

#[test]
fn sweep_removes_expired() {
    let store = MappingStore::new(Duration::from_millis(50), 100, true);
    store.insert("old", "m".to_string(), vec![]);
    std::thread::sleep(Duration::from_millis(80));
    store.insert("fresh", "m".to_string(), vec![]);
    let removed = store.sweep();
    assert_eq!(removed, 1);
    assert_eq!(store.len(), 1);
    assert!(store.get("old").is_none());
    assert!(store.get("fresh").is_some());
}

#[test]
fn max_entries_evicts_oldest() {
    let store = MappingStore::new(Duration::from_secs(60), 3, true);
    for id in ["a", "b", "c", "d", "e"] {
        store.insert(id, "m".to_string(), vec![]);
    }
    assert!(store.len() <= 3);
    assert!(store.get("e").is_some());
    assert!(store.get("d").is_some());
    assert!(store.get("c").is_some());
    assert!(store.get("a").is_none());
    assert!(store.get("b").is_none());
}

#[test]
fn max_entries_evicts_oldest_large() {
    let store = MappingStore::new(Duration::from_secs(60), 1000, true);
    for i in 0..5000 {
        store.insert(&format!("id{i}"), "m".to_string(), vec![]);
    }
    assert!(store.len() <= 1000);
    for i in 0..4000 {
        assert!(store.get(&format!("id{i}")).is_none(), "old id{i} should be evicted");
    }
    for i in 4000..5000 {
        assert!(store.get(&format!("id{i}")).is_some(), "recent id{i} should be present");
    }
}

#[test]
fn insert_200k_within_budget() {
    if cfg!(debug_assertions) {
        return;
    }
    let store = MappingStore::new(Duration::from_secs(60), 10_000, true);
    let start = std::time::Instant::now();
    for i in 0..200_000 {
        store.insert(&format!("id{i}"), "m".to_string(), vec![]);
    }
    let elapsed = start.elapsed();
    assert!(store.len() <= 10_000);
    assert!(
        elapsed.as_secs() < 2,
        "200k inserts took {elapsed:?}, expected under 2s"
    );
}

#[test]
fn sweep_removes_expired_and_get_none() {
    let store = MappingStore::new(Duration::from_millis(50), 100, true);
    store.insert("old", "m".to_string(), vec![]);
    std::thread::sleep(Duration::from_millis(80));
    store.insert("fresh", "m".to_string(), vec![]);
    let removed = store.sweep();
    assert_eq!(removed, 1);
    assert_eq!(store.len(), 1);
    assert!(store.get("old").is_none());
    assert!(store.get("fresh").is_some());
}

#[test]
fn reinserted_key_not_evicted_by_stale_queue_entry() {
    let store = MappingStore::new(Duration::from_secs(60), 3, true);
    store.insert("a", "m".to_string(), vec![]);
    store.insert("b", "m".to_string(), vec![]);
    store.insert("c", "m".to_string(), vec![]);
    store.insert("a", "m".to_string(), vec![]);
    store.insert("d", "m".to_string(), vec![]);
    assert!(store.len() <= 3);
    assert!(store.get("a").is_some(), "fresh a should survive");
    assert!(store.get("d").is_some());
    assert!(store.get("b").is_none(), "b should be evicted");
}

#[test]
fn stored_mappings_are_encrypted() {
    let store = MappingStore::new(Duration::from_secs(60), 100, true);
    let original = "7707083893";
    store.insert(
        "id1",
        "masked".to_string(),
        vec![Mapping {
            type_id: "inn".into(),
            original: original.into(),
            masked: "<<INN_1>>".into(),
        }],
    );
    let stored = store.contains_original("id1", original);
    assert!(
        !stored,
        "original value must not appear in the stored representation"
    );
    let e = store.get("id1").expect("entry present");
    assert_eq!(e.mappings[0].original, original);
    assert_eq!(e.mappings[0].masked, "<<INN_1>>");
}