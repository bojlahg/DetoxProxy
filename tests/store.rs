use pii_guard::store::MappingStore;
use pii_guard::types::Mapping;
use std::time::Duration;

#[test]
fn insert_get() {
    let store = MappingStore::new(Duration::from_secs(60), 100);
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
    let store = MappingStore::new(Duration::from_secs(60), 100);
    store.insert("id1", "first".to_string(), vec![]);
    store.insert("id1", "second".to_string(), vec![]);
    assert_eq!(store.len(), 1);
    assert_eq!(store.get("id1").unwrap().masked_text, "second");
}

#[test]
fn get_after_ttl_returns_none() {
    let store = MappingStore::new(Duration::from_millis(50), 100);
    store.insert("id1", "m".to_string(), vec![]);
    std::thread::sleep(Duration::from_millis(80));
    assert!(store.get("id1").is_none());
}

#[test]
fn sweep_removes_expired() {
    let store = MappingStore::new(Duration::from_millis(50), 100);
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
    let store = MappingStore::new(Duration::from_secs(60), 3);
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