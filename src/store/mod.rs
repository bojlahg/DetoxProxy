use crate::types::Mapping;
use std::time::Duration;

/// In-memory mapping store keyed by payload_id / session_id. TTL + max entries. Values never leave the process.
pub struct MappingStore {
    inner: dashmap::DashMap<String, StoredEntry>,
    ttl: Duration,
    max_entries: usize,
}
pub struct StoredEntry {
    pub mappings: Vec<Mapping>,
    /// First masked result for this id; returned again on identical repeat (idempotency).
    pub masked_text: String,
    pub created_at: std::time::Instant,
}
impl MappingStore {
    pub fn new(ttl: Duration, max_entries: usize) -> Self { todo!() }
    pub fn insert(&self, id: &str, masked_text: String, mappings: Vec<Mapping>) { todo!() }
    pub fn get(&self, id: &str) -> Option<StoredEntry> { todo!() }
    pub fn len(&self) -> usize { todo!() }
    pub fn is_empty(&self) -> bool { todo!() }
    /// Removes expired entries; called periodically.
    pub fn sweep(&self) -> usize { todo!() }
}