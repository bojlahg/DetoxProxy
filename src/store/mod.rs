use crate::types::Mapping;
use std::time::{Duration, Instant};

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
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        MappingStore {
            inner: dashmap::DashMap::new(),
            ttl,
            max_entries,
        }
    }

    pub fn insert(&self, id: &str, masked_text: String, mappings: Vec<Mapping>) {
        if self.inner.len() >= self.max_entries {
            self.sweep();
        }
        if self.inner.len() >= self.max_entries {
            self.evict_oldest();
        }
        self.inner.insert(
            id.to_string(),
            StoredEntry {
                mappings,
                masked_text,
                created_at: Instant::now(),
            },
        );
    }

    pub fn get(&self, id: &str) -> Option<StoredEntry> {
        let entry = self.inner.get(id)?;
        if entry.created_at.elapsed() > self.ttl {
            return None;
        }
        Some(StoredEntry {
            mappings: entry.mappings.clone(),
            masked_text: entry.masked_text.clone(),
            created_at: entry.created_at,
        })
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Removes expired entries; called periodically.
    pub fn sweep(&self) -> usize {
        let now = Instant::now();
        let mut removed = 0;
        self.inner.retain(|_, e| {
            if now.duration_since(e.created_at) > self.ttl {
                removed += 1;
                false
            } else {
                true
            }
        });
        removed
    }

    fn evict_oldest(&self) {
        let mut oldest: Option<(String, Instant)> = None;
        for entry in self.inner.iter() {
            match &oldest {
                Some((_, t)) if *t <= entry.created_at => {}
                _ => oldest = Some((entry.key().clone(), entry.created_at)),
            }
        }
        if let Some((key, _)) = oldest {
            self.inner.remove(&key);
        }
    }
}