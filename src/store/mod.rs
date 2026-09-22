use crate::types::Mapping;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// In-memory mapping store keyed by payload_id / session_id. TTL + max entries. Values never leave the process.
pub struct MappingStore {
    inner: dashmap::DashMap<String, StoredEntry>,
    /// Insertion order of keys, used for O(1) amortized eviction on overflow.
    order: Mutex<VecDeque<(String, Instant)>>,
    ttl: Duration,
    max_entries: usize,
}
pub struct StoredEntry {
    pub mappings: Vec<Mapping>,
    /// First masked result for this id; returned again on identical repeat (idempotency).
    pub masked_text: String,
    /// Hash of the original payload, used to detect a retry of masking.
    pub original_hash: String,
    pub created_at: std::time::Instant,
}
impl MappingStore {
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        MappingStore {
            inner: dashmap::DashMap::new(),
            order: Mutex::new(VecDeque::new()),
            ttl,
            max_entries,
        }
    }

    pub fn insert(&self, id: &str, masked_text: String, mappings: Vec<Mapping>) {
        self.insert_with_hash(id, masked_text, mappings, String::new());
    }

    pub fn insert_with_hash(&self, id: &str, masked_text: String, mappings: Vec<Mapping>, original_hash: String) {
        let now = Instant::now();
        self.order.lock().unwrap().push_back((id.to_string(), now));
        self.inner.insert(
            id.to_string(),
            StoredEntry {
                mappings,
                masked_text,
                original_hash,
                created_at: now,
            },
        );
        self.evict_overflow();
    }

    pub fn get(&self, id: &str) -> Option<StoredEntry> {
        let entry = self.inner.get(id)?;
        if entry.created_at.elapsed() > self.ttl {
            return None;
        }
        Some(StoredEntry {
            mappings: entry.mappings.clone(),
            masked_text: entry.masked_text.clone(),
            original_hash: entry.original_hash.clone(),
            created_at: entry.created_at,
        })
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Removes expired entries; called periodically. Also prunes the head of the insertion
    /// queue so it does not grow unbounded with already-removed keys.
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
        if removed > 0 {
            metrics::counter!("pii_store_expired_total").increment(removed as u64);
        }
        self.prune_order_queue();
        removed
    }

    /// Spawns a background task that periodically sweeps expired entries. The sweep runs on the
    /// blocking thread pool so a large table never blocks async workers.
    pub fn spawn_sweeper(self: &Arc<Self>, every: Duration) {
        let store = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(every);
            loop {
                interval.tick().await;
                let store2 = store.clone();
                let removed = tokio::task::spawn_blocking(move || store2.sweep())
                    .await
                    .unwrap_or(0);
                metrics::gauge!("pii_mappings_stored").set(store.len() as f64);
                if removed > 0 {
                    tracing::debug!(removed = removed, "store sweep");
                }
            }
        });
    }

    /// Evicts the oldest entries until the store is within `max_entries`. O(1) amortized: only
    /// walks the head of the insertion queue. A queued key is removed only if its recorded
    /// timestamp still matches the stored entry, so a re-inserted (fresh) key is never evicted
    /// by a stale queue entry. Keys already removed by a sweep are skipped.
    fn evict_overflow(&self) {
        let mut evicted = 0;
        while self.inner.len() > self.max_entries {
            let (key, t) = {
                let mut order = self.order.lock().unwrap();
                match order.pop_front() {
                    Some(pair) => pair,
                    None => break,
                }
            };
            if self.inner.remove_if(&key, |_, e| e.created_at == t).is_some() {
                evicted += 1;
            }
        }
        if evicted > 0 {
            metrics::counter!("pii_store_evictions_total").increment(evicted as u64);
        }
    }

    /// Drops queue entries whose key is no longer present in the map (already swept or evicted).
    fn prune_order_queue(&self) {
        let mut order = self.order.lock().unwrap();
        while let Some(front) = order.front() {
            if self.inner.contains_key(&front.0) {
                break;
            }
            order.pop_front();
        }
    }
}