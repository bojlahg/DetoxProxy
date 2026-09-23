use crate::types::Mapping;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// In-memory mapping store keyed by payload_id / session_id. TTL + max entries. Values never leave the process.
pub struct MappingStore {
    inner: dashmap::DashMap<String, StoredEntrySealed>,
    /// Insertion order of keys, used for O(1) amortized eviction on overflow.
    order: Mutex<VecDeque<(String, Instant)>>,
    ttl: Duration,
    max_entries: usize,
    /// When true, `original` values are encrypted at rest inside the store.
    encrypt_mappings: bool,
    /// Per-process cipher; the key is generated once at startup and never persisted or logged.
    cipher: Option<ChaCha20Poly1305>,
}

/// A single mapping sealed at rest: the original value is stored only as ciphertext.
#[derive(Clone)]
struct SealedMapping {
    type_id: String,
    masked: String,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

/// Internal stored entry: mappings are kept sealed (encrypted) at rest.
struct StoredEntrySealed {
    mappings: Vec<SealedMapping>,
    masked_text: String,
    original_hash: String,
    created_at: std::time::Instant,
}

/// Public entry returned by `get`: mappings are decrypted back to plain `Mapping`s.
pub struct StoredEntry {
    pub mappings: Vec<Mapping>,
    /// First masked result for this id; returned again on identical repeat (idempotency).
    pub masked_text: String,
    /// Hash of the original payload, used to detect a retry of masking.
    pub original_hash: String,
    pub created_at: std::time::Instant,
}

impl std::fmt::Debug for MappingStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MappingStore")
            .field("len", &self.inner.len())
            .field("ttl", &self.ttl)
            .field("max_entries", &self.max_entries)
            .field("encrypt_mappings", &self.encrypt_mappings)
            .finish_non_exhaustive()
    }
}

impl MappingStore {
    pub fn new(ttl: Duration, max_entries: usize, encrypt_mappings: bool) -> Self {
        let cipher = if encrypt_mappings {
            let key = ChaCha20Poly1305::generate_key(&mut OsRng);
            Some(ChaCha20Poly1305::new(&key))
        } else {
            None
        };
        MappingStore {
            inner: dashmap::DashMap::new(),
            order: Mutex::new(VecDeque::new()),
            ttl,
            max_entries,
            encrypt_mappings,
            cipher,
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
            StoredEntrySealed {
                mappings: self.seal(mappings),
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
            mappings: self.unseal(&entry.mappings),
            masked_text: entry.masked_text.clone(),
            original_hash: entry.original_hash.clone(),
            created_at: entry.created_at,
        })
    }

    /// Encrypts the `original` field of each mapping when encryption is enabled.
    fn seal(&self, mappings: Vec<Mapping>) -> Vec<SealedMapping> {
        let Some(cipher) = &self.cipher else {
            return mappings
                .into_iter()
                .map(|m| SealedMapping {
                    type_id: m.type_id,
                    masked: m.masked,
                    nonce: [0; 12],
                    ciphertext: m.original.into_bytes(),
                })
                .collect();
        };
        mappings
            .into_iter()
            .map(|m| {
                let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
                let ciphertext = cipher
                    .encrypt(&nonce, m.original.as_bytes())
                    .expect("encrypt");
                SealedMapping {
                    type_id: m.type_id,
                    masked: m.masked,
                    nonce: nonce.into(),
                    ciphertext,
                }
            })
            .collect()
    }

    /// Decrypts the stored mappings back into plain `Mapping`s. A failed decryption is treated as
    /// an absent record and logged as a warning without any content.
    fn unseal(&self, sealed: &[SealedMapping]) -> Vec<Mapping> {
        let Some(cipher) = &self.cipher else {
            return sealed
                .iter()
                .map(|s| Mapping {
                    type_id: s.type_id.clone(),
                    original: String::from_utf8_lossy(&s.ciphertext).into_owned(),
                    masked: s.masked.clone(),
                })
                .collect();
        };
        sealed
            .iter()
            .filter_map(|s| {
                let plain = cipher
                    .decrypt(Nonce::from_slice(&s.nonce), s.ciphertext.as_ref())
                    .ok();
                match plain.and_then(|p| String::from_utf8(p).ok()) {
                    Some(original) => Some(Mapping {
                        type_id: s.type_id.clone(),
                        original,
                        masked: s.masked.clone(),
                    }),
                    None => {
                        tracing::warn!(type_id = %s.type_id, "failed to decrypt stored mapping; treating as absent");
                        None
                    }
                }
            })
            .collect()
    }

    /// Returns whether the stored entry for `id` contains `original` in its internal (sealed)
    /// representation. Used by tests to assert that plaintext originals are not kept at rest.
    pub fn contains_original(&self, id: &str, original: &str) -> bool {
        let Some(entry) = self.inner.get(id) else {
            return false;
        };
        entry
            .mappings
            .iter()
            .any(|m| m.ciphertext.windows(original.len()).any(|w| w == original.as_bytes()))
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