use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use serde::Serialize;

/// Number of one-second slots in the sliding window.
const SLOTS: usize = 60;
/// Number of latency histogram buckets. Bucket `i` covers latencies below `2^i * 50` microseconds.
const BUCKETS: usize = 24;
/// Base latency in microseconds for the first histogram bucket.
const BUCKET_BASE_US: u64 = 50;

/// A single one-second slot of the live statistics window. All counters are atomics so the hot
/// path only performs `fetch_add` and never blocks.
struct Slot {
    /// Second number (from process start) this slot belongs to.
    second: AtomicU64,
    requests: AtomicU64,
    errors: AtomicU64,
    tokens: AtomicU64,
    latency: [AtomicU64; BUCKETS],
}

impl Slot {
    fn new() -> Self {
        Slot {
            second: AtomicU64::new(0),
            requests: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            tokens: AtomicU64::new(0),
            latency: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    fn reset(&self, second: u64) {
        self.second.store(second, Ordering::Relaxed);
        self.requests.store(0, Ordering::Relaxed);
        self.errors.store(0, Ordering::Relaxed);
        self.tokens.store(0, Ordering::Relaxed);
        for b in &self.latency {
            b.store(0, Ordering::Relaxed);
        }
    }
}

/// Lock-free sliding-window statistics over the last 60 seconds. `record` is safe to call from
/// any number of concurrent request handlers.
pub struct LiveStats {
    slots: Vec<Slot>,
    started: Instant,
}

impl LiveStats {
    pub fn new() -> Self {
        LiveStats {
            slots: (0..SLOTS).map(|_| Slot::new()).collect(),
            started: Instant::now(),
        }
    }

    /// Records one request. `latency_us` is the total request latency in microseconds, `tokens`
    /// the token estimate and `status` the HTTP status. Errors are statuses >= 500 or 429.
    pub fn record(&self, latency_us: u64, tokens: u64, status: u16) {
        let second = self.started.elapsed().as_secs();
        let slot = &self.slots[(second % SLOTS as u64) as usize];
        if slot.second.load(Ordering::Relaxed) != second {
            // The slot belongs to an older second; claim it for the current one. A rare race
            // between two threads resetting the same slot is acceptable for demo statistics.
            let _ = slot.second.compare_exchange(
                slot.second.load(Ordering::Relaxed),
                second,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
            if slot.second.load(Ordering::Relaxed) == second {
                slot.reset(second);
            }
        }
        slot.requests.fetch_add(1, Ordering::Relaxed);
        if status >= 500 || status == 429 {
            slot.errors.fetch_add(1, Ordering::Relaxed);
        }
        slot.tokens.fetch_add(tokens, Ordering::Relaxed);
        let bucket = latency_bucket(latency_us);
        slot.latency[bucket].fetch_add(1, Ordering::Relaxed);
    }

    /// Builds a snapshot over the slots whose second falls within the last 60 seconds.
    pub fn snapshot(&self) -> StatsSnapshot {
        let uptime_sec = self.started.elapsed().as_secs();
        let window = uptime_sec.min(SLOTS as u64).max(1);
        let mut requests = 0u64;
        let mut errors = 0u64;
        let mut tokens = 0u64;
        let mut hist = [0u64; BUCKETS];
        let now = uptime_sec;
        for slot in &self.slots {
            let second = slot.second.load(Ordering::Relaxed);
            if now.saturating_sub(second) >= SLOTS as u64 {
                continue;
            }
            requests += slot.requests.load(Ordering::Relaxed);
            errors += slot.errors.load(Ordering::Relaxed);
            tokens += slot.tokens.load(Ordering::Relaxed);
            for (i, b) in slot.latency.iter().enumerate() {
                hist[i] += b.load(Ordering::Relaxed);
            }
        }
        let rps = requests as f64 / window as f64;
        let tps = tokens as f64 / window as f64;
        StatsSnapshot {
            window_sec: window,
            requests,
            rps,
            tps,
            errors,
            p50_ms: percentile_ms(&hist, 0.50),
            p95_ms: percentile_ms(&hist, 0.95),
            p99_ms: percentile_ms(&hist, 0.99),
            uptime_sec,
        }
    }
}

impl Default for LiveStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Maps a latency in microseconds to a histogram bucket index.
fn latency_bucket(latency_us: u64) -> usize {
    let mut bucket = 0usize;
    let mut bound = BUCKET_BASE_US;
    while bucket + 1 < BUCKETS && latency_us >= bound {
        bucket += 1;
        bound = bound.saturating_mul(2);
    }
    bucket
}

/// Computes a percentile (0..=1) from a histogram and returns the upper bound of the bucket in
/// milliseconds. Returns 0.0 when there are no samples.
fn percentile_ms(hist: &[u64; BUCKETS], p: f64) -> f64 {
    let total: u64 = hist.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let target = (total as f64 * p).ceil() as u64;
    let mut acc = 0u64;
    for (i, count) in hist.iter().enumerate() {
        acc += count;
        if acc >= target {
            let bound_us = BUCKET_BASE_US.saturating_mul(1u64 << i);
            return bound_us as f64 / 1000.0;
        }
    }
    let bound_us = BUCKET_BASE_US.saturating_mul(1u64 << (BUCKETS - 1));
    bound_us as f64 / 1000.0
}

/// Compact JSON view of the live statistics, served at `/stats`.
#[derive(Serialize)]
pub struct StatsSnapshot {
    pub window_sec: u64,
    pub requests: u64,
    pub rps: f64,
    pub tps: f64,
    pub errors: u64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub uptime_sec: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_stats_percentiles() {
        let stats = LiveStats::new();
        for _ in 0..100 {
            stats.record(1000, 10, 200);
        }
        let snap = stats.snapshot();
        assert_eq!(snap.requests, 100);
        assert!(snap.rps > 0.0);
        assert!(snap.p50_ms >= 1.0 && snap.p50_ms <= 2.0, "p50: {}", snap.p50_ms);
        assert!(snap.p99_ms >= snap.p50_ms, "p99 {} < p50 {}", snap.p99_ms, snap.p50_ms);
    }

    #[test]
    fn live_stats_errors() {
        let stats = LiveStats::new();
        stats.record(100, 5, 200);
        stats.record(100, 5, 500);
        stats.record(100, 5, 429);
        let snap = stats.snapshot();
        assert_eq!(snap.requests, 3);
        assert_eq!(snap.errors, 2);
    }
}