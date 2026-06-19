//! Token-bucket bandwidth throttling.
//!
//! A [`TokenBucket`] meters bytes: it refills at a fixed rate (bytes per second)
//! up to a capacity (the burst allowance). Two enforcement styles use it:
//!
//! - **Shaping** (TCP): [`Throttle::shape`] awaits until the requested bytes are
//!   covered, so the relay *slows* — the read loop pauses and TCP backpressure
//!   builds — instead of tearing the connection down.
//! - **Policing** (UDP): [`Throttle::police`] consumes without waiting and tells
//!   the caller to drop the datagram when the bucket cannot cover it, because
//!   delaying a real-time datagram is worse than dropping it.
//!
//! A [`Throttle`] groups the buckets governing one flow (for example a
//! per-client bucket and, later, a per-rule bucket); the flow must satisfy every
//! bucket, so the effective limit is the most restrictive one.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A token bucket metering bytes.
#[derive(Debug)]
pub struct TokenBucket {
    /// Maximum tokens (the burst allowance), in bytes.
    capacity: f64,
    /// Refill rate, in bytes per second.
    rate: f64,
    /// Current tokens, in bytes. May go negative under [`TokenBucket::reserve`]
    /// to represent bytes promised but not yet refilled, so successive
    /// reservations queue in order.
    tokens: f64,
    /// When `tokens` was last refilled.
    last: Instant,
}

impl TokenBucket {
    /// Creates a bucket that refills at `rate` bytes/sec up to `capacity` bytes,
    /// starting full so an initially idle client may burst up to `capacity`.
    pub fn new(rate: f64, capacity: f64, now: Instant) -> Self {
        TokenBucket {
            capacity,
            rate,
            tokens: capacity,
            last: now,
        }
    }

    /// Builds a bucket from a `BYTES/WINDOW` limit: it sustains `bytes / window`
    /// per second and bursts up to `bytes`. Returns `None` for a degenerate
    /// limit (zero bytes or window) that cannot define a rate.
    pub fn from_rate_window(bytes: u64, window: Duration, now: Instant) -> Option<Self> {
        let secs = window.as_secs_f64();
        if bytes == 0 || secs <= 0.0 {
            return None;
        }
        Some(TokenBucket::new(bytes as f64 / secs, bytes as f64, now))
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
            self.last = now;
        }
    }

    /// Reserves `bytes` for shaping, returning how long the caller should wait
    /// before sending them. Tokens may go negative so that back-to-back
    /// reservations queue in order and the long-run rate is held to `rate`.
    fn reserve(&mut self, bytes: u64, now: Instant) -> Duration {
        self.refill(now);
        self.tokens -= bytes as f64;
        if self.tokens >= 0.0 || self.rate <= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-self.tokens / self.rate)
        }
    }

    /// Refills and reports whether `bytes` are available now, without consuming
    /// them — the peek half of policing.
    fn has(&mut self, bytes: u64, now: Instant) -> bool {
        self.refill(now);
        self.tokens >= bytes as f64
    }

    /// Consumes `bytes` a prior [`TokenBucket::has`] confirmed are available.
    fn take(&mut self, bytes: u64) {
        self.tokens -= bytes as f64;
    }
}

/// The token buckets governing one relayed flow. A flow must satisfy every
/// bucket, so the effective limit is the most restrictive one. An empty
/// `Throttle` imposes no limit.
#[derive(Clone, Default)]
pub struct Throttle {
    buckets: Vec<Arc<Mutex<TokenBucket>>>,
}

impl Throttle {
    /// An unlimited throttle (no buckets).
    pub fn new() -> Self {
        Throttle::default()
    }

    /// Adds a bucket the flow must satisfy. Buckets are added most-general
    /// first (per-client, then per-rule) so every flow locks them in the same
    /// order under [`Throttle::police`].
    pub fn with_bucket(mut self, bucket: Arc<Mutex<TokenBucket>>) -> Self {
        self.buckets.push(bucket);
        self
    }

    /// True when no bucket limits the flow.
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    /// Shapes a TCP write: waits until every bucket covers `bytes`, applying
    /// backpressure to the relay rather than dropping data. No lock is held
    /// across the await.
    pub async fn shape(&self, bytes: u64) {
        let wait = {
            let now = Instant::now();
            let mut wait = Duration::ZERO;
            for bucket in &self.buckets {
                let mut bucket = bucket.lock().unwrap_or_else(|e| e.into_inner());
                wait = wait.max(bucket.reserve(bytes, now));
            }
            wait
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }

    /// Polices a UDP datagram: returns `true` to forward (consuming `bytes` from
    /// every bucket) or `false` to drop it when any bucket is short.
    /// Consumption is all-or-nothing, so a dropped datagram costs no tokens.
    pub fn police(&self, bytes: u64) -> bool {
        if self.buckets.is_empty() {
            return true;
        }
        let now = Instant::now();
        let mut guards: Vec<_> = self
            .buckets
            .iter()
            .map(|b| b.lock().unwrap_or_else(|e| e.into_inner()))
            .collect();
        if guards.iter_mut().all(|g| g.has(bytes, now)) {
            for g in guards.iter_mut() {
                g.take(bytes);
            }
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bucket(rate: f64, capacity: f64) -> Arc<Mutex<TokenBucket>> {
        Arc::new(Mutex::new(TokenBucket::new(rate, capacity, Instant::now())))
    }

    #[test]
    fn from_rate_window_rejects_degenerate_limits() {
        let now = Instant::now();
        assert!(TokenBucket::from_rate_window(0, Duration::from_secs(1), now).is_none());
        assert!(TokenBucket::from_rate_window(10, Duration::ZERO, now).is_none());
        assert!(TokenBucket::from_rate_window(10, Duration::from_secs(1), now).is_some());
    }

    #[test]
    fn reserve_is_free_within_burst_then_charges_time() {
        let now = Instant::now();
        // 100 B/s, burst 100 B.
        let mut b = TokenBucket::new(100.0, 100.0, now);
        // The first 100 bytes fit in the burst and cost no wait.
        assert_eq!(b.reserve(100, now), Duration::ZERO);
        // The next 50 bytes must wait ~0.5s for the refill.
        let wait = b.reserve(50, now);
        assert!(
            (wait.as_secs_f64() - 0.5).abs() < 1e-6,
            "unexpected wait {wait:?}"
        );
    }

    #[test]
    fn reserve_debt_is_repaid_by_elapsed_time() {
        let start = Instant::now();
        let mut b = TokenBucket::new(100.0, 100.0, start);
        let _ = b.reserve(100, start); // empties the burst
        let _ = b.reserve(100, start); // goes 100 into debt
                                       // After 1s, 100 bytes have refilled, clearing the debt: the next small
                                       // reserve is free again.
        let later = start + Duration::from_secs(1);
        assert_eq!(b.reserve(0, later), Duration::ZERO);
    }

    #[test]
    fn police_forwards_within_capacity_and_drops_when_short() {
        let now = Instant::now();
        let throttle =
            Throttle::new().with_bucket(Arc::new(Mutex::new(TokenBucket::new(10.0, 10.0, now))));
        assert!(throttle.police(10)); // spends the whole bucket
        assert!(!throttle.police(1)); // now empty → drop
    }

    #[test]
    fn police_is_all_or_nothing_across_buckets() {
        // A generous bucket and a tiny one: a datagram larger than the tiny
        // bucket is dropped, and must not have spent the generous bucket.
        let big = bucket(1000.0, 1000.0);
        let small = bucket(2.0, 2.0);
        let throttle = Throttle::new()
            .with_bucket(big.clone())
            .with_bucket(small.clone());

        assert!(!throttle.police(5));
        // The big bucket still has its full capacity (nothing was consumed).
        assert!(big.lock().unwrap().has(1000, Instant::now()));
    }

    #[test]
    fn empty_throttle_never_limits() {
        let throttle = Throttle::new();
        assert!(throttle.is_empty());
        assert!(throttle.police(1_000_000));
    }

    #[tokio::test(start_paused = true)]
    async fn shape_sleeps_to_hold_the_rate() {
        // 1000 B/s, burst 1000 B. Spend the burst, then a further 1000 B must
        // take ~1s of shaped waiting. The sleep advances tokio's (paused) clock,
        // so measure that rather than wall-clock time.
        let throttle = Throttle::new().with_bucket(bucket(1000.0, 1000.0));
        throttle.shape(1000).await; // free (burst)
        let start = tokio::time::Instant::now();
        throttle.shape(1000).await; // waits ~1s of virtual time
        assert!(
            start.elapsed() >= Duration::from_millis(990),
            "shaped wait was only {:?}",
            start.elapsed()
        );
    }
}
