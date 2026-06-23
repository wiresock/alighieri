//! Per-client abuse controls.
//!
//! The server owns one shared `AbuseControls` instance. It admits or rejects
//! newly accepted client sockets, records authentication failures, and exposes
//! a byte-accounting hook used by relay code.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use crate::config::{RateLimit, RateLimits};
use crate::throttle::TokenBucket;

/// How many admissions may pass between sweeps of expired client entries.
/// Pruning scans the whole client map, so doing it on every accepted
/// connection makes the accept path O(tracked clients); expired entries are
/// harmless in the meantime because windows reset on access.
const PRUNE_EVERY_N_ADMISSIONS: u64 = 64;

/// Soft cap on tracked client states. Without it, a spray from many distinct
/// source IPs would grow the map (and the O(n) prune scan that runs under the
/// global lock) unbounded. A new client at the cap evicts an idle entry to make
/// room (see [`evict_idle_clients`]). Only *idle* states are evicted, so the map
/// can still exceed the cap by the number of concurrently active clients — but
/// that is bounded by `maxconnections`, so the map stays bounded overall (near
/// 10 MB at ~150 bytes per entry, plus the active set).
const MAX_TRACKED_CLIENTS: usize = 65_536;

#[derive(Debug)]
pub struct AbuseControls {
    config: RwLock<RateLimits>,
    clients: Mutex<HashMap<IpAddr, Arc<Mutex<ClientState>>>>,
    admissions: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenialReason {
    ConnectionRate,
    AuthFailureRate,
    ConcurrentConnections,
}

impl DenialReason {
    pub fn as_str(self) -> &'static str {
        match self {
            DenialReason::ConnectionRate => "connection rate limit exceeded",
            DenialReason::AuthFailureRate => "auth failure rate limit exceeded",
            DenialReason::ConcurrentConnections => "concurrent connection limit exceeded",
        }
    }
}

#[derive(Debug)]
pub struct ClientPermit {
    controls: Arc<AbuseControls>,
    state: Arc<Mutex<ClientState>>,
    bandwidth: Option<Arc<Mutex<TokenBucket>>>,
}

impl AbuseControls {
    pub fn new(config: RateLimits) -> Arc<Self> {
        Arc::new(Self {
            config: RwLock::new(config),
            clients: Mutex::new(HashMap::new()),
            admissions: AtomicU64::new(0),
        })
    }

    pub fn update_config(&self, config: RateLimits) {
        *self.config.write().unwrap_or_else(|e| e.into_inner()) = config;
    }

    pub fn admit(self: &Arc<Self>, ip: IpAddr) -> Result<ClientPermit, DenialReason> {
        let config = self
            .config
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let state = checkout_state(&self.admissions, &mut clients, ip, &config, now);
        // Hold the global `clients` lock until the permit is built: it keeps the
        // freshly checked-out state in the map (so a concurrent prune/eviction
        // cannot drop it) until `active_connections` is incremented below.
        let mut state_guard = state.lock().unwrap_or_else(|e| e.into_inner());

        if is_limit_exceeded(
            &mut state_guard.auth_failures,
            config.auth_failure_rate.as_ref(),
            now,
        ) {
            return Err(DenialReason::AuthFailureRate);
        }
        // Check the concurrent-connection limit before the connection-rate
        // window so a connection rejected for concurrency does not also consume
        // rate budget (it was never admitted).
        if let Some(limit) = config.concurrent_connections {
            if state_guard.active_connections >= limit {
                return Err(DenialReason::ConcurrentConnections);
            }
        }
        if increment_window(
            &mut state_guard.connections,
            config.connection_rate.as_ref(),
            now,
        ) {
            return Err(DenialReason::ConnectionRate);
        }

        state_guard.active_connections += 1;
        // Reconcile the per-client bandwidth bucket with the current config so a
        // reload takes effect: add or drop the bucket when `byterate` is enabled
        // or disabled, and re-tune the existing shared bucket in place when the
        // rate changes, applying to the client's ongoing flows at once.
        match (&config.byte_rate, &state_guard.bandwidth) {
            (Some(limit), None) => {
                state_guard.bandwidth =
                    TokenBucket::from_rate_window(limit.limit, limit.window, now)
                        .map(|b| Arc::new(Mutex::new(b)));
            }
            (Some(limit), Some(bucket)) => {
                // Re-tune the existing shared bucket in place so a reloaded rate
                // applies to this client's ongoing flows, not just new clients.
                bucket
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .update_rate_window(limit.limit, limit.window, now);
            }
            (None, Some(_)) => state_guard.bandwidth = None,
            (None, None) => {}
        }
        let bandwidth = state_guard.bandwidth.clone();
        drop(state_guard);
        Ok(ClientPermit {
            controls: self.clone(),
            state,
            bandwidth,
        })
    }

    pub fn record_auth_failure(&self, ip: IpAddr) {
        let config = self
            .config
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let state = checkout_state(&self.admissions, &mut clients, ip, &config, now);
        let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
        let _ = increment_window(
            &mut state.auth_failures,
            config.auth_failure_rate.as_ref(),
            now,
        );
    }

    fn release(&self, state: &Mutex<ClientState>) {
        let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
        state.active_connections = state.active_connections.saturating_sub(1);
    }
}

impl ClientPermit {
    /// The shared per-client token bucket (when `byterate` is configured), used
    /// to throttle this client's relays. All of one client's connections share
    /// it, so the limit is an aggregate over both directions of every flow.
    pub fn throttle_bucket(&self) -> Option<Arc<Mutex<TokenBucket>>> {
        self.bandwidth.clone()
    }
}

impl Drop for ClientPermit {
    fn drop(&mut self) {
        self.controls.release(&self.state);
    }
}

#[derive(Debug)]
struct ClientState {
    connections: Window,
    auth_failures: Window,
    /// Shared per-client bandwidth bucket; `None` until `byterate` applies.
    bandwidth: Option<Arc<Mutex<TokenBucket>>>,
    active_connections: usize,
}

impl ClientState {
    fn new(now: Instant) -> Self {
        Self {
            connections: Window::new(now),
            auth_failures: Window::new(now),
            bandwidth: None,
            active_connections: 0,
        }
    }
}

#[derive(Debug)]
struct Window {
    started: Instant,
    count: u64,
}

impl Window {
    fn new(now: Instant) -> Self {
        Self {
            started: now,
            count: 0,
        }
    }
}

fn reset_if_expired(window: &mut Window, limit: &RateLimit, now: Instant) {
    if now.duration_since(window.started) >= limit.window {
        window.started = now;
        window.count = 0;
    }
}

fn is_limit_exceeded(window: &mut Window, limit: Option<&RateLimit>, now: Instant) -> bool {
    let Some(limit) = limit else {
        return false;
    };
    reset_if_expired(window, limit, now);
    window.count >= limit.limit
}

fn increment_window(window: &mut Window, limit: Option<&RateLimit>, now: Instant) -> bool {
    let Some(limit) = limit else {
        return false;
    };
    reset_if_expired(window, limit, now);
    window.count = window.count.saturating_add(1);
    window.count > limit.limit
}

/// Looks up or creates the per-client state for `ip` under the already-held
/// `clients` lock, running the amortized prune and — at the cap — evicting an
/// idle entry, so the map and its prune scan stay bounded. Shared by `admit`
/// and `record_auth_failure`.
fn checkout_state(
    admissions: &AtomicU64,
    clients: &mut HashMap<IpAddr, Arc<Mutex<ClientState>>>,
    ip: IpAddr,
    config: &RateLimits,
    now: Instant,
) -> Arc<Mutex<ClientState>> {
    let due = admissions
        .fetch_add(1, Ordering::Relaxed)
        .is_multiple_of(PRUNE_EVERY_N_ADMISSIONS);
    // Prune only on the amortized schedule. At the cap, `clients.len() >= cap`
    // holds on every new-IP connection, so forcing a full O(n) prune there would
    // run it on *every* connection instead of every Nth — worse than the
    // unbounded version. The eviction below already keeps the map bounded.
    if due {
        prune_expired_clients(clients, config, now);
    }
    // A brand-new client at the cap: evict an idle entry to make room so a spray
    // from many distinct source IPs cannot grow the map without bound. With
    // `target = cap - 1` only one victim is needed, so this stops at the first
    // idle (non-active) entry rather than scanning the whole map.
    if clients.len() >= MAX_TRACKED_CLIENTS && !clients.contains_key(&ip) {
        evict_idle_clients(clients, MAX_TRACKED_CLIENTS - 1);
    }
    clients
        .entry(ip)
        .or_insert_with(|| Arc::new(Mutex::new(ClientState::new(now))))
        .clone()
}

fn prune_expired_clients(
    clients: &mut HashMap<IpAddr, Arc<Mutex<ClientState>>>,
    config: &RateLimits,
    now: Instant,
) {
    clients.retain(|_, state| match state.try_lock() {
        Ok(state) => !state.is_expired(config, now),
        Err(_) => true,
    });
}

/// Evicts idle (no active connections) client states until the map holds at most
/// `target` entries. Active states are never evicted — a live `ClientPermit`
/// references them for connection accounting, and dropping one would split a
/// client's concurrent-connection count across two states. Best-effort: if too
/// few states are idle the map may briefly exceed `target` (bounded by the live
/// connection count), and evicting an idle debt-owing state yields its
/// burst-evasion protection to the hard memory bound.
fn evict_idle_clients(clients: &mut HashMap<IpAddr, Arc<Mutex<ClientState>>>, target: usize) {
    if clients.len() <= target {
        return;
    }
    let excess = clients.len() - target;
    let victims: Vec<IpAddr> = clients
        .iter()
        // A state we cannot lock is in active use, so treat it as not idle.
        .filter(|(_, state)| state.try_lock().is_ok_and(|g| g.active_connections == 0))
        .take(excess)
        .map(|(ip, _)| *ip)
        .collect();
    for ip in victims {
        clients.remove(&ip);
    }
}

impl ClientState {
    fn is_expired(&self, config: &RateLimits, now: Instant) -> bool {
        // Keep the state alive while its bandwidth bucket still owes throttled
        // bytes (is not full), so a client cannot shed accumulated debt — and
        // regain a fresh burst — by briefly disconnecting and reconnecting. Once
        // the bucket has refilled, the client has earned that burst and pruning
        // (which only resets it to full anyway) is safe.
        self.active_connections == 0
            && window_is_prunable(&self.connections, config.connection_rate.as_ref(), now)
            && window_is_prunable(&self.auth_failures, config.auth_failure_rate.as_ref(), now)
            && self.bandwidth.as_ref().is_none_or(|b| {
                // Best-effort: the prune sweep holds the global clients lock, so
                // never block it on a bucket a relay may be using. A bucket we
                // cannot lock is in active use, hence not prunable.
                b.try_lock().is_ok_and(|mut g| g.is_full(now))
            })
    }
}

fn window_is_prunable(window: &Window, limit: Option<&RateLimit>, now: Instant) -> bool {
    let Some(limit) = limit else {
        return true;
    };
    window.count == 0 || now.duration_since(window.started) >= limit.window
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ip() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    #[test]
    fn enforces_connection_rate() {
        let controls = AbuseControls::new(RateLimits {
            connection_rate: Some(RateLimit {
                limit: 1,
                window: Duration::from_secs(60),
            }),
            ..RateLimits::default()
        });

        let _permit = controls.admit(ip()).unwrap();
        let err = controls.admit(ip()).unwrap_err();
        assert_eq!(err, DenialReason::ConnectionRate);
    }

    #[test]
    fn releases_concurrent_connection_permit_on_drop() {
        let controls = AbuseControls::new(RateLimits {
            concurrent_connections: Some(1),
            ..RateLimits::default()
        });

        let permit = controls.admit(ip()).unwrap();
        assert_eq!(
            controls.admit(ip()).unwrap_err(),
            DenialReason::ConcurrentConnections
        );
        drop(permit);
        assert!(controls.admit(ip()).is_ok());
    }

    #[test]
    fn auth_failures_block_later_connections() {
        let controls = AbuseControls::new(RateLimits {
            auth_failure_rate: Some(RateLimit {
                limit: 1,
                window: Duration::from_secs(60),
            }),
            ..RateLimits::default()
        });

        controls.record_auth_failure(ip());
        assert_eq!(
            controls.admit(ip()).unwrap_err(),
            DenialReason::AuthFailureRate
        );
    }

    #[test]
    fn byte_rate_yields_a_shared_per_client_bucket() {
        let controls = AbuseControls::new(RateLimits {
            byte_rate: Some(RateLimit {
                limit: 4,
                window: Duration::from_secs(60),
            }),
            ..RateLimits::default()
        });

        // Two connections from the same client share one bandwidth bucket.
        let a = controls.admit(ip()).unwrap();
        let b = controls.admit(ip()).unwrap();
        let bucket_a = a.throttle_bucket().expect("byterate yields a bucket");
        let bucket_b = b.throttle_bucket().expect("byterate yields a bucket");
        assert!(Arc::ptr_eq(&bucket_a, &bucket_b));
    }

    #[test]
    fn no_byte_rate_yields_no_bucket() {
        let controls = AbuseControls::new(RateLimits::default());
        let permit = controls.admit(ip()).unwrap();
        assert!(permit.throttle_bucket().is_none());
    }

    #[test]
    fn reload_retunes_existing_bucket_in_place() {
        let controls = AbuseControls::new(RateLimits {
            byte_rate: Some(RateLimit {
                limit: 1000,
                window: Duration::from_secs(1),
            }),
            ..RateLimits::default()
        });
        let first = controls.admit(ip()).unwrap();
        let bucket = first.throttle_bucket().unwrap();

        // Reload with a different rate, then re-admit the same client.
        controls.update_config(RateLimits {
            byte_rate: Some(RateLimit {
                limit: 5000,
                window: Duration::from_secs(1),
            }),
            ..RateLimits::default()
        });
        let second = controls.admit(ip()).unwrap();

        // The bucket is re-tuned in place (the same instance), not recreated, so
        // the new rate applies to the client's ongoing flows immediately.
        assert!(Arc::ptr_eq(&bucket, &second.throttle_bucket().unwrap()));
    }

    #[test]
    fn drained_bandwidth_state_survives_prune_until_refilled() {
        use crate::throttle::Throttle;
        // Only byterate is set, so nothing but the bandwidth bucket gates pruning.
        let controls = AbuseControls::new(RateLimits {
            byte_rate: Some(RateLimit {
                limit: 1000,
                window: Duration::from_secs(60),
            }),
            ..RateLimits::default()
        });
        let drained = "127.0.0.9".parse().unwrap();
        let permit = controls.admit(drained).unwrap();
        let bucket = permit.throttle_bucket().unwrap();
        // Spend the whole bucket, then go idle.
        assert!(Throttle::new().with_bucket(bucket).police(1000));
        drop(permit);

        // Drive enough admissions of another client to trigger a prune sweep.
        let other = ip();
        for _ in 0..PRUNE_EVERY_N_ADMISSIONS {
            drop(controls.admit(other).unwrap());
        }

        // The drained client still owes throttled bytes, so its state was kept —
        // it cannot reconnect into a fresh burst.
        assert!(controls.clients.lock().unwrap().contains_key(&drained));
    }

    #[test]
    fn prunes_expired_idle_client_states_on_amortized_sweep() {
        let controls = AbuseControls::new(RateLimits {
            connection_rate: Some(RateLimit {
                limit: u64::MAX,
                window: Duration::ZERO,
            }),
            ..RateLimits::default()
        });

        let first = "127.0.0.1".parse().unwrap();
        let second = "127.0.0.2".parse().unwrap();
        drop(controls.admit(first).unwrap());
        assert_eq!(controls.clients.lock().unwrap().len(), 1);

        // Pruning is amortized; admit until the next sweep fires and confirm
        // the expired idle entry is gone while the active one remains.
        for _ in 0..PRUNE_EVERY_N_ADMISSIONS {
            drop(controls.admit(second).unwrap());
        }
        let clients = controls.clients.lock().unwrap();
        assert_eq!(clients.len(), 1);
        assert!(clients.contains_key(&second));
    }

    #[test]
    fn evict_idle_clients_drops_idle_but_keeps_active() {
        let now = Instant::now();
        let mut clients: HashMap<IpAddr, Arc<Mutex<ClientState>>> = HashMap::new();
        for i in 0..5u8 {
            clients.insert(
                IpAddr::from([10, 0, 0, i]),
                Arc::new(Mutex::new(ClientState::new(now))),
            );
        }
        let active_ip = IpAddr::from([10, 0, 0, 100]);
        let active = Arc::new(Mutex::new(ClientState::new(now)));
        active.lock().unwrap().active_connections = 1;
        clients.insert(active_ip, active);
        assert_eq!(clients.len(), 6);

        // Evict down to two: idle states are dropped, the active one survives.
        evict_idle_clients(&mut clients, 2);
        assert_eq!(clients.len(), 2);
        assert!(
            clients.contains_key(&active_ip),
            "an active state must never be evicted"
        );
    }

    #[test]
    fn evict_idle_clients_never_drops_active_even_over_target() {
        let now = Instant::now();
        let mut clients: HashMap<IpAddr, Arc<Mutex<ClientState>>> = HashMap::new();
        for i in 0..3u8 {
            let state = Arc::new(Mutex::new(ClientState::new(now)));
            state.lock().unwrap().active_connections = 1;
            clients.insert(IpAddr::from([10, 0, 0, i]), state);
        }
        // Nothing is idle, so the map stays put even though it exceeds the target.
        evict_idle_clients(&mut clients, 1);
        assert_eq!(clients.len(), 3);
    }
}
