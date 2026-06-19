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
    active: bool,
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
        if self.admissions.fetch_add(1, Ordering::Relaxed) % PRUNE_EVERY_N_ADMISSIONS == 0 {
            prune_expired_clients(&mut clients, &config, now);
        }
        let state = clients
            .entry(ip)
            .or_insert_with(|| Arc::new(Mutex::new(ClientState::new(now))))
            .clone();
        let mut state_guard = state.lock().unwrap_or_else(|e| e.into_inner());

        if is_limit_exceeded(
            &mut state_guard.auth_failures,
            config.auth_failure_rate.as_ref(),
            now,
        ) {
            return Err(DenialReason::AuthFailureRate);
        }
        if increment_window(
            &mut state_guard.connections,
            config.connection_rate.as_ref(),
            now,
        ) {
            return Err(DenialReason::ConnectionRate);
        }
        if let Some(limit) = config.concurrent_connections {
            if state_guard.active_connections >= limit {
                return Err(DenialReason::ConcurrentConnections);
            }
        }

        state_guard.active_connections += 1;
        // Reconcile the per-client bandwidth bucket with the current config so a
        // reload that adds or removes `byterate` takes effect on new admissions.
        // A changed rate keeps the existing bucket until the state is pruned.
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
                    .update_rate_window(limit.limit, limit.window);
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
            active: true,
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
        if self.admissions.fetch_add(1, Ordering::Relaxed) % PRUNE_EVERY_N_ADMISSIONS == 0 {
            prune_expired_clients(&mut clients, &config, now);
        }
        let state = clients
            .entry(ip)
            .or_insert_with(|| Arc::new(Mutex::new(ClientState::new(now))))
            .clone();
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

    pub fn disarm(mut self) {
        self.active = false;
    }
}

impl Drop for ClientPermit {
    fn drop(&mut self) {
        if self.active {
            self.controls.release(&self.state);
        }
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
            && self
                .bandwidth
                .as_ref()
                .is_none_or(|b| b.lock().unwrap_or_else(|e| e.into_inner()).is_full(now))
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
}
