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
    ByteRate,
}

impl DenialReason {
    pub fn as_str(self) -> &'static str {
        match self {
            DenialReason::ConnectionRate => "connection rate limit exceeded",
            DenialReason::AuthFailureRate => "auth failure rate limit exceeded",
            DenialReason::ConcurrentConnections => "concurrent connection limit exceeded",
            DenialReason::ByteRate => "byte rate limit exceeded",
        }
    }
}

#[derive(Debug)]
pub struct ClientPermit {
    controls: Arc<AbuseControls>,
    state: Arc<Mutex<ClientState>>,
    byte_rate: Option<RateLimit>,
    active: bool,
}

#[derive(Debug, Clone)]
pub struct ClientByteRecorder {
    state: Arc<Mutex<ClientState>>,
    byte_rate: RateLimit,
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
        drop(state_guard);
        Ok(ClientPermit {
            controls: self.clone(),
            state,
            byte_rate: config.byte_rate,
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
    pub fn byte_recorder(&self) -> Option<ClientByteRecorder> {
        self.byte_rate.clone().map(|byte_rate| ClientByteRecorder {
            state: self.state.clone(),
            byte_rate,
        })
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

impl ClientByteRecorder {
    pub fn record_bytes(&self, bytes: u64) -> Result<(), DenialReason> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if add_window_bytes(
            &mut state.bytes,
            Some(&self.byte_rate),
            Instant::now(),
            bytes,
        ) {
            return Err(DenialReason::ByteRate);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct ClientState {
    connections: Window,
    auth_failures: Window,
    bytes: Window,
    active_connections: usize,
}

impl ClientState {
    fn new(now: Instant) -> Self {
        Self {
            connections: Window::new(now),
            auth_failures: Window::new(now),
            bytes: Window::new(now),
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

fn add_window_bytes(
    window: &mut Window,
    limit: Option<&RateLimit>,
    now: Instant,
    bytes: u64,
) -> bool {
    let Some(limit) = limit else {
        return false;
    };
    reset_if_expired(window, limit, now);
    let next = window.count.saturating_add(bytes);
    if next > limit.limit {
        return true;
    }
    window.count = next;
    false
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
        self.active_connections == 0
            && window_is_prunable(&self.connections, config.connection_rate.as_ref(), now)
            && window_is_prunable(&self.auth_failures, config.auth_failure_rate.as_ref(), now)
            && window_is_prunable(&self.bytes, config.byte_rate.as_ref(), now)
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
    fn byte_rate_rejects_over_limit_write() {
        let controls = AbuseControls::new(RateLimits {
            byte_rate: Some(RateLimit {
                limit: 4,
                window: Duration::from_secs(60),
            }),
            ..RateLimits::default()
        });

        let permit = controls.admit(ip()).unwrap();
        let recorder = permit.byte_recorder().unwrap();
        recorder.record_bytes(4).unwrap();
        assert_eq!(
            recorder.record_bytes(1).unwrap_err(),
            DenialReason::ByteRate
        );
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
