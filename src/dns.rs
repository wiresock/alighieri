//! DNS resolution helpers and post-resolution destination policy.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::sync::{watch, Mutex};

use crate::config::{DnsDenyCategory, DnsPolicy, DnsPreference};
use crate::socks5::TargetAddr;

const MAX_DNS_CACHE_ENTRIES: usize = 4096;

/// The outcome a lookup leader publishes to coalesced followers. Errors are
/// shared as kind + message because `io::Error` is not `Clone`, so followers
/// observe the same `ErrorKind` the leader saw; they are never cached.
type SharedLookup = Option<std::result::Result<Vec<SocketAddr>, (io::ErrorKind, String)>>;

/// Resolves a SOCKS target into policy-ordered, policy-allowed socket
/// addresses. IP literals are still passed through the same policy filter.
pub async fn resolve_all(dest: &TargetAddr, policy: &DnsPolicy) -> io::Result<Vec<SocketAddr>> {
    let mut addrs = match dest {
        TargetAddr::Ip(sa) => vec![*sa],
        TargetAddr::Domain(host, port) => lookup_domain(host, *port).await?,
    };
    order_addresses(&mut addrs, policy.preference);
    addrs.retain(|addr| address_allowed(addr.ip(), policy));
    Ok(addrs)
}

/// Returns the first policy-allowed address for UDP-style forwarding.
pub async fn resolve_one(dest: &TargetAddr, policy: &DnsPolicy) -> io::Result<Option<SocketAddr>> {
    Ok(resolve_all(dest, policy).await?.into_iter().next())
}

/// Shared DNS resolver with an optional in-memory TTL cache for domain
/// lookups and per-key coalescing of concurrent lookups: when many requests
/// resolve the same cold name at once, one of them performs the system
/// lookup and the rest wait for its result instead of stampeding the
/// blocking resolver pool.
#[derive(Debug, Default)]
pub struct DnsResolver {
    cache: Mutex<HashMap<DnsCacheKey, DnsCacheEntry>>,
    inflight: std::sync::Mutex<HashMap<DnsCacheKey, watch::Receiver<SharedLookup>>>,
    backend: LookupBackend,
}

/// How `lookup_domain` reaches name resolution; tests substitute a custom
/// backend to make coalescing observable and deterministic.
#[derive(Debug, Default)]
enum LookupBackend {
    #[default]
    System,
    #[cfg(test)]
    Custom(TestLookup),
}

#[cfg(test)]
type TestLookupFn = dyn Fn(
        &str,
        u16,
    )
        -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<Vec<SocketAddr>>> + Send>>
    + Send
    + Sync;

#[cfg(test)]
#[derive(Clone)]
struct TestLookup(std::sync::Arc<TestLookupFn>);

#[cfg(test)]
impl std::fmt::Debug for TestLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestLookup").finish_non_exhaustive()
    }
}

impl DnsResolver {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn with_lookup(lookup: std::sync::Arc<TestLookupFn>) -> Self {
        DnsResolver {
            backend: LookupBackend::Custom(TestLookup(lookup)),
            ..DnsResolver::default()
        }
    }

    async fn backend_lookup(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        match &self.backend {
            LookupBackend::System => lookup_domain(host, port).await,
            #[cfg(test)]
            LookupBackend::Custom(lookup) => (lookup.0)(host, port).await,
        }
    }

    /// Resolves a SOCKS target into policy-ordered, policy-allowed socket
    /// addresses. IP literals are still passed through the same policy filter.
    pub async fn resolve_all(
        &self,
        dest: &TargetAddr,
        policy: &DnsPolicy,
    ) -> io::Result<Vec<SocketAddr>> {
        let mut addrs = match dest {
            TargetAddr::Ip(sa) => vec![*sa],
            TargetAddr::Domain(host, port) => {
                self.resolve_domain(host, *port, policy.cache_ttl).await?
            }
        };
        order_addresses(&mut addrs, policy.preference);
        addrs.retain(|addr| address_allowed(addr.ip(), policy));
        Ok(addrs)
    }

    /// Returns the first policy-allowed address for UDP-style forwarding.
    pub async fn resolve_one(
        &self,
        dest: &TargetAddr,
        policy: &DnsPolicy,
    ) -> io::Result<Option<SocketAddr>> {
        Ok(self.resolve_all(dest, policy).await?.into_iter().next())
    }

    async fn resolve_domain(
        &self,
        host: &str,
        port: u16,
        ttl: Option<Duration>,
    ) -> io::Result<Vec<SocketAddr>> {
        let key = DnsCacheKey::new(host, port);
        loop {
            if ttl.is_some() {
                if let Some(addrs) = self.cached(&key, Instant::now()).await {
                    return Ok(addrs);
                }
            }

            match self.join_or_lead(&key) {
                Flight::Lead(mut lead) => {
                    let result = self.backend_lookup(host, port).await;
                    if let (Some(ttl), Ok(addrs)) = (ttl, &result) {
                        self.store(
                            key.clone(),
                            addrs.clone(),
                            cache_expiration(Instant::now(), ttl),
                        )
                        .await;
                    }
                    lead.publish(&result);
                    return result;
                }
                Flight::Follow(mut rx) => {
                    loop {
                        let outcome = rx.borrow_and_update().clone();
                        match outcome {
                            Some(Ok(addrs)) => return Ok(addrs),
                            Some(Err((kind, message))) => {
                                return Err(io::Error::new(kind, message));
                            }
                            None => {
                                if rx.changed().await.is_err() {
                                    // The leader was cancelled before
                                    // publishing; retry from the top.
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Joins an in-flight lookup for `key`, or registers this caller as the
    /// leader that will perform it.
    fn join_or_lead(&self, key: &DnsCacheKey) -> Flight<'_> {
        let mut inflight = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(rx) = inflight.get(key) {
            return Flight::Follow(rx.clone());
        }
        let (tx, rx) = watch::channel(None);
        inflight.insert(key.clone(), rx);
        Flight::Lead(InflightLead {
            resolver: self,
            key: key.clone(),
            tx: Some(tx),
        })
    }

    async fn cached(&self, key: &DnsCacheKey, now: Instant) -> Option<Vec<SocketAddr>> {
        let mut cache = self.cache.lock().await;
        let entry = cache.get(key)?;
        if cache_entry_live(entry, now) {
            return Some(entry.addrs.clone());
        }
        cache.remove(key);
        None
    }

    async fn store(&self, key: DnsCacheKey, addrs: Vec<SocketAddr>, expires_at: Option<Instant>) {
        let mut cache = self.cache.lock().await;
        // Sweeping the whole map costs O(capacity); do it only when the cache
        // is actually full rather than on every insert, and fall back to
        // evicting the soonest-to-expire entry when the sweep frees nothing.
        if cache.len() >= MAX_DNS_CACHE_ENTRIES && !cache.contains_key(&key) {
            let now = Instant::now();
            cache.retain(|_, entry| cache_entry_live(entry, now));
            if cache.len() >= MAX_DNS_CACHE_ENTRIES {
                if let Some(oldest_key) = oldest_cache_key(&cache) {
                    cache.remove(&oldest_key);
                }
            }
        }
        cache.insert(key, DnsCacheEntry { addrs, expires_at });
    }
}

enum Flight<'a> {
    Lead(InflightLead<'a>),
    Follow(watch::Receiver<SharedLookup>),
}

/// Registration of a lookup leader. Publishing shares the outcome with
/// followers; dropping (publish or cancellation) removes the in-flight entry
/// so later callers start fresh instead of waiting on a dead leader.
struct InflightLead<'a> {
    resolver: &'a DnsResolver,
    key: DnsCacheKey,
    tx: Option<watch::Sender<SharedLookup>>,
}

impl InflightLead<'_> {
    fn publish(&mut self, result: &io::Result<Vec<SocketAddr>>) {
        if let Some(tx) = self.tx.take() {
            // Deregister before sending so a caller arriving after
            // completion starts a fresh lookup; only followers already
            // waiting observe this outcome (which is what keeps shared
            // errors scoped to the requests that were actually coalesced).
            self.remove_inflight();
            let shared = match result {
                Ok(addrs) => Ok(addrs.clone()),
                Err(e) => Err((e.kind(), e.to_string())),
            };
            let _ = tx.send(Some(shared));
        }
    }

    fn remove_inflight(&self) {
        let mut inflight = self
            .resolver
            .inflight
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        inflight.remove(&self.key);
    }
}

impl Drop for InflightLead<'_> {
    fn drop(&mut self) {
        // Only the cancellation path still holds `tx` here; `publish` has
        // already deregistered, and removing again could evict a newer
        // leader registered for the same key in the meantime.
        if self.tx.is_some() {
            self.remove_inflight();
            // `tx` drops with self, waking followers with an error so they
            // retry instead of waiting forever.
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DnsCacheKey {
    host: String,
    port: u16,
}

impl DnsCacheKey {
    fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_ascii_lowercase(),
            port,
        }
    }
}

#[derive(Debug, Clone)]
struct DnsCacheEntry {
    addrs: Vec<SocketAddr>,
    /// `None` is used when a configured TTL is too large to represent as an
    /// `Instant`; practically, that means the entry lives until eviction.
    expires_at: Option<Instant>,
}

fn cache_expiration(now: Instant, ttl: Duration) -> Option<Instant> {
    now.checked_add(ttl)
}

fn cache_entry_live(entry: &DnsCacheEntry, now: Instant) -> bool {
    entry.expires_at.is_none_or(|expires_at| expires_at > now)
}

fn oldest_cache_key(cache: &HashMap<DnsCacheKey, DnsCacheEntry>) -> Option<DnsCacheKey> {
    let mut oldest: Option<(&DnsCacheKey, Option<Instant>)> = None;
    for (key, entry) in cache {
        if match oldest {
            Some((_, oldest_expires)) => expires_before(entry.expires_at, oldest_expires),
            None => true,
        } {
            oldest = Some((key, entry.expires_at));
        }
    }
    oldest.map(|(key, _)| key.clone())
}

fn expires_before(candidate: Option<Instant>, current: Option<Instant>) -> bool {
    match (candidate, current) {
        (Some(candidate), Some(current)) => candidate < current,
        (Some(_), None) => true,
        (None, Some(_)) | (None, None) => false,
    }
}

async fn lookup_domain(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    tokio::net::lookup_host((host, port))
        .await
        .map(|addrs| addrs.collect())
}

fn order_addresses(addrs: &mut [SocketAddr], preference: DnsPreference) {
    match preference {
        DnsPreference::System => {}
        DnsPreference::Ipv4 => addrs.sort_by_key(|addr| if addr.is_ipv4() { 0 } else { 1 }),
        DnsPreference::Ipv6 => addrs.sort_by_key(|addr| if addr.is_ipv6() { 0 } else { 1 }),
    }
}

/// Returns `true` when `ip` passes the post-resolution deny policy. Exposed
/// for per-packet paths that check IP literals without building an address
/// list.
pub fn address_allowed(ip: IpAddr, policy: &DnsPolicy) -> bool {
    !policy
        .deny
        .iter()
        .any(|category| ip_matches_category(ip, *category))
}

fn ip_matches_category(ip: IpAddr, category: DnsDenyCategory) -> bool {
    match category {
        DnsDenyCategory::Private => is_private(ip),
        DnsDenyCategory::LinkLocal => is_link_local(ip),
        DnsDenyCategory::Loopback => ip.is_loopback(),
        DnsDenyCategory::Multicast => is_multicast(ip),
        DnsDenyCategory::Unspecified => ip.is_unspecified(),
        DnsDenyCategory::Documentation => is_documentation(ip),
        DnsDenyCategory::Reserved => is_reserved(ip),
    }
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private(),
        IpAddr::V6(ip) => (ip.segments()[0] & 0xfe00) == 0xfc00,
    }
}

fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, _, _] = ip.octets();
            a == 169 && b == 254
        }
        IpAddr::V6(ip) => (ip.segments()[0] & 0xffc0) == 0xfe80,
    }
}

fn is_multicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_multicast(),
        IpAddr::V6(ip) => ip.is_multicast(),
    }
}

fn is_documentation(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            (a == 192 && b == 0 && c == 2)
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(ip) => ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8,
    }
}

fn is_reserved(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            a == 0
                || a >= 240
                || (a == 100 && (64..=127).contains(&b))
                || (a == 192 && b == 0 && c == 0)
        }
        IpAddr::V6(ip) => {
            ip == Ipv6Addr::UNSPECIFIED
                || ip == Ipv6Addr::LOCALHOST
                || is_documentation(IpAddr::V6(ip))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn policy(preference: DnsPreference, deny: Vec<DnsDenyCategory>) -> DnsPolicy {
        DnsPolicy {
            preference,
            try_all: false,
            deny,
            cache_ttl: None,
        }
    }

    fn answer(port: u16) -> SocketAddr {
        SocketAddr::from(([203, 0, 113, 7], port))
    }

    /// A backend that counts invocations and parks each call on a semaphore
    /// permit, so tests control exactly when the leader completes.
    fn parked_backend(
        calls: Arc<AtomicUsize>,
        release: Arc<tokio::sync::Semaphore>,
        fail: bool,
    ) -> Arc<TestLookupFn> {
        Arc::new(move |_host, port| {
            let calls = calls.clone();
            let release = release.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                let _permit = release.acquire().await.expect("semaphore closed");
                if fail {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "backend unavailable",
                    ))
                } else {
                    Ok(vec![answer(port)])
                }
            })
        })
    }

    async fn spawn_resolvers(
        resolver: &Arc<DnsResolver>,
        count: usize,
    ) -> Vec<tokio::task::JoinHandle<io::Result<Vec<SocketAddr>>>> {
        let mut tasks = Vec::with_capacity(count);
        for _ in 0..count {
            let resolver = resolver.clone();
            let dns_policy = policy(DnsPreference::System, Vec::new());
            tasks.push(tokio::spawn(async move {
                resolver
                    .resolve_all(&TargetAddr::Domain("example.com".into(), 443), &dns_policy)
                    .await
            }));
        }
        // The singleflight tests pin the current-thread flavor explicitly:
        // on a single thread, yielding drives every spawned task to its
        // join-or-follow await point deterministically.
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        tasks
    }

    #[tokio::test(flavor = "current_thread")]
    async fn singleflight_coalesces_concurrent_lookups() {
        let calls = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let resolver = Arc::new(DnsResolver::with_lookup(parked_backend(
            calls.clone(),
            release.clone(),
            false,
        )));

        let tasks = spawn_resolvers(&resolver, 8).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        release.add_permits(1);

        for task in tasks {
            assert_eq!(task.await.unwrap().unwrap(), vec![answer(443)]);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn singleflight_shares_leader_error_without_caching_it() {
        let calls = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let resolver = Arc::new(DnsResolver::with_lookup(parked_backend(
            calls.clone(),
            release.clone(),
            true,
        )));

        let tasks = spawn_resolvers(&resolver, 4).await;
        release.add_permits(1);
        for task in tasks {
            let err = task.await.unwrap().unwrap_err();
            // Followers observe the same error kind the leader saw.
            assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
            assert!(err.to_string().contains("backend unavailable"));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Errors are not cached or coalesced into later attempts: a fresh
        // request triggers a fresh lookup.
        release.add_permits(1);
        let dns_policy = policy(DnsPreference::System, Vec::new());
        let _ = resolver
            .resolve_all(&TargetAddr::Domain("example.com".into(), 443), &dns_policy)
            .await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn singleflight_recovers_when_the_leader_is_cancelled() {
        let calls = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let resolver = Arc::new(DnsResolver::with_lookup(parked_backend(
            calls.clone(),
            release.clone(),
            false,
        )));

        let mut tasks = spawn_resolvers(&resolver, 2).await;
        let follower = tasks.pop().unwrap();
        let leader = tasks.pop().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Cancelling the leader mid-lookup must not strand the follower: it
        // retries, becomes the new leader, and completes.
        leader.abort();
        release.add_permits(1);
        assert_eq!(follower.await.unwrap().unwrap(), vec![answer(443)]);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn store_purges_expired_entries_when_full() {
        let resolver = DnsResolver::new();
        let now = Instant::now();
        for i in 0..MAX_DNS_CACHE_ENTRIES {
            resolver
                .store(
                    DnsCacheKey::new(&format!("expired{i}.example"), 80),
                    vec![answer(80)],
                    Some(now - Duration::from_secs(1)),
                )
                .await;
        }

        resolver
            .store(
                DnsCacheKey::new("fresh.example", 80),
                vec![answer(80)],
                Some(now + Duration::from_secs(60)),
            )
            .await;

        let cache = resolver.cache.lock().await;
        assert_eq!(cache.len(), 1);
        assert!(cache.contains_key(&DnsCacheKey::new("fresh.example", 80)));
    }

    #[tokio::test]
    async fn resolves_ip_literal_without_dns() {
        let sa: SocketAddr = "9.9.9.9:53".parse().unwrap();
        let resolved = resolve_all(
            &TargetAddr::Ip(sa),
            &policy(DnsPreference::System, Vec::new()),
        )
        .await
        .unwrap();
        assert_eq!(resolved, vec![sa]);
    }

    #[tokio::test]
    async fn denies_private_ip_literal() {
        let sa: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let resolved = resolve_all(
            &TargetAddr::Ip(sa),
            &policy(DnsPreference::System, vec![DnsDenyCategory::Private]),
        )
        .await
        .unwrap();
        assert!(resolved.is_empty());
    }

    #[test]
    fn orders_ipv4_first() {
        let mut addrs = vec![
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 80),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80),
        ];
        order_addresses(&mut addrs, DnsPreference::Ipv4);
        assert!(addrs[0].is_ipv4());
    }

    #[test]
    fn orders_ipv6_first() {
        let mut addrs = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 80),
        ];
        order_addresses(&mut addrs, DnsPreference::Ipv6);
        assert!(addrs[0].is_ipv6());
    }

    #[test]
    fn matches_documentation_ranges() {
        assert!(is_documentation("192.0.2.1".parse().unwrap()));
        assert!(is_documentation("2001:db8::1".parse().unwrap()));
        assert!(!is_documentation("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn cache_keys_normalize_host_case() {
        assert_eq!(
            DnsCacheKey::new("Example.COM", 443),
            DnsCacheKey::new("example.com", 443)
        );
    }

    #[tokio::test]
    async fn cached_entries_expire() {
        let resolver = DnsResolver::new();
        let key = DnsCacheKey::new("example.com", 80);
        let addrs = vec!["203.0.113.10:80".parse().unwrap()];
        let now = Instant::now();

        resolver
            .store(
                key.clone(),
                addrs.clone(),
                Some(now + Duration::from_secs(10)),
            )
            .await;
        assert_eq!(resolver.cached(&key, now).await, Some(addrs));
        assert_eq!(
            resolver.cached(&key, now + Duration::from_secs(11)).await,
            None
        );
    }

    #[test]
    fn oversized_cache_ttl_has_no_internal_expiration() {
        let now = Instant::now();
        assert_eq!(cache_expiration(now, Duration::MAX), None);
    }

    #[tokio::test]
    async fn cache_evicts_oldest_entry_when_full() {
        let resolver = DnsResolver::new();
        let addrs = vec!["203.0.113.10:80".parse().unwrap()];
        let now = Instant::now();

        for i in 0..MAX_DNS_CACHE_ENTRIES {
            resolver
                .store(
                    DnsCacheKey::new(&format!("host{i}.example"), 80),
                    addrs.clone(),
                    Some(now + Duration::from_secs(60 + i as u64)),
                )
                .await;
        }

        let oldest = DnsCacheKey::new("host0.example", 80);
        resolver
            .store(
                DnsCacheKey::new("new.example", 80),
                addrs,
                Some(now + Duration::from_secs(120)),
            )
            .await;

        assert_eq!(resolver.cached(&oldest, now).await, None);
    }
}
