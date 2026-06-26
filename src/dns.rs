//! DNS resolution helpers and post-resolution destination policy.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{watch, Mutex, OwnedSemaphorePermit, Semaphore};

use crate::config::{DnsDenyCategory, DnsPolicy, DnsPreference};
use crate::socks5::TargetAddr;

const MAX_DNS_CACHE_ENTRIES: usize = 4096;

/// Cap on concurrent system DNS lookups in flight. `getaddrinfo` runs on a
/// blocking thread that cannot be cancelled, so a timed-out lookup keeps
/// occupying one until the OS resolver gives up. Bounding the count stops a DNS
/// outage with many unique names from spawning an unbounded number of orphaned
/// blocking tasks and starving Tokio's blocking pool (default 512 threads),
/// which also serves userlist reads and other `spawn_blocking` work. Coalesced
/// lookups for the same name share one slot (only the singleflight leader
/// resolves), so this bounds distinct concurrent names; 128 leaves ample pool
/// headroom for other work even during an outage.
const MAX_CONCURRENT_SYSTEM_LOOKUPS: usize = 128;

/// How long a *timed-out* name is remembered so repeated requests fail fast
/// instead of each starting (and waiting `dns.timeout` on) a fresh, uncancellable
/// system lookup. This is a short backoff, not a definitive negative cache: a
/// timeout is not proof a name is unresolvable, so the window is kept brief to
/// limit how long a name that has since recovered keeps being failed fast.
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(2);

/// Cap on remembered timed-out names, bounding the negative cache's memory the
/// way [`MAX_DNS_CACHE_ENTRIES`] bounds the positive cache.
const MAX_NEGATIVE_CACHE_ENTRIES: usize = 1024;

/// The outcome a lookup leader publishes to coalesced followers. Errors are
/// shared as kind + message because `io::Error` is not `Clone`, so followers
/// observe the same `ErrorKind` the leader saw; they are never cached.
type SharedLookup = Option<std::result::Result<Vec<SocketAddr>, (io::ErrorKind, String)>>;

/// Cache-bypassing one-shot resolution, for tests only. Production resolves
/// through [`DnsResolver`] (cache + request coalescing); keeping this
/// test-scoped avoids a second public path that could drift from the ordering
/// and policy `DnsResolver::resolve_all` applies.
#[cfg(test)]
async fn resolve_all(dest: &TargetAddr, policy: &DnsPolicy) -> io::Result<Vec<SocketAddr>> {
    let mut addrs = match dest {
        TargetAddr::Ip(sa) => vec![*sa],
        TargetAddr::Domain(host, port) => lookup_domain(host, *port).await?,
    };
    canonicalize_addrs(&mut addrs);
    order_addresses(&mut addrs, policy.preference);
    addrs.retain(|addr| address_allowed(addr.ip(), policy));
    Ok(addrs)
}

/// Shared DNS resolver with an optional in-memory TTL cache for domain
/// lookups and per-key coalescing of concurrent lookups: when many requests
/// resolve the same cold name at once, one of them performs the system
/// lookup and the rest wait for its result instead of stampeding the
/// blocking resolver pool.
#[derive(Debug)]
pub struct DnsResolver {
    cache: Mutex<HashMap<DnsCacheKey, DnsCacheEntry>>,
    inflight: std::sync::Mutex<HashMap<DnsCacheKey, watch::Receiver<SharedLookup>>>,
    backend: LookupBackend,
    /// Bounds concurrent system lookups; see [`MAX_CONCURRENT_SYSTEM_LOOKUPS`].
    lookup_slots: Arc<Semaphore>,
    /// Names that recently timed out, mapped to when, so repeated requests back
    /// off rather than each starting a fresh lookup. See [`NEGATIVE_CACHE_TTL`].
    negative: std::sync::Mutex<HashMap<DnsCacheKey, Instant>>,
}

impl Default for DnsResolver {
    fn default() -> Self {
        DnsResolver {
            cache: Mutex::new(HashMap::new()),
            inflight: std::sync::Mutex::new(HashMap::new()),
            backend: LookupBackend::default(),
            lookup_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_SYSTEM_LOOKUPS)),
            negative: std::sync::Mutex::new(HashMap::new()),
        }
    }
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
        Self::with_lookup_and_slots(lookup, MAX_CONCURRENT_SYSTEM_LOOKUPS)
    }

    #[cfg(test)]
    fn with_lookup_and_slots(lookup: std::sync::Arc<TestLookupFn>, slots: usize) -> Self {
        DnsResolver {
            backend: LookupBackend::Custom(TestLookup(lookup)),
            lookup_slots: Arc::new(Semaphore::new(slots)),
            ..DnsResolver::default()
        }
    }

    async fn backend_lookup(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        // Take a lookup slot before resolving so concurrent distinct-name lookups
        // stay bounded (only the singleflight leader reaches here per name, so
        // coalesced callers share one slot). Waiting for a slot happens inside the
        // caller's `tokio::time::timeout`, so it cannot block past the deadline.
        let Ok(permit) = self.lookup_slots.clone().acquire_owned().await else {
            // The semaphore is never closed; if it ever were, fail this lookup
            // gracefully rather than panicking the whole process.
            return Err(io::Error::other("DNS lookup semaphore closed"));
        };
        match &self.backend {
            LookupBackend::System => system_lookup(host.to_owned(), port, permit).await,
            #[cfg(test)]
            LookupBackend::Custom(lookup) => {
                // Hold the slot across the mock so tests exercise the same bound.
                let _permit = permit;
                (lookup.0)(host, port).await
            }
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
            // `policy.timeout` bounds resolution inside `resolve_domain` (around
            // the singleflight leader's lookup), so a slow or wedged resolver
            // cannot pin a CONNECT permit or stall the UDP relay loop.
            TargetAddr::Domain(host, port) => {
                self.resolve_domain(host, *port, policy.cache_ttl, policy.timeout)
                    .await?
            }
        };
        canonicalize_addrs(&mut addrs);
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

    /// Resolves `host` to all of its addresses (both families, canonicalised),
    /// bounded by `timeout` and using the shared singleflight (and positive cache
    /// when `ttl` is set) — but without the connection deny/preference policy. The
    /// caller is choosing an address to *advertise* (`udp.advertise`), not a
    /// destination to connect to, so the deny categories and v4/v6 preference
    /// (which exist to shape outbound connections) must not filter it.
    pub async fn resolve_host(
        &self,
        host: &str,
        ttl: Option<Duration>,
        timeout: Duration,
    ) -> io::Result<Vec<IpAddr>> {
        let mut addrs = self.resolve_domain(host, 0, ttl, timeout).await?;
        canonicalize_addrs(&mut addrs);
        Ok(addrs.into_iter().map(|addr| addr.ip()).collect())
    }

    async fn resolve_domain(
        &self,
        host: &str,
        port: u16,
        ttl: Option<Duration>,
        timeout: Duration,
    ) -> io::Result<Vec<SocketAddr>> {
        let key = DnsCacheKey::new(host, port);
        loop {
            if let Some(ttl) = ttl {
                if let Some(addrs) = self.cached(&key, Instant::now(), ttl).await {
                    return Ok(addrs);
                }
            }
            // Fail fast for a name that timed out within the last
            // NEGATIVE_CACHE_TTL rather than starting another lookup that would
            // (most likely) just time out again and tie up a lookup slot.
            if self.negatively_cached(&key, Instant::now()) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "DNS resolution timed out",
                ));
            }

            match self.join_or_lead(&key) {
                Flight::Lead(mut lead) => {
                    // Bound the leader's lookup and publish the result — including
                    // a timeout — to followers. Applying the deadline here (rather
                    // than dropping the whole `resolve_domain` future) keeps the
                    // singleflight intact: a timed-out leader publishes `TimedOut`
                    // so the followers it coalesced fail fast instead of waking to
                    // retry, which would each start a fresh OS lookup for the same
                    // name. The underlying `getaddrinfo` is not cancellable, so its
                    // blocking thread still runs to completion. This does not cap
                    // how many lookups for a name are outstanding (a later request,
                    // after the in-flight entry clears, can start another while an
                    // orphaned one runs) — it only stops one coalesced batch from
                    // fanning back out into a lookup per follower.
                    let result = match tokio::time::timeout(
                        timeout,
                        self.backend_lookup(host, port),
                    )
                    .await
                    {
                        Ok(result) => result,
                        Err(_) => Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "DNS resolution timed out",
                        )),
                    };
                    if let (Some(ttl), Ok(addrs)) = (ttl, &result) {
                        self.store(key.clone(), addrs.clone(), ttl).await;
                    }
                    // Remember a timeout so the next request for this name backs
                    // off instead of starting another doomed lookup.
                    if matches!(&result, Err(e) if e.kind() == io::ErrorKind::TimedOut) {
                        self.store_negative(key.clone(), Instant::now());
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

    async fn cached(
        &self,
        key: &DnsCacheKey,
        now: Instant,
        ttl: Duration,
    ) -> Option<Vec<SocketAddr>> {
        let mut cache = self.cache.lock().await;
        let entry = cache.get(key)?;
        if cache_entry_live(entry, now, ttl) {
            return Some(entry.addrs.clone());
        }
        cache.remove(key);
        None
    }

    async fn store(&self, key: DnsCacheKey, addrs: Vec<SocketAddr>, ttl: Duration) {
        let mut cache = self.cache.lock().await;
        // Capture the time after acquiring the lock so a contended await does
        // not backdate the entry (which would make it expire and be evicted
        // earlier than its TTL intends).
        let now = Instant::now();
        // Sweeping the whole map costs O(capacity); do it only when the cache
        // is actually full rather than on every insert, and fall back to
        // evicting the oldest entry when the sweep frees nothing.
        if cache.len() >= MAX_DNS_CACHE_ENTRIES && !cache.contains_key(&key) {
            cache.retain(|_, entry| cache_entry_live(entry, now, ttl));
            if cache.len() >= MAX_DNS_CACHE_ENTRIES {
                if let Some(oldest_key) = oldest_cache_key(&cache) {
                    cache.remove(&oldest_key);
                }
            }
        }
        cache.insert(
            key,
            DnsCacheEntry {
                addrs,
                inserted_at: now,
            },
        );
    }

    /// Whether `key` timed out within the last [`NEGATIVE_CACHE_TTL`] (as of
    /// `now`), expiring a stale entry as a side effect.
    fn negatively_cached(&self, key: &DnsCacheKey, now: Instant) -> bool {
        let mut negative = self.negative.lock().unwrap_or_else(|e| e.into_inner());
        match negative.get(key) {
            Some(&failed_at) if now.saturating_duration_since(failed_at) < NEGATIVE_CACHE_TTL => {
                true
            }
            Some(_) => {
                negative.remove(key);
                false
            }
            None => false,
        }
    }

    /// Records that `key` timed out at `now` so later requests back off. Bounded
    /// like the positive cache: a full map first drops expired entries, then the
    /// oldest, before inserting.
    fn store_negative(&self, key: DnsCacheKey, now: Instant) {
        let mut negative = self.negative.lock().unwrap_or_else(|e| e.into_inner());
        if negative.len() >= MAX_NEGATIVE_CACHE_ENTRIES && !negative.contains_key(&key) {
            negative.retain(|_, failed_at| {
                now.saturating_duration_since(*failed_at) < NEGATIVE_CACHE_TTL
            });
            if negative.len() >= MAX_NEGATIVE_CACHE_ENTRIES {
                if let Some(oldest) = negative
                    .iter()
                    .min_by_key(|(_, &failed_at)| failed_at)
                    .map(|(k, _)| k.clone())
                {
                    negative.remove(&oldest);
                }
            }
        }
        negative.insert(key, now);
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
    /// When the entry was stored. Liveness is judged at lookup against the
    /// *current* `cache_ttl` (`now - inserted_at < ttl`), so a reload that lowers
    /// the TTL shortens existing entries immediately instead of honouring the
    /// TTL that was in force when they were cached. Comparing elapsed time
    /// against the TTL (rather than storing an absolute expiry) also sidesteps
    /// the `Instant`-overflow handling the previous `checked_add` needed: a very
    /// large TTL is simply never reached within a process lifetime.
    inserted_at: Instant,
}

fn cache_entry_live(entry: &DnsCacheEntry, now: Instant, ttl: Duration) -> bool {
    now.saturating_duration_since(entry.inserted_at) < ttl
}

/// The entry stored longest ago — the soonest to expire under a single shared
/// TTL, evicted to make room when a sweep of expired entries frees nothing. The
/// key (port, host) breaks ties so eviction is deterministic when a coarse clock
/// stamps several entries with the same `inserted_at`, rather than depending on
/// the `HashMap`'s iteration order.
fn oldest_cache_key(cache: &HashMap<DnsCacheKey, DnsCacheEntry>) -> Option<DnsCacheKey> {
    cache
        .iter()
        .min_by_key(|(key, entry)| (entry.inserted_at, key.port, key.host.as_str()))
        .map(|(key, _)| key.clone())
}

/// Runs the blocking system resolver (`getaddrinfo`) on the blocking pool,
/// holding `permit` for the call's full duration. The permit is moved into the
/// blocking closure rather than held in this future, so a caller that times out
/// and drops this future does not free the slot early: it stays held until the
/// real, uncancellable OS lookup on its blocking thread actually returns.
async fn system_lookup(
    host: String,
    port: u16,
    permit: OwnedSemaphorePermit,
) -> io::Result<Vec<SocketAddr>> {
    tokio::task::spawn_blocking(move || -> io::Result<Vec<SocketAddr>> {
        let _permit = permit;
        Ok((host.as_str(), port).to_socket_addrs()?.collect())
    })
    .await
    .map_err(io::Error::other)?
}

/// Cache-bypassing one-shot resolution used only by the test helper above.
#[cfg(test)]
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
    // Collapse an IPv4-in-IPv6 wrapper to its real IPv4 form before matching: the
    // deny categories below recognise the IPv4 address, not its wrapper, so
    // without this `::ffff:127.0.0.1` (or `::127.0.0.1`) would slip past a
    // `loopback` (or `private`, etc.) deny.
    let ip = canonical_ip(ip);
    !policy
        .deny
        .iter()
        .any(|category| ip_matches_category(ip, *category))
}

/// Collapses an IPv4-in-IPv6 *wrapper* to its embedded IPv4 so the deny
/// categories and CIDR rules — which recognise the real IPv4 address, not its
/// wrapper — apply. Handles both the IPv4-mapped form (`::ffff:a.b.c.d`, via
/// [`IpAddr::to_canonical`]) and the deprecated IPv4-compatible form
/// (`::a.b.c.d`, RFC 4291 §2.5.5.1), which `to_canonical` leaves as an opaque
/// IPv6 address that would otherwise dodge every category (e.g. `::127.0.0.1`
/// evading `loopback`). `::` and `::1` keep their own meanings. Genuine IPv6
/// addresses (including NAT64/6to4/Teredo, which are real routable prefixes that
/// must not be re-routed as IPv4) are returned unchanged, preserving any scope;
/// those prefixes are instead covered by the `reserved` category.
fn canonical_ip(ip: IpAddr) -> IpAddr {
    let ip = ip.to_canonical();
    let IpAddr::V6(v6) = ip else { return ip };
    let s = v6.segments();
    // IPv4-compatible `::a.b.c.d`: the top 96 bits are zero. Exclude `::`
    // (unspecified) and `::1` (loopback), which are not IPv4 wrappers.
    let top_96_zero = s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0;
    if top_96_zero && !(s[6] == 0 && s[7] <= 1) {
        return IpAddr::V4(Ipv4Addr::from((u32::from(s[6]) << 16) | u32::from(s[7])));
    }
    ip
}

/// Collapses IPv4-in-IPv6 wrappers (`::ffff:a.b.c.d` and the deprecated
/// `::a.b.c.d`) to their IPv4 form so every downstream consumer — the deny
/// policy, ACL CIDR matching, and the outbound connection — sees the real
/// destination rather than the wrapper that would dodge IPv4 rules.
fn canonicalize_addrs(addrs: &mut [SocketAddr]) {
    for addr in addrs.iter_mut() {
        // `set_ip` keeps the port and — for a genuine IPv6 address, where
        // `canonical_ip` is a no-op — its `flowinfo`/`scope_id`. Only an actual
        // IPv4 wrapper changes family. Rebuilding via `SocketAddr::new` would
        // instead strip those fields from scoped (e.g. link-local) destinations.
        addr.set_ip(canonical_ip(addr.ip()));
    }
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

/// IANA special-purpose ranges that should never name a real service.
///
/// The IPv4 entries are special-purpose ranges the other deny categories
/// (private, link-local, loopback, multicast, unspecified, documentation) do not
/// otherwise cover: `0.0.0.0/8` ("this network"; overlaps `unspecified` only at
/// `0.0.0.0`), `100.64.0.0/10` (CGNAT, RFC 6598), `192.0.0.0/24` (IETF protocol
/// assignments), `192.88.99.0/24` (6to4 relay anycast, RFC 7526),
/// `198.18.0.0/15` (benchmarking, RFC 2544), and `240.0.0.0/4` (reserved for
/// future use, including the `255.255.255.255` limited broadcast).
///
/// The IPv6 entries cover `::` (also `unspecified`), `::1` (also `loopback`),
/// and `2001:db8::/32` (also `documentation`) — so denying `reserved` alone still
/// blocks those — plus the IPv4-embedding / special-use prefixes that have no
/// dedicated category: 6to4 `2002::/16` (RFC 3056), the NAT64 well-known prefix
/// `64:ff9b::/96` (RFC 6052), and the IETF protocol-assignments block
/// `2001::/23` (RFC 2928), which includes Teredo `2001::/32` and ORCHIDv2
/// `2001:20::/28`. (Folding of the IPv4-in-IPv6 *wrappers* `::ffff:a.b.c.d` and
/// `::a.b.c.d` happens earlier, in `canonical_ip`.)
///
/// Private (`10/8`, `172.16/12`, `192.168/16`), link-local, multicast, and the
/// IPv4 `TEST-NET` documentation ranges have their own categories, so combine
/// `reserved` with them for broader coverage.
fn is_reserved(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            a == 0
                || a >= 240
                || (a == 100 && (64..=127).contains(&b))
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 88 && c == 99)
                || (a == 198 && (b == 18 || b == 19))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            ip == Ipv6Addr::UNSPECIFIED
                || ip == Ipv6Addr::LOCALHOST
                || is_documentation(IpAddr::V6(ip))
                // 6to4 (RFC 3056): 2002::/16 — embeds an IPv4 address.
                || s[0] == 0x2002
                // NAT64 well-known prefix (RFC 6052): 64:ff9b::/96 — maps IPv4,
                // so 64:ff9b::7f00:1 reaches 127.0.0.1 via a NAT64 gateway.
                || (s[0] == 0x0064
                    && s[1] == 0xff9b
                    && s[2] == 0
                    && s[3] == 0
                    && s[4] == 0
                    && s[5] == 0)
                // IETF protocol-assignments block (RFC 2928): 2001::/23 — covers
                // Teredo (2001::/32) and ORCHIDv2 (2001:20::/28); excludes the
                // separate 2001:db8::/32 documentation range (handled above).
                || (s[0] == 0x2001 && (s[1] & 0xfe00) == 0)
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
            timeout: Duration::from_secs(5),
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

    /// A backend that records peak/in-flight concurrency and blocks each lookup
    /// until `release` is posted, so the lookup-slot bound is observable.
    fn counting_backend(
        in_flight: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
        release: Arc<tokio::sync::Semaphore>,
    ) -> Arc<TestLookupFn> {
        Arc::new(move |_host, port| {
            let in_flight = in_flight.clone();
            let peak = peak.clone();
            let release = release.clone();
            Box::pin(async move {
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                let _permit = release.acquire().await.expect("semaphore closed");
                in_flight.fetch_sub(1, Ordering::SeqCst);
                Ok(vec![answer(port)])
            })
        })
    }

    #[tokio::test(flavor = "current_thread")]
    async fn caps_concurrent_system_lookups() {
        // With two slots and five *distinct* names (distinct so the singleflight
        // does not coalesce them into one lookup), at most two may resolve at once.
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let resolver = Arc::new(DnsResolver::with_lookup_and_slots(
            counting_backend(in_flight.clone(), peak.clone(), release.clone()),
            2,
        ));

        let mut handles = Vec::new();
        for i in 0..5 {
            let resolver = resolver.clone();
            handles.push(tokio::spawn(async move {
                let dns_policy = policy(DnsPreference::System, Vec::new());
                resolver
                    .resolve_all(
                        &TargetAddr::Domain(format!("name{i}.example"), 443),
                        &dns_policy,
                    )
                    .await
            }));
        }
        // Drive every task to its await point: two inside the backend, three
        // parked on the lookup semaphore.
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            in_flight.load(Ordering::SeqCst),
            2,
            "exactly the slot count should be resolving at once"
        );
        assert_eq!(
            peak.load(Ordering::SeqCst),
            2,
            "the cap must never be exceeded"
        );

        // Release the blocked lookups; the parked ones then proceed and finish.
        release.add_permits(5);
        for handle in handles {
            assert_eq!(handle.await.unwrap().unwrap(), vec![answer(443)]);
        }
        assert_eq!(
            peak.load(Ordering::SeqCst),
            2,
            "the cap held for the whole run"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn resolution_times_out_on_a_wedged_resolver() {
        // A backend that blocks forever (a semaphore that is never released)
        // stands in for a wedged resolver; resolution must give up at the
        // policy deadline rather than hang.
        let calls = Arc::new(AtomicUsize::new(0));
        let never_released = Arc::new(tokio::sync::Semaphore::new(0));
        let resolver = DnsResolver::with_lookup(parked_backend(calls, never_released, false));
        let mut policy = policy(DnsPreference::System, Vec::new());
        policy.timeout = Duration::from_secs(2);

        let result = resolver
            .resolve_all(&TargetAddr::Domain("wedged.example".into(), 443), &policy)
            .await;
        assert!(
            matches!(&result, Err(e) if e.kind() == io::ErrorKind::TimedOut),
            "expected a TimedOut error, got {result:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn timed_out_name_is_negatively_cached() {
        // After a name times out, a second request within the backoff window must
        // fail fast without starting another (doomed) lookup.
        let calls = Arc::new(AtomicUsize::new(0));
        let never_released = Arc::new(tokio::sync::Semaphore::new(0));
        let resolver =
            DnsResolver::with_lookup(parked_backend(calls.clone(), never_released, false));
        let mut policy = policy(DnsPreference::System, Vec::new());
        policy.timeout = Duration::from_secs(1);

        let first = resolver
            .resolve_all(&TargetAddr::Domain("wedged.example".into(), 443), &policy)
            .await;
        assert!(matches!(&first, Err(e) if e.kind() == io::ErrorKind::TimedOut));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let second = resolver
            .resolve_all(&TargetAddr::Domain("wedged.example".into(), 443), &policy)
            .await;
        assert!(matches!(&second, Err(e) if e.kind() == io::ErrorKind::TimedOut));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the negative cache should suppress the second lookup"
        );
    }

    #[test]
    fn negative_cache_expires_after_ttl() {
        let resolver = DnsResolver::new();
        let key = DnsCacheKey::new("wedged.example", 443);
        let t0 = Instant::now();
        resolver.store_negative(key.clone(), t0);

        assert!(resolver.negatively_cached(&key, t0));
        assert!(
            resolver.negatively_cached(&key, t0 + NEGATIVE_CACHE_TTL - Duration::from_millis(1))
        );
        // At the TTL boundary the entry is expired (and removed as a side effect).
        assert!(!resolver.negatively_cached(&key, t0 + NEGATIVE_CACHE_TTL));
        // A name that never failed is not cached.
        assert!(!resolver.negatively_cached(&DnsCacheKey::new("other.example", 443), t0));
    }

    #[test]
    fn negative_cache_evicts_oldest_when_full() {
        let resolver = DnsResolver::new();
        let now = Instant::now();
        // Seed a full negative cache with distinct, increasing timestamps so the
        // oldest is unambiguous (`host0`). Seed directly because `store_negative`
        // would otherwise stamp its own time.
        {
            let mut negative = resolver.negative.lock().unwrap();
            for i in 0..MAX_NEGATIVE_CACHE_ENTRIES {
                negative.insert(
                    DnsCacheKey::new(&format!("host{i}.example"), 80),
                    now + Duration::from_millis(i as u64),
                );
            }
        }

        // Every seeded entry is still within the TTL, so the expired-sweep frees
        // nothing and the oldest entry must be evicted to make room.
        let insert_time = now + Duration::from_millis(MAX_NEGATIVE_CACHE_ENTRIES as u64);
        resolver.store_negative(DnsCacheKey::new("new.example", 80), insert_time);

        let negative = resolver.negative.lock().unwrap();
        assert_eq!(negative.len(), MAX_NEGATIVE_CACHE_ENTRIES, "the cap holds");
        assert!(!negative.contains_key(&DnsCacheKey::new("host0.example", 80)));
        assert!(negative.contains_key(&DnsCacheKey::new("new.example", 80)));
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_keeps_singleflight_coalesced() {
        // A wedged resolver with several concurrent waiters for the same name:
        // the leader times out and publishes `TimedOut` to its followers, so they
        // fail fast rather than retrying — which would each start a fresh lookup.
        let calls = Arc::new(AtomicUsize::new(0));
        let never_released = Arc::new(tokio::sync::Semaphore::new(0));
        let resolver = Arc::new(DnsResolver::with_lookup(parked_backend(
            calls.clone(),
            never_released,
            false,
        )));

        // The default policy deadline is 5s; one leader, the rest coalesced.
        let tasks = spawn_resolvers(&resolver, 8).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Time advances to the leader's deadline; every waiter sees `TimedOut`.
        for task in tasks {
            let res = task.await.unwrap();
            assert!(
                matches!(&res, Err(e) if e.kind() == io::ErrorKind::TimedOut),
                "expected TimedOut, got {res:?}"
            );
        }
        // Still exactly one backend lookup despite the timeout — coalescing held.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
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
        // Pre-age the entries past the TTL the store below will apply. `store`
        // stamps `inserted_at` itself, so seed them directly to control it.
        {
            let mut cache = resolver.cache.lock().await;
            for i in 0..MAX_DNS_CACHE_ENTRIES {
                cache.insert(
                    DnsCacheKey::new(&format!("expired{i}.example"), 80),
                    DnsCacheEntry {
                        addrs: vec![answer(80)],
                        inserted_at: now - Duration::from_secs(2),
                    },
                );
            }
        }

        resolver
            .store(
                DnsCacheKey::new("fresh.example", 80),
                vec![answer(80)],
                Duration::from_secs(1),
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
    fn address_allowed_canonicalizes_ipv4_mapped() {
        // The v4-oriented deny categories must catch a mapped v6 form too, or a
        // request to ::ffff:127.0.0.1 would dodge a loopback deny (SSRF).
        let deny = policy(DnsPreference::System, vec![DnsDenyCategory::Loopback]);
        assert!(!address_allowed("::ffff:127.0.0.1".parse().unwrap(), &deny));
        assert!(!address_allowed("127.0.0.1".parse().unwrap(), &deny));
        // A genuine public address (mapped or not) still passes.
        assert!(address_allowed("::ffff:8.8.8.8".parse().unwrap(), &deny));
    }

    #[test]
    fn address_allowed_canonicalizes_ipv4_compatible() {
        // The deprecated IPv4-compatible form `::a.b.c.d` (which `to_canonical`
        // does NOT fold) must also be collapsed, or `::127.0.0.1` would dodge a
        // loopback deny the way `::ffff:127.0.0.1` once did (SSRF). `::1` is still
        // caught here as IPv6 loopback — it is excluded from folding (not turned
        // into `0.0.0.1`).
        let deny = policy(
            DnsPreference::System,
            vec![
                DnsDenyCategory::Loopback,
                DnsDenyCategory::LinkLocal,
                DnsDenyCategory::Private,
            ],
        );
        for ip in ["::127.0.0.1", "::169.254.169.254", "::10.0.0.1", "::1"] {
            assert!(
                !address_allowed(ip.parse().unwrap(), &deny),
                "{ip} should be denied"
            );
        }
        // A genuine public address in compatible form still passes (folded to v4).
        assert!(address_allowed("::8.8.8.8".parse().unwrap(), &deny));
    }

    #[test]
    fn reserved_covers_iana_special_ranges() {
        let deny = policy(DnsPreference::System, vec![DnsDenyCategory::Reserved]);
        // One representative (and a boundary) per reserved range.
        for ip in [
            "0.0.0.0",
            "0.255.255.255", // 0.0.0.0/8
            "100.64.0.1",
            "100.127.255.255", // 100.64.0.0/10 (CGNAT)
            "192.0.0.7",       // 192.0.0.0/24
            "192.88.99.1",     // 192.88.99.0/24 (6to4 relay anycast)
            "198.18.0.1",
            "198.19.255.255", // 198.18.0.0/15 (benchmarking)
            "240.0.0.1",
            "255.255.255.255", // 240.0.0.0/4 + limited broadcast
            "::",
            "::1",
            "2001:db8::1",       // documentation
            "2002::1",           // 6to4 (2002::/16)
            "2002:7f00:1::",     // 6to4 wrapping 127.0.0.1
            "64:ff9b::7f00:1",   // NAT64 well-known prefix wrapping 127.0.0.1
            "64:ff9b::1",        // NAT64 (boundary)
            "2001::1",           // Teredo (2001::/32)
            "2001:20::1",        // ORCHIDv2 (2001:20::/28)
            "2001:1ff:ffff::",   // top of the 2001::/23 IETF block
            "::ffff:198.18.0.1", // mapped form still caught
        ] {
            assert!(
                !address_allowed(ip.parse().unwrap(), &deny),
                "{ip} should be denied as reserved"
            );
        }
        // Public addresses just outside the reserved ranges still pass.
        for ip in [
            "8.8.8.8",
            "100.63.255.255",       // just below 100.64.0.0/10
            "100.128.0.0",          // just above 100.64.0.0/10
            "198.17.255.255",       // just below 198.18.0.0/15
            "198.20.0.0",           // just above 198.18.0.0/15
            "192.88.98.255",        // adjacent to 192.88.99.0/24
            "2001:4860:4860::8888", // Google DNS — above the 2001::/23 block
            "2606:4700:4700::1111", // Cloudflare DNS
            "2003::1",              // allocated unicast, just above 2002::/16
            "2400::1",              // APNIC unicast
        ] {
            assert!(
                address_allowed(ip.parse().unwrap(), &deny),
                "{ip} should be allowed"
            );
        }
    }

    #[tokio::test]
    async fn denies_ipv4_mapped_loopback_and_private() {
        for (literal, category) in [
            ("[::ffff:127.0.0.1]:80", DnsDenyCategory::Loopback),
            ("[::ffff:10.0.0.1]:80", DnsDenyCategory::Private),
        ] {
            let sa: SocketAddr = literal.parse().unwrap();
            let resolved = resolve_all(
                &TargetAddr::Ip(sa),
                &policy(DnsPreference::System, vec![category]),
            )
            .await
            .unwrap();
            assert!(
                resolved.is_empty(),
                "{literal} should be denied as {category:?}"
            );
        }
    }

    #[tokio::test]
    async fn resolve_all_canonicalizes_mapped_addresses() {
        // A mapped literal that passes policy comes back as plain IPv4, so ACL
        // CIDR matching and the outbound connect see the real address.
        let sa: SocketAddr = "[::ffff:8.8.8.8]:53".parse().unwrap();
        let resolved = resolve_all(
            &TargetAddr::Ip(sa),
            &policy(DnsPreference::System, Vec::new()),
        )
        .await
        .unwrap();
        assert_eq!(resolved, vec!["8.8.8.8:53".parse().unwrap()]);
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
        let addrs: Vec<SocketAddr> = vec!["203.0.113.10:80".parse().unwrap()];
        let now = Instant::now();
        let ttl = Duration::from_secs(10);

        // `store` stamps `inserted_at` itself, so seed entries directly to pin it
        // and judge liveness against an explicit `now`.
        let seed = |inserted_at: Instant| DnsCacheEntry {
            addrs: addrs.clone(),
            inserted_at,
        };

        resolver.cache.lock().await.insert(key.clone(), seed(now));
        assert_eq!(
            resolver
                .cached(&key, now + Duration::from_secs(5), ttl)
                .await,
            Some(addrs.clone())
        );
        // Past the TTL: expired (and evicted on the miss).
        assert_eq!(
            resolver
                .cached(&key, now + Duration::from_secs(11), ttl)
                .await,
            None
        );
        // The fix: liveness is judged against the *current* TTL, so a reload
        // that lowered it expires an entry the original TTL would still keep.
        resolver.cache.lock().await.insert(key.clone(), seed(now));
        assert_eq!(
            resolver
                .cached(&key, now + Duration::from_secs(5), Duration::from_secs(3))
                .await,
            None
        );
    }

    #[test]
    fn oversized_ttl_never_expires() {
        let now = Instant::now();
        let entry = DnsCacheEntry {
            addrs: vec![answer(80)],
            inserted_at: now,
        };
        // A TTL larger than any realistic elapsed time keeps the entry live.
        assert!(cache_entry_live(
            &entry,
            now + Duration::from_secs(86_400),
            Duration::MAX
        ));
    }

    #[test]
    fn cache_liveness_uses_current_ttl() {
        let now = Instant::now();
        let entry = DnsCacheEntry {
            addrs: vec![answer(80)],
            inserted_at: now,
        };
        let later = now + Duration::from_secs(30);
        // Within the current TTL: live. Past it: expired.
        assert!(cache_entry_live(&entry, later, Duration::from_secs(60)));
        assert!(!cache_entry_live(
            &entry,
            now + Duration::from_secs(61),
            Duration::from_secs(60)
        ));
        // Same entry and instant, a shorter (reloaded) TTL: expired.
        assert!(!cache_entry_live(&entry, later, Duration::from_secs(10)));
    }

    #[tokio::test]
    async fn cache_evicts_oldest_entry_when_full() {
        let resolver = DnsResolver::new();
        let addrs: Vec<SocketAddr> = vec!["203.0.113.10:80".parse().unwrap()];
        // A long TTL: no entry is expired, so the full-cache path falls through
        // to evicting the oldest.
        let ttl = Duration::from_secs(3600);
        let now = Instant::now();

        // Seed a full cache with distinct, increasing insertion times so the
        // oldest is unambiguous — a coarse clock (Windows, some VMs) could stamp
        // several `store` calls with the same `Instant`. host0 is the oldest.
        {
            let mut cache = resolver.cache.lock().await;
            for i in 0..MAX_DNS_CACHE_ENTRIES {
                cache.insert(
                    DnsCacheKey::new(&format!("host{i}.example"), 80),
                    DnsCacheEntry {
                        addrs: addrs.clone(),
                        inserted_at: now + Duration::from_millis(i as u64),
                    },
                );
            }
        }

        let oldest = DnsCacheKey::new("host0.example", 80);
        resolver
            .store(DnsCacheKey::new("new.example", 80), addrs, ttl)
            .await;

        assert_eq!(resolver.cached(&oldest, Instant::now(), ttl).await, None);
        let cache = resolver.cache.lock().await;
        assert!(cache.contains_key(&DnsCacheKey::new("new.example", 80)));
    }
}
