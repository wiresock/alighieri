//! Data-plane relays: bidirectional TCP copying and the UDP associate relay.
//!
//! These functions contain no policy: authorisation decisions are made by the
//! caller (the [`crate::connection`] state machine) and, for UDP, supplied as
//! an `authorize` closure invoked per destination.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

use crate::client_stream::ClientStream;
use crate::config::DnsPolicy;
use crate::dns::{self, DnsResolver};
use crate::errors::Result;
use crate::metrics::Metrics;
use crate::socks5::{self, TargetAddr};
use crate::throttle::Throttle;

/// A read buffer size that balances syscall overhead against memory use.
const TCP_BUF: usize = 32 * 1024;
/// Upper bound on a single shaping sleep. A normal reservation is far shorter;
/// this just keeps a degenerate (saturated) one from handing the timer an
/// unreasonable duration, and bounds how long a shaped pause goes unmarked.
const MAX_SHAPED_NAP: Duration = Duration::from_secs(3600);
/// Maximum UDP datagram we will buffer (covers a full IPv4 payload).
const UDP_BUF: usize = 65535;
/// Best-effort per-socket UDP buffer target. On Linux the kernel clamps this to
/// `net.core.{r,w}mem_max` (and stores roughly double the request), so operators
/// expecting sustained high throughput should raise those sysctls to actually
/// get the larger buffers.
const UDP_SOCKET_BUFFER: usize = 4 * 1024 * 1024;
/// Consecutive *unexpected* `recv_from` failures tolerated on a relay socket
/// before the association is torn down. ICMP-driven errors (a prior send hit a
/// dead port) are ignored entirely; only a sustained run of *other* failures —
/// a genuinely broken socket — gives up.
const MAX_CONSECUTIVE_UDP_RECV_ERRORS: u32 = 16;
/// Backoff bounds for repeated UDP `recv_from` errors. A single transient error
/// retries after `BASE` (negligible); a socket that errors on every recv backs
/// off toward `MAX` so it cannot spin the relay task on a core.
const UDP_RECV_BACKOFF_BASE: Duration = Duration::from_millis(1);
const UDP_RECV_BACKOFF_MAX: Duration = Duration::from_millis(100);

/// Best-effort enlarge a UDP relay socket's send and receive buffers so a burst
/// of sustained high-rate traffic is absorbed rather than dropped by the kernel.
/// A setsockopt error is ignored, and the OS may silently clamp or adjust the
/// requested size (Linux caps it at `net.core.{r,w}mem_max`).
pub(crate) fn tune_udp_buffers(socket: &UdpSocket) {
    let sock = socket2::SockRef::from(socket);
    let _ = sock.set_recv_buffer_size(UDP_SOCKET_BUFFER);
    let _ = sock.set_send_buffer_size(UDP_SOCKET_BUFFER);
}

/// True for recv errors that are normal while relaying UDP to many destinations:
/// an ICMP unreachable/reset surfaced from a prior send to a dead port (notably
/// `ConnectionReset` on Windows, `ConnectionRefused`/`*Unreachable` on Unix), or
/// an interrupted syscall. These are reported on the receiving socket but say
/// nothing about its health, so the relay ignores them without counting toward
/// teardown.
fn is_transient_recv_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::Interrupted
    )
}

/// `recv_from` on a UDP relay socket, tolerating transient errors. Ignores
/// ICMP-driven/interrupted errors without counting them, resets the counter on
/// success, and surfaces the error (tearing the association down) only once a
/// run of *other* failures exceeds [`MAX_CONSECUTIVE_UDP_RECV_ERRORS`]. Backs
/// off (capped exponential) on every error so a socket that errors on every
/// recv cannot spin the task on a core.
pub(crate) async fn recv_resilient(
    socket: &UdpSocket,
    buf: &mut [u8],
    consecutive_errors: &mut u32,
) -> io::Result<(usize, SocketAddr)> {
    // Counts transient errors since the last successful recv in this call, to
    // grow the backoff when a socket returns a transient error on *every* recv
    // (e.g. a recurring Windows ICMP-driven `ConnectionReset`) so it cannot spin.
    // A non-transient error in between does not reset this — it uses its own
    // counter below, which tears the association down after
    // `MAX_CONSECUTIVE_UDP_RECV_ERRORS` — so a mixed-error storm still backs off
    // and ultimately gives up.
    let mut transient_errors: u32 = 0;
    loop {
        match socket.recv_from(buf).await {
            Ok(v) => {
                *consecutive_errors = 0;
                return Ok(v);
            }
            Err(e) if is_transient_recv_error(&e) => {
                transient_errors = transient_errors.saturating_add(1);
                debug!(error = %e, "udp relay recv: ignoring transient error");
                // Back off (a real sleep, not a bare yield, which reschedules
                // immediately and would still pin a core). Transient errors never
                // count toward teardown.
                tokio::time::sleep(crate::util::capped_exponential_backoff(
                    transient_errors,
                    UDP_RECV_BACKOFF_BASE,
                    UDP_RECV_BACKOFF_MAX,
                ))
                .await;
            }
            Err(e) => {
                *consecutive_errors += 1;
                if *consecutive_errors >= MAX_CONSECUTIVE_UDP_RECV_ERRORS {
                    return Err(e);
                }
                debug!(error = %e, count = *consecutive_errors, "udp relay recv error; continuing");
                tokio::time::sleep(crate::util::capped_exponential_backoff(
                    *consecutive_errors,
                    UDP_RECV_BACKOFF_BASE,
                    UDP_RECV_BACKOFF_MAX,
                ))
                .await;
            }
        }
    }
}

/// Whether a datagram received on the client-facing relay socket is from the
/// legitimate client. Its source IP must equal the association's client IP —
/// compared canonically, so a `::ffff:`-mapped source matches a plain-IPv4 lock
/// and vice versa — and, once the client endpoint is `locked`, its full
/// `ip:port` must match the lock (any other port of the client is rejected).
///
/// Both `src` and `client_ip` are canonicalised internally, so a caller may pass
/// either form without silently rejecting legitimate traffic — this is a shared
/// utility and must not depend on a caller precondition. Canonicalisation is a
/// cheap branch (a no-op for a plain IPv4 address).
///
/// This is the single source of truth for the client-leg source/lock invariant,
/// shared between the core relay loop and the plugin datagram facade.
pub(crate) fn client_source_accepted(
    src: SocketAddr,
    client_ip: IpAddr,
    locked: Option<SocketAddr>,
) -> bool {
    let client_ip = client_ip.to_canonical();
    let src_canon_ip = src.ip().to_canonical();
    if src_canon_ip != client_ip {
        return false; // spoofed / unrelated source
    }
    if let Some(locked) = locked {
        if locked.ip().to_canonical() != src_canon_ip || locked.port() != src.port() {
            return false; // a different port of the client, once locked
        }
    }
    true
}

/// Parses the SOCKS5 UDP request header of a client datagram, rejecting
/// fragmented datagrams (`FRAG != 0`) — fragmentation is rarely used and is a
/// common evasion vector. Returns `None` to drop the datagram (unparseable or
/// fragmented).
///
/// The single source of truth for the client-leg framing invariant, shared
/// between the core relay loop and the plugin datagram facade.
pub(crate) fn parse_client_header(buf: &[u8]) -> Option<socks5::UdpHeader> {
    // FRAG is the third header byte (`RSV(2) FRAG(1) ...`). Reject a fragment on
    // the raw byte before the full parse — which may allocate for a domain ATYP —
    // so a fragment flood cannot make us do that work. Same drop outcome either
    // way: any fragmented or malformed datagram is dropped regardless of order.
    if buf.get(2).is_some_and(|&frag| frag != 0) {
        return None; // drop fragments
    }
    let header = socks5::parse_udp_header(buf).ok()?;
    debug_assert_eq!(header.frag, 0, "FRAG must be zero after the raw pre-check");
    Some(header)
}

/// Runtime options for a UDP ASSOCIATE relay.
pub struct UdpAssociateOptions {
    pub client_ip: IpAddr,
    pub client_endpoint: Option<SocketAddr>,
    pub idle: Duration,
    pub dns_policy: DnsPolicy,
    pub dns_resolver: Arc<DnsResolver>,
    pub metrics: Arc<Metrics>,
    pub throttle: Option<Throttle>,
    /// The outbound socket is a dual-stack IPv6 socket: IPv4 destinations are
    /// sent in `::ffff:` mapped form. See `connection::bind_outbound_udp`.
    pub outbound_dual: bool,
    /// When `true` (the default; `udp.strictreply: true`), a reply must come from
    /// the exact remote `host:port` the client sent to, not merely the same host.
    /// `udp.strictreply: false` relaxes it to host-only for servers that answer
    /// from a different port.
    pub strict_reply: bool,
}

/// Relays data in both directions between `client` and `remote` until both
/// directions finish (or fail), or — when `idle` is non-zero — until the
/// connection carries no traffic in either direction for that long. Returns
/// `(client→remote, remote→client)` byte counts.
pub async fn relay_tcp(
    client: ClientStream,
    remote: TcpStream,
    idle: Duration,
    throttle: Option<Throttle>,
) -> io::Result<(u64, u64)> {
    let (rr, rw) = remote.into_split();
    let idle_opt = if idle.is_zero() { None } else { Some(idle) };

    match client {
        ClientStream::Tcp(client) => {
            let (cr, cw) = client.into_split();
            relay_streams(cr, cw, rr, rw, idle_opt, throttle).await
        }
        ClientStream::Tls(client) => {
            let (cr, cw) = tokio::io::split(client);
            relay_streams(cr, cw, rr, rw, idle_opt, throttle).await
        }
    }
}

/// Like [`relay_tcp`] but generic over any two `AsyncRead + AsyncWrite` streams —
/// the relay a plugin stream interceptor uses for pass-through (`plugin::splice`)
/// and for the decrypted inspect path (`plugin::relay`). Uses `tokio::io::split`
/// on both sides (no owned-split fast path), which is fine off the default relay
/// hot path.
#[cfg(feature = "plugins")]
pub async fn relay_generic<C, R>(
    client: C,
    remote: R,
    idle: Duration,
    throttle: Option<Throttle>,
) -> io::Result<(u64, u64)>
where
    C: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    let (cr, cw) = tokio::io::split(client);
    let (rr, rw) = tokio::io::split(remote);
    let idle_opt = if idle.is_zero() { None } else { Some(idle) };
    relay_streams(cr, cw, rr, rw, idle_opt, throttle).await
}

/// The idle timeout applies to the connection as a whole: traffic in either
/// direction keeps it alive, matching Dante's `iotimeout`. A coarse watchdog
/// enforces it so the hot copy loops never re-arm timers per read.
async fn relay_streams<CR, CW, RR, RW>(
    mut client_read: CR,
    mut client_write: CW,
    mut remote_read: RR,
    mut remote_write: RW,
    idle: Option<Duration>,
    throttle: Option<Throttle>,
) -> io::Result<(u64, u64)>
where
    CR: AsyncRead + Unpin,
    CW: AsyncWrite + Unpin,
    RR: AsyncRead + Unpin,
    RW: AsyncWrite + Unpin,
{
    let up_total = AtomicU64::new(0);
    let down_total = AtomicU64::new(0);
    let activity = ActivityClock::new();
    let result = {
        let up = copy_direction(
            &mut client_read,
            &mut remote_write,
            throttle.as_ref(),
            &activity,
            &up_total,
            idle,
        );
        let down = copy_direction(
            &mut remote_read,
            &mut client_write,
            throttle.as_ref(),
            &activity,
            &down_total,
            idle,
        );
        relay_both(up, down, idle, &activity).await
    };
    // Directions cut off by the idle watchdog have not shut their writers
    // down; doing it here is a no-op for the ones that finished normally.
    let _ = remote_write.shutdown().await;
    let _ = client_write.shutdown().await;
    result?;
    Ok((
        up_total.load(Ordering::Relaxed),
        down_total.load(Ordering::Relaxed),
    ))
}

/// Drives both copy directions to completion, failing fast on errors.
///
/// A clean EOF on one direction (`Ok(())`) leaves the other running for a normal
/// half-close, but an `Err` on either returns immediately and drops the opposite
/// future — so a broken connection never keeps waiting on a half that stays open
/// but idle. With no idle timeout (`iotimeout: 0`) that wait was unbounded and
/// pinned the connection permit; the idle path merely delayed teardown by up to
/// `idle`. When `idle` is set, a coarse watchdog ends the relay after the shared
/// activity clock has been quiet that long.
async fn relay_both<U, D>(
    up: U,
    down: D,
    idle: Option<Duration>,
    activity: &ActivityClock,
) -> io::Result<()>
where
    U: Future<Output = io::Result<()>>,
    D: Future<Output = io::Result<()>>,
{
    tokio::pin!(up, down);
    let mut up_done = false;
    let mut down_done = false;
    let mut ticker = idle.map(|idle| {
        let mut tick = tokio::time::interval(idle_tick_period(idle));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick
    });
    loop {
        tokio::select! {
            // Biased, watchdog last: when a copy future is ready in the same poll
            // as an idle tick, the copy branch wins, so a ready error always
            // propagates (via `res?`) instead of being masked by the watchdog
            // returning `Ok`.
            biased;
            res = &mut up, if !up_done => {
                res?; // propagate a copy error at once, dropping `down`
                up_done = true;
            }
            res = &mut down, if !down_done => {
                res?; // propagate a copy error at once, dropping `up`
                down_done = true;
            }
            // `maybe_tick` keeps this branch inert without an idle timeout. A
            // `select!` precondition only skips *polling* the branch future — the
            // async expression is still evaluated — so a guarded
            // `ticker.as_mut().unwrap().tick()` would panic when the ticker is None.
            _ = maybe_tick(ticker.as_mut()) => {
                if idle.is_some_and(|idle| activity.idle_for() >= idle) {
                    break; // no traffic in either direction for too long
                }
                continue;
            }
        }
        if up_done && down_done {
            break;
        }
    }
    Ok(())
}

/// Ticks `ticker` when an idle timeout is configured; otherwise never resolves,
/// so the watchdog `select!` branch stays inert when there is no idle timeout.
async fn maybe_tick(ticker: Option<&mut tokio::time::Interval>) {
    match ticker {
        Some(tick) => {
            tick.tick().await;
        }
        None => std::future::pending::<()>().await,
    }
}

/// Copies from `r` to `w` until EOF or an error, marking shared activity and
/// accumulating the byte count as it goes. On exit the write half is shut
/// down so the peer observes a clean half-close.
async fn copy_direction<R, W>(
    r: &mut R,
    w: &mut W,
    throttle: Option<&Throttle>,
    activity: &ActivityClock,
    total: &AtomicU64,
    idle: Option<Duration>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; TCP_BUF];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        activity.mark();
        // Shape the flow to the configured rate by waiting for tokens before
        // forwarding, rather than tearing the relay down — backpressure then
        // slows the peer. The wait refreshes the activity clock so the idle
        // watchdog never mistakes a shaped pause for a dead connection.
        if let Some(throttle) = throttle {
            shaped_wait(throttle.reserve(n as u64), activity, idle).await;
        }
        w.write_all(&buf[..n]).await?;
        total.fetch_add(n as u64, Ordering::Relaxed);
    }
    let _ = w.shutdown().await;
    Ok(())
}

/// Sleeps for `wait`, marking `activity` at least every `idle/2` so a long
/// shaped pause keeps the connection alive instead of tripping the idle
/// watchdog. Each sleep is also capped at [`MAX_SHAPED_NAP`] so a degenerate
/// (saturated) reservation never hands an unreasonable duration to the timer.
async fn shaped_wait(wait: Duration, activity: &ActivityClock, idle: Option<Duration>) {
    if wait.is_zero() {
        return;
    }
    // Cap each nap at idle/2 (when set) and never above MAX_SHAPED_NAP.
    let cap = idle
        .map(|d| d / 2)
        .filter(|s| !s.is_zero())
        .map_or(MAX_SHAPED_NAP, |s| s.min(MAX_SHAPED_NAP));
    let mut remaining = wait;
    loop {
        let nap = remaining.min(cap);
        tokio::time::sleep(nap).await;
        activity.mark();
        remaining = remaining.saturating_sub(nap);
        if remaining.is_zero() {
            break;
        }
    }
}

/// Runs a UDP associate relay until the controlling TCP connection closes or
/// the association is idle for `idle` (zero disables the idle timeout).
///
/// The two datagram directions run as separate tasks so they relay
/// concurrently — a single serialized loop caps packet rate at one
/// recv+send round per iteration. The parent task watches the control
/// connection and the idle clock, and aborts the direction tasks on
/// teardown.
///
/// Security properties:
/// - Only datagrams whose source IP equals `client_ip` are accepted, defeating
///   trivial off-path spoofing of the relay.
/// - Every destination is passed through `authorize` before a packet is
///   forwarded, so UDP traffic obeys the same rule set as TCP.
/// - Fragmented datagrams (`FRAG != 0`) are dropped — fragmentation is rarely
///   used and is a common evasion vector.
pub async fn run_udp_associate<C, F, G>(
    mut control: C,
    relay_socket: UdpSocket,
    outbound: UdpSocket,
    options: UdpAssociateOptions,
    authorize: F,
    on_datagram: G,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    F: Fn(Option<&str>, IpAddr, u16) -> bool + Send + Sync + 'static,
    // Per-datagram plugin verdict, `(is_reply, dst, payload) -> forward?`. Kept as
    // core types (not `plugin::DatagramVerdict`) so the UDP relay stays compiled in
    // every build; the default caller passes `|_, _, _| true`, which monomorphizes
    // the check away. `false` drops the datagram, exactly like an authorize denial.
    G: Fn(bool, SocketAddr, &[u8]) -> bool + Clone + Send + Sync + 'static,
{
    let relay_socket = Arc::new(relay_socket);
    let outbound = Arc::new(outbound);
    // The client's UDP endpoint: optionally pre-announced in the associate
    // request, otherwise locked to the first fully validated source.
    let client_endpoint = Arc::new(OnceLock::new());
    if let Some(endpoint) = options.client_endpoint {
        let _ = client_endpoint.set(endpoint);
    }
    let activity = Arc::new(ActivityClock::new());
    // Remote endpoints the client has sent to; replies from any other source are
    // dropped as unsolicited injection (see `ContactedRemotes` for the IP-only
    // vs strict `host:port` match modes).
    let contacted = Arc::new(Mutex::new(ContactedRemotes::new(options.strict_reply)));

    let mut client_to_remote = tokio::spawn(relay_client_to_remote(
        relay_socket.clone(),
        outbound.clone(),
        options.client_ip,
        options.dns_policy,
        options.dns_resolver,
        options.metrics.clone(),
        options.throttle.clone(),
        client_endpoint.clone(),
        activity.clone(),
        contacted.clone(),
        options.outbound_dual,
        authorize,
        on_datagram.clone(),
    ));
    let mut remote_to_client = tokio::spawn(relay_remote_to_client(
        outbound,
        relay_socket,
        options.metrics,
        options.throttle,
        client_endpoint,
        activity.clone(),
        contacted,
        on_datagram,
    ));

    // Idleness is enforced with a coarse periodic check rather than a timer
    // armed per packet: re-registering a timer for every datagram costs more
    // than the tick on busy associations.
    let idle_enabled = !options.idle.is_zero();
    let tick_period = if idle_enabled {
        idle_tick_period(options.idle)
    } else {
        Duration::from_secs(3600)
    };
    let mut idle_tick = tokio::time::interval(tick_period);
    idle_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut ctrl_buf = [0u8; 512];

    let result = loop {
        tokio::select! {
            // The control connection is only a teardown signal: its closing ends
            // the association, but data on it (unexpected) must not refresh the
            // UDP idle timer — only an accepted datagram does.
            res = control.read(&mut ctrl_buf) => {
                match res {
                    Ok(0) | Err(_) => break Ok(()),
                    Ok(_) => continue, // unexpected data — ignore, keep relaying
                }
            }
            res = &mut client_to_remote => break flatten_direction(res),
            res = &mut remote_to_client => break flatten_direction(res),
            _ = idle_tick.tick() => {
                if idle_enabled && activity.idle_for() >= options.idle {
                    break Ok(()); // idle for too long
                }
            }
        }
    };
    client_to_remote.abort();
    remote_to_client.abort();
    result
}

fn flatten_direction(
    joined: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> Result<()> {
    match joined {
        Ok(result) => result,
        Err(e) => Err(crate::errors::Error::Io(std::io::Error::other(e))),
    }
}

/// Cap on remembered remote destinations per UDP association. The set is
/// consulted on every reply, and the least-recently-recorded IP is evicted at
/// the cap, which only a client contacting a very large number of distinct
/// destinations could reach. 256 covers ordinary UDP use comfortably.
const MAX_CONTACTED_REMOTES: usize = 256;

/// The remote endpoints a client has sent to on one UDP association, shared
/// between the two relay tasks. A reply is forwarded to the client only from a
/// recorded remote, so an off-path host cannot inject unsolicited datagrams.
///
/// Matching is always on the canonical IP (so an IPv4 reply on a dual-stack
/// socket, arriving `::ffff:`-mapped, still matches). When `match_port` is set
/// (the `udp.strictreply` option) the reply's source *port* must match too;
/// otherwise any port on a contacted host is accepted, which tolerates a server
/// that answers from a different port (e.g. TFTP). Bounded (the
/// least-recently-recorded entry is evicted at the cap) so it cannot grow
/// without limit.
///
/// Keys are rebuilt from the canonical IP and port via `SocketAddr::new`, which
/// deliberately drops IPv6 `scope_id`/`flowinfo`: a reply's `recvfrom` zone can
/// differ from the zone-less address in the SOCKS request, so folding it into
/// the key would drop legitimate replies for no security gain (the prior
/// `IpAddr`-only match excluded it too).
pub(crate) struct ContactedRemotes {
    seen: HashMap<SocketAddr, u64>,
    ticks: u64,
    /// When set, the source port is part of the key (strict matching); otherwise
    /// it is ignored so every port on a contacted host shares one entry.
    match_port: bool,
}

impl ContactedRemotes {
    fn new(match_port: bool) -> Self {
        ContactedRemotes {
            seen: HashMap::new(),
            ticks: 0,
            match_port,
        }
    }

    /// The lookup key for an already-canonical `addr`: the port is kept only in
    /// strict mode, otherwise zeroed so all ports on a host collapse to one key.
    fn key(&self, addr: SocketAddr) -> SocketAddr {
        if self.match_port {
            addr
        } else {
            SocketAddr::new(addr.ip(), 0)
        }
    }

    /// Records that the client sent to `addr` (pass the canonical form).
    fn record(&mut self, addr: SocketAddr) {
        let key = self.key(addr);
        self.ticks += 1;
        if self.seen.len() >= MAX_CONTACTED_REMOTES && !self.seen.contains_key(&key) {
            if let Some(oldest) = self
                .seen
                .iter()
                .min_by_key(|(_, &tick)| tick)
                .map(|(addr, _)| *addr)
            {
                self.seen.remove(&oldest);
            }
        }
        self.seen.insert(key, self.ticks);
    }

    /// Whether the client has sent to `addr` (pass the canonical form).
    fn contains(&self, addr: SocketAddr) -> bool {
        self.seen.contains_key(&self.key(addr))
    }
}

/// Coarse last-activity tracking shared across a relay's tasks. Uses the
/// tokio clock so idle behaviour is testable under paused time.
pub(crate) struct ActivityClock {
    started: tokio::time::Instant,
    last_ms: AtomicU64,
}

impl ActivityClock {
    fn new() -> Self {
        ActivityClock {
            started: tokio::time::Instant::now(),
            last_ms: AtomicU64::new(0),
        }
    }

    fn mark(&self) {
        let ms = self.started.elapsed().as_millis() as u64;
        self.last_ms.store(ms, Ordering::Relaxed);
    }

    fn idle_for(&self) -> Duration {
        let now_ms = self.started.elapsed().as_millis() as u64;
        Duration::from_millis(now_ms.saturating_sub(self.last_ms.load(Ordering::Relaxed)))
    }
}

/// Watchdog granularity for an idle timeout: coarse enough to stay off the
/// hot path, fine enough that overshoot stays within a quarter of the limit
/// for the second-granularity timeouts the config can express. The 250 ms
/// floor binds only for sub-second limits, where overshoot may reach the
/// full floor.
fn idle_tick_period(idle: Duration) -> Duration {
    (idle / 4).clamp(Duration::from_millis(250), Duration::from_secs(15))
}

#[allow(clippy::too_many_arguments)]
async fn relay_client_to_remote<F, G>(
    relay_socket: Arc<UdpSocket>,
    outbound: Arc<UdpSocket>,
    client_ip: IpAddr,
    dns_policy: DnsPolicy,
    dns_resolver: Arc<DnsResolver>,
    metrics: Arc<Metrics>,
    throttle: Option<Throttle>,
    client_endpoint: Arc<OnceLock<SocketAddr>>,
    activity: Arc<ActivityClock>,
    contacted: Arc<Mutex<ContactedRemotes>>,
    outbound_dual: bool,
    authorize: F,
    on_datagram: G,
) -> Result<()>
where
    F: Fn(Option<&str>, IpAddr, u16) -> bool,
    G: Fn(bool, SocketAddr, &[u8]) -> bool,
{
    let mut buf = vec![0u8; UDP_BUF];
    let mut recv_errors = 0u32;
    loop {
        let (n, src) = recv_resilient(&relay_socket, &mut buf, &mut recv_errors).await?;
        // Accept only datagrams from the legitimate client. `src` is kept in the
        // socket's own family (it is stored as the reply target below and must
        // stay sendable on this socket); `client_source_accepted` canonicalises
        // both addresses internally. The predeclared lock is stored in the
        // client's family by `requested_udp_endpoint`.
        if !client_source_accepted(src, client_ip, client_endpoint.get().copied()) {
            continue; // spoofed / unrelated / off-lock source
        }

        let header = match parse_client_header(&buf[..n]) {
            Some(h) => h,
            None => continue, // unparseable or fragmented
        };
        // IP literals — the common case for UDP — skip the resolver and its
        // address-list allocation entirely.
        let dest = match &header.dest {
            TargetAddr::Ip(sa) => {
                // Canonicalise a mapped literal (`::ffff:a.b.c.d`) so the deny
                // check, the per-packet authoriser, and the forward all act on
                // the real IPv4 address. (The resolver already canonicalises the
                // domain branch below.)
                let sa = SocketAddr::new(sa.ip().to_canonical(), sa.port());
                if !dns::address_allowed(sa.ip(), &dns_policy) {
                    continue;
                }
                sa
            }
            domain => match dns_resolver.resolve_one(domain, &dns_policy).await {
                Ok(Some(sa)) => sa,
                Ok(None) => continue,
                Err(_) => continue,
            },
        };
        // Hostname the client requested in the SOCKS UDP header (for `to:`
        // hostname rules), matched before resolution; `None` for an IP literal.
        let host = match &header.dest {
            TargetAddr::Domain(d, _) => Some(d.as_str()),
            TargetAddr::Ip(_) => None,
        };
        if !authorize(host, dest.ip(), dest.port()) {
            continue;
        }
        // Per-datagram plugin verdict (client→target). A drop behaves exactly like
        // an authorize denial: the datagram is not recorded as a contacted remote,
        // forwarded, or counted as activity, so the association invariants below are
        // untouched.
        if !on_datagram(false, dest, &buf[header.payload_offset..n]) {
            continue;
        }
        let _ = client_endpoint.set(src);
        // Remember the destination before sending, so a fast reply is already
        // recognised by relay_remote_to_client; replies from any other remote are
        // dropped there as unsolicited injection. Store the canonical endpoint so
        // an IPv4 reply on a dual-stack socket (`::ffff:`) still matches; whether
        // the port is part of the match is decided inside `ContactedRemotes` by
        // `udp.strictreply`. Canonicalize before locking to keep the critical
        // section minimal.
        let dest_canon = SocketAddr::new(dest.ip().to_canonical(), dest.port());
        contacted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record(dest_canon);
        // A fully validated, authorized datagram from the locked client endpoint
        // is genuine client use of the association, so it refreshes the idle
        // timer here — even if the token bucket below then polices it or the send
        // fails (both are our delivery concerns, not the client's liveness).
        // Spoofed/unrelated sources, malformed headers, fragments, and
        // denied/unauthorized destinations were all dropped above without ever
        // reaching this point.
        activity.mark();
        let payload = &buf[header.payload_offset..n];
        // Police the datagram against the token bucket: drop it when the bucket
        // is short rather than delaying real-time traffic.
        if throttle
            .as_ref()
            .is_some_and(|t| !t.police(payload.len() as u64))
        {
            metrics.rate_limited();
            continue;
        }
        // A dual-stack outbound socket needs IPv4 destinations in `::ffff:`
        // mapped form; `dest` was already canonicalised to a real IPv4 above.
        let mut send_dest = dest;
        if outbound_dual {
            if let SocketAddr::V4(v4) = dest {
                send_dest.set_ip(IpAddr::V6(v4.ip().to_ipv6_mapped()));
            }
        }
        match outbound.send_to(payload, send_dest).await {
            Ok(_) => metrics.udp_client_packet_relayed(payload.len() as u64),
            Err(e) => {
                // Surface the failure instead of dropping silently — e.g. an
                // IPv6 destination on an IPv4-pinned `external`.
                metrics.udp_send_failed();
                debug!(dest = %dest, error = %e, "UDP outbound send failed");
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn relay_remote_to_client<G>(
    outbound: Arc<UdpSocket>,
    relay_socket: Arc<UdpSocket>,
    metrics: Arc<Metrics>,
    throttle: Option<Throttle>,
    client_endpoint: Arc<OnceLock<SocketAddr>>,
    activity: Arc<ActivityClock>,
    contacted: Arc<Mutex<ContactedRemotes>>,
    on_datagram: G,
) -> Result<()>
where
    G: Fn(bool, SocketAddr, &[u8]) -> bool,
{
    // Headroom in front of the receive area lets the relay prepend the SOCKS
    // header in place instead of allocating per packet.
    let mut buf = vec![0u8; socks5::UDP_IP_HEADER_MAX + UDP_BUF];
    let mut recv_errors = 0u32;
    loop {
        let (n, remote_src) = recv_resilient(
            &outbound,
            &mut buf[socks5::UDP_IP_HEADER_MAX..],
            &mut recv_errors,
        )
        .await?;
        let Some(caddr) = client_endpoint.get().copied() else {
            continue; // no client endpoint locked yet — do not refresh idle
        };
        // Forward only replies from a remote the client has actually sent to;
        // drop the rest so an off-path host cannot inject unsolicited UDP to the
        // client. Match on the canonical endpoint (an IPv4 reply on a dual-stack
        // socket arrives `::ffff:`-mapped); `ContactedRemotes` decides whether the
        // port must match (`udp.strictreply`). Canonicalize before locking to keep
        // the critical section minimal. Dropped injections do not refresh idle.
        let remote_canon = SocketAddr::new(remote_src.ip().to_canonical(), remote_src.port());
        if !contacted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(remote_canon)
        {
            continue;
        }
        // Per-datagram plugin verdict (target→client). Dropped before marking
        // activity, so a dropped reply does not keep the association alive — the
        // same treatment an unsolicited-source reply gets above. Pass the
        // canonical peer (`remote_canon`), not the raw `::ffff:`-mapped source a
        // dual-stack socket reports, so `dst` matches the client→target direction.
        if !on_datagram(
            true,
            remote_canon,
            &buf[socks5::UDP_IP_HEADER_MAX..socks5::UDP_IP_HEADER_MAX + n],
        ) {
            continue;
        }
        // A reply for an established association counts as activity; packets that
        // arrive before the client's endpoint is locked do not keep it alive.
        activity.mark();
        let prefix: &mut [u8; socks5::UDP_IP_HEADER_MAX] = (&mut buf[..socks5::UDP_IP_HEADER_MAX])
            .try_into()
            .expect("prefix slice is UDP_IP_HEADER_MAX bytes");
        let start = socks5::write_udp_header_tail(remote_src, prefix);
        let datagram = &buf[start..socks5::UDP_IP_HEADER_MAX + n];
        if throttle
            .as_ref()
            .is_some_and(|t| !t.police(datagram.len() as u64))
        {
            metrics.rate_limited();
            continue;
        }
        match relay_socket.send_to(datagram, caddr).await {
            Ok(_) => metrics.udp_remote_packet_relayed(n as u64),
            Err(e) => {
                // Surface the failed reply instead of dropping it silently — e.g.
                // a gone client socket or an endpoint-family mismatch — mirroring
                // the outbound direction above.
                metrics.udp_send_failed();
                debug!(client = %caddr, error = %e, "UDP reply to client failed");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Plugin datagram facades (UDP association takeover)
// ---------------------------------------------------------------------------
//
// When a plugin takes over a UDP association to run its own datagram stack (a
// QUIC/HTTP-3 MITM), it must NOT get the raw sockets: the client-leg SOCKS5
// framing and every association invariant the core enforces (source-IP match,
// endpoint lock, fragment drop, DNS-deny, ACL, contacted-remotes reply gating,
// idle accounting) still have to hold. These two facades own the sockets and
// enforce exactly those invariants, so the plugin only ever sees clean payloads
// and can never originate to an unvetted destination. They wrap the same
// primitives the core relay loop uses (`recv_resilient`, `client_source_accepted`,
// `parse_client_header`, `ContactedRemotes`, `ActivityClock`), so a taken-over
// association is byte-for-byte as safe as a core-relayed one.
//
// These land here (unwired) ahead of the `DatagramInterceptor`/`AssociationArgs`
// takeover seam; constructors are `pub(crate)` — the core builds them and hands
// them over — while the data-plane methods are public for the plugin to call.

/// The client-facing datagram endpoint of a taken-over UDP association.
///
/// [`recv`](Self::recv) yields fully validated, SOCKS5-header-stripped payloads
/// (a clean QUIC datagram) together with the origin the client addressed;
/// [`send`](Self::send) re-frames a reply with the SOCKS5 UDP header and delivers
/// it to the locked client endpoint. The SOCKS5 framing never crosses this
/// boundary, which is why the facade is mandatory rather than a raw socket.
#[cfg(feature = "plugins")]
pub struct ClientDatagrams {
    /// The bound relay socket the client sends its datagrams to (already
    /// advertised to the client as BND.ADDR/PORT — never rebound).
    socket: Arc<UdpSocket>,
    /// The association's client IP; a datagram from any other source is dropped.
    client_ip: IpAddr,
    /// The client's UDP endpoint: locked to the first fully validated source (or
    /// pre-seeded from the ASSOCIATE request). Shared with the core so idle and
    /// teardown accounting stay consistent.
    client_endpoint: Arc<OnceLock<SocketAddr>>,
    /// Shared idle clock, marked only on an accepted datagram.
    activity: Arc<ActivityClock>,
    throttle: Option<Throttle>,
    metrics: Arc<Metrics>,
}

#[cfg(feature = "plugins")]
impl ClientDatagrams {
    // The core builds this when it hands an association to an interceptor; that
    // call site lands with the `AssociationArgs` takeover seam, so until then it
    // is exercised only by tests.
    #[allow(dead_code)]
    pub(crate) fn new(
        socket: Arc<UdpSocket>,
        client_ip: IpAddr,
        client_endpoint: Arc<OnceLock<SocketAddr>>,
        activity: Arc<ActivityClock>,
        throttle: Option<Throttle>,
        metrics: Arc<Metrics>,
    ) -> Self {
        ClientDatagrams {
            socket,
            client_ip,
            client_endpoint,
            activity,
            throttle,
            metrics,
        }
    }

    /// Receives the next datagram genuinely from the client, with the SOCKS5
    /// header stripped. Datagrams that fail a client-leg invariant are dropped
    /// and the method keeps waiting: a wrong source IP, a port other than the
    /// locked endpoint, a malformed or fragmented header, or a domain-addressed
    /// datagram (proxy-side DNS is not supported on a taken-over association — a
    /// QUIC/UDP client addresses an IP endpoint directly). The first accepted
    /// datagram locks the client endpoint and marks the association active.
    ///
    /// The payload is written to `buf[..len]` and returned as `(len, origin)`,
    /// where `origin` is the canonical destination the client addressed. `buf`
    /// must be large enough for a whole datagram (header included); a QUIC packet
    /// fits comfortably. Returns `Err` only if the socket itself fails.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut recv_errors = 0u32;
        loop {
            let (n, src) = recv_resilient(&self.socket, buf, &mut recv_errors).await?;
            if !client_source_accepted(src, self.client_ip, self.client_endpoint.get().copied()) {
                continue; // spoofed / unrelated / off-lock source
            }
            // Domain-addressed datagrams are unsupported on a taken-over
            // association (dropped below). Reject on the raw ATYP byte before the
            // full parse, which would otherwise allocate and validate the domain
            // string for untrusted input — the same short-circuit idea as the
            // fragment drop inside `parse_client_header`.
            if buf[..n].get(3) == Some(&socks5::ATYP_DOMAIN) {
                continue;
            }
            let header = match parse_client_header(&buf[..n]) {
                Some(h) => h,
                None => continue, // unparseable or fragmented
            };
            let payload_offset = header.payload_offset;
            let origin = match header.dest {
                TargetAddr::Ip(sa) => SocketAddr::new(sa.ip().to_canonical(), sa.port()),
                // Pre-filtered on the ATYP byte above; kept for exhaustiveness.
                TargetAddr::Domain(..) => continue,
            };
            // A fully validated datagram locks the client endpoint (kept in the
            // socket's own family so it stays a valid reply target) and refreshes
            // the idle clock — even if a later reply send fails.
            let _ = self.client_endpoint.set(src);
            self.activity.mark();
            let payload_len = n - payload_offset;
            buf.copy_within(payload_offset..n, 0);
            return Ok((payload_len, origin));
        }
    }

    /// Sends `payload` to the client as a reply appearing to come from `from`,
    /// prepending the SOCKS5 UDP header (canonical ATYP). A no-op (returns `Ok`)
    /// until the client endpoint is locked — there is nowhere to reply to yet,
    /// mirroring the core relay. Police-drops under the shaping throttle. Returns
    /// `Err` only if the socket send fails.
    pub async fn send(&self, from: SocketAddr, payload: &[u8]) -> io::Result<()> {
        let Some(caddr) = self.client_endpoint.get().copied() else {
            return Ok(()); // client endpoint not locked yet — nothing to reply to
        };
        // Lay the header in front of the payload in one buffer (header tail is
        // written into the headroom, then the datagram starts at `start`).
        //
        // NOTE: this allocates per datagram, unlike the core relay's
        // `relay_remote_to_client`, which reuses a headroom buffer. A zero-alloc
        // path here needs a buffer whose lifetime spans the async send without a
        // lock held across `.await`; that buffer model is co-designed with the
        // quinn `AsyncUdpSocket` shim (its GSO `Transmit` batching may emit
        // several datagrams per call), so it is deferred to that PR rather than
        // fixed on this still-unwired facade.
        let mut datagram = vec![0u8; socks5::UDP_IP_HEADER_MAX + payload.len()];
        datagram[socks5::UDP_IP_HEADER_MAX..].copy_from_slice(payload);
        let prefix: &mut [u8; socks5::UDP_IP_HEADER_MAX] = (&mut datagram
            [..socks5::UDP_IP_HEADER_MAX])
            .try_into()
            .expect("prefix slice is UDP_IP_HEADER_MAX bytes");
        let start = socks5::write_udp_header_tail(from, prefix);
        let out = &datagram[start..];
        if self
            .throttle
            .as_ref()
            .is_some_and(|t| !t.police(out.len() as u64))
        {
            self.metrics.rate_limited();
            return Ok(());
        }
        self.socket.send_to(out, caddr).await?;
        self.metrics.udp_remote_packet_relayed(payload.len() as u64);
        Ok(())
    }

    /// The relay socket address advertised to the client (BND.ADDR/PORT).
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// The locked client endpoint, or `None` before the first validated datagram.
    pub fn client_endpoint(&self) -> Option<SocketAddr> {
        self.client_endpoint.get().copied()
    }
}

/// Proof that a destination passed DNS-deny and the SOCKS ACL. The only way to
/// obtain one is [`UpstreamOriginator::authorize`], and
/// [`UpstreamOriginator::send_to`] takes one by reference — so a plugin cannot
/// originate a datagram to an unvetted address (the SSRF gate is type-enforced).
#[cfg(feature = "plugins")]
#[non_exhaustive]
pub struct UpstreamTarget {
    dst: SocketAddr,
}

#[cfg(feature = "plugins")]
impl UpstreamTarget {
    /// The canonical destination this token authorizes.
    pub fn dst(&self) -> SocketAddr {
        self.dst
    }
}

/// The per-destination SOCKS ACL a taken-over association consults for every
/// upstream destination: `(host, ip, port) -> allowed`. It also records its own
/// rule-hit / deny metrics. Shared (`Arc`) so the closure the core already built
/// for the connection is reused unchanged.
#[cfg(feature = "plugins")]
pub(crate) type DatagramAuthorizer = Arc<dyn Fn(Option<&str>, IpAddr, u16) -> bool + Send + Sync>;

/// The origin-facing leg of a taken-over UDP association. Every destination must
/// clear [`authorize`](Self::authorize) (DNS-deny + the SOCKS ACL) before a
/// datagram can be sent to it, and replies are accepted only from destinations
/// the association has actually contacted — the same guarantees the core relay
/// gives, enforced here so a plugin-owned association cannot weaken them.
#[cfg(feature = "plugins")]
pub struct UpstreamOriginator {
    outbound: Arc<UdpSocket>,
    /// The outbound socket is dual-stack: IPv4 destinations are sent `::ffff:`-mapped.
    outbound_dual: bool,
    dns_policy: DnsPolicy,
    authorize: DatagramAuthorizer,
    /// Destinations the association has sent to; replies from anything else are
    /// dropped as unsolicited injection.
    contacted: Arc<Mutex<ContactedRemotes>>,
    /// Shared idle clock, marked only on an accepted reply.
    activity: Arc<ActivityClock>,
    throttle: Option<Throttle>,
    metrics: Arc<Metrics>,
}

#[cfg(feature = "plugins")]
impl UpstreamOriginator {
    // Built by the core at association takeover (with the wiring PR); until then
    // it is exercised only by tests.
    #[allow(dead_code, clippy::too_many_arguments)]
    pub(crate) fn new(
        outbound: Arc<UdpSocket>,
        outbound_dual: bool,
        dns_policy: DnsPolicy,
        authorize: DatagramAuthorizer,
        contacted: Arc<Mutex<ContactedRemotes>>,
        activity: Arc<ActivityClock>,
        throttle: Option<Throttle>,
        metrics: Arc<Metrics>,
    ) -> Self {
        UpstreamOriginator {
            outbound,
            outbound_dual,
            dns_policy,
            authorize,
            contacted,
            activity,
            throttle,
            metrics,
        }
    }

    /// Vets an IP destination against DNS-deny and the SOCKS ACL (with `host` for
    /// hostname rules, e.g. the SNI). Returns the [`UpstreamTarget`] token needed
    /// to send to it, or `None` if either check denies it. This is the only
    /// producer of an `UpstreamTarget`.
    pub fn authorize(&self, host: Option<&str>, dst: SocketAddr) -> Option<UpstreamTarget> {
        let dst = SocketAddr::new(dst.ip().to_canonical(), dst.port());
        if !dns::address_allowed(dst.ip(), &self.dns_policy) {
            return None;
        }
        if !(self.authorize)(host, dst.ip(), dst.port()) {
            return None;
        }
        Some(UpstreamTarget { dst })
    }

    /// Sends `payload` to a vetted destination, recording it as contacted so its
    /// replies are accepted. Applies the dual-stack `::ffff:` mapping and the
    /// shaping throttle (police-drop under pressure). Returns `Err` only if the
    /// socket send fails.
    pub async fn send_to(&self, target: &UpstreamTarget, payload: &[u8]) -> io::Result<()> {
        // Record before sending so a fast reply is already recognised, matching
        // the core relay (record even if the throttle then drops this datagram).
        self.contacted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record(target.dst);
        if self
            .throttle
            .as_ref()
            .is_some_and(|t| !t.police(payload.len() as u64))
        {
            self.metrics.rate_limited();
            return Ok(());
        }
        let mut send_dest = target.dst;
        if self.outbound_dual {
            if let SocketAddr::V4(v4) = target.dst {
                send_dest.set_ip(IpAddr::V6(v4.ip().to_ipv6_mapped()));
            }
        }
        self.outbound.send_to(payload, send_dest).await?;
        self.metrics.udp_client_packet_relayed(payload.len() as u64);
        Ok(())
    }

    /// Receives the next reply from a contacted origin. Replies from a source the
    /// association never contacted are dropped (unsolicited injection) and the
    /// method keeps waiting. An accepted reply marks the association active.
    /// Returns `(len, origin)` with `origin` canonicalised, and `Err` only if the
    /// socket fails.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut recv_errors = 0u32;
        loop {
            let (n, remote_src) = recv_resilient(&self.outbound, buf, &mut recv_errors).await?;
            let remote_canon = SocketAddr::new(remote_src.ip().to_canonical(), remote_src.port());
            if !self
                .contacted
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(remote_canon)
            {
                continue; // reply from an uncontacted source — drop
            }
            self.activity.mark();
            return Ok((n, remote_canon));
        }
    }

    /// Whether the outbound socket is dual-stack (IPv4 sent `::ffff:`-mapped).
    pub fn is_dual_stack(&self) -> bool {
        self.outbound_dual
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test(start_paused = true)]
    async fn idle_relay_stays_alive_while_one_direction_flows() {
        let (client, mut client_peer) = tokio::io::duplex(64 * 1024);
        let (remote, mut remote_peer) = tokio::io::duplex(64 * 1024);
        let (cr, cw) = tokio::io::split(client);
        let (rr, rw) = tokio::io::split(remote);
        let relay = tokio::spawn(relay_streams(
            cr,
            cw,
            rr,
            rw,
            Some(Duration::from_secs(5)),
            None,
        ));

        // The client direction stays silent the whole time; traffic in the
        // remote direction alone must keep the connection alive. Under the
        // old per-direction timeout this relay died after five seconds.
        let mut received = [0u8; 4];
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            remote_peer.write_all(b"ping").await.unwrap();
            client_peer.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, b"ping");
        }
        assert!(!relay.is_finished());

        drop(remote_peer);
        drop(client_peer);
        let (up, down) = relay.await.unwrap().unwrap();
        assert_eq!(up, 0);
        assert_eq!(down, 12);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_relay_times_out_quiet_connections() {
        let (client, client_peer) = tokio::io::duplex(64 * 1024);
        let (remote, remote_peer) = tokio::io::duplex(64 * 1024);
        let (cr, cw) = tokio::io::split(client);
        let (rr, rw) = tokio::io::split(remote);
        let relay = tokio::spawn(relay_streams(
            cr,
            cw,
            rr,
            rw,
            Some(Duration::from_secs(5)),
            None,
        ));

        // Both peers stay open but silent: only the watchdog can end this.
        let result = tokio::time::timeout(Duration::from_secs(30), relay)
            .await
            .expect("idle watchdog should end the relay");
        let (up, down) = result.unwrap().unwrap();
        assert_eq!((up, down), (0, 0));
        drop(client_peer);
        drop(remote_peer);
    }

    #[tokio::test]
    async fn relay_tcp_echoes_both_directions() {
        // Set up an echo server as the "remote".
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                let n = s.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                s.write_all(&buf[..n]).await.unwrap();
            }
        });

        // A second listener stands in for the "client" side of the relay.
        let client_side = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_side_addr = client_side.local_addr().unwrap();

        let remote = TcpStream::connect(echo_addr).await.unwrap();

        // Connect a real client and accept it to obtain the proxy-side stream.
        let mut client = TcpStream::connect(client_side_addr).await.unwrap();
        let (proxy_client, _) = client_side.accept().await.unwrap();

        tokio::spawn(async move {
            let _ = relay_tcp(
                ClientStream::Tcp(proxy_client),
                remote,
                Duration::ZERO,
                None,
            )
            .await;
        });

        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test(start_paused = true)]
    async fn copy_direction_shapes_instead_of_dropping() {
        use crate::throttle::TokenBucket;
        use std::sync::Mutex;

        // 1000 B/s with a 1000 B burst. Copying 3000 bytes spends the burst
        // immediately and then shapes the remaining 2000 B over ~2s — and, unlike
        // the old hard cap, forwards every byte rather than tearing down.
        let throttle = Throttle::new().with_bucket(Arc::new(Mutex::new(TokenBucket::new(
            1000.0,
            1000.0,
            std::time::Instant::now(),
        ))));
        let data = vec![0u8; 3000];
        let mut reader = &data[..];
        let mut writer = tokio::io::sink();
        let activity = ActivityClock::new();
        let total = AtomicU64::new(0);

        let start = tokio::time::Instant::now();
        copy_direction(
            &mut reader,
            &mut writer,
            Some(&throttle),
            &activity,
            &total,
            None,
        )
        .await
        .unwrap();

        assert_eq!(total.load(Ordering::Relaxed), 3000, "all bytes forwarded");
        assert!(
            start.elapsed() >= Duration::from_millis(1900),
            "expected ~2s of shaping, got {:?}",
            start.elapsed()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn relay_both_fails_fast_when_a_direction_errors() {
        // With no idle timeout, an error on one direction must not keep waiting on
        // the other half staying open — that would hang and pin the permit.
        let activity = ActivityClock::new();
        let up = async { Err::<(), io::Error>(io::Error::other("up failed")) };
        let down = std::future::pending::<io::Result<()>>();
        let outcome = tokio::time::timeout(
            Duration::from_secs(3600),
            relay_both(up, down, None, &activity),
        )
        .await
        .expect("relay must not hang when one direction errors");
        assert!(outcome.is_err(), "the copy error must propagate");
    }

    #[tokio::test(start_paused = true)]
    async fn relay_both_waits_for_the_open_half_after_a_clean_close() {
        // A clean EOF (`Ok`) on one direction is a half-close: the other half must
        // keep relaying rather than tear the connection down.
        let activity = ActivityClock::new();
        let up = async { Ok::<(), io::Error>(()) };
        let down = std::future::pending::<io::Result<()>>();
        let outcome = tokio::time::timeout(
            Duration::from_secs(60),
            relay_both(up, down, None, &activity),
        )
        .await;
        assert!(
            outcome.is_err(),
            "relay must keep waiting for the open half after a clean half-close"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn relay_both_completes_when_both_directions_finish() {
        let activity = ActivityClock::new();
        let up = async { Ok::<(), io::Error>(()) };
        let down = async { Ok::<(), io::Error>(()) };
        relay_both(up, down, None, &activity)
            .await
            .expect("both directions closing cleanly is success");
    }

    #[tokio::test(start_paused = true)]
    async fn relay_both_ends_on_idle_timeout() {
        // Both directions stay open but silent; the watchdog must end the relay.
        let activity = ActivityClock::new();
        let up = std::future::pending::<io::Result<()>>();
        let down = std::future::pending::<io::Result<()>>();
        let outcome = tokio::time::timeout(
            Duration::from_secs(3600),
            relay_both(up, down, Some(Duration::from_secs(10)), &activity),
        )
        .await
        .expect("the idle watchdog must end the relay");
        assert!(outcome.is_ok(), "an idle timeout ends the relay cleanly");
    }

    #[tokio::test(start_paused = true)]
    async fn shaped_wait_keeps_connection_alive_under_small_idle() {
        // A 10s shaped wait with a 2s idle timeout must refresh activity at least
        // every idle/2, so a watchdog polling every idle never sees the
        // connection idle for the full timeout (which would tear it down).
        let activity = ActivityClock::new();
        let idle = Duration::from_secs(2);
        let wait = shaped_wait(Duration::from_secs(10), &activity, Some(idle));
        tokio::pin!(wait);

        let mut tick = tokio::time::interval(idle);
        tick.tick().await; // consume the immediate tick at t=0
        loop {
            tokio::select! {
                _ = &mut wait => break,
                _ = tick.tick() => {
                    assert!(
                        activity.idle_for() < idle,
                        "connection looked idle for {:?} while shaping",
                        activity.idle_for()
                    );
                }
            }
        }
    }

    fn udp_options(client_ip: IpAddr, idle: Duration) -> UdpAssociateOptions {
        UdpAssociateOptions {
            client_ip,
            client_endpoint: None,
            idle,
            dns_policy: DnsPolicy {
                preference: crate::config::DnsPreference::System,
                try_all: false,
                deny: Vec::new(),
                cache_ttl: None,
                timeout: Duration::from_secs(5),
            },
            dns_resolver: Arc::new(DnsResolver::new()),
            metrics: Metrics::new(),
            throttle: None,
            outbound_dual: false,
            strict_reply: false,
        }
    }

    // The three tests below drive the real recv/validate/mark path through real
    // UDP sockets, so they use wall-clock time rather than a paused clock: real
    // datagram readiness comes from the OS I/O driver, which does not advance with
    // `tokio::time`, so there is no race-free way to interleave a delivered
    // datagram with `tokio::time::advance`. Margins are wide (sends every 100ms vs
    // a 500ms idle), and the two negative tests are robust to load besides — a
    // delayed junk spray can only make the association idle out sooner, never keep
    // it alive.

    // A stream of wrong-source datagrams must not keep a UDP association alive:
    // `activity.mark()` now runs only after the source/endpoint/header checks, so
    // spoofed or unrelated datagrams are dropped without refreshing the timer.
    #[tokio::test]
    async fn spoofed_source_datagrams_do_not_refresh_udp_idle() {
        let (control, _control_peer) = tokio::io::duplex(1024);
        let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_socket.local_addr().unwrap();
        let outbound = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // The association expects a client at 10.0.0.1, so the loopback datagrams
        // sprayed below are all wrong-source and must be ignored.
        let options = udp_options(IpAddr::from([10, 0, 0, 1]), Duration::from_millis(500));
        let assoc = tokio::spawn(run_udp_associate(
            control,
            relay_socket,
            outbound,
            options,
            |_, _, _| true,
            |_, _, _| true,
        ));

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let spray = tokio::spawn(async move {
            for _ in 0..40 {
                let _ = sender.send_to(b"junk", relay_addr).await;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        // The spray runs for ~4s, but the association must idle out at its 500ms
        // deadline regardless — so it finishes well within 2s.
        let result = tokio::time::timeout(Duration::from_secs(2), assoc)
            .await
            .expect("association should idle out despite spoofed traffic");
        assert!(result.unwrap().is_ok());
        spray.abort();
    }

    // Bytes on the TCP control channel must not refresh the UDP idle timer; only
    // its *closing* tears the association down.
    #[tokio::test]
    async fn control_channel_data_does_not_refresh_udp_idle() {
        let (control, mut control_peer) = tokio::io::duplex(1024);
        let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let outbound = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let options = udp_options(IpAddr::from([127, 0, 0, 1]), Duration::from_millis(500));
        let assoc = tokio::spawn(run_udp_associate(
            control,
            relay_socket,
            outbound,
            options,
            |_, _, _| true,
            |_, _, _| true,
        ));

        let junk = tokio::spawn(async move {
            for _ in 0..40 {
                if control_peer.write_all(b"x").await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        let result = tokio::time::timeout(Duration::from_secs(2), assoc)
            .await
            .expect("association should idle out despite control-channel data");
        assert!(result.unwrap().is_ok());
        junk.abort();
    }

    // Validated datagrams from the locked client endpoint DO keep the association
    // alive — the regression guard that the mark still fires for real traffic.
    #[tokio::test]
    async fn validated_datagrams_keep_udp_association_alive() {
        let (control, _control_peer) = tokio::io::duplex(1024);
        let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_socket.local_addr().unwrap();
        let outbound = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let options = udp_options(IpAddr::from([127, 0, 0, 1]), Duration::from_millis(500));
        let mut assoc = tokio::spawn(run_udp_associate(
            control,
            relay_socket,
            outbound,
            options,
            |_, _, _| true,
            |_, _, _| true,
        ));

        // A well-formed SOCKS UDP datagram to an allowed IPv4 destination:
        // RSV(2) FRAG(1) ATYP=IPv4(1) DST.ADDR(4) DST.PORT(2) DATA.
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut datagram = vec![0u8, 0, 0, 1];
        datagram.extend_from_slice(&[127, 0, 0, 1]);
        datagram.extend_from_slice(&9u16.to_be_bytes());
        datagram.extend_from_slice(b"ping");
        let keepalive = tokio::spawn(async move {
            for _ in 0..20 {
                let _ = sender.send_to(&datagram, relay_addr).await;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        // Datagrams every 100ms are well inside the 500ms idle window, so the
        // association must still be running after 1.5s (3x the idle timeout).
        let still_running = tokio::time::timeout(Duration::from_millis(1500), &mut assoc).await;
        assert!(
            still_running.is_err(),
            "validated traffic must keep the association alive"
        );
        keepalive.abort();
        assoc.abort();
    }

    #[test]
    fn contacted_remotes_records_and_evicts_oldest() {
        let mut contacted = ContactedRemotes::new(false);
        let addr = |i: usize| SocketAddr::new(IpAddr::from([10, 0, (i >> 8) as u8, i as u8]), 9);

        contacted.record(addr(0));
        assert!(contacted.contains(addr(0)));
        assert!(!contacted.contains(addr(1)));

        // Fill to the cap with distinct IPs; addr(0) was recorded first (oldest).
        for i in 1..MAX_CONTACTED_REMOTES {
            contacted.record(addr(i));
        }
        assert!(contacted.contains(addr(0)));

        // One more distinct IP evicts the oldest.
        contacted.record(addr(MAX_CONTACTED_REMOTES));
        assert!(
            !contacted.contains(addr(0)),
            "the oldest contacted remote should be evicted at the cap"
        );
        assert!(contacted.contains(addr(MAX_CONTACTED_REMOTES)));
        assert!(contacted.contains(addr(MAX_CONTACTED_REMOTES - 1)));
    }

    #[test]
    fn contacted_remotes_port_matching_modes() {
        let dest = SocketAddr::from(([10, 0, 0, 1], 53));
        let same_ip_other_port = SocketAddr::from(([10, 0, 0, 1], 9999));
        let other_ip = SocketAddr::from(([10, 0, 0, 2], 53));

        // Default (port-agnostic): any port on a contacted host is accepted, but
        // a different host is not.
        let mut loose = ContactedRemotes::new(false);
        loose.record(dest);
        assert!(loose.contains(dest));
        assert!(loose.contains(same_ip_other_port));
        assert!(!loose.contains(other_ip));

        // Strict (`udp.strictreply`): only the exact host:port matches.
        let mut strict = ContactedRemotes::new(true);
        strict.record(dest);
        assert!(strict.contains(dest));
        assert!(!strict.contains(same_ip_other_port));
        assert!(!strict.contains(other_ip));
    }

    // Split into two tests so neither depends on processing order: in the drop
    // test the client never contacts anything, so the set stays empty and the
    // reply is unsolicited whenever it is processed (no shared loopback-IP race).
    #[tokio::test]
    async fn udp_drops_replies_from_uncontacted_remotes() {
        let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let outbound = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let outbound_addr = outbound.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let (control, _control_peer) = tokio::io::duplex(1024);
        let mut options = udp_options(client_addr.ip(), Duration::from_secs(5));
        options.client_endpoint = Some(client_addr);
        let assoc = tokio::spawn(run_udp_associate(
            control,
            relay_socket,
            outbound,
            options,
            |_, _, _| true,
            |_, _, _| true,
        ));

        // The client never sends, so the contacted set stays empty: a reply to the
        // outbound socket is always unsolicited and dropped.
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        stranger
            .send_to(b"unsolicited", outbound_addr)
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        assert!(
            tokio::time::timeout(Duration::from_millis(500), client.recv_from(&mut buf))
                .await
                .is_err(),
            "an unsolicited reply must not reach the client"
        );

        assoc.abort();
    }

    #[tokio::test]
    async fn udp_forwards_replies_from_contacted_remotes() {
        let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_socket.local_addr().unwrap();
        let outbound = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let outbound_addr = outbound.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let dest = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest_addr = dest.local_addr().unwrap();

        let (control, _control_peer) = tokio::io::duplex(1024);
        let mut options = udp_options(client_addr.ip(), Duration::from_secs(5));
        options.client_endpoint = Some(client_addr);
        let assoc = tokio::spawn(run_udp_associate(
            control,
            relay_socket,
            outbound,
            options,
            |_, _, _| true,
            |_, _, _| true,
        ));

        // The client contacts `dest`, recording its IP.
        let IpAddr::V4(dest_ip) = dest_addr.ip() else {
            unreachable!()
        };
        let mut datagram = vec![0u8, 0, 0, 1]; // RSV RSV FRAG ATYP=IPv4
        datagram.extend_from_slice(&dest_ip.octets());
        datagram.extend_from_slice(&dest_addr.port().to_be_bytes());
        datagram.extend_from_slice(b"ping");
        client.send_to(&datagram, relay_addr).await.unwrap();
        let mut dbuf = [0u8; 64];
        let (dn, _) = tokio::time::timeout(Duration::from_secs(1), dest.recv_from(&mut dbuf))
            .await
            .expect("dest should receive the forwarded datagram")
            .unwrap();
        assert_eq!(&dbuf[..dn], b"ping");

        // A reply from the now-contacted remote is forwarded to the client.
        dest.send_to(b"pong", outbound_addr).await.unwrap();
        let mut buf = [0u8; 256];
        let (cn, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .expect("a reply from a contacted remote must reach the client")
            .unwrap();
        assert!(buf[..cn].ends_with(b"pong"));

        assoc.abort();
    }

    #[tokio::test]
    async fn udp_datagram_to_denied_destination_is_dropped() {
        // The per-datagram authorizer is consulted for every client datagram; when
        // it denies a destination the datagram must not be forwarded. (The default
        // test policy allows loopback, so the drop here is the authorizer's doing,
        // not the address filter's.)
        let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_socket.local_addr().unwrap();
        let outbound = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let dest = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest_addr = dest.local_addr().unwrap();

        let (control, _control_peer) = tokio::io::duplex(1024);
        let mut options = udp_options(client_addr.ip(), Duration::from_secs(5));
        options.client_endpoint = Some(client_addr);
        // Authorizer denies every datagram.
        let assoc = tokio::spawn(run_udp_associate(
            control,
            relay_socket,
            outbound,
            options,
            |_, _, _| false,
            |_, _, _| true,
        ));

        let IpAddr::V4(dest_ip) = dest_addr.ip() else {
            unreachable!()
        };
        let mut datagram = vec![0u8, 0, 0, 1]; // RSV RSV FRAG ATYP=IPv4
        datagram.extend_from_slice(&dest_ip.octets());
        datagram.extend_from_slice(&dest_addr.port().to_be_bytes());
        datagram.extend_from_slice(b"ping");
        client.send_to(&datagram, relay_addr).await.unwrap();

        // The denied datagram must never reach the destination. A generous window
        // (matching the adjacent relay tests) so a slow-but-real forward would
        // still be observed rather than mistaken for the expected drop.
        let mut dbuf = [0u8; 64];
        let forwarded =
            tokio::time::timeout(Duration::from_secs(1), dest.recv_from(&mut dbuf)).await;
        assert!(
            forwarded.is_err(),
            "a datagram the authorizer denied must not be forwarded to the destination"
        );
        // Guard against a vacuous pass: the timeout above must mean the datagram
        // was dropped by a *running* association, not that the task died and never
        // processed it.
        assert!(
            !assoc.is_finished(),
            "association task exited prematurely; the no-forward result is not meaningful"
        );

        assoc.abort();
    }

    // The per-datagram verdict (the plugin `on_datagram` hook, threaded as a core
    // closure) can drop a client→target datagram even when `authorize` allows it.
    #[tokio::test]
    async fn on_datagram_can_drop_client_to_target() {
        let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_socket.local_addr().unwrap();
        let outbound = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let dest = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest_addr = dest.local_addr().unwrap();

        let (control, _control_peer) = tokio::io::duplex(1024);
        let mut options = udp_options(client_addr.ip(), Duration::from_secs(5));
        options.client_endpoint = Some(client_addr);
        let assoc = tokio::spawn(run_udp_associate(
            control,
            relay_socket,
            outbound,
            options,
            |_, _, _| true,            // authorize: allow all
            |is_reply, _, _| is_reply, // on_datagram: drop client→target, allow replies
        ));

        let IpAddr::V4(dest_ip) = dest_addr.ip() else {
            unreachable!()
        };
        let mut datagram = vec![0u8, 0, 0, 1];
        datagram.extend_from_slice(&dest_ip.octets());
        datagram.extend_from_slice(&dest_addr.port().to_be_bytes());
        datagram.extend_from_slice(b"ping");
        client.send_to(&datagram, relay_addr).await.unwrap();

        let mut dbuf = [0u8; 64];
        let forwarded =
            tokio::time::timeout(Duration::from_secs(1), dest.recv_from(&mut dbuf)).await;
        assert!(
            forwarded.is_err(),
            "a datagram dropped by on_datagram must not be forwarded to the destination"
        );
        assert!(
            !assoc.is_finished(),
            "association task exited prematurely; the no-forward result is not meaningful"
        );
        assoc.abort();
    }

    // The reply-direction verdict is a genuinely new call site: forward the
    // client→target datagram (so the destination replies) but drop the reply — the
    // client must never see it.
    #[tokio::test]
    async fn on_datagram_can_drop_target_to_client() {
        let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_socket.local_addr().unwrap();
        let outbound = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let outbound_addr = outbound.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let dest = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest_addr = dest.local_addr().unwrap();

        let (control, _control_peer) = tokio::io::duplex(1024);
        let mut options = udp_options(client_addr.ip(), Duration::from_secs(5));
        options.client_endpoint = Some(client_addr);
        let assoc = tokio::spawn(run_udp_associate(
            control,
            relay_socket,
            outbound,
            options,
            |_, _, _| true,             // authorize: allow all
            |is_reply, _, _| !is_reply, // on_datagram: forward client→target, drop replies
        ));

        let IpAddr::V4(dest_ip) = dest_addr.ip() else {
            unreachable!()
        };
        let mut datagram = vec![0u8, 0, 0, 1];
        datagram.extend_from_slice(&dest_ip.octets());
        datagram.extend_from_slice(&dest_addr.port().to_be_bytes());
        datagram.extend_from_slice(b"ping");
        client.send_to(&datagram, relay_addr).await.unwrap();

        // The destination receives the forwarded datagram and replies.
        let mut dbuf = [0u8; 64];
        let (dn, _) = tokio::time::timeout(Duration::from_secs(1), dest.recv_from(&mut dbuf))
            .await
            .expect("dest should receive the forwarded datagram")
            .unwrap();
        assert_eq!(&dbuf[..dn], b"ping");
        dest.send_to(b"pong", outbound_addr).await.unwrap();

        // But the reply is dropped by on_datagram, so the client never sees it.
        let mut buf = [0u8; 256];
        assert!(
            tokio::time::timeout(Duration::from_millis(500), client.recv_from(&mut buf))
                .await
                .is_err(),
            "a reply dropped by on_datagram must not reach the client"
        );
        assoc.abort();
    }

    // -- client-leg validation primitives (shared with the plugin datagram facade) --

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn client_source_rejects_a_different_ip() {
        let client_ip = sa("203.0.113.7:0").ip().to_canonical();
        assert!(client_source_accepted(
            sa("203.0.113.7:5000"),
            client_ip,
            None
        ));
        assert!(!client_source_accepted(
            sa("203.0.113.8:5000"),
            client_ip,
            None
        ));
    }

    #[test]
    fn client_source_matches_across_v4_mapped_v6() {
        // A dual-stack relay socket reports an IPv4 client as `::ffff:a.b.c.d`;
        // it must match a plain-IPv4 client, and vice versa.
        let client_ip = sa("203.0.113.7:0").ip().to_canonical();
        assert!(client_source_accepted(
            sa("[::ffff:203.0.113.7]:5000"),
            client_ip,
            None
        ));
        // A non-canonical (v4-mapped-v6) client_ip is canonicalised internally,
        // so a caller need not pre-canonicalise: a plain-v4 source still matches.
        let mapped_client = sa("[::ffff:203.0.113.7]:0").ip(); // deliberately not canonicalised
        assert!(client_source_accepted(
            sa("203.0.113.7:5000"),
            mapped_client,
            None
        ));
    }

    #[test]
    fn client_source_enforces_the_endpoint_lock() {
        let client_ip = sa("203.0.113.7:0").ip().to_canonical();
        let lock = sa("203.0.113.7:5000");
        // Same ip:port as the lock is accepted; a different port of the same
        // client is rejected once locked.
        assert!(client_source_accepted(
            sa("203.0.113.7:5000"),
            client_ip,
            Some(lock)
        ));
        assert!(!client_source_accepted(
            sa("203.0.113.7:6000"),
            client_ip,
            Some(lock)
        ));
        // The lock comparison is also canonical across the v4/v6-mapped forms.
        assert!(client_source_accepted(
            sa("[::ffff:203.0.113.7]:5000"),
            client_ip,
            Some(lock)
        ));
    }

    #[test]
    fn parse_client_header_drops_fragments_and_garbage() {
        // A well-formed, unfragmented v4 header (ATYP=0x01) parses.
        let mut good = vec![0x00, 0x00, 0x00, 0x01, 203, 0, 113, 9, 0x01, 0xbb];
        good.extend_from_slice(b"payload");
        let header = parse_client_header(&good).expect("valid header parses");
        assert_eq!(header.frag, 0);
        assert_eq!(&good[header.payload_offset..], b"payload");

        // FRAG != 0 is dropped even though the rest is well-formed.
        let mut fragmented = good.clone();
        fragmented[2] = 0x01;
        assert!(parse_client_header(&fragmented).is_none());

        // Unparseable garbage (bad reserved bytes) is dropped.
        assert!(parse_client_header(&[0xff, 0xff, 0x00, 0x01]).is_none());
    }
}

#[cfg(all(test, feature = "plugins"))]
mod facade_tests {
    use super::*;
    use crate::config::{DnsDenyCategory, DnsPreference};

    fn permissive_policy() -> DnsPolicy {
        DnsPolicy {
            preference: DnsPreference::System,
            try_all: false,
            deny: vec![],
            cache_ttl: None,
            timeout: Duration::from_secs(5),
        }
    }

    /// A SOCKS5 UDP datagram (header + payload) addressed to `dest`.
    fn socks_dg(dest: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let mut dg = socks5::build_udp_header(&TargetAddr::Ip(dest));
        dg.extend_from_slice(payload);
        dg
    }

    fn acl_allow_all() -> DatagramAuthorizer {
        Arc::new(|_, _, _| true)
    }

    fn client_datagrams(
        socket: Arc<UdpSocket>,
        client_ip: IpAddr,
        lock: Arc<OnceLock<SocketAddr>>,
    ) -> ClientDatagrams {
        ClientDatagrams::new(
            socket,
            client_ip,
            lock,
            Arc::new(ActivityClock::new()),
            None,
            Metrics::new(),
        )
    }

    // -- ClientDatagrams (the client leg) --

    #[tokio::test]
    async fn client_datagrams_recv_strips_header_and_locks_endpoint() {
        let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_addr = relay.local_addr().unwrap();
        let cd = client_datagrams(
            relay,
            IpAddr::from([127, 0, 0, 1]),
            Arc::new(OnceLock::new()),
        );

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let dest: SocketAddr = "198.51.100.5:443".parse().unwrap();
        client
            .send_to(&socks_dg(dest, b"quic"), relay_addr)
            .await
            .unwrap();

        let mut buf = vec![0u8; 2048];
        let (len, origin) = tokio::time::timeout(Duration::from_secs(2), cd.recv(&mut buf))
            .await
            .expect("a valid datagram should be delivered")
            .unwrap();
        assert_eq!(&buf[..len], b"quic", "the SOCKS header must be stripped");
        assert_eq!(origin, dest, "the addressed origin is reported");
        assert_eq!(
            cd.client_endpoint(),
            Some(client_addr),
            "the first validated datagram locks the client endpoint"
        );
    }

    #[tokio::test]
    async fn client_datagrams_recv_rejects_foreign_source() {
        let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_addr = relay.local_addr().unwrap();
        // The association expects 127.0.0.9, but the datagram arrives from 127.0.0.1.
        let cd = client_datagrams(
            relay,
            IpAddr::from([127, 0, 0, 9]),
            Arc::new(OnceLock::new()),
        );

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(
                &socks_dg("198.51.100.5:443".parse().unwrap(), b"quic"),
                relay_addr,
            )
            .await
            .unwrap();

        let mut buf = vec![0u8; 2048];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), cd.recv(&mut buf))
                .await
                .is_err(),
            "a datagram from a foreign source must be dropped, not returned"
        );
    }

    #[tokio::test]
    async fn client_datagrams_recv_drops_fragment_keeps_good() {
        let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_addr = relay.local_addr().unwrap();
        let cd = client_datagrams(
            relay,
            IpAddr::from([127, 0, 0, 1]),
            Arc::new(OnceLock::new()),
        );

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest: SocketAddr = "198.51.100.5:443".parse().unwrap();
        let mut fragmented = socks_dg(dest, b"frag");
        fragmented[2] = 1; // FRAG != 0
        client.send_to(&fragmented, relay_addr).await.unwrap();
        client
            .send_to(&socks_dg(dest, b"good"), relay_addr)
            .await
            .unwrap();

        let mut buf = vec![0u8; 2048];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), cd.recv(&mut buf))
            .await
            .expect("the unfragmented datagram should be delivered")
            .unwrap();
        assert_eq!(
            &buf[..len],
            b"good",
            "a fragmented datagram must never be returned"
        );
    }

    #[tokio::test]
    async fn client_datagrams_recv_drops_domain_addressed() {
        let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_addr = relay.local_addr().unwrap();
        let cd = client_datagrams(
            relay,
            IpAddr::from([127, 0, 0, 1]),
            Arc::new(OnceLock::new()),
        );

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut domain = socks5::build_udp_header(&TargetAddr::Domain("example.com".into(), 443));
        domain.extend_from_slice(b"dom");
        client.send_to(&domain, relay_addr).await.unwrap();
        client
            .send_to(
                &socks_dg("198.51.100.5:443".parse().unwrap(), b"ip"),
                relay_addr,
            )
            .await
            .unwrap();

        let mut buf = vec![0u8; 2048];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), cd.recv(&mut buf))
            .await
            .expect("the IP-addressed datagram should be delivered")
            .unwrap();
        assert_eq!(
            &buf[..len],
            b"ip",
            "a domain-addressed datagram is unsupported on takeover and must be dropped"
        );
    }

    #[tokio::test]
    async fn client_datagrams_send_reframes_reply_to_client() {
        let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_addr = relay.local_addr().unwrap();
        let cd = client_datagrams(
            relay,
            IpAddr::from([127, 0, 0, 1]),
            Arc::new(OnceLock::new()),
        );

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // A client datagram first, so the endpoint locks.
        client
            .send_to(
                &socks_dg("198.51.100.5:443".parse().unwrap(), b"hi"),
                relay_addr,
            )
            .await
            .unwrap();
        let mut buf = vec![0u8; 2048];
        cd.recv(&mut buf).await.unwrap();

        // A reply appearing to come from the origin is re-framed and delivered.
        let origin: SocketAddr = "203.0.113.1:443".parse().unwrap();
        cd.send(origin, b"pong").await.unwrap();

        let mut cbuf = vec![0u8; 2048];
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut cbuf))
            .await
            .expect("the client should receive the reply")
            .unwrap();
        assert_eq!(from, relay_addr);
        let hdr = socks5::parse_udp_header(&cbuf[..n]).unwrap();
        assert_eq!(
            hdr.dest,
            TargetAddr::Ip(origin),
            "the reply carries the origin in its SOCKS header"
        );
        assert_eq!(&cbuf[hdr.payload_offset..n], b"pong");
    }

    #[tokio::test]
    async fn client_datagrams_send_before_lock_is_noop() {
        let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let cd = client_datagrams(
            relay,
            IpAddr::from([127, 0, 0, 1]),
            Arc::new(OnceLock::new()),
        );

        // No datagram received yet: send has nowhere to go and must be a silent
        // Ok. Use a real local socket's address as `from` so that if send ever
        // mistakenly delivered to `from` (the plausible bug), this would catch it.
        let would_be_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let from = would_be_target.local_addr().unwrap();
        cd.send(from, b"pong").await.unwrap();
        assert!(cd.client_endpoint().is_none());
        let mut b = [0u8; 64];
        assert!(
            tokio::time::timeout(
                Duration::from_millis(300),
                would_be_target.recv_from(&mut b)
            )
            .await
            .is_err(),
            "send before the endpoint lock must not deliver anywhere, not even to `from`"
        );
    }

    // -- UpstreamOriginator (the origin leg) --

    fn originator(
        outbound: Arc<UdpSocket>,
        policy: DnsPolicy,
        acl: DatagramAuthorizer,
        contacted: Arc<Mutex<ContactedRemotes>>,
    ) -> UpstreamOriginator {
        UpstreamOriginator::new(
            outbound,
            false,
            policy,
            acl,
            contacted,
            Arc::new(ActivityClock::new()),
            None,
            Metrics::new(),
        )
    }

    #[tokio::test]
    async fn upstream_authorize_gates_on_acl() {
        let outbound = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        // The ACL denies port 1, allows the rest.
        let acl: DatagramAuthorizer = Arc::new(|_h, _ip, port| port != 1);
        let orig = originator(
            outbound,
            permissive_policy(),
            acl,
            Arc::new(Mutex::new(ContactedRemotes::new(true))),
        );

        let allowed: SocketAddr = "203.0.113.7:443".parse().unwrap();
        assert_eq!(
            orig.authorize(None, allowed).map(|t| t.dst()),
            Some(allowed),
            "an ACL-allowed destination yields a token"
        );
        assert!(
            orig.authorize(None, "203.0.113.7:1".parse().unwrap())
                .is_none(),
            "an ACL-denied destination yields no token"
        );
    }

    #[tokio::test]
    async fn upstream_authorize_denies_dns_deny_category() {
        let outbound = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let policy = DnsPolicy {
            deny: vec![DnsDenyCategory::Loopback],
            ..permissive_policy()
        };
        // ACL allows everything; the DNS-deny policy must still block loopback.
        let orig = originator(
            outbound,
            policy,
            acl_allow_all(),
            Arc::new(Mutex::new(ContactedRemotes::new(true))),
        );

        assert!(
            orig.authorize(None, "127.0.0.1:443".parse().unwrap())
                .is_none(),
            "a loopback destination is denied by the DNS-deny policy"
        );
        assert!(
            orig.authorize(None, "203.0.113.7:443".parse().unwrap())
                .is_some(),
            "a public destination passes"
        );
    }

    #[tokio::test]
    async fn upstream_send_to_reaches_origin_and_accepts_its_reply() {
        let outbound = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let outbound_addr = outbound.local_addr().unwrap();
        let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let contacted = Arc::new(Mutex::new(ContactedRemotes::new(true)));
        let orig = originator(
            outbound,
            permissive_policy(),
            acl_allow_all(),
            contacted.clone(),
        );

        let target = orig
            .authorize(None, origin_addr)
            .expect("permissive authorize");
        orig.send_to(&target, b"ping").await.unwrap();

        let mut b = vec![0u8; 64];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), origin.recv_from(&mut b))
            .await
            .expect("the origin should receive the datagram")
            .unwrap();
        assert_eq!(&b[..n], b"ping");
        assert!(
            contacted.lock().unwrap().contains(SocketAddr::new(
                origin_addr.ip().to_canonical(),
                origin_addr.port()
            )),
            "send_to records the destination as contacted"
        );

        // The origin's reply is accepted, since it is now a contacted source.
        origin.send_to(b"pong", outbound_addr).await.unwrap();
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), orig.recv(&mut b))
            .await
            .expect("a reply from a contacted origin should be delivered")
            .unwrap();
        assert_eq!(&b[..n], b"pong");
        assert_eq!(from.ip(), origin_addr.ip().to_canonical());
    }

    #[tokio::test]
    async fn upstream_recv_drops_uncontacted_reply() {
        let outbound = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let outbound_addr = outbound.local_addr().unwrap();
        let orig = originator(
            outbound,
            permissive_policy(),
            acl_allow_all(),
            Arc::new(Mutex::new(ContactedRemotes::new(true))),
        );

        // A source the association never contacted sends an unsolicited datagram.
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        stranger.send_to(b"inject", outbound_addr).await.unwrap();

        let mut b = vec![0u8; 64];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), orig.recv(&mut b))
                .await
                .is_err(),
            "an unsolicited reply from an uncontacted source must be dropped"
        );
    }
}
