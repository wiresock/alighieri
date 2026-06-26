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
/// run of *other* failures exceeds [`MAX_CONSECUTIVE_UDP_RECV_ERRORS`]. Yields
/// on every error so a socket that errors immediately cannot spin the task.
async fn recv_resilient(
    socket: &UdpSocket,
    buf: &mut [u8],
    consecutive_errors: &mut u32,
) -> io::Result<(usize, SocketAddr)> {
    loop {
        match socket.recv_from(buf).await {
            Ok(v) => {
                *consecutive_errors = 0;
                return Ok(v);
            }
            Err(e) if is_transient_recv_error(&e) => {
                debug!(error = %e, "udp relay recv: ignoring transient error");
                tokio::task::yield_now().await;
            }
            Err(e) => {
                *consecutive_errors += 1;
                if *consecutive_errors >= MAX_CONSECUTIVE_UDP_RECV_ERRORS {
                    return Err(e);
                }
                debug!(error = %e, count = *consecutive_errors, "udp relay recv error; continuing");
                tokio::task::yield_now().await;
            }
        }
    }
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
pub async fn run_udp_associate<C, F>(
    mut control: C,
    relay_socket: UdpSocket,
    outbound: UdpSocket,
    options: UdpAssociateOptions,
    authorize: F,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    F: Fn(Option<&str>, IpAddr, u16) -> bool + Send + Sync + 'static,
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
    ));
    let mut remote_to_client = tokio::spawn(relay_remote_to_client(
        outbound,
        relay_socket,
        options.metrics,
        options.throttle,
        client_endpoint,
        activity.clone(),
        contacted,
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
struct ContactedRemotes {
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
struct ActivityClock {
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
async fn relay_client_to_remote<F>(
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
) -> Result<()>
where
    F: Fn(Option<&str>, IpAddr, u16) -> bool,
{
    let mut buf = vec![0u8; UDP_BUF];
    let mut recv_errors = 0u32;
    // Canonicalise the client's address once so the source check and the endpoint
    // lock compare on the real family: a dual-stack socket reports an IPv4 client
    // as `::ffff:a.b.c.d`, which must match a plain-IPv4 predeclared lock and the
    // plain-IPv4 source of its datagrams.
    let client_ip = client_ip.to_canonical();
    loop {
        let (n, raw_src) = recv_resilient(&relay_socket, &mut buf, &mut recv_errors).await?;
        // Canonicalise the source to the same form as `client_ip` and the lock
        // (an IPv4-mapped `::ffff:` from a dual-stack socket becomes plain IPv4).
        let src = SocketAddr::new(raw_src.ip().to_canonical(), raw_src.port());
        if src.ip() != client_ip {
            continue; // reject spoofed / unrelated source
        }
        if let Some(locked) = client_endpoint.get() {
            if *locked != src {
                continue;
            }
        }

        let header = match socks5::parse_udp_header(&buf[..n]) {
            Ok(h) => h,
            Err(_) => continue,
        };
        if header.frag != 0 {
            continue; // drop fragments
        }
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

async fn relay_remote_to_client(
    outbound: Arc<UdpSocket>,
    relay_socket: Arc<UdpSocket>,
    metrics: Arc<Metrics>,
    throttle: Option<Throttle>,
    client_endpoint: Arc<OnceLock<SocketAddr>>,
    activity: Arc<ActivityClock>,
    contacted: Arc<Mutex<ContactedRemotes>>,
) -> Result<()> {
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
        if relay_socket.send_to(datagram, caddr).await.is_ok() {
            metrics.udp_remote_packet_relayed(n as u64);
        }
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
}
