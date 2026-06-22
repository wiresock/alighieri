//! Data-plane relays: bidirectional TCP copying and the UDP associate relay.
//!
//! These functions contain no policy: authorisation decisions are made by the
//! caller (the [`crate::connection`] state machine) and, for UDP, supplied as
//! an `authorize` closure invoked per destination.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
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
        match idle {
            None => {
                let (up, down) = tokio::join!(up, down);
                up.and(down)
            }
            Some(idle) => relay_until_idle(up, down, idle, &activity).await,
        }
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

/// Drives both copy directions while a watchdog checks the shared activity
/// clock; returns early when the connection has been idle for `idle`.
async fn relay_until_idle<U, D>(
    up: U,
    down: D,
    idle: Duration,
    activity: &ActivityClock,
) -> io::Result<()>
where
    U: Future<Output = io::Result<()>>,
    D: Future<Output = io::Result<()>>,
{
    tokio::pin!(up, down);
    let mut tick = tokio::time::interval(idle_tick_period(idle));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut up_result: Option<io::Result<()>> = None;
    let mut down_result: Option<io::Result<()>> = None;
    loop {
        tokio::select! {
            res = &mut up, if up_result.is_none() => up_result = Some(res),
            res = &mut down, if down_result.is_none() => down_result = Some(res),
            _ = tick.tick() => {
                if activity.idle_for() >= idle {
                    break; // no traffic in either direction for too long
                }
                continue;
            }
        }
        if up_result.is_some() && down_result.is_some() {
            break;
        }
    }
    up_result
        .unwrap_or(Ok(()))
        .and(down_result.unwrap_or(Ok(())))
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
            // The TCP control connection closing tears down the association.
            res = control.read(&mut ctrl_buf) => {
                activity.mark();
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
    outbound_dual: bool,
    authorize: F,
) -> Result<()>
where
    F: Fn(Option<&str>, IpAddr, u16) -> bool,
{
    let mut buf = vec![0u8; UDP_BUF];
    let mut recv_errors = 0u32;
    loop {
        let (n, src) = recv_resilient(&relay_socket, &mut buf, &mut recv_errors).await?;
        activity.mark();
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
        let send_dest = match dest {
            SocketAddr::V4(v4) if outbound_dual => {
                SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
            }
            other => other,
        };
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
        activity.mark();
        let Some(caddr) = client_endpoint.get().copied() else {
            continue;
        };
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
}
