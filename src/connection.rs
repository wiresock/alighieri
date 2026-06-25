//! The per-client SOCKS5 state machine.
//!
//! Each accepted TCP connection is driven through:
//! 1. connection admission (`client` rules),
//! 2. method negotiation (RFC 1928 §3),
//! 3. optional username/password authentication (RFC 1929),
//! 4. request parsing and authorisation (`socks` rules),
//! 5. command execution (CONNECT relay or UDP associate).

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tracing::{debug, info, warn};

use crate::abuse::AbuseControls;
use crate::acl::{ClientContext, Scope, SocksContext, Verdict};
use crate::auth::{AuthOutcome, CommandAuth, UserDb};
use crate::client_stream::ClientStream;
use crate::config::{Config, Protocol, RateLimit};
use crate::dns::DnsResolver;
use crate::errors::{Error, Result};
use crate::metrics::Metrics;
use crate::net::PortRange;
use crate::relay;
use crate::socks5::{self, Command, Method, Reply, Request, TargetAddr};
use crate::throttle::{Throttle, TokenBucket};

/// A single client connection together with the shared server state it needs.
pub struct Connection {
    stream: ClientStream,
    peer: SocketAddr,
    local: SocketAddr,
    config: Arc<Config>,
    users: Arc<UserDb>,
    command_auth: Option<Arc<CommandAuth>>,
    metrics: Arc<Metrics>,
    abuse: Arc<AbuseControls>,
    dns_resolver: Arc<DnsResolver>,
    throttle_bucket: Option<Arc<Mutex<TokenBucket>>>,
}

pub struct ConnectionResources {
    pub config: Arc<Config>,
    pub users: Arc<UserDb>,
    pub command_auth: Option<Arc<CommandAuth>>,
    pub metrics: Arc<Metrics>,
    pub abuse: Arc<AbuseControls>,
    pub dns_resolver: Arc<DnsResolver>,
    pub throttle_bucket: Option<Arc<Mutex<TokenBucket>>>,
}

impl Connection {
    /// Creates a connection handler. `local` is the proxy's accepting address
    /// for this socket (used for `client` rule evaluation and as the UDP relay
    /// bind address).
    pub fn new(
        stream: ClientStream,
        peer: SocketAddr,
        local: SocketAddr,
        resources: ConnectionResources,
    ) -> Self {
        Connection {
            stream,
            peer,
            local,
            config: resources.config,
            users: resources.users,
            command_auth: resources.command_auth,
            metrics: resources.metrics,
            abuse: resources.abuse,
            dns_resolver: resources.dns_resolver,
            throttle_bucket: resources.throttle_bucket,
        }
    }

    /// Drives the connection to completion. Errors are returned for logging;
    /// the appropriate SOCKS5 reply (if any) has already been sent.
    pub async fn handle(mut self) -> Result<()> {
        // 1. Connection admission. Canonicalise IPv4-mapped IPv6 addresses (an
        // IPv4 client on a dual-stack `[::]` listener arrives as `::ffff:a.b.c.d`)
        // so `from:`/`to:` IPv4 CIDR rules match the real address rather than
        // being silently skipped.
        let client_ctx = ClientContext {
            client_ip: self.peer.ip().to_canonical(),
            client_port: self.peer.port(),
            proxy_ip: self.local.ip().to_canonical(),
            proxy_port: self.local.port(),
        };
        let client_decision = self.config.rules.evaluate_client_detail(&client_ctx);
        if client_decision.verdict != Verdict::Pass {
            self.metrics.client_denied(&client_decision);
            debug!(
                peer = %self.peer,
                rule_line = ?client_decision.source_line,
                rule_name = client_decision.rule_name.as_deref().unwrap_or(""),
                "connection denied by client rule"
            );
            return Err(Error::AccessDenied);
        }
        self.metrics.client_allowed(&client_decision);
        debug!(
            peer = %self.peer,
            rule_line = ?client_decision.source_line,
            rule_name = client_decision.rule_name.as_deref().unwrap_or(""),
            "connection allowed by client rule"
        );

        // 2. Method negotiation.
        let greeting = with_timeout(
            self.config.handshake_timeout,
            socks5::read_greeting(&mut self.stream),
        )
        .await?;
        let chosen = self
            .config
            .socks_methods
            .iter()
            .copied()
            .find(|m| greeting.methods.contains(&m.to_method()));

        let method = match chosen {
            Some(m) => m,
            None => {
                socks5::write_method_selection(&mut self.stream, Method::NoAcceptable).await?;
                self.metrics.auth_failed();
                self.record_auth_failure();
                debug!(peer = %self.peer, "no acceptable auth method");
                return Err(Error::AuthFailed);
            }
        };
        socks5::write_method_selection(&mut self.stream, method.to_method()).await?;

        // 3. Authentication (only for username/password).
        if method.to_method() == Method::UserPass {
            let creds = with_timeout(
                self.config.handshake_timeout,
                socks5::read_userpass(&mut self.stream),
            )
            .await?;
            // Verify against the external command hook when configured, otherwise
            // the userlist; both cache successful verifications. Each owns the
            // single deadline for its path: CommandAuth bounds its whole operation
            // (a concurrency-limited spawn, credential delivery and the wait) by
            // the handshake timeout, killing and reaping any overrun child out of
            // band, while the userlist path has no internal deadline and is
            // bounded here.
            let outcome = match &self.command_auth {
                Some(cmd) => {
                    cmd.verify_async(
                        &creds.username,
                        &creds.password,
                        self.config.auth_cache_ttl,
                        self.config.handshake_timeout,
                    )
                    .await
                }
                None => {
                    let verify = self.users.verify_async(
                        &creds.username,
                        &creds.password,
                        self.config.auth_cache_ttl,
                    );
                    match tokio::time::timeout(self.config.handshake_timeout, verify).await {
                        Ok(true) => AuthOutcome::Allowed,
                        Ok(false) => AuthOutcome::Denied,
                        Err(_) => AuthOutcome::TimedOut,
                    }
                }
            };
            match outcome {
                AuthOutcome::Allowed => {
                    socks5::write_userpass_status(&mut self.stream, true).await?;
                    debug!(peer = %self.peer, user = %creds.username, "authenticated");
                }
                AuthOutcome::Denied => {
                    socks5::write_userpass_status(&mut self.stream, false).await?;
                    self.metrics.auth_failed();
                    self.record_auth_failure();
                    warn!(peer = %self.peer, user = %creds.username, "authentication failed");
                    return Err(Error::AuthFailed);
                }
                AuthOutcome::TimedOut => {
                    socks5::write_userpass_status(&mut self.stream, false).await?;
                    self.metrics.auth_failed();
                    self.record_auth_failure();
                    warn!(peer = %self.peer, user = %creds.username, "authentication timed out");
                    return Err(Error::Timeout);
                }
            }
        }

        // 4. Request.
        let request = with_timeout(
            self.config.handshake_timeout,
            socks5::read_request(&mut self.stream),
        )
        .await?;
        info!(
            peer = %self.peer,
            command = ?request.command,
            dest = %request.dest,
            "request received"
        );

        match request.command {
            Command::Connect => self.handle_connect(request, method).await,
            Command::UdpAssociate => self.handle_udp_associate(request, method).await,
            Command::Bind => {
                socks5::write_reply(
                    &mut self.stream,
                    Reply::CommandNotSupported,
                    socks5::unspecified_v4(),
                )
                .await?;
                Err(Error::CommandNotSupported)
            }
        }
    }

    /// Handles a TCP CONNECT request.
    async fn handle_connect(
        mut self,
        request: Request,
        method: crate::config::AuthKind,
    ) -> Result<()> {
        let targets = match self
            .dns_resolver
            .resolve_all(&request.dest, &self.config.dns)
            .await
        {
            Ok(addrs) if !addrs.is_empty() => addrs,
            Ok(_) => {
                socks5::write_reply(
                    &mut self.stream,
                    Reply::HostUnreachable,
                    socks5::unspecified_v4(),
                )
                .await?;
                warn!(peer = %self.peer, dest = %request.dest, "destination resolution returned no allowed addresses");
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "resolution returned no allowed addresses",
                )));
            }
            Err(e) => {
                socks5::write_reply(
                    &mut self.stream,
                    Reply::HostUnreachable,
                    socks5::unspecified_v4(),
                )
                .await?;
                warn!(peer = %self.peer, dest = %request.dest, error = %e, "destination resolution failed");
                return Err(Error::Io(e));
            }
        };

        // Hostname the client requested (for `to:` hostname rules), matched
        // before resolution. `None` for IP-literal requests.
        let req_host = match &request.dest {
            TargetAddr::Domain(host, _) => Some(host.as_str()),
            TargetAddr::Ip(_) => None,
        };

        let candidates = if self.config.dns.try_all {
            targets
        } else {
            targets.into_iter().take(1).collect()
        };

        let mut denied = 0usize;
        let mut last_error = None;
        let mut connected = None;
        for target in candidates {
            let decision = self.authorize_connect_target(req_host, target, method);
            self.metrics.rule_hit(
                Scope::Socks,
                decision.verdict,
                decision.source_line,
                decision.rule_name.clone(),
            );
            if decision.verdict != Verdict::Pass {
                denied += 1;
                info!(
                    peer = %self.peer,
                    dest = %target,
                    rule_line = ?decision.source_line,
                    rule_name = decision.rule_name.as_deref().unwrap_or(""),
                    "connect candidate denied by socks rule"
                );
                continue;
            }

            match connect_remote(target, self.config.external, self.config.connect_timeout).await {
                Ok(remote) => {
                    connected = Some((target, remote, decision));
                    break;
                }
                Err(e) => {
                    warn!(peer = %self.peer, dest = %target, error = %e, "connect failed");
                    last_error = Some(e);
                    if !self.config.dns.try_all {
                        break;
                    }
                }
            }
        }

        let Some((target, remote, decision)) = connected else {
            if let Some(e) = last_error {
                socks5::write_reply(&mut self.stream, e.to_reply(), socks5::unspecified_v4())
                    .await?;
                return Err(e);
            }
            self.metrics.socks_request_denied();
            socks5::write_reply(
                &mut self.stream,
                Reply::ConnectionNotAllowed,
                socks5::unspecified_v4(),
            )
            .await?;
            info!(peer = %self.peer, denied, "connect denied by socks rules");
            return Err(Error::AccessDenied);
        };
        self.metrics.socks_request_allowed();

        let bound = remote
            .local_addr()
            .unwrap_or_else(|_| socks5::unspecified_v4());
        socks5::write_reply(&mut self.stream, Reply::Succeeded, bound).await?;
        self.metrics.tcp_connect();
        info!(
            peer = %self.peer,
            dest = %target,
            rule_line = ?decision.source_line,
            rule_name = decision.rule_name.as_deref().unwrap_or(""),
            "connect established"
        );

        let throttle = self.throttle(decision.bandwidth.as_ref());
        let (up, down) =
            relay::relay_tcp(self.stream, remote, self.config.io_timeout, throttle).await?;
        self.metrics.tcp_relay_closed(up, down);
        debug!(peer = %self.peer, dest = %target, up, down, "connect closed");
        Ok(())
    }

    fn authorize_connect_target(
        &self,
        host: Option<&str>,
        target: SocketAddr,
        method: crate::config::AuthKind,
    ) -> crate::acl::RuleDecision {
        let ctx = SocksContext {
            client_ip: self.peer.ip().to_canonical(),
            client_port: self.peer.port(),
            dest_host: host,
            // `target` is already canonical (the resolver collapses mapped
            // addresses); canonicalise again defensively so a CIDR `to:` rule
            // can never be dodged with an `::ffff:` literal.
            dest_ip: target.ip().to_canonical(),
            dest_port: target.port(),
            command: Command::Connect,
            protocol: Protocol::Tcp,
            method,
        };
        self.config.rules.evaluate_socks_detail(&ctx)
    }

    /// Handles a UDP ASSOCIATE request.
    async fn handle_udp_associate(
        mut self,
        request: Request,
        method: crate::config::AuthKind,
    ) -> Result<()> {
        // Authorise the command before allocating any resources: if no socks
        // rule could ever permit UDP for this client (e.g. a `command: connect`
        // only policy), reject now rather than binding sockets and replying
        // success only for the per-datagram checks to drop every datagram while
        // the association lingers until the idle timeout. Per-datagram
        // destination checks still run for clients that pass this gate.
        if !self.config.rules.udp_associate_reachable(
            self.peer.ip().to_canonical(),
            self.peer.port(),
            method,
        ) {
            self.metrics.socks_request_denied();
            socks5::write_reply(
                &mut self.stream,
                Reply::ConnectionNotAllowed,
                socks5::unspecified_v4(),
            )
            .await?;
            info!(peer = %self.peer, "udp associate denied by socks rules");
            return Err(Error::AccessDenied);
        }

        // The relay socket is bound on the same interface the client reached us
        // on, so the address we advertise is reachable by the client.
        let relay_socket =
            match bind_udp_in_range(self.local.ip(), self.config.udp_port_range).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(peer = %self.peer, error = %e, "failed to bind UDP relay socket");
                    socks5::write_reply(
                        &mut self.stream,
                        Reply::GeneralFailure,
                        socks5::unspecified_v4(),
                    )
                    .await?;
                    return Err(Error::Io(e));
                }
            };
        // The outbound socket carries traffic to/from remote peers, sourced from
        // the configured external address. `outbound_dual` is true when it is a
        // dual-stack IPv6 socket (so IPv4 destinations are sent in `::ffff:`
        // mapped form); see `bind_outbound_udp`.
        let (outbound, outbound_dual) = match bind_outbound_udp(self.config.external).await {
            Ok(pair) => pair,
            Err(e) => {
                socks5::write_reply(
                    &mut self.stream,
                    Reply::GeneralFailure,
                    socks5::unspecified_v4(),
                )
                .await?;
                return Err(Error::Io(e));
            }
        };
        // Enlarge the relay sockets' kernel buffers so sustained high-rate UDP
        // (e.g. a VPN tunnel) tolerates scheduling bursts without the kernel
        // dropping datagrams. Best-effort; the OS may clamp the request (on
        // Linux, to net.core.{r,w}mem_max).
        relay::tune_udp_buffers(&relay_socket);
        relay::tune_udp_buffers(&outbound);

        let relay_addr = relay_socket
            .local_addr()
            .unwrap_or_else(|_| socks5::unspecified_v4());
        // Advertise the configured public host (with the real relay port) so a
        // client reaching us via NAT is told an address it can send to; otherwise
        // advertise the bound relay address.
        let advertise = self.config.udp_advertise.as_ref();
        let advertised = advertised_reply_addr(relay_addr, advertise);
        if advertise.is_some_and(|adv| adv.for_local(relay_addr.ip()).is_none()) {
            // The operator configured an advertised address, but none of the
            // resolved families matches this client's — so it gets the bound
            // (possibly private/LAN) relay address, which defeats the point.
            warn!(
                peer = %self.peer,
                relay = %relay_addr,
                "udp.advertise is configured but has no address for this client's family; advertising the bound relay address, which may be unreachable behind NAT"
            );
        }
        socks5::write_reply(&mut self.stream, Reply::Succeeded, advertised).await?;
        info!(peer = %self.peer, relay = %relay_addr, advertised = %advertised, "udp associate established");

        let client_endpoint = requested_udp_endpoint(&request.dest, self.peer.ip());

        // Build a per-destination authoriser that reuses the socks rule set.
        let config = self.config.clone();
        let metrics = self.metrics.clone();
        let client_ip = self.peer.ip();
        let client_port = self.peer.port();
        let authorize = move |host: Option<&str>, dest_ip: IpAddr, dest_port: u16| -> bool {
            let ctx = SocksContext {
                // Canonicalise for rule matching so IPv4 CIDR rules apply to
                // mapped addresses; `client_ip` keeps its original form for the
                // relay's source check and logging.
                client_ip: client_ip.to_canonical(),
                client_port,
                dest_host: host,
                dest_ip: dest_ip.to_canonical(),
                dest_port,
                command: Command::UdpAssociate,
                protocol: Protocol::Udp,
                method,
            };
            let decision = config.rules.evaluate_socks_detail(&ctx);
            if decision.verdict == Verdict::Pass {
                metrics.rule_hit(
                    Scope::Socks,
                    Verdict::Pass,
                    decision.source_line,
                    decision.rule_name.clone(),
                );
                true
            } else {
                metrics.rule_hit(
                    Scope::Socks,
                    Verdict::Block,
                    decision.source_line,
                    decision.rule_name.clone(),
                );
                metrics.udp_client_packet_denied();
                debug!(
                    peer = %client_ip,
                    dest = %SocketAddr::new(dest_ip, dest_port),
                    rule_line = ?decision.source_line,
                    rule_name = decision.rule_name.as_deref().unwrap_or(""),
                    "UDP packet denied by socks rule"
                );
                false
            }
        };

        self.metrics.udp_association_started();
        let metrics = self.metrics.clone();
        // Per-rule bandwidth applies to CONNECT relays; UDP uses the per-client
        // limit only (datagrams may match different rules each).
        let throttle = self.throttle(None);
        let run_result = relay::run_udp_associate(
            self.stream,
            relay_socket,
            outbound,
            relay::UdpAssociateOptions {
                client_ip,
                client_endpoint,
                idle: self.config.udp_timeout,
                dns_policy: self.config.dns.clone(),
                dns_resolver: self.dns_resolver.clone(),
                metrics: self.metrics.clone(),
                throttle,
                outbound_dual,
                strict_reply: self.config.udp_strict_reply,
            },
            authorize,
        )
        .await;
        metrics.udp_association_closed();
        run_result?;

        debug!(peer = %self.peer, "udp associate closed");
        Ok(())
    }

    fn record_auth_failure(&self) {
        self.abuse.record_auth_failure(self.peer.ip());
    }

    /// Builds the throttle governing this connection's relay: the shared
    /// per-client bucket (`byterate`) and, for a CONNECT whose matching `socks`
    /// rule sets `bandwidth`, a fresh per-session bucket. `None` when neither
    /// applies, so the relay hot path stays allocation- and lock-free.
    fn throttle(&self, rule_bandwidth: Option<&RateLimit>) -> Option<Throttle> {
        let client_bucket = self.throttle_bucket.clone();
        let rule_bucket = rule_bandwidth.and_then(|limit| {
            TokenBucket::from_rate_window(limit.limit, limit.window, Instant::now())
                .map(|b| Arc::new(Mutex::new(b)))
        });
        if client_bucket.is_none() && rule_bucket.is_none() {
            return None;
        }
        let mut throttle = Throttle::new();
        if let Some(bucket) = client_bucket {
            throttle = throttle.with_bucket(bucket);
        }
        if let Some(bucket) = rule_bucket {
            throttle = throttle.with_bucket(bucket);
        }
        Some(throttle)
    }
}

async fn with_timeout<T, F>(timeout: Duration, operation: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    tokio::time::timeout(timeout, operation)
        .await
        .map_err(|_| Error::Timeout)?
}

/// The address to advertise in the UDP ASSOCIATE reply: the configured
/// `udp.advertise` host matching the relay socket's family (keeping the real
/// bound relay port), or the bound relay address when no advertise address
/// applies (unset, or no address resolved for that family).
fn advertised_reply_addr(
    mut relay_addr: SocketAddr,
    advertise: Option<&crate::config::UdpAdvertise>,
) -> SocketAddr {
    // `for_local` only returns a same-family address, so `set_ip` keeps the
    // SocketAddr variant and the real bound port — just swapping the host.
    if let Some(ip) = advertise.and_then(|adv| adv.for_local(relay_addr.ip())) {
        relay_addr.set_ip(ip);
    }
    relay_addr
}

fn requested_udp_endpoint(dest: &TargetAddr, client_ip: IpAddr) -> Option<SocketAddr> {
    let TargetAddr::Ip(addr) = dest else {
        return None;
    };
    if addr.port() == 0 {
        return None;
    }
    if addr.ip().is_unspecified() {
        return Some(SocketAddr::new(client_ip, addr.port()));
    }
    if addr.ip() == client_ip {
        return Some(*addr);
    }
    None
}

/// Binds a UDP relay socket on `ip`. With a configured `range`, scans the
/// inclusive port range starting from a pseudo-random offset — so concurrent
/// associations spread across the range instead of contending on its low end,
/// and the advertised `BND.PORT` is not trivially predictable — and returns
/// `AddrInUse` if no port in the range can be bound. Without a range it binds an
/// OS-assigned ephemeral port (the historical default).
async fn bind_udp_in_range(ip: IpAddr, range: Option<PortRange>) -> io::Result<UdpSocket> {
    let Some(range) = range else {
        return UdpSocket::bind((ip, 0)).await;
    };
    let span = u32::from(range.max - range.min) + 1;
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let start = scan_start_offset(seed, COUNTER.fetch_add(1, Ordering::Relaxed), span);
    for i in 0..span {
        let port = range.min + ((start + i) % span) as u16;
        match UdpSocket::bind((ip, port)).await {
            Ok(socket) => return Ok(socket),
            // Skip a port we cannot bind right now — already in use, or not
            // permitted for this process (e.g. a privileged port < 1024 when the
            // range dips below it) — since a later port in the range may still
            // bind. Errors that apply to the bind address regardless of port
            // (e.g. the address is not local) repeat for every port, so fail fast.
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
                ) =>
            {
                continue
            }
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        format!(
            "no bindable UDP port in configured udp.portrange {}-{}",
            range.min, range.max
        ),
    ))
}

/// Binds the remote-facing UDP socket, returning it with a flag that is `true`
/// when it is a dual-stack IPv6 socket.
///
/// When `external` is unspecified (the default `0.0.0.0`, or `::`) the operator
/// did not pin a source address, so we prefer a dual-stack IPv6 socket and can
/// reach both IPv4 and IPv6 destinations — mirroring the per-target family
/// choice the TCP path makes. The caller must then send IPv4 destinations in
/// `::ffff:` mapped form (that is what the returned flag signals). If IPv6 is
/// disabled or unsupported (some container environments, older kernels) the
/// dual-stack bind fails, so we fall back to a plain IPv4 socket — IPv6
/// destinations then surface as counted `send_to` failures rather than breaking
/// UDP entirely. A concrete `external` pins the source family; the other family
/// is then legitimately unreachable, and a datagram to it surfaces as a counted
/// `send_to` failure rather than a silent drop.
async fn bind_outbound_udp(external: IpAddr) -> io::Result<(UdpSocket, bool)> {
    use std::net::Ipv4Addr;

    if external.is_unspecified() {
        match bind_dual_stack_udp() {
            Ok(socket) => return Ok((socket, true)),
            Err(e) => {
                debug!(error = %e, "dual-stack UDP bind failed; falling back to IPv4-only");
                let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
                return Ok((socket, false));
            }
        }
    }
    // A concrete `external` pins the source family; the address determines it.
    let socket = UdpSocket::bind((external, 0)).await?;
    Ok((socket, false))
}

/// Binds a dual-stack IPv6 UDP socket on the unspecified address, so it can
/// reach both IPv4 (as `::ffff:` mapped) and IPv6 destinations. Returns an error
/// when IPv6 is unavailable, letting the caller fall back to IPv4.
fn bind_dual_stack_udp() -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::Ipv6Addr;

    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    // Accept and emit IPv4 as `::ffff:` mapped. Windows defaults IPV6_V6ONLY on,
    // so set it explicitly for portable dual-stack.
    socket.set_only_v6(false)?;
    // tokio's `from_std` requires a non-blocking socket.
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).into())?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket)
}

/// Pseudo-random start offset (`0..span`) for the UDP port scan. The atomic
/// `count` is XORed with the clock seed so consecutive associations always get
/// distinct offsets even when the system clock is coarse (e.g. ~1-15 ms on
/// Windows and some VMs), where `subsec_nanos()` alone is a multiple of the
/// resolution and `% span` would collapse to 0 whenever `span` divides it.
fn scan_start_offset(seed_nanos: u32, count: u32, span: u32) -> u32 {
    (seed_nanos ^ count) % span
}

/// Establishes an outbound TCP connection to `target`, optionally bound to the
/// configured `external` source address, subject to `timeout`.
async fn connect_remote(
    target: SocketAddr,
    external: IpAddr,
    timeout: std::time::Duration,
) -> Result<TcpStream> {
    let socket = match target {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };

    // Only bind an explicit source when the family matches and a concrete
    // address was configured; otherwise let the OS choose.
    match (external, target) {
        (IpAddr::V4(ip), SocketAddr::V4(_)) if !ip.is_unspecified() => {
            socket.bind(SocketAddr::new(IpAddr::V4(ip), 0))?;
        }
        (IpAddr::V6(ip), SocketAddr::V6(_)) if !ip.is_unspecified() => {
            socket.bind(SocketAddr::new(IpAddr::V6(ip), 0))?;
        }
        _ => {}
    }

    let stream = tokio::time::timeout(timeout, socket.connect(target))
        .await
        .map_err(|_| Error::Timeout)??;
    // Match the client-side socket: interactive proxied traffic benefits more
    // from low latency than from Nagle coalescing on either leg.
    if let Err(e) = stream.set_nodelay(true) {
        debug!(target = %target, error = %e, "failed to set TCP_NODELAY on outbound socket");
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requested_udp_endpoint_uses_concrete_matching_client_addr() {
        let client_ip = "127.0.0.1".parse().unwrap();
        let endpoint = requested_udp_endpoint(
            &TargetAddr::Ip("127.0.0.1:53000".parse().unwrap()),
            client_ip,
        );
        assert_eq!(endpoint, Some("127.0.0.1:53000".parse().unwrap()));
    }

    #[test]
    fn requested_udp_endpoint_maps_unspecified_ip_to_client_ip() {
        let client_ip = "127.0.0.1".parse().unwrap();
        let endpoint =
            requested_udp_endpoint(&TargetAddr::Ip("0.0.0.0:53000".parse().unwrap()), client_ip);
        assert_eq!(endpoint, Some("127.0.0.1:53000".parse().unwrap()));
    }

    #[test]
    fn advertised_reply_addr_overrides_host_and_keeps_port() {
        let advertise = crate::config::Config::parse(
            "internal: 0.0.0.0 port = 1080\nudp.advertise: 203.0.113.5",
        )
        .unwrap()
        .udp_advertise;
        let relay: SocketAddr = "10.0.0.1:40000".parse().unwrap();
        assert_eq!(
            advertised_reply_addr(relay, advertise.as_ref()),
            "203.0.113.5:40000".parse().unwrap()
        );
    }

    #[test]
    fn advertised_reply_addr_falls_back_to_bound_addr() {
        let relay: SocketAddr = "10.0.0.1:40000".parse().unwrap();
        // Nothing configured.
        assert_eq!(advertised_reply_addr(relay, None), relay);
        // Configured, but no address for the relay's (IPv4) family.
        let v6_only = crate::config::Config::parse(
            "internal: 0.0.0.0 port = 1080\nudp.advertise: 2001:db8::1",
        )
        .unwrap()
        .udp_advertise;
        assert_eq!(advertised_reply_addr(relay, v6_only.as_ref()), relay);
    }

    #[test]
    fn advertised_reply_addr_handles_ipv4_mapped_relay() {
        // A dual-stack relay socket reports an IPv4 client as an IPv4-mapped IPv6
        // local address. The IPv4 advertise address must still apply (and the
        // reply become a plain IPv4 address), so a client reaching us via NAT
        // gets a reachable BND.ADDR rather than the bound mapped address.
        let advertise = crate::config::Config::parse(
            "internal: 0.0.0.0 port = 1080\nudp.advertise: 203.0.113.5",
        )
        .unwrap()
        .udp_advertise;
        let relay: SocketAddr = "[::ffff:10.0.0.1]:40000".parse().unwrap();
        assert_eq!(
            advertised_reply_addr(relay, advertise.as_ref()),
            "203.0.113.5:40000".parse().unwrap()
        );
    }

    #[test]
    fn requested_udp_endpoint_ignores_mismatched_or_zero_endpoint() {
        let client_ip = "127.0.0.1".parse().unwrap();
        assert_eq!(
            requested_udp_endpoint(
                &TargetAddr::Ip("127.0.0.2:53000".parse().unwrap()),
                client_ip
            ),
            None
        );
        assert_eq!(
            requested_udp_endpoint(&TargetAddr::Ip("127.0.0.1:0".parse().unwrap()), client_ip),
            None
        );
    }

    #[tokio::test]
    async fn connect_remote_times_out_to_blackhole() {
        // 10.255.255.1 is non-routable in most test environments; a tiny
        // timeout guarantees the timeout branch is exercised quickly.
        let target: SocketAddr = "10.255.255.1:9".parse().unwrap();
        let res = connect_remote(
            target,
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            std::time::Duration::from_millis(150),
        )
        .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn bind_udp_in_range_respects_the_configured_range() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // No range -> an ephemeral bind still succeeds (historical default).
        let any = bind_udp_in_range(ip, None).await.unwrap();
        assert!(any.local_addr().unwrap().port() > 0);

        // With a range, the bound port falls inside it.
        let range = PortRange {
            min: 40000,
            max: 40063,
        };
        let sock = bind_udp_in_range(ip, Some(range)).await.unwrap();
        let port = sock.local_addr().unwrap().port();
        assert!(
            range.contains(port),
            "bound port {port} is outside {}-{}",
            range.min,
            range.max
        );

        // A fully-occupied (single-port) range reports exhaustion as AddrInUse
        // rather than panicking or returning an out-of-range port.
        let occupied = UdpSocket::bind((ip, 0)).await.unwrap();
        let taken = occupied.local_addr().unwrap().port();
        let err = bind_udp_in_range(
            ip,
            Some(PortRange {
                min: taken,
                max: taken,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    }

    #[test]
    fn scan_start_offset_survives_a_coarse_clock() {
        // A coarse clock makes subsec_nanos a multiple of its resolution; pick a
        // span that divides it, so the time seed alone would always yield 0.
        let coarse_nanos = 5_000_000; // 5 ms, a multiple of a 1 ms tick
        let span = 100;
        assert_eq!(coarse_nanos % span, 0, "precondition: the degenerate case");

        // The XORed counter perturbs successive offsets so they are not all 0,
        // and every offset stays within the range.
        let offsets: Vec<u32> = (0..4)
            .map(|count| scan_start_offset(coarse_nanos, count, span))
            .collect();
        assert!(
            offsets.iter().any(|&o| o != 0),
            "counter failed to perturb the offset: {offsets:?}"
        );
        assert!(offsets.iter().all(|&o| o < span));
    }
}
