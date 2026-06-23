//! The listener and accept loop.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;

use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::abuse::AbuseControls;
use crate::acl::Scope;
use crate::auth::{CommandAuth, UserDb};
use crate::client_stream::ClientStream;
use crate::config::Config;
use crate::connection::{Connection, ConnectionResources};
use crate::dns::DnsResolver;
use crate::errors::Result;
use crate::metrics::{self, Metrics};
use crate::net::Cidr;
use crate::tls;

/// A bound SOCKS5 server ready to accept connections.
pub struct Server {
    state: Arc<RwLock<ServerState>>,
    process_config: Arc<Config>,
    listener: TcpListener,
    max_connections: usize,
    metrics: Arc<Metrics>,
    abuse: Arc<AbuseControls>,
    metrics_addr: Option<SocketAddr>,
    metrics_listener: Mutex<Option<TcpListener>>,
    tls_listener: Option<tls::TlsListener>,
    /// Background ACME renewal task, aborted when the `Server` is dropped (the
    /// same `AbortOnDrop` guard used for the metrics task). Held only for that
    /// drop side effect, so a `Server` bound and dropped without running to
    /// process exit does not leak it.
    #[allow(dead_code)]
    acme_driver: Option<AbortOnDrop<()>>,
    has_run: AtomicBool,
}

struct ServerState {
    config: Arc<Config>,
    users: Arc<UserDb>,
    command_auth: Option<Arc<CommandAuth>>,
    dns_resolver: Arc<DnsResolver>,
}

impl Server {
    /// Binds the listener and loads the user database (if configured).
    ///
    /// Emits warnings for configurations that would silently deny all traffic,
    /// since deny-by-default can otherwise be surprising.
    pub async fn bind(config: Config) -> Result<Server> {
        let users = load_users(&config).await?;
        warn_config_footguns(&config);
        // Build the acceptor and (for ACME) the renewal driver up front so config
        // errors surface before binding, but defer spawning the driver until the
        // listener is bound (below).
        let tls_setup = tls::load_acceptor(config.tls.as_ref())?;

        let (metrics_addr, metrics_listener) = match config.metrics_listen {
            Some(addr) => {
                let listener = TcpListener::bind(addr).await?;
                let listen = listener.local_addr()?;
                if listen.ip().is_unspecified() || !listen.ip().is_loopback() {
                    warn!(
                        listen = %listen,
                        "metrics endpoint is not bound to loopback; protect it with network access controls"
                    );
                }
                (Some(listen), Some(listener))
            }
            None => (None, None),
        };
        let listener = TcpListener::bind(config.internal).await?;
        let listen = listener.local_addr()?;
        if let Some(tls) = &config.tls {
            info!(listen = %listen, "listening with TLS");
            // The port stays fixed for the life of the process (it is not
            // reloadable), so this startup-only check is sufficient. The
            // ACME-vs-proxyprotocol check lives in `warn_config_footguns` so it
            // also fires on reload, where `proxyprotocol` can change.
            if matches!(tls, crate::config::TlsConfig::Acme(_)) && listen.port() != 443 {
                warn!(
                    listen = %listen,
                    "ACME uses TLS-ALPN-01, which Let's Encrypt validates on port 443; ensure this listener is reachable on port 443 (directly or via forwarding) or certificate issuance will fail"
                );
            }
        } else {
            info!(listen = %listen, "listening");
        }
        // Now the listener is bound, spawn the ACME renewal driver (if any): a
        // failed bind above cannot leak it, and validation cannot start before
        // the listener can answer the TLS-ALPN-01 challenge.
        let (tls_listener, acme_driver) = match tls_setup {
            Some(setup) => {
                // Hold the renewal task as an abort-on-drop handle so a `Server`
                // bound and dropped without running to process exit (e.g. in
                // tests) does not leak it.
                let driver = setup.acme_driver.map(|d| AbortOnDrop(tokio::spawn(d)));
                (Some(setup.listener), driver)
            }
            None => (None, None),
        };
        let max_connections = config.max_connections;
        let abuse = AbuseControls::new(config.rate_limits.clone());
        let mut process_config = config.clone();
        process_config.internal = listen;
        process_config.metrics_listen = metrics_addr;
        let process_config = Arc::new(process_config);

        Ok(Server {
            state: Arc::new(RwLock::new(ServerState {
                config: process_config.clone(),
                users: Arc::new(users),
                command_auth: build_command_auth(&config),
                dns_resolver: Arc::new(DnsResolver::new()),
            })),
            process_config,
            listener,
            max_connections,
            metrics: Metrics::new(),
            abuse,
            metrics_addr,
            metrics_listener: Mutex::new(metrics_listener),
            tls_listener,
            acme_driver,
            has_run: AtomicBool::new(false),
        })
    }

    /// Returns the actual local address the listener is bound to (useful when
    /// the configured port was `0`).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Returns the metrics endpoint address when metrics are enabled.
    pub fn metrics_addr(&self) -> std::io::Result<Option<SocketAddr>> {
        Ok(self.metrics_addr)
    }

    /// Replaces the runtime configuration used for newly accepted
    /// connections. Startup resources such as listener addresses, logging
    /// sinks, and the max-connection semaphore require a process restart.
    pub async fn reload(&self, mut config: Config) -> Result<()> {
        warn_restart_required_changes(&self.process_config, &config);
        let users = load_users(&config).await?;
        warn_config_footguns(&config);
        preserve_process_config(&mut config, &self.process_config);
        self.abuse.update_config(config.rate_limits.clone());

        let command_auth = build_command_auth(&config);
        let mut state = self.state.write().await;
        state.config = Arc::new(config);
        state.users = Arc::new(users);
        state.command_auth = command_auth;
        // The DNS resolver (and its TTL cache) is intentionally preserved across
        // reloads: the resolution *policy* lives in the config and is read per
        // lookup, so a reload takes effect on the next resolve without discarding
        // the cache and triggering a re-resolve storm. The deny policy is also
        // applied per call, so newly denied categories take effect immediately.
        info!("configuration reloaded");
        Ok(())
    }

    /// Runs the accept loop until a fatal error occurs.
    ///
    /// Per-connection errors are logged and never abort the loop. A semaphore
    /// caps the number of concurrent connections at `max_connections`.
    pub async fn run(&self) -> Result<()> {
        if self
            .has_run
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "server accept loop is already running",
            )
            .into());
        }

        let limiter = Arc::new(Semaphore::new(self.max_connections));
        let metrics_listener = self
            .metrics_listener
            .lock()
            .map_err(|_| std::io::Error::other("metrics listener lock poisoned"))?
            .take();
        let _metrics_task = metrics_listener
            .map(|listener| tokio::spawn(metrics::serve_metrics(listener, self.metrics.clone())))
            .map(AbortOnDrop);

        loop {
            // Acquire a slot before accepting so we apply backpressure rather
            // than unboundedly spawning tasks under load.
            let permit = match limiter.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => {
                    error!("connection limiter closed unexpectedly");
                    break;
                }
            };

            let (mut stream, peer) = match self.listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    // Transient accept errors (e.g. EMFILE) should not kill the
                    // server; log and continue after dropping the permit.
                    warn!(error = %e, "accept failed");
                    drop(permit);
                    continue;
                }
            };

            let local = match stream.local_addr() {
                Ok(a) => a,
                Err(e) => {
                    warn!(error = %e, "could not read local address; dropping connection");
                    // No `accepted_connection()` ran for this socket yet (that
                    // happens after admission below), so do not call
                    // `closed_connection()` here — it would drift the active gauge.
                    drop(permit);
                    continue;
                }
            };

            // Snapshot the live config up front: the PROXY-protocol gate needs
            // the trusted-upstream set and the connection task needs the rest.
            let state = self.state.read().await;
            let config = state.config.clone();
            let users = state.users.clone();
            let command_auth = state.command_auth.clone();
            let dns_resolver = state.dns_resolver.clone();
            drop(state);

            // PROXY-protocol admission gate. The cheap source-IP check is done
            // here; the header read itself is deferred to the task so a silent
            // upstream cannot stall the accept loop. When enabled, only trusted
            // upstreams may connect — a direct client must not reach this
            // listener, or it could forge its advertised source address.
            let expect_proxy = if config.proxy_protocol.is_empty() {
                false
            } else if is_trusted_proxy_upstream(&config.proxy_protocol, peer.ip()) {
                true
            } else {
                warn!(peer = %peer, "rejecting connection: proxyprotocol is enabled and the source is not a trusted upstream");
                drop(permit);
                continue;
            };

            // Disable Nagle's algorithm: proxied interactive traffic benefits
            // from low latency more than from coalescing.
            if let Err(e) = stream.set_nodelay(true) {
                debug!(peer = %peer, error = %e, "failed to set TCP_NODELAY");
            }

            let metrics = self.metrics.clone();
            let tls_listener = self.tls_listener.clone();
            let abuse = self.abuse.clone();
            let handshake_timeout = config.handshake_timeout;
            tokio::spawn(async move {
                // Resolve the real client address from a trusted upstream's
                // PROXY header before admitting and handling the connection.
                let peer = if expect_proxy {
                    match tokio::time::timeout(
                        handshake_timeout,
                        crate::proxy_protocol::read_header(&mut stream),
                    )
                    .await
                    {
                        Ok(Ok(Some(real))) => real,
                        // LOCAL / UNSPEC (e.g. a health check): keep the peer.
                        Ok(Ok(None)) => peer,
                        Ok(Err(e)) => {
                            debug!(peer = %peer, error = %e, "invalid PROXY protocol header; dropping");
                            drop(permit);
                            return;
                        }
                        Err(_) => {
                            debug!(peer = %peer, "PROXY protocol header timed out; dropping");
                            drop(permit);
                            return;
                        }
                    }
                } else {
                    peer
                };

                // Per-client abuse admission, keyed on the real client address.
                let client_permit = match abuse.admit(peer.ip()) {
                    Ok(p) => p,
                    Err(reason) => {
                        metrics.rate_limited();
                        warn!(peer = %peer, reason = reason.as_str(), "connection rejected by rate limit");
                        drop(permit);
                        return;
                    }
                };
                metrics.accepted_connection();
                let throttle_bucket = client_permit.throttle_bucket();

                let resources = ConnectionResources {
                    config,
                    users,
                    command_auth,
                    metrics: metrics.clone(),
                    abuse,
                    dns_resolver,
                    throttle_bucket,
                };
                if let Some(listener) = tls_listener {
                    match tokio::time::timeout(handshake_timeout, listener.accept(stream)).await {
                        Ok(Ok(Some(stream))) => {
                            let conn = Connection::new(
                                ClientStream::Tls(Box::new(stream)),
                                peer,
                                local,
                                resources,
                            );
                            if let Err(e) = conn.handle().await {
                                debug!(peer = %peer, error = %e, "connection ended");
                            }
                        }
                        // An ACME TLS-ALPN-01 challenge was answered during the
                        // handshake; the connection carries no SOCKS traffic.
                        Ok(Ok(None)) => {
                            debug!(peer = %peer, "answered ACME TLS-ALPN-01 challenge");
                        }
                        Ok(Err(e)) => {
                            debug!(peer = %peer, error = %e, "TLS handshake failed");
                        }
                        Err(_) => {
                            debug!(peer = %peer, "TLS handshake timed out");
                        }
                    }
                } else {
                    let conn = Connection::new(ClientStream::Tcp(stream), peer, local, resources);
                    if let Err(e) = conn.handle().await {
                        debug!(peer = %peer, error = %e, "connection ended");
                    }
                }
                metrics.closed_connection();
                drop(client_permit);
                drop(permit); // release the slot when the connection finishes
            });
        }

        Ok(())
    }
}

async fn load_users(config: &Config) -> Result<UserDb> {
    let Some(path) = config.userlist.clone() else {
        return Ok(UserDb::new());
    };
    // Read and hash-parse the userlist off the runtime threads so a large file on
    // slow storage cannot stall a worker during startup or reload. The outer `?`
    // surfaces a join failure (only on a panic — `spawn_blocking` is never
    // cancelled) with context; the inner `?` surfaces the load/parse error.
    let db = tokio::task::spawn_blocking(move || -> Result<UserDb> {
        let db = UserDb::load(&path)?;
        info!(users = db.len(), path = %path.display(), "loaded userlist");
        Ok(db)
    })
    .await
    .map_err(|e| {
        crate::errors::Error::Io(std::io::Error::other(format!(
            "userlist load task failed: {e}"
        )))
    })??;
    Ok(db)
}

/// Builds the external auth verifier when `auth.command` is configured. The
/// verified-credential cache lives inside it, so it is rebuilt (and the cache
/// reset) on reload, matching how the userlist cache behaves.
fn build_command_auth(config: &Config) -> Option<Arc<CommandAuth>> {
    let command = config.auth_command.as_ref()?;
    match CommandAuth::new(command) {
        Some(auth) => {
            info!(program = %command[0], "external auth command enabled");
            Some(Arc::new(auth))
        }
        None => None,
    }
}

/// Returns `true` if `peer` falls within one of the trusted PROXY-protocol
/// upstream networks.
///
/// The peer address is canonicalized first so an IPv4 trust CIDR still matches
/// an upstream that arrives IPv4-mapped (`::ffff:a.b.c.d`) on a dual-stack
/// listener — `Cidr::contains` itself treats a mapped address as IPv6 and would
/// otherwise reject a legitimately trusted IPv4 upstream.
fn is_trusted_proxy_upstream(trusted: &[Cidr], peer: IpAddr) -> bool {
    let canonical = peer.to_canonical();
    trusted.iter().any(|cidr| cidr.contains(canonical))
}

fn warn_config_footguns(config: &Config) {
    if !config.rules.has_scope(Scope::Client) {
        warn!("no 'client' rules defined — all incoming connections will be denied");
    }
    if !config.rules.has_scope(Scope::Socks) {
        warn!("no 'socks' rules defined — all requests will be denied");
    }
    if config.noauth_on_non_loopback_listener() {
        warn!(
            listen = %config.internal,
            "the SOCKS 'none' (no-authentication) method is offered on a non-loopback listener; combined with permissive 'socks'/'client' rules this is an open proxy — drop 'none' from 'socksmethod' (require 'username'), tighten the rules, or bind 'internal' to loopback"
        );
    }
    // Checked here (rather than only at bind) so it also fires on reload, where
    // `proxyprotocol` can be enabled while ACME stays active.
    if matches!(config.tls.as_ref(), Some(crate::config::TlsConfig::Acme(_)))
        && !config.proxy_protocol.is_empty()
    {
        warn!(
            listen = %config.internal,
            "ACME and proxyprotocol are both configured: TLS-ALPN-01 validation connections that reach this listener without a trusted PROXY header (for example Let's Encrypt connecting directly) are rejected by the proxy-protocol admission gate, so certificate issuance/renewal fails unless every validation connection is proxied through a trusted PROXY-protocol upstream (TCP passthrough)"
        );
    }
}

fn warn_restart_required_changes(old: &Config, new: &Config) {
    if old.internal != new.internal {
        warn!(
            current = %old.internal,
            requested = %new.internal,
            "internal listener changes require a restart"
        );
    }
    if old.metrics_listen != new.metrics_listen {
        warn!(
            current = ?old.metrics_listen,
            requested = ?new.metrics_listen,
            "metrics listener changes require a restart"
        );
    }
    if old.tls != new.tls {
        warn!("TLS listener changes require a restart");
    }
    if old.max_connections != new.max_connections {
        warn!(
            current = old.max_connections,
            requested = new.max_connections,
            "maxconnections changes require a restart"
        );
    }
    if old.log_outputs != new.log_outputs
        || old.log_file != new.log_file
        || old.log_format != new.log_format
        || old.log_rotate_size != new.log_rotate_size
        || old.log_rotate_keep != new.log_rotate_keep
    {
        warn!("logging changes require a restart");
    }
}

fn preserve_process_config(config: &mut Config, process_config: &Config) {
    config.internal = process_config.internal;
    config.metrics_listen = process_config.metrics_listen;
    config.tls = process_config.tls.clone();
    config.max_connections = process_config.max_connections;
    config.log_outputs = process_config.log_outputs.clone();
    config.log_file = process_config.log_file.clone();
    config.log_format = process_config.log_format;
    config.log_rotate_size = process_config.log_rotate_size;
    config.log_rotate_keep = process_config.log_rotate_keep;
}

struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_trust_matches_ipv4_mapped_upstream() {
        let trusted: Vec<Cidr> = vec!["10.0.0.0/8".parse().unwrap()];

        // A plain IPv4 trusted upstream matches.
        assert!(is_trusted_proxy_upstream(
            &trusted,
            "10.1.2.3".parse().unwrap()
        ));
        // The same upstream arriving IPv4-mapped on a dual-stack listener must
        // also match the IPv4 trust CIDR — the regression this fixes.
        assert!(is_trusted_proxy_upstream(
            &trusted,
            "::ffff:10.1.2.3".parse().unwrap()
        ));

        // An untrusted source is rejected whether it arrives plain or mapped.
        assert!(!is_trusted_proxy_upstream(
            &trusted,
            "203.0.113.7".parse().unwrap()
        ));
        assert!(!is_trusted_proxy_upstream(
            &trusted,
            "::ffff:203.0.113.7".parse().unwrap()
        ));
    }

    #[test]
    fn proxy_trust_matches_native_ipv6_upstream() {
        // A native (non-mapped) IPv6 upstream still matches an IPv6 trust CIDR.
        let trusted: Vec<Cidr> = vec!["2001:db8::/32".parse().unwrap()];
        assert!(is_trusted_proxy_upstream(
            &trusted,
            "2001:db8::1".parse().unwrap()
        ));
        assert!(!is_trusted_proxy_upstream(
            &trusted,
            "2001:dead::1".parse().unwrap()
        ));
    }

    #[tokio::test]
    async fn bind_reports_local_addr() {
        let cfg = Config::parse(
            "internal: 127.0.0.1 port = 0\nsocks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }",
        )
        .unwrap();
        let server = Server::bind(cfg).await.unwrap();
        let addr = server.local_addr().unwrap();
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert_ne!(addr.port(), 0);
    }

    #[tokio::test]
    async fn reload_updates_runtime_config_for_new_connections() {
        let server = Server::bind(
            Config::parse(
                "internal: 127.0.0.1 port = 0\nhandshaketimeout: 7\nclient pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }\nsocks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }",
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let listen = server.local_addr().unwrap();

        server
            .reload(
                Config::parse(
                    "internal: 127.0.0.1 port = 1\nhandshaketimeout: 11\nmaxconnections: 7\nclient pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }\nsocks block { from: 0.0.0.0/0 to: 0.0.0.0/0 }",
                )
                .unwrap(),
            )
            .await
            .unwrap();

        let state = server.state.read().await;
        assert_eq!(
            state.config.handshake_timeout,
            std::time::Duration::from_secs(11)
        );
        assert_eq!(state.config.internal, listen);
        assert_eq!(state.config.max_connections, 1024);
        assert_eq!(state.config.rules.rules.len(), 2);
    }

    #[tokio::test]
    async fn run_can_only_start_once() {
        let server = Arc::new(
            Server::bind(
                Config::parse(
                    "internal: 127.0.0.1 port = 0\nclient pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }\nsocks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }",
                )
                .unwrap(),
            )
            .await
            .unwrap(),
        );
        let running = server.clone();
        let handle = tokio::spawn(async move { running.run().await });
        while !server.has_run.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }

        let err = server.run().await.unwrap_err();
        assert!(err.to_string().contains("already running"));
        handle.abort();
    }

    #[tokio::test]
    async fn metrics_addr_remains_available_after_run_starts() {
        let server = Arc::new(
            Server::bind(
                Config::parse(
                    "internal: 127.0.0.1 port = 0\nmetrics.listen: 127.0.0.1:0\nclient pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }\nsocks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }",
                )
                .unwrap(),
            )
            .await
            .unwrap(),
        );
        let before = server.metrics_addr().unwrap().unwrap();
        let running = server.clone();
        let handle = tokio::spawn(async move { running.run().await });
        while !server.has_run.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }

        assert_eq!(server.metrics_addr().unwrap(), Some(before));
        handle.abort();
    }
}
