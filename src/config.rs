//! The Alighieri configuration model and its Dante-inspired parser.
//!
//! The configuration language borrows Dante's `sockd.conf` look and feel:
//! line-oriented `keyword: value` settings plus brace-delimited
//! `client`/`socks` rule blocks. It is **not** a copy of Dante's grammar — it
//! is a clean, independent implementation of a familiar style.
//!
//! # Example
//!
//! ```text
//! # Listen for clients on all interfaces, port 1080.
//! internal: 0.0.0.0 port = 1080
//! # Make outbound connections from this address (0.0.0.0 = OS default).
//! external: 0.0.0.0
//!
//! # Offer "no auth" and username/password; require a userlist for the latter.
//! socksmethod: username none
//! userlist: /etc/alighieri/users
//! auth.cachettl: 300
//!
//! connecttimeout: 30
//! handshaketimeout: 10
//! iotimeout: 0
//! udptimeout: 60
//! maxconnections: 1024
//! logoutput: stdout
//! logformat: text
//! dns.prefer: system
//! dns.tryall: false
//! dns.cachettl: 0
//! dns.timeout: 5
//! # metrics.listen: 127.0.0.1:9090
//! # tls.certfile: /etc/alighieri/tls/server.crt
//! # tls.keyfile: /etc/alighieri/tls/server.key
//!
//! # Admission: accept connections from the RFC1918 LAN only.
//! client pass {
//!     from: 10.0.0.0/8 to: 0.0.0.0/0
//! }
//!
//! # Authorisation: allow TCP CONNECT and UDP anywhere except loopback.
//! socks block {
//!     from: 0.0.0.0/0 to: 127.0.0.0/8
//! }
//! socks pass {
//!     from: 0.0.0.0/0 to: 0.0.0.0/0
//!     protocol: tcp udp
//!     command: connect udpassociate
//! }
//! ```

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::acl::{Rule, RuleSet, Scope, Verdict};
use crate::errors::{Error, Result};
use crate::net::{AddrSpec, Cidr, HostPattern, PortRange};
use crate::socks5::{Command, Method};

/// An authentication kind usable both as a server-offered method and as a
/// per-rule selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    /// No authentication (`socksmethod: none`).
    None,
    /// RFC 1929 username/password (`socksmethod: username`).
    Username,
}

impl AuthKind {
    /// Maps to the corresponding SOCKS5 method byte.
    pub fn to_method(self) -> Method {
        match self {
            AuthKind::None => Method::NoAuth,
            AuthKind::Username => Method::UserPass,
        }
    }
}

/// A transport protocol selector for `socks` rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Where log lines are emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogOutput {
    Stdout,
    Stderr,
    File,
}

/// Log record encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    Json,
}

/// Address-family ordering for DNS results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsPreference {
    System,
    Ipv4,
    Ipv6,
}

/// Destination IP categories that may be denied after DNS resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsDenyCategory {
    Private,
    LinkLocal,
    Loopback,
    Multicast,
    Unspecified,
    Documentation,
    Reserved,
}

/// DNS resolution policy used by TCP CONNECT and UDP ASSOCIATE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPolicy {
    pub preference: DnsPreference,
    pub try_all: bool,
    pub deny: Vec<DnsDenyCategory>,
    pub cache_ttl: Option<Duration>,
    /// Deadline for resolving one destination name, as monotonic elapsed time
    /// (enforced with `tokio::time::timeout`). Bounds how long a CONNECT or a
    /// domain-target UDP datagram *waits* on a slow or wedged resolver, so it
    /// cannot pin a connection permit or stall UDP forwarding. It does not cancel
    /// the underlying system `getaddrinfo`, which runs on a blocking thread and
    /// keeps running until the OS resolver returns — this bounds the caller's
    /// wait, not the resolver thread's lifetime.
    pub timeout: Duration,
}

/// TLS listener settings. When present, accepted client TCP connections are
/// upgraded to TLS before the SOCKS5 greeting is read. The certificate is
/// either operator-provided files or obtained automatically over ACME.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsConfig {
    /// Operator-provided certificate and private key (PEM).
    Files {
        cert_file: PathBuf,
        key_file: PathBuf,
    },
    /// Automatic certificates from an ACME provider (Let's Encrypt), answered
    /// with the TLS-ALPN-01 challenge on the TLS listener itself.
    Acme(AcmeConfig),
}

/// ACME (Let's Encrypt) settings for automatic TLS certificates. Validation uses
/// TLS-ALPN-01, so the listener must be reachable at each domain on port 443.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeConfig {
    /// Domains the certificate covers (the SANs).
    pub domains: Vec<String>,
    /// Optional account contact e-mail (e.g. for expiry notices).
    pub email: Option<String>,
    /// Directory persisting the ACME account and issued certificates across
    /// restarts, so they are not re-requested (which would hit rate limits).
    pub cache_dir: PathBuf,
    /// Use the provider's staging environment — for testing, with far looser
    /// rate limits but untrusted certificates.
    pub staging: bool,
}

/// A fixed-window rate limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimit {
    pub limit: u64,
    pub window: Duration,
}

/// Optional per-client abuse controls.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RateLimits {
    pub connection_rate: Option<RateLimit>,
    pub auth_failure_rate: Option<RateLimit>,
    pub concurrent_connections: Option<usize>,
    pub byte_rate: Option<RateLimit>,
}

/// The fully validated runtime configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address the proxy listens on for clients (Dante `internal`).
    pub internal: SocketAddr,
    /// Local address used as the source for outbound connections
    /// (Dante `external`). `0.0.0.0` lets the OS choose.
    pub external: IpAddr,
    /// Trusted upstream CIDRs permitted to send a PROXY protocol header. Empty
    /// disables PROXY protocol. When non-empty, a connection from a listed
    /// source must begin with a v1/v2 header (its advertised client address then
    /// drives rules, abuse limits, metrics, and logs), and connections from any
    /// other source are rejected.
    pub proxy_protocol: Vec<Cidr>,
    /// Authentication methods offered to clients, in preference order.
    pub socks_methods: Vec<AuthKind>,
    /// Maximum time allowed to establish an outbound connection.
    pub connect_timeout: Duration,
    /// Maximum time allowed for pre-relay SOCKS negotiation.
    pub handshake_timeout: Duration,
    /// Idle timeout for established relays. `Duration::ZERO` disables it.
    pub io_timeout: Duration,
    /// Idle timeout for UDP associations.
    pub udp_timeout: Duration,
    /// Inclusive UDP port range for the client-facing relay socket (the
    /// `BND.PORT` advertised in the ASSOCIATE reply, where clients send their
    /// datagrams). `None` lets the OS pick an ephemeral port. Useful for
    /// firewalling: open exactly this range to the proxy for inbound UDP.
    pub udp_port_range: Option<PortRange>,
    /// Whether a UDP ASSOCIATE reply must come from the exact remote `host:port`
    /// the client sent to, rather than merely the same host. Defaults on (`true`);
    /// set `udp.strictreply: false` to relax to host-only matching for servers
    /// that legitimately answer from a different port (e.g. TFTP).
    pub udp_strict_reply: bool,
    /// Public host advertised as the `BND.ADDR` in the UDP ASSOCIATE reply (the
    /// real bound relay port is kept), for a proxy reached via NAT or a different
    /// public address than it binds on locally. An IP is advertised directly; a
    /// hostname is resolved per UDP association through the async resolver (so
    /// config load does no DNS). `None` advertises the locally-bound relay address.
    pub udp_advertise: Option<UdpAdvertise>,
    /// How long shutdown waits for in-flight connections to finish before
    /// aborting the rest (`shutdown.draintimeout`, seconds). `0` cuts them
    /// immediately. Read at process start; a reload does not change it.
    pub shutdown_drain_timeout: Duration,
    /// Path to the username/password database (required if `username` is
    /// offered as a method).
    pub userlist: Option<PathBuf>,
    /// How long a successful credential verification may be reused without
    /// re-running the password hash. `None` disables the cache.
    pub auth_cache_ttl: Option<Duration>,
    /// External credential-verification command (the `auth.command` hook). When
    /// set, username/password verification runs this command instead of the
    /// userlist; the first element is the program and the rest are arguments.
    pub auth_command: Option<Vec<String>>,
    /// Maximum number of concurrent client connections.
    pub max_connections: usize,
    /// Active log sinks.
    pub log_outputs: Vec<LogOutput>,
    /// File path used when `logoutput` includes `file`.
    pub log_file: Option<PathBuf>,
    /// Log record encoding.
    pub log_format: LogFormat,
    /// Maximum active log file size before rotation.
    pub log_rotate_size: u64,
    /// Number of rotated log files to retain.
    pub log_rotate_keep: usize,
    /// DNS resolution policy.
    pub dns: DnsPolicy,
    /// Optional local metrics endpoint listen address.
    pub metrics_listen: Option<SocketAddr>,
    /// Whether a `metrics.listen` that is not loopback — including an unspecified
    /// address such as `0.0.0.0`/`[::]` — is allowed. The metrics endpoint is
    /// unauthenticated, so binding it off loopback is refused unless this is
    /// explicitly set (`metrics.allowpublic: true`).
    pub metrics_allow_public: bool,
    /// Optional TLS wrapper for the client listener.
    pub tls: Option<TlsConfig>,
    /// Optional per-client rate limits and abuse controls.
    pub rate_limits: RateLimits,
    /// The access-control rule set.
    pub rules: RuleSet,
}

impl Config {
    pub fn uses_file_logging(&self) -> bool {
        self.log_outputs.contains(&LogOutput::File)
    }

    /// True when the no-authentication (`none`) SOCKS method is offered on a
    /// non-loopback `internal` listener. `none` is offered by default, and also
    /// whenever `socksmethod` lists it (e.g. `username none`). Combined with
    /// permissive `socks`/`client` rules that is an open proxy, so the server
    /// warns about it at startup and on reload. An IPv4-mapped loopback address
    /// (`::ffff:127.0.0.1`) is canonicalised first so it is recognised as
    /// loopback.
    pub fn noauth_on_non_loopback_listener(&self) -> bool {
        self.socks_methods.contains(&AuthKind::None)
            && !self.internal.ip().to_canonical().is_loopback()
    }

    /// Validates settings that only take effect when the process starts (so this
    /// is run at startup and by `config check`, but not on reload, where these
    /// settings are not applied anyway).
    ///
    /// The metrics endpoint is unauthenticated and exposes operational counters
    /// and rule labels, so a non-loopback (or unspecified) `metrics.listen` is
    /// refused unless the operator explicitly opts in with `metrics.allowpublic`.
    /// An IPv4-mapped loopback address is canonicalised first.
    pub fn validate_startup(&self) -> Result<()> {
        if let Some(addr) = self.metrics_listen {
            let ip = addr.ip().to_canonical();
            if (ip.is_unspecified() || !ip.is_loopback()) && !self.metrics_allow_public {
                return Err(Error::Config(format!(
                    "metrics.listen {addr} is not loopback; the metrics endpoint is unauthenticated, \
                     so set 'metrics.allowpublic: true' to expose it or bind it to 127.0.0.1/[::1]"
                )));
            }
        }
        Ok(())
    }

    /// Loads and validates configuration from a file on disk.
    pub fn load(path: &Path) -> Result<Config> {
        let mut builder = Builder::default();
        let mut stack = Vec::new();
        let text = fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("failed to read {}: {e}", path.display())))?;
        let canonical = fs::canonicalize(path)
            .map_err(|e| Error::Config(format!("failed to resolve {}: {e}", path.display())))?;
        parse_resolved_config_file(canonical, text, &mut builder, &mut stack)?;
        builder.build()
    }

    /// Parses and validates configuration from a string.
    pub fn parse(text: &str) -> Result<Config> {
        let mut builder = Builder::default();
        let source = ParseSource::memory();
        let mut stack = Vec::new();
        parse_config_text(text, &mut builder, &source, &mut stack)?;
        builder.build()
    }
}

#[derive(Debug)]
struct ParseSource {
    display: Option<String>,
    base_dir: Option<PathBuf>,
}

impl ParseSource {
    fn memory() -> Self {
        Self {
            display: None,
            base_dir: None,
        }
    }

    fn file(path: &Path) -> Self {
        Self {
            display: Some(path.display().to_string()),
            base_dir: path.parent().map(Path::to_path_buf),
        }
    }
}

fn parse_config_file(path: &Path, builder: &mut Builder, stack: &mut Vec<PathBuf>) -> Result<()> {
    let canonical = fs::canonicalize(path)
        .map_err(|e| Error::Config(format!("failed to resolve {}: {e}", path.display())))?;
    let text = fs::read_to_string(&canonical)
        .map_err(|e| Error::Config(format!("failed to read {}: {e}", canonical.display())))?;
    parse_resolved_config_file(canonical, text, builder, stack)
}

fn parse_resolved_config_file(
    canonical: PathBuf,
    text: String,
    builder: &mut Builder,
    stack: &mut Vec<PathBuf>,
) -> Result<()> {
    if stack.contains(&canonical) {
        let mut cycle = stack
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>();
        cycle.push(canonical.display().to_string());
        return Err(Error::Config(format!(
            "include cycle detected: {}",
            cycle.join(" -> ")
        )));
    }

    let source = ParseSource::file(&canonical);

    stack.push(canonical);
    let result = parse_config_text(&text, builder, &source, stack);
    stack.pop();
    result
}

fn parse_config_text(
    text: &str,
    builder: &mut Builder,
    source: &ParseSource,
    stack: &mut Vec<PathBuf>,
) -> Result<()> {
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let lineno = i + 1;
        let stripped = strip_comment(lines[i]);
        let trimmed = stripped.trim();
        if trimmed.is_empty() {
            i += 1;
            continue;
        }
        let head_tokens: Vec<&str> = trimmed.split_whitespace().collect();
        let head = head_tokens[0].trim_end_matches(':').to_ascii_lowercase();

        if (head == "client" || head == "socks")
            && head_tokens.len() >= 2
            && matches!(
                head_tokens[1].to_ascii_lowercase().as_str(),
                "pass" | "block"
            )
        {
            let (block, next) =
                gather_block(&lines, i).map_err(|e| with_source_context(e, source))?;
            let rule = parse_rule(&block, lineno).map_err(|e| with_source_context(e, source))?;
            builder.rules.push(rule);
            i = next;
        } else if head == "include" {
            let values: Vec<String> = head_tokens[1..].iter().map(|s| s.to_string()).collect();
            parse_include(&values, lineno, source, builder, stack)?;
            i += 1;
        } else {
            let values: Vec<String> = head_tokens[1..].iter().map(|s| s.to_string()).collect();
            parse_setting(builder, &head, &values, lineno)
                .map_err(|e| with_source_context(e, source))?;
            i += 1;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Builder + defaults
// ---------------------------------------------------------------------------

const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 30;
const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 10;
const DEFAULT_UDP_TIMEOUT_SECS: u64 = 60;
const DEFAULT_DNS_TIMEOUT_SECS: u64 = 5;
/// How long shutdown waits for in-flight connections to drain before aborting
/// the rest. Kept under typical service-manager stop windows (systemd's 90s) so
/// the process exits on its own first.
const DEFAULT_SHUTDOWN_DRAIN_TIMEOUT_SECS: u64 = 10;
/// Upper bound for `shutdown.draintimeout`. A drain should never take an hour,
/// and bounding it avoids an overflow panic when the timer deadline is computed.
const MAX_SHUTDOWN_DRAIN_TIMEOUT_SECS: u64 = 3600;
/// Upper bound for `dns.timeout`. A resolution should never take an hour, and
/// rejecting absurd values keeps the timer deadline (`Instant::now() + dur`)
/// well clear of overflow.
const MAX_DNS_TIMEOUT_SECS: u64 = 3600;
const DEFAULT_AUTH_CACHE_TTL_SECS: u64 = 300;
const DEFAULT_MAX_CONNECTIONS: usize = 1024;
/// Upper bound on `maxconnections`: the value is passed to `Semaphore::new`,
/// which panics above `Semaphore::MAX_PERMITS`, so reject an absurd value at
/// parse time rather than crashing at startup.
const MAX_CONNECTIONS_LIMIT: usize = tokio::sync::Semaphore::MAX_PERMITS;
pub const DEFAULT_LOG_ROTATE_SIZE_BYTES: u64 = 10 * 1024 * 1024;
pub const DEFAULT_LOG_ROTATE_KEEP: usize = 5;
/// Upper bound on `logrotate.keep`: it drives an O(n) rename loop on each
/// rotation, so an absurd value would stall logging. Far above any practical
/// retention.
const MAX_LOG_ROTATE_KEEP: usize = 10_000;

#[derive(Default)]
struct Builder {
    internal: Option<SocketAddr>,
    external: Option<IpAddr>,
    proxy_protocol: Option<Vec<Cidr>>,
    socks_methods: Option<Vec<AuthKind>>,
    connect_timeout: Option<Duration>,
    handshake_timeout: Option<Duration>,
    io_timeout: Option<Duration>,
    udp_timeout: Option<Duration>,
    udp_port_range: Option<PortRange>,
    udp_strict_reply: Option<bool>,
    udp_advertise: Option<UdpAdvertise>,
    shutdown_drain_timeout: Option<Duration>,
    userlist: Option<PathBuf>,
    auth_cache_ttl: Option<Option<Duration>>,
    auth_command: Option<Vec<String>>,
    max_connections: Option<usize>,
    log_outputs: Option<Vec<LogOutput>>,
    log_file: Option<PathBuf>,
    log_format: Option<LogFormat>,
    log_rotate_size: Option<u64>,
    log_rotate_keep: Option<usize>,
    dns_preference: Option<DnsPreference>,
    dns_try_all: Option<bool>,
    dns_deny: Option<Vec<DnsDenyCategory>>,
    dns_cache_ttl: Option<Option<Duration>>,
    dns_timeout: Option<Duration>,
    metrics_listen: Option<SocketAddr>,
    metrics_allow_public: Option<bool>,
    tls_cert_file: Option<PathBuf>,
    tls_key_file: Option<PathBuf>,
    tls_acme_domains: Vec<String>,
    tls_acme_email: Option<String>,
    tls_acme_cache: Option<PathBuf>,
    tls_acme_staging: Option<bool>,
    rate_connection: Option<RateLimit>,
    rate_auth_failure: Option<RateLimit>,
    rate_concurrent: Option<usize>,
    rate_bytes: Option<RateLimit>,
    rules: Vec<Rule>,
}

impl Builder {
    fn build(self) -> Result<Config> {
        let internal = self
            .internal
            .ok_or_else(|| Error::Config("missing required setting: internal".into()))?;
        let socks_methods = self.socks_methods.unwrap_or_else(|| vec![AuthKind::None]);

        if socks_methods.is_empty() {
            return Err(Error::Config(
                "socksmethod must list at least one method".into(),
            ));
        }
        if socks_methods.contains(&AuthKind::Username)
            && self.userlist.is_none()
            && self.auth_command.is_none()
        {
            return Err(Error::Config(
                "socksmethod 'username' requires a 'userlist' or 'auth.command' setting".into(),
            ));
        }

        let mut log_outputs = self.log_outputs.unwrap_or_else(|| vec![LogOutput::Stdout]);
        if self.log_file.is_some() && !log_outputs.contains(&LogOutput::File) {
            log_outputs.push(LogOutput::File);
        }
        if log_outputs.contains(&LogOutput::File) && self.log_file.is_none() {
            return Err(Error::Config(
                "logoutput 'file' requires a 'logfile' setting".into(),
            ));
        }

        let has_files = self.tls_cert_file.is_some() || self.tls_key_file.is_some();
        let has_acme = !self.tls_acme_domains.is_empty()
            || self.tls_acme_email.is_some()
            || self.tls_acme_cache.is_some()
            || self.tls_acme_staging.is_some();
        if has_files && has_acme {
            return Err(Error::Config(
                "TLS cannot use both 'tls.certfile'/'tls.keyfile' and 'tls.acme.*'; choose one"
                    .into(),
            ));
        }
        let tls = if has_acme {
            if self.tls_acme_domains.is_empty() {
                return Err(Error::Config(
                    "tls.acme requires at least one domain in 'tls.acme.domains'".into(),
                ));
            }
            let cache_dir = self.tls_acme_cache.ok_or_else(|| {
                Error::Config(
                    "tls.acme requires 'tls.acme.cache' (a directory to persist the account and \
                     certificates so they are not re-requested on restart)"
                        .into(),
                )
            })?;
            Some(TlsConfig::Acme(AcmeConfig {
                domains: self.tls_acme_domains,
                email: self.tls_acme_email,
                cache_dir,
                staging: self.tls_acme_staging.unwrap_or(false),
            }))
        } else {
            match (self.tls_cert_file, self.tls_key_file) {
                (Some(cert_file), Some(key_file)) => Some(TlsConfig::Files {
                    cert_file,
                    key_file,
                }),
                (Some(_), None) => {
                    return Err(Error::Config(
                        "tls.certfile requires a matching 'tls.keyfile' setting".into(),
                    ));
                }
                (None, Some(_)) => {
                    return Err(Error::Config(
                        "tls.keyfile requires a matching 'tls.certfile' setting".into(),
                    ));
                }
                (None, None) => None,
            }
        };

        Ok(Config {
            internal,
            external: self.external.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            proxy_protocol: self.proxy_protocol.unwrap_or_default(),
            socks_methods,
            connect_timeout: self
                .connect_timeout
                .unwrap_or(Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS)),
            handshake_timeout: self
                .handshake_timeout
                .unwrap_or(Duration::from_secs(DEFAULT_HANDSHAKE_TIMEOUT_SECS)),
            io_timeout: self.io_timeout.unwrap_or(Duration::ZERO),
            udp_timeout: self
                .udp_timeout
                .unwrap_or(Duration::from_secs(DEFAULT_UDP_TIMEOUT_SECS)),
            udp_port_range: self.udp_port_range,
            udp_strict_reply: self.udp_strict_reply.unwrap_or(true),
            udp_advertise: self.udp_advertise,
            shutdown_drain_timeout: self
                .shutdown_drain_timeout
                .unwrap_or(Duration::from_secs(DEFAULT_SHUTDOWN_DRAIN_TIMEOUT_SECS)),
            userlist: self.userlist,
            auth_cache_ttl: self
                .auth_cache_ttl
                .unwrap_or(Some(Duration::from_secs(DEFAULT_AUTH_CACHE_TTL_SECS))),
            auth_command: self.auth_command,
            max_connections: self.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
            log_outputs,
            log_file: self.log_file,
            log_format: self.log_format.unwrap_or(LogFormat::Text),
            log_rotate_size: self
                .log_rotate_size
                .unwrap_or(DEFAULT_LOG_ROTATE_SIZE_BYTES),
            log_rotate_keep: self.log_rotate_keep.unwrap_or(DEFAULT_LOG_ROTATE_KEEP),
            dns: DnsPolicy {
                preference: self.dns_preference.unwrap_or(DnsPreference::System),
                try_all: self.dns_try_all.unwrap_or(false),
                deny: self.dns_deny.unwrap_or_default(),
                cache_ttl: self.dns_cache_ttl.unwrap_or(None),
                timeout: self
                    .dns_timeout
                    .unwrap_or(Duration::from_secs(DEFAULT_DNS_TIMEOUT_SECS)),
            },
            metrics_listen: self.metrics_listen,
            metrics_allow_public: self.metrics_allow_public.unwrap_or(false),
            tls,
            rate_limits: RateLimits {
                connection_rate: self.rate_connection,
                auth_failure_rate: self.rate_auth_failure,
                concurrent_connections: self.rate_concurrent,
                byte_rate: self.rate_bytes,
            },
            rules: RuleSet::new(self.rules),
        })
    }
}

// ---------------------------------------------------------------------------
// Setting parsing
// ---------------------------------------------------------------------------

fn parse_setting(b: &mut Builder, key: &str, vals: &[String], lineno: usize) -> Result<()> {
    match key {
        "internal" => b.internal = Some(parse_endpoint(vals, lineno)?),
        "external" => b.external = Some(parse_ip(vals, lineno)?),
        "proxyprotocol" | "proxy.protocol" => {
            if vals.is_empty() {
                return Err(cfg_err(
                    lineno,
                    "proxyprotocol requires at least one trusted upstream CIDR",
                ));
            }
            let mut cidrs = Vec::with_capacity(vals.len());
            for v in vals {
                let cidr: Cidr = v.parse().map_err(|e| {
                    cfg_err(lineno, &format!("invalid proxyprotocol CIDR '{v}': {e}"))
                })?;
                cidrs.push(cidr);
            }
            b.proxy_protocol = Some(cidrs);
        }
        "socksmethod" | "clientmethod" => {
            // clientmethod is accepted for Dante familiarity; Alighieri performs
            // authentication at the SOCKS layer, so both populate the offered
            // method list. The last one wins if both are present.
            b.socks_methods = Some(parse_methods(vals, lineno)?);
        }
        "connecttimeout" | "connect.timeout" => {
            b.connect_timeout = Some(Duration::from_secs(parse_nonzero_secs(
                vals,
                lineno,
                "connecttimeout",
            )?));
        }
        "handshaketimeout" | "handshake.timeout" => {
            b.handshake_timeout = Some(Duration::from_secs(parse_nonzero_secs(
                vals,
                lineno,
                "handshaketimeout",
            )?));
        }
        "iotimeout" | "io.timeout" => {
            b.io_timeout = Some(Duration::from_secs(parse_u64(vals, lineno)?));
        }
        "udptimeout" | "udp.timeout" => {
            b.udp_timeout = Some(Duration::from_secs(parse_u64(vals, lineno)?));
        }
        "udpportrange" | "udp.portrange" => {
            if vals.is_empty() {
                return Err(cfg_err(
                    lineno,
                    "udp.portrange requires a value (MIN-MAX or a single PORT)",
                ));
            }
            let spec = vals.join(" ");
            let range: PortRange = spec
                .parse()
                .map_err(|e| cfg_err(lineno, &format!("invalid udp.portrange '{spec}': {e}")))?;
            if range.min == 0 {
                return Err(cfg_err(lineno, "udp.portrange must not include port 0"));
            }
            b.udp_port_range = Some(range);
        }
        "udpstrictreply" | "udp.strictreply" => {
            b.udp_strict_reply = Some(parse_bool(vals, lineno)?);
        }
        "udpadvertise" | "udp.advertise" => {
            let spec = expect_single(vals, lineno, "udp.advertise host")?;
            b.udp_advertise = Some(match spec.parse::<IpAddr>() {
                Ok(ip) => UdpAdvertise::Ip(ip),
                Err(_) => {
                    // A non-IP value is a hostname resolved per association — reject
                    // a malformed one now so `--check` catches it instead of it
                    // silently failing to resolve and falling back at runtime.
                    crate::net::validate_hostname(spec).map_err(|e| {
                        // `{spec:?}` escapes the value: it is one validation rejects
                        // (e.g. a control char), so it must not land verbatim in the
                        // error/log output it would otherwise forge.
                        cfg_err(lineno, &format!("invalid udp.advertise host {spec:?}: {e}"))
                    })?;
                    UdpAdvertise::Host(spec.clone())
                }
            });
        }
        "shutdowndraintimeout" | "shutdown.draintimeout" => {
            let secs = parse_u64(vals, lineno)?;
            if secs > MAX_SHUTDOWN_DRAIN_TIMEOUT_SECS {
                return Err(cfg_err(
                    lineno,
                    &format!(
                        "shutdown.draintimeout cannot exceed {MAX_SHUTDOWN_DRAIN_TIMEOUT_SECS} seconds"
                    ),
                ));
            }
            b.shutdown_drain_timeout = Some(Duration::from_secs(secs));
        }
        "userlist" => {
            if vals.is_empty() {
                return Err(cfg_err(lineno, "userlist requires a path"));
            }
            b.userlist = Some(PathBuf::from(vals.join(" ")));
        }
        "maxconnections" | "max.connections" => {
            let value = parse_usize_positive(vals, lineno, "maxconnections")?;
            if value > MAX_CONNECTIONS_LIMIT {
                return Err(cfg_err(
                    lineno,
                    &format!("maxconnections must be at most {MAX_CONNECTIONS_LIMIT}"),
                ));
            }
            b.max_connections = Some(value);
        }
        "logoutput" => b.log_outputs = Some(parse_log_outputs(vals, lineno)?),
        "logfile" | "log.file" => {
            if vals.is_empty() {
                return Err(cfg_err(lineno, "logfile requires a path"));
            }
            b.log_file = Some(PathBuf::from(vals.join(" ")));
        }
        "logformat" | "log.format" => b.log_format = Some(parse_log_format(vals, lineno)?),
        "logrotatesize" | "logrotate.size" | "log.rotate.size" => {
            let size = parse_byte_size(vals, lineno)?;
            if size == 0 {
                return Err(cfg_err(lineno, "logrotate.size must be > 0"));
            }
            b.log_rotate_size = Some(size);
        }
        "logrotatekeep" | "logrotate.keep" | "log.rotate.keep" => {
            let value = parse_usize(vals, lineno, "logrotate.keep")?;
            if value > MAX_LOG_ROTATE_KEEP {
                return Err(cfg_err(
                    lineno,
                    &format!("logrotate.keep must be at most {MAX_LOG_ROTATE_KEEP}"),
                ));
            }
            b.log_rotate_keep = Some(value);
        }
        "dnsprefer" | "dns.prefer" => b.dns_preference = Some(parse_dns_preference(vals, lineno)?),
        "dnstryall" | "dns.tryall" | "dns.try_all" => {
            b.dns_try_all = Some(parse_bool(vals, lineno)?);
        }
        "dnsdeny" | "dns.deny" => b.dns_deny = Some(parse_dns_deny(vals, lineno)?),
        "dnscachettl" | "dns.cachettl" | "dns.cache.ttl" => {
            b.dns_cache_ttl = Some(parse_cache_ttl(vals, lineno, "dns.cachettl")?);
        }
        "dnstimeout" | "dns.timeout" => {
            let secs = parse_u64(vals, lineno)?;
            if secs == 0 {
                return Err(cfg_err(
                    lineno,
                    "dns.timeout must be at least 1 second (0 would fail every name resolution)",
                ));
            }
            if secs > MAX_DNS_TIMEOUT_SECS {
                return Err(cfg_err(
                    lineno,
                    &format!("dns.timeout cannot exceed {MAX_DNS_TIMEOUT_SECS} seconds"),
                ));
            }
            b.dns_timeout = Some(Duration::from_secs(secs));
        }
        "authcachettl" | "auth.cachettl" | "auth.cache.ttl" => {
            b.auth_cache_ttl = Some(parse_cache_ttl(vals, lineno, "auth.cachettl")?);
        }
        "authcommand" | "auth.command" => {
            if vals.is_empty() {
                return Err(cfg_err(lineno, "auth.command requires a program path"));
            }
            b.auth_command = Some(vals.to_vec());
        }
        "metricslisten" | "metrics.listen" => {
            b.metrics_listen = Some(parse_endpoint(vals, lineno)?)
        }
        "metricsallowpublic" | "metrics.allowpublic" => {
            b.metrics_allow_public = Some(parse_bool(vals, lineno)?)
        }
        "tlscertfile" | "tls.certfile" | "tls.cert" => {
            b.tls_cert_file = Some(parse_path(vals, lineno, "tls.certfile")?);
        }
        "tlskeyfile" | "tls.keyfile" | "tls.key" => {
            b.tls_key_file = Some(parse_path(vals, lineno, "tls.keyfile")?);
        }
        "tlsacmedomains" | "tls.acme.domains" | "tls.acme.domain" => {
            if vals.is_empty() {
                return Err(cfg_err(
                    lineno,
                    "tls.acme.domains requires at least one domain",
                ));
            }
            // Reject a name a public CA cannot issue for via TLS-ALPN-01 (IP
            // address, single-label/local name, wildcard, underscore, raw Unicode,
            // bad hyphen) at config load, rather than starting up and only failing
            // later in the ACME order with no usable certificate.
            for domain in vals {
                crate::net::validate_acme_domain(domain).map_err(|e| {
                    // `{domain:?}` escapes the value so a rejected control character
                    // cannot forge the error/log line it appears in.
                    cfg_err(
                        lineno,
                        &format!("invalid tls.acme.domains entry {domain:?}: {e}"),
                    )
                })?;
            }
            // Store the canonical form: a tolerated trailing dot (FQDN) is stripped
            // so the ACME stack receives a clean identifier.
            b.tls_acme_domains = vals
                .iter()
                .map(|d| d.strip_suffix('.').unwrap_or(d).to_string())
                .collect();
        }
        "tlsacmeemail" | "tls.acme.email" => match vals {
            [] => return Err(cfg_err(lineno, "tls.acme.email requires an address")),
            [email] => b.tls_acme_email = Some(email.clone()),
            _ => {
                return Err(cfg_err(
                    lineno,
                    "tls.acme.email accepts only a single address",
                ))
            }
        },
        "tlsacmecache" | "tls.acme.cache" | "tls.acme.cachedir" => {
            b.tls_acme_cache = Some(parse_path(vals, lineno, "tls.acme.cache")?);
        }
        "tlsacmestaging" | "tls.acme.staging" => {
            b.tls_acme_staging = Some(parse_bool(vals, lineno)?);
        }
        "ratelimit.connectionrate" | "ratelimit.connection.rate" | "ratelimit.connections" => {
            b.rate_connection = Some(parse_rate_limit(vals, lineno, "ratelimit.connectionrate")?);
        }
        "ratelimit.authfailurerate" | "ratelimit.auth.failure.rate" | "ratelimit.authfailures" => {
            b.rate_auth_failure =
                Some(parse_rate_limit(vals, lineno, "ratelimit.authfailurerate")?);
        }
        "ratelimit.concurrentconnections"
        | "ratelimit.concurrent.connections"
        | "ratelimit.concurrent" => {
            b.rate_concurrent = Some(parse_usize_positive(
                vals,
                lineno,
                "ratelimit.concurrentconnections",
            )?);
        }
        "ratelimit.byterate" | "ratelimit.byte.rate" | "ratelimit.bytes" => {
            b.rate_bytes = Some(parse_byte_rate_limit(vals, lineno, "ratelimit.byterate")?);
        }
        other => {
            return Err(cfg_err(lineno, &format!("unknown keyword '{other}'")));
        }
    }
    Ok(())
}

/// Parses an `IP [port = N]` or `IP:PORT` endpoint.
fn parse_endpoint(vals: &[String], lineno: usize) -> Result<SocketAddr> {
    if vals.is_empty() {
        return Err(cfg_err(lineno, "expected an address"));
    }
    if let Some(pos) = vals.iter().position(|v| v.eq_ignore_ascii_case("port")) {
        // The only valid form is `IP port = N`, so `port` must follow the IP
        // directly; anything between them is a typo to reject rather than ignore.
        if pos != 1 {
            return Err(cfg_err(
                lineno,
                "expected 'IP port = N' (unexpected tokens before 'port')",
            ));
        }
        // The keyword form is exactly `port = N` (the documented spelling), so
        // the tokens after `port` must be `=` then the port. This rejects a
        // missing value (`port =`), a `=`-less `port N`, and split/trailing
        // tokens (`port = 10 80`) that whitespace tokenization would otherwise
        // join into a single port string.
        if !matches!(&vals[pos + 1..], [eq, _] if eq == "=") {
            return Err(cfg_err(lineno, "expected 'IP port = N'"));
        }
        let ip: IpAddr = vals[0]
            .parse()
            .map_err(|_| cfg_err(lineno, &format!("invalid IP address '{}'", vals[0])))?;
        let port_str = join_value_after(&vals[pos + 1..]);
        let port: u16 = port_str
            .parse()
            .map_err(|_| cfg_err(lineno, &format!("invalid port '{port_str}'")))?;
        Ok(SocketAddr::new(ip, port))
    } else {
        // A bare `IP:PORT` is a single token; reject trailing tokens.
        let val = expect_single(vals, lineno, "'IP:PORT' or 'IP port = N' address")?;
        val.parse::<SocketAddr>().map_err(|_| {
            cfg_err(
                lineno,
                &format!("expected 'IP port = N' or 'IP:PORT', got '{val}'"),
            )
        })
    }
}

fn parse_path(vals: &[String], lineno: usize, setting: &str) -> Result<PathBuf> {
    if vals.is_empty() {
        return Err(cfg_err(lineno, &format!("{setting} requires a path")));
    }
    Ok(PathBuf::from(vals.join(" ")))
}

/// Parses a `usize` setting (zero allowed), rejecting a value too large for the
/// target's pointer width rather than silently truncating it — `as usize` would
/// wrap a `u64` above `usize::MAX` on a 32-bit target.
fn parse_usize(vals: &[String], lineno: usize, setting: &str) -> Result<usize> {
    let n = parse_u64(vals, lineno)?;
    usize::try_from(n).map_err(|_| cfg_err(lineno, &format!("{setting} is too large")))
}

fn parse_usize_positive(vals: &[String], lineno: usize, setting: &str) -> Result<usize> {
    let n = parse_usize(vals, lineno, setting)?;
    if n == 0 {
        return Err(cfg_err(lineno, &format!("{setting} must be > 0")));
    }
    Ok(n)
}

fn parse_rate_limit(vals: &[String], lineno: usize, setting: &str) -> Result<RateLimit> {
    if vals.is_empty() {
        return Err(cfg_err(
            lineno,
            &format!("{setting} requires LIMIT/WINDOW_SECONDS"),
        ));
    }
    let raw = join_value_after(vals);
    let Some((limit, window)) = raw.split_once('/') else {
        return Err(cfg_err(
            lineno,
            &format!("{setting} must use LIMIT/WINDOW_SECONDS"),
        ));
    };
    let limit = limit
        .replace('_', "")
        .parse::<u64>()
        .map_err(|_| cfg_err(lineno, &format!("invalid rate limit '{limit}'")))?;
    let window = window
        .replace('_', "")
        .parse::<u64>()
        .map_err(|_| cfg_err(lineno, &format!("invalid rate window '{window}'")))?;
    if limit == 0 || window == 0 {
        return Err(cfg_err(lineno, &format!("{setting} values must be > 0")));
    }
    Ok(RateLimit {
        limit,
        window: Duration::from_secs(window),
    })
}

fn parse_byte_rate_limit(vals: &[String], lineno: usize, setting: &str) -> Result<RateLimit> {
    if vals.is_empty() {
        return Err(cfg_err(
            lineno,
            &format!("{setting} requires BYTES/WINDOW_SECONDS"),
        ));
    }
    let raw = join_value_after(vals);
    let Some((bytes, window)) = raw.split_once('/') else {
        return Err(cfg_err(
            lineno,
            &format!("{setting} must use BYTES/WINDOW_SECONDS"),
        ));
    };
    let limit = parse_byte_size(&[bytes.to_string()], lineno)?;
    let window = window
        .replace('_', "")
        .parse::<u64>()
        .map_err(|_| cfg_err(lineno, &format!("invalid byte rate window '{window}'")))?;
    if limit == 0 || window == 0 {
        return Err(cfg_err(lineno, &format!("{setting} values must be > 0")));
    }
    Ok(RateLimit {
        limit,
        window: Duration::from_secs(window),
    })
}

fn parse_ip(vals: &[String], lineno: usize) -> Result<IpAddr> {
    let val = expect_single(vals, lineno, "IP address")?;
    val.parse()
        .map_err(|_| cfg_err(lineno, &format!("invalid IP address '{val}'")))
}

/// Public host advertised as the UDP ASSOCIATE reply `BND.ADDR` (host only; the
/// real relay port is kept). An IP is advertised directly; a hostname is resolved
/// at UDP-associate time through the async resolver — so config load does no DNS,
/// and a wedged resolver can neither hang the load nor leak abandoned threads. The
/// address matching the client's connection family is chosen at that point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpAdvertise {
    /// A literal IP address, advertised as-is (family-matched per association).
    Ip(IpAddr),
    /// A hostname, resolved per association.
    Host(String),
}

/// Returns the single value of a scalar setting, rejecting trailing tokens that
/// would otherwise be silently ignored (e.g. `dns.tryall: yes maybe` or
/// `connecttimeout: 5 oops`).
fn expect_single<'a>(vals: &'a [String], lineno: usize, what: &str) -> Result<&'a String> {
    match vals {
        [single] => Ok(single),
        [] => Err(cfg_err(lineno, &format!("expected a {what}"))),
        _ => Err(cfg_err(
            lineno,
            &format!("expected a single {what}, got {} values", vals.len()),
        )),
    }
}

fn parse_u64(vals: &[String], lineno: usize) -> Result<u64> {
    let val = expect_single(vals, lineno, "number")?;
    val.parse()
        .map_err(|_| cfg_err(lineno, &format!("invalid number '{val}'")))
}

/// Parses a positive (non-zero) number of seconds. For `connecttimeout` and
/// `handshaketimeout`, `0` is not "disabled" — it would make `tokio::time::timeout`
/// expire immediately and fail every connection — so it is rejected.
fn parse_nonzero_secs(vals: &[String], lineno: usize, name: &str) -> Result<u64> {
    let secs = parse_u64(vals, lineno)?;
    if secs == 0 {
        return Err(cfg_err(
            lineno,
            &format!(
                "{name} must be at least 1 second (0 would fail every connection immediately)"
            ),
        ));
    }
    Ok(secs)
}

fn parse_bool(vals: &[String], lineno: usize) -> Result<bool> {
    let val = expect_single(vals, lineno, "boolean")?;
    match val.to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        other => Err(cfg_err(
            lineno,
            &format!("invalid boolean '{other}' (expected yes/no or true/false)"),
        )),
    }
}

fn parse_methods(vals: &[String], lineno: usize) -> Result<Vec<AuthKind>> {
    if vals.is_empty() {
        return Err(cfg_err(lineno, "expected at least one method"));
    }
    let mut out = Vec::new();
    for v in vals {
        let kind = match v.to_ascii_lowercase().as_str() {
            "none" => AuthKind::None,
            "username" => AuthKind::Username,
            other => {
                return Err(cfg_err(
                    lineno,
                    &format!("unknown method '{other}' (expected 'none' or 'username')"),
                ))
            }
        };
        if !out.contains(&kind) {
            out.push(kind);
        }
    }
    Ok(out)
}

fn parse_log_outputs(vals: &[String], lineno: usize) -> Result<Vec<LogOutput>> {
    if vals.is_empty() {
        return Err(cfg_err(lineno, "expected at least one log output"));
    }
    let mut out = Vec::new();
    for v in vals {
        let sink = match v.to_ascii_lowercase().as_str() {
            "stdout" => LogOutput::Stdout,
            "stderr" => LogOutput::Stderr,
            "file" => LogOutput::File,
            other => {
                return Err(cfg_err(
                    lineno,
                    &format!(
                        "unsupported logoutput '{other}' (expected 'stdout', 'stderr' or 'file')"
                    ),
                ))
            }
        };
        if !out.contains(&sink) {
            out.push(sink);
        }
    }
    Ok(out)
}

fn parse_log_format(vals: &[String], lineno: usize) -> Result<LogFormat> {
    match expect_single(vals, lineno, "log format")?
        .to_ascii_lowercase()
        .as_str()
    {
        "text" => Ok(LogFormat::Text),
        "json" => Ok(LogFormat::Json),
        other => Err(cfg_err(
            lineno,
            &format!("unsupported logformat '{other}' (expected 'text' or 'json')"),
        )),
    }
}

fn parse_byte_size(vals: &[String], lineno: usize) -> Result<u64> {
    if vals.is_empty() {
        return Err(cfg_err(lineno, "expected a byte size"));
    }
    let raw = join_value_after(vals).to_ascii_lowercase();
    let (number, multiplier) = if let Some(number) = raw.strip_suffix("kib") {
        (number, 1024_u64)
    } else if let Some(number) = raw.strip_suffix("kb") {
        (number, 1000_u64)
    } else if let Some(number) = raw.strip_suffix('k') {
        (number, 1024_u64)
    } else if let Some(number) = raw.strip_suffix("mib") {
        (number, 1024_u64 * 1024)
    } else if let Some(number) = raw.strip_suffix("mb") {
        (number, 1000_u64 * 1000)
    } else if let Some(number) = raw.strip_suffix('m') {
        (number, 1024_u64 * 1024)
    } else if let Some(number) = raw.strip_suffix("gib") {
        (number, 1024_u64 * 1024 * 1024)
    } else if let Some(number) = raw.strip_suffix("gb") {
        (number, 1000_u64 * 1000 * 1000)
    } else if let Some(number) = raw.strip_suffix('g') {
        (number, 1024_u64 * 1024 * 1024)
    } else if let Some(number) = raw.strip_suffix('b') {
        (number, 1_u64)
    } else {
        (raw.as_str(), 1_u64)
    };
    let number = number.replace('_', "");
    let bytes = number.parse::<u64>().map_err(|_| {
        cfg_err(
            lineno,
            &format!(
                "invalid byte size '{}' (expected bytes or K/M/G suffix)",
                vals[0]
            ),
        )
    })?;
    bytes
        .checked_mul(multiplier)
        .ok_or_else(|| cfg_err(lineno, "byte size is too large"))
}

fn parse_dns_preference(vals: &[String], lineno: usize) -> Result<DnsPreference> {
    match expect_single(vals, lineno, "DNS preference")?
        .to_ascii_lowercase()
        .as_str()
    {
        "system" | "default" => Ok(DnsPreference::System),
        "ipv4" | "v4" => Ok(DnsPreference::Ipv4),
        "ipv6" | "v6" => Ok(DnsPreference::Ipv6),
        other => Err(cfg_err(
            lineno,
            &format!("unsupported dns.prefer '{other}' (expected 'system', 'ipv4' or 'ipv6')"),
        )),
    }
}

fn parse_cache_ttl(vals: &[String], lineno: usize, setting: &str) -> Result<Option<Duration>> {
    let what = format!("{setting} value (seconds, 0, off, none, or disabled)");
    match expect_single(vals, lineno, &what)?
        .to_ascii_lowercase()
        .as_str()
    {
        "off" | "none" | "disabled" => Ok(None),
        _ => {
            let secs = parse_u64(vals, lineno)?;
            Ok((secs > 0).then(|| Duration::from_secs(secs)))
        }
    }
}

fn parse_dns_deny(vals: &[String], lineno: usize) -> Result<Vec<DnsDenyCategory>> {
    if vals.is_empty() {
        return Err(cfg_err(lineno, "expected at least one DNS deny category"));
    }
    let mut out = Vec::new();
    for v in vals {
        let category = match v.to_ascii_lowercase().as_str() {
            "private" => DnsDenyCategory::Private,
            "linklocal" | "link-local" | "link_local" => DnsDenyCategory::LinkLocal,
            "loopback" => DnsDenyCategory::Loopback,
            "multicast" => DnsDenyCategory::Multicast,
            "unspecified" => DnsDenyCategory::Unspecified,
            "documentation" | "doc" => DnsDenyCategory::Documentation,
            "reserved" => DnsDenyCategory::Reserved,
            other => {
                return Err(cfg_err(
                    lineno,
                    &format!("unknown DNS deny category '{other}'"),
                ))
            }
        };
        if !out.contains(&category) {
            out.push(category);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Rule-block parsing
// ---------------------------------------------------------------------------

/// Collects the tokens of a brace-delimited block starting at line `start`,
/// returning the tokens (header words included) and the index of the first
/// line after the closing brace.
fn gather_block(lines: &[&str], start: usize) -> Result<(Vec<String>, usize)> {
    let mut tokens: Vec<String> = Vec::new();
    let mut depth: i32 = 0;
    let mut opened = false;
    let mut i = start;
    while i < lines.len() {
        let stripped = strip_comment(lines[i]);
        let spaced = stripped.replace('{', " { ").replace('}', " } ");
        let line_tokens: Vec<&str> = spaced.split_whitespace().collect();
        for (j, tok) in line_tokens.iter().enumerate() {
            match *tok {
                "{" => {
                    depth += 1;
                    opened = true;
                }
                "}" => {
                    depth -= 1;
                    if depth < 0 {
                        return Err(cfg_err(i + 1, "unexpected '}'"));
                    }
                }
                _ => {}
            }
            tokens.push((*tok).to_string());
            // The brace that closes the block must be the last token on its
            // line. Anything after it — a selector typed outside the braces, or
            // a second rule crammed onto the line — would be silently dropped by
            // the body parser (which only sees tokens up to '}'), broadening the
            // rule. Reject it instead.
            if opened && depth == 0 && j + 1 < line_tokens.len() {
                return Err(cfg_err(i + 1, "unexpected tokens after '}'"));
            }
        }
        i += 1;
        if opened && depth == 0 {
            return Ok((tokens, i));
        }
    }
    Err(cfg_err(start + 1, "unterminated rule block (missing '}')"))
}

fn parse_rule(tokens: &[String], lineno: usize) -> Result<Rule> {
    let scope = match tokens[0].to_ascii_lowercase().as_str() {
        "client" => Scope::Client,
        "socks" => Scope::Socks,
        other => return Err(cfg_err(lineno, &format!("unknown rule scope '{other}'"))),
    };
    let verdict = match tokens[1].to_ascii_lowercase().as_str() {
        "pass" => Verdict::Pass,
        "block" => Verdict::Block,
        other => return Err(cfg_err(lineno, &format!("unknown verdict '{other}'"))),
    };

    let open = tokens
        .iter()
        .position(|t| t == "{")
        .ok_or_else(|| cfg_err(lineno, "rule is missing '{'"))?;
    let close = tokens
        .iter()
        .rposition(|t| t == "}")
        .ok_or_else(|| cfg_err(lineno, "rule is missing '}'"))?;
    let name = parse_rule_name(&tokens[2..open], lineno)?;
    let body = &tokens[open + 1..close];

    let mut from: Option<AddrSpec> = None;
    let mut to: Option<AddrSpec> = None;
    let mut protocols: Vec<Protocol> = Vec::new();
    let mut commands: Vec<Command> = Vec::new();
    let mut methods: Vec<AuthKind> = Vec::new();
    let mut bandwidth: Option<RateLimit> = None;

    let mut idx = 0;
    while idx < body.len() {
        let key = body[idx].trim_end_matches(':').to_ascii_lowercase();
        idx += 1;
        let mut vals: Vec<String> = Vec::new();
        while idx < body.len() && !is_known_body_key(&body[idx]) {
            vals.push(body[idx].clone());
            idx += 1;
        }
        match key.as_str() {
            "from" => from = Some(parse_addr_spec(&vals, lineno, false)?),
            "to" => to = Some(parse_addr_spec(&vals, lineno, scope == Scope::Socks)?),
            "protocol" => protocols = parse_protocols(&vals, lineno)?,
            "command" => commands = parse_commands(&vals, lineno)?,
            "method" => methods = parse_methods(&vals, lineno)?,
            "bandwidth" => {
                if scope != Scope::Socks {
                    return Err(cfg_err(lineno, "bandwidth is only valid in a socks rule"));
                }
                bandwidth = Some(parse_byte_rate_limit(&vals, lineno, "bandwidth")?);
            }
            "log" => { /* accepted for familiarity; per-rule logging is implicit */ }
            other => {
                return Err(cfg_err(
                    lineno,
                    &format!("unknown rule directive '{other}'"),
                ))
            }
        }
    }

    Ok(Rule {
        name,
        verdict,
        scope,
        from: from.unwrap_or_else(AddrSpec::any),
        to: to.unwrap_or_else(AddrSpec::any),
        commands,
        protocols,
        methods,
        bandwidth,
        source_line: lineno,
    })
}

fn parse_rule_name(tokens: &[String], lineno: usize) -> Result<Option<Arc<str>>> {
    match tokens {
        [] => Ok(None),
        [name] => {
            let name = unquote_rule_name(name, lineno)?;
            if name.is_empty() {
                return Err(cfg_err(lineno, "rule name cannot be empty"));
            }
            Ok(Some(Arc::from(name)))
        }
        _ => Err(cfg_err(
            lineno,
            "rule name must be a single token before '{'",
        )),
    }
}

fn unquote_rule_name(name: &str, lineno: usize) -> Result<String> {
    if let Some(stripped) = name.strip_prefix('"') {
        let Some(stripped) = stripped.strip_suffix('"') else {
            return Err(cfg_err(lineno, "quoted rule name is missing closing quote"));
        };
        return Ok(stripped.to_string());
    }
    if name.ends_with('"') {
        return Err(cfg_err(lineno, "quoted rule name is missing opening quote"));
    }
    Ok(name.to_string())
}

fn is_known_body_key(tok: &str) -> bool {
    matches!(
        tok.trim_end_matches(':').to_ascii_lowercase().as_str(),
        "from" | "to" | "protocol" | "command" | "method" | "bandwidth" | "log"
    )
}

fn parse_addr_spec(vals: &[String], lineno: usize, allow_hosts: bool) -> Result<AddrSpec> {
    let Some((addr, rest)) = vals.split_first() else {
        return Err(cfg_err(lineno, "address selector requires a value"));
    };

    // After the address, the only accepted continuation is `port = RANGE` (the
    // `=` is optional). Any other trailing tokens — a `ports`/typo, a word before
    // `port`, or garbage after the range — are rejected rather than silently
    // dropped: dropping the port spec would broaden the rule to match *all* ports
    // (e.g. `to: 0.0.0.0/0 ports = 443` would otherwise allow every port).
    let ports = match rest {
        [] => None,
        [kw, spec @ ..] if kw.eq_ignore_ascii_case("port") => {
            // The `=` is optional but, if present, appears exactly once right
            // after `port`. Strip that single leading `=`; any further `=` is a
            // stray token and rejected rather than silently dropped. The range
            // itself may still be split across tokens (`1024 - 2000`).
            let range_tokens = match spec {
                [eq, rest @ ..] if eq == "=" => rest,
                _ => spec,
            };
            if range_tokens.iter().any(|tok| tok == "=") {
                return Err(cfg_err(lineno, "unexpected '=' in port spec"));
            }
            let spec = range_tokens.concat();
            if spec.is_empty() {
                return Err(cfg_err(lineno, "'port' requires a range value"));
            }
            let range: PortRange = spec
                .parse()
                .map_err(|e| cfg_err(lineno, &format!("invalid port spec '{spec}': {e}")))?;
            Some(range)
        }
        _ => {
            return Err(cfg_err(
                lineno,
                &format!(
                    "expected 'ADDR' or 'ADDR port = RANGE', got unexpected tokens after '{addr}'"
                ),
            ));
        }
    };

    // The selector address is the first token: a network (CIDR or bare IP), or
    // — only for a `socks` rule `to:` — a hostname pattern such as
    // `.example.com` (domain and subdomains) or `example.com` (exact).
    match addr.parse::<Cidr>() {
        Ok(cidr) => Ok(AddrSpec::new(cidr, ports)),
        Err(cidr_err) if allow_hosts => match HostPattern::parse(addr) {
            Ok(pattern) => Ok(AddrSpec::host(pattern, ports)),
            // Neither a network nor a hostname: surface both errors so a
            // mistyped CIDR (e.g. `10.0.0.0/33`) is not mislabelled as a bad
            // hostname pattern.
            Err(host_err) => Err(cfg_err(
                lineno,
                &format!(
                    "invalid destination '{addr}': not a network ({cidr_err}) \
                     or hostname pattern ({host_err})"
                ),
            )),
        },
        Err(cidr_err) => Err(cfg_err(
            lineno,
            &format!(
                "invalid address '{addr}': {cidr_err} \
                 (hostname patterns are only allowed in a socks rule 'to:')"
            ),
        )),
    }
}

fn parse_protocols(vals: &[String], lineno: usize) -> Result<Vec<Protocol>> {
    if vals.is_empty() {
        // A present-but-empty `protocol:` would parse to an empty set, which the
        // matcher treats as "any" — silently broadening the rule. Omit the
        // directive entirely to mean "any protocol".
        return Err(cfg_err(lineno, "expected at least one protocol"));
    }
    let mut out = Vec::new();
    for v in vals {
        let p = match v.to_ascii_lowercase().as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            other => {
                return Err(cfg_err(
                    lineno,
                    &format!("unknown protocol '{other}' (expected 'tcp' or 'udp')"),
                ))
            }
        };
        if !out.contains(&p) {
            out.push(p);
        }
    }
    Ok(out)
}

fn parse_commands(vals: &[String], lineno: usize) -> Result<Vec<Command>> {
    if vals.is_empty() {
        // A present-but-empty `command:` would parse to an empty set, which the
        // matcher treats as "any" — silently broadening the rule. Omit the
        // directive entirely to mean "any command".
        return Err(cfg_err(lineno, "expected at least one command"));
    }
    let mut out = Vec::new();
    for v in vals {
        let c = match v.to_ascii_lowercase().as_str() {
            "connect" => Command::Connect,
            "bind" => Command::Bind,
            "udpassociate" | "udp" => Command::UdpAssociate,
            other => {
                return Err(cfg_err(
                    lineno,
                    &format!(
                        "unknown command '{other}' (expected 'connect', 'bind' or 'udpassociate')"
                    ),
                ))
            }
        };
        if !out.contains(&c) {
            out.push(c);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Include expansion
// ---------------------------------------------------------------------------

fn parse_include(
    vals: &[String],
    lineno: usize,
    source: &ParseSource,
    builder: &mut Builder,
    stack: &mut Vec<PathBuf>,
) -> Result<()> {
    if vals.is_empty() {
        return Err(cfg_err_at(source, lineno, "include requires a path"));
    }
    if source.base_dir.is_none() {
        return Err(cfg_err_at(
            source,
            lineno,
            "include is only supported when loading configuration from a file",
        ));
    }

    let raw_pattern = vals.join(" ");
    let pattern = resolve_include_pattern(&raw_pattern, source).map_err(|e| {
        cfg_err_at(
            source,
            lineno,
            &format!(
                "include '{raw_pattern}' failed: {}",
                config_error_message(&e)
            ),
        )
    })?;
    let include_paths = expand_include_pattern(&pattern).map_err(|e| {
        cfg_err_at(
            source,
            lineno,
            &format!("include '{raw_pattern}' failed: {e}"),
        )
    })?;

    if include_paths.is_empty() {
        return Err(cfg_err_at(
            source,
            lineno,
            &format!("include '{raw_pattern}' failed: matched no files"),
        ));
    }

    for include_path in include_paths {
        parse_config_file(&include_path, builder, stack).map_err(|e| {
            cfg_err_at(
                source,
                lineno,
                &format!(
                    "include '{}' failed: {}",
                    include_path.display(),
                    config_error_message(&e)
                ),
            )
        })?;
    }

    Ok(())
}

fn resolve_include_pattern(raw_pattern: &str, source: &ParseSource) -> Result<PathBuf> {
    let pattern = PathBuf::from(raw_pattern);
    if pattern.is_absolute() {
        return Ok(pattern);
    }

    let base = source
        .base_dir
        .clone()
        .ok_or_else(|| Error::Config("include has no base directory".into()))?;
    Ok(base.join(pattern))
}

fn expand_include_pattern(pattern: &Path) -> std::io::Result<Vec<PathBuf>> {
    if !path_has_wildcards(pattern) {
        return Ok(vec![pattern.to_path_buf()]);
    }

    let Some(file_name) = pattern.file_name() else {
        return Ok(Vec::new());
    };
    let file_pattern = file_name.to_string_lossy();
    let parent = pattern.parent().unwrap_or_else(|| Path::new("."));
    if path_has_wildcards(parent) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "wildcards are only supported in the final path component",
        ));
    }

    let mut matches = Vec::new();
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if wildcard_match(&file_pattern, &name) && entry.path().metadata()?.is_file() {
            matches.push(parent.join(entry.file_name()));
        }
    }

    matches.sort();
    Ok(matches)
}

fn path_has_wildcards(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(
            component,
            Component::Normal(value) if string_has_wildcards(&value.to_string_lossy())
        )
    })
}

fn string_has_wildcards(value: &str) -> bool {
    value.contains('*') || value.contains('?')
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    #[cfg(windows)]
    let (pattern, text) = (pattern.to_ascii_lowercase(), text.to_ascii_lowercase());
    #[cfg(not(windows))]
    let (pattern, text) = (pattern.to_string(), text.to_string());

    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let mut dp = vec![vec![false; text.len() + 1]; pattern.len() + 1];
    dp[0][0] = true;

    for i in 1..=pattern.len() {
        if pattern[i - 1] == '*' {
            dp[i][0] = dp[i - 1][0];
        }
    }

    for i in 1..=pattern.len() {
        for j in 1..=text.len() {
            dp[i][j] = match pattern[i - 1] {
                '*' => dp[i - 1][j] || dp[i][j - 1],
                '?' => dp[i - 1][j - 1],
                ch => ch == text[j - 1] && dp[i - 1][j - 1],
            };
        }
    }

    dp[pattern.len()][text.len()]
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Strips a `#` comment from a line, respecting nothing fancy (no quoting).
fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(pos) => &line[..pos],
        None => line,
    }
}

/// Joins tokens (dropping a leading `=`) and removes interior whitespace so
/// that `["=", "1024", "-", "2000"]` becomes `"1024-2000"`.
fn join_value_after(vals: &[String]) -> String {
    vals.iter()
        .filter(|v| v.as_str() != "=")
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join("")
}

fn cfg_err(lineno: usize, msg: &str) -> Error {
    Error::Config(format!("line {lineno}: {msg}"))
}

fn cfg_err_at(source: &ParseSource, lineno: usize, msg: &str) -> Error {
    match &source.display {
        Some(display) => Error::Config(format!("{display}:line {lineno}: {msg}")),
        None => cfg_err(lineno, msg),
    }
}

fn with_source_context(err: Error, source: &ParseSource) -> Error {
    let Some(display) = &source.display else {
        return err;
    };

    match err {
        Error::Config(msg) if msg.starts_with("line ") => Error::Config(format!("{display}:{msg}")),
        other => other,
    }
}

fn config_error_message(err: &Error) -> String {
    match err {
        Error::Config(msg) => msg.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> &'static str {
        r#"
# Alighieri sample
internal: 0.0.0.0 port = 1080
external: 0.0.0.0
socksmethod: none
connecttimeout: 15
handshaketimeout: 7
udptimeout: 90
maxconnections: 256
logoutput: stdout stderr
logformat: json
logrotate.size: 2MiB
logrotate.keep: 3
dns.prefer: ipv6
dns.tryall: yes
dns.deny: private linklocal loopback
dns.cachettl: 30
auth.cachettl: 120
metrics.listen: 127.0.0.1:9090
tls.certfile: /etc/alighieri/tls/server.crt
tls.keyfile: /etc/alighieri/tls/server.key
ratelimit.connectionrate: 60/60
ratelimit.authfailurerate: 5/300
ratelimit.concurrentconnections: 10
ratelimit.byterate: 10MiB/60

client pass {
    from: 10.0.0.0/8 to: 0.0.0.0/0
}

socks block {
    from: 0.0.0.0/0 to: 127.0.0.0/8
}

socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    protocol: tcp udp
    command: connect udpassociate
}
"#
    }

    #[test]
    fn parse_full_sample() {
        let cfg = Config::parse(sample()).unwrap();
        assert_eq!(cfg.internal, "0.0.0.0:1080".parse().unwrap());
        assert_eq!(cfg.external, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(cfg.socks_methods, vec![AuthKind::None]);
        assert_eq!(cfg.connect_timeout, Duration::from_secs(15));
        assert_eq!(cfg.handshake_timeout, Duration::from_secs(7));
        assert_eq!(cfg.udp_timeout, Duration::from_secs(90));
        assert_eq!(cfg.max_connections, 256);
        assert_eq!(cfg.log_outputs, vec![LogOutput::Stdout, LogOutput::Stderr]);
        assert_eq!(cfg.log_format, LogFormat::Json);
        assert_eq!(cfg.log_rotate_size, 2 * 1024 * 1024);
        assert_eq!(cfg.log_rotate_keep, 3);
        assert_eq!(cfg.dns.preference, DnsPreference::Ipv6);
        assert!(cfg.dns.try_all);
        assert_eq!(
            cfg.dns.deny,
            vec![
                DnsDenyCategory::Private,
                DnsDenyCategory::LinkLocal,
                DnsDenyCategory::Loopback
            ]
        );
        assert_eq!(cfg.dns.cache_ttl, Some(Duration::from_secs(30)));
        assert_eq!(cfg.auth_cache_ttl, Some(Duration::from_secs(120)));
        assert_eq!(cfg.metrics_listen, Some("127.0.0.1:9090".parse().unwrap()));
        assert_eq!(
            cfg.tls,
            Some(TlsConfig::Files {
                cert_file: PathBuf::from("/etc/alighieri/tls/server.crt"),
                key_file: PathBuf::from("/etc/alighieri/tls/server.key")
            })
        );
        assert_eq!(
            cfg.rate_limits.connection_rate,
            Some(RateLimit {
                limit: 60,
                window: Duration::from_secs(60)
            })
        );
        assert_eq!(
            cfg.rate_limits.auth_failure_rate,
            Some(RateLimit {
                limit: 5,
                window: Duration::from_secs(300)
            })
        );
        assert_eq!(cfg.rate_limits.concurrent_connections, Some(10));
        assert_eq!(
            cfg.rate_limits.byte_rate,
            Some(RateLimit {
                limit: 10 * 1024 * 1024,
                window: Duration::from_secs(60)
            })
        );
        assert_eq!(cfg.rules.rules.len(), 3);
    }

    #[test]
    fn defaults_applied() {
        let cfg = Config::parse("internal: 127.0.0.1 port = 1080").unwrap();
        assert_eq!(cfg.external, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(cfg.socks_methods, vec![AuthKind::None]);
        assert_eq!(cfg.connect_timeout, Duration::from_secs(30));
        assert_eq!(cfg.handshake_timeout, Duration::from_secs(10));
        assert_eq!(cfg.io_timeout, Duration::ZERO);
        assert_eq!(cfg.udp_timeout, Duration::from_secs(60));
        assert_eq!(cfg.max_connections, 1024);
        assert_eq!(cfg.log_outputs, vec![LogOutput::Stdout]);
        assert_eq!(cfg.log_file, None);
        assert_eq!(cfg.log_format, LogFormat::Text);
        assert_eq!(cfg.log_rotate_size, DEFAULT_LOG_ROTATE_SIZE_BYTES);
        assert_eq!(cfg.log_rotate_keep, DEFAULT_LOG_ROTATE_KEEP);
        assert_eq!(cfg.dns.preference, DnsPreference::System);
        assert!(!cfg.dns.try_all);
        assert!(cfg.dns.deny.is_empty());
        assert_eq!(cfg.dns.cache_ttl, None);
        assert_eq!(
            cfg.auth_cache_ttl,
            Some(Duration::from_secs(DEFAULT_AUTH_CACHE_TTL_SECS))
        );
        assert_eq!(cfg.metrics_listen, None);
        assert_eq!(cfg.tls, None);
        assert_eq!(cfg.rate_limits, RateLimits::default());
    }

    #[test]
    fn tls_requires_cert_and_key() {
        let err = Config::parse("internal: 127.0.0.1:1080\ntls.certfile: server.crt").unwrap_err();
        assert!(err.to_string().contains("tls.certfile requires"));

        let err = Config::parse("internal: 127.0.0.1:1080\ntls.keyfile: server.key").unwrap_err();
        assert!(err.to_string().contains("tls.keyfile requires"));
    }

    #[test]
    fn acme_tls_parses() {
        let cfg = Config::parse(
            r#"
internal: 0.0.0.0:443
tls.acme.domains: a.example.com b.example.com
tls.acme.email: admin@example.com
tls.acme.cache: /var/lib/alighieri/acme
tls.acme.staging: on
"#,
        )
        .unwrap();
        assert_eq!(
            cfg.tls,
            Some(TlsConfig::Acme(AcmeConfig {
                domains: vec!["a.example.com".into(), "b.example.com".into()],
                email: Some("admin@example.com".into()),
                cache_dir: PathBuf::from("/var/lib/alighieri/acme"),
                staging: true,
            }))
        );
    }

    #[test]
    fn acme_email_rejects_multiple_addresses() {
        let err = Config::parse(
            "internal: 0.0.0.0:443\ntls.acme.domains: x.example.com\ntls.acme.cache: /tmp/acme\ntls.acme.email: a@example.com b@example.com",
        )
        .unwrap_err();
        assert!(err.to_string().contains("single address"), "got: {err}");
    }

    #[test]
    fn acme_and_certfile_are_mutually_exclusive() {
        let err = Config::parse(
            "internal: 0.0.0.0:443\ntls.acme.domains: x.example.com\ntls.acme.cache: /tmp/acme\ntls.certfile: server.crt\ntls.keyfile: server.key",
        )
        .unwrap_err();
        assert!(err.to_string().contains("cannot use both"), "got: {err}");
    }

    #[test]
    fn acme_requires_a_cache_dir() {
        let err =
            Config::parse("internal: 0.0.0.0:443\ntls.acme.domains: x.example.com").unwrap_err();
        assert!(err.to_string().contains("tls.acme.cache"), "got: {err}");
    }

    #[test]
    fn parses_rate_limit_aliases() {
        let cfg = Config::parse(
            r#"
internal: 127.0.0.1:1080
ratelimit.connection.rate: 2/10
ratelimit.auth.failure.rate: 3/20
ratelimit.concurrent: 4
ratelimit.bytes: 64KiB/30
"#,
        )
        .unwrap();

        assert_eq!(
            cfg.rate_limits.connection_rate,
            Some(RateLimit {
                limit: 2,
                window: Duration::from_secs(10)
            })
        );
        assert_eq!(
            cfg.rate_limits.auth_failure_rate,
            Some(RateLimit {
                limit: 3,
                window: Duration::from_secs(20)
            })
        );
        assert_eq!(cfg.rate_limits.concurrent_connections, Some(4));
        assert_eq!(
            cfg.rate_limits.byte_rate,
            Some(RateLimit {
                limit: 64 * 1024,
                window: Duration::from_secs(30)
            })
        );
    }

    #[test]
    fn rejects_invalid_rate_limits() {
        let err =
            Config::parse("internal: 127.0.0.1:1080\nratelimit.connectionrate: 1").unwrap_err();
        assert!(err.to_string().contains("LIMIT/WINDOW_SECONDS"));

        let err = Config::parse("internal: 127.0.0.1:1080\nratelimit.byterate: 0/60").unwrap_err();
        assert!(err.to_string().contains("values must be > 0"));

        let err = Config::parse("internal: 127.0.0.1:1080\nratelimit.concurrentconnections: 0")
            .unwrap_err();
        assert!(err.to_string().contains("must be > 0"));
    }

    #[test]
    fn logfile_implies_file_output() {
        let cfg =
            Config::parse("internal: 127.0.0.1:1080\nlogfile: /var/log/alighieri/alighieri.log")
                .unwrap();
        assert_eq!(cfg.log_outputs, vec![LogOutput::Stdout, LogOutput::File]);
        assert_eq!(
            cfg.log_file,
            Some(PathBuf::from("/var/log/alighieri/alighieri.log"))
        );
    }

    #[test]
    fn file_output_requires_logfile() {
        let err = Config::parse("internal: 127.0.0.1:1080\nlogoutput: file").unwrap_err();
        assert!(err.to_string().contains("requires a 'logfile'"));
    }

    #[test]
    fn parses_log_rotation_size_suffixes() {
        let cfg =
            Config::parse("internal: 127.0.0.1:1080\nlogrotate.size: 10MiB\nlogrotate.keep: 0")
                .unwrap();
        assert_eq!(cfg.log_rotate_size, 10 * 1024 * 1024);
        assert_eq!(cfg.log_rotate_keep, 0);
    }

    #[test]
    fn parses_dns_policy_aliases() {
        let cfg = Config::parse(
            "internal: 127.0.0.1:1080\ndnsprefer: v4\ndnstryall: on\ndnsdeny: reserved doc\ndnscachettl: 45",
        )
        .unwrap();
        assert_eq!(cfg.dns.preference, DnsPreference::Ipv4);
        assert!(cfg.dns.try_all);
        assert_eq!(
            cfg.dns.deny,
            vec![DnsDenyCategory::Reserved, DnsDenyCategory::Documentation]
        );
        assert_eq!(cfg.dns.cache_ttl, Some(Duration::from_secs(45)));
    }

    #[test]
    fn parses_disabled_dns_cache_ttl() {
        let cfg = Config::parse("internal: 127.0.0.1:1080\ndns.cache.ttl: off").unwrap();
        assert_eq!(cfg.dns.cache_ttl, None);

        let cfg = Config::parse("internal: 127.0.0.1:1080\ndns.cachettl: 0").unwrap();
        assert_eq!(cfg.dns.cache_ttl, None);
    }

    #[test]
    fn parses_dns_timeout_and_rejects_zero() {
        let cfg = Config::parse("internal: 127.0.0.1:1080\ndns.timeout: 3").unwrap();
        assert_eq!(cfg.dns.timeout, Duration::from_secs(3));

        // Unset falls back to the default.
        let cfg = Config::parse("internal: 127.0.0.1:1080").unwrap();
        assert_eq!(cfg.dns.timeout, Duration::from_secs(5));

        // Zero is rejected — it would time out every name resolution.
        let err = Config::parse("internal: 127.0.0.1:1080\ndns.timeout: 0").unwrap_err();
        assert!(format!("{err}").contains("dns.timeout"), "{err}");

        // An absurd value is rejected so it cannot overflow the timer deadline.
        let err = Config::parse("internal: 127.0.0.1:1080\ndns.timeout: 100000").unwrap_err();
        assert!(format!("{err}").contains("dns.timeout"), "{err}");
        // The upper bound itself is accepted.
        let cfg = Config::parse("internal: 127.0.0.1:1080\ndns.timeout: 3600").unwrap();
        assert_eq!(cfg.dns.timeout, Duration::from_secs(3600));
    }

    #[test]
    fn rejects_zero_connect_and_handshake_timeout() {
        // Zero would make tokio::time::timeout expire immediately and fail every
        // connection, so it is rejected rather than silently accepted.
        let err = Config::parse("internal: 127.0.0.1:1080\nconnecttimeout: 0").unwrap_err();
        assert!(format!("{err}").contains("connecttimeout"), "{err}");
        let err = Config::parse("internal: 127.0.0.1:1080\nhandshaketimeout: 0").unwrap_err();
        assert!(format!("{err}").contains("handshaketimeout"), "{err}");

        // Positive values parse, and `iotimeout: 0` (a genuine "disabled" idle
        // timeout) is still accepted.
        let cfg = Config::parse(
            "internal: 127.0.0.1:1080\nconnecttimeout: 5\nhandshaketimeout: 3\niotimeout: 0",
        )
        .unwrap();
        assert_eq!(cfg.connect_timeout, Duration::from_secs(5));
        assert_eq!(cfg.handshake_timeout, Duration::from_secs(3));
        assert_eq!(cfg.io_timeout, Duration::ZERO);
    }

    #[test]
    fn rejects_trailing_tokens_on_scalar_settings() {
        // A trailing token on a scalar setting is a typo, not silently ignored.
        assert!(Config::parse("internal: 127.0.0.1:1080\nmaxconnections: 100 oops").is_err());
        assert!(Config::parse("internal: 127.0.0.1:1080\ndns.tryall: yes maybe").is_err());
        // Endpoint: tokens before `port`, or after a bare `IP:PORT`.
        assert!(Config::parse("internal: 127.0.0.1 oops port = 1080").is_err());
        assert!(Config::parse("internal: 127.0.0.1:1080 oops").is_err());
        // Endpoint: split or trailing tokens after `port` must not be joined into
        // a single port (e.g. `port = 10 80` -> 1080); a lone `port =` (no value)
        // is rejected directly rather than as an empty port string.
        assert!(Config::parse("internal: 127.0.0.1 port = 10 80").is_err());
        assert!(Config::parse("internal: 127.0.0.1 port = 1080 =").is_err());
        assert!(Config::parse("internal: 127.0.0.1 port =").is_err());
        // The keyword form is exactly `port = N`; a `=`-less `port N` is rejected.
        assert!(Config::parse("internal: 127.0.0.1 port 1080").is_err());
        // The documented `IP port = N` and bare `IP:PORT` forms still parse.
        assert!(Config::parse("internal: 127.0.0.1 port = 1080").is_ok());
        assert!(Config::parse("internal: 127.0.0.1:1080").is_ok());
        assert!(
            Config::parse("internal: 127.0.0.1:1080\nmaxconnections: 100\ndns.tryall: yes").is_ok()
        );
    }

    #[test]
    fn rejects_trailing_tokens_on_value_settings() {
        // Scalar value parsers (IP, enum keywords, the cache-ttl keyword, usize)
        // reject extra tokens instead of silently using only the first.
        assert!(Config::parse("internal: 127.0.0.1:1080\nexternal: 0.0.0.0 oops").is_err());
        assert!(Config::parse("internal: 127.0.0.1:1080\nlogformat: json text").is_err());
        assert!(Config::parse("internal: 127.0.0.1:1080\ndns.prefer: ipv4 oops").is_err());
        assert!(Config::parse("internal: 127.0.0.1:1080\ndns.cachettl: off oops").is_err());
        assert!(Config::parse("internal: 127.0.0.1:1080\nauth.cachettl: none oops").is_err());
        assert!(Config::parse("internal: 127.0.0.1:1080\nlogrotate.keep: 5 oops").is_err());
        // The valid single-value forms still parse.
        assert!(Config::parse("internal: 127.0.0.1:1080\nexternal: 0.0.0.0").is_ok());
        assert!(Config::parse("internal: 127.0.0.1:1080\nlogformat: json").is_ok());
        assert!(Config::parse("internal: 127.0.0.1:1080\ndns.prefer: ipv4").is_ok());
        assert!(Config::parse("internal: 127.0.0.1:1080\ndns.cachettl: off").is_ok());
        assert!(Config::parse("internal: 127.0.0.1:1080\ndns.cachettl: 60").is_ok());
        assert!(Config::parse("internal: 127.0.0.1:1080\nlogrotate.keep: 5").is_ok());
    }

    #[test]
    fn rejects_out_of_range_numeric_limits() {
        // maxconnections above the connection-limiter maximum is rejected — it
        // would otherwise panic `Semaphore::new` at startup.
        assert!(
            Config::parse("internal: 127.0.0.1:1080\nmaxconnections: 18446744073709551615")
                .is_err()
        );
        // logrotate.keep above the practical maximum is rejected — it drives an
        // O(n) rename loop on each rotation.
        assert!(Config::parse("internal: 127.0.0.1:1080\nlogrotate.keep: 10001").is_err());
        // Generous-but-bounded values still parse.
        assert!(Config::parse("internal: 127.0.0.1:1080\nmaxconnections: 1000000").is_ok());
        assert!(Config::parse("internal: 127.0.0.1:1080\nlogrotate.keep: 10000").is_ok());
    }

    #[test]
    fn parses_disabled_auth_cache_ttl() {
        let cfg = Config::parse("internal: 127.0.0.1:1080\nauth.cachettl: off").unwrap();
        assert_eq!(cfg.auth_cache_ttl, None);

        let cfg = Config::parse("internal: 127.0.0.1:1080\nauth.cache.ttl: 0").unwrap();
        assert_eq!(cfg.auth_cache_ttl, None);
    }

    #[test]
    fn missing_dns_cache_ttl_mentions_disabled_values() {
        let err = Config::parse("internal: 127.0.0.1:1080\ndns.cachettl:").unwrap_err();
        let message = err.to_string();

        assert!(message.contains("0"));
        assert!(message.contains("off"));
        assert!(message.contains("none"));
        assert!(message.contains("disabled"));
    }

    #[test]
    fn rejects_unknown_dns_preference() {
        let err = Config::parse("internal: 127.0.0.1:1080\ndns.prefer: ipv10").unwrap_err();
        assert!(err.to_string().contains("unsupported dns.prefer"));
    }

    #[test]
    fn internal_required() {
        let err = Config::parse("external: 0.0.0.0").unwrap_err();
        assert!(err
            .to_string()
            .contains("missing required setting: internal"));
    }

    #[test]
    fn internal_ip_port_colon_form() {
        let cfg = Config::parse("internal: 0.0.0.0:1080").unwrap();
        assert_eq!(cfg.internal, "0.0.0.0:1080".parse().unwrap());
    }

    #[test]
    fn username_requires_userlist() {
        let err =
            Config::parse("internal: 0.0.0.0 port = 1080\nsocksmethod: username").unwrap_err();
        assert!(err.to_string().contains("requires a 'userlist'"));
    }

    #[test]
    fn username_with_userlist_ok() {
        let cfg = Config::parse(
            "internal: 0.0.0.0 port = 1080\nsocksmethod: username none\nuserlist: /tmp/users",
        )
        .unwrap();
        assert_eq!(cfg.socks_methods, vec![AuthKind::Username, AuthKind::None]);
        assert_eq!(cfg.userlist, Some(PathBuf::from("/tmp/users")));
    }

    #[test]
    fn metrics_public_bind_requires_allowpublic() {
        let head = "internal: 127.0.0.1 port = 1080\n";

        // The rule is a startup-only validation, not a parse error (so a reload
        // that touches the non-reloadable metrics settings does not fail).
        // Loopback — including IPv4-mapped — is always allowed.
        for addr in ["127.0.0.1:9090", "[::1]:9090", "[::ffff:127.0.0.1]:9090"] {
            let cfg = Config::parse(&format!("{head}metrics.listen: {addr}")).unwrap();
            assert!(!cfg.metrics_allow_public);
            cfg.validate_startup()
                .unwrap_or_else(|e| panic!("{addr} should be allowed: {e}"));
        }

        // A non-loopback or unspecified bind parses but is refused at startup
        // without the opt-in.
        for addr in ["0.0.0.0:9090", "192.168.1.5:9090", "[::]:9090"] {
            let cfg = Config::parse(&format!("{head}metrics.listen: {addr}")).unwrap();
            let err = cfg.validate_startup().unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("metrics.allowpublic"), "{addr}: {err}");
            // The message uses a `\` line continuation, which strips the next
            // line's indentation — guard against it leaking a run of spaces.
            assert!(!msg.contains("  "), "message has stray spacing: {msg}");
        }

        // With the explicit opt-in it passes startup validation.
        let cfg = Config::parse(&format!(
            "{head}metrics.listen: 0.0.0.0:9090\nmetrics.allowpublic: true"
        ))
        .unwrap();
        assert!(cfg.metrics_allow_public);
        assert_eq!(cfg.metrics_listen, Some("0.0.0.0:9090".parse().unwrap()));
        cfg.validate_startup().unwrap();

        // The concatenated alias parses too (set to the non-default value).
        let cfg = Config::parse(&format!(
            "{head}metrics.listen: 127.0.0.1:9090\nmetricsallowpublic: true"
        ))
        .unwrap();
        assert!(cfg.metrics_allow_public);
    }

    #[test]
    fn flags_noauth_on_a_non_loopback_listener() {
        let flagged = |cfg: &str| {
            Config::parse(cfg)
                .unwrap()
                .noauth_on_non_loopback_listener()
        };

        // No-auth (the default) on a non-loopback listener is flagged.
        assert!(flagged("internal: 0.0.0.0 port = 1080"));
        assert!(flagged("internal: 192.168.1.5 port = 1080"));
        // Loopback listeners — including IPv6 and IPv4-mapped — are not flagged.
        assert!(!flagged("internal: 127.0.0.1 port = 1080"));
        assert!(!flagged("internal: ::1 port = 1080"));
        assert!(!flagged("internal: ::ffff:127.0.0.1 port = 1080"));
        // Username-only auth on a non-loopback listener is not flagged.
        assert!(!flagged(
            "internal: 0.0.0.0 port = 1080\nsocksmethod: username\nuserlist: /tmp/users"
        ));
        // Offering 'none' alongside 'username' still flags it: a client can pick none.
        assert!(flagged(
            "internal: 0.0.0.0 port = 1080\nsocksmethod: username none\nuserlist: /tmp/users"
        ));
    }

    #[test]
    fn rule_with_port_range() {
        let cfg = Config::parse(
            r#"internal: 0.0.0.0 port = 1080
socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0 port = 1024 - 2000
    command: connect
}"#,
        )
        .unwrap();
        let rule = &cfg.rules.rules[0];
        assert_eq!(
            rule.to.ports,
            Some(PortRange {
                min: 1024,
                max: 2000
            })
        );
        assert_eq!(rule.commands, vec![Command::Connect]);
    }

    #[test]
    fn socks_rule_bandwidth_parses() {
        let cfg = Config::parse(
            r#"internal: 0.0.0.0 port = 1080
socks pass {
    to: 0.0.0.0/0
    command: connect
    bandwidth: 5MiB/2
}"#,
        )
        .unwrap();
        assert_eq!(
            cfg.rules.rules[0].bandwidth,
            Some(RateLimit {
                limit: 5 * 1024 * 1024,
                window: Duration::from_secs(2),
            })
        );
    }

    #[test]
    fn bandwidth_on_client_rule_is_rejected() {
        let err = Config::parse(
            "internal: 0.0.0.0 port = 1080\nclient pass { from: 0.0.0.0/0 bandwidth: 1MiB/1 }",
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("bandwidth is only valid in a socks rule"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rule_single_port() {
        let cfg = Config::parse(
            r#"internal: 0.0.0.0 port = 1080
socks pass {
    to: 0.0.0.0/0 port = 443
}"#,
        )
        .unwrap();
        assert_eq!(
            cfg.rules.rules[0].to.ports,
            Some(PortRange { min: 443, max: 443 })
        );
    }

    #[test]
    fn socks_to_accepts_hostname_patterns() {
        let cfg = Config::parse("internal: 0.0.0.0 port = 1080\nsocks pass { to: .example.com }")
            .unwrap();
        let to = &cfg.rules.rules[0].to;
        assert_eq!(to.hosts, vec![HostPattern::Suffix("example.com".into())]);
        assert!(to.cidrs.is_empty());

        let cfg = Config::parse(
            "internal: 0.0.0.0 port = 1080\nsocks pass { to: api.example.com port 443 }",
        )
        .unwrap();
        let to = &cfg.rules.rules[0].to;
        assert_eq!(to.hosts, vec![HostPattern::Exact("api.example.com".into())]);
        assert_eq!(to.ports, Some(PortRange { min: 443, max: 443 }));
    }

    #[test]
    fn address_selectors_reject_stray_tokens() {
        let base = "internal: 0.0.0.0 port = 1080\n";
        let parse = |rule: &str| Config::parse(&format!("{base}{rule}"));

        // A `port` typo or stray token must not be silently dropped: dropping the
        // port spec would broaden the rule to match *all* ports.
        assert!(parse("socks pass { to: 0.0.0.0/0 ports = 443 }").is_err());
        assert!(parse("socks pass { to: 0.0.0.0/0 oops port = 443 }").is_err());
        assert!(parse("socks pass { to: 0.0.0.0/0 port = 443 oops }").is_err());
        assert!(parse("socks pass { to: 0.0.0.0/0 oops }").is_err());
        assert!(parse("socks pass { from: 10.0.0.0/8 oops }").is_err());
        // A stray `=` is a token too: it is not silently filtered out.
        assert!(parse("socks pass { to: 0.0.0.0/0 port = 443 = }").is_err());
        assert!(parse("socks pass { to: 0.0.0.0/0 port = = 443 }").is_err());
        // The documented forms still parse (the `=` is optional; ranges allowed).
        assert!(parse("socks pass { to: 0.0.0.0/0 port = 443 }").is_ok());
        assert!(parse("socks pass { to: 0.0.0.0/0 port 443 }").is_ok());
        assert!(parse("socks pass { to: 0.0.0.0/0 port = 1024 - 2000 }").is_ok());
        assert!(parse("socks pass { to: 0.0.0.0/0 }").is_ok());
    }

    #[test]
    fn hostname_patterns_rejected_outside_socks_to() {
        // `from:` is IP-only (source-hostname matching is unsupported).
        assert!(Config::parse(
            "internal: 0.0.0.0 port = 1080\nsocks pass { from: .example.com to: 0.0.0.0/0 }"
        )
        .is_err());
        // A `client` rule `to:` is the proxy's own address — an IP, not a host.
        assert!(Config::parse(
            "internal: 0.0.0.0 port = 1080\nclient pass { from: 0.0.0.0/0 to: .example.com }"
        )
        .is_err());
    }

    #[test]
    fn socks_to_mistyped_cidr_reports_network_error() {
        // A bad CIDR in a socks `to:` must not be mislabelled as a bad hostname;
        // the error should mention the network failure too.
        let err = Config::parse("internal: 0.0.0.0 port = 1080\nsocks pass { to: 10.0.0.0/33 }")
            .unwrap_err();
        assert!(err.to_string().contains("not a network"), "got: {err}");
    }

    #[test]
    fn rule_defaults_to_any() {
        let cfg = Config::parse(
            r#"internal: 0.0.0.0 port = 1080
socks pass { command: connect }"#,
        )
        .unwrap();
        let rule = &cfg.rules.rules[0];
        assert!(rule.from.matches("8.8.8.8".parse().unwrap(), 443));
        assert!(rule.from.matches("2001:db8::1".parse().unwrap(), 443));
        assert!(rule.to.matches("8.8.8.8".parse().unwrap(), 443));
        assert!(rule.to.matches("2001:db8::1".parse().unwrap(), 443));
    }

    #[test]
    fn parses_named_rules() {
        let cfg = Config::parse(
            r#"internal: 0.0.0.0 port = 1080
client pass "lan-clients" { from: 10.0.0.0/8 }
socks block blocked-loopback { to: 127.0.0.0/8 }"#,
        )
        .unwrap();

        assert_eq!(cfg.rules.rules[0].name.as_deref(), Some("lan-clients"));
        assert_eq!(cfg.rules.rules[1].name.as_deref(), Some("blocked-loopback"));
    }

    #[test]
    fn rejects_invalid_rule_names() {
        let err = Config::parse(
            r#"internal: 0.0.0.0 port = 1080
socks pass "allow web" { command: connect }"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("single token"));

        let err = Config::parse(
            r#"internal: 0.0.0.0 port = 1080
socks pass "" { command: connect }"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("cannot be empty"));
    }

    #[test]
    fn unknown_keyword_rejected() {
        let err = Config::parse("internal: 0.0.0.0 port = 1080\nbogus: 1").unwrap_err();
        assert!(err.to_string().contains("unknown keyword 'bogus'"));
    }

    #[test]
    fn udp_port_range_parses_with_default_none() {
        let cfg = Config::parse("internal: 0.0.0.0 port = 1080").unwrap();
        assert_eq!(cfg.udp_port_range, None);

        let cfg =
            Config::parse("internal: 0.0.0.0 port = 1080\nudp.portrange: 20000-21000").unwrap();
        assert_eq!(
            cfg.udp_port_range,
            Some(PortRange {
                min: 20000,
                max: 21000
            })
        );

        // The concatenated alias and the single-port form both work.
        let cfg = Config::parse("internal: 0.0.0.0 port = 1080\nudpportrange: 30000").unwrap();
        assert_eq!(
            cfg.udp_port_range,
            Some(PortRange {
                min: 30000,
                max: 30000
            })
        );
    }

    #[test]
    fn udp_strict_reply_parses_and_defaults_on() {
        let cfg = Config::parse("internal: 0.0.0.0 port = 1080").unwrap();
        assert!(
            cfg.udp_strict_reply,
            "defaults to strict host:port matching"
        );

        // Set `false` (not the default) so the assertion actually proves the key
        // was parsed rather than falling back to the default.
        let cfg = Config::parse("internal: 0.0.0.0 port = 1080\nudp.strictreply: false").unwrap();
        assert!(!cfg.udp_strict_reply);

        // The concatenated alias works too — again with the non-default value.
        let cfg = Config::parse("internal: 0.0.0.0 port = 1080\nudpstrictreply: false").unwrap();
        assert!(!cfg.udp_strict_reply);

        // A non-boolean value is rejected like other booleans.
        assert!(Config::parse("internal: 0.0.0.0 port = 1080\nudp.strictreply: maybe").is_err());
    }

    #[test]
    fn udp_advertise_parses_an_ip() {
        let cfg =
            Config::parse("internal: 0.0.0.0 port = 1080\nudp.advertise: 203.0.113.5").unwrap();
        assert_eq!(
            cfg.udp_advertise,
            Some(UdpAdvertise::Ip("203.0.113.5".parse().unwrap()))
        );

        let cfg =
            Config::parse("internal: 0.0.0.0 port = 1080\nudp.advertise: 2001:db8::1").unwrap();
        assert_eq!(
            cfg.udp_advertise,
            Some(UdpAdvertise::Ip("2001:db8::1".parse().unwrap()))
        );

        // Unset by default.
        assert!(Config::parse("internal: 0.0.0.0 port = 1080")
            .unwrap()
            .udp_advertise
            .is_none());
    }

    #[test]
    fn udp_advertise_parses_a_hostname_without_resolving() {
        // A non-IP value is kept as a hostname and resolved per association, not
        // at config load — so a bad or wedged resolver never affects parsing.
        let cfg = Config::parse(
            "internal: 0.0.0.0 port = 1080\nudp.advertise: nonexistent.invalid.example",
        )
        .unwrap();
        assert_eq!(
            cfg.udp_advertise,
            Some(UdpAdvertise::Host("nonexistent.invalid.example".into()))
        );
    }

    #[test]
    fn udp_advertise_rejects_empty_and_trailing() {
        assert!(Config::parse("internal: 0.0.0.0 port = 1080\nudp.advertise:").is_err());
        // Trailing token is rejected at parse time.
        assert!(
            Config::parse("internal: 0.0.0.0 port = 1080\nudp.advertise: 203.0.113.5 extra")
                .is_err()
        );
    }

    #[test]
    fn udp_advertise_rejects_malformed_hostname() {
        // A non-IP advertise value is a hostname; a structurally malformed one
        // must be caught at config load, not silently fall back at runtime. (Each
        // is a single token reaching the validator; a space-separated value is
        // instead rejected earlier as multiple tokens.)
        let oversize = format!("{}.com", "a".repeat(64));
        for bad in ["foo..bar", ".", oversize.as_str()] {
            let src = format!("internal: 0.0.0.0 port = 1080\nudp.advertise: {bad}");
            let err = Config::parse(&src).unwrap_err().to_string();
            assert!(
                err.contains("invalid udp.advertise host"),
                "expected a host-validation error for {bad:?}, got: {err}"
            );
        }
        // A normal hostname (and an IP) are still accepted.
        assert!(
            Config::parse("internal: 0.0.0.0 port = 1080\nudp.advertise: relay.example.com")
                .is_ok()
        );
        assert!(Config::parse("internal: 0.0.0.0 port = 1080\nudp.advertise: 203.0.113.5").is_ok());
    }

    #[test]
    fn acme_domains_reject_malformed_entries() {
        // Every tls.acme.domains entry is validated during parsing, so a name that
        // is malformed (foo..bar/.) or that a CA cannot issue for via TLS-ALPN-01
        // (wildcard, underscore, single-label, IP) fails --check rather than
        // reaching the ACME stack.
        for bad in [
            "foo..bar",
            ".",
            "*.example.com",
            "_svc.example.com",
            "localhost",
            "127.0.0.1",
        ] {
            let src = format!("internal: 0.0.0.0 port = 1080\ntls.acme.domains: {bad}");
            let err = Config::parse(&src).unwrap_err().to_string();
            assert!(
                err.contains("invalid tls.acme.domains entry"),
                "expected a host-validation error for {bad:?}, got: {err}"
            );
        }
        // (Acceptance of a valid issuable name is covered by net::validate_acme_domain
        // tests; a full ACME config needs more fields than this unit asserts.)
    }

    #[test]
    fn shutdown_drain_timeout_parses_and_defaults() {
        let cfg = Config::parse("internal: 0.0.0.0 port = 1080").unwrap();
        assert_eq!(cfg.shutdown_drain_timeout, Duration::from_secs(10));

        let cfg =
            Config::parse("internal: 0.0.0.0 port = 1080\nshutdown.draintimeout: 30").unwrap();
        assert_eq!(cfg.shutdown_drain_timeout, Duration::from_secs(30));

        // `0` is allowed (cut in-flight connections immediately); alias parses.
        let cfg = Config::parse("internal: 0.0.0.0 port = 1080\nshutdowndraintimeout: 0").unwrap();
        assert_eq!(cfg.shutdown_drain_timeout, Duration::ZERO);

        // A non-numeric value is rejected.
        assert!(
            Config::parse("internal: 0.0.0.0 port = 1080\nshutdown.draintimeout: soon").is_err()
        );

        // A value over the cap is rejected (it would overflow the timer deadline).
        let err = Config::parse("internal: 0.0.0.0 port = 1080\nshutdown.draintimeout: 3601")
            .unwrap_err();
        assert!(err.to_string().contains("cannot exceed"), "{err}");
    }

    #[test]
    fn udp_port_range_rejects_invalid() {
        for bad in [
            "udp.portrange:",             // missing value
            "udp.portrange: 0-100",       // includes the ephemeral sentinel 0
            "udp.portrange: 21000-20000", // min > max
            "udp.portrange: nope",        // not a number
        ] {
            let src = format!("internal: 0.0.0.0 port = 1080\n{bad}");
            assert!(Config::parse(&src).is_err(), "expected error for: {bad}");
        }
    }

    #[test]
    fn proxyprotocol_parses_trusted_cidrs() {
        let cfg = Config::parse(
            "internal: 0.0.0.0 port = 1080\nproxyprotocol: 10.0.0.0/8 192.168.0.0/16",
        )
        .unwrap();
        assert_eq!(cfg.proxy_protocol.len(), 2);
        assert!(cfg.proxy_protocol[0].contains("10.1.2.3".parse().unwrap()));
        assert!(cfg.proxy_protocol[1].contains("192.168.5.5".parse().unwrap()));

        // Disabled by default.
        let cfg = Config::parse("internal: 0.0.0.0 port = 1080").unwrap();
        assert!(cfg.proxy_protocol.is_empty());
    }

    #[test]
    fn proxyprotocol_rejects_empty_or_invalid() {
        assert!(Config::parse("internal: 0.0.0.0 port = 1080\nproxyprotocol:").is_err());
        assert!(Config::parse("internal: 0.0.0.0 port = 1080\nproxyprotocol: not-a-cidr").is_err());
    }

    #[test]
    fn auth_command_parses_program_and_args() {
        let cfg = Config::parse(
            "internal: 0.0.0.0 port = 1080\nauth.command: /usr/local/bin/verify --ldap",
        )
        .unwrap();
        assert_eq!(
            cfg.auth_command.as_deref(),
            Some(["/usr/local/bin/verify".to_string(), "--ldap".to_string()].as_slice())
        );

        // Disabled by default.
        assert!(Config::parse("internal: 0.0.0.0 port = 1080")
            .unwrap()
            .auth_command
            .is_none());

        // A program path is required.
        assert!(Config::parse("internal: 0.0.0.0 port = 1080\nauth.command:").is_err());

        // The `username` method is satisfied by auth.command without a userlist.
        assert!(Config::parse(
            "internal: 0.0.0.0 port = 1080\nsocksmethod: username\nauth.command: /bin/true"
        )
        .is_ok());
    }

    #[test]
    fn unterminated_block_rejected() {
        let err = Config::parse("internal: 0.0.0.0 port = 1080\nsocks pass {\n from: 0.0.0.0/0")
            .unwrap_err();
        assert!(err.to_string().contains("unterminated"));
    }

    #[test]
    fn rejects_tokens_after_closing_brace() {
        let head = "internal: 0.0.0.0 port = 1080\n";

        // A selector typed outside the braces is dropped by the body parser
        // (which only sees tokens up to '}'), silently widening the rule — so it
        // must be a parse error.
        let err = Config::parse(&format!(
            "{head}socks pass {{ command: connect }} protocol: tcp"
        ))
        .unwrap_err();
        assert!(
            err.to_string().contains("unexpected tokens after '}'"),
            "{err}"
        );

        // A second rule crammed onto the same line as the first's '}' is also
        // rejected rather than silently mangled.
        let err = Config::parse(&format!(
            "{head}socks pass {{ command: connect }} socks block {{ }}"
        ))
        .unwrap_err();
        assert!(
            err.to_string().contains("unexpected tokens after '}'"),
            "{err}"
        );
    }

    #[test]
    fn comment_after_closing_brace_is_ok() {
        // A comment is stripped before tokenizing, so it is not mistaken for
        // stray tokens after the closing brace.
        let cfg = Config::parse(
            "internal: 0.0.0.0 port = 1080\nsocks pass { command: connect } # trailing comment",
        )
        .expect("a comment after '}' should parse");
        assert_eq!(cfg.rules.rules.len(), 1);
    }

    #[test]
    fn brace_on_same_line_inline_rule() {
        let cfg = Config::parse(
            "internal: 0.0.0.0 port = 1080\nsocks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }",
        )
        .unwrap();
        assert_eq!(cfg.rules.rules.len(), 1);
    }

    #[test]
    fn comments_are_stripped() {
        let cfg = Config::parse(
            "internal: 0.0.0.0 port = 1080 # listen here\n# full line comment\nsocksmethod: none",
        )
        .unwrap();
        assert_eq!(cfg.internal, "0.0.0.0:1080".parse().unwrap());
    }

    #[test]
    fn load_expands_relative_include_glob() {
        let dir = tempfile::tempdir().unwrap();
        let conf_dir = dir.path().join("conf.d");
        fs::create_dir(&conf_dir).unwrap();
        fs::write(
            dir.path().join("alighieri.conf"),
            "internal: 127.0.0.1:1080\ninclude: conf.d/*.conf\n",
        )
        .unwrap();
        fs::write(
            conf_dir.join("10-policy.conf"),
            "socks block { to: 127.0.0.0/8 }\n",
        )
        .unwrap();
        fs::write(
            conf_dir.join("20-policy.conf"),
            "socks pass { to: 0.0.0.0/0 command: connect }\n",
        )
        .unwrap();

        let cfg = Config::load(&dir.path().join("alighieri.conf")).unwrap();

        assert_eq!(cfg.internal, "127.0.0.1:1080".parse().unwrap());
        assert_eq!(cfg.rules.rules.len(), 2);
        assert_eq!(cfg.rules.rules[0].verdict, Verdict::Block);
        assert_eq!(cfg.rules.rules[1].verdict, Verdict::Pass);
    }

    #[test]
    fn missing_entrypoint_reports_read_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = Config::load(&dir.path().join("missing.conf")).unwrap_err();
        let message = err.to_string();

        assert!(message.contains("failed to read"));
        assert!(!message.contains("failed to resolve"));
    }

    #[test]
    fn included_parse_error_reports_file_and_line() {
        let dir = tempfile::tempdir().unwrap();
        let included = dir.path().join("bad.conf");
        fs::write(
            dir.path().join("alighieri.conf"),
            "internal: 127.0.0.1:1080\ninclude: bad.conf\n",
        )
        .unwrap();
        fs::write(&included, "bogus: true\n").unwrap();

        let err = Config::load(&dir.path().join("alighieri.conf")).unwrap_err();
        let message = err.to_string();

        assert!(message.contains("alighieri.conf:line 2"));
        assert!(message.contains("bad.conf"));
        assert!(message.contains("line 1"));
        assert!(message.contains("unknown keyword 'bogus'"));
    }

    #[test]
    fn include_cycle_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("alighieri.conf");
        let included = dir.path().join("loop.conf");
        fs::write(&main, "internal: 127.0.0.1:1080\ninclude: loop.conf\n").unwrap();
        fs::write(&included, "include: alighieri.conf\n").unwrap();

        let err = Config::load(&main).unwrap_err();

        assert!(err.to_string().contains("include cycle detected"));
    }

    #[test]
    fn unmatched_include_glob_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("alighieri.conf");
        let conf_dir = dir.path().join("conf.d");
        fs::create_dir(&conf_dir).unwrap();
        fs::write(&main, "internal: 127.0.0.1:1080\ninclude: conf.d/*.conf\n").unwrap();

        let err = Config::load(&main).unwrap_err();

        assert!(err
            .to_string()
            .contains("include 'conf.d/*.conf' failed: matched no files"));
    }

    #[test]
    fn include_glob_ignores_matching_directories() {
        let dir = tempfile::tempdir().unwrap();
        let conf_dir = dir.path().join("conf.d");
        fs::create_dir(&conf_dir).unwrap();
        fs::create_dir(conf_dir.join("10-dir.conf")).unwrap();
        fs::write(
            dir.path().join("alighieri.conf"),
            "internal: 127.0.0.1:1080\ninclude: conf.d/*.conf\n",
        )
        .unwrap();
        fs::write(
            conf_dir.join("20-policy.conf"),
            "socks pass { command: connect }\n",
        )
        .unwrap();

        let cfg = Config::load(&dir.path().join("alighieri.conf")).unwrap();

        assert_eq!(cfg.rules.rules.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn include_glob_includes_symlinked_files() {
        let dir = tempfile::tempdir().unwrap();
        let conf_dir = dir.path().join("conf.d");
        fs::create_dir(&conf_dir).unwrap();
        fs::write(
            dir.path().join("alighieri.conf"),
            "internal: 127.0.0.1:1080\ninclude: conf.d/*.conf\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("policy-target.conf"),
            "socks pass { command: connect }\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(
            dir.path().join("policy-target.conf"),
            conf_dir.join("10-policy.conf"),
        )
        .unwrap();

        let cfg = Config::load(&dir.path().join("alighieri.conf")).unwrap();

        assert_eq!(cfg.rules.rules.len(), 1);
    }

    #[test]
    fn parse_rejects_include_without_file_context() {
        let err = Config::parse("internal: 127.0.0.1:1080\ninclude: conf.d/*.conf\n").unwrap_err();

        assert!(err
            .to_string()
            .contains("include is only supported when loading configuration from a file"));
    }

    #[test]
    fn missing_direct_include_reports_resolution_error_with_line() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("alighieri.conf");
        fs::write(&main, "internal: 127.0.0.1:1080\ninclude: missing.conf\n").unwrap();

        let err = Config::load(&main).unwrap_err();
        let message = err.to_string();

        assert!(message.contains("alighieri.conf:line 2"));
        assert!(message.contains("include"));
        assert!(message.contains("failed to resolve"));
        assert!(!message.contains("failed to read"));
    }

    #[test]
    fn bad_protocol_rejected() {
        let err = Config::parse("internal: 0.0.0.0 port = 1080\nsocks pass { protocol: sctp }")
            .unwrap_err();
        assert!(err.to_string().contains("unknown protocol"));
    }

    #[test]
    fn empty_selector_directives_rejected() {
        // A present-but-empty `protocol:`/`command:`/`method:` parses to an empty
        // set, which the matcher treats as "any" — silently broadening the rule.
        // The directive must carry at least one value; omit it to mean "any".
        let head = "internal: 0.0.0.0 port = 1080\n";

        let err = Config::parse(&format!("{head}socks pass {{ protocol: }}")).unwrap_err();
        assert!(
            err.to_string().contains("expected at least one protocol"),
            "{err}"
        );

        let err = Config::parse(&format!("{head}socks pass {{ command: }}")).unwrap_err();
        assert!(
            err.to_string().contains("expected at least one command"),
            "{err}"
        );

        let err = Config::parse(&format!("{head}socks pass {{ method: }}")).unwrap_err();
        assert!(
            err.to_string().contains("expected at least one method"),
            "{err}"
        );

        // The sneaky case: an empty `protocol:` whose value is swallowed by the
        // next selector keyword must still be rejected, not read as "any".
        let err = Config::parse(&format!(
            "{head}socks pass {{ protocol: command: connect }}"
        ))
        .unwrap_err();
        assert!(
            err.to_string().contains("expected at least one protocol"),
            "{err}"
        );
    }

    #[test]
    fn omitted_selector_directives_are_wildcard() {
        // Omitting a selector entirely keeps the rule a wildcard for that axis
        // (an empty set the matcher reads as "any"); only the present-but-empty
        // form is an error.
        let cfg = Config::parse("internal: 0.0.0.0 port = 1080\nsocks pass { command: connect }")
            .expect("a rule without protocol:/method: should parse (wildcard)");
        let rule = &cfg.rules.rules[0];
        assert!(
            rule.protocols.is_empty(),
            "omitted protocol: should stay wildcard"
        );
        assert!(
            rule.methods.is_empty(),
            "omitted method: should stay wildcard"
        );
        // The selector that *was* present is restricted — so the empty ones above
        // are genuinely omitted, not a vacuous pass.
        assert_eq!(rule.commands, vec![Command::Connect]);
    }

    #[test]
    fn auth_kind_to_method() {
        assert_eq!(AuthKind::None.to_method(), Method::NoAuth);
        assert_eq!(AuthKind::Username.to_method(), Method::UserPass);
    }
}
