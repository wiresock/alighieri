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
}

/// TLS listener settings. When present, accepted client TCP connections are
/// upgraded to TLS before the SOCKS5 greeting is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsConfig {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
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
const DEFAULT_AUTH_CACHE_TTL_SECS: u64 = 300;
const DEFAULT_MAX_CONNECTIONS: usize = 1024;
pub const DEFAULT_LOG_ROTATE_SIZE_BYTES: u64 = 10 * 1024 * 1024;
pub const DEFAULT_LOG_ROTATE_KEEP: usize = 5;

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
    metrics_listen: Option<SocketAddr>,
    tls_cert_file: Option<PathBuf>,
    tls_key_file: Option<PathBuf>,
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

        let tls = match (self.tls_cert_file, self.tls_key_file) {
            (Some(cert_file), Some(key_file)) => Some(TlsConfig {
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
            },
            metrics_listen: self.metrics_listen,
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
            b.connect_timeout = Some(Duration::from_secs(parse_u64(vals, lineno)?));
        }
        "handshaketimeout" | "handshake.timeout" => {
            b.handshake_timeout = Some(Duration::from_secs(parse_u64(vals, lineno)?));
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
        "userlist" => {
            if vals.is_empty() {
                return Err(cfg_err(lineno, "userlist requires a path"));
            }
            b.userlist = Some(PathBuf::from(vals.join(" ")));
        }
        "maxconnections" | "max.connections" => {
            let n = parse_u64(vals, lineno)? as usize;
            if n == 0 {
                return Err(cfg_err(lineno, "maxconnections must be > 0"));
            }
            b.max_connections = Some(n);
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
            b.log_rotate_keep = Some(parse_u64(vals, lineno)? as usize);
        }
        "dnsprefer" | "dns.prefer" => b.dns_preference = Some(parse_dns_preference(vals, lineno)?),
        "dnstryall" | "dns.tryall" | "dns.try_all" => {
            b.dns_try_all = Some(parse_bool(vals, lineno)?);
        }
        "dnsdeny" | "dns.deny" => b.dns_deny = Some(parse_dns_deny(vals, lineno)?),
        "dnscachettl" | "dns.cachettl" | "dns.cache.ttl" => {
            b.dns_cache_ttl = Some(parse_cache_ttl(vals, lineno, "dns.cachettl")?);
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
        "tlscertfile" | "tls.certfile" | "tls.cert" => {
            b.tls_cert_file = Some(parse_path(vals, lineno, "tls.certfile")?);
        }
        "tlskeyfile" | "tls.keyfile" | "tls.key" => {
            b.tls_key_file = Some(parse_path(vals, lineno, "tls.keyfile")?);
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
        let ip: IpAddr = vals[0]
            .parse()
            .map_err(|_| cfg_err(lineno, &format!("invalid IP address '{}'", vals[0])))?;
        let port_str = join_value_after(&vals[pos + 1..]);
        let port: u16 = port_str
            .parse()
            .map_err(|_| cfg_err(lineno, &format!("invalid port '{port_str}'")))?;
        Ok(SocketAddr::new(ip, port))
    } else {
        vals[0].parse::<SocketAddr>().map_err(|_| {
            cfg_err(
                lineno,
                &format!("expected 'IP port = N' or 'IP:PORT', got '{}'", vals[0]),
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

fn parse_usize_positive(vals: &[String], lineno: usize, setting: &str) -> Result<usize> {
    let n = parse_u64(vals, lineno)?;
    if n == 0 {
        return Err(cfg_err(lineno, &format!("{setting} must be > 0")));
    }
    usize::try_from(n).map_err(|_| cfg_err(lineno, &format!("{setting} is too large")))
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
    if vals.is_empty() {
        return Err(cfg_err(lineno, "expected an IP address"));
    }
    vals[0]
        .parse()
        .map_err(|_| cfg_err(lineno, &format!("invalid IP address '{}'", vals[0])))
}

fn parse_u64(vals: &[String], lineno: usize) -> Result<u64> {
    if vals.is_empty() {
        return Err(cfg_err(lineno, "expected a number"));
    }
    vals[0]
        .parse()
        .map_err(|_| cfg_err(lineno, &format!("invalid number '{}'", vals[0])))
}

fn parse_bool(vals: &[String], lineno: usize) -> Result<bool> {
    if vals.is_empty() {
        return Err(cfg_err(lineno, "expected a boolean"));
    }
    match vals[0].to_ascii_lowercase().as_str() {
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
    if vals.is_empty() {
        return Err(cfg_err(lineno, "expected a log format"));
    }
    match vals[0].to_ascii_lowercase().as_str() {
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
    if vals.is_empty() {
        return Err(cfg_err(lineno, "expected a DNS preference"));
    }
    match vals[0].to_ascii_lowercase().as_str() {
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
    if vals.is_empty() {
        return Err(cfg_err(
            lineno,
            &format!("{setting} requires seconds, 0, off, none, or disabled"),
        ));
    }
    match vals[0].to_ascii_lowercase().as_str() {
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
        for tok in spaced.split_whitespace() {
            match tok {
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
            tokens.push(tok.to_string());
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
        "from" | "to" | "protocol" | "command" | "method" | "log"
    )
}

fn parse_addr_spec(vals: &[String], lineno: usize, allow_hosts: bool) -> Result<AddrSpec> {
    if vals.is_empty() {
        return Err(cfg_err(lineno, "address selector requires a value"));
    }

    let ports = if let Some(pos) = vals.iter().position(|v| v.eq_ignore_ascii_case("port")) {
        let spec = join_value_after(&vals[pos + 1..]);
        if spec.is_empty() {
            return Err(cfg_err(lineno, "'port' requires a value"));
        }
        let range: PortRange = spec
            .parse()
            .map_err(|e| cfg_err(lineno, &format!("invalid port spec '{spec}': {e}")))?;
        Some(range)
    } else {
        None
    };

    // The selector address is the first token: a network (CIDR or bare IP), or
    // — only for a `socks` rule `to:` — a hostname pattern such as
    // `.example.com` (domain and subdomains) or `example.com` (exact).
    let addr = &vals[0];
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
            Some(TlsConfig {
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
    fn auth_kind_to_method() {
        assert_eq!(AuthKind::None.to_method(), Method::NoAuth);
        assert_eq!(AuthKind::Username.to_method(), Method::UserPass);
    }
}
