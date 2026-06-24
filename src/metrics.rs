//! Runtime counters and the optional local metrics endpoint.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, TryLockError};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::acl::{RuleDecision, Scope, Verdict};

const MAX_REQUEST_LINE: usize = 8 * 1024;
const MAX_METRICS_CONNECTIONS: usize = 16;
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Default)]
pub struct Metrics {
    accepted_connections: AtomicU64,
    active_connections: AtomicU64,
    client_denied_connections: AtomicU64,
    rate_limit_events: AtomicU64,
    socks_allowed_requests: AtomicU64,
    socks_denied_requests: AtomicU64,
    auth_failures: AtomicU64,
    tcp_connects: AtomicU64,
    tcp_relay_bytes_up: AtomicU64,
    tcp_relay_bytes_down: AtomicU64,
    udp_associations: AtomicU64,
    active_udp_associations: AtomicU64,
    udp_packets_up: AtomicU64,
    udp_packets_down: AtomicU64,
    udp_packets_denied: AtomicU64,
    udp_send_failures: AtomicU64,
    udp_relay_bytes_up: AtomicU64,
    udp_relay_bytes_down: AtomicU64,
    /// Per-rule hit counts. Keyed by rule (not a fixed atomic set), so it sits
    /// behind a mutex and is updated best-effort — see [`Metrics::rule_hit`].
    rule_hits: Mutex<BTreeMap<RuleHitKey, u64>>,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn accepted_connection(&self) {
        self.accepted_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn closed_connection(&self) {
        decrement_gauge(&self.active_connections);
    }

    pub fn client_denied(&self, decision: &RuleDecision) {
        self.client_denied_connections
            .fetch_add(1, Ordering::Relaxed);
        self.rule_hit(
            Scope::Client,
            Verdict::Block,
            decision.source_line,
            decision.rule_name.clone(),
        );
    }

    pub fn rate_limited(&self) {
        self.rate_limit_events.fetch_add(1, Ordering::Relaxed);
    }

    pub fn client_allowed(&self, decision: &RuleDecision) {
        self.rule_hit(
            Scope::Client,
            Verdict::Pass,
            decision.source_line,
            decision.rule_name.clone(),
        );
    }

    pub fn socks_request_allowed(&self) {
        self.socks_allowed_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn socks_request_denied(&self) {
        self.socks_denied_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn auth_failed(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn tcp_connect(&self) {
        self.tcp_connects.fetch_add(1, Ordering::Relaxed);
    }

    pub fn tcp_relay_closed(&self, up: u64, down: u64) {
        self.tcp_relay_bytes_up.fetch_add(up, Ordering::Relaxed);
        self.tcp_relay_bytes_down.fetch_add(down, Ordering::Relaxed);
    }

    pub fn udp_association_started(&self) {
        self.udp_associations.fetch_add(1, Ordering::Relaxed);
        self.active_udp_associations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn udp_association_closed(&self) {
        decrement_gauge(&self.active_udp_associations);
    }

    pub fn udp_client_packet_relayed(&self, bytes: u64) {
        self.udp_packets_up.fetch_add(1, Ordering::Relaxed);
        self.udp_relay_bytes_up.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn udp_remote_packet_relayed(&self, bytes: u64) {
        self.udp_packets_down.fetch_add(1, Ordering::Relaxed);
        self.udp_relay_bytes_down
            .fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn udp_client_packet_denied(&self) {
        self.udp_packets_denied.fetch_add(1, Ordering::Relaxed);
    }

    /// A datagram could not be forwarded to its destination (e.g. an IPv6 target
    /// on an IPv4-only outbound socket, or a transient socket error). Makes the
    /// otherwise-silent `send_to` failure observable.
    pub fn udp_send_failed(&self) {
        self.udp_send_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();
        write_metric(
            &mut out,
            "alighieri_connections_accepted_total",
            self.accepted_connections.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "alighieri_connections_active",
            self.active_connections.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "alighieri_connections_denied_total",
            self.client_denied_connections.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "alighieri_rate_limit_events_total",
            self.rate_limit_events.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "alighieri_socks_requests_allowed_total",
            self.socks_allowed_requests.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "alighieri_socks_requests_denied_total",
            self.socks_denied_requests.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "alighieri_auth_failures_total",
            self.auth_failures.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "alighieri_tcp_connects_total",
            self.tcp_connects.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "alighieri_tcp_relay_bytes_up_total",
            self.tcp_relay_bytes_up.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "alighieri_tcp_relay_bytes_down_total",
            self.tcp_relay_bytes_down.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "alighieri_udp_associations_total",
            self.udp_associations.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "alighieri_udp_associations_active",
            self.active_udp_associations.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "alighieri_udp_packets_up_total",
            self.udp_packets_up.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "alighieri_udp_packets_down_total",
            self.udp_packets_down.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "alighieri_udp_packets_denied_total",
            self.udp_packets_denied.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "alighieri_udp_send_failures_total",
            self.udp_send_failures.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "alighieri_udp_relay_bytes_up_total",
            self.udp_relay_bytes_up.load(Ordering::Relaxed),
        );
        write_metric(
            &mut out,
            "alighieri_udp_relay_bytes_down_total",
            self.udp_relay_bytes_down.load(Ordering::Relaxed),
        );

        let rule_hits = match self.rule_hits.lock() {
            Ok(rule_hits) => rule_hits,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut legacy_rule_hits = BTreeMap::new();
        for (key, value) in rule_hits.iter() {
            *legacy_rule_hits
                .entry(LegacyRuleHitKey {
                    scope: key.scope,
                    verdict: key.verdict,
                    source_line: key.source_line,
                })
                .or_insert(0) += value;
        }

        for (key, value) in legacy_rule_hits.iter() {
            let scope = match key.scope {
                Scope::Client => "client",
                Scope::Socks => "socks",
            };
            let verdict = match key.verdict {
                Verdict::Pass => "pass",
                Verdict::Block => "block",
            };
            let line = key
                .source_line
                .map(|line| line.to_string())
                .unwrap_or_else(|| "default".into());
            let _ = writeln!(
                out,
                "alighieri_rule_hits_total{{scope=\"{scope}\",verdict=\"{verdict}\",line=\"{line}\"}} {value}"
            );
        }

        for (key, value) in rule_hits.iter() {
            let scope = match key.scope {
                Scope::Client => "client",
                Scope::Socks => "socks",
            };
            let verdict = match key.verdict {
                Verdict::Pass => "pass",
                Verdict::Block => "block",
            };
            let line = key
                .source_line
                .map(|line| line.to_string())
                .unwrap_or_else(|| "default".into());
            let name = key.rule_name.as_deref().unwrap_or("");
            let name = escape_label_value(name);
            let _ = writeln!(
                out,
                "alighieri_rule_named_hits_total{{scope=\"{scope}\",verdict=\"{verdict}\",line=\"{line}\",name=\"{name}\"}} {value}"
            );
        }

        out
    }

    /// Records a rule match. **Best-effort**: the per-rule counters live behind a
    /// mutex (the map is keyed by rule, not a fixed set of atomics), and to keep
    /// the hot authorisation path non-blocking this uses `try_lock` and *drops*
    /// the increment when the lock is contended — including while a Prometheus
    /// scrape is rendering the map. So `alighieri_rule_hits_total` /
    /// `alighieri_rule_named_hits_total` may undercount under load; they are an
    /// observability aid, not an exact ledger. The aggregate counters
    /// (connections, denials, bytes) are exact atomics.
    pub fn rule_hit(
        &self,
        scope: Scope,
        verdict: Verdict,
        source_line: Option<usize>,
        rule_name: Option<Arc<str>>,
    ) {
        match self.rule_hits.try_lock() {
            Ok(mut rule_hits) => {
                increment_rule_hit(&mut rule_hits, scope, verdict, source_line, rule_name)
            }
            Err(TryLockError::Poisoned(poisoned)) => {
                let mut rule_hits = poisoned.into_inner();
                increment_rule_hit(&mut rule_hits, scope, verdict, source_line, rule_name);
            }
            // Contended (e.g. a concurrent scrape render): drop this increment
            // rather than block the authorisation path. See the doc comment.
            Err(TryLockError::WouldBlock) => {}
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct LegacyRuleHitKey {
    scope: Scope,
    verdict: Verdict,
    source_line: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RuleHitKey {
    scope: Scope,
    verdict: Verdict,
    source_line: Option<usize>,
    rule_name: Option<Arc<str>>,
}

fn increment_rule_hit(
    rule_hits: &mut BTreeMap<RuleHitKey, u64>,
    scope: Scope,
    verdict: Verdict,
    source_line: Option<usize>,
    rule_name: Option<Arc<str>>,
) {
    *rule_hits
        .entry(RuleHitKey {
            scope,
            verdict,
            source_line,
            rule_name,
        })
        .or_insert(0) += 1;
}

pub async fn serve_metrics(listener: TcpListener, metrics: Arc<Metrics>) -> io::Result<()> {
    let addr = listener.local_addr()?;
    info!(listen = %addr, "metrics endpoint listening");
    let limiter = Arc::new(Semaphore::new(MAX_METRICS_CONNECTIONS));
    loop {
        let permit = match limiter.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => break,
        };
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "metrics accept failed");
                drop(permit);
                continue;
            }
        };
        let metrics = metrics.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_metrics_connection(stream, metrics).await {
                debug!(peer = %peer, error = %e, "metrics connection failed");
            }
            drop(permit);
        });
    }
    Ok(())
}

async fn handle_metrics_connection(mut stream: TcpStream, metrics: Arc<Metrics>) -> io::Result<()> {
    let Some(request_line) =
        with_request_timeout(read_request_line(&mut stream), "metrics request line").await?
    else {
        return Ok(());
    };
    with_request_timeout(read_request_headers(&mut stream), "metrics request headers").await?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or("");
    let path = request_parts.next().unwrap_or("/");

    // A metrics scrape is a read; only GET (and HEAD) are meaningful. Reject any
    // other method with 405 and the `Allow` header RFC 7231 requires, so the
    // endpoint cannot be driven with write-style verbs.
    if method != "GET" && method != "HEAD" {
        write_response(
            &mut stream,
            405,
            "Method Not Allowed",
            "method not allowed\n",
            "allow: GET, HEAD\r\n",
            true,
        )
        .await?;
        return Ok(());
    }

    // HEAD carries no message body on any status, so decide this before
    // branching on the path — otherwise a `HEAD /invalid` would return a 404
    // with a body, which RFC 7231 forbids.
    let include_body = method == "GET";

    if path != "/metrics" {
        write_response(
            &mut stream,
            404,
            "Not Found",
            "not found\n",
            "",
            include_body,
        )
        .await?;
        return Ok(());
    }

    let body = metrics.render_prometheus();
    write_response(&mut stream, 200, "OK", &body, "", include_body).await
}

async fn with_request_timeout<T>(
    operation: impl std::future::Future<Output = io::Result<T>>,
    context: &'static str,
) -> io::Result<T> {
    tokio::time::timeout(REQUEST_READ_TIMEOUT, operation)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, context))?
}

async fn read_request_line(stream: &mut TcpStream) -> io::Result<Option<String>> {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            if line.is_empty() {
                return Ok(None);
            }
            break;
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
        if line.len() >= MAX_REQUEST_LINE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "metrics request line is too long",
            ));
        }
    }
    Ok(Some(String::from_utf8_lossy(&line).into_owned()))
}

async fn read_request_headers(stream: &mut TcpStream) -> io::Result<()> {
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    while bytes.len() < MAX_REQUEST_LINE {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Ok(());
        }
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") || bytes.ends_with(b"\n\n") {
            return Ok(());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "metrics request headers are too long",
    ))
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &str,
    extra_headers: &str,
    include_body: bool,
) -> io::Result<()> {
    // `content-length` always advertises the body length — a HEAD reports the
    // size a GET would return without sending the bytes. `extra_headers`, when
    // non-empty, must be CRLF-terminated header lines placed before the blank
    // line (e.g. `allow: GET, HEAD\r\n`); otherwise the following `connection`
    // header would be folded onto the same line and the response malformed.
    debug_assert!(
        extra_headers.is_empty() || extra_headers.ends_with("\r\n"),
        "extra_headers must be empty or CRLF-terminated, got: {extra_headers:?}"
    );
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: text/plain; version=0.0.4\r\ncontent-length: {}\r\n{extra_headers}connection: close\r\n\r\n",
        body.len()
    );
    if include_body {
        response.push_str(body);
    }
    stream.write_all(response.as_bytes()).await
}

fn write_metric(out: &mut String, name: &str, value: u64) {
    let _ = writeln!(out, "{name} {value}");
}

fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn decrement_gauge(gauge: &AtomicU64) {
    let _ = gauge.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        value.checked_sub(1)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_core_counters() {
        let metrics = Metrics::default();
        metrics.accepted_connection();
        metrics.closed_connection();
        metrics.closed_connection();
        metrics.rate_limited();
        metrics.auth_failed();
        metrics.tcp_relay_closed(12, 34);
        metrics.udp_association_closed();
        metrics.udp_client_packet_denied();
        metrics.udp_send_failed();
        metrics.udp_send_failed();

        let rendered = metrics.render_prometheus();

        assert!(rendered.contains("alighieri_connections_accepted_total 1\n"));
        assert!(rendered.contains("alighieri_connections_active 0\n"));
        assert!(rendered.contains("alighieri_rate_limit_events_total 1\n"));
        assert!(rendered.contains("alighieri_auth_failures_total 1\n"));
        assert!(rendered.contains("alighieri_tcp_relay_bytes_up_total 12\n"));
        assert!(rendered.contains("alighieri_tcp_relay_bytes_down_total 34\n"));
        assert!(rendered.contains("alighieri_udp_associations_active 0\n"));
        assert!(rendered.contains("alighieri_udp_packets_denied_total 1\n"));
        assert!(rendered.contains("alighieri_udp_send_failures_total 2\n"));
    }

    #[test]
    fn renders_rule_hits() {
        let metrics = Metrics::default();
        // Mirror the data path: a denied socks request bumps the counter and
        // records a rule hit separately.
        metrics.socks_request_denied();
        metrics.rule_hit(
            Scope::Socks,
            Verdict::Block,
            Some(19),
            Some("blocked-loopback".into()),
        );
        metrics.client_allowed(&RuleDecision {
            verdict: Verdict::Pass,
            source_line: None,
            rule_name: None,
            bandwidth: None,
        });

        let rendered = metrics.render_prometheus();

        assert!(rendered.contains(
            "alighieri_rule_hits_total{scope=\"socks\",verdict=\"block\",line=\"19\"} 1\n"
        ));
        assert!(rendered.contains(
            "alighieri_rule_named_hits_total{scope=\"socks\",verdict=\"block\",line=\"19\",name=\"blocked-loopback\"} 1\n"
        ));
        assert!(rendered.contains(
            "alighieri_rule_hits_total{scope=\"client\",verdict=\"pass\",line=\"default\"} 1\n"
        ));
        assert!(rendered.contains(
            "alighieri_rule_named_hits_total{scope=\"client\",verdict=\"pass\",line=\"default\",name=\"\"} 1\n"
        ));
    }

    #[test]
    fn escapes_rule_name_labels() {
        let metrics = Metrics::default();
        metrics.rule_hit(
            Scope::Socks,
            Verdict::Pass,
            Some(7),
            Some(Arc::from("quote\"slash\\newline\n")),
        );

        let rendered = metrics.render_prometheus();

        assert!(rendered.contains("name=\"quote\\\"slash\\\\newline\\n\""));
    }

    #[test]
    fn aggregates_legacy_rule_hits_without_name_label() {
        let metrics = Metrics::default();
        metrics.rule_hit(
            Scope::Socks,
            Verdict::Pass,
            Some(7),
            Some(Arc::from("first")),
        );
        metrics.rule_hit(
            Scope::Socks,
            Verdict::Pass,
            Some(7),
            Some(Arc::from("second")),
        );

        let rendered = metrics.render_prometheus();

        assert!(rendered.contains(
            "alighieri_rule_hits_total{scope=\"socks\",verdict=\"pass\",line=\"7\"} 2\n"
        ));
        assert!(rendered.contains(
            "alighieri_rule_named_hits_total{scope=\"socks\",verdict=\"pass\",line=\"7\",name=\"first\"} 1\n"
        ));
        assert!(rendered.contains(
            "alighieri_rule_named_hits_total{scope=\"socks\",verdict=\"pass\",line=\"7\",name=\"second\"} 1\n"
        ));
    }

    #[tokio::test]
    async fn metrics_endpoint_serves_metrics_path() {
        let metrics = Metrics::new();
        metrics.accepted_connection();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(serve_metrics(listener, metrics));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        task.abort();

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("alighieri_connections_accepted_total 1\n"));
    }

    #[tokio::test]
    async fn metrics_endpoint_rejects_other_paths() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(serve_metrics(listener, Metrics::new()));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        task.abort();

        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
    }

    #[tokio::test]
    async fn metrics_endpoint_rejects_non_get_method() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(serve_metrics(listener, Metrics::new()));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"POST /metrics HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        task.abort();

        assert!(
            response.starts_with("HTTP/1.1 405 Method Not Allowed"),
            "{response}"
        );
        assert!(response.contains("allow: GET, HEAD\r\n"), "{response}");
    }

    #[tokio::test]
    async fn metrics_endpoint_head_returns_headers_without_body() {
        let metrics = Metrics::new();
        metrics.accepted_connection();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(serve_metrics(listener, metrics));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"HEAD /metrics HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        task.abort();

        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        // The content-length advertises the body a GET would return, but a HEAD
        // carries no body of its own.
        assert!(response.contains("content-length: "), "{response}");
        let (_, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(
            body.is_empty(),
            "HEAD must not return a body, got: {body:?}"
        );
    }

    #[tokio::test]
    async fn metrics_endpoint_head_on_unknown_path_has_no_body() {
        // A HEAD must carry no body on any status, including the 404 path.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(serve_metrics(listener, Metrics::new()));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"HEAD /nope HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        task.abort();

        assert!(response.starts_with("HTTP/1.1 404 Not Found"), "{response}");
        let (_, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(
            body.is_empty(),
            "HEAD must not return a body, got: {body:?}"
        );
    }

    #[tokio::test]
    async fn metrics_endpoint_handles_split_request_line() {
        let metrics = Metrics::new();
        metrics.accepted_connection();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(serve_metrics(listener, metrics));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"GET /met").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        stream
            .write_all(b"rics HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        task.abort();

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("alighieri_connections_accepted_total 1\n"));
    }

    #[tokio::test]
    async fn metrics_endpoint_ignores_empty_connections() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(serve_metrics(listener, Metrics::new()));

        let stream = TcpStream::connect(addr).await.unwrap();
        drop(stream);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        task.abort();
    }
}
