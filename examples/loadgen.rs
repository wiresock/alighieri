//! End-to-end load generator for Alighieri.
//!
//! Measures the three baseline numbers that matter for the proxy data path:
//!
//! - `throughput`: payload bytes relayed per second through CONNECT streams,
//! - `handshakes`: full connection setups per second (TCP connect, greeting,
//!   optional username/password authentication, CONNECT, teardown),
//! - `udp`: datagrams per second through a UDP ASSOCIATE relay.
//!
//! By default the proxy under test is self-hosted in-process against an
//! in-process echo server, so a single command produces a number:
//!
//! ```text
//! cargo run --release --example loadgen -- throughput --connections 8
//! cargo run --release --example loadgen -- handshakes --auth argon2
//! cargo run --release --example loadgen -- udp --payload 512
//! ```
//!
//! Self-hosting shares the tokio runtime between proxy, echo server, and load
//! generator, which understates absolute numbers slightly but keeps runs
//! reproducible with one command. For isolated measurements start a release
//! proxy separately on the same host and point the generator at it (the
//! generator's echo servers bind to loopback, so the proxy must be able to
//! reach this machine's 127.0.0.1):
//!
//! ```text
//! cargo run --release -- bench.conf
//! cargo run --release --example loadgen -- throughput --proxy 127.0.0.1:1080
//! ```
//!
//! Results print as human-readable summaries; pass `--json` for a single
//! machine-readable line suitable for tracking across commits.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use alighieri::auth::UserDb;
use alighieri::config::Config;
use alighieri::server::Server;

const DEFAULT_DURATION_SECS: u64 = 10;
const PROXY_PREFLIGHT_TIMEOUT_SECS: u64 = 5;
const SOCKS_SETUP_TIMEOUT_SECS: u64 = 10;
const DEFAULT_CONNECTIONS: usize = 8;
const DEFAULT_TCP_PAYLOAD: usize = 64 * 1024;
const DEFAULT_UDP_PAYLOAD: usize = 512;
const BENCH_USER: &str = "bench";
const BENCH_PASSWORD: &str = "benchpass";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Throughput,
    Handshakes,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthMode {
    None,
    Plain,
    Argon2,
}

#[derive(Debug)]
struct Options {
    scenario: Scenario,
    proxy: Option<SocketAddr>,
    connections: usize,
    duration: Duration,
    payload: Option<usize>,
    auth: AuthMode,
    io_timeout_secs: Option<u64>,
    auth_cache_ttl_secs: Option<u64>,
    json: bool,
}

fn main() {
    let options = match parse_args(std::env::args().skip(1).collect()) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("loadgen: {message}");
            eprintln!("{}", usage());
            std::process::exit(2);
        }
    };

    // A real subscriber with the default filter keeps per-event costs
    // representative of a quiet production setup without spamming the console.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    if let Err(e) = runtime.block_on(run(options)) {
        eprintln!("loadgen: {e}");
        std::process::exit(1);
    }
}

fn usage() -> String {
    "usage: loadgen <throughput|handshakes|udp> [OPTIONS]\n\
     \n\
     options:\n\
       --proxy ADDR        measure an externally started proxy instead of self-hosting\n\
       --connections N     concurrent workers (default 8)\n\
       --duration SECS     measurement window (default 10)\n\
       --payload BYTES     chunk/datagram payload size (default 65536 tcp, 512 udp)\n\
       --auth MODE         none | plain | argon2 (default none; authenticated\n\
                           scenarios send fixed credentials bench/benchpass)\n\
       --iotimeout SECS    set iotimeout in the self-hosted config (default 0;\n\
                           incompatible with --proxy)\n\
       --auth-cachettl SECS  set auth.cachettl in the self-hosted config\n\
                           (0 disables; incompatible with --proxy)\n\
       --json              print a machine-readable result line"
        .into()
}

fn parse_args(args: Vec<String>) -> Result<Options, String> {
    let mut args = args.into_iter();
    let scenario = match args.next().as_deref() {
        Some("throughput") => Scenario::Throughput,
        Some("handshakes") => Scenario::Handshakes,
        Some("udp") => Scenario::Udp,
        Some(other) => return Err(format!("unknown scenario '{other}'")),
        None => return Err("missing scenario".into()),
    };

    let mut options = Options {
        scenario,
        proxy: None,
        connections: DEFAULT_CONNECTIONS,
        duration: Duration::from_secs(DEFAULT_DURATION_SECS),
        payload: None,
        auth: AuthMode::None,
        io_timeout_secs: None,
        auth_cache_ttl_secs: None,
        json: false,
    };

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--proxy" => {
                options.proxy = Some(
                    parse_value(&mut args, "--proxy")?
                        .parse()
                        .map_err(|e| format!("invalid --proxy address: {e}"))?,
                );
            }
            "--connections" => {
                options.connections = parse_value(&mut args, "--connections")?
                    .parse()
                    .map_err(|e| format!("invalid --connections: {e}"))?;
                if options.connections == 0 {
                    return Err("--connections must be at least 1".into());
                }
            }
            "--duration" => {
                let secs: u64 = parse_value(&mut args, "--duration")?
                    .parse()
                    .map_err(|e| format!("invalid --duration: {e}"))?;
                if secs == 0 {
                    return Err("--duration must be at least 1".into());
                }
                options.duration = Duration::from_secs(secs);
            }
            "--payload" => {
                let bytes: usize = parse_value(&mut args, "--payload")?
                    .parse()
                    .map_err(|e| format!("invalid --payload: {e}"))?;
                if bytes == 0 {
                    return Err("--payload must be at least 1".into());
                }
                options.payload = Some(bytes);
            }
            "--auth" => {
                options.auth = match parse_value(&mut args, "--auth")?.as_str() {
                    "none" => AuthMode::None,
                    "plain" => AuthMode::Plain,
                    "argon2" => AuthMode::Argon2,
                    other => return Err(format!("unknown --auth mode '{other}'")),
                };
            }
            "--iotimeout" => {
                options.io_timeout_secs = Some(
                    parse_value(&mut args, "--iotimeout")?
                        .parse()
                        .map_err(|e| format!("invalid --iotimeout: {e}"))?,
                );
            }
            "--auth-cachettl" => {
                options.auth_cache_ttl_secs = Some(
                    parse_value(&mut args, "--auth-cachettl")?
                        .parse()
                        .map_err(|e| format!("invalid --auth-cachettl: {e}"))?,
                );
            }
            "--json" => options.json = true,
            other => return Err(format!("unknown option '{other}'")),
        }
    }
    if options.proxy.is_some() && options.io_timeout_secs.is_some() {
        return Err(
            "--iotimeout configures the self-hosted proxy and cannot be combined with --proxy"
                .into(),
        );
    }
    if options.proxy.is_some() && options.auth_cache_ttl_secs.is_some() {
        return Err(
            "--auth-cachettl configures the self-hosted proxy and cannot be combined with --proxy"
                .into(),
        );
    }
    Ok(options)
}

fn parse_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

async fn run(options: Options) -> Result<(), String> {
    let credentials = match options.auth {
        AuthMode::None => None,
        AuthMode::Plain | AuthMode::Argon2 => Some((BENCH_USER, BENCH_PASSWORD)),
    };

    // `_host` keeps the self-hosted proxy's temp files alive for the run.
    let (proxy, _host) = match options.proxy {
        Some(addr) => (addr, None),
        None => {
            let host = SelfHostedProxy::start(
                options.auth,
                options.io_timeout_secs,
                options.auth_cache_ttl_secs,
            )
            .await?;
            (host.addr, Some(host))
        }
    };

    // Fail fast on an unreachable proxy instead of letting every worker spin
    // against a dead endpoint for the whole measurement window. The timeout
    // keeps blackholed addresses (firewall drops) from hanging the tool for
    // the OS connect timeout.
    if options.proxy.is_some() && !proxy.ip().is_loopback() {
        eprintln!(
            "loadgen: note: the echo servers bind to this host's loopback; \
             a proxy that cannot reach this machine's 127.0.0.1 will fail every request"
        );
    }

    match tokio::time::timeout(
        Duration::from_secs(PROXY_PREFLIGHT_TIMEOUT_SECS),
        TcpStream::connect(proxy),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(format!("cannot reach proxy at {proxy}: {e}")),
        Err(_) => {
            return Err(format!(
                "cannot reach proxy at {proxy}: connect timed out after {PROXY_PREFLIGHT_TIMEOUT_SECS}s"
            ));
        }
    }

    // Each scenario starts only the echo server it relays against.
    match options.scenario {
        Scenario::Throughput => {
            let echo = spawn_tcp_echo().await?;
            run_throughput(&options, proxy, credentials, echo).await
        }
        Scenario::Handshakes => {
            let echo = spawn_tcp_echo().await?;
            run_handshakes(&options, proxy, credentials, echo).await
        }
        Scenario::Udp => run_udp(&options, proxy, credentials).await,
    }
}

struct SelfHostedProxy {
    addr: SocketAddr,
    _tempdir: tempfile::TempDir,
}

impl SelfHostedProxy {
    async fn start(
        auth: AuthMode,
        io_timeout_secs: Option<u64>,
        auth_cache_ttl_secs: Option<u64>,
    ) -> Result<Self, String> {
        let tempdir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
        let mut config_text = String::from("internal: 127.0.0.1 port = 0\nexternal: 0.0.0.0\n");
        match auth {
            AuthMode::None => config_text.push_str("socksmethod: none\n"),
            AuthMode::Plain | AuthMode::Argon2 => {
                let userlist = tempdir.path().join("users");
                let entry = match auth {
                    AuthMode::Plain => format!("{BENCH_USER}:{BENCH_PASSWORD}"),
                    _ => UserDb::hash_user_line(BENCH_USER, BENCH_PASSWORD)
                        .map_err(|e| format!("hash user: {e}"))?,
                };
                std::fs::write(&userlist, entry).map_err(|e| format!("write userlist: {e}"))?;
                config_text.push_str("socksmethod: username\n");
                config_text.push_str(&format!("userlist: {}\n", userlist.display()));
            }
        }
        config_text.push_str(&format!("iotimeout: {}\n", io_timeout_secs.unwrap_or(0)));
        if let Some(ttl) = auth_cache_ttl_secs {
            config_text.push_str(&format!("auth.cachettl: {ttl}\n"));
        }
        config_text.push_str("client pass { from: 127.0.0.1 to: 0.0.0.0/0 }\n");
        config_text.push_str(
            "socks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 protocol: tcp udp command: connect udpassociate }\n",
        );

        let config = Config::parse(&config_text).map_err(|e| format!("bench config: {e}"))?;
        let server = Server::bind(config)
            .await
            .map_err(|e| format!("bind proxy: {e}"))?;
        let addr = server
            .local_addr()
            .map_err(|e| format!("proxy addr: {e}"))?;
        let server = Arc::new(server);
        let running = server.clone();
        tokio::spawn(async move {
            if let Err(e) = running.run().await {
                eprintln!("loadgen: proxy exited: {e}");
            }
        });
        Ok(SelfHostedProxy {
            addr,
            _tempdir: tempdir,
        })
    }
}

async fn spawn_tcp_echo() -> Result<SocketAddr, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind tcp echo: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("echo addr: {e}"))?;
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let _ = stream.set_nodelay(true);
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    Ok(addr)
}

async fn spawn_udp_echo() -> Result<SocketAddr, String> {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind udp echo: {e}"))?;
    let addr = socket.local_addr().map_err(|e| format!("echo addr: {e}"))?;
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, peer)) => {
                    let _ = socket.send_to(&buf[..n], peer).await;
                }
                Err(_) => continue,
            }
        }
    });
    Ok(addr)
}

// --- Minimal SOCKS5 client -------------------------------------------------

async fn socks_handshake(
    proxy: SocketAddr,
    credentials: Option<(&str, &str)>,
) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await?;
    stream.set_nodelay(true)?;

    let method: u8 = if credentials.is_some() { 0x02 } else { 0x00 };
    stream.write_all(&[0x05, 0x01, method]).await?;
    let mut selection = [0u8; 2];
    stream.read_exact(&mut selection).await?;
    if selection != [0x05, method] {
        return Err(io_error("proxy refused the offered auth method"));
    }

    if let Some((user, pass)) = credentials {
        let mut auth = Vec::with_capacity(3 + user.len() + pass.len());
        auth.push(0x01);
        auth.push(user.len() as u8);
        auth.extend_from_slice(user.as_bytes());
        auth.push(pass.len() as u8);
        auth.extend_from_slice(pass.as_bytes());
        stream.write_all(&auth).await?;
        let mut status = [0u8; 2];
        stream.read_exact(&mut status).await?;
        if status[0] != 0x01 {
            return Err(io_error("malformed RFC 1929 auth reply"));
        }
        if status[1] != 0 {
            return Err(io_error("authentication rejected"));
        }
    }
    Ok(stream)
}

async fn socks_request(
    stream: &mut TcpStream,
    command: u8,
    target: SocketAddr,
) -> std::io::Result<SocketAddr> {
    let IpAddr::V4(ip) = target.ip() else {
        return Err(io_error("loadgen targets must be IPv4"));
    };
    let mut request = [0u8; 10];
    request[0] = 0x05;
    request[1] = command;
    request[3] = 0x01;
    request[4..8].copy_from_slice(&ip.octets());
    request[8..10].copy_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 || head[2] != 0x00 {
        return Err(io_error("malformed SOCKS5 reply header"));
    }
    if head[1] != 0x00 {
        return Err(io_error(&format!("request rejected (REP={})", head[1])));
    }
    match head[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest).await?;
            let ip = Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
            let port = u16::from_be_bytes([rest[4], rest[5]]);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x04 => {
            let mut rest = [0u8; 18];
            stream.read_exact(&mut rest).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&rest[..16]);
            let port = u16::from_be_bytes([rest[16], rest[17]]);
            Ok(SocketAddr::new(IpAddr::V6(octets.into()), port))
        }
        other => Err(io_error(&format!("unsupported reply ATYP {other}"))),
    }
}

async fn socks_connect(
    proxy: SocketAddr,
    credentials: Option<(&str, &str)>,
    target: SocketAddr,
) -> std::io::Result<TcpStream> {
    let mut stream = socks_handshake(proxy, credentials).await?;
    socks_request(&mut stream, 0x01, target).await?;
    Ok(stream)
}

fn io_error(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

/// Bounds a SOCKS setup operation so a proxy that accepts TCP but stalls
/// mid-negotiation cannot hang the tool before measurement starts.
async fn with_setup_timeout<T>(
    operation: impl std::future::Future<Output = std::io::Result<T>>,
) -> std::io::Result<T> {
    match tokio::time::timeout(Duration::from_secs(SOCKS_SETUP_TIMEOUT_SECS), operation).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "SOCKS setup timed out",
        )),
    }
}

/// Builds a SOCKS5 UDP request header for an IPv4 destination.
fn udp_header(target: SocketAddr) -> [u8; 10] {
    let IpAddr::V4(ip) = target.ip() else {
        panic!("loadgen targets must be IPv4");
    };
    let mut header = [0u8; 10];
    header[3] = 0x01;
    header[4..8].copy_from_slice(&ip.octets());
    header[8..10].copy_from_slice(&target.port().to_be_bytes());
    header
}

// --- Scenarios --------------------------------------------------------------

async fn run_throughput(
    options: &Options,
    proxy: SocketAddr,
    credentials: Option<(&'static str, &'static str)>,
    echo: SocketAddr,
) -> Result<(), String> {
    let payload = options.payload.unwrap_or(DEFAULT_TCP_PAYLOAD);
    let echoed_bytes = Arc::new(AtomicU64::new(0));

    // Establish every stream before starting the clock so the window measures
    // steady-state relaying rather than connection setup and auth latency.
    let mut connectors = Vec::with_capacity(options.connections);
    for _ in 0..options.connections {
        connectors.push(tokio::spawn(async move {
            with_setup_timeout(socks_connect(proxy, credentials, echo)).await
        }));
    }
    let mut streams = Vec::with_capacity(options.connections);
    for connector in connectors {
        let stream = connector
            .await
            .map_err(|e| format!("connector panicked: {e}"))?
            .map_err(|e| format!("connect through proxy: {e}"))?;
        streams.push(stream);
    }

    let started = Instant::now();
    let deadline = started + options.duration;

    let mut workers = Vec::with_capacity(streams.len());
    for stream in streams {
        let echoed_bytes = echoed_bytes.clone();
        workers.push(tokio::spawn(async move {
            let (mut reader, mut writer) = stream.into_split();

            let write_half = async move {
                let chunk = vec![0xa5u8; payload];
                while Instant::now() < deadline {
                    if writer.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
                let _ = writer.shutdown().await;
            };
            let read_half = async {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match reader.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            echoed_bytes.fetch_add(n as u64, Ordering::Relaxed);
                        }
                    }
                }
            };
            tokio::join!(write_half, read_half);
        }));
    }
    // Sample the counter when the window closes: bytes drained afterwards
    // arrive outside the window and would dilute the rate. Workers are still
    // awaited afterwards for an orderly teardown, but only within a grace
    // period — a proxy that keeps connections open without relaying could
    // otherwise block write_all/read forever and hang the benchmark.
    tokio::time::sleep(deadline.saturating_duration_since(Instant::now())).await;
    let elapsed = started.elapsed();
    let bytes = echoed_bytes.load(Ordering::Relaxed);
    let cleanup_deadline = Instant::now() + Duration::from_secs(5);
    let mut stalled = 0usize;
    for mut worker in workers {
        let remaining = cleanup_deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, &mut worker).await {
            Ok(result) => result.map_err(|e| format!("worker panicked: {e}"))?,
            Err(_) => {
                worker.abort();
                stalled += 1;
            }
        }
    }
    if stalled > 0 {
        eprintln!(
            "loadgen: warning: aborted {stalled} relay workers still blocked after the window \
             (is the proxy still relaying?)"
        );
    }

    let mib_per_sec = bytes as f64 / 1024.0 / 1024.0 / elapsed.as_secs_f64();
    let gbit_per_sec = bytes as f64 * 8.0 / 1e9 / elapsed.as_secs_f64();
    if options.json {
        println!(
            "{{\"scenario\":\"throughput\",\"connections\":{},\"payload\":{},\"seconds\":{:.2},\"echoed_bytes\":{},\"mib_per_sec\":{:.1},\"gbit_per_sec\":{:.3}}}",
            options.connections,
            payload,
            elapsed.as_secs_f64(),
            bytes,
            mib_per_sec,
            gbit_per_sec
        );
    } else {
        println!(
            "throughput: {} connections x {} B chunks for {:.1}s",
            options.connections,
            payload,
            elapsed.as_secs_f64()
        );
        println!(
            "  echoed {:.1} MiB total -> {:.1} MiB/s ({:.3} Gbit/s) per direction",
            bytes as f64 / 1024.0 / 1024.0,
            mib_per_sec,
            gbit_per_sec
        );
    }
    Ok(())
}

async fn run_handshakes(
    options: &Options,
    proxy: SocketAddr,
    credentials: Option<(&'static str, &'static str)>,
    echo: SocketAddr,
) -> Result<(), String> {
    let socket_errors = Arc::new(AtomicU64::new(0));
    let socks_errors = Arc::new(AtomicU64::new(0));
    let started = Instant::now();
    let deadline = started + options.duration;

    let mut workers = Vec::with_capacity(options.connections);
    for _ in 0..options.connections {
        let socket_errors = socket_errors.clone();
        let socks_errors = socks_errors.clone();
        workers.push(tokio::spawn(async move {
            let mut latencies_us = Vec::new();
            loop {
                let attempt = Instant::now();
                let remaining = deadline.saturating_duration_since(attempt);
                if remaining.is_zero() {
                    break;
                }
                // Bound each attempt by the remaining window so a slow
                // handshake cannot stretch the measurement period; an attempt
                // cut off by the closing window is censored, not a failure.
                match tokio::time::timeout(remaining, socks_connect(proxy, credentials, echo)).await
                {
                    Ok(Ok(stream)) => {
                        latencies_us.push(attempt.elapsed().as_micros() as u64);
                        drop(stream);
                    }
                    // Local socket failures (ephemeral port exhaustion) are
                    // environment limits, not proxy verdicts; count apart.
                    // Refused connections count as proxy failures: the
                    // preflight check passed, so the proxy went away mid-run.
                    Ok(Err(e))
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::AddrInUse | std::io::ErrorKind::AddrNotAvailable
                        ) =>
                    {
                        socket_errors.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(Err(_)) => {
                        socks_errors.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => break,
                }
            }
            latencies_us
        }));
    }

    let mut latencies = Vec::new();
    for worker in workers {
        let mut worker_latencies = worker.await.map_err(|e| format!("worker panicked: {e}"))?;
        latencies.append(&mut worker_latencies);
    }
    let elapsed = started.elapsed();
    latencies.sort_unstable();
    let completed = latencies.len() as u64;
    let socket_failed = socket_errors.load(Ordering::Relaxed);
    let socks_failed = socks_errors.load(Ordering::Relaxed);
    let rate = completed as f64 / elapsed.as_secs_f64();
    let auth = match options.auth {
        AuthMode::None => "none",
        AuthMode::Plain => "plain",
        AuthMode::Argon2 => "argon2",
    };

    if options.json {
        println!(
            "{{\"scenario\":\"handshakes\",\"auth\":\"{}\",\"connections\":{},\"seconds\":{:.2},\"completed\":{},\"socket_errors\":{},\"socks_errors\":{},\"per_sec\":{:.1},\"p50_us\":{},\"p95_us\":{},\"p99_us\":{}}}",
            auth,
            options.connections,
            elapsed.as_secs_f64(),
            completed,
            socket_failed,
            socks_failed,
            rate,
            percentile(&latencies, 50),
            percentile(&latencies, 95),
            percentile(&latencies, 99)
        );
    } else {
        println!(
            "handshakes (auth={}): {} workers for {:.1}s",
            auth,
            options.connections,
            elapsed.as_secs_f64()
        );
        println!(
            "  {} completed, {} socket errors, {} socks errors -> {:.1}/s",
            completed, socket_failed, socks_failed, rate
        );
        println!(
            "  latency p50 {:.1} ms, p95 {:.1} ms, p99 {:.1} ms",
            percentile(&latencies, 50) as f64 / 1000.0,
            percentile(&latencies, 95) as f64 / 1000.0,
            percentile(&latencies, 99) as f64 / 1000.0
        );
        if socket_failed > 0 {
            println!(
                "  note: socket errors usually mean ephemeral-port exhaustion (TIME_WAIT); \
                 let the OS recover between runs"
            );
        }
    }
    Ok(())
}

async fn run_udp(
    options: &Options,
    proxy: SocketAddr,
    credentials: Option<(&'static str, &'static str)>,
) -> Result<(), String> {
    let payload = options.payload.unwrap_or(DEFAULT_UDP_PAYLOAD);
    let echo = spawn_udp_echo().await?;

    // The control connection must stay open for the association's lifetime.
    let mut control = with_setup_timeout(socks_handshake(proxy, credentials))
        .await
        .map_err(|e| format!("associate handshake: {e}"))?;
    let relay = with_setup_timeout(socks_request(
        &mut control,
        0x03,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    ))
    .await
    .map_err(|e| format!("udp associate: {e}"))?;

    // Bind to the unspecified address of the relay's family so datagrams
    // route correctly when the proxy is reached via a non-loopback or IPv6
    // address (the OS picks the right source for the connected relay).
    let bind_addr: SocketAddr = if relay.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| format!("bind udp client: {e}"))?;
    socket
        .connect(relay)
        .await
        .map_err(|e| format!("connect udp client: {e}"))?;
    let socket = Arc::new(socket);

    let mut datagram = Vec::with_capacity(10 + payload);
    datagram.extend_from_slice(&udp_header(echo));
    datagram.resize(10 + payload, 0x5a);

    let started = Instant::now();
    let deadline = started + options.duration;
    let sender_socket = socket.clone();
    let sender = tokio::spawn(async move {
        let mut sent: u64 = 0;
        'window: loop {
            // The batch amortises the yield, not the deadline check: every
            // send re-checks the window so backpressure cannot stretch it.
            for _ in 0..64 {
                if Instant::now() >= deadline {
                    break 'window;
                }
                if sender_socket.send(&datagram).await.is_err() {
                    return sent;
                }
                sent += 1;
            }
            // Give the receiver and the relay a fair chance to drain.
            tokio::task::yield_now().await;
        }
        sent
    });

    // Echoes of packets sent late in the window are still in flight when the
    // sender stops; drain them briefly, but never receive unbounded.
    let drain_deadline = deadline + Duration::from_millis(500);
    let receiver = tokio::spawn(async move {
        let mut received: u64 = 0;
        let mut buf = vec![0u8; 65536];
        loop {
            match tokio::time::timeout(Duration::from_millis(300), socket.recv(&mut buf)).await {
                Ok(Ok(n)) if n > 10 => {
                    received += 1;
                    if Instant::now() >= drain_deadline {
                        break;
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(_)) | Err(_) => {
                    if Instant::now() >= deadline {
                        break;
                    }
                }
            }
        }
        received
    });

    let sent = sender.await.map_err(|e| format!("sender panicked: {e}"))?;
    // The send window defines the measurement period; the receiver only
    // drains in-flight echoes after it.
    let elapsed = started.elapsed();
    let received = receiver
        .await
        .map_err(|e| format!("receiver panicked: {e}"))?;
    drop(control);

    let sent_pps = sent as f64 / elapsed.as_secs_f64();
    let received_pps = received as f64 / elapsed.as_secs_f64();
    let delivered = if sent == 0 {
        0.0
    } else {
        received as f64 * 100.0 / sent as f64
    };
    if options.json {
        println!(
            "{{\"scenario\":\"udp\",\"payload\":{},\"seconds\":{:.2},\"sent\":{},\"received\":{},\"sent_pps\":{:.0},\"received_pps\":{:.0},\"delivered_pct\":{:.1}}}",
            payload,
            elapsed.as_secs_f64(),
            sent,
            received,
            sent_pps,
            received_pps,
            delivered
        );
    } else {
        println!(
            "udp associate: {} B payloads for {:.1}s",
            payload,
            elapsed.as_secs_f64()
        );
        println!(
            "  sent {} ({:.0} pps), echoed back {} ({:.0} pps), delivered {:.1}%",
            sent, sent_pps, received, received_pps, delivered
        );
    }
    Ok(())
}

fn percentile(sorted: &[u64], pct: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let index = (sorted.len() * pct).div_ceil(100).saturating_sub(1);
    sorted[index.min(sorted.len() - 1)]
}
