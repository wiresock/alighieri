//! End-to-end integration tests for the Alighieri SOCKS5 proxy.
//!
//! These tests spin up real TCP listeners and exercise the full proxy path:
//! handshake → method selection → (optional auth) → request → relay.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use alighieri::auth::UserDb;
use alighieri::config::Config;
use alighieri::server::Server;
use alighieri::socks5::{self, TargetAddr};

/// A minimal permissive configuration. The listen address uses port 0 so the
/// kernel assigns an ephemeral port; the real address is obtained from
/// `Server::local_addr()` after binding.
fn permissive_config() -> Config {
    Config::parse(
        r#"
internal: 127.0.0.1:0
external: 127.0.0.1
socksmethod: none
client pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }
socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    protocol: tcp udp
    command: connect udpassociate
}
"#,
    )
    .unwrap()
}

/// Starts the proxy, queries the actual bound address, then spawns the run loop.
async fn start_proxy() -> (tokio::task::JoinHandle<Option<()>>, SocketAddr) {
    let server = Server::bind(permissive_config()).await.unwrap();
    let addr = server.local_addr().unwrap();
    let handle = tokio::spawn(async move { server.run().await.ok() });
    // Give the server time to enter its accept loop.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (handle, addr)
}

async fn start_proxy_with_config(cfg: Config) -> (tokio::task::JoinHandle<Option<()>>, SocketAddr) {
    let server = Server::bind(cfg).await.unwrap();
    let addr = server.local_addr().unwrap();
    let handle = tokio::spawn(async move { server.run().await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (handle, addr)
}

/// Performs a SOCKS5 handshake with `Method::None` (0x00) on `stream`.
async fn handshake_noauth(stream: &mut TcpStream) {
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, [0x05, 0x00]);
}

async fn handshake_username(stream: &mut TcpStream, username: &str, password: &str) -> bool {
    stream.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut selection = [0u8; 2];
    stream.read_exact(&mut selection).await.unwrap();
    assert_eq!(selection, [0x05, 0x02]);

    let mut auth = vec![0x01, username.len() as u8];
    auth.extend_from_slice(username.as_bytes());
    auth.push(password.len() as u8);
    auth.extend_from_slice(password.as_bytes());
    stream.write_all(&auth).await.unwrap();

    let mut status = [0u8; 2];
    stream.read_exact(&mut status).await.unwrap();
    assert_eq!(status[0], 0x01);
    status[1] == 0x00
}

async fn expect_connection_closed(mut stream: TcpStream) {
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut buf = [0u8; 2];
    let res = tokio::time::timeout(Duration::from_millis(500), stream.read(&mut buf)).await;
    match res {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("expected closed connection, read {n} bytes"),
        Err(_) => panic!("connection stayed open instead of being rate limited"),
    }
}

/// Sends a CONNECT request for `dest` and returns the bound address from the
/// reply. Panics on failure.
async fn request_connect(stream: &mut TcpStream, dest: SocketAddr) -> SocketAddr {
    let mut req = vec![0x05, 0x01, 0x00];
    match dest {
        SocketAddr::V4(v4) => {
            req.push(0x01);
            req.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            req.push(0x04);
            req.extend_from_slice(&v6.ip().octets());
        }
    }
    req.extend_from_slice(&dest.port().to_be_bytes());
    stream.write_all(&req).await.unwrap();

    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    assert_eq!(
        reply[1], 0x00,
        "CONNECT failed with reply 0x{:02x}",
        reply[1]
    );
    assert_eq!(reply[2], 0x00); // RSV

    let atyp = reply[3];
    let bound = match atyp {
        0x01 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await.unwrap();
            let port = stream.read_u16().await.unwrap();
            SocketAddr::new(std::net::IpAddr::V4(octets.into()), port)
        }
        0x04 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await.unwrap();
            let port = stream.read_u16().await.unwrap();
            SocketAddr::new(std::net::IpAddr::V6(octets.into()), port)
        }
        other => panic!("unexpected ATYP {other}"),
    };
    bound
}

async fn request_udp_associate(stream: &mut TcpStream) -> SocketAddr {
    let mut req = vec![0x05, 0x03, 0x00, 0x01];
    req.extend_from_slice(&[0, 0, 0, 0]);
    req.extend_from_slice(&0u16.to_be_bytes());
    stream.write_all(&req).await.unwrap();

    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    assert_eq!(
        reply[1], 0x00,
        "UDP ASSOCIATE failed with reply 0x{:02x}",
        reply[1]
    );
    assert_eq!(reply[2], 0x00);

    match reply[3] {
        0x01 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await.unwrap();
            let port = stream.read_u16().await.unwrap();
            SocketAddr::new(std::net::IpAddr::V4(octets.into()), port)
        }
        0x04 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await.unwrap();
            let port = stream.read_u16().await.unwrap();
            SocketAddr::new(std::net::IpAddr::V6(octets.into()), port)
        }
        other => panic!("unexpected ATYP {other}"),
    }
}

/// Starts a TCP echo server and returns its local address.
async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 512];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            stream.write_all(&buf[..n]).await.unwrap();
        }
    });
    addr
}

async fn start_udp_echo_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            socket.send_to(&buf[..n], peer).await.unwrap();
        }
    });
    addr
}

/// IPv6 UDP echo server on `[::1]:0`. Returns `None` when IPv6 loopback is
/// unavailable on the host, so the caller can skip rather than fail.
async fn start_udp_echo_server_v6() -> Option<SocketAddr> {
    let socket = UdpSocket::bind("[::1]:0").await.ok()?;
    let addr = socket.local_addr().ok()?;
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            socket.send_to(&buf[..n], peer).await.unwrap();
        }
    });
    Some(addr)
}

#[tokio::test]
async fn full_connect_relay_ipv4() {
    let (_handle, proxy_addr) = start_proxy().await;
    let echo = start_echo_server().await;

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    handshake_noauth(&mut client).await;
    let _bound = request_connect(&mut client, echo).await;

    let payload = b"Hello through SOCKS5!";
    client.write_all(payload).await.unwrap();
    client.shutdown().await.ok();

    let mut received = Vec::new();
    client.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, payload);
}

#[tokio::test]
async fn connect_relays_under_per_rule_bandwidth() {
    // A generous per-rule bandwidth (well above the tiny payload's burst) must
    // not disturb relaying — it proves the per-session rule bucket is wired into
    // the CONNECT relay without shaping the traffic noticeably.
    let cfg = Config::parse(
        r#"
internal: 127.0.0.1:0
external: 127.0.0.1
socksmethod: none
client pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }
socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    command: connect
    bandwidth: 10MiB/1
}
"#,
    )
    .unwrap();
    let (_proxy, addr) = start_proxy_with_config(cfg).await;
    let echo = start_echo_server().await;

    let mut client = TcpStream::connect(addr).await.unwrap();
    handshake_noauth(&mut client).await;
    let _bound = request_connect(&mut client, echo).await;

    let payload = b"shaped but flowing";
    client.write_all(payload).await.unwrap();
    client.shutdown().await.ok();

    let mut received = Vec::new();
    client.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, payload);
}

#[tokio::test]
async fn connection_rate_limit_rejects_excess_client_connections() {
    let cfg = Config::parse(
        r#"
internal: 127.0.0.1:0
external: 127.0.0.1
socksmethod: none
ratelimit.connectionrate: 1/60
client pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }
socks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 command: connect }
"#,
    )
    .unwrap();
    let (_handle, proxy_addr) = start_proxy_with_config(cfg).await;

    let mut first = TcpStream::connect(proxy_addr).await.unwrap();
    handshake_noauth(&mut first).await;

    let second = TcpStream::connect(proxy_addr).await.unwrap();
    expect_connection_closed(second).await;
}

#[tokio::test]
async fn auth_failure_rate_limit_blocks_later_connections() {
    let mut users = tempfile::NamedTempFile::new().unwrap();
    writeln!(users, "alice:s3cr3t").unwrap();
    let cfg = Config::parse(&format!(
        r#"
internal: 127.0.0.1:0
external: 127.0.0.1
socksmethod: username
userlist: {}
ratelimit.authfailurerate: 1/60
client pass {{ from: 0.0.0.0/0 to: 0.0.0.0/0 }}
socks pass {{ from: 0.0.0.0/0 to: 0.0.0.0/0 command: connect }}
"#,
        users.path().display()
    ))
    .unwrap();
    let (_handle, proxy_addr) = start_proxy_with_config(cfg).await;

    let mut first = TcpStream::connect(proxy_addr).await.unwrap();
    assert!(!handshake_username(&mut first, "alice", "wrong").await);

    let second = TcpStream::connect(proxy_addr).await.unwrap();
    expect_connection_closed(second).await;
}

#[tokio::test]
async fn username_password_auth_success_allows_connect() {
    let mut users = tempfile::NamedTempFile::new().unwrap();
    writeln!(users, "alice:s3cr3t").unwrap();
    let cfg = Config::parse(&format!(
        r#"
internal: 127.0.0.1:0
external: 127.0.0.1
socksmethod: username
userlist: {}
client pass {{ from: 0.0.0.0/0 to: 0.0.0.0/0 }}
socks pass {{ from: 0.0.0.0/0 to: 0.0.0.0/0 command: connect }}
"#,
        users.path().display()
    ))
    .unwrap();
    let (_handle, proxy_addr) = start_proxy_with_config(cfg).await;
    let echo = start_echo_server().await;

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    assert!(handshake_username(&mut client, "alice", "s3cr3t").await);
    let _bound = request_connect(&mut client, echo).await;

    client.write_all(b"auth ok").await.unwrap();
    let mut received = [0u8; 7];
    client.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"auth ok");
}

#[tokio::test]
async fn argon2_username_password_auth_success_allows_connect() {
    let mut users = tempfile::NamedTempFile::new().unwrap();
    let line = UserDb::hash_user_line("alice", "s3cr3t").unwrap();
    writeln!(users, "{line}").unwrap();
    let cfg = Config::parse(&format!(
        r#"
internal: 127.0.0.1:0
external: 127.0.0.1
socksmethod: username
userlist: {}
client pass {{ from: 0.0.0.0/0 to: 0.0.0.0/0 }}
socks pass {{ from: 0.0.0.0/0 to: 0.0.0.0/0 command: connect }}
"#,
        users.path().display()
    ))
    .unwrap();
    let (_handle, proxy_addr) = start_proxy_with_config(cfg).await;
    let echo = start_echo_server().await;

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    assert!(handshake_username(&mut client, "alice", "s3cr3t").await);
    let _bound = request_connect(&mut client, echo).await;

    client.write_all(b"argon ok").await.unwrap();
    let mut received = [0u8; 8];
    client.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"argon ok");
}

#[tokio::test]
async fn username_password_auth_failure_closes_connection() {
    let mut users = tempfile::NamedTempFile::new().unwrap();
    writeln!(users, "alice:s3cr3t").unwrap();
    let cfg = Config::parse(&format!(
        r#"
internal: 127.0.0.1:0
external: 127.0.0.1
socksmethod: username
userlist: {}
client pass {{ from: 0.0.0.0/0 to: 0.0.0.0/0 }}
socks pass {{ from: 0.0.0.0/0 to: 0.0.0.0/0 command: connect }}
"#,
        users.path().display()
    ))
    .unwrap();
    let (_handle, proxy_addr) = start_proxy_with_config(cfg).await;

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    assert!(!handshake_username(&mut client, "alice", "wrong").await);
    let mut buf = [0u8; 1];
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(n, 0, "expected EOF after failed authentication");
}

#[tokio::test]
async fn connect_denied_by_socks_rule() {
    let cfg = Config::parse(
        r#"
internal: 127.0.0.1:0
external: 127.0.0.1
client pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }
socks block { from: 0.0.0.0/0 to: 0.0.0.0/0 }
"#,
    )
    .unwrap();
    let server = Server::bind(cfg).await.unwrap();
    let proxy_addr = server.local_addr().unwrap();
    tokio::spawn(async move { server.run().await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let echo = start_echo_server().await;

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    handshake_noauth(&mut client).await;

    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(
        &echo
            .ip()
            .to_string()
            .parse::<std::net::Ipv4Addr>()
            .unwrap()
            .octets(),
    );
    req.extend_from_slice(&echo.port().to_be_bytes());
    client.write_all(&req).await.unwrap();

    let mut reply = [0u8; 4];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x02); // ConnectionNotAllowed
}

#[tokio::test]
async fn connect_to_ipv4_mapped_loopback_is_blocked_by_v4_cidr_rule() {
    // A `to: 127.0.0.0/8` block must catch the IPv4-mapped form
    // ::ffff:127.0.0.1, or a client bypasses loopback protection (SSRF). The
    // pass rule matches both families, so without canonicalisation the mapped
    // address slipped past the v4 block straight to it.
    let cfg = Config::parse(
        r#"
internal: 127.0.0.1:0
external: 127.0.0.1
client pass { }
socks block { to: 127.0.0.0/8 }
socks pass { protocol: tcp command: connect }
"#,
    )
    .unwrap();
    let server = Server::bind(cfg).await.unwrap();
    let proxy_addr = server.local_addr().unwrap();
    tokio::spawn(async move { server.run().await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    handshake_noauth(&mut client).await;

    // CONNECT to ::ffff:127.0.0.1 (ATYP=0x04, IPv4-mapped loopback).
    let mapped: std::net::Ipv6Addr = "::ffff:127.0.0.1".parse().unwrap();
    let mut req = vec![0x05, 0x01, 0x00, 0x04];
    req.extend_from_slice(&mapped.octets());
    req.extend_from_slice(&9u16.to_be_bytes());
    client.write_all(&req).await.unwrap();

    let mut reply = [0u8; 4];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(
        reply[1], 0x02,
        "mapped loopback must be blocked, got reply 0x{:02x}",
        reply[1]
    );
}

#[tokio::test]
async fn udp_associate_handshake() {
    let (_handle, proxy_addr) = start_proxy().await;

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    handshake_noauth(&mut client).await;

    // UDP ASSOCIATE request (dest is usually ignored; 0.0.0.0:0 is conventional).
    let mut req = vec![0x05, 0x03, 0x00, 0x01];
    req.extend_from_slice(&[0, 0, 0, 0]);
    req.extend_from_slice(&0u16.to_be_bytes());
    client.write_all(&req).await.unwrap();

    let mut reply = [0u8; 4];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(
        reply[1], 0x00,
        "UDP ASSOCIATE failed with reply 0x{:02x}",
        reply[1]
    );
    assert_eq!(reply[3], 0x01); // ATYP IPv4

    let mut bound_octets = [0u8; 4];
    client.read_exact(&mut bound_octets).await.unwrap();
    let _bound_port = client.read_u16().await.unwrap();

    client.shutdown().await.ok();
}

#[tokio::test]
async fn udp_associate_relays_datagrams() {
    let (_handle, proxy_addr) = start_proxy().await;
    let echo = start_udp_echo_server().await;

    let mut control = TcpStream::connect(proxy_addr).await.unwrap();
    handshake_noauth(&mut control).await;
    let relay_addr = request_udp_associate(&mut control).await;

    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut datagram = socks5::build_udp_header(&TargetAddr::Ip(echo));
    datagram.extend_from_slice(b"udp ping");
    udp.send_to(&datagram, relay_addr).await.unwrap();

    let mut buf = [0u8; 1024];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), udp.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let header = socks5::parse_udp_header(&buf[..n]).unwrap();
    assert_eq!(header.dest, TargetAddr::Ip(echo));
    assert_eq!(&buf[header.payload_offset..n], b"udp ping");
}

/// On a dual-stack `[::]` listener an IPv4 client is accepted as an IPv4-mapped
/// peer, so the UDP relay socket is bound on a `::ffff:` (AF_INET6) address. This
/// exercises the reply path for that case — the locked client endpoint must stay
/// sendable on the v6 relay socket (a plain-IPv4 endpoint cannot be `send_to` on
/// AF_INET6). Skipped where dual-stack v4-mapped accept is unavailable (e.g.
/// Windows' default `IPV6_V6ONLY`, or a host without IPv6), detected by checking
/// that the connected peer actually arrived IPv4-mapped.
#[tokio::test]
async fn udp_associate_relays_for_mapped_client_on_dual_stack_listener() {
    let cfg = Config::parse(
        r#"
internal: [::]:0
external: 127.0.0.1
socksmethod: none
client pass { }
socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    protocol: tcp udp
    command: connect udpassociate
}
"#,
    )
    .unwrap();
    let server = match Server::bind(cfg).await {
        Ok(s) => s,
        Err(_) => {
            eprintln!("skipping udp_associate_relays_for_mapped_client_on_dual_stack_listener: cannot bind [::]:0");
            return;
        }
    };
    let listen = server.local_addr().unwrap();
    let _handle = tokio::spawn(async move { server.run().await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Reach the dual-stack listener over IPv4 so the peer arrives `::ffff:`-mapped.
    let v4_listen = SocketAddr::new("127.0.0.1".parse().unwrap(), listen.port());
    let Ok(mut control) = TcpStream::connect(v4_listen).await else {
        eprintln!("skipping udp_associate_relays_for_mapped_client_on_dual_stack_listener: no IPv4 path to [::] listener");
        return;
    };
    handshake_noauth(&mut control).await;
    let relay_addr = request_udp_associate(&mut control).await;

    let echo = start_udp_echo_server().await;
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut datagram = socks5::build_udp_header(&TargetAddr::Ip(echo));
    datagram.extend_from_slice(b"mapped ping");
    // The advertised relay address may be `::ffff:127.0.0.1` or plain `127.0.0.1`;
    // send over IPv4 either way.
    let relay_v4 = SocketAddr::new(relay_addr.ip().to_canonical(), relay_addr.port());
    udp.send_to(&datagram, relay_v4).await.unwrap();

    let mut buf = [0u8; 1024];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), udp.recv_from(&mut buf))
        .await
        .expect("relay did not reply to the IPv4-mapped client on the dual-stack socket")
        .unwrap();
    let header = socks5::parse_udp_header(&buf[..n]).unwrap();
    assert_eq!(header.dest, TargetAddr::Ip(echo));
    assert_eq!(&buf[header.payload_offset..n], b"mapped ping");
}

/// The default `external` (`0.0.0.0`) yields a dual-stack outbound, so the
/// common case — a v4 destination — must still relay through the `::ffff:`
/// mapped-send path. Guards against the dual-stack change breaking v4 UDP.
#[tokio::test]
async fn udp_associate_dual_stack_outbound_reaches_ipv4() {
    let echo = start_udp_echo_server().await;
    let cfg = Config::parse(
        r#"
internal: 127.0.0.1:0
external: 0.0.0.0
socksmethod: none
client pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }
socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    protocol: tcp udp
    command: connect udpassociate
}
"#,
    )
    .unwrap();
    let (_handle, proxy_addr) = start_proxy_with_config(cfg).await;

    let mut control = TcpStream::connect(proxy_addr).await.unwrap();
    handshake_noauth(&mut control).await;
    let relay_addr = request_udp_associate(&mut control).await;

    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut datagram = socks5::build_udp_header(&TargetAddr::Ip(echo));
    datagram.extend_from_slice(b"udp4 via dualstack");
    udp.send_to(&datagram, relay_addr).await.unwrap();

    let mut buf = [0u8; 1024];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), udp.recv_from(&mut buf))
        .await
        .expect("no reply: dual-stack outbound failed to reach the IPv4 destination")
        .unwrap();
    let header = socks5::parse_udp_header(&buf[..n]).unwrap();
    assert_eq!(header.dest, TargetAddr::Ip(echo));
    assert_eq!(&buf[header.payload_offset..n], b"udp4 via dualstack");
}

/// With an unspecified `external` the outbound UDP socket is dual-stack, so a
/// v4 client must be able to relay to an IPv6 destination (regression test for
/// the single-IPv4-socket bug that silently dropped IPv6 UDP targets).
#[tokio::test]
async fn udp_associate_relays_to_ipv6_destination() {
    let Some(echo) = start_udp_echo_server_v6().await else {
        eprintln!("skipping udp_associate_relays_to_ipv6_destination: no IPv6 loopback");
        return;
    };
    let cfg = Config::parse(
        r#"
internal: 127.0.0.1:0
external: 0.0.0.0
socksmethod: none
client pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }
socks pass {
    from: 0.0.0.0/0 to: ::/0
    protocol: tcp udp
    command: connect udpassociate
}
"#,
    )
    .unwrap();
    let (_handle, proxy_addr) = start_proxy_with_config(cfg).await;

    let mut control = TcpStream::connect(proxy_addr).await.unwrap();
    handshake_noauth(&mut control).await;
    let relay_addr = request_udp_associate(&mut control).await;

    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut datagram = socks5::build_udp_header(&TargetAddr::Ip(echo));
    datagram.extend_from_slice(b"udp6 ping");
    udp.send_to(&datagram, relay_addr).await.unwrap();

    let mut buf = [0u8; 1024];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), udp.recv_from(&mut buf))
        .await
        .expect("no reply: dual-stack outbound failed to reach the IPv6 destination")
        .unwrap();
    let header = socks5::parse_udp_header(&buf[..n]).unwrap();
    assert_eq!(header.dest, TargetAddr::Ip(echo));
    assert_eq!(&buf[header.payload_offset..n], b"udp6 ping");
}

/// A literal IPv4 `udp.advertise` must be encoded as the reply `BND.ADDR`, with
/// the real (nonzero) relay port preserved. This is the NAT case: the client is
/// handed the proxy's public address instead of its private bind, but the same
/// port it must send datagrams to.
#[tokio::test]
async fn udp_associate_advertises_literal_ipv4() {
    let cfg = Config::parse(
        r#"
internal: 127.0.0.1:0
external: 127.0.0.1
socksmethod: none
udp.advertise: 203.0.113.7
client pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }
socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    protocol: tcp udp
    command: connect udpassociate
}
"#,
    )
    .unwrap();
    let (_handle, proxy_addr) = start_proxy_with_config(cfg).await;

    let mut control = TcpStream::connect(proxy_addr).await.unwrap();
    handshake_noauth(&mut control).await;
    let advertised = request_udp_associate(&mut control).await;

    assert_eq!(
        advertised.ip(),
        "203.0.113.7".parse::<std::net::IpAddr>().unwrap(),
        "the configured public IP must replace the bound relay address"
    );
    assert_ne!(
        advertised.port(),
        0,
        "the real relay port must be preserved"
    );
}

/// When `udp.advertise` has no address for the client's family — here a v6-only
/// literal for a v4 client — the reply must fall back to the bound relay address
/// rather than advertise an unreachable family. (Guards the `None` branch of
/// `advertise_ip_for_family` end to end.)
#[tokio::test]
async fn udp_associate_advertise_wrong_family_falls_back_to_relay() {
    let cfg = Config::parse(
        r#"
internal: 127.0.0.1:0
external: 127.0.0.1
socksmethod: none
udp.advertise: 2001:db8::1
client pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }
socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    protocol: tcp udp
    command: connect udpassociate
}
"#,
    )
    .unwrap();
    let (_handle, proxy_addr) = start_proxy_with_config(cfg).await;

    let mut control = TcpStream::connect(proxy_addr).await.unwrap();
    handshake_noauth(&mut control).await;
    let advertised = request_udp_associate(&mut control).await;

    assert!(
        advertised.is_ipv4(),
        "a v4 client must get a v4 BND.ADDR, got {advertised}"
    );
    assert_eq!(
        advertised.ip(),
        "127.0.0.1".parse::<std::net::IpAddr>().unwrap(),
        "the bound relay address is advertised when no candidate matches the family"
    );
    assert_ne!(advertised.port(), 0);
}

/// A hostname `udp.advertise` is resolved through the async resolver at associate
/// time (config load does no DNS). The proxy binds on a *distinct* loopback
/// (`127.0.0.2`) so a successful resolution is distinguishable from the
/// relay-address fallback: the advertised IP must be one of the IPv4 addresses
/// `localhost` actually resolves to (never the `127.0.0.2` relay), which fails if
/// resolution regressed to the bound relay. The expected set is derived from the
/// same system resolver the proxy uses (`getaddrinfo`), so the test does not
/// assume `localhost` maps to `127.0.0.1`. Skipped where `127.0.0.2` is not a
/// usable loopback (default macOS) or `localhost` has no IPv4 address.
#[tokio::test]
async fn udp_associate_advertises_resolved_hostname() {
    // Derive what `localhost` resolves to from the same source the proxy uses
    // (getaddrinfo), rather than hard-coding 127.0.0.1. `tokio::net::lookup_host`
    // runs the blocking resolver on Tokio's blocking pool, so the async test
    // thread is not blocked. A resolver *error* is a genuine fault (localhost must
    // resolve on a working system), so fail loudly rather than skip — only the
    // explicit platform gaps below (no IPv4 localhost, 127.0.0.2 unbindable) are
    // skip conditions.
    let localhost_v4: Vec<std::net::IpAddr> = tokio::net::lookup_host(("localhost", 0))
        .await
        .expect("resolving localhost must succeed; a resolver failure is a real fault, not a skip")
        .map(|s| s.ip())
        .filter(std::net::IpAddr::is_ipv4)
        .collect();
    if localhost_v4.is_empty() {
        eprintln!(
            "skipping udp_associate_advertises_resolved_hostname: localhost has no IPv4 address"
        );
        return;
    }
    // The "resolution applied, not the relay fallback" assertion below holds only
    // because the relay bind IP (127.0.0.2) is not one of localhost's addresses.
    // A custom /etc/hosts mapping localhost to 127.0.0.2 would make resolved and
    // fallback indistinguishable, so skip rather than risk a false pass.
    let relay_ip = "127.0.0.2".parse::<std::net::IpAddr>().unwrap();
    if localhost_v4.contains(&relay_ip) {
        eprintln!(
            "skipping udp_associate_advertises_resolved_hostname: localhost resolves to the 127.0.0.2 relay IP"
        );
        return;
    }
    let cfg = Config::parse(
        r#"
internal: 127.0.0.2:0
external: 127.0.0.1
socksmethod: none
udp.advertise: localhost
client pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }
socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    protocol: tcp udp
    command: connect udpassociate
}
"#,
    )
    .unwrap();
    // Skip only the known platform gap — 127.0.0.2 not being a usable loopback
    // (default macOS configures only 127.0.0.1) — by probing it directly. Any
    // other bind failure must surface as a test failure, not a silent skip, so
    // the proxy itself is started through start_proxy_with_config (which unwraps).
    if TcpListener::bind("127.0.0.2:0").await.is_err() {
        eprintln!(
            "skipping udp_associate_advertises_resolved_hostname: 127.0.0.2 loopback unavailable"
        );
        return;
    }
    let (_handle, proxy_addr) = start_proxy_with_config(cfg).await;

    let mut control = TcpStream::connect(proxy_addr).await.unwrap();
    handshake_noauth(&mut control).await;
    let advertised = request_udp_associate(&mut control).await;

    assert!(
        localhost_v4.contains(&advertised.ip()),
        "advertised {} must be one of localhost's IPv4 addresses {localhost_v4:?} \
         (resolution applied, not the 127.0.0.2 relay fallback)",
        advertised.ip()
    );
    assert_ne!(advertised.port(), 0);
}

/// A `udp.advertise` hostname that cannot be resolved must not fail the
/// association: it falls back to the bound relay address at associate time. The
/// `.invalid` TLD never resolves (RFC 6761); a short `dns.timeout` bounds the
/// lookup so the fallback path stays fast.
#[tokio::test]
async fn udp_associate_unresolvable_advertise_falls_back_to_relay() {
    let cfg = Config::parse(
        r#"
internal: 127.0.0.1:0
external: 127.0.0.1
socksmethod: none
dns.timeout: 1
udp.advertise: alighieri-no-such-host.invalid
client pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }
socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    protocol: tcp udp
    command: connect udpassociate
}
"#,
    )
    .unwrap();
    let (_handle, proxy_addr) = start_proxy_with_config(cfg).await;

    let mut control = TcpStream::connect(proxy_addr).await.unwrap();
    handshake_noauth(&mut control).await;
    let advertised =
        tokio::time::timeout(Duration::from_secs(5), request_udp_associate(&mut control))
            .await
            .expect("unresolvable udp.advertise must fall back, not hang the associate");

    assert_eq!(
        advertised.ip(),
        "127.0.0.1".parse::<std::net::IpAddr>().unwrap(),
        "an unresolvable advertise host must fall back to the bound relay address"
    );
    assert_ne!(advertised.port(), 0);
}

/// A v6 client with a v6 `udp.advertise` literal must receive that v6 address in
/// the reply (ATYP = 0x04) with the relay port preserved, proving family
/// selection picks the matching candidate for a v6 peer. Skipped where IPv6
/// loopback is unavailable.
#[tokio::test]
async fn udp_associate_advertises_literal_ipv6_for_v6_client() {
    let cfg = Config::parse(
        r#"
internal: [::1]:0
external: ::1
socksmethod: none
udp.advertise: 2001:db8::1
client pass { }
socks pass {
    from: ::/0 to: ::/0
    protocol: tcp udp
    command: connect udpassociate
}
"#,
    )
    .unwrap();
    // Skip only when IPv6 loopback is genuinely unavailable, probed directly;
    // any other bind failure must fail the test rather than skip, so the proxy is
    // started through start_proxy_with_config (which unwraps).
    if TcpListener::bind("[::1]:0").await.is_err() {
        eprintln!("skipping udp_associate_advertises_literal_ipv6_for_v6_client: no IPv6 loopback");
        return;
    }
    let (_handle, proxy_addr) = start_proxy_with_config(cfg).await;

    let mut control = TcpStream::connect(proxy_addr).await.unwrap();
    handshake_noauth(&mut control).await;
    let advertised = request_udp_associate(&mut control).await;

    assert_eq!(
        advertised.ip(),
        "2001:db8::1".parse::<std::net::IpAddr>().unwrap(),
        "the v6 client must be advertised the matching v6 candidate"
    );
    assert_ne!(
        advertised.port(),
        0,
        "the real relay port must be preserved"
    );
}

/// A `command: connect` only policy must reject UDP ASSOCIATE up front with
/// "connection not allowed by ruleset" — not establish an association that
/// lingers until the idle timeout while every datagram is dropped.
#[tokio::test]
async fn udp_associate_denied_by_connect_only_policy() {
    let cfg = Config::parse(
        r#"
internal: 127.0.0.1:0
external: 127.0.0.1
socksmethod: none
client pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }
socks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 command: connect }
"#,
    )
    .unwrap();
    let (_handle, proxy_addr) = start_proxy_with_config(cfg).await;

    let mut control = TcpStream::connect(proxy_addr).await.unwrap();
    handshake_noauth(&mut control).await;

    // UDP ASSOCIATE with the usual 0.0.0.0:0 placeholder destination.
    let mut req = vec![0x05, 0x03, 0x00, 0x01];
    req.extend_from_slice(&[0, 0, 0, 0]);
    req.extend_from_slice(&0u16.to_be_bytes());
    control.write_all(&req).await.unwrap();

    let mut reply = [0u8; 4];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    assert_eq!(
        reply[1], 0x02,
        "UDP ASSOCIATE should be denied by ruleset, got reply 0x{:02x}",
        reply[1]
    );
}

#[tokio::test]
async fn udp_associate_rejects_second_client_port_from_same_ip() {
    let (_handle, proxy_addr) = start_proxy().await;
    let echo = start_udp_echo_server().await;

    let mut control = TcpStream::connect(proxy_addr).await.unwrap();
    handshake_noauth(&mut control).await;
    let relay_addr = request_udp_associate(&mut control).await;

    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let mut first_datagram = socks5::build_udp_header(&TargetAddr::Ip(echo));
    first_datagram.extend_from_slice(b"first");
    first.send_to(&first_datagram, relay_addr).await.unwrap();

    let mut buf = [0u8; 1024];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), first.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let header = socks5::parse_udp_header(&buf[..n]).unwrap();
    assert_eq!(&buf[header.payload_offset..n], b"first");

    let mut second_datagram = socks5::build_udp_header(&TargetAddr::Ip(echo));
    second_datagram.extend_from_slice(b"second");
    second.send_to(&second_datagram, relay_addr).await.unwrap();

    let blocked =
        tokio::time::timeout(Duration::from_millis(250), second.recv_from(&mut buf)).await;
    assert!(
        blocked.is_err(),
        "second UDP port should not receive a relay response"
    );
}

#[tokio::test]
async fn slow_client_is_disconnected_during_handshake() {
    let cfg = Config::parse(
        r#"
internal: 127.0.0.1:0
external: 127.0.0.1
handshaketimeout: 1
maxconnections: 1
client pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }
socks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 command: connect }
"#,
    )
    .unwrap();
    let (_handle, proxy_addr) = start_proxy_with_config(cfg).await;

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(3), client.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 0, "expected EOF after handshake timeout");
}

#[tokio::test]
async fn client_rule_blocks_untrusted_source() {
    let cfg = Config::parse(
        r#"
internal: 127.0.0.1:0
external: 127.0.0.1
client block { from: 0.0.0.0/0 to: 0.0.0.0/0 }
socks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 command: connect }
"#,
    )
    .unwrap();
    let server = Server::bind(cfg).await.unwrap();
    let proxy_addr = server.local_addr().unwrap();
    tokio::spawn(async move { server.run().await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    // The server immediately closes the connection because the client rule
    // blocks everything.
    let mut buf = [0u8; 1];
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(n, 0, "expected immediate EOF because client rule blocks");
}

#[tokio::test]
async fn metrics_endpoint_reports_connection_counters() {
    let cfg = Config::parse(
        r#"
internal: 127.0.0.1:0
external: 127.0.0.1
metrics.listen: 127.0.0.1:0
client pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }
socks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 command: connect }
"#,
    )
    .unwrap();
    let server = Server::bind(cfg).await.unwrap();
    let proxy_addr = server.local_addr().unwrap();
    let metrics_addr = server.metrics_addr().unwrap().unwrap();
    let handle = tokio::spawn(async move { server.run().await.ok() });
    let _ = wait_for_metrics(metrics_addr, |_| true).await;

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    handshake_noauth(&mut client).await;
    drop(client);

    let response = wait_for_metrics(metrics_addr, |response| {
        response.contains("alighieri_connections_accepted_total 1\n")
            && response.contains("alighieri_connections_active 0\n")
    })
    .await;
    handle.abort();

    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.contains("alighieri_connections_accepted_total 1\n"));
    assert!(response.contains("alighieri_connections_active 0\n"));
}

#[tokio::test]
async fn metrics_endpoint_reports_named_rule_hits() {
    let cfg = Config::parse(
        r#"
internal: 127.0.0.1:0
external: 127.0.0.1
metrics.listen: 127.0.0.1:0
client pass "client-any" { from: 0.0.0.0/0 to: 0.0.0.0/0 }
socks block "block-all" { from: 0.0.0.0/0 to: 0.0.0.0/0 command: connect }
"#,
    )
    .unwrap();
    let server = Server::bind(cfg).await.unwrap();
    let proxy_addr = server.local_addr().unwrap();
    let metrics_addr = server.metrics_addr().unwrap().unwrap();
    let handle = tokio::spawn(async move { server.run().await.ok() });
    let _ = wait_for_metrics(metrics_addr, |_| true).await;

    let echo = start_echo_server().await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    handshake_noauth(&mut client).await;

    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(
        &echo
            .ip()
            .to_string()
            .parse::<std::net::Ipv4Addr>()
            .unwrap()
            .octets(),
    );
    req.extend_from_slice(&echo.port().to_be_bytes());
    client.write_all(&req).await.unwrap();

    let mut reply = [0u8; 4];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x02);
    drop(client);

    let response = wait_for_metrics(metrics_addr, |response| {
        response.contains(
            "alighieri_rule_hits_total{scope=\"client\",verdict=\"pass\",line=\"5\"} 1\n",
        ) && response.contains(
            "alighieri_rule_hits_total{scope=\"socks\",verdict=\"block\",line=\"6\"} 1\n",
        ) && response.contains(
            "alighieri_rule_named_hits_total{scope=\"client\",verdict=\"pass\",line=\"5\",name=\"client-any\"} 1\n",
        ) && response.contains(
            "alighieri_rule_named_hits_total{scope=\"socks\",verdict=\"block\",line=\"6\",name=\"block-all\"} 1\n",
        )
    })
    .await;
    handle.abort();

    assert!(response.contains("name=\"client-any\""));
    assert!(response.contains("name=\"block-all\""));
}

async fn fetch_metrics(metrics_addr: SocketAddr) -> std::io::Result<String> {
    let mut metrics = TcpStream::connect(metrics_addr).await?;
    metrics
        .write_all(b"GET /metrics HTTP/1.1\r\nhost: localhost\r\n\r\n")
        .await?;
    let mut response = String::new();
    metrics.read_to_string(&mut response).await?;
    Ok(response)
}

async fn wait_for_metrics(metrics_addr: SocketAddr, ready: impl Fn(&str) -> bool) -> String {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(response) = fetch_metrics(metrics_addr).await {
                if response.starts_with("HTTP/1.1 200 OK") && ready(&response) {
                    return response;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("metrics endpoint did not become ready")
}

// ---------------------------------------------------------------------------
// TLS listener
// ---------------------------------------------------------------------------

/// Leaf certificate for `localhost` (SAN: DNS:localhost, CA:FALSE, EKU
/// serverAuth), signed by `TLS_TEST_CA`. The server presents this leaf
/// followed by the CA — the chain is assembled at write time, so the CA PEM
/// lives in exactly one place. Clients trust the CA; rustls' verifier rejects
/// CA certificates presented as end entities, so a bare self-signed CA cert
/// would not do. Both certs are backdated to 2020 and valid until 2126, so
/// clock skew on a CI or developer machine cannot make the handshake flaky.
const TLS_TEST_LEAF: &str = r#"-----BEGIN CERTIFICATE-----
MIIDTTCCAjWgAwIBAgIURQDuPY3MmGaKrbiFJlpV/RA+jIMwDQYJKoZIhvcNAQEL
BQAwHDEaMBgGA1UEAwwRYWxpZ2hpZXJpLXRlc3QtY2EwIBcNMjAwMTAxMDAwMDAw
WhgPMjEyNjAxMDEwMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAIhoiMB0/+yHm1AlM03aLlxK+a6eKVq+
VllxkZAv+uAGllWtr78Dp/gcaBM1M1vlZjw2dS+hMrQ352fQ9NkTdyzZkZViuAeL
0RIGbWIzDFpP5rf4k+JUAPysPmWFv/n6041U/B9ZMyhaRfJQ+76xZkgTxvUWnvCw
KwnEyxaPX8DyN2A2azmiuJZVxM3vQROsCrX30JeF6js3gK4h6VdAGNYy+tBdbhWj
haj/FusiB+1hEj1CP85yzlq6y2yj9LZKiqARPeeJvEJ6d76WTAytAz8eqh6iXG9K
oTpTaGadkMKExr5bzDD4g2gPJc/AU933NN+hMwU9apTBVdhC3pAjNgcCAwEAAaOB
jDCBiTAUBgNVHREEDTALgglsb2NhbGhvc3QwDAYDVR0TAQH/BAIwADAOBgNVHQ8B
Af8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFJwS23CF10/s
q0TAs0Gb3uQAdIjPMB8GA1UdIwQYMBaAFAd4EsDqm4dEcMlNHNV/I6CjgZbpMA0G
CSqGSIb3DQEBCwUAA4IBAQC0zAoEpwghJ8SWOT6AcE0Irw+Fky9Uoiep3sLW/wTJ
qjvBIyfQPnx+m4KJXHa3tqsOcxWpdnveYcm6xWP0eSR14LMPbOLNmVLmsWfrd9Oc
pdraiaPRQk6jdcKkrJKib2pHmaDvlwbuKh9jhFaNQ0XDQvyiSXrw0BROlx33jTEf
tlPuWnAzeAa9KoCcmhzjRAC0O4x1Jx18U91FN/lzzQIkfDYbjNmOHu/gwICiqr/7
XXU0Z2cRAaCi4Cec/up6iScZjC3filyh7LUt6mhGHjT5xSosX8dMUkPj51hB2UdU
/k2UNbZTJNoD3pFtaLomU8VLMrrP2N2IPXv79HYBr+Zd
-----END CERTIFICATE-----
"#;

/// The issuing CA: the client-side trust root, and — appended after the leaf
/// at write time — the second link in the chain the server presents. Single
/// source of truth so the two uses cannot drift.
const TLS_TEST_CA: &str = r#"-----BEGIN CERTIFICATE-----
MIIDKzCCAhOgAwIBAgIUTWWGs0iyjcAZCL0sKzpkYtnlsXUwDQYJKoZIhvcNAQEL
BQAwHDEaMBgGA1UEAwwRYWxpZ2hpZXJpLXRlc3QtY2EwIBcNMjAwMTAxMDAwMDAw
WhgPMjEyNjAxMDEwMDAwMDBaMBwxGjAYBgNVBAMMEWFsaWdoaWVyaS10ZXN0LWNh
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1DLhD2+I9gU5DGQE0SsD
3IQKD4Y7fOyypTyRWzJLuBHmI8E2HuRUGWVcAXgfYuE2Fx8miFNIdGPFBXoSj/iP
mVF6GhbJdtkP2FhaYSuj6mqlpaNYjXesU+LCJydtVCTYwsoBaL3zMFOYs/VkUF5S
Z17Y4PhIT8dNl/d38DceiOntqeokJXHR7d3pu3reTLzITV+9ka5HJWXlwyMew00m
ytUMk5K6Fo+ZOH4iIg+bry4tehgO3XbpGXs2o7PIQKPC9fy31NNzjxy1P3w8kWsb
m/9lYcqPIDZ9t1ox6AE6uu5cDwSzMV+hJy1xqmbPSd1u0UGEqOoiP40cfTHtmkjF
1wIDAQABo2MwYTAdBgNVHQ4EFgQUB3gSwOqbh0RwyU0c1X8joKOBlukwHwYDVR0j
BBgwFoAUB3gSwOqbh0RwyU0c1X8joKOBlukwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQELBQADggEBAMYjv16fkPw4o7JDKCAehDMW
0rz+ccBRludL/MmNSbceiWhtZ9X4zPho/IjQRUgq/ockPy6d1UV6dvE445k1/5ly
jb3ObrbFaHGkwLuvnTJpPzKB48zl3JsT3t9AXYoTdRC5F6NyBZsnU3eokuhF40sK
BS/Vm+pMwCZ3D9CGWssYCG1y1RjPHVqP+u+V7YZ4hBgHmNS3WZsA9cgikoXAgIXO
A/EI4pnfvre8USf55/11bmVWL8A6E4b5llf8fW4TdBimFHs2++/19oB/QXRP3T0P
g/mn7lfAslalLxDgp9UvP8qfAhoXNZ0rJRRXDnrTB7HZwoSArrYpiil53cai0Bo=
-----END CERTIFICATE-----
"#;

const TLS_TEST_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCIaIjAdP/sh5tQ
JTNN2i5cSvmunilavlZZcZGQL/rgBpZVra+/A6f4HGgTNTNb5WY8NnUvoTK0N+dn
0PTZE3cs2ZGVYrgHi9ESBm1iMwxaT+a3+JPiVAD8rD5lhb/5+tONVPwfWTMoWkXy
UPu+sWZIE8b1Fp7wsCsJxMsWj1/A8jdgNms5oriWVcTN70ETrAq199CXheo7N4Cu
IelXQBjWMvrQXW4Vo4Wo/xbrIgftYRI9Qj/Ocs5austso/S2SoqgET3nibxCene+
lkwMrQM/HqoeolxvSqE6U2hmnZDChMa+W8ww+INoDyXPwFPd9zTfoTMFPWqUwVXY
Qt6QIzYHAgMBAAECggEAC2g2e2WtWzHR5qddvXZv5w7sB1K5oZmGLg+lvRmOELrs
SnjuV/ptyv1RJL4Pr/Eklgd10EhaLaD5LIDYYOjUT/9XwdbSDet+zdOUxSAAufKx
mBPlBgnBVV/wDdxb/AMiOtDvDo4OjaLS85sbGkzKgV+KBUfhfb41syjuVNIjj0Zy
4ZQo/CV1Zhlmjj6Btvxf19RF+jCqRSNJbUJEsnpvHj7BpBVNQxbLvFw0IhbyBHNe
s4a3TYn/0LkoSL78rqjPFpk4HJqo1Ad9gdIKNVbgMpouboXxI98dr9g1BwqMKRCQ
3BqTTmyvf6zmGxQFz1jLY+FceGmG/YdIoGeGnAHHaQKBgQC+Vl1dg+OTg06M3AvS
v0dmlXlPbc+owPkS7hkB1qijObRvtINuwQVay8l9ySXvZD5gkIIyaAkIqfZIBgrS
vwPW2CrB8nVPeii1OzVo1cIT9xcIRik/xe7q2966WdnlY9VcO+whqQuhrqk+lZaZ
42kPBmisfR+UDoY8T82csZWomQKBgQC3d24bCBnVDjnwhFMeejmU3cMP4+tAV6DY
jYfv5hayI/ZW2Lr9C/q7zR7Htp2eIlpjz/NrTPz9LD/mdMMnEu32iQlGLYR27u8+
li1vGLEU0JJowU9wJJfrkyChGWtmQW77Tk9GtZvvXs6F2+rbzbsqjuRKATcRBwAe
qZeoy6/XnwKBgEQPyAUno1pdatpN2WB8C8EwFBgGEWqrzqUpRQH2S4lKmi4To6gY
F50XIC79nbYT54ZKRnRV5V0Wwb2Rg49GxM2vsOJ3m+FWsnXT/U5Gmcbf5XmM9TUb
x0puYx/J/3PaljIML2z98O3Y8iYyAY931VqNFSMQ/xjHdNLeSo0Mp5KJAoGBAIEH
WoViViCUB8WSmo5lsVdz+zqStaGjvzhtmTvr2uxgBGChvig3I5iussYMNZ/AU0e9
OVmuZIJ9e1dNqO4zDu6DA+W6H14xvkqK/dsTR373DPDle0PISJvh9mG2aeUZgb72
HSUClm9rgt17hBof/1D3+6/cWOj9vmTSKxoIXlvLAoGAa8s9ugjAL5LnpPoIXmAn
dj//P1QEVipld48dJDHXxFA94xpmWnUamZ1zZGSdzUvYZJ80e7N1PB/9WYa5K8zV
VrxXuzx+kIDNIXMLXwcOfYWfSgzD/irxEPpg25GcQXti89IwkPXIF45YimDy3cr6
1N896Ol4hWNORttOvx0kN/o=
-----END PRIVATE KEY-----
"#;

/// Full TLS round trip through the proxy: handshake with the TLS-wrapped
/// listener, SOCKS5 negotiation and CONNECT over the encrypted stream, then
/// an echo relay — proving the upgraded rustls stack end to end.
#[tokio::test]
async fn tls_listener_relays_connect_traffic() {
    use tokio_rustls::rustls::pki_types::pem::PemObject;
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};

    let dir = tempfile::tempdir().unwrap();
    let cert_file = dir.path().join("server.crt");
    let key_file = dir.path().join("server.key");
    // Server presents the leaf followed by the issuing CA.
    std::fs::write(&cert_file, format!("{TLS_TEST_LEAF}{TLS_TEST_CA}")).unwrap();
    std::fs::write(&key_file, TLS_TEST_KEY).unwrap();

    let config = Config::parse(&format!(
        r#"
internal: 127.0.0.1:0
external: 127.0.0.1
socksmethod: none
tls.certfile: {}
tls.keyfile: {}
client pass {{ from: 0.0.0.0/0 to: 0.0.0.0/0 }}
socks pass {{ from: 0.0.0.0/0 to: 0.0.0.0/0 protocol: tcp command: connect }}
"#,
        cert_file.display(),
        key_file.display()
    ))
    .unwrap();
    let (_proxy, proxy_addr) = start_proxy_with_config(config).await;
    let echo_addr = start_echo_server().await;

    // Trust exactly the test CA.
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(TLS_TEST_CA.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));

    let tcp = TcpStream::connect(proxy_addr).await.unwrap();
    let mut stream = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .expect("TLS handshake with the proxy listener failed");

    // SOCKS5 over TLS: greeting, CONNECT to the echo server, then relay.
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut selection = [0u8; 2];
    stream.read_exact(&mut selection).await.unwrap();
    assert_eq!(selection, [0x05, 0x00]);

    let SocketAddr::V4(echo_v4) = echo_addr else {
        panic!("echo server should bind IPv4");
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&echo_v4.ip().octets());
    request.extend_from_slice(&echo_v4.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    assert_eq!(
        reply[1], 0x00,
        "CONNECT failed with reply 0x{:02x}",
        reply[1]
    );

    stream.write_all(b"over tls").await.unwrap();
    let mut echoed = [0u8; 8];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"over tls");
}

// ---------------------------------------------------------------------------
// IPv6, domain-name, negative-TLS, and hot-reload coverage
// ---------------------------------------------------------------------------

/// Starts a TCP echo server bound to `bind`, returning its address, or `None`
/// when the bind fails — e.g. a host without IPv6 loopback.
async fn try_start_echo_server(bind: &str) -> Option<SocketAddr> {
    let listener = TcpListener::bind(bind).await.ok()?;
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 512];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            stream.write_all(&buf[..n]).await.unwrap();
        }
    });
    Some(addr)
}

/// Sends a CONNECT request for a domain name (ATYP = 0x03) and returns the
/// bound address from the reply. Panics on failure.
async fn request_connect_domain(stream: &mut TcpStream, domain: &str, port: u16) -> SocketAddr {
    // SOCKS5 domain names carry a single-byte length, so reject anything that
    // would not fit rather than silently truncating with `as u8`.
    let len = u8::try_from(domain.len()).expect("domain name exceeds 255 bytes");
    let mut req = vec![0x05, 0x01, 0x00, 0x03, len];
    req.extend_from_slice(domain.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await.unwrap();

    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    assert_eq!(
        reply[1], 0x00,
        "CONNECT failed with reply 0x{:02x}",
        reply[1]
    );
    assert_eq!(reply[2], 0x00);
    match reply[3] {
        0x01 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await.unwrap();
            let port = stream.read_u16().await.unwrap();
            SocketAddr::new(std::net::IpAddr::V4(octets.into()), port)
        }
        0x04 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await.unwrap();
            let port = stream.read_u16().await.unwrap();
            SocketAddr::new(std::net::IpAddr::V6(octets.into()), port)
        }
        other => panic!("unexpected ATYP {other}"),
    }
}

/// End-to-end CONNECT to an IPv6 destination (ATYP = 0x04). Skipped when the
/// platform has no IPv6 loopback to bind the echo server to.
#[tokio::test]
async fn connect_relay_over_ipv6() {
    let Some(echo_addr) = try_start_echo_server("[::1]:0").await else {
        eprintln!("skipping connect_relay_over_ipv6: no IPv6 loopback");
        return;
    };
    assert!(matches!(echo_addr, SocketAddr::V6(_)));

    // The destination is IPv6, so the socks rule must allow `::/0`.
    let cfg = Config::parse(
        r#"
internal: 127.0.0.1:0
external: 127.0.0.1
socksmethod: none
client pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }
socks pass { from: 0.0.0.0/0 to: ::/0 protocol: tcp command: connect }
"#,
    )
    .unwrap();
    let (_handle, proxy_addr) = start_proxy_with_config(cfg).await;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    handshake_noauth(&mut stream).await;
    request_connect(&mut stream, echo_addr).await;

    stream.write_all(b"over ipv6").await.unwrap();
    let mut echoed = [0u8; 9];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"over ipv6");
}

/// End-to-end CONNECT addressed by domain name, exercising proxy-side DNS
/// resolution. `dns.prefer: ipv4` pins `localhost` to the 127.0.0.1 echo.
#[tokio::test]
async fn connect_relay_via_domain_name() {
    let echo_addr = start_echo_server().await;
    let SocketAddr::V4(echo_v4) = echo_addr else {
        panic!("echo server should bind IPv4");
    };

    let cfg = Config::parse(
        r#"
internal: 127.0.0.1:0
external: 127.0.0.1
socksmethod: none
dns.prefer: ipv4
client pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }
socks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 protocol: tcp command: connect }
"#,
    )
    .unwrap();
    let (_handle, proxy_addr) = start_proxy_with_config(cfg).await;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    handshake_noauth(&mut stream).await;
    request_connect_domain(&mut stream, "localhost", echo_v4.port()).await;

    stream.write_all(b"via dns").await.unwrap();
    let mut echoed = [0u8; 7];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"via dns");
}

/// A TLS client that trusts no roots must fail the handshake with the TLS
/// listener — the negative companion to `tls_listener_relays_connect_traffic`.
#[tokio::test]
async fn tls_listener_rejects_untrusted_client() {
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};

    let dir = tempfile::tempdir().unwrap();
    let cert_file = dir.path().join("server.crt");
    let key_file = dir.path().join("server.key");
    std::fs::write(&cert_file, format!("{TLS_TEST_LEAF}{TLS_TEST_CA}")).unwrap();
    std::fs::write(&key_file, TLS_TEST_KEY).unwrap();

    let config = Config::parse(&format!(
        r#"
internal: 127.0.0.1:0
external: 127.0.0.1
socksmethod: none
tls.certfile: {}
tls.keyfile: {}
client pass {{ from: 0.0.0.0/0 to: 0.0.0.0/0 }}
socks pass {{ from: 0.0.0.0/0 to: 0.0.0.0/0 protocol: tcp command: connect }}
"#,
        cert_file.display(),
        key_file.display()
    ))
    .unwrap();
    let (_proxy, proxy_addr) = start_proxy_with_config(config).await;

    // Empty trust store: the server's certificate is an unknown issuer.
    let client_config = ClientConfig::builder()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));

    let tcp = TcpStream::connect(proxy_addr).await.unwrap();
    let result = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await;
    assert!(
        result.is_err(),
        "handshake must fail when the client trusts no CA"
    );
}

/// Hot reload swaps the ACL set for newly accepted connections: a blocked
/// destination becomes reachable after `Server::reload` without rebinding.
#[tokio::test]
async fn reload_swaps_acls_for_new_connections() {
    let echo_addr = start_echo_server().await;
    let SocketAddr::V4(echo_v4) = echo_addr else {
        panic!("echo server should bind IPv4");
    };

    // Start with a config that blocks the echo destination outright.
    let blocking = Config::parse(&format!(
        r#"
internal: 127.0.0.1:0
external: 127.0.0.1
socksmethod: none
client pass {{ from: 0.0.0.0/0 to: 0.0.0.0/0 }}
socks block {{ from: 0.0.0.0/0 to: {}/32 }}
socks pass {{ from: 0.0.0.0/0 to: 0.0.0.0/0 protocol: tcp command: connect }}
"#,
        echo_v4.ip()
    ))
    .unwrap();

    let server = std::sync::Arc::new(Server::bind(blocking).await.unwrap());
    let proxy_addr = server.local_addr().unwrap();
    let run_server = server.clone();
    let _handle = tokio::spawn(async move { run_server.run().await.ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Before reload: the block rule denies CONNECT to the echo server.
    {
        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        handshake_noauth(&mut stream).await;
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&echo_v4.ip().octets());
        req.extend_from_slice(&echo_v4.port().to_be_bytes());
        stream.write_all(&req).await.unwrap();
        let mut reply = [0u8; 4];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(
            reply[1], 0x02,
            "expected ConnectionNotAllowed before reload"
        );
        // Drain the rest of the reply (BND.ADDR + BND.PORT) before dropping the
        // socket, so it closes cleanly instead of resetting with unread data.
        let addr_len = match reply[3] {
            0x01 => 4,
            0x04 => 16,
            other => panic!("unexpected ATYP {other}"),
        };
        let mut rest = vec![0u8; addr_len + 2];
        stream.read_exact(&mut rest).await.unwrap();
    }

    // Reload with a permissive policy; the bound listener address is preserved.
    server.reload(permissive_config()).await.unwrap();

    // After reload: a new connection reaches the echo server and relays.
    {
        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        handshake_noauth(&mut stream).await;
        request_connect(&mut stream, echo_addr).await;
        stream.write_all(b"after reload").await.unwrap();
        let mut echoed = [0u8; 12];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"after reload");
    }
}

/// A config that trusts `trusted` for PROXY protocol and only admits
/// `allowed_client` at the `client` rule, so admission proves which address is
/// used for rule evaluation.
fn proxy_protocol_config(trusted: &str, allowed_client: &str) -> Config {
    Config::parse(&format!(
        r#"
internal: 127.0.0.1:0
external: 127.0.0.1
socksmethod: none
proxyprotocol: {trusted}
client pass {{ from: {allowed_client} to: 0.0.0.0/0 }}
socks pass {{ from: 0.0.0.0/0 to: 0.0.0.0/0 protocol: tcp command: connect }}
"#
    ))
    .unwrap()
}

#[tokio::test]
async fn proxy_protocol_v1_uses_real_client_for_rules() {
    // Trust loopback as the upstream, but only admit the PROXY-advertised client
    // IP (203.0.113.5) — not the loopback transport peer. A successful connect
    // proves the header address drives `client`-rule evaluation.
    let (_proxy, proxy_addr) =
        start_proxy_with_config(proxy_protocol_config("127.0.0.0/8", "203.0.113.5/32")).await;

    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = target.accept().await;
    });

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream
        .write_all(b"PROXY TCP4 203.0.113.5 127.0.0.1 40000 1080\r\n")
        .await
        .unwrap();
    handshake_noauth(&mut stream).await;
    request_connect(&mut stream, target_addr).await;
}

#[tokio::test]
async fn proxy_protocol_rejects_untrusted_source() {
    // PROXY protocol is enabled but only 10.0.0.0/8 is trusted; the loopback
    // test client is not, so the connection is dropped before any handshake.
    let (_proxy, proxy_addr) =
        start_proxy_with_config(proxy_protocol_config("10.0.0.0/8", "0.0.0.0/0")).await;
    let stream = TcpStream::connect(proxy_addr).await.unwrap();
    expect_connection_closed(stream).await;
}

#[cfg(unix)]
#[tokio::test]
async fn external_command_auth_gates_username_password() {
    use std::io::Write;

    // A verifier script that allows only alice/secret (read from stdin). Create
    // it under /tmp (space-free) rather than honoring TMPDIR, which may contain
    // spaces: auth.command is whitespace-split, so a spaced path would break
    // config parsing. Invoke it via `/bin/sh <script>` so the test depends on
    // neither the exec bit nor a non-noexec mount.
    let dir = tempfile::Builder::new()
        .prefix("alighieri-auth")
        .tempdir_in("/tmp")
        .unwrap();
    let script = dir.path().join("verify.sh");
    {
        let mut f = std::fs::File::create(&script).unwrap();
        writeln!(
            f,
            "read u\nread p\n[ \"$u\" = alice ] && [ \"$p\" = secret ]"
        )
        .unwrap();
    }

    let cfg = Config::parse(&format!(
        r#"
internal: 127.0.0.1:0
external: 127.0.0.1
socksmethod: username
auth.command: /bin/sh {}
client pass {{ from: 0.0.0.0/0 to: 0.0.0.0/0 }}
socks pass {{ from: 0.0.0.0/0 to: 0.0.0.0/0 protocol: tcp command: connect }}
"#,
        script.display()
    ))
    .unwrap();
    let (_proxy, addr) = start_proxy_with_config(cfg).await;

    // Correct credentials authenticate via the external command.
    let mut ok = TcpStream::connect(addr).await.unwrap();
    assert!(handshake_username(&mut ok, "alice", "secret").await);

    // Wrong credentials are rejected.
    let mut bad = TcpStream::connect(addr).await.unwrap();
    assert!(!handshake_username(&mut bad, "alice", "wrong").await);
}

#[tokio::test]
async fn graceful_shutdown_drains_inflight_connection() {
    let echo = start_echo_server().await;

    // Keep an Arc so the test can trigger shutdown while `run` executes.
    let server = Arc::new(Server::bind(permissive_config()).await.unwrap());
    let proxy_addr = server.local_addr().unwrap();
    let run = {
        let server = server.clone();
        tokio::spawn(async move { server.run().await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Establish a tunnel through the proxy to the echo server.
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    handshake_noauth(&mut client).await;
    let _bound = request_connect(&mut client, echo).await;

    // Signal shutdown while the tunnel is open.
    server.begin_shutdown();

    // The in-flight tunnel must still carry data: it is drained, not cut.
    client.write_all(b"after shutdown").await.unwrap();
    let mut buf = [0u8; 14];
    tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut buf))
        .await
        .expect("in-flight tunnel was cut on shutdown instead of draining")
        .unwrap();
    assert_eq!(&buf, b"after shutdown");

    // Closing the client lets the connection finish; `run` then drains and exits
    // (proving it also stopped accepting — the loop returned).
    client.shutdown().await.ok();
    drop(client);
    tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .expect("run() did not return after the connection drained")
        .expect("run task panicked")
        .expect("run() returned an error");
}

#[tokio::test]
async fn graceful_shutdown_returns_promptly_when_idle() {
    let server = Arc::new(Server::bind(permissive_config()).await.unwrap());
    let run = {
        let server = server.clone();
        tokio::spawn(async move { server.run().await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;

    // With no in-flight connections the drain is empty, so `run` returns at once.
    server.begin_shutdown();
    tokio::time::timeout(Duration::from_secs(2), run)
        .await
        .expect("idle server did not exit promptly on shutdown")
        .expect("run task panicked")
        .expect("run() returned an error");
}

#[tokio::test]
async fn shutdown_aborts_inflight_after_drain_timeout() {
    let echo = start_echo_server().await;
    // A short, configured drain window so the abort path runs quickly.
    let cfg = Config::parse(
        "internal: 127.0.0.1:0\nexternal: 127.0.0.1\nsocksmethod: none\n\
         shutdown.draintimeout: 1\n\
         client pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }\n\
         socks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 protocol: tcp command: connect }\n",
    )
    .unwrap();
    let server = Arc::new(Server::bind(cfg).await.unwrap());
    let proxy_addr = server.local_addr().unwrap();
    let run = {
        let server = server.clone();
        tokio::spawn(async move { server.run().await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Establish a tunnel and leave it open and idle — neither side closes, so it
    // does not drain on its own and must be aborted at the timeout.
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    handshake_noauth(&mut client).await;
    let _bound = request_connect(&mut client, echo).await;

    let started = std::time::Instant::now();
    server.begin_shutdown();
    tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .expect("run() hung past the drain timeout")
        .expect("run task panicked")
        .expect("run() returned an error");
    let elapsed = started.elapsed();
    // It waited out the ~1s drain rather than cutting instantly. The surrounding
    // 5s timeout already fails the test if shutdown hangs, so no upper bound here
    // (which would only add CI flakiness).
    assert!(
        elapsed >= Duration::from_millis(500),
        "returned before the drain window elapsed: {elapsed:?}"
    );

    // The aborted connection cut the tunnel: the client now reads EOF or errors.
    let mut buf = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("expected the tunnel to be cut, read {n} bytes"),
        Err(_) => panic!("tunnel was not cut after the drain timeout"),
    }
}

#[tokio::test]
async fn udp_strict_reply_default_rejects_same_ip_different_port() {
    // `permissive_config` uses the default `udp.strictreply` (now strict).
    let (_handle, proxy_addr) = start_proxy().await;

    // The contacted target; the proxy's outbound address is learned from the
    // datagram it forwards here.
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();

    let mut control = TcpStream::connect(proxy_addr).await.unwrap();
    handshake_noauth(&mut control).await;
    let relay_addr = request_udp_associate(&mut control).await;

    // Client sends a datagram destined for `target` through the proxy.
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut datagram = socks5::build_udp_header(&TargetAddr::Ip(target_addr));
    datagram.extend_from_slice(b"ping");
    client.send_to(&datagram, relay_addr).await.unwrap();

    let mut buf = [0u8; 1024];
    let (_, proxy_outbound) =
        tokio::time::timeout(Duration::from_secs(2), target.recv_from(&mut buf))
            .await
            .expect("proxy did not forward the datagram to the target")
            .unwrap();

    // Inject a reply to the proxy's outbound socket from the same IP but a
    // different port. Under strict matching it must be dropped.
    let injector = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert_ne!(injector.local_addr().unwrap().port(), target_addr.port());
    injector.send_to(b"inject", proxy_outbound).await.unwrap();
    let leaked = tokio::time::timeout(Duration::from_millis(500), client.recv_from(&mut buf)).await;
    assert!(
        leaked.is_err(),
        "strict mode forwarded an injected reply from a different port"
    );

    // A reply from the contacted endpoint itself is still delivered.
    target.send_to(b"legit", proxy_outbound).await.unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("a legitimate reply from the contacted endpoint was dropped")
        .unwrap();
    let header = socks5::parse_udp_header(&buf[..n]).unwrap();
    assert_eq!(&buf[header.payload_offset..n], b"legit");
}

#[tokio::test]
async fn udp_loose_reply_accepts_same_ip_different_port() {
    // Opt out of strict matching: any port on a contacted host is accepted.
    let cfg = Config::parse(
        r#"
internal: 127.0.0.1:0
external: 127.0.0.1
socksmethod: none
udp.strictreply: false
client pass { from: 0.0.0.0/0 to: 0.0.0.0/0 }
socks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 protocol: tcp udp command: connect udpassociate }
"#,
    )
    .unwrap();
    let (_handle, proxy_addr) = start_proxy_with_config(cfg).await;

    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();

    let mut control = TcpStream::connect(proxy_addr).await.unwrap();
    handshake_noauth(&mut control).await;
    let relay_addr = request_udp_associate(&mut control).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut datagram = socks5::build_udp_header(&TargetAddr::Ip(target_addr));
    datagram.extend_from_slice(b"ping");
    client.send_to(&datagram, relay_addr).await.unwrap();

    let mut buf = [0u8; 1024];
    let (_, proxy_outbound) =
        tokio::time::timeout(Duration::from_secs(2), target.recv_from(&mut buf))
            .await
            .expect("proxy did not forward the datagram to the target")
            .unwrap();

    // A same-IP, different-port reply is accepted under loose matching.
    let injector = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert_ne!(injector.local_addr().unwrap().port(), target_addr.port());
    injector
        .send_to(b"from-other-port", proxy_outbound)
        .await
        .unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("loose mode dropped a reply from a different port on the contacted host")
        .unwrap();
    let header = socks5::parse_udp_header(&buf[..n]).unwrap();
    assert_eq!(&buf[header.payload_offset..n], b"from-other-port");
}
