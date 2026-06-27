//! SOCKS5 wire-format primitives.
//!
//! Implements the parts of RFC 1928 (SOCKS Protocol Version 5) and RFC 1929
//! (Username/Password Authentication) that Alighieri needs, expressed as
//! strongly-typed values plus `async` read/write helpers over any
//! [`AsyncRead`]/[`AsyncWrite`] stream.
//!
//! Nothing in this module performs policy decisions or I/O beyond serialising
//! and deserialising frames — that keeps the protocol layer easy to test in
//! isolation from the proxy logic.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::errors::{Error, Result};

/// The only SOCKS protocol version this server speaks.
pub const VERSION: u8 = 0x05;

/// The version byte used by the RFC 1929 username/password sub-negotiation.
pub const AUTH_VERSION: u8 = 0x01;

// ---------------------------------------------------------------------------
// Authentication methods (RFC 1928 §3)
// ---------------------------------------------------------------------------

/// A SOCKS5 authentication method identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `0x00` — no authentication required.
    NoAuth,
    /// `0x02` — username/password (RFC 1929).
    UserPass,
    /// `0xFF` — no acceptable methods (server → client only).
    NoAcceptable,
    /// Any other method byte we do not implement.
    Other(u8),
}

impl Method {
    /// Decodes a method byte.
    pub fn from_u8(b: u8) -> Method {
        match b {
            0x00 => Method::NoAuth,
            0x02 => Method::UserPass,
            0xFF => Method::NoAcceptable,
            other => Method::Other(other),
        }
    }

    /// Encodes the method as its wire byte.
    pub fn as_u8(self) -> u8 {
        match self {
            Method::NoAuth => 0x00,
            Method::UserPass => 0x02,
            Method::NoAcceptable => 0xFF,
            Method::Other(b) => b,
        }
    }
}

// ---------------------------------------------------------------------------
// Commands (RFC 1928 §4)
// ---------------------------------------------------------------------------

/// A SOCKS5 request command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// `0x01` — establish a TCP connection to the target.
    Connect,
    /// `0x02` — bind for an inbound TCP connection (e.g. FTP active mode).
    Bind,
    /// `0x03` — establish a UDP relay association.
    UdpAssociate,
}

impl Command {
    /// Decodes a command byte, returning a protocol error for unknown values.
    pub fn from_u8(b: u8) -> Result<Command> {
        match b {
            0x01 => Ok(Command::Connect),
            0x02 => Ok(Command::Bind),
            0x03 => Ok(Command::UdpAssociate),
            other => Err(Error::Protocol(format!(
                "unknown command byte 0x{other:02x}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Reply codes (RFC 1928 §6)
// ---------------------------------------------------------------------------

/// A SOCKS5 reply status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    Succeeded,
    GeneralFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
}

impl Reply {
    /// The wire byte for this reply.
    pub fn as_u8(self) -> u8 {
        match self {
            Reply::Succeeded => 0x00,
            Reply::GeneralFailure => 0x01,
            Reply::ConnectionNotAllowed => 0x02,
            Reply::NetworkUnreachable => 0x03,
            Reply::HostUnreachable => 0x04,
            Reply::ConnectionRefused => 0x05,
            Reply::TtlExpired => 0x06,
            Reply::CommandNotSupported => 0x07,
            Reply::AddressTypeNotSupported => 0x08,
        }
    }
}

// ---------------------------------------------------------------------------
// Target addresses (RFC 1928 §4 / §5 ATYP)
// ---------------------------------------------------------------------------

/// A destination address as carried in a SOCKS5 request or UDP header.
///
/// Domain names are preserved verbatim (not resolved here) so that the proxy
/// can decide when and how to perform DNS resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    /// A resolved socket address (`ATYP` 0x01 or 0x04).
    Ip(SocketAddr),
    /// A domain name plus port (`ATYP` 0x03).
    Domain(String, u16),
}

impl TargetAddr {
    /// The destination port, regardless of address kind.
    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Ip(sa) => sa.port(),
            TargetAddr::Domain(_, p) => *p,
        }
    }

    /// Returns the host as a string suitable for DNS resolution input.
    pub fn host_string(&self) -> String {
        match self {
            TargetAddr::Ip(sa) => sa.ip().to_string(),
            TargetAddr::Domain(d, _) => d.clone(),
        }
    }
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetAddr::Ip(sa) => write!(f, "{sa}"),
            TargetAddr::Domain(d, p) => write!(f, "{d}:{p}"),
        }
    }
}

const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;

/// Reads an `ATYP`-prefixed address followed by a 2-byte big-endian port.
pub async fn read_target_addr<R: AsyncRead + Unpin>(r: &mut R) -> Result<TargetAddr> {
    let atyp = r.read_u8().await?;
    match atyp {
        ATYP_V4 => {
            let mut octets = [0u8; 4];
            r.read_exact(&mut octets).await?;
            let port = r.read_u16().await?;
            Ok(TargetAddr::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(octets)),
                port,
            )))
        }
        ATYP_V6 => {
            let mut octets = [0u8; 16];
            r.read_exact(&mut octets).await?;
            let port = r.read_u16().await?;
            Ok(TargetAddr::Ip(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(octets)),
                port,
            )))
        }
        ATYP_DOMAIN => {
            let len = r.read_u8().await? as usize;
            if len == 0 {
                return Err(Error::Protocol("empty domain name".into()));
            }
            let mut buf = vec![0u8; len];
            r.read_exact(&mut buf).await?;
            let domain = String::from_utf8(buf)
                .map_err(|_| Error::Protocol("domain name is not valid UTF-8".into()))?;
            crate::net::validate_hostname(&domain)
                .map_err(|e| Error::Protocol(format!("domain name {e}")))?;
            let port = r.read_u16().await?;
            Ok(TargetAddr::Domain(domain, port))
        }
        other => Err(Error::Protocol(format!(
            "unsupported address type 0x{other:02x}"
        ))),
    }
}

/// Serialises a [`TargetAddr`] (ATYP + address + port) into `buf`.
pub fn encode_target_addr(addr: &TargetAddr, buf: &mut Vec<u8>) {
    match addr {
        TargetAddr::Ip(SocketAddr::V4(v4)) => {
            buf.push(ATYP_V4);
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        TargetAddr::Ip(SocketAddr::V6(v6)) => {
            buf.push(ATYP_V6);
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
        TargetAddr::Domain(domain, port) => {
            buf.push(ATYP_DOMAIN);
            // Domain length is a single byte; callers should never construct
            // domains longer than 255 bytes, but clamp defensively.
            let bytes = domain.as_bytes();
            let len = bytes.len().min(u8::MAX as usize);
            buf.push(len as u8);
            buf.extend_from_slice(&bytes[..len]);
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
}

/// Encodes a concrete [`SocketAddr`] as an ATYP-prefixed address+port.
pub fn encode_socket_addr(addr: SocketAddr, buf: &mut Vec<u8>) {
    encode_target_addr(&TargetAddr::Ip(addr), buf);
}

// ---------------------------------------------------------------------------
// Method-selection handshake (RFC 1928 §3)
// ---------------------------------------------------------------------------

/// The client's opening greeting: the version byte followed by the list of
/// authentication methods it supports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Greeting {
    pub methods: Vec<Method>,
}

/// Reads and validates a client greeting.
pub async fn read_greeting<R: AsyncRead + Unpin>(r: &mut R) -> Result<Greeting> {
    let ver = r.read_u8().await?;
    if ver != VERSION {
        return Err(Error::Protocol(format!(
            "unsupported SOCKS version 0x{ver:02x}"
        )));
    }
    let nmethods = r.read_u8().await? as usize;
    if nmethods == 0 {
        return Err(Error::Protocol("client offered no auth methods".into()));
    }
    let mut raw = vec![0u8; nmethods];
    r.read_exact(&mut raw).await?;
    Ok(Greeting {
        methods: raw.into_iter().map(Method::from_u8).collect(),
    })
}

/// Writes the server's chosen method (`VER, METHOD`).
pub async fn write_method_selection<W: AsyncWrite + Unpin>(
    w: &mut W,
    method: Method,
) -> Result<()> {
    w.write_all(&[VERSION, method.as_u8()]).await?;
    w.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Username/password sub-negotiation (RFC 1929)
// ---------------------------------------------------------------------------

/// Credentials submitted by a client during RFC 1929 authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserPassCredentials {
    pub username: String,
    pub password: String,
}

/// Reads an RFC 1929 username/password request.
pub async fn read_userpass<R: AsyncRead + Unpin>(r: &mut R) -> Result<UserPassCredentials> {
    let ver = r.read_u8().await?;
    if ver != AUTH_VERSION {
        return Err(Error::Protocol(format!(
            "unsupported auth version 0x{ver:02x}"
        )));
    }
    let ulen = r.read_u8().await? as usize;
    let mut ubuf = vec![0u8; ulen];
    r.read_exact(&mut ubuf).await?;
    let plen = r.read_u8().await? as usize;
    let mut pbuf = vec![0u8; plen];
    r.read_exact(&mut pbuf).await?;

    let username =
        String::from_utf8(ubuf).map_err(|_| Error::Protocol("username is not UTF-8".into()))?;
    let password =
        String::from_utf8(pbuf).map_err(|_| Error::Protocol("password is not UTF-8".into()))?;
    // Reject a zero-length username before it reaches an auth backend: there is
    // no valid empty username, and `auth.command` would otherwise be handed a
    // blank credential to adjudicate. An empty password is left to the backend —
    // the userlist plaintext format permits one (`user:`), so rejecting it here
    // would change behaviour for that (discouraged) configuration.
    if username.is_empty() {
        return Err(Error::Protocol("empty username".into()));
    }
    Ok(UserPassCredentials { username, password })
}

/// Writes an RFC 1929 auth response. `success == true` yields status `0x00`.
pub async fn write_userpass_status<W: AsyncWrite + Unpin>(w: &mut W, success: bool) -> Result<()> {
    let status = if success { 0x00 } else { 0x01 };
    w.write_all(&[AUTH_VERSION, status]).await?;
    w.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Request / reply (RFC 1928 §4 / §6)
// ---------------------------------------------------------------------------

/// A decoded SOCKS5 request line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub command: Command,
    pub dest: TargetAddr,
}

/// Reads a SOCKS5 request (`VER, CMD, RSV, ATYP, ADDR, PORT`).
pub async fn read_request<R: AsyncRead + Unpin>(r: &mut R) -> Result<Request> {
    let ver = r.read_u8().await?;
    if ver != VERSION {
        return Err(Error::Protocol(format!(
            "unsupported SOCKS version 0x{ver:02x} in request"
        )));
    }
    let cmd = Command::from_u8(r.read_u8().await?)?;
    let rsv = r.read_u8().await?;
    if rsv != 0x00 {
        return Err(Error::Protocol(format!(
            "request reserved byte must be 0x00, got 0x{rsv:02x}"
        )));
    }
    let dest = read_target_addr(r).await?;
    Ok(Request { command: cmd, dest })
}

/// Writes a SOCKS5 reply (`VER, REP, RSV, ATYP, BND.ADDR, BND.PORT`).
///
/// `bound` is the address the server bound on the client's behalf; for error
/// replies an all-zero `0.0.0.0:0` placeholder is conventional and accepted.
pub async fn write_reply<W: AsyncWrite + Unpin>(
    w: &mut W,
    reply: Reply,
    bound: SocketAddr,
) -> Result<()> {
    // On a dual-stack listener an IPv4 client is accepted with an IPv4-mapped
    // IPv6 local address (`::ffff:a.b.c.d`). Encoding that verbatim yields an
    // ATYP=0x04 (IPv6) reply, but a client that reached us over IPv4 expects an
    // ATYP=0x01 (IPv4) reply and misparses the longer address — notably reading
    // BND.PORT as 0, which breaks UDP ASSOCIATE. Canonicalising collapses the
    // mapped form back to IPv4 while leaving genuine IPv6 addresses untouched.
    let bound = SocketAddr::new(bound.ip().to_canonical(), bound.port());
    let mut buf = Vec::with_capacity(22);
    buf.push(VERSION);
    buf.push(reply.as_u8());
    buf.push(0x00); // RSV
    encode_socket_addr(bound, &mut buf);
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

/// The conventional all-zero placeholder address used in error replies.
pub fn unspecified_v4() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

// ---------------------------------------------------------------------------
// UDP request header (RFC 1928 §7)
// ---------------------------------------------------------------------------

/// A parsed SOCKS5 UDP relay header together with the offset at which the
/// user payload begins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpHeader {
    pub frag: u8,
    pub dest: TargetAddr,
    /// Offset into the original datagram where the payload starts.
    pub payload_offset: usize,
}

/// Parses the leading SOCKS5 UDP header from a datagram.
///
/// Header layout: `RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT(2) DATA...`.
pub fn parse_udp_header(buf: &[u8]) -> Result<UdpHeader> {
    if buf.len() < 4 {
        return Err(Error::Protocol("UDP datagram too short for header".into()));
    }
    if buf[0] != 0x00 || buf[1] != 0x00 {
        return Err(Error::Protocol("UDP reserved bytes must be 0x0000".into()));
    }
    let frag = buf[2];
    let atyp = buf[3];
    let mut pos = 4;
    let dest = match atyp {
        ATYP_V4 => {
            if buf.len() < pos + 4 + 2 {
                return Err(Error::Protocol("UDP header truncated (v4)".into()));
            }
            let octets: [u8; 4] = buf[pos..pos + 4].try_into().unwrap();
            pos += 4;
            let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            pos += 2;
            TargetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        ATYP_V6 => {
            if buf.len() < pos + 16 + 2 {
                return Err(Error::Protocol("UDP header truncated (v6)".into()));
            }
            let octets: [u8; 16] = buf[pos..pos + 16].try_into().unwrap();
            pos += 16;
            let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            pos += 2;
            TargetAddr::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        ATYP_DOMAIN => {
            if buf.len() < pos + 1 {
                return Err(Error::Protocol("UDP header truncated (domain len)".into()));
            }
            let len = buf[pos] as usize;
            pos += 1;
            if len == 0 {
                // Reject zero-length domains to match the TCP request parser
                // (`read_target_addr`); an empty host is invalid protocol input.
                return Err(Error::Protocol("UDP empty domain name".into()));
            }
            if buf.len() < pos + len + 2 {
                return Err(Error::Protocol("UDP header truncated (domain)".into()));
            }
            let domain = String::from_utf8(buf[pos..pos + len].to_vec())
                .map_err(|_| Error::Protocol("UDP domain not UTF-8".into()))?;
            crate::net::validate_hostname(&domain)
                .map_err(|e| Error::Protocol(format!("UDP domain {e}")))?;
            pos += len;
            let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            pos += 2;
            TargetAddr::Domain(domain, port)
        }
        other => {
            return Err(Error::Protocol(format!(
                "unsupported UDP address type 0x{other:02x}"
            )))
        }
    };
    Ok(UdpHeader {
        frag,
        dest,
        payload_offset: pos,
    })
}

/// Builds a SOCKS5 UDP header (with `FRAG = 0`) for the given source address,
/// returning the header bytes that should prefix the payload.
pub fn build_udp_header(src: &TargetAddr) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10);
    buf.extend_from_slice(&[0x00, 0x00]); // RSV
    buf.push(0x00); // FRAG
    encode_target_addr(src, &mut buf);
    buf
}

/// The largest SOCKS5 UDP header for an IP source: `RSV(2) FRAG(1) ATYP(1)
/// IPv6(16) PORT(2)`.
pub const UDP_IP_HEADER_MAX: usize = 22;

/// Writes the UDP header (with `FRAG = 0`) for `src` into the tail of
/// `prefix` and returns the offset at which it starts.
///
/// Relay loops lay a datagram out as `[..start][header][payload]` inside one
/// reused buffer, so wrapping a payload needs no per-packet allocation.
pub fn write_udp_header_tail(src: SocketAddr, prefix: &mut [u8; UDP_IP_HEADER_MAX]) -> usize {
    // The outbound socket may be dual-stack (e.g. `external: ::`), so a reply
    // from an IPv4 peer arrives as an IPv4-mapped `::ffff:a.b.c.d` source. Emit
    // it as an ATYP=0x01 IPv4 header so an IPv4 client parses the payload offset
    // correctly; genuine IPv6 sources are left as ATYP=0x04.
    let src = SocketAddr::new(src.ip().to_canonical(), src.port());
    let start = match src {
        SocketAddr::V4(_) => UDP_IP_HEADER_MAX - 10,
        SocketAddr::V6(_) => 0,
    };
    let header = &mut prefix[start..];
    header[0] = 0x00; // RSV
    header[1] = 0x00;
    header[2] = 0x00; // FRAG
    match src {
        SocketAddr::V4(v4) => {
            header[3] = ATYP_V4;
            header[4..8].copy_from_slice(&v4.ip().octets());
            header[8..10].copy_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            header[3] = ATYP_V6;
            header[4..20].copy_from_slice(&v6.ip().octets());
            header[20..22].copy_from_slice(&v6.port().to_be_bytes());
        }
    }
    start
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn method_roundtrip() {
        for b in [0x00u8, 0x02, 0xFF, 0x42] {
            assert_eq!(Method::from_u8(b).as_u8(), b);
        }
    }

    #[test]
    fn command_decode() {
        assert_eq!(Command::from_u8(0x01).unwrap(), Command::Connect);
        assert_eq!(Command::from_u8(0x03).unwrap(), Command::UdpAssociate);
        assert!(Command::from_u8(0x09).is_err());
    }

    #[tokio::test]
    async fn read_greeting_ok() {
        let bytes = [VERSION, 0x02, 0x00, 0x02];
        let mut cur = Cursor::new(bytes.to_vec());
        let g = read_greeting(&mut cur).await.unwrap();
        assert_eq!(g.methods, vec![Method::NoAuth, Method::UserPass]);
    }

    #[tokio::test]
    async fn read_greeting_bad_version() {
        let bytes = [0x04u8, 0x01, 0x00];
        let mut cur = Cursor::new(bytes.to_vec());
        assert!(read_greeting(&mut cur).await.is_err());
    }

    #[tokio::test]
    async fn read_request_v4() {
        // VER CMD RSV ATYP=1 1.2.3.4 :0x0050(80)
        let bytes = [VERSION, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50];
        let mut cur = Cursor::new(bytes.to_vec());
        let req = read_request(&mut cur).await.unwrap();
        assert_eq!(req.command, Command::Connect);
        assert_eq!(req.dest, TargetAddr::Ip("1.2.3.4:80".parse().unwrap()));
    }

    #[tokio::test]
    async fn read_request_domain() {
        let mut bytes = vec![VERSION, 0x01, 0x00, 0x03, 0x0b];
        bytes.extend_from_slice(b"example.com");
        bytes.extend_from_slice(&443u16.to_be_bytes());
        let mut cur = Cursor::new(bytes);
        let req = read_request(&mut cur).await.unwrap();
        assert_eq!(req.dest, TargetAddr::Domain("example.com".into(), 443));
    }

    #[tokio::test]
    async fn read_request_rejects_nonzero_reserved_byte() {
        let bytes = [VERSION, 0x01, 0x01, 0x01, 1, 2, 3, 4, 0x00, 0x50];
        let mut cur = Cursor::new(bytes.to_vec());
        assert!(read_request(&mut cur).await.is_err());
    }

    #[tokio::test]
    async fn read_request_rejects_bad_version() {
        // A request must carry VER=0x05, like the greeting.
        let bytes = [0x04u8, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50];
        let mut cur = Cursor::new(bytes.to_vec());
        assert!(read_request(&mut cur).await.is_err());
    }

    #[tokio::test]
    async fn read_request_rejects_unknown_command() {
        // CMD 0x09 is not CONNECT/BIND/UDP ASSOCIATE.
        let bytes = [VERSION, 0x09, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50];
        let mut cur = Cursor::new(bytes.to_vec());
        assert!(read_request(&mut cur).await.is_err());
    }

    #[tokio::test]
    async fn read_target_addr_rejects_unsupported_atyp() {
        // ATYP 0x02 is unassigned; reject it rather than misread the following
        // bytes as an address (a parser that fell through could desync the stream).
        let bytes = [0x02u8, 1, 2, 3, 4, 0x00, 0x50];
        let mut cur = Cursor::new(bytes.to_vec());
        let err = read_target_addr(&mut cur).await.unwrap_err();
        assert!(
            matches!(err, Error::Protocol(ref m) if m.contains("unsupported address type")),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn read_target_addr_rejects_truncated_ipv4() {
        // ATYP=0x01 with only three address octets and no port: error on the short
        // read rather than block or fabricate an address.
        let bytes = [0x01u8, 1, 2, 3];
        let mut cur = Cursor::new(bytes.to_vec());
        assert!(read_target_addr(&mut cur).await.is_err());
    }

    #[tokio::test]
    async fn read_target_addr_rejects_truncated_ipv6() {
        // ATYP=0x04 with only four of sixteen octets.
        let bytes = [0x04u8, 0, 0, 0, 0];
        let mut cur = Cursor::new(bytes.to_vec());
        assert!(read_target_addr(&mut cur).await.is_err());
    }

    #[tokio::test]
    async fn read_target_addr_rejects_truncated_domain() {
        // Length byte claims 10 bytes but only three follow (and no port).
        let bytes = [0x03u8, 0x0a, b'f', b'o', b'o'];
        let mut cur = Cursor::new(bytes.to_vec());
        assert!(read_target_addr(&mut cur).await.is_err());
    }

    #[tokio::test]
    async fn read_target_addr_rejects_empty_domain() {
        // ATYP=0x03 with a zero length byte is invalid (matches the UDP parser).
        let bytes = [0x03u8, 0x00, 0x00, 0x50];
        let mut cur = Cursor::new(bytes.to_vec());
        let err = read_target_addr(&mut cur).await.unwrap_err();
        assert!(
            matches!(err, Error::Protocol(ref m) if m.contains("empty domain")),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn read_target_addr_rejects_non_utf8_domain() {
        // A two-byte domain of invalid UTF-8 (0xff 0xfe) followed by a port.
        let bytes = [0x03u8, 0x02, 0xff, 0xfe, 0x00, 0x50];
        let mut cur = Cursor::new(bytes.to_vec());
        let err = read_target_addr(&mut cur).await.unwrap_err();
        assert!(
            matches!(err, Error::Protocol(ref m) if m.contains("not valid UTF-8")),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn read_target_addr_rejects_crlf_in_domain() {
        // ATYP=0x03 with a CR/LF in the domain must be rejected by the parser, so
        // the value never reaches the logger or resolver.
        let host = b"ev\r\nil.com";
        let mut bytes = vec![0x03u8, host.len() as u8];
        bytes.extend_from_slice(host);
        bytes.extend_from_slice(&80u16.to_be_bytes());
        let mut cur = Cursor::new(bytes);
        assert!(read_target_addr(&mut cur).await.is_err());
    }

    #[test]
    fn parse_udp_header_rejects_crlf_in_domain() {
        // The UDP header parser shares the same domain validation.
        let host = b"ev\r\nil.com";
        let mut datagram = vec![0x00, 0x00, 0x00, ATYP_DOMAIN, host.len() as u8];
        datagram.extend_from_slice(host);
        datagram.extend_from_slice(&53u16.to_be_bytes());
        datagram.extend_from_slice(b"payload");
        assert!(parse_udp_header(&datagram).is_err());
    }

    #[tokio::test]
    async fn read_userpass_ok() {
        let mut bytes = vec![AUTH_VERSION, 0x04];
        bytes.extend_from_slice(b"user");
        bytes.push(0x04);
        bytes.extend_from_slice(b"pass");
        let mut cur = Cursor::new(bytes);
        let creds = read_userpass(&mut cur).await.unwrap();
        assert_eq!(creds.username, "user");
        assert_eq!(creds.password, "pass");
    }

    #[tokio::test]
    async fn read_userpass_rejects_empty_username() {
        // ULEN = 0, then PLEN = 4 "pass": a blank username must be refused
        // before it reaches an auth backend.
        let mut bytes = vec![AUTH_VERSION, 0x00, 0x04];
        bytes.extend_from_slice(b"pass");
        let mut cur = Cursor::new(bytes);
        assert!(read_userpass(&mut cur).await.is_err());
    }

    #[tokio::test]
    async fn read_userpass_allows_empty_password() {
        // ULEN = 4 "user", PLEN = 0: the userlist plaintext format permits an
        // empty password, so the parser must not reject it.
        let mut bytes = vec![AUTH_VERSION, 0x04];
        bytes.extend_from_slice(b"user");
        bytes.push(0x00);
        let mut cur = Cursor::new(bytes);
        let creds = read_userpass(&mut cur).await.unwrap();
        assert_eq!(creds.username, "user");
        assert_eq!(creds.password, "");
    }

    #[tokio::test]
    async fn write_reply_v4() {
        let mut out: Vec<u8> = Vec::new();
        write_reply(&mut out, Reply::Succeeded, "10.0.0.1:1080".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(
            out,
            vec![VERSION, 0x00, 0x00, 0x01, 10, 0, 0, 1, 0x04, 0x38]
        );
    }

    #[tokio::test]
    async fn write_reply_canonicalizes_mapped_v6_to_v4() {
        // A dual-stack listener accepts IPv4 clients with a v4-mapped local
        // address; the reply must still be IPv4 (ATYP=0x01) or clients misparse
        // it and read BND.PORT as 0 (breaking UDP ASSOCIATE).
        let mut out: Vec<u8> = Vec::new();
        write_reply(
            &mut out,
            Reply::Succeeded,
            "[::ffff:10.0.0.1]:1080".parse().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            out,
            vec![VERSION, 0x00, 0x00, 0x01, 10, 0, 0, 1, 0x04, 0x38]
        );
    }

    #[tokio::test]
    async fn write_reply_keeps_genuine_v6() {
        let mut out: Vec<u8> = Vec::new();
        write_reply(
            &mut out,
            Reply::Succeeded,
            "[2001:db8::1]:1080".parse().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(out[3], ATYP_V6);
    }

    #[test]
    fn encode_decode_target_v6() {
        let addr = TargetAddr::Ip("[2001:db8::1]:8080".parse().unwrap());
        let mut buf = Vec::new();
        encode_target_addr(&addr, &mut buf);
        assert_eq!(buf[0], ATYP_V6);
    }

    #[test]
    fn write_udp_header_tail_canonicalizes_mapped_v6() {
        // A reply relayed from a v4 peer via a dual-stack outbound socket arrives
        // as `::ffff:a.b.c.d`; the returned header must use the IPv4 layout so an
        // IPv4 client locates the payload at the right offset.
        let src: SocketAddr = "[::ffff:8.8.8.8]:53".parse().unwrap();
        let mut prefix = [0u8; UDP_IP_HEADER_MAX];
        let start = write_udp_header_tail(src, &mut prefix);
        assert_eq!(start, UDP_IP_HEADER_MAX - 10);
        assert_eq!(prefix[start + 3], ATYP_V4);
        assert_eq!(&prefix[start + 4..start + 8], &[8, 8, 8, 8]);
        assert_eq!(&prefix[start + 8..start + 10], &53u16.to_be_bytes());
    }

    #[test]
    fn udp_header_roundtrip_v4() {
        let src = TargetAddr::Ip("8.8.8.8:53".parse().unwrap());
        let mut datagram = build_udp_header(&src);
        let payload = b"hello";
        datagram.extend_from_slice(payload);

        let hdr = parse_udp_header(&datagram).unwrap();
        assert_eq!(hdr.frag, 0);
        assert_eq!(hdr.dest, src);
        assert_eq!(&datagram[hdr.payload_offset..], payload);
    }

    #[test]
    fn udp_header_domain() {
        let mut datagram = vec![0x00, 0x00, 0x00, ATYP_DOMAIN, 0x03];
        datagram.extend_from_slice(b"foo");
        datagram.extend_from_slice(&53u16.to_be_bytes());
        datagram.extend_from_slice(b"payload");
        let hdr = parse_udp_header(&datagram).unwrap();
        assert_eq!(hdr.dest, TargetAddr::Domain("foo".into(), 53));
        assert_eq!(&datagram[hdr.payload_offset..], b"payload");
    }

    #[test]
    fn udp_header_too_short() {
        assert!(parse_udp_header(&[0x00, 0x00]).is_err());
    }

    #[test]
    fn udp_header_tail_matches_parser() {
        for src in [
            "203.0.113.9:4433".parse::<SocketAddr>().unwrap(),
            "[2001:db8::7]:53".parse::<SocketAddr>().unwrap(),
        ] {
            let mut datagram = vec![0u8; UDP_IP_HEADER_MAX];
            datagram.extend_from_slice(b"payload");
            let prefix: &mut [u8; UDP_IP_HEADER_MAX] =
                (&mut datagram[..UDP_IP_HEADER_MAX]).try_into().unwrap();
            let start = write_udp_header_tail(src, prefix);

            let hdr = parse_udp_header(&datagram[start..]).unwrap();
            assert_eq!(hdr.frag, 0);
            assert_eq!(hdr.dest, TargetAddr::Ip(src));
            assert_eq!(&datagram[start + hdr.payload_offset..], b"payload");
        }
    }

    #[test]
    fn udp_header_rejects_nonzero_reserved_bytes() {
        let datagram = [0x00, 0x01, 0x00, ATYP_V4, 1, 2, 3, 4, 0x00, 0x35];
        assert!(parse_udp_header(&datagram).is_err());
    }

    #[test]
    fn udp_header_rejects_empty_domain() {
        // A zero-length ATYP_DOMAIN host (len byte 0x00) is otherwise
        // well-formed here, so this exercises the empty-name check rather than
        // the truncation guard — matching how the TCP parser rejects it.
        let mut datagram = vec![0x00, 0x00, 0x00, ATYP_DOMAIN, 0x00];
        datagram.extend_from_slice(&53u16.to_be_bytes());
        assert!(parse_udp_header(&datagram).is_err());
    }
}
