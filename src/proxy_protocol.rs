//! PROXY protocol (v1 text and v2 binary) header parsing.
//!
//! When Alighieri runs behind a TCP load balancer (HAProxy, nginx `stream`,
//! AWS/GCP Network Load Balancers), the balancer prepends a small header to each
//! connection carrying the original client address. Reading it lets `client`
//! rules, abuse limits, metrics, and logs key on the real client rather than the
//! balancer.
//!
//! Headers are only honoured from configured trusted upstreams (see
//! `proxyprotocol` in the config) — accepting them from arbitrary peers would
//! let a client forge its source address and bypass `client` rules.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};

/// The 12-byte signature that opens a v2 (binary) header.
const V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Maximum length of a v1 (text) header line, including the trailing CRLF.
const V1_MAX_LEN: usize = 107;

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Reads a PROXY protocol header (v1 or v2) from `reader`, consuming **exactly**
/// the header bytes so the SOCKS handshake can continue on the same stream.
///
/// Returns the real client address from the header, or `None` for a v2 `LOCAL`
/// command or an unspecified address family (a health check or non-TCP
/// connection), where the caller should fall back to the transport peer.
pub async fn read_header<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Option<SocketAddr>> {
    // The first 12 bytes are either the v2 signature or the start of a v1 line
    // (`PROXY <proto>...`); the shortest valid v1 line is 15 bytes, so reading
    // 12 never consumes past a v1 CRLF.
    let mut first = [0u8; 12];
    reader.read_exact(&mut first).await?;
    if first == V2_SIGNATURE {
        read_v2(reader).await
    } else if first.starts_with(b"PROXY ") {
        read_v1(reader, &first).await
    } else {
        Err(invalid("not a PROXY protocol header"))
    }
}

async fn read_v1<R: AsyncRead + Unpin>(
    reader: &mut R,
    prefix: &[u8; 12],
) -> io::Result<Option<SocketAddr>> {
    let mut line = Vec::with_capacity(V1_MAX_LEN);
    line.extend_from_slice(prefix);
    loop {
        if line.ends_with(b"\r\n") {
            break;
        }
        if line.len() >= V1_MAX_LEN {
            return Err(invalid("PROXY v1 header too long"));
        }
        let mut b = [0u8; 1];
        reader.read_exact(&mut b).await?;
        line.push(b[0]);
    }
    parse_v1_line(&line[..line.len() - 2])
}

fn parse_v1_line(line: &[u8]) -> io::Result<Option<SocketAddr>> {
    // The balancer connected on its own behalf (e.g. a health check). After
    // `UNKNOWN` the spec permits arbitrary, possibly non-UTF-8 bytes up to the
    // CRLF that the receiver must ignore, so detect it on the raw bytes before
    // UTF-8 decoding the rest of the line.
    if line == b"PROXY UNKNOWN" || line.starts_with(b"PROXY UNKNOWN ") {
        return Ok(None);
    }
    let line = std::str::from_utf8(line).map_err(|_| invalid("PROXY v1 header is not UTF-8"))?;
    let mut parts = line.split(' ');
    if parts.next() != Some("PROXY") {
        return Err(invalid("PROXY v1 header malformed"));
    }
    // The spec requires receivers to reject a malformed header: validate every
    // field, require the address family to match the protocol, and reject extra
    // trailing fields.
    let want_v6 = match parts.next() {
        Some("TCP4") => false,
        Some("TCP6") => true,
        _ => return Err(invalid("PROXY v1 unknown protocol")),
    };
    let mut next_field = || {
        parts
            .next()
            .ok_or_else(|| invalid("PROXY v1 header truncated"))
    };
    let src_ip = next_field()?;
    let dst_ip = next_field()?;
    let src_port = next_field()?;
    let dst_port = next_field()?;
    if parts.next().is_some() {
        return Err(invalid("PROXY v1 header has extra fields"));
    }
    let parse_ip = |s: &str| -> io::Result<IpAddr> {
        let ip: IpAddr = s.parse().map_err(|_| invalid("PROXY v1 invalid IP"))?;
        if ip.is_ipv6() != want_v6 {
            return Err(invalid("PROXY v1 address family does not match protocol"));
        }
        Ok(ip)
    };
    let src = parse_ip(src_ip)?;
    parse_ip(dst_ip)?; // validate the destination address too
    let port: u16 = src_port
        .parse()
        .map_err(|_| invalid("PROXY v1 invalid source port"))?;
    let _dst_port: u16 = dst_port
        .parse()
        .map_err(|_| invalid("PROXY v1 invalid dest port"))?;
    Ok(Some(SocketAddr::new(src, port)))
}

async fn read_v2<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Option<SocketAddr>> {
    let mut meta = [0u8; 4];
    reader.read_exact(&mut meta).await?;
    let ver_cmd = meta[0];
    let fam_proto = meta[1];
    let len = u16::from_be_bytes([meta[2], meta[3]]) as usize;
    if ver_cmd >> 4 != 0x2 {
        return Err(invalid("PROXY v2 bad version"));
    }
    // The address block can carry trailing TLVs after the addresses; read all of
    // it so the stream is left positioned at the application data, then parse
    // only the leading addresses.
    let mut block = vec![0u8; len];
    reader.read_exact(&mut block).await?;

    // Low nibble of the version/command byte: 0 = LOCAL (no real client), 1 =
    // PROXY; any other value is invalid and must be rejected.
    match ver_cmd & 0x0F {
        0x0 => return Ok(None),
        0x1 => {}
        _ => return Err(invalid("PROXY v2 unsupported command")),
    }

    // High nibble of fam_proto = address family, low nibble = transport. For a
    // TCP listener the transport of an INET/INET6 address must be STREAM (0x1).
    let transport = fam_proto & 0x0F;
    match fam_proto >> 4 {
        0x1 | 0x2 if transport != 0x1 => Err(invalid("PROXY v2 transport must be STREAM")),
        // AF_INET: src(4) dst(4) sport(2) dport(2)
        0x1 if block.len() >= 12 => {
            let src = Ipv4Addr::new(block[0], block[1], block[2], block[3]);
            let port = u16::from_be_bytes([block[8], block[9]]);
            Ok(Some(SocketAddr::new(IpAddr::V4(src), port)))
        }
        // AF_INET6: src(16) dst(16) sport(2) dport(2)
        0x2 if block.len() >= 36 => {
            let mut src = [0u8; 16];
            src.copy_from_slice(&block[0..16]);
            let port = u16::from_be_bytes([block[32], block[33]]);
            Ok(Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(src)), port)))
        }
        0x1 | 0x2 => Err(invalid("PROXY v2 address block too short")),
        // AF_UNSPEC / AF_UNIX: no usable TCP client address.
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn read_with_tail(mut header: Vec<u8>) -> (io::Result<Option<SocketAddr>>, Vec<u8>) {
        header.extend_from_slice(b"SOCKSDATA");
        let mut reader: &[u8] = &header;
        let result = read_header(&mut reader).await;
        // Whatever is left after the header should be exactly the app data.
        let mut tail = Vec::new();
        let _ = AsyncReadExt::read_to_end(&mut reader, &mut tail).await;
        (result, tail)
    }

    #[tokio::test]
    async fn v1_tcp4_parsed_and_consumed_exactly() {
        let (res, tail) =
            read_with_tail(b"PROXY TCP4 192.0.2.7 198.51.100.1 56324 443\r\n".to_vec()).await;
        assert_eq!(res.unwrap(), Some("192.0.2.7:56324".parse().unwrap()));
        assert_eq!(tail, b"SOCKSDATA");
    }

    #[tokio::test]
    async fn v1_unknown_yields_none() {
        let (res, tail) = read_with_tail(b"PROXY UNKNOWN\r\n".to_vec()).await;
        assert_eq!(res.unwrap(), None);
        assert_eq!(tail, b"SOCKSDATA");
    }

    #[tokio::test]
    async fn v1_unknown_ignores_non_utf8_remainder() {
        // The bytes after UNKNOWN may be arbitrary and non-UTF-8; they must be
        // ignored rather than rejected as invalid UTF-8.
        let mut header = b"PROXY UNKNOWN ".to_vec();
        header.extend_from_slice(&[0xFF, 0xFE, 0x01]);
        header.extend_from_slice(b"\r\n");
        let (res, tail) = read_with_tail(header).await;
        assert_eq!(res.unwrap(), None);
        assert_eq!(tail, b"SOCKSDATA");
    }

    #[tokio::test]
    async fn v2_tcp4_parsed_and_consumed_exactly() {
        let mut h = V2_SIGNATURE.to_vec();
        h.push(0x21); // version 2, PROXY command
        h.push(0x11); // AF_INET, STREAM
        h.extend_from_slice(&12u16.to_be_bytes());
        h.extend_from_slice(&[192, 0, 2, 9]); // src ip
        h.extend_from_slice(&[198, 51, 100, 1]); // dst ip
        h.extend_from_slice(&40000u16.to_be_bytes()); // src port
        h.extend_from_slice(&443u16.to_be_bytes()); // dst port
        let (res, tail) = read_with_tail(h).await;
        assert_eq!(res.unwrap(), Some("192.0.2.9:40000".parse().unwrap()));
        assert_eq!(tail, b"SOCKSDATA");
    }

    #[tokio::test]
    async fn v2_tcp6_parsed() {
        let mut h = V2_SIGNATURE.to_vec();
        h.push(0x21);
        h.push(0x21); // AF_INET6, STREAM
        h.extend_from_slice(&36u16.to_be_bytes());
        let src = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets();
        h.extend_from_slice(&src);
        h.extend_from_slice(&[0u8; 16]); // dst
        h.extend_from_slice(&51000u16.to_be_bytes());
        h.extend_from_slice(&443u16.to_be_bytes());
        let (res, _tail) = read_with_tail(h).await;
        assert_eq!(res.unwrap(), Some("[2001:db8::1]:51000".parse().unwrap()));
    }

    #[tokio::test]
    async fn v2_local_command_yields_none() {
        let mut h = V2_SIGNATURE.to_vec();
        h.push(0x20); // version 2, LOCAL command
        h.push(0x00); // AF_UNSPEC
        h.extend_from_slice(&0u16.to_be_bytes());
        let (res, tail) = read_with_tail(h).await;
        assert_eq!(res.unwrap(), None);
        assert_eq!(tail, b"SOCKSDATA");
    }

    #[tokio::test]
    async fn v2_with_trailing_tlv_is_consumed() {
        let mut h = V2_SIGNATURE.to_vec();
        h.push(0x21);
        h.push(0x11);
        // 12 address bytes + 4 bytes of TLV padding.
        h.extend_from_slice(&16u16.to_be_bytes());
        h.extend_from_slice(&[192, 0, 2, 9, 198, 51, 100, 1]);
        h.extend_from_slice(&40000u16.to_be_bytes());
        h.extend_from_slice(&443u16.to_be_bytes());
        h.extend_from_slice(&[0x03, 0x00, 0x01, 0xAB]); // a TLV
        let (res, tail) = read_with_tail(h).await;
        assert_eq!(res.unwrap(), Some("192.0.2.9:40000".parse().unwrap()));
        assert_eq!(tail, b"SOCKSDATA");
    }

    #[tokio::test]
    async fn non_proxy_header_is_rejected() {
        let mut reader: &[u8] = b"\x05\x01\x00 not a proxy header at all";
        assert!(read_header(&mut reader).await.is_err());
    }

    #[tokio::test]
    async fn v1_rejects_family_mismatch_truncation_and_extras() {
        // IPv6 address tagged TCP4.
        let (res, _) =
            read_with_tail(b"PROXY TCP4 2001:db8::1 198.51.100.1 1 2\r\n".to_vec()).await;
        assert!(res.is_err(), "family mismatch should be rejected");
        // Missing the destination port.
        let (res, _) = read_with_tail(b"PROXY TCP4 192.0.2.7 198.51.100.1 1\r\n".to_vec()).await;
        assert!(res.is_err(), "truncated header should be rejected");
        // A trailing extra field.
        let (res, _) =
            read_with_tail(b"PROXY TCP4 192.0.2.7 198.51.100.1 1 2 extra\r\n".to_vec()).await;
        assert!(res.is_err(), "extra fields should be rejected");
    }

    #[tokio::test]
    async fn v2_rejects_unknown_command_and_non_stream() {
        // Unknown command nibble (2).
        let mut h = V2_SIGNATURE.to_vec();
        h.push(0x22);
        h.push(0x11);
        h.extend_from_slice(&12u16.to_be_bytes());
        h.extend_from_slice(&[0u8; 12]);
        assert!(
            read_with_tail(h).await.0.is_err(),
            "unknown command rejected"
        );

        // AF_INET but DGRAM transport on a TCP listener.
        let mut h = V2_SIGNATURE.to_vec();
        h.push(0x21);
        h.push(0x12); // AF_INET, DGRAM
        h.extend_from_slice(&12u16.to_be_bytes());
        h.extend_from_slice(&[192, 0, 2, 9, 198, 51, 100, 1, 0x9c, 0x40, 0x01, 0xbb]);
        assert!(read_with_tail(h).await.0.is_err(), "non-STREAM rejected");
    }
}
