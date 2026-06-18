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
    let line = std::str::from_utf8(line).map_err(|_| invalid("PROXY v1 header is not UTF-8"))?;
    let mut parts = line.split(' ');
    if parts.next() != Some("PROXY") {
        return Err(invalid("PROXY v1 header malformed"));
    }
    match parts.next() {
        Some("TCP4") | Some("TCP6") => {
            let src_ip = parts
                .next()
                .ok_or_else(|| invalid("PROXY v1 missing source IP"))?;
            let _dst_ip = parts
                .next()
                .ok_or_else(|| invalid("PROXY v1 missing dest IP"))?;
            let src_port = parts
                .next()
                .ok_or_else(|| invalid("PROXY v1 missing source port"))?;
            let ip: IpAddr = src_ip
                .parse()
                .map_err(|_| invalid("PROXY v1 invalid source IP"))?;
            let port: u16 = src_port
                .parse()
                .map_err(|_| invalid("PROXY v1 invalid source port"))?;
            Ok(Some(SocketAddr::new(ip, port)))
        }
        // The balancer connected on its own behalf (e.g. a health check).
        Some("UNKNOWN") => Ok(None),
        _ => Err(invalid("PROXY v1 unknown protocol")),
    }
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

    // Low nibble of the version/command byte: 0 = LOCAL (no real client).
    if ver_cmd & 0x0F == 0x0 {
        return Ok(None);
    }
    match fam_proto >> 4 {
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
}
