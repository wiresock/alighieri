//! Network address primitives used by the access-control engine.
//!
//! Alighieri deliberately implements its own small CIDR type rather than
//! depending on an external crate. The matching surface we need is narrow
//! (does an [`IpAddr`] fall inside a network?) and keeping it in-tree avoids
//! pulling additional dependencies into a security-sensitive code path.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A CIDR network: a base address plus a prefix length in bits.
///
/// IPv4 and IPv6 are represented uniformly by storing the address as a 128-bit
/// integer (IPv4 addresses are mapped into the low 32 bits) together with the
/// address family so that a v4 network never matches a v6 address and vice
/// versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    bits: u128,
    prefix: u8,
    is_v6: bool,
}

impl Cidr {
    /// Constructs a CIDR from an address and a prefix length.
    ///
    /// Returns `None` if the prefix length is too large for the address family
    /// (more than 32 for IPv4 or 128 for IPv6).
    pub fn new(addr: IpAddr, prefix: u8) -> Option<Self> {
        match addr {
            IpAddr::V4(v4) => {
                if prefix > 32 {
                    return None;
                }
                Some(Cidr {
                    bits: u32::from(v4) as u128,
                    prefix,
                    is_v6: false,
                })
            }
            IpAddr::V6(v6) => {
                if prefix > 128 {
                    return None;
                }
                Some(Cidr {
                    bits: u128::from(v6),
                    prefix,
                    is_v6: true,
                })
            }
        }
    }

    /// Returns `true` if `addr` falls within this network.
    ///
    /// Address families must match: an IPv4 network never contains an IPv6
    /// address. IPv4-mapped IPv6 addresses are treated as IPv6; callers that
    /// want them matched against IPv4 rules should canonicalise first.
    pub fn contains(&self, addr: IpAddr) -> bool {
        let (value, is_v6) = match addr {
            IpAddr::V4(v4) => (u32::from(v4) as u128, false),
            IpAddr::V6(v6) => (u128::from(v6), true),
        };
        if is_v6 != self.is_v6 {
            return false;
        }
        let total_bits = if self.is_v6 { 128 } else { 32 };
        if self.prefix == 0 {
            return true;
        }
        let shift = total_bits - self.prefix as u32;
        // Compare only the network portion by discarding host bits.
        (value >> shift) == (self.bits >> shift)
    }

    /// The prefix length in bits.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Whether this is an IPv6 network.
    pub fn is_v6(&self) -> bool {
        self.is_v6
    }
}

impl std::str::FromStr for Cidr {
    type Err = String;

    /// Parses `"ADDR/PREFIX"` or a bare `"ADDR"` (treated as a host route,
    /// i.e. `/32` for IPv4 or `/128` for IPv6).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if let Some((addr_s, prefix_s)) = s.split_once('/') {
            let addr: IpAddr = addr_s
                .trim()
                .parse()
                .map_err(|_| format!("invalid IP address '{addr_s}'"))?;
            let prefix: u8 = prefix_s
                .trim()
                .parse()
                .map_err(|_| format!("invalid prefix '{prefix_s}'"))?;
            Cidr::new(addr, prefix).ok_or_else(|| format!("prefix /{prefix} too large for address"))
        } else {
            let addr: IpAddr = s.parse().map_err(|_| format!("invalid IP address '{s}'"))?;
            let prefix = match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            Ok(Cidr::new(addr, prefix).expect("host prefix is always valid"))
        }
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let addr = if self.is_v6 {
            IpAddr::V6(Ipv6Addr::from(self.bits))
        } else {
            IpAddr::V4(Ipv4Addr::from(self.bits as u32))
        };
        write!(f, "{addr}/{}", self.prefix)
    }
}

/// An inclusive TCP/UDP port range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub min: u16,
    pub max: u16,
}

impl PortRange {
    /// A range matching every port (`0..=65535`).
    pub const ANY: PortRange = PortRange {
        min: 0,
        max: u16::MAX,
    };

    /// Returns `true` if `port` falls within the range (inclusive).
    pub fn contains(&self, port: u16) -> bool {
        port >= self.min && port <= self.max
    }
}

impl std::str::FromStr for PortRange {
    type Err = String;

    /// Parses `"N"` (a single port) or `"N - M"` (an inclusive range).
    /// Whitespace around the dash is tolerated.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if let Some((lo, hi)) = s.split_once('-') {
            let min: u16 = lo
                .trim()
                .parse()
                .map_err(|_| format!("invalid port '{lo}'"))?;
            let max: u16 = hi
                .trim()
                .parse()
                .map_err(|_| format!("invalid port '{hi}'"))?;
            if min > max {
                return Err(format!("port range min ({min}) > max ({max})"));
            }
            Ok(PortRange { min, max })
        } else {
            let p: u16 = s.parse().map_err(|_| format!("invalid port '{s}'"))?;
            Ok(PortRange { min: p, max: p })
        }
    }
}

/// A destination hostname matcher for a `socks` rule `to:` selector.
///
/// Matched against the hostname the client requested *before* resolution, so a
/// rule allowlists the name the client asked for rather than whatever it
/// resolves to (resistant to DNS rebinding). Patterns are stored lowercased and
/// matching is case-insensitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPattern {
    /// Matches exactly this hostname (e.g. `example.com`).
    Exact(String),
    /// The leading-dot form `.example.com`: matches the domain itself and any
    /// subdomain (`example.com`, `a.example.com`, `a.b.example.com`, ...).
    Suffix(String),
}

impl HostPattern {
    /// Parses a `to:` token as a hostname pattern. A leading dot selects the
    /// domain and all of its subdomains; otherwise the token is an exact host.
    pub fn parse(token: &str) -> Result<Self, String> {
        let lower = token.trim().to_ascii_lowercase();
        let (mut domain, suffix) = match lower.strip_prefix('.') {
            Some(rest) => (rest.to_string(), true),
            None => (lower, false),
        };
        // Tolerate a single trailing dot so an FQDN like `example.com.` is
        // accepted in config; the checks below still reject `example.com..`.
        if domain.ends_with('.') && !domain.ends_with("..") {
            domain.pop();
        }
        if domain.is_empty()
            || domain.starts_with('.')
            || domain.ends_with('.')
            || domain.contains("..")
            || !domain
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return Err(format!("'{token}' is not a valid hostname pattern"));
        }
        Ok(if suffix {
            HostPattern::Suffix(domain)
        } else {
            HostPattern::Exact(domain)
        })
    }

    /// Returns `true` if `host` (the requested hostname) matches this pattern.
    ///
    /// Allocation-free and case-insensitive: patterns are already stored
    /// lowercased, so this compares against the borrowed host directly. The UDP
    /// authorisation path calls this per datagram, so the hot path must not
    /// allocate.
    pub fn matches(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.');
        match self {
            HostPattern::Exact(h) => host.eq_ignore_ascii_case(h),
            HostPattern::Suffix(domain) => {
                host.eq_ignore_ascii_case(domain)
                    || (host.len() > domain.len()
                        // The boundary byte is an ASCII '.', so the index is a
                        // char boundary even when `host` contains non-ASCII.
                        && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
                        && host[host.len() - domain.len()..].eq_ignore_ascii_case(domain))
            }
        }
    }
}

/// An address specification used as the `from:` / `to:` clause of a rule.
///
/// A spec matches when the port range matches *and* either a network or (for a
/// `socks` rule `to:`) a destination hostname pattern matches. A `None` port
/// range matches every port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrSpec {
    pub cidrs: Vec<Cidr>,
    /// Destination hostname patterns; only populated for a `socks` rule `to:`.
    pub hosts: Vec<HostPattern>,
    pub ports: Option<PortRange>,
}

impl AddrSpec {
    /// A selector matching all IPv4 and IPv6 addresses.
    pub fn any() -> Self {
        AddrSpec {
            cidrs: vec![
                "0.0.0.0/0".parse().expect("constant CIDR is valid"),
                "::/0".parse().expect("constant CIDR is valid"),
            ],
            hosts: Vec::new(),
            ports: None,
        }
    }

    /// A selector matching a single CIDR, optionally constrained by port.
    pub fn new(cidr: Cidr, ports: Option<PortRange>) -> Self {
        AddrSpec {
            cidrs: vec![cidr],
            hosts: Vec::new(),
            ports,
        }
    }

    /// A selector matching a destination hostname pattern, optionally
    /// constrained by port. Used only for `socks` rule `to:` clauses.
    pub fn host(pattern: HostPattern, ports: Option<PortRange>) -> Self {
        AddrSpec {
            cidrs: Vec::new(),
            hosts: vec![pattern],
            ports,
        }
    }

    /// Returns `true` if both the IP and port satisfy this spec. Hostname
    /// patterns are ignored; this is the IP-only matcher used by `from:` and by
    /// `client` rule `to:` (the proxy's own accepting address).
    pub fn matches(&self, ip: IpAddr, port: u16) -> bool {
        self.cidrs.iter().any(|cidr| cidr.contains(ip)) && self.port_matches(port)
    }

    /// Returns `true` if this destination spec matches a `socks` request: the
    /// port must be in range, and either a hostname pattern matches the
    /// requested host (when the client sent a domain) or a CIDR contains the
    /// resolved IP.
    pub fn matches_dest(&self, host: Option<&str>, ip: IpAddr, port: u16) -> bool {
        self.port_matches(port)
            && (self.cidrs.iter().any(|cidr| cidr.contains(ip))
                || host.is_some_and(|h| self.hosts.iter().any(|p| p.matches(h))))
    }

    fn port_matches(&self, port: u16) -> bool {
        match self.ports {
            Some(range) => range.contains(port),
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_v4_contains() {
        let net: Cidr = "10.0.0.0/8".parse().unwrap();
        assert!(net.contains("10.1.2.3".parse().unwrap()));
        assert!(net.contains("10.255.255.255".parse().unwrap()));
        assert!(!net.contains("11.0.0.0".parse().unwrap()));
    }

    #[test]
    fn cidr_any_v4() {
        let net: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(net.contains("8.8.8.8".parse().unwrap()));
        assert!(net.contains("192.168.1.1".parse().unwrap()));
        // Does not match IPv6.
        assert!(!net.contains("::1".parse().unwrap()));
    }

    #[test]
    fn cidr_host_route() {
        let net: Cidr = "127.0.0.1".parse().unwrap();
        assert_eq!(net.prefix(), 32);
        assert!(net.contains("127.0.0.1".parse().unwrap()));
        assert!(!net.contains("127.0.0.2".parse().unwrap()));
    }

    #[test]
    fn cidr_v6_contains() {
        let net: Cidr = "fd00::/8".parse().unwrap();
        assert!(net.is_v6());
        assert!(net.contains("fd12:3456::1".parse().unwrap()));
        assert!(!net.contains("fe80::1".parse().unwrap()));
        // Does not match IPv4.
        assert!(!net.contains("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn cidr_partial_byte_prefix() {
        let net: Cidr = "192.168.1.0/25".parse().unwrap();
        assert!(net.contains("192.168.1.0".parse().unwrap()));
        assert!(net.contains("192.168.1.127".parse().unwrap()));
        assert!(!net.contains("192.168.1.128".parse().unwrap()));
    }

    #[test]
    fn cidr_rejects_oversized_prefix() {
        assert!("10.0.0.0/33".parse::<Cidr>().is_err());
        assert!("::/129".parse::<Cidr>().is_err());
    }

    #[test]
    fn cidr_display_roundtrip() {
        let net: Cidr = "172.16.0.0/12".parse().unwrap();
        assert_eq!(net.to_string(), "172.16.0.0/12");
    }

    #[test]
    fn port_range_single() {
        let r: PortRange = "443".parse().unwrap();
        assert_eq!(r, PortRange { min: 443, max: 443 });
        assert!(r.contains(443));
        assert!(!r.contains(444));
    }

    #[test]
    fn port_range_span() {
        let r: PortRange = "1000 - 2000".parse().unwrap();
        assert!(r.contains(1000));
        assert!(r.contains(1500));
        assert!(r.contains(2000));
        assert!(!r.contains(999));
        assert!(!r.contains(2001));
    }

    #[test]
    fn port_range_inverted_rejected() {
        assert!("2000-1000".parse::<PortRange>().is_err());
    }

    #[test]
    fn addr_spec_matches_ip_and_port() {
        let spec = AddrSpec {
            cidrs: vec!["192.168.0.0/16".parse().unwrap()],
            hosts: Vec::new(),
            ports: Some(PortRange { min: 80, max: 80 }),
        };
        assert!(spec.matches("192.168.5.5".parse().unwrap(), 80));
        assert!(!spec.matches("192.168.5.5".parse().unwrap(), 81));
        assert!(!spec.matches("10.0.0.1".parse().unwrap(), 80));
    }

    #[test]
    fn addr_spec_any_port() {
        let spec = AddrSpec {
            cidrs: vec!["0.0.0.0/0".parse().unwrap()],
            hosts: Vec::new(),
            ports: None,
        };
        assert!(spec.matches("1.2.3.4".parse().unwrap(), 1));
        assert!(spec.matches("1.2.3.4".parse().unwrap(), 65535));
    }

    #[test]
    fn addr_spec_any_matches_v4_and_v6() {
        let spec = AddrSpec::any();
        assert!(spec.matches("8.8.8.8".parse().unwrap(), 53));
        assert!(spec.matches("2001:db8::1".parse().unwrap(), 443));
    }

    #[test]
    fn host_pattern_exact_and_suffix_match() {
        let exact = HostPattern::parse("Example.com").unwrap();
        assert_eq!(exact, HostPattern::Exact("example.com".into()));
        assert!(exact.matches("example.com"));
        assert!(exact.matches("EXAMPLE.COM"));
        assert!(exact.matches("example.com.")); // trailing dot tolerated
        assert!(!exact.matches("a.example.com"));
        assert!(!exact.matches("notexample.com"));

        let suffix = HostPattern::parse(".example.com").unwrap();
        assert_eq!(suffix, HostPattern::Suffix("example.com".into()));
        assert!(suffix.matches("example.com")); // the apex itself
        assert!(suffix.matches("a.example.com"));
        assert!(suffix.matches("a.b.example.com"));
        assert!(!suffix.matches("example.com.evil.com"));
        assert!(!suffix.matches("notexample.com")); // not a label boundary
        assert!(!suffix.matches("fooexample.com"));
    }

    #[test]
    fn host_pattern_rejects_invalid() {
        for bad in [".", "", "..", "exam ple.com", "a..b.com", "ex@mple.com"] {
            assert!(HostPattern::parse(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn host_pattern_tolerates_trailing_dot() {
        // An FQDN-style trailing dot in the pattern is normalised away.
        assert_eq!(
            HostPattern::parse("example.com.").unwrap(),
            HostPattern::Exact("example.com".into())
        );
        assert_eq!(
            HostPattern::parse(".example.com.").unwrap(),
            HostPattern::Suffix("example.com".into())
        );
        // A double trailing dot is still rejected.
        assert!(HostPattern::parse("example.com..").is_err());
    }

    #[test]
    fn addr_spec_matches_dest_by_host_or_ip() {
        let host = AddrSpec::host(HostPattern::Suffix("example.com".into()), None);
        // Hostname matches the requested domain, regardless of the resolved IP.
        assert!(host.matches_dest(Some("api.example.com"), "203.0.113.1".parse().unwrap(), 443));
        // No hostname (IP literal) -> a hostname rule does not match.
        assert!(!host.matches_dest(None, "203.0.113.1".parse().unwrap(), 443));
        // CIDR rules still match on the resolved IP and ignore the host.
        let cidr = AddrSpec::new("10.0.0.0/8".parse().unwrap(), None);
        assert!(cidr.matches_dest(Some("anything"), "10.1.2.3".parse().unwrap(), 80));
        assert!(!cidr.matches_dest(Some("anything"), "192.0.2.1".parse().unwrap(), 80));
    }
}
