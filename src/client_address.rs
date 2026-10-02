//! Client address resolution behind explicitly trusted reverse proxies.
//!
//! The TCP peer is the client unless it falls inside a configured trusted
//! network. Only then is the forwarding header consulted, walked from the
//! right (the entry the trusted proxy appended) towards the left, skipping
//! entries that are themselves trusted proxies. Anything unexpected falls back
//! to the TCP peer, never to a value the client chose.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use axum::http::{HeaderMap, header};

use crate::config::ForwardedHeader;

/// Combined size of every forwarding header instance that is parsed at all.
pub const MAX_FORWARDED_BYTES: usize = 8 * 1024;
/// Maximum number of hops in the combined forwarding header.
pub const MAX_FORWARDED_ENTRIES: usize = 64;

/// An IP network in CIDR notation, stored with its host bits cleared.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpNetwork {
    address: IpAddr,
    prefix: u8,
}

impl IpNetwork {
    /// Parses `address/prefix`, or a bare address as a single-host network.
    ///
    /// Host bits beyond the prefix, IPv4-mapped IPv6 forms, zone identifiers,
    /// and anything but decimal prefix lengths are rejected.
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| "is not an IP address or CIDR range")?;
        if let IpAddr::V6(v6) = address
            && v6.to_ipv4_mapped().is_some()
        {
            return Err("must use the IPv4 form instead of an IPv4-mapped IPv6 address");
        }
        let width = address_width(address);
        let prefix = match prefix {
            None => width,
            Some(prefix)
                if !prefix.is_empty()
                    && prefix.len() <= 3
                    && prefix.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                prefix
                    .parse::<u8>()
                    .map_err(|_| "has an invalid prefix length")?
            }
            Some(_) => return Err("has an invalid prefix length"),
        };
        if prefix > width {
            return Err("has a prefix length longer than the address");
        }
        if masked(address, prefix) != address {
            return Err("has host bits set beyond its prefix length");
        }
        Ok(Self { address, prefix })
    }

    #[must_use]
    pub const fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Whether `address` (IPv4-mapped IPv6 is treated as IPv4) is inside the network.
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        let address = address.to_canonical();
        address.is_ipv4() == self.address.is_ipv4() && masked(address, self.prefix) == self.address
    }
}

impl std::fmt::Display for IpNetwork {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}/{}", self.address, self.prefix)
    }
}

const fn address_width(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn masked(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(v4) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
        }
        IpAddr::V6(v6) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
    }
}

/// The reverse proxies whose forwarding header names the client.
#[derive(Clone, Debug, Default)]
pub struct TrustedProxies {
    networks: Vec<IpNetwork>,
    header: ForwardedHeader,
}

impl TrustedProxies {
    #[must_use]
    pub fn new(networks: Vec<IpNetwork>, header: ForwardedHeader) -> Self {
        Self { networks, header }
    }

    fn is_trusted(&self, address: IpAddr) -> bool {
        self.networks
            .iter()
            .any(|network| network.contains(address))
    }

    /// Resolves the client address for one request.
    ///
    /// Returns the TCP peer unless it is trusted and the forwarding header
    /// yields an untrusted address; IPv4-mapped IPv6 results become IPv4.
    #[must_use]
    pub fn client_address(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let peer = peer.to_canonical();
        if !self.is_trusted(peer) {
            return peer;
        }
        self.forwarded_client(headers).unwrap_or(peer)
    }

    fn forwarded_client(&self, headers: &HeaderMap) -> Option<IpAddr> {
        let name = match self.header {
            ForwardedHeader::XForwardedFor => "x-forwarded-for",
            ForwardedHeader::Forwarded => header::FORWARDED.as_str(),
        };
        // Multiple instances form one list in their received order.
        let mut combined = String::new();
        for value in headers.get_all(name) {
            let text = value.to_str().ok()?;
            if combined.len() + text.len() + 1 > MAX_FORWARDED_BYTES {
                return None;
            }
            if !combined.is_empty() {
                combined.push(',');
            }
            combined.push_str(text);
        }
        if combined.is_empty() {
            return None;
        }
        let entries = split_outside_quotes(&combined, b',')?;
        if entries.len() > MAX_FORWARDED_ENTRIES {
            return None;
        }
        for entry in entries.into_iter().rev() {
            let address = match self.header {
                ForwardedHeader::XForwardedFor => parse_node(entry.trim())?,
                ForwardedHeader::Forwarded => forwarded_for(entry)?,
            }
            .to_canonical();
            if !self.is_trusted(address) {
                return Some(address);
            }
        }
        None
    }
}

/// Splits on `separator` outside RFC 7230 quoted strings. An unterminated
/// quoted string makes the whole value malformed.
fn split_outside_quotes(text: &str, separator: u8) -> Option<Vec<&str>> {
    let bytes = text.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' if quoted => index += 1,
            b'"' => quoted = !quoted,
            byte if byte == separator && !quoted => {
                parts.push(&text[start..index]);
                start = index + 1;
            }
            _ => {}
        }
        index += 1;
    }
    if quoted {
        return None;
    }
    parts.push(&text[start.min(text.len())..]);
    Some(parts)
}

/// Extracts the address of the single `for` parameter of an RFC 7239
/// forwarded-element. Obfuscated identifiers and `unknown` are rejected.
fn forwarded_for(element: &str) -> Option<IpAddr> {
    let mut found = None;
    for pair in split_outside_quotes(element, b';')? {
        let (name, value) = pair.trim().split_once('=')?;
        if !name.trim().eq_ignore_ascii_case("for") {
            continue;
        }
        if found.is_some() {
            return None;
        }
        let value = value.trim();
        let value = match value.strip_prefix('"') {
            Some(rest) => {
                let inner = rest.strip_suffix('"')?;
                if inner.contains(['"', '\\']) {
                    return None;
                }
                inner
            }
            None => value,
        };
        found = Some(parse_node(value)?);
    }
    found
}

/// Parses an address with an optional port: `192.0.2.1`, `192.0.2.1:443`,
/// `2001:db8::1`, `[2001:db8::1]`, or `[2001:db8::1]:443`.
fn parse_node(text: &str) -> Option<IpAddr> {
    if let Some(rest) = text.strip_prefix('[') {
        let (address, rest) = rest.split_once(']')?;
        if !rest.is_empty() && !valid_port(rest.strip_prefix(':')?) {
            return None;
        }
        return address.parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }
    if let Ok(address) = text.parse::<IpAddr>() {
        return Some(address);
    }
    let (address, port) = text.split_once(':')?;
    if !valid_port(port) {
        return None;
    }
    address.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
}

fn valid_port(port: &str) -> bool {
    !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok()
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn proxies(networks: &[&str], header: ForwardedHeader) -> TrustedProxies {
        TrustedProxies::new(
            networks
                .iter()
                .map(|network| IpNetwork::parse(network).unwrap())
                .collect(),
            header,
        )
    }

    fn headers(name: &str, values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    const PROXY: &str = "192.0.2.10";

    fn xff(values: &[&str]) -> IpAddr {
        proxies(
            &["192.0.2.0/28", "2001:db8:ffff::/48"],
            ForwardedHeader::XForwardedFor,
        )
        .client_address(ip(PROXY), &headers("x-forwarded-for", values))
    }

    fn forwarded(values: &[&str]) -> IpAddr {
        proxies(
            &["192.0.2.0/28", "2001:db8:ffff::/48"],
            ForwardedHeader::Forwarded,
        )
        .client_address(ip(PROXY), &headers("forwarded", values))
    }

    #[test]
    fn networks_parse_strictly() {
        let network = IpNetwork::parse("192.0.2.0/24").unwrap();
        assert!(network.contains(ip("192.0.2.200")));
        assert!(network.contains(ip("::ffff:192.0.2.200")));
        assert!(!network.contains(ip("192.0.3.1")));
        assert!(!network.contains(ip("2001:db8::1")));
        let single = IpNetwork::parse("2001:db8::1").unwrap();
        assert_eq!(single.prefix(), 128);
        assert!(single.contains(ip("2001:db8::1")));
        assert!(!single.contains(ip("2001:db8::2")));
        assert_eq!(IpNetwork::parse("::/0").unwrap().prefix(), 0);
        assert!(
            IpNetwork::parse("0.0.0.0/0")
                .unwrap()
                .contains(ip("203.0.113.1"))
        );
        for invalid in [
            "",
            "example.com",
            "192.0.2.0/33",
            "2001:db8::/129",
            "192.0.2.1/24",
            "192.0.2.0/",
            "192.0.2.0/+24",
            "192.0.2.0/0024",
            "192.0.2.0/24/1",
            "::ffff:192.0.2.0/120",
            "fe80::1%eth0/128",
            " 192.0.2.0/24",
        ] {
            assert!(IpNetwork::parse(invalid).is_err(), "{invalid:?} parsed");
        }
    }

    #[test]
    fn untrusted_peer_ignores_the_header() {
        let trusted = proxies(&["192.0.2.0/28"], ForwardedHeader::XForwardedFor);
        let spoofed = headers("x-forwarded-for", &["198.51.100.7"]);
        assert_eq!(
            trusted.client_address(ip("203.0.113.9"), &spoofed),
            ip("203.0.113.9")
        );
        let none = TrustedProxies::default();
        assert_eq!(
            none.client_address(ip("192.0.2.10"), &spoofed),
            ip("192.0.2.10")
        );
        assert_eq!(
            none.client_address(ip("::ffff:192.0.2.10"), &spoofed),
            ip("192.0.2.10")
        );
    }

    #[test]
    fn x_forwarded_for_is_walked_from_the_right() {
        assert_eq!(xff(&["198.51.100.7"]), ip("198.51.100.7"));
        // The leftmost entry is whatever the client sent; it is never used
        // while an untrusted entry appended by the proxy follows it.
        assert_eq!(xff(&["203.0.113.66, 198.51.100.7"]), ip("198.51.100.7"));
        // Trusted hops between the client and the last proxy are skipped.
        assert_eq!(
            xff(&["203.0.113.66, 198.51.100.7, 192.0.2.3, 2001:db8:ffff::2"]),
            ip("198.51.100.7")
        );
        // Instances are concatenated in their received order.
        assert_eq!(
            xff(&["203.0.113.66", "198.51.100.7", "192.0.2.4"]),
            ip("198.51.100.7")
        );
        assert_eq!(xff(&["198.51.100.7:8443"]), ip("198.51.100.7"));
        assert_eq!(xff(&["[2001:db8:1::5]:8443"]), ip("2001:db8:1::5"));
        assert_eq!(xff(&["[2001:db8:1::5]"]), ip("2001:db8:1::5"));
        assert_eq!(xff(&[" 2001:db8:1::5 "]), ip("2001:db8:1::5"));
        assert_eq!(xff(&["::ffff:198.51.100.7"]), ip("198.51.100.7"));
    }

    #[test]
    fn malformed_or_exhausted_headers_fall_back_to_the_peer() {
        let peer = ip(PROXY);
        assert_eq!(xff(&[]), peer);
        assert_eq!(xff(&[""]), peer);
        assert_eq!(xff(&["192.0.2.3"]), peer);
        assert_eq!(xff(&["192.0.2.3, 2001:db8:ffff::9"]), peer);
        assert_eq!(xff(&["198.51.100.7,"]), peer);
        assert_eq!(xff(&["198.51.100.7, unknown"]), peer);
        assert_eq!(xff(&["198.51.100.7, garbage, 192.0.2.3"]), peer);
        assert_eq!(xff(&["198.51.100.7:99999"]), peer);
        assert_eq!(xff(&["[2001:db8:1::5]:"]), peer);
        assert_eq!(xff(&["fe80::1%eth0"]), peer);
        // Garbage to the left of the first untrusted entry is never examined.
        assert_eq!(xff(&["garbage, 198.51.100.7"]), ip("198.51.100.7"));
        let mut opaque = HeaderMap::new();
        opaque.insert(
            "x-forwarded-for",
            HeaderValue::from_bytes(b"198.51.100.\xff").unwrap(),
        );
        assert_eq!(
            proxies(&["192.0.2.0/28"], ForwardedHeader::XForwardedFor)
                .client_address(peer, &opaque),
            peer
        );
    }

    #[test]
    fn header_parsing_is_bounded() {
        let peer = ip(PROXY);
        let at_limit = vec!["198.51.100.7"; MAX_FORWARDED_ENTRIES].join(",");
        assert_eq!(xff(&[&at_limit]), ip("198.51.100.7"));
        let too_many = vec!["198.51.100.7"; MAX_FORWARDED_ENTRIES + 1].join(",");
        assert_eq!(xff(&[&too_many]), peer);
        let too_long = format!("{}198.51.100.7", " ".repeat(MAX_FORWARDED_BYTES));
        assert_eq!(xff(&[&too_long]), peer);
        let half = format!("{}198.51.100.7", " ".repeat(MAX_FORWARDED_BYTES / 2));
        assert_eq!(xff(&[&half]), ip("198.51.100.7"));
        assert_eq!(xff(&[&half, &half]), peer);
    }

    #[test]
    fn forwarded_syntax_is_parsed() {
        assert_eq!(forwarded(&["for=198.51.100.7"]), ip("198.51.100.7"));
        assert_eq!(
            forwarded(&[r#"for="[2001:db8:1::5]:4711";proto=https;by=192.0.2.10"#]),
            ip("2001:db8:1::5")
        );
        assert_eq!(
            forwarded(&[r#"For="198.51.100.7:4711""#]),
            ip("198.51.100.7")
        );
        assert_eq!(
            forwarded(&[r#"for=203.0.113.66, for=198.51.100.7;host="a,b", for=192.0.2.3"#]),
            ip("198.51.100.7")
        );
        assert_eq!(
            forwarded(&["for=203.0.113.66", "for=198.51.100.7;proto=https"]),
            ip("198.51.100.7")
        );
        assert_eq!(forwarded(&["for=\"[2001:db8:ffff::1]\""]), ip(PROXY));
        let peer = ip(PROXY);
        for malformed in [
            "for=unknown",
            "for=_hidden",
            "proto=https",
            "for=198.51.100.7;for=203.0.113.66",
            r#"for="198.51.100.7"#,
            r#"for="198.51\"100.7""#,
            "for",
            "for=203.0.113.66, by=192.0.2.10",
        ] {
            assert_eq!(forwarded(&[malformed]), peer, "{malformed:?} accepted");
        }
        // The other header type is ignored entirely.
        assert_eq!(
            proxies(&["192.0.2.0/28"], ForwardedHeader::Forwarded)
                .client_address(peer, &headers("x-forwarded-for", &["198.51.100.7"])),
            peer
        );
    }
}
