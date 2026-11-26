// Copyright 2026 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Trusted proxy allowlists and zero-over-read HAProxy PROXY protocol v1/v2 parsing.
//!
//! Responsible for: matching socket peers against validated IPv4/IPv6 CIDR allowlists,
//! defining [`ProxyPolicy`], and reading bounded PROXY protocol v1/v2 headers off a `TcpStream`
//! without consuming any following TLS or HTTP byte.
//! NOT responsible for: per-IP seat counting (`client_admission`) or HTTP `Forwarded` headers.
//! Upstream: `ServerConfig::proxy_policy` and `conn`. Downstream: `conn` admission and `ConnectionInfo`.

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio::io::AsyncReadExt;

use crate::config::ConfigError;

/// Maximum PROXY protocol v1 line length including the trailing `\r\n` (HAProxy spec §2.1).
const MAX_V1_LEN: usize = 107;
/// Exact 12-byte PROXY protocol v2 signature (HAProxy spec §2.2).
const V2_SIGNATURE: [u8; 12] = [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];
/// Fixed PROXY protocol v2 header prefix size (12-byte signature + 4-byte metadata).
const V2_HEADER_LEN: usize = 16;
/// Upper bound on PROXY protocol v2 address + TLV payload length read per accepted socket.
const MAX_V2_PAYLOAD_LEN: usize = 512;

/// Validated IPv4 or IPv6 CIDR range used in [`ProxyPolicy`] allowlists.
///
/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are canonicalized to IPv4 on both construction
/// and matching so dual-stack listeners match configured IPv4 proxies reliably.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

impl IpCidr {
    /// Builds a validated CIDR range from any IP address and prefix length.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidCidrPrefix`] if `prefix` exceeds 32 for IPv4 or 128 for IPv6.
    pub fn new(ip: IpAddr, prefix: u8) -> Result<Self, ConfigError> {
        match ip {
            IpAddr::V4(v4) => Self::v4(v4, prefix),
            IpAddr::V6(v6) => Self::v6(v6, prefix),
        }
    }

    /// Builds a validated IPv4 CIDR range (`0..=32`).
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidCidrPrefix`] when `prefix > 32`.
    pub fn v4(ip: Ipv4Addr, prefix: u8) -> Result<Self, ConfigError> {
        if prefix > 32 {
            return Err(ConfigError::InvalidCidrPrefix { prefix, max: 32 });
        }
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0)
        };
        let masked = Ipv4Addr::from(u32::from(ip) & mask);
        Ok(Self {
            network: IpAddr::V4(masked),
            prefix,
        })
    }

    /// Builds a validated IPv6 CIDR range (`0..=128`).
    ///
    /// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are canonicalized to IPv4 with prefix
    /// `prefix - 96`, rejecting prefixes below `96`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidCidrPrefix`] when `prefix > 128`, or when `ip` is an
    /// IPv4-mapped IPv6 address and `prefix < 96`.
    pub fn v6(ip: Ipv6Addr, prefix: u8) -> Result<Self, ConfigError> {
        if let Some(mapped) = ip.to_ipv4_mapped() {
            if !(96..=128).contains(&prefix) {
                return Err(ConfigError::InvalidCidrPrefix { prefix, max: 128 });
            }
            return Self::v4(mapped, prefix - 96);
        }
        if prefix > 128 {
            return Err(ConfigError::InvalidCidrPrefix { prefix, max: 128 });
        }
        let mask = if prefix == 0 {
            0
        } else {
            u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0)
        };
        let masked = Ipv6Addr::from(u128::from(ip) & mask);
        Ok(Self {
            network: IpAddr::V6(masked),
            prefix,
        })
    }

    /// Builds a single-host CIDR (`/32` for IPv4, `/128` for IPv6).
    #[must_use]
    pub fn host(ip: IpAddr) -> Self {
        match ip.to_canonical() {
            IpAddr::V4(v4) => Self {
                network: IpAddr::V4(v4),
                prefix: 32,
            },
            IpAddr::V6(v6) => Self {
                network: IpAddr::V6(v6),
                prefix: 128,
            },
        }
    }

    /// Returns whether `peer` (canonicalized for dual-stack IPv4-mapped peers) belongs to this CIDR.
    #[must_use]
    pub fn contains(&self, peer: IpAddr) -> bool {
        match (self.network, peer.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(candidate)) => {
                if self.prefix == 0 {
                    true
                } else {
                    let mask = u32::MAX.checked_shl(u32::from(32 - self.prefix)).unwrap_or(0);
                    (u32::from(candidate) & mask) == u32::from(net)
                }
            }
            (IpAddr::V6(net), IpAddr::V6(candidate)) => {
                if self.prefix == 0 {
                    true
                } else {
                    let mask = u128::MAX.checked_shl(u32::from(128 - self.prefix)).unwrap_or(0);
                    (u128::from(candidate) & mask) == u128::from(net)
                }
            }
            _ => false,
        }
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

impl FromStr for IpCidr {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.split_once('/') {
            Some((addr, prefix)) => {
                let ip: IpAddr = addr.parse().map_err(|_| format!("invalid CIDR address: {text}"))?;
                let prefix: u8 = prefix.parse().map_err(|_| format!("invalid CIDR prefix: {text}"))?;
                Self::new(ip, prefix).map_err(|error| error.to_string())
            }
            None => {
                let ip: IpAddr = text.parse().map_err(|_| format!("invalid IP address: {text}"))?;
                Ok(Self::host(ip))
            }
        }
    }
}

impl Serialize for IpCidr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for IpCidr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// How per-IP connection admission treats connections arriving from reverse proxies or load balancers.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum ProxyPolicy {
    /// Every connection is keyed directly on its raw socket peer address.
    #[default]
    Direct,
    /// Connections whose raw socket peer matches `trusted_proxies` must begin with a valid HAProxy
    /// PROXY protocol v1 or v2 header. Per-IP admission and [`crate::ConnectionInfo::peer_addr`]
    /// use the attested client address. Untrusted peers never parse PROXY headers.
    ProxyProtocol {
        /// Non-empty allowlist of proxy IPs or CIDR ranges permitted to supply PROXY headers.
        trusted_proxies: Vec<IpCidr>,
    },
    /// Connections whose raw socket peer matches `trusted_proxies` bypass the per-IP connection
    /// ceiling (while remaining bounded by [`crate::ServerConfig::max_connections`]). All other
    /// peers remain subject to [`crate::ServerConfig::max_connections_per_ip`].
    ExemptTrustedProxies {
        /// Non-empty allowlist of proxy IPs or CIDR ranges exempt from the per-IP ceiling.
        trusted_proxies: Vec<IpCidr>,
    },
}

impl ProxyPolicy {
    pub(crate) fn is_trusted_proxy_protocol_peer(&self, peer: IpAddr) -> bool {
        match self {
            Self::ProxyProtocol { trusted_proxies } => trusted_proxies.iter().any(|cidr| cidr.contains(peer)),
            Self::Direct | Self::ExemptTrustedProxies { .. } => false,
        }
    }

    pub(crate) fn is_exempt_from_per_ip(&self, peer: IpAddr) -> bool {
        match self {
            Self::ExemptTrustedProxies { trusted_proxies } => trusted_proxies.iter().any(|cidr| cidr.contains(peer)),
            Self::Direct | Self::ProxyProtocol { .. } => false,
        }
    }
}

/// Reads and strictly validates one HAProxy PROXY protocol v1 or v2 header from `reader` without
/// consuming a single byte past the end of the PROXY header.
///
/// Returns the attested client socket address for forwarded connections, or `socket_peer` for
/// PROXY v1 `UNKNOWN` and PROXY v2 `LOCAL` health checks.
pub(crate) async fn read_proxy_header<R>(reader: &mut R, socket_peer: SocketAddr) -> io::Result<SocketAddr>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut prefix = [0_u8; 6];
    reader.read_exact(&mut prefix).await?;
    if &prefix == b"PROXY " {
        read_v1_header(reader, socket_peer).await
    } else if V2_SIGNATURE.get(..6) == Some(prefix.as_slice()) {
        read_v2_header(reader, prefix, socket_peer).await
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing or unrecognized PROXY protocol header",
        ))
    }
}

async fn read_v1_header<R>(reader: &mut R, socket_peer: SocketAddr) -> io::Result<SocketAddr>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut line = [0_u8; MAX_V1_LEN];
    if let Some(dest) = line.get_mut(..6) {
        dest.copy_from_slice(b"PROXY ");
    }
    let mut len = 6;
    while len < MAX_V1_LEN {
        let mut byte = [0_u8; 1];
        reader.read_exact(&mut byte).await?;
        let [octet] = byte;
        let slot = line
            .get_mut(len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "PROXY v1 header exceeded 107 bytes"))?;
        *slot = octet;
        len += 1;
        if len >= 8 && line.get(len - 2..len) == Some(b"\r\n") {
            let body = line
                .get(6..len - 2)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "PROXY v1 header malformed"))?;
            return parse_v1_fields(body, socket_peer);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "PROXY v1 header exceeded 107 bytes without CRLF",
    ))
}

fn parse_v1_fields(body: &[u8], socket_peer: SocketAddr) -> io::Result<SocketAddr> {
    let text =
        std::str::from_utf8(body).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "PROXY v1 header is not UTF-8"))?;
    if text.contains('\r') || text.contains('\n') {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "PROXY v1 header contains stray CR or LF"));
    }
    let mut parts = text.split(' ');
    let protocol = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "PROXY v1 protocol missing"))?;
    match protocol {
        "UNKNOWN" => Ok(socket_peer),
        "TCP4" | "TCP6" => {
            let src_ip = parts
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "PROXY v1 source IP missing"))?;
            let dst_ip = parts
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "PROXY v1 destination IP missing"))?;
            let src_port = parts
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "PROXY v1 source port missing"))?;
            let dst_port = parts
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "PROXY v1 destination port missing"))?;
            if parts.next().is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "PROXY v1 header has unexpected trailing fields",
                ));
            }
            let src_port = parse_v1_port(src_port)?;
            let _dst_port = parse_v1_port(dst_port)?;
            if protocol == "TCP4" {
                let src: Ipv4Addr = src_ip
                    .parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid PROXY v1 IPv4 source"))?;
                let _dst: Ipv4Addr = dst_ip
                    .parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid PROXY v1 IPv4 destination"))?;
                Ok(SocketAddr::new(IpAddr::V4(src), src_port))
            } else {
                let src: Ipv6Addr = src_ip
                    .parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid PROXY v1 IPv6 source"))?;
                let _dst: Ipv6Addr = dst_ip
                    .parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid PROXY v1 IPv6 destination"))?;
                Ok(SocketAddr::new(IpAddr::V6(src), src_port))
            }
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported PROXY v1 transport protocol")),
    }
}

fn parse_v1_port(text: &str) -> io::Result<u16> {
    if text.is_empty() || (text.len() > 1 && text.starts_with('0')) || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid PROXY v1 port"));
    }
    text.parse::<u16>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "PROXY v1 port out of range"))
}

async fn read_v2_header<R>(reader: &mut R, prefix: [u8; 6], socket_peer: SocketAddr) -> io::Result<SocketAddr>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut header = [0_u8; V2_HEADER_LEN];
    if let Some(head) = header.get_mut(..6) {
        head.copy_from_slice(&prefix);
    }
    if let Some(tail) = header.get_mut(6..) {
        reader.read_exact(tail).await?;
    }
    if header.get(..12) != Some(&V2_SIGNATURE[..]) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid PROXY v2 signature"));
    }
    let [.., ver_cmd, fam_proto, len_hi, len_lo] = header;
    let version = ver_cmd >> 4;
    let command = ver_cmd & 0x0f;
    if version != 0x02 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported PROXY v2 version"));
    }
    let payload_len = usize::from(u16::from_be_bytes([len_hi, len_lo]));
    if payload_len > MAX_V2_PAYLOAD_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "PROXY v2 payload length exceeds bound"));
    }
    let mut payload = [0_u8; MAX_V2_PAYLOAD_LEN];
    let body = payload
        .get_mut(..payload_len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "PROXY v2 payload length exceeds bound"))?;
    if !body.is_empty() {
        reader.read_exact(body).await?;
    }
    match command {
        // LOCAL (health check or proxy-originated connection).
        0x00 => Ok(socket_peer),
        // PROXY (forwarded client connection).
        0x01 => parse_v2_address(fam_proto, body, socket_peer),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported PROXY v2 command")),
    }
}

fn parse_v2_address(fam_proto: u8, payload: &[u8], socket_peer: SocketAddr) -> io::Result<SocketAddr> {
    let family = fam_proto >> 4;
    let transport = fam_proto & 0x0f;
    match (family, transport) {
        (0x00, 0x00) => Ok(socket_peer),
        // AF_INET (0x1) + STREAM (0x1) or DGRAM (0x2): 4 src + 4 dst + 2 sport + 2 dport = 12 bytes.
        (0x01, 0x01 | 0x02) => {
            let Some(addr) = payload.get(..12) else {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "PROXY v2 IPv4 address block truncated"));
            };
            let Ok([a0, a1, a2, a3, _, _, _, _, sp0, sp1, _, _]): Result<[u8; 12], _> = addr.try_into() else {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "PROXY v2 IPv4 address block truncated"));
            };
            let src = Ipv4Addr::new(a0, a1, a2, a3);
            let sport = u16::from_be_bytes([sp0, sp1]);
            Ok(SocketAddr::new(IpAddr::V4(src), sport))
        }
        // AF_INET6 (0x2) + STREAM (0x1) or DGRAM (0x2): 16 src + 16 dst + 2 sport + 2 dport = 36 bytes.
        (0x02, 0x01 | 0x02) => {
            let Some(addr) = payload.get(..36) else {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "PROXY v2 IPv6 address block truncated"));
            };
            let Ok(octets): Result<[u8; 16], _> = addr.get(..16).unwrap_or_default().try_into() else {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "PROXY v2 IPv6 address block truncated"));
            };
            let Ok(port_bytes): Result<[u8; 2], _> = addr.get(32..34).unwrap_or_default().try_into() else {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "PROXY v2 IPv6 address block truncated"));
            };
            let src = Ipv6Addr::from(octets);
            let sport = u16::from_be_bytes(port_bytes);
            Ok(SocketAddr::new(IpAddr::V6(src), sport))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported PROXY v2 address family or transport",
        )),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn peer() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999)
    }

    #[test]
    fn ip_cidr_matches_canonical_ipv4_and_ipv6_ranges_and_rejects_invalid_prefixes() {
        assert!(IpCidr::v4(Ipv4Addr::new(10, 0, 0, 1), 33).is_err());
        assert!(IpCidr::v6(Ipv6Addr::LOCALHOST, 129).is_err());
        let cidr = IpCidr::v4(Ipv4Addr::new(10, 1, 2, 3), 24).expect("valid v4 cidr");
        assert!(cidr.contains(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 200))));
        assert!(cidr.contains("::ffff:10.1.2.99".parse().expect("mapped ip")));
        assert!(!cidr.contains(IpAddr::V4(Ipv4Addr::new(10, 1, 3, 1))));
    }

    #[test]
    fn n_ip_cidr_v6_canonicalizes_ipv4_mapped_addresses_and_rejects_short_prefixes() {
        let mapped: Ipv6Addr = "::ffff:10.1.2.3".parse().expect("valid IPv4-mapped IPv6");
        for bad_prefix in [0_u8, 32, 95, 129] {
            assert_eq!(
                IpCidr::v6(mapped, bad_prefix),
                Err(ConfigError::InvalidCidrPrefix {
                    prefix: bad_prefix,
                    max: 128,
                }),
                "IpCidr::v6 must reject prefix {bad_prefix} on IPv4-mapped IPv6"
            );
        }

        let cidr = IpCidr::v6(mapped, 120).expect("valid IPv4-mapped /120");
        assert_eq!(cidr, IpCidr::v4(Ipv4Addr::new(10, 1, 2, 0), 24).expect("valid v4"));
        assert!(cidr.contains(IpAddr::V6(mapped)));
        assert!(cidr.contains(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 99))));
        assert!(cidr.contains("::ffff:10.1.2.99".parse().expect("mapped peer")));
        assert!(!cidr.contains(IpAddr::V4(Ipv4Addr::new(10, 1, 3, 1))));
        assert!(!cidr.contains("::ffff:10.1.3.1".parse().expect("outside mapped peer")));

        let host_cidr = IpCidr::v6(mapped, 128).expect("valid IPv4-mapped /128");
        assert!(host_cidr.contains(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!host_cidr.contains(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 4))));

        let any_v4 = IpCidr::v6("::ffff:0.0.0.0".parse().expect("mapped zero"), 96).expect("valid /96");
        assert!(any_v4.contains(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))));
        assert!(!any_v4.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[tokio::test]
    async fn n_malformed_and_oversized_proxy_headers_are_rejected() {
        for raw in [
            b"GET / HTTP/1.1\r\n\r\n".as_slice(),
            b"PROXY TCP4 203.0.113.1 10.0.0.1 0123 443\r\n",
            b"PROXY TCP4 999.0.0.1 10.0.0.1 123 443\r\n",
            b"PROXY TCP4 203.0.113.1 10.0.0.1 123 443 extra\r\n",
            b"PROXY UDP4 203.0.113.1 10.0.0.1 123 443\r\n",
            b"PROXY TCP4 203.0.113.1 10.0.0.1 123 443\n",
            &[b'A'; 120],
        ] {
            let mut cursor = raw;
            assert!(
                read_proxy_header(&mut cursor, peer()).await.is_err(),
                "must reject malformed PROXY header: {:?}",
                String::from_utf8_lossy(raw)
            );
        }

        // Oversized PROXY v2 payload (> 512 bytes) is rejected before allocation.
        let mut oversized_v2 = Vec::from(V2_SIGNATURE);
        oversized_v2.extend_from_slice(&[0x21, 0x11, 0x02, 0x01]); // length = 513
        let mut cursor = oversized_v2.as_slice();
        assert!(read_proxy_header(&mut cursor, peer()).await.is_err());

        // Truncated PROXY v2 IPv4 payload (11 bytes instead of 12).
        let mut truncated_v2 = Vec::from(V2_SIGNATURE);
        truncated_v2.extend_from_slice(&[0x21, 0x11, 0x00, 0x0b]);
        truncated_v2.extend_from_slice(&[0_u8; 11]);
        let mut cursor = truncated_v2.as_slice();
        assert!(read_proxy_header(&mut cursor, peer()).await.is_err());
    }

    #[tokio::test]
    async fn valid_proxy_v1_and_v2_preserve_trailing_http_bytes_unread() {
        let mut v1 = b"PROXY TCP4 203.0.113.5 10.0.0.1 54321 443\r\nGET / HTTP/1.1".as_slice();
        let client = read_proxy_header(&mut v1, peer()).await.expect("valid v1");
        assert_eq!(client, "203.0.113.5:54321".parse::<SocketAddr>().expect("addr"));
        assert_eq!(v1, b"GET / HTTP/1.1", "must not over-read past CRLF");

        let mut v2 = Vec::from(V2_SIGNATURE);
        v2.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]); // v2 PROXY, AF_INET STREAM, len 12
        v2.extend_from_slice(&[198, 51, 100, 7, 10, 0, 0, 1]);
        v2.extend_from_slice(&44_321_u16.to_be_bytes());
        v2.extend_from_slice(&443_u16.to_be_bytes());
        v2.extend_from_slice(b"HELLO");
        let mut cursor = v2.as_slice();
        let client = read_proxy_header(&mut cursor, peer()).await.expect("valid v2");
        assert_eq!(client, "198.51.100.7:44321".parse::<SocketAddr>().expect("addr"));
        assert_eq!(cursor, b"HELLO", "must not over-read past v2 payload");
    }
}
