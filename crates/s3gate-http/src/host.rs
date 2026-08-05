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

//! The one effective-host determination, made once per request and never repeated.
//!
//! Responsible for: reconciling `:authority` (or an HTTP/1.1 absolute-form request target) with
//! the `Host` header, refusing every way the two can disagree, and producing an
//! [`EffectiveHost`] that carries both the normalised value routing reads and the raw bytes
//! signing reads.
//! NOT responsible for: extracting a bucket from a host (virtual-hosted style is P4-01),
//! resolving a name, deciding a region, or verifying a signature. This module returns a value; it
//! never decides what the value means.
//! Upstream: `http`, and this crate's `text`. Downstream: `wire`, and through the stored value
//! every router and every signer.
//!
//! # Why this exists at all
//!
//! The server library performs no `Host` validation whatsoever. A request with no `Host` header,
//! with an empty one, with two conflicting ones, or with an HTTP/2 `:authority` that contradicts
//! its `host` header is delivered to the application unchanged and, left alone, answered `200`.
//! RFC 9112 §5.5 describes how to rebuild the effective request URI and leaves the work to the
//! application; hyper's issue #1612 ("Getting Effective URI") is open for exactly that reason.
//! This module is that work. Getting it wrong is not a cosmetic bug: the signature covers the
//! `Host` header, so a request signed for one host and routed to another is a signature bypass.
//!
//! # Reject, do not choose
//!
//! RFC 9112 §3.2.2 tells an origin server to *ignore* the `Host` header when the request target
//! is in absolute-form. A gateway must not: "the two sources disagree" is itself the signal, and
//! discarding one of them is how the gateway and the backend end up acting on different hosts.
//! Every disagreement here is [`HostError::Conflict`], and every malformed host is
//! [`HostError::Invalid`] — a `400`, never a `403`, so a bad host is distinguishable from a
//! failed signature in a log without reading the request back.

use http::{HeaderMap, HeaderValue, Request, Uri, header::HOST};

use crate::text::{AsciiBuf, is_all_ascii_graphic};

/// The longest host this layer accepts, including any port.
///
/// A fully qualified DNS name is at most 253 characters; the extra bytes leave room for a port
/// and a bracketed IPv6 literal without admitting an unbounded header value.
pub const MAX_HOST_BYTES: usize = 273;

/// Where the effective host was read from.
///
/// Recorded rather than discarded because the two sources are signed differently: SigV4 covers
/// the `Host` header, and a request whose host came from the request target has no `Host` header
/// to canonicalise. A signer that cannot tell the two apart cannot be correct for both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostSource {
    /// The `Host` header field.
    HostHeader,
    /// The authority component of the request target: an HTTP/2 `:authority`, or an HTTP/1.1
    /// absolute-form request target.
    Authority,
}

impl HostSource {
    /// A short, stable label for logs and tests.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HostHeader => "host-header",
            Self::Authority => "authority",
        }
    }
}

/// Why a host could not be determined.
///
/// Each variant corresponds to one row of the ambiguity matrix, and each is a `400`. They are
/// kept apart rather than collapsed into one "bad host" because they say different things about
/// the peer: `Missing` is usually an old client, `Conflict` and `Duplicate` are almost never
/// anything but an attempt to make two components disagree.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostError {
    /// Neither a request-target authority nor a `Host` header was present.
    Missing,
    /// More than one `Host` header field was present, whether or not the values agreed.
    Duplicate,
    /// A request-target authority and a `Host` header were both present and differ.
    Conflict,
    /// A host was present but is not a well-formed authority: empty, non-ASCII, containing a
    /// control character, carrying userinfo, or bearing an unusable port.
    Invalid,
}

impl HostError {
    /// A short, stable label for logs and tests.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Duplicate => "duplicate",
            Self::Conflict => "conflict",
            Self::Invalid => "invalid",
        }
    }
}

/// The host exactly as it arrived, plus where it came from.
///
/// This is the signer's only input. It is deliberately awkward to obtain — [`EffectiveHost`]
/// exposes it through one method with a name that says what it is for — because normalisation is
/// many-to-one: `B.Example.COM.`, `b.example.com.` and `b.example.com` all normalise together,
/// and a signature computed over the normalised form would be valid for all three.
#[derive(Clone, Debug)]
pub struct RawHost {
    bytes: AsciiBuf,
    source: HostSource,
}

impl RawHost {
    /// The bytes as received, in their original case, with any trailing dot and port intact.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_str().as_bytes()
    }

    /// The bytes as received, as a string.
    ///
    /// A host that is not ASCII never gets this far — [`HostError::Invalid`] is returned first —
    /// so no lossy conversion is involved and none is offered.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.bytes.as_str()
    }

    /// Where these bytes were read from.
    #[must_use]
    pub fn source(&self) -> HostSource {
        self.source
    }
}

/// The determined host: normalised for routing, raw for signing.
///
/// Constructed once per request by [`effective_host`] and stored on the
/// [`WireRequest`](crate::WireRequest). Nothing downstream re-derives it, reads the `HOST` header
/// again, or looks at the request target — those are the three ways two components come to
/// disagree about the same request.
#[derive(Clone, Debug)]
pub struct EffectiveHost {
    normalized: AsciiBuf,
    /// Byte offset of the `:` that begins the port, if any, within `normalized`.
    port_at: Option<usize>,
    port: Option<u16>,
    raw: RawHost,
}

impl EffectiveHost {
    /// The normalised host: lowercased, with a trailing root dot removed, port retained.
    ///
    /// One normalisation function produces this, and both the router and the virtual-host
    /// resolver read this stored value; there is deliberately no second implementation for either
    /// of them to drift from.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.normalized.as_str()
    }

    /// The normalised host with any port removed — what virtual-hosted-style routing matches on.
    #[must_use]
    pub fn host_without_port(&self) -> &str {
        let text = self.normalized.as_str();
        match self.port_at {
            Some(at) => text.get(..at).unwrap_or(text),
            None => text,
        }
    }

    /// The port, when the host carried one.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Where the host came from.
    #[must_use]
    pub fn source(&self) -> HostSource {
        self.raw.source
    }

    /// Whether both the raw and the normalised host stayed off the heap.
    ///
    /// Exposed so the allocation budget this layer promises can be asserted rather than claimed;
    /// it says nothing about the host itself and no routing decision may read it.
    #[must_use]
    pub fn is_inline(&self) -> bool {
        self.normalized.is_inline() && self.raw.bytes.is_inline()
    }

    /// The raw bytes, for the canonical request and for nothing else.
    ///
    /// This is the only accessor that yields un-normalised bytes. Signing must use it; routing
    /// must not.
    #[must_use]
    pub fn raw_for_signing(&self) -> &RawHost {
        &self.raw
    }
}

/// Determines the effective host of a request.
///
/// Called once, as early as possible, and the result stored. See [`effective_host_of`] for the
/// decision table.
///
/// # Errors
///
/// [`HostError`], one variant per ambiguity; every one of them is a `400`.
pub fn effective_host<B>(request: &Request<B>) -> Result<EffectiveHost, HostError> {
    effective_host_of(request.uri(), request.headers())
}

/// Determines the effective host from a request target and a header map.
///
/// The decision table, one row per shape observed against a real server:
///
/// | request-target authority | `Host` header | result |
/// |---|---|---|
/// | present | absent | accepted, source [`HostSource::Authority`] |
/// | present | present, equal ignoring ASCII case | accepted, source [`HostSource::Authority`] |
/// | present | present, different | [`HostError::Conflict`] |
/// | absent | present, non-empty | accepted, source [`HostSource::HostHeader`] |
/// | absent | present, empty | [`HostError::Invalid`] |
/// | absent | present twice or more | [`HostError::Duplicate`] |
/// | absent | absent | [`HostError::Missing`] |
///
/// Two of those rows are not defensive programming. An HTTP/2 request may legally carry `host`
/// and no `:authority` (RFC 9113 §8.3.1), in which case the request target has neither an
/// authority nor a scheme; and an HTTP/1.1 absolute-form request target supplies an authority
/// while the `Host` header says something else entirely. Assuming either component is always
/// present produces a gateway that authenticates one host and serves another.
///
/// # Errors
///
/// [`HostError`], as tabulated above.
pub fn effective_host_of(uri: &Uri, headers: &HeaderMap) -> Result<EffectiveHost, HostError> {
    let authority = uri.authority().map(http::uri::Authority::as_str);

    let mut host_values = headers.get_all(HOST).iter();
    let first_host: Option<&HeaderValue> = host_values.next();
    let has_second_host = host_values.next().is_some();

    // A duplicated `Host` is refused even when the two values are byte-identical: an intermediary
    // that keeps one and a backend that keeps the other still see one request each way, and the
    // identical case is the one an attacker uses to find out which end wins.
    if has_second_host {
        return Err(HostError::Duplicate);
    }

    match (authority, first_host) {
        (Some(authority_text), Some(host_value)) => {
            let host_bytes = host_value.as_bytes();
            if !authority_text.as_bytes().eq_ignore_ascii_case(host_bytes) {
                return Err(HostError::Conflict);
            }
            build(authority_text.as_bytes(), HostSource::Authority)
        }
        (Some(authority_text), None) => build(authority_text.as_bytes(), HostSource::Authority),
        (None, Some(host_value)) => build(host_value.as_bytes(), HostSource::HostHeader),
        (None, None) => Err(HostError::Missing),
    }
}

/// Validates and normalises one authority.
fn build(bytes: &[u8], source: HostSource) -> Result<EffectiveHost, HostError> {
    if bytes.is_empty() || bytes.len() > MAX_HOST_BYTES {
        return Err(HostError::Invalid);
    }
    // Non-ASCII is refused rather than percent-decoded or punycoded. An internationalised host
    // has exactly one wire spelling — its A-label — and accepting a second spelling here would
    // mean two byte strings routing to one bucket while only one of them was signed.
    if !is_all_ascii_graphic(bytes) {
        return Err(HostError::Invalid);
    }
    // Userinfo, a path, a query or a fragment inside what is supposed to be an authority means
    // some other component parsed this string differently than we are about to.
    if bytes.iter().any(|byte| matches!(byte, b'@' | b'/' | b'\\' | b'?' | b'#')) {
        return Err(HostError::Invalid);
    }

    let (host_part, port_part) = split_port(bytes)?;
    validate_host_part(host_part)?;
    let port = match port_part {
        Some(digits) => Some(parse_port(digits)?),
        None => None,
    };

    let mut raw = AsciiBuf::new();
    for byte in bytes {
        if !raw.push_ascii(*byte) {
            return Err(HostError::Invalid);
        }
    }

    let mut normalized = AsciiBuf::new();
    // The root dot is stripped: `example.com.` and `example.com` name the same host, and leaving
    // both spellings in play would give one bucket two routing keys.
    let trimmed = strip_root_dot(host_part);
    for byte in trimmed {
        if !normalized.push_ascii(byte.to_ascii_lowercase()) {
            return Err(HostError::Invalid);
        }
    }
    let port_at = match port_part {
        Some(digits) => {
            let at = normalized.as_str().len();
            if !normalized.push_ascii(b':') {
                return Err(HostError::Invalid);
            }
            for byte in digits {
                if !normalized.push_ascii(*byte) {
                    return Err(HostError::Invalid);
                }
            }
            Some(at)
        }
        None => None,
    };

    Ok(EffectiveHost {
        normalized,
        port_at,
        port,
        raw: RawHost { bytes: raw, source },
    })
}

/// Splits an authority into its host and port components, honouring bracketed IPv6 literals.
fn split_port(bytes: &[u8]) -> Result<(&[u8], Option<&[u8]>), HostError> {
    if bytes.first() == Some(&b'[') {
        let close = bytes.iter().position(|byte| *byte == b']').ok_or(HostError::Invalid)?;
        let after = close.saturating_add(1);
        let host = bytes.get(..after).ok_or(HostError::Invalid)?;
        return match bytes.get(after..) {
            None | Some([]) => Ok((host, None)),
            Some([b':', rest @ ..]) => Ok((host, Some(rest))),
            Some(_) => Err(HostError::Invalid),
        };
    }
    match bytes.iter().position(|byte| *byte == b':') {
        Some(at) => {
            let host = bytes.get(..at).ok_or(HostError::Invalid)?;
            let rest = bytes.get(at.saturating_add(1)..).ok_or(HostError::Invalid)?;
            // A second colon outside brackets means the peer sent something neither an IPv6
            // literal nor a `host:port`, and two parsers will disagree about which colon counts.
            if rest.contains(&b':') {
                return Err(HostError::Invalid);
            }
            Ok((host, Some(rest)))
        }
        None => Ok((bytes, None)),
    }
}

/// Checks the host component: a bracketed IPv6 literal, or a run of DNS-legal characters.
fn validate_host_part(host: &[u8]) -> Result<(), HostError> {
    if host.is_empty() {
        return Err(HostError::Invalid);
    }
    if host.first() == Some(&b'[') {
        let inner_end = host.len().saturating_sub(1);
        if host.last() != Some(&b']') || inner_end <= 1 {
            return Err(HostError::Invalid);
        }
        let inner = host.get(1..inner_end).ok_or(HostError::Invalid)?;
        let ok = inner
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() || matches!(byte, b':' | b'.' | b'%'));
        return if ok { Ok(()) } else { Err(HostError::Invalid) };
    }
    let ok = host
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'));
    if !ok {
        return Err(HostError::Invalid);
    }
    // An empty label (`a..b`, or a leading dot) has no single interpretation across resolvers.
    if host.first() == Some(&b'.') || host.windows(2).any(|pair| pair == b"..") {
        return Err(HostError::Invalid);
    }
    Ok(())
}

/// Parses a port, rejecting everything a lenient integer parser would accept.
fn parse_port(digits: &[u8]) -> Result<u16, HostError> {
    if digits.is_empty() || digits.len() > 5 || !digits.iter().all(u8::is_ascii_digit) {
        return Err(HostError::Invalid);
    }
    let mut port: u32 = 0;
    for byte in digits {
        let digit = u32::from(byte.wrapping_sub(b'0'));
        port = port
            .checked_mul(10)
            .and_then(|acc| acc.checked_add(digit))
            .ok_or(HostError::Invalid)?;
    }
    u16::try_from(port).map_err(|_| HostError::Invalid)
}

/// Removes one trailing root dot from a host component, leaving a bare `.` alone.
fn strip_root_dot(host: &[u8]) -> &[u8] {
    if host.len() > 1 && host.last() == Some(&b'.') {
        return host.get(..host.len().saturating_sub(1)).unwrap_or(host);
    }
    host
}
