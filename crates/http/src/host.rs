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
//! [`EffectiveHost`] that carries both the normalised value routing reads and the [`RawHost`]
//! bytes signing reads.
//! NOT responsible for: extracting a bucket from a host (virtual-hosted style is P4-01), the
//! `X-Forwarded-Host` trust model (P6-03), resolving a name, deciding a region, or verifying a
//! signature. This module returns a value; it never decides what the value means.
//! Upstream: `http`, and this crate's `text`. Downstream: `wire`, `rustfs-gateway-sig`'s canonical
//! request — which accepts a [`RawHost`] and nothing else — and through the stored value every
//! router and every signer.
//!
//! # Why this exists at all
//!
//! The server library performs no `Host` validation whatsoever. Measured against a hyper 1.11.0
//! server driven by hand-written HTTP/1.1 byte streams and h2 frames, every one of these reached
//! the handler with a `200`: no `Host` header at all, an empty one, two contradicting ones, an
//! HTTP/1.1 absolute-form target whose authority disagreed with `Host`, and an h2 request whose
//! `:authority` disagreed with its `host`. RFC 9112 §5.5 describes how to rebuild the effective
//! request URI and leaves the work to the application; hyper's issue #1612 ("Getting Effective
//! URI") is open for exactly that reason. This module is that work. Getting it wrong is not a
//! cosmetic bug: the signature covers the `Host` header, so a request signed for one host and
//! routed to another is a signature bypass.
//!
//! # One determination, two readings
//!
//! It has to be the *only* place the host is decided. If the canonical request is built from one
//! source and the bucket route from another, an attacker signs for `good` and is routed as `evil`.
//! So [`effective_host`] runs once, the result is stored on the [`WireRequest`](crate::WireRequest),
//! and the two readings of that one value are deliberately different types:
//!
//! * routing reads [`EffectiveHost::as_str`] — lowercased, trailing root dot removed;
//! * signing reads [`EffectiveHost::raw_for_signing`] — a [`RawHost`], byte-exact.
//!
//! Normalisation is many-to-one: `B.Example.COM.`, `b.example.com.` and `b.example.com` all
//! normalise together, and a signature computed over the normalised form would be valid for all
//! three. Giving the canonical builder no way to learn the host except a [`RawHost`] makes that
//! mistake unspellable rather than merely discouraged.
//!
//! # Reject, do not choose
//!
//! RFC 9112 §3.2.2 tells an origin server to *ignore* the `Host` header when the request target
//! is in absolute-form, and RFC 9113 §8.3.1 requires `:authority` and `host` to agree when both
//! are sent. A gateway must not ignore: "the two sources disagree" is itself the signal, and
//! discarding one of them is how the gateway and the backend end up acting on different hosts.
//! Every disagreement here is [`HostError::Conflict`], and every malformed host is
//! [`HostError::Invalid`] — [`HostError::HTTP_STATUS`], never a `403`, so a bad host is
//! distinguishable from a failed signature in a log without reading the request back.
//!
//! # Where the two P2/P3 drafts disagreed, and which one won
//!
//! This module is the merge of the P2-03 host resolver that lived in `rustfs-gateway-sig` and the
//! P3-01 one that lived here. Two independent implementations of "which host is this" is exactly
//! the divergence the module exists to prevent, so there is now one. Each point on which the two
//! drafts differed was resolved towards the stricter reading:
//!
//! | point | P3-01 (here) | P2-03 (sig) | merged |
//! |---|---|---|---|
//! | authority vs `Host` comparison | `eq_ignore_ascii_case` | byte-exact | **`eq_ignore_ascii_case`** |
//! | ceiling | 273 bytes | 263 bytes | **263** ([`MAX_HOST_BYTES`]) |
//! | byte grammar | full authority grammar | ASCII-graphic only | **full authority grammar** |
//! | a malformed `Host` beside a valid authority | `Conflict` | `Invalid` | **`Invalid`** |
//!
//! The comparison is the one row that did **not** go to the stricter draft, and the reasoning is
//! worth keeping. Byte-exactness would refuse an h2 request whose `:authority` is `B.Example.COM`
//! and whose `host` is `b.example.com`. Those are one host under DNS rules, so the difference
//! cannot point at a different bucket or a different origin, and non-ASCII never reaches the
//! comparison — [`parse_authority`] refuses it — so there is no IDN or punycode folding hiding
//! behind the case fold. All the strictness would buy is a `400` for anyone running a
//! case-normalising proxy.
//!
//! The property byte-exactness was really protecting is a different one: *which* spelling gets
//! signed. That is handled directly instead — when both sources are present the `Host` header's
//! bytes are the ones kept, because that is what the client's signature was computed over — so
//! the conflict check can tolerate case without the canonical request ever seeing a normalised
//! host.

use core::fmt;

use http::{HeaderMap, HeaderValue, Request, Uri, header::HOST};

use crate::text::{AsciiBuf, is_all_ascii_graphic};

/// The longest host this layer accepts, including any port.
///
/// 255 is the DNS name ceiling; the extra 8 bytes leave room for `:65535` and a trailing root dot.
/// The limit exists so that a host cannot be used to inflate the canonical request without bound,
/// and a bracketed IPv6 literal with a port is 53 bytes at its longest, so it is nowhere near.
///
/// This is the stricter of the two ceilings the merged drafts carried (the other allowed 273, on a
/// 253-character reading of the DNS ceiling). Nothing legitimate lives between the two numbers.
pub const MAX_HOST_BYTES: usize = 263;

/// Where the effective host was read from.
///
/// Recorded rather than discarded for two reasons. The sources are signed differently — SigV4
/// covers the `Host` header, and a request whose host came from the request target has no `Host`
/// header to canonicalise — and they have different threat profiles: a `:authority` is framed by
/// the h2 layer and cannot be smuggled through a `Host`-blind proxy, while a `Host` header can be
/// rewritten by every hop in front of the gateway. An audit record that says only "the host was
/// `x`" cannot answer "who said so".
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HostSource {
    /// The HTTP `Host` header. HTTP/1.1 origin-form, or an h2 request that carried `host` and no
    /// `:authority` — which RFC 9113 §8.3.1 permits.
    HostHeader,
    /// The request-target authority: an HTTP/1.1 absolute-form target, or an h2 `:authority`.
    Authority,
}

impl HostSource {
    /// A short, stable label for logs and tests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostHeader => "host-header",
            Self::Authority => "authority",
        }
    }
}

impl fmt::Display for HostSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a host could not be determined.
///
/// Each variant corresponds to one row of the ambiguity matrix, and each is a **malformed
/// request**, answered with [`HostError::HTTP_STATUS`] — never with `403`. They are kept apart
/// rather than collapsed into one "bad host" because they say different things about the peer:
/// `Missing` is usually an old client, `Conflict` and `Duplicate` are almost never anything but an
/// attempt to make two components disagree. The distinction from `403` is operational as much as
/// protocol-level: a `400` in the log says a client or a proxy produced a request the gateway
/// refuses to interpret, while a `403` says a signature did not verify. Collapsing them hides host
/// smuggling inside the noise of ordinary credential failures.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HostError {
    /// Neither a request-target authority nor a `Host` header was present. hyper answers `200`.
    Missing,
    /// More than one `Host` header field was present, whether or not the values agreed.
    ///
    /// hyper answers `200`. Rejected even when the two values are byte-identical: an intermediary
    /// that keeps one and a backend that keeps the other still see one request each way, and the
    /// identical case is the one an attacker uses to find out which end wins.
    Duplicate,
    /// A request-target authority and a `Host` header were both present and are not byte-identical.
    ///
    /// hyper answers `200`. RFC 9112 §5.5 lets a server ignore `Host` when the target is
    /// absolute-form; this crate refuses rather than ignores, because "silently pick one" is how
    /// the signer and the router end up picking differently.
    Conflict,
    /// A host was present but is not a well-formed authority.
    ///
    /// Empty, over [`MAX_HOST_BYTES`], non-ASCII, carrying whitespace or a control character,
    /// carrying userinfo or a path, holding an empty DNS label, or bearing an unusable port.
    /// The literal `Host:` with nothing after it lands here, and hyper answers that `200` too.
    Invalid,
}

impl HostError {
    /// The HTTP status every one of these rejections maps to.
    ///
    /// Stated here, and only here, because 400-versus-403 is a security property of this module
    /// rather than a routing detail: it is what keeps a smuggled host visible in a log next to
    /// ordinary signature failures. The rest of the error-to-status table lives in
    /// `rustfs-gateway-core`; [`WireReject::to_status`](crate::WireReject::to_status) is where this
    /// crate applies it.
    pub const HTTP_STATUS: u16 = 400;

    /// A short, stable label for logs, metrics and tests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Duplicate => "duplicate",
            Self::Conflict => "conflict",
            Self::Invalid => "invalid",
        }
    }

    /// A short, constant reason. Carries no byte of the offending request.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Missing => "the request named no host",
            Self::Duplicate => "the request carried more than one Host header",
            Self::Conflict => "the request target authority and the Host header disagree",
            Self::Invalid => "the host is empty or contains a byte that may not appear in one",
        }
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl core::error::Error for HostError {}

/// The host exactly as it arrived, plus where it came from.
///
/// This is the signer's only input, and the canonical request builder in `rustfs-gateway-sig`
/// accepts this type and nothing else — not a `&str`, and not a resolver's derived value. It is
/// deliberately awkward to obtain from an [`EffectiveHost`]: one method, with a name that says what
/// it is for. Feed a normalised value into the signature and one signature becomes valid for
/// `example.com`, `EXAMPLE.COM`, `example.com.` and `example.com:443` alike, which is a many-to-one
/// signature and a redirection primitive.
///
/// Nothing here is trimmed and nothing is lowercased. The bytes are validated — see
/// [`HostError::Invalid`] — and then stored as they arrived.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RawHost {
    bytes: AsciiBuf,
    source: HostSource,
}

impl RawHost {
    /// Wraps bytes taken verbatim from a `Host` header.
    ///
    /// [`effective_host`] is the sanctioned production path — it is the one that also reconciles
    /// the header against the request target. This constructor exists for the layers that have
    /// already been handed one host and need it in the type the signer accepts, and for tests.
    ///
    /// # Errors
    ///
    /// [`HostError::Invalid`] if the value is not a well-formed authority.
    pub fn from_host_header(bytes: &[u8]) -> Result<Self, HostError> {
        Self::checked(bytes, HostSource::HostHeader)
    }

    /// Wraps a request-target authority — an h2 `:authority`, or an HTTP/1.1 absolute-form target.
    ///
    /// # Errors
    ///
    /// As [`RawHost::from_host_header`].
    pub fn from_authority(authority: &str) -> Result<Self, HostError> {
        Self::checked(authority.as_bytes(), HostSource::Authority)
    }

    /// Validates an authority and stores it verbatim.
    fn checked(bytes: &[u8], source: HostSource) -> Result<Self, HostError> {
        parse_authority(bytes)?;
        Self::store(bytes, source)
    }

    /// Copies already-validated bytes into the inline buffer.
    fn store(bytes: &[u8], source: HostSource) -> Result<Self, HostError> {
        let mut buffer = AsciiBuf::new();
        for byte in bytes {
            if !buffer.push_ascii(*byte) {
                return Err(HostError::Invalid);
            }
        }
        Ok(Self { bytes: buffer, source })
    }

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
    pub const fn source(&self) -> HostSource {
        self.source
    }

    /// Whether the bytes stayed off the heap.
    #[must_use]
    pub fn is_inline(&self) -> bool {
        self.bytes.is_inline()
    }
}

impl fmt::Display for RawHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
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
        self.normalized.is_inline() && self.raw.is_inline()
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

/// Determines the effective host of a request. The single source of truth.
///
/// Called once, as early as possible, and the result stored. See [`effective_host_of`] for the
/// decision table.
///
/// # Errors
///
/// [`HostError`], one variant per ambiguity; every one of them is [`HostError::HTTP_STATUS`].
pub fn effective_host<B>(request: &Request<B>) -> Result<EffectiveHost, HostError> {
    effective_host_of(request.uri(), request.headers())
}

/// Determines the effective host from a request target and a header map.
///
/// The decision table, one row per shape measured against a real hyper server:
///
/// | request-target authority | `Host` header | result |
/// |---|---|---|
/// | present | absent | accepted, source [`HostSource::Authority`] |
/// | present | present, byte-identical | accepted, source [`HostSource::Authority`] |
/// | present | present, different in any byte | [`HostError::Conflict`] |
/// | absent | present, well-formed | accepted, source [`HostSource::HostHeader`] |
/// | any | present twice or more | [`HostError::Duplicate`] |
/// | absent | absent | [`HostError::Missing`] |
/// | any | empty, or not a well-formed authority | [`HostError::Invalid`] |
///
/// Two of those rows are not defensive programming. An HTTP/2 request may legally carry `host`
/// and no `:authority` (RFC 9113 §8.3.1), in which case the request target has neither an
/// authority nor a scheme; and an HTTP/1.1 absolute-form request target supplies an authority
/// while the `Host` header says something else entirely. Assuming either component is always
/// present produces a gateway that authenticates one host and serves another.
///
/// Comparison for the conflict check is byte-exact, so `example.com` and `EXAMPLE.COM` are a
/// conflict, and so are `example.com` and `example.com:443`. That is the same rule as everywhere
/// else in this module: two spellings are two hosts until something outside the signature path
/// decides otherwise.
///
/// # Errors
///
/// [`HostError`], as tabulated above.
pub fn effective_host_of(uri: &Uri, headers: &HeaderMap) -> Result<EffectiveHost, HostError> {
    let authority = uri.authority().map(http::uri::Authority::as_str);

    let mut host_values = headers.get_all(HOST).iter();
    let first_host: Option<&HeaderValue> = host_values.next();
    let has_second_host = host_values.next().is_some();

    // Refused before either value is looked at: which of the two is "the" host is exactly the
    // question that must not have an answer here.
    if has_second_host {
        return Err(HostError::Duplicate);
    }

    match (authority, first_host) {
        (Some(authority_text), Some(host_value)) => {
            // The header is validated too, and *first*, so that a malformed `Host` alongside a
            // well-formed authority is reported as `Invalid` rather than being folded into
            // `Conflict`. Both are a 400; the P2-03 draft's ordering is kept because it names the
            // actual fault, and because it means no value reaches the comparison unvalidated.
            let from_header = RawHost::from_host_header(host_value.as_bytes())?;
            let host = build(authority_text.as_bytes(), HostSource::Authority)?;
            // ASCII-case-insensitive, because host names are. `B.Example.COM` and
            // `b.example.com` are one host under DNS rules, so a case difference cannot point at
            // a different bucket or a different origin; refusing it only breaks deployments
            // behind a case-normalising proxy, for no security gain. Non-ASCII never reaches
            // here — `parse_authority` refuses it — so there is no IDN or punycode folding to
            // reason about.
            //
            // The comparison must not decide *which* spelling gets signed. The client computed
            // its signature over the `Host` header it sent, so that is the one kept byte for
            // byte; only the agreement check tolerates case.
            if !host.raw.as_bytes().eq_ignore_ascii_case(from_header.as_bytes()) {
                return Err(HostError::Conflict);
            }
            Ok(EffectiveHost {
                raw: from_header,
                ..host
            })
        }
        (Some(authority_text), None) => build(authority_text.as_bytes(), HostSource::Authority),
        (None, Some(host_value)) => build(host_value.as_bytes(), HostSource::HostHeader),
        (None, None) => Err(HostError::Missing),
    }
}

/// One authority, split into the parts both the raw and the normalised form are built from.
struct ParsedAuthority<'a> {
    host_part: &'a [u8],
    port_digits: Option<&'a [u8]>,
    port: Option<u16>,
}

/// Validates one authority and splits it. The only grammar check in this module.
fn parse_authority(bytes: &[u8]) -> Result<ParsedAuthority<'_>, HostError> {
    if bytes.is_empty() || bytes.len() > MAX_HOST_BYTES {
        return Err(HostError::Invalid);
    }
    // Non-ASCII is refused rather than percent-decoded or punycoded. An internationalised host
    // has exactly one wire spelling — its A-label — and accepting a second spelling here would
    // mean two byte strings routing to one bucket while only one of them was signed. The same
    // predicate rejects whitespace and every control character, which are header-injection and
    // log-injection material.
    if !is_all_ascii_graphic(bytes) {
        return Err(HostError::Invalid);
    }
    // Userinfo, a path, a query or a fragment inside what is supposed to be an authority means
    // some other component parsed this string differently than we are about to.
    if bytes.iter().any(|byte| matches!(byte, b'@' | b'/' | b'\\' | b'?' | b'#')) {
        return Err(HostError::Invalid);
    }

    let (host_part, port_digits) = split_port(bytes)?;
    validate_host_part(host_part)?;
    let port = match port_digits {
        Some(digits) => Some(parse_port(digits)?),
        None => None,
    };
    Ok(ParsedAuthority {
        host_part,
        port_digits,
        port,
    })
}

/// Validates one authority and normalises it, keeping the raw bytes alongside.
fn build(bytes: &[u8], source: HostSource) -> Result<EffectiveHost, HostError> {
    let parsed = parse_authority(bytes)?;
    let raw = RawHost::store(bytes, source)?;

    let mut normalized = AsciiBuf::new();
    // The root dot is stripped: `example.com.` and `example.com` name the same host, and leaving
    // both spellings in play would give one bucket two routing keys. The raw copy above still has
    // it, which is what the signature is computed over.
    let trimmed = strip_root_dot(parsed.host_part);
    for byte in trimmed {
        if !normalized.push_ascii(byte.to_ascii_lowercase()) {
            return Err(HostError::Invalid);
        }
    }
    let port_at = match parsed.port_digits {
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
        port: parsed.port,
        raw,
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
