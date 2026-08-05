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

//! The effective host, resolved once, from raw bytes, by exactly one function.
//!
//! Responsible for: [`effective_host`] — the single source of truth for "which host did this
//! request address" — the [`RawHost`] container that carries the bytes verbatim, [`HostSource`]
//! for the audit record, and [`HostError`] for the six ambiguities hyper forwards untouched.
//! NOT responsible for: normalisation of any kind (lowercasing, default-port stripping, trailing
//! dot, punycode), virtual-host bucket extraction, label-boundary matching, or the
//! `X-Forwarded-Host` trust model — all of that is the router's `HostResolver` (P4-01, P6-03) and
//! it consumes a [`RawHost`], never the other way round.
//! Upstream: `http`. Downstream: P2-03's canonical request builder, which accepts nothing but a
//! [`RawHost`], and the route table, which must read the same stored value rather than re-derive.
//!
//! # Why this function exists at all
//!
//! hyper does not compute an effective request URI, and it validates the `Host` header hardly at
//! all. Measured against a hyper 1.11.0 server driven by hand-written HTTP/1.1 byte streams and h2
//! frames, every one of these reached the handler with a `200`: a request with no `Host` at all, a
//! request with an empty `Host`, a request with two contradicting `Host` headers, an HTTP/1.1
//! absolute-form request whose authority disagreed with its `Host`, and an h2 request whose
//! `:authority` disagreed with its `host`. hyper's own "getting effective URI" issue (1612) is
//! still open, and the maintainers' position is that RFC 9112 §5.5 reconstruction belongs to the
//! application. So it belongs here, and it has to be the *only* place it happens: if the canonical
//! request is built from one source and the bucket route from another, an attacker signs for
//! `good` and is routed as `evil`.
//!
//! # Why the bytes are kept raw
//!
//! The canonical request's `host` line must reproduce the byte string the client signed.
//! A resolver naturally normalises — lowercase, strip `:443`, drop the trailing dot, punycode —
//! and each of those steps maps several distinct host strings onto one. Feed the normalised value
//! into the signature and one signature becomes valid for `example.com`, `EXAMPLE.COM`,
//! `example.com.` and `example.com:443` alike, which is a many-to-one signature and a redirection
//! primitive. Keeping [`RawHost`] byte-exact, and giving the canonical builder no other way to
//! learn the host, makes that mistake unspellable rather than merely discouraged.

use core::fmt;

use http::Request;
use http::header::HOST;

/// Where the effective host was read from.
///
/// Recorded rather than discarded because the two sources have different threat profiles: a
/// `:authority` is framed by the h2 layer and cannot be smuggled through a `Host`-blind proxy,
/// while a `Host` header can be rewritten by every hop in front of the gateway. An audit record
/// that says only "the host was `x`" cannot answer "who said so".
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HostSource {
    /// The HTTP `Host` header. HTTP/1.1 origin-form, or an h2 request that carried `host` and no
    /// `:authority` — which RFC 9113 §8.3.1 permits.
    HostHeader,
    /// The request-target authority: an HTTP/1.1 absolute-form target, or an h2 `:authority`.
    Authority,
}

impl fmt::Display for HostSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::HostHeader => "host-header",
            Self::Authority => "authority",
        })
    }
}

/// Why the effective host could not be determined.
///
/// Every variant is a **malformed request**, answered with [`HostError::HTTP_STATUS`] — never with
/// `403`. The distinction is operational as much as protocol-level: a `400` in the log says a
/// client or a proxy produced a request the gateway refuses to interpret, while a `403` says a
/// signature did not verify. Collapsing them hides host smuggling inside the noise of ordinary
/// credential failures.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HostError {
    /// Neither a request-target authority nor a `Host` header was present. hyper answers `200`.
    Missing,
    /// More than one `Host` header arrived. hyper answers `200`.
    ///
    /// Rejected whether or not the values agree. Two `Host` headers mean two hops disagreed about
    /// how to address this request, or one hop is trying to make the front and the back of the
    /// chain read different values — an ambiguity, and ambiguity on the signature's own input is
    /// not something to resolve by picking a winner.
    Duplicate,
    /// The request-target authority and the `Host` header disagree. hyper answers `200`.
    ///
    /// RFC 9112 §5.5 lets a server ignore `Host` when the target is absolute-form, and RFC 9113
    /// §8.3.1 requires `:authority` and `host` to agree when both are sent. This crate refuses
    /// rather than ignores: a disagreement is a request-smuggling signal, and "silently pick one"
    /// is how the signer and the router end up picking differently.
    Conflict,
    /// The host is empty, or contains a byte that may not appear in one.
    ///
    /// Empty covers the literal `Host:` with nothing after it, which hyper also answers `200`.
    /// The byte rule rejects whitespace and control characters, both of which are header-injection
    /// and log-injection material, and non-ASCII, which has more than one spelling once a resolver
    /// applies punycode.
    Invalid,
}

impl HostError {
    /// The HTTP status every one of these rejections maps to.
    ///
    /// Stated here, and only here, because 400-versus-403 is a security property of this module
    /// rather than a routing detail: it is what keeps a smuggled host visible in a log next to
    /// ordinary signature failures. The rest of the error-to-status table lives in `s3gate-core`.
    pub const HTTP_STATUS: u16 = 400;

    /// A short, constant reason. Carries no byte of the offending request.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
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

/// The effective host, byte-exact, plus where it came from.
///
/// This is the only type the canonical request builder accepts for its host line. A resolver's
/// derived value — bucket name, region subdomain, normalised authority — is a different type
/// living in a different crate, so the many-to-one mistake described in the module docs cannot be
/// made by passing the wrong variable.
///
/// A plain string is not accepted either, which is what makes the constraint hold against the
/// obvious workaround:
///
/// ```compile_fail,E0308
/// use s3gate_sig::{CanonicalRequestSpec, PayloadMode, RawQuery, SignedHeaderSet, UriPathCandidates};
/// # use http::{HeaderMap, Method};
/// # let headers = HeaderMap::new();
/// # let signed = SignedHeaderSet::parse_and_enforce("host", &headers, None).expect("valid");
/// # let path = UriPathCandidates::new("/").expect("valid");
/// # let query = RawQuery::new("");
/// let _ = CanonicalRequestSpec::new(
///     &Method::GET,
///     &path,
///     &query,
///     &headers,
///     &signed,
///     "example.com", // a normalised host string: does not compile, only `&RawHost` is accepted
///     PayloadMode::Empty.canonical_payload_token(),
/// );
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RawHost {
    bytes: Box<[u8]>,
    source: HostSource,
}

impl RawHost {
    /// The longest host accepted, in bytes.
    ///
    /// 255 is the DNS name ceiling; the extra 8 leave room for `:65535` and a trailing dot. The
    /// limit exists so that a host cannot be used to inflate the canonical request without bound.
    pub const MAX_LEN: usize = 263;

    /// Wraps bytes taken verbatim from a `Host` header.
    ///
    /// # Errors
    ///
    /// [`HostError::Invalid`] if the value is empty, longer than [`RawHost::MAX_LEN`], or contains
    /// a byte outside the ASCII graphic range. Nothing is trimmed and nothing is lowercased: this
    /// is the value that goes into the canonical request, and every transformation applied here
    /// would be a second spelling of one host.
    pub fn from_host_header(bytes: &[u8]) -> Result<Self, HostError> {
        Self::new(bytes, HostSource::HostHeader)
    }

    /// Wraps a request-target authority — an h2 `:authority`, or an HTTP/1.1 absolute-form target.
    ///
    /// # Errors
    ///
    /// As [`RawHost::from_host_header`].
    pub fn from_authority(authority: &str) -> Result<Self, HostError> {
        Self::new(authority.as_bytes(), HostSource::Authority)
    }

    fn new(bytes: &[u8], source: HostSource) -> Result<Self, HostError> {
        if bytes.is_empty() || bytes.len() > Self::MAX_LEN {
            return Err(HostError::Invalid);
        }
        if !bytes.iter().all(u8::is_ascii_graphic) {
            return Err(HostError::Invalid);
        }
        Ok(Self {
            bytes: Box::from(bytes),
            source,
        })
    }

    /// The host bytes, exactly as they arrived.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The host as a string.
    ///
    /// Infallible because construction rejected every non-ASCII byte, so the bytes are valid
    /// UTF-8 by the time one of these exists.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Every byte was checked to be ASCII graphic at construction, so this cannot fail.
        core::str::from_utf8(&self.bytes).unwrap_or("")
    }

    /// Where the value was read from.
    #[must_use]
    pub const fn source(&self) -> HostSource {
        self.source
    }
}

impl fmt::Display for RawHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Resolves the effective host of a request. The single source of truth.
///
/// Call it once, as early as possible, and put the result in the request extensions. The canonical
/// request builder and the bucket/virtual-host router must both read *that stored value*. Neither
/// may re-derive it: two derivations are two opportunities to disagree, and the whole class of
/// attack this function exists to close is "the signature covered one host, the routing used
/// another".
///
/// The resolution table, one row per measured hyper behaviour:
///
/// | authority | `Host` headers | result |
/// |---|---|---|
/// | absent | one, valid | that header, [`HostSource::HostHeader`] |
/// | present | absent | the authority, [`HostSource::Authority`] |
/// | present | one, byte-identical | the authority, [`HostSource::Authority`] |
/// | present | one, different | [`HostError::Conflict`] |
/// | any | two or more | [`HostError::Duplicate`] |
/// | absent | absent | [`HostError::Missing`] |
/// | any | empty, or containing a forbidden byte | [`HostError::Invalid`] |
///
/// Comparison for the conflict check is byte-exact, so `example.com` and `example.com:443` are a
/// conflict rather than a match. That is intentional and is the same rule as everywhere else in
/// this module: two spellings are two hosts until something outside the signature path decides
/// otherwise.
///
/// # Errors
///
/// Any [`HostError`]. All of them are [`HostError::HTTP_STATUS`], never `403`.
pub fn effective_host<B>(req: &Request<B>) -> Result<RawHost, HostError> {
    let mut host_headers = req.headers().get_all(HOST).iter();
    let first_host = host_headers.next();
    if host_headers.next().is_some() {
        // Rejected before either value is looked at: which of the two is "the" host is exactly the
        // question that must not have an answer here.
        return Err(HostError::Duplicate);
    }

    let authority = req.uri().authority().map(http::uri::Authority::as_str);

    match (authority, first_host) {
        (None, None) => Err(HostError::Missing),
        (None, Some(header)) => RawHost::from_host_header(header.as_bytes()),
        (Some(authority), None) => RawHost::from_authority(authority),
        (Some(authority), Some(header)) => {
            // Validate the header too, so that a malformed `Host` alongside a well-formed
            // authority is still a rejection rather than a silently ignored value.
            let from_header = RawHost::from_host_header(header.as_bytes())?;
            let from_authority = RawHost::from_authority(authority)?;
            if from_header.as_bytes() == from_authority.as_bytes() {
                Ok(from_authority)
            } else {
                Err(HostError::Conflict)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Uri;

    fn request(uri: &str, hosts: &[&str]) -> Request<()> {
        let mut builder = Request::builder().method("GET").uri(uri.parse::<Uri>().expect("test uri"));
        for host in hosts {
            builder = builder.header(HOST, *host);
        }
        builder.body(()).expect("test request")
    }

    #[test]
    fn origin_form_with_one_host_header_uses_that_header() {
        let host = effective_host(&request("/foo", &["127.0.0.1:38080"])).expect("resolved");
        assert_eq!(host.as_str(), "127.0.0.1:38080");
        assert_eq!(host.source(), HostSource::HostHeader);
    }

    #[test]
    fn an_absolute_form_target_without_a_host_header_uses_the_authority() {
        let host = effective_host(&request("http://bucket.example.com/foo", &[])).expect("resolved");
        assert_eq!(host.as_str(), "bucket.example.com");
        assert_eq!(host.source(), HostSource::Authority);
    }

    #[test]
    fn a_matching_authority_and_host_header_agree_on_one_value() {
        let host = effective_host(&request("http://a.example.com/foo", &["a.example.com"])).expect("resolved");
        assert_eq!(host.as_str(), "a.example.com");
        assert_eq!(host.source(), HostSource::Authority);
    }

    #[test]
    fn the_six_ambiguities_hyper_forwards_are_all_rejected() {
        assert_eq!(effective_host(&request("/foo", &[])).unwrap_err(), HostError::Missing);
        assert_eq!(effective_host(&request("/foo", &["a", "b"])).unwrap_err(), HostError::Duplicate);
        assert_eq!(effective_host(&request("/foo", &["a", "a"])).unwrap_err(), HostError::Duplicate);
        assert_eq!(effective_host(&request("/foo", &[""])).unwrap_err(), HostError::Invalid);
        assert_eq!(
            effective_host(&request("http://a.example.com/foo", &["b.example.com"])).unwrap_err(),
            HostError::Conflict
        );
        assert_eq!(
            effective_host(&request("http://a.example.com/foo", &["a.example.com:443"])).unwrap_err(),
            HostError::Conflict
        );
    }

    #[test]
    fn nothing_about_the_bytes_is_normalised() {
        for spelling in ["EXAMPLE.COM", "example.com.", "example.com:443", "example.com"] {
            let host = RawHost::from_host_header(spelling.as_bytes()).expect("valid");
            assert_eq!(host.as_str(), spelling);
        }
    }

    #[test]
    fn hosts_with_forbidden_bytes_are_rejected() {
        for bad in ["exa mple.com", "example.com\r\nX-Injected: 1", "exa\u{0}mple", "exämple.com"] {
            assert_eq!(RawHost::from_host_header(bad.as_bytes()), Err(HostError::Invalid), "must reject {bad:?}");
        }
        assert_eq!(RawHost::from_host_header(&[b'a'; RawHost::MAX_LEN + 1]), Err(HostError::Invalid));
    }
}
