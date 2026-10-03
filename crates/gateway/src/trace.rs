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

//! The one identifier a request is given, and the only place it is rendered.
//!
//! Responsible for: [`RequestId`] and [`HostId`] — opaque, closed-alphabet values — the
//! [`RequestTrace`] that pairs them with which of them an answer carries, the [`TraceSource`] that
//! mints one per request, the default [`MintedTraces`], and the substitutable [`FixedTrace`] a
//! conformance case needs.
//! NOT responsible for: deciding when a request is identified (`crate::service` identifies it once,
//! at the top), what an error document says (`crate::render`), a host's own identifier (`host`:
//! [`HostRequestId`]), or which identifiers an assembly's answers carry (`answer`). Neither the
//! service nor the renderer formats an identifier itself: both read one out of a [`RequestTrace`].
//! Upstream: `http`, `std`, `rustfs-gateway-xml` (the document elements), and
//! `rustfs-gateway-core`'s router (the claims `answer` reads). Downstream: `crate::builder`,
//! `crate::service`, `crate::render`, `crate::commit`, `crate::stamp`, `crate::ext::observer`.
//!
//! # The invariant, in one sentence
//!
//! **A request is identified once, and every identifier header, the `<RequestId>` element of an
//! error document and every event the service emits carry that one value.**
//!
//! It is fixed by a type rather than by discipline. `crate::service` builds exactly one
//! [`RequestTrace`] per call and passes it by reference to the places that write it out; none of
//! them can obtain a second one, because none holds a [`TraceSource`]. Two call sites formatting
//! from one value cannot drift; two call sites formatting from two sources can, and would do so
//! silently — the header and the body of the same response would name different requests, which is
//! worse than having no identifier at all, because an operator would trust it.
//!
//! # Whose identifier it is
//!
//! By default the service's: [`TraceSource::mint`] produces it. An embedding host that already
//! identifies every request — RustFS mints its own and records it in its logs, audit entries and
//! notifications — hands its value over instead, as a [`HostRequestId`] in the request's
//! extensions, and the service answers and reports with that value. Without that path the head
//! would name the host's request and the body and the events the service's, which is the drift the
//! invariant above rules out (rustfs/backlog#1677, ruling R10).
//!
//! # Why an echo is not writable
//!
//! Three independent reasons, each of which is sufficient on its own:
//!
//! 1. **[`TraceSource::mint`] takes no request.** Its only parameter is `&self`. An implementation
//!    that wanted to echo a header value has nothing to echo *from*. A host's value arrives in the
//!    request's extensions, which no byte on the wire can write: only code in the same process
//!    inserts one, and the host is the party that decides where its identifier comes from.
//! 2. **No minting constructor accepts text.** [`RequestId::from_bits`],
//!    [`RequestId::uuid_from_bits`] and [`HostId::from_bits`] are built from integers. The one text
//!    constructor, [`HostRequestId::new`], is the host's, and it refuses anything outside the
//!    closed alphabet below rather than repairing it.
//! 3. **The alphabet is closed.** Every identifier is ASCII letters, digits and `-`, and nothing
//!    else — 16 uppercase hexadecimal digits for a minted [`RequestId`], a lowercase hyphenated UUID
//!    for [`MintedTraces::with_uuid_request_ids`], 32 hexadecimal digits for a [`HostId`], and at
//!    most [`RequestId::MAX_LEN`] bytes from a host. So no identifier can carry a quote, an angle
//!    bracket, a newline or a terminal escape into a log line, a header or an XML document. The
//!    property a log sink needs is not "the caller did not choose this" but "the caller cannot choose
//!    *what characters* this contains", and every constructor enforces it.
//!
//! # Why the identifier is unpredictable, and how far that goes
//!
//! A bare counter would be correct for correlation and wrong for everything else: an id of `0011`
//! tells a caller that the next request will be given `0012`, so a caller can quote an identifier
//! for a request it never made and have it look authentic in a support conversation, and can tell
//! from two of its own ids how much traffic the deployment took in between.
//!
//! So [`MintedTraces`] mints `keyed_hash(process_key, (domain, ordinal))` rather than the ordinal
//! itself. The key comes from `std::collections::hash_map::RandomState`, which the standard
//! library seeds from the operating system's random source once per process; the counter supplies
//! distinctness, and the keyed hash supplies opacity. An observer holding a bag of identifiers has
//! seen outputs of a keyed hash under a key it does not have, and neither the ordinal nor the next
//! identifier follows from them.
//!
//! What this deliberately is **not**: a cryptographic guarantee. The standard library does not
//! specify its hasher and may change it, so this is not a primitive to build a security control
//! on. The trade is stated plainly because the alternative was worse in both directions — a
//! `uuid` dependency for a value nobody parses, or a public integer mixer over a counter, which
//! is invertible from two observed identifiers and would therefore have been unpredictability in
//! name only.
//!
//! # Why a fixed source is a first-class type and not a test helper
//!
//! Exactly the argument [`crate::clock`] makes for `FixedClock`. A conformance case that compares
//! an error document byte for byte cannot do so while a fresh identifier appears in it, so the
//! suite needs a source it can pin. Keeping [`FixedTrace`] public is what stops every consumer
//! from inventing its own — and it is why the security note on it is written in the open.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};

use http::header::{HeaderMap, HeaderName, HeaderValue};
use rustfs_gateway_xml::XmlWriter;

mod answer;
mod host;

pub(crate) use self::answer::{Answer, Identification};
pub use self::host::{HostRequestId, InvalidRequestId};

/// The header carrying the [`RequestId`].
pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-amz-request-id");

/// The header carrying the [`HostId`].
pub const HOST_ID_HEADER: HeaderName = HeaderName::from_static("x-amz-id-2");

/// The second header legacy RustFS writes its request identifier under, beside
/// [`REQUEST_ID_HEADER`].
///
/// Written only by an assembly that identifies its answers as legacy RustFS does
/// (`ServiceBuilder::identify_requests_as_legacy_rustfs`); every other assembly leaves the name to
/// whoever else wants it.
pub const X_REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// The identifier of one request, as it appears on the wire.
///
/// Opaque: a closed alphabet of ASCII letters, digits and `-`. The service mints 16 uppercase
/// hexadecimal digits ([`RequestId::from_bits`]), the shape AWS answers with and the shape SDK
/// diagnostics and support tooling already cope with; a host that identifies its own requests
/// hands over its value instead ([`HostRequestId`]). Nothing may parse it — this type publishes no
/// accessor that returns a number, precisely so that no downstream behaviour can come to depend on
/// the bits inside.
///
/// # Security
///
/// Never read from a header, a query parameter or a body. See the module documentation for the
/// three reasons an echo of a caller-supplied value is not writable through this type.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId {
    text: [u8; RequestId::MAX_LEN],
    len: u8,
}

impl RequestId {
    /// The length, in bytes, of an identifier [`RequestId::from_bits`] mints.
    pub const LEN: usize = 16;

    /// The longest identifier any constructor produces, in bytes: a host's ceiling.
    pub const MAX_LEN: usize = 64;

    /// Mints an identifier from 64 bits, as 16 uppercase hexadecimal digits.
    ///
    /// Takes an integer rather than text, which is reason 2 of the module documentation. A caller
    /// holding a header value cannot reach this constructor without deciding, in writing, to turn
    /// that value into a number first.
    #[must_use]
    pub fn from_bits(bits: u64) -> Self {
        Self::from_ascii(&hex_16(bits))
    }

    /// Mints an identifier from 128 bits, as a random (version 4) UUID in its hyphenated lowercase
    /// spelling: `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`, where `y` is `8`, `9`, `a` or `b`.
    ///
    /// Six of the bits are overwritten with the version and the RFC 9562 variant, so every input
    /// yields a well-formed UUID; the other 122 are the input's. This is the shape legacy RustFS
    /// answers every S3 request with (`uuid::Uuid::new_v4().to_string()`, rustfs/rustfs
    /// `e870a6d25b`, `rustfs/src/storage/request_context.rs:121-123`).
    #[must_use]
    pub fn uuid_from_bits(bits: u128) -> Self {
        Self::from_ascii(&uuid_36(bits))
    }

    /// An identifier over bytes this module has already checked or produced.
    ///
    /// Every caller hands over ASCII letters, digits and `-`, at most [`RequestId::MAX_LEN`] of
    /// them: the minting constructors by construction, [`HostRequestId::new`] by refusing anything
    /// else. Anything past the ceiling is dropped rather than indexed, so even a defect in a caller
    /// cannot overrun the buffer.
    fn from_ascii(bytes: &[u8]) -> Self {
        let mut text = [0_u8; Self::MAX_LEN];
        let mut len = 0_u8;
        for (slot, byte) in text.iter_mut().zip(bytes) {
            *slot = *byte;
            len = len.saturating_add(1);
        }
        Self { text, len }
    }

    /// The rendered identifier.
    ///
    /// The one renderer. The headers, the error document and every event read this, which is what
    /// makes "they agree" a property of the type rather than of several `format!` calls.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.text
            .get(..usize::from(self.len))
            .map_or(ZEROS_16, |bytes| as_ascii(bytes, ZEROS_16))
    }
}

/// The identifier of the host that answered, as it appears on the wire.
///
/// AWS sends this as `x-amz-id-2` on every response, alongside the [`RequestId`], and support
/// escalations ask for both. It is opaque there and it is opaque here; this implementation renders
/// 32 hexadecimal digits rather than AWS's longer base64-shaped token, because the closed alphabet
/// of the module documentation is worth more than a resemblance no client may depend on.
///
/// # Security
///
/// The same three properties as [`RequestId`]. In particular this carries nothing about the host:
/// no hostname, no address, no pool name. A value that identified the answering machine to an
/// unauthenticated caller would be an infrastructure map handed out with every `403`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HostId([u8; HostId::LEN]);

impl HostId {
    /// The rendered length, in bytes.
    pub const LEN: usize = 32;

    /// Mints an identifier from 128 bits. Integers only, for [`RequestId::from_bits`]'s reason.
    #[must_use]
    pub fn from_bits(bits: u128) -> Self {
        Self(hex_32(bits))
    }

    /// The rendered identifier. The one renderer.
    #[must_use]
    pub fn as_str(&self) -> &str {
        as_ascii(self.0.as_slice(), ZEROS_32)
    }
}

/// The identifiers of one request, and which of them its answer carries.
///
/// Passed by reference down the pipeline. A stage that writes an identifier out takes one of these
/// and never a [`TraceSource`], so no stage below the entry point is able to mint a second. Which
/// identifiers an answer carries is decided once, with the identifiers themselves, so a refusal,
/// a success and a committed document of one assembly cannot disagree about it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestTrace {
    request_id: RequestId,
    host_id: HostId,
    answer: Answer,
}

impl RequestTrace {
    /// A trace from its two identifiers, answered as AWS answers: both in the head, both in an
    /// error document.
    #[must_use]
    pub const fn new(request_id: RequestId, host_id: HostId) -> Self {
        Self {
            request_id,
            host_id,
            answer: Answer::Aws,
        }
    }

    /// A trace from the bits of both. Integers only, for [`RequestId::from_bits`]'s reason.
    #[must_use]
    pub fn from_bits(request_bits: u64, host_bits: u128) -> Self {
        Self::new(RequestId::from_bits(request_bits), HostId::from_bits(host_bits))
    }

    /// The request identifier.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// The host identifier.
    #[must_use]
    pub const fn host_id(&self) -> &HostId {
        &self.host_id
    }

    /// This trace, identified by `host` when the embedding host handed one over, and answered as
    /// `answer` says.
    pub(crate) const fn identified(self, host: Option<&HostRequestId>, answer: Answer) -> Self {
        Self {
            request_id: match host {
                Some(host) => *host.request_id(),
                None => self.request_id,
            },
            host_id: self.host_id,
            answer,
        }
    }

    /// Writes the identifiers this answer carries into a response head, replacing anything already
    /// there, and removes the ones it does not carry.
    ///
    /// The one header writer, and it **replaces** rather than appends: an encoder or a filter that
    /// wrote its own `x-amz-request-id` loses, so the value a caller receives is always the value
    /// the service reports in its own events. A response carrying two of these headers is a
    /// response an intermediary is free to pick either half of. A name this answer does not carry
    /// is removed rather than left to whoever wrote it, for the same reason: the framework owns the
    /// name, and "no identifier" is as much its answer as a value is.
    pub fn apply(&self, headers: &mut HeaderMap) {
        // Every identifier is ASCII letters, digits and `-` by construction, so no conversion below
        // can fail; a header value only rejects control bytes and non-ASCII.
        let request_id = HeaderValue::from_str(self.request_id.as_str()).ok();
        match self.answer {
            Answer::Aws => {
                if let Some(value) = request_id {
                    headers.insert(REQUEST_ID_HEADER, value);
                }
                if let Ok(value) = HeaderValue::from_str(self.host_id.as_str()) {
                    headers.insert(HOST_ID_HEADER, value);
                }
            }
            Answer::LegacyRustfs => {
                if let Some(value) = request_id {
                    headers.insert(X_REQUEST_ID_HEADER, value.clone());
                    headers.insert(REQUEST_ID_HEADER, value);
                }
                headers.remove(HOST_ID_HEADER);
            }
            Answer::HostWritten => {
                headers.remove(REQUEST_ID_HEADER);
                headers.remove(HOST_ID_HEADER);
            }
        }
    }

    /// Writes the identifier elements this answer's error document carries, last in the document.
    pub(crate) fn write_document_elements(&self, xml: &mut XmlWriter) {
        match self.answer {
            Answer::Aws => {
                xml.element("RequestId", self.request_id.as_str());
                xml.element("HostId", self.host_id.as_str());
            }
            Answer::LegacyRustfs => xml.element("RequestId", self.request_id.as_str()),
            Answer::HostWritten => {}
        }
    }
}

impl core::fmt::Display for RequestId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::fmt::Debug for RequestId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "RequestId({})", self.as_str())
    }
}

impl core::fmt::Display for HostId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::fmt::Debug for HostId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "HostId({})", self.as_str())
    }
}

impl core::fmt::Debug for RequestTrace {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RequestTrace")
            .field("request_id", &self.request_id.as_str())
            .field("host_id", &self.host_id.as_str())
            .field("answer", &self.answer)
            .finish()
    }
}

/// Where a request's identifiers come from.
///
/// Held as `Arc<dyn TraceSource>` by the assembled service, and called exactly once per request.
/// Synchronous, because minting an identifier is not I/O and an implementation that awaited would
/// be awaiting before the request has been accepted, let alone authenticated.
///
/// # Security
///
/// [`TraceSource::mint`] takes **no request**, and that is the point rather than an oversight. A
/// source cannot see a header, a query parameter or a body, so no implementation of this trait —
/// including one written outside this workspace — can return an identifier the caller chose. This
/// is reason 1 of the module documentation, and it is the only one of the three that also binds a
/// third-party implementation. A host that identifies its own requests does not implement this
/// trait: it hands its value over per request as a [`HostRequestId`].
pub trait TraceSource: Send + Sync + 'static {
    /// Mints the identifiers for one request.
    fn mint(&self) -> RequestTrace;
}

impl<T: TraceSource + ?Sized> TraceSource for std::sync::Arc<T> {
    fn mint(&self) -> RequestTrace {
        (**self).mint()
    }
}

/// The spelling [`MintedTraces`] renders a request identifier in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    /// 16 uppercase hexadecimal digits.
    Hex,
    /// A random (version 4) UUID, hyphenated and lowercase.
    Uuid,
}

/// The default source: a per-process counter behind a per-process keyed hash.
///
/// Distinctness comes from the counter, opacity from the key. See the module documentation for
/// what this buys and, just as importantly, what it does not.
#[derive(Debug)]
pub struct MintedTraces {
    keys: RandomState,
    ordinal: AtomicU64,
    shape: Shape,
}

impl MintedTraces {
    /// A source keyed from the operating system's random source.
    ///
    /// One of these per service. Two services in one process mint from different keys, which is
    /// correct: they are different answering endpoints and nothing should be able to tell from two
    /// identifiers that they came from the same binary.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: RandomState::new(),
            ordinal: AtomicU64::new(0),
            shape: Shape::Hex,
        }
    }

    /// A source like [`MintedTraces::new`] whose request identifiers are random (version 4) UUIDs
    /// in their hyphenated lowercase spelling ([`RequestId::uuid_from_bits`]): the shape legacy
    /// RustFS answers every S3 request with, for an assembly whose host hands over no identifier
    /// of its own.
    ///
    /// 122 of the 128 bits are keyed-hash output, with the same opacity as the default's 64.
    #[must_use]
    pub fn with_uuid_request_ids() -> Self {
        Self {
            shape: Shape::Uuid,
            ..Self::new()
        }
    }

    /// One keyed hash over `(domain, ordinal)`.
    ///
    /// The domain separator is what keeps the request identifier and the two halves of the host
    /// identifier from being the same number three times, without spending three counters on it.
    fn keyed(&self, domain: u64, ordinal: u64) -> u64 {
        let mut hasher = self.keys.build_hasher();
        hasher.write_u64(domain);
        hasher.write_u64(ordinal);
        hasher.finish()
    }
}

impl Default for MintedTraces {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceSource for MintedTraces {
    fn mint(&self) -> RequestTrace {
        // Relaxed is enough: nothing is published through this counter and nothing reads it back.
        // All that is required is that two concurrent requests receive two different ordinals,
        // which `fetch_add` gives on its own.
        let ordinal = self.ordinal.fetch_add(1, Ordering::Relaxed);
        let request = self.keyed(REQUEST_DOMAIN, ordinal);
        let request_id = match self.shape {
            Shape::Hex => RequestId::from_bits(request),
            Shape::Uuid => {
                RequestId::uuid_from_bits((u128::from(request) << 64) | u128::from(self.keyed(REQUEST_LOW_DOMAIN, ordinal)))
            }
        };
        let host = (u128::from(self.keyed(HOST_HIGH_DOMAIN, ordinal)) << 64) | u128::from(self.keyed(HOST_LOW_DOMAIN, ordinal));
        RequestTrace::new(request_id, HostId::from_bits(host))
    }
}

/// A source that answers the same trace for every request.
///
/// What a conformance case installs so that an error document can be compared byte for byte, in
/// the same way `crate::FixedClock` pins a timestamp.
///
/// # Security
///
/// A deployment that installs one has turned every request identifier into the same string, which
/// makes the audit trail unable to tell two requests apart and lets any caller quote an identifier
/// that matches every request the service ever answered. This exists for cases. It is not a
/// configuration of the default; it is the absence of one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FixedTrace {
    trace: RequestTrace,
}

impl FixedTrace {
    /// A source pinned to the given bits. Integers only, for [`RequestId::from_bits`]'s reason.
    #[must_use]
    pub fn at(request_bits: u64, host_bits: u128) -> Self {
        Self {
            trace: RequestTrace::from_bits(request_bits, host_bits),
        }
    }

    /// A source pinned to an already-minted trace.
    #[must_use]
    pub const fn of(trace: RequestTrace) -> Self {
        Self { trace }
    }

    /// The trace this source answers with.
    #[must_use]
    pub const fn trace(&self) -> &RequestTrace {
        &self.trace
    }
}

impl TraceSource for FixedTrace {
    fn mint(&self) -> RequestTrace {
        self.trace
    }
}

/// Domain separators. Arbitrary constants; only their distinctness matters.
const REQUEST_DOMAIN: u64 = 0x5245_5155_4553_5449; // "REQUESTI"
const REQUEST_LOW_DOMAIN: u64 = 0x5245_515f_5f4c_4f57; // "REQ__LOW"
const HOST_HIGH_DOMAIN: u64 = 0x484f_5354_4849_4748; // "HOSTHIGH"
const HOST_LOW_DOMAIN: u64 = 0x484f_5354_5f4c_4f57; // "HOST_LOW"

/// One hexadecimal digit, by arithmetic rather than by table lookup.
///
/// Arithmetic because this crate denies `clippy::indexing_slicing`, and a table lookup indexed by
/// a runtime nibble is exactly the pattern that lint exists to question. It is also the whole of
/// the closed alphabet: `0`–`9` and `A`–`F` (`a`–`f` when `lower`), with no input able to produce
/// anything else.
const fn hex_digit(nibble: u8, lower: bool) -> u8 {
    let ten = if lower { b'a' } else { b'A' };
    if nibble < 10 { b'0' + nibble } else { ten + (nibble - 10) }
}

/// 64 bits as 16 uppercase hexadecimal digits, most significant first.
///
/// Written with `array::from_fn` rather than an indexed loop so that no `clippy::indexing_slicing`
/// waiver is needed anywhere in this module.
fn hex_16(bits: u64) -> [u8; 16] {
    core::array::from_fn(|index| hex_digit(nibble_of(u128::from(bits), 15, index), false))
}

/// 128 bits as 32 uppercase hexadecimal digits, most significant first.
fn hex_32(bits: u128) -> [u8; 32] {
    core::array::from_fn(|index| hex_digit(nibble_of(bits, 31, index), false))
}

/// The version-4 nibble, at the thirteenth hexadecimal digit.
const UUID_VERSION_MASK: u128 = 0xF << 76;
const UUID_VERSION_4: u128 = 0x4 << 76;
/// The RFC 9562 variant, the top two bits of the seventeenth hexadecimal digit.
const UUID_VARIANT_MASK: u128 = 0x3 << 62;
const UUID_VARIANT_RFC: u128 = 0x2 << 62;

/// 128 bits as a version-4 UUID: 32 lowercase hexadecimal digits in groups of 8-4-4-4-12.
fn uuid_36(bits: u128) -> [u8; 36] {
    let bits = (bits & !UUID_VERSION_MASK & !UUID_VARIANT_MASK) | UUID_VERSION_4 | UUID_VARIANT_RFC;
    core::array::from_fn(|index| {
        // The four separators sit after the 8th, 12th, 16th and 20th digit; every other position is
        // the digit its index names once the separators before it are counted out.
        let separators_before = [8, 13, 18, 23].iter().filter(|separator| **separator < index).count();
        match index {
            8 | 13 | 18 | 23 => b'-',
            _ => hex_digit(nibble_of(bits, 31, index - separators_before), true),
        }
    })
}

/// The `index`-th nibble counting from the most significant of `last + 1` of them.
fn nibble_of(bits: u128, last: usize, index: usize) -> u8 {
    let shift = 4 * u32::try_from(last.saturating_sub(index)).unwrap_or(0);
    ((bits >> shift) & 0xF) as u8
}

/// Sixteen zeroes, and thirty-two. The unreachable fallbacks of [`as_ascii`].
const ZEROS_16: &str = "0000000000000000";
const ZEROS_32: &str = "00000000000000000000000000000000";

/// Reads bytes this module wrote back as text.
///
/// Every byte reaching here is ASCII — a digit this module emitted or a host byte
/// [`HostRequestId::new`] admitted — so the conversion cannot fail. The fallback is a placeholder
/// rather than an empty string, because an identifier that silently became empty would look, in a
/// log, like a request that was never given one.
fn as_ascii<'a>(bytes: &'a [u8], fallback: &'a str) -> &'a str {
    core::str::from_utf8(bytes).unwrap_or(fallback)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Negative — the rendered alphabet is closed. This is the assertion behind the claim that an
    /// identifier cannot carry a byte into a log line or an XML document, whatever it was minted
    /// from.
    #[test]
    fn every_rendering_is_uppercase_hexadecimal_of_a_fixed_length() {
        for bits in [0, 1, u64::MAX, 0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210] {
            let rendered = RequestId::from_bits(bits).as_str().to_owned();
            assert_eq!(rendered.len(), RequestId::LEN, "{rendered}");
            assert!(
                rendered
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)),
                "{rendered}"
            );
        }
        let host = HostId::from_bits(u128::MAX).as_str().to_owned();
        assert_eq!(host, "F".repeat(HostId::LEN));
        assert_eq!(HostId::from_bits(0).as_str(), "0".repeat(HostId::LEN));
    }

    /// Negative — the rendering is zero-padded and most-significant-first, so a small identifier is
    /// as long as a large one. A variable-width identifier is one that column-aligned log tooling
    /// silently mangles.
    #[test]
    fn a_small_identifier_is_padded_rather_than_shortened() {
        assert_eq!(RequestId::from_bits(1).as_str(), "0000000000000001");
        assert_eq!(RequestId::from_bits(0x0123_4567_89AB_CDEF).as_str(), "0123456789ABCDEF");
        assert_eq!(HostId::from_bits(0xABC).as_str(), "00000000000000000000000000000ABC");
    }

    /// Negative — whatever the bits, a UUID-shaped identifier carries version 4 and the RFC
    /// variant, keeps its hyphens where a UUID parser looks for them, and is lowercase. A bit
    /// pattern that reached the output unmasked would be a UUID of no version, which a strict
    /// parser refuses.
    #[test]
    fn a_uuid_carries_version_four_and_the_rfc_variant_whatever_its_bits() {
        assert_eq!(RequestId::uuid_from_bits(0).as_str(), "00000000-0000-4000-8000-000000000000");
        assert_eq!(RequestId::uuid_from_bits(u128::MAX).as_str(), "ffffffff-ffff-4fff-bfff-ffffffffffff");
        assert_eq!(
            RequestId::uuid_from_bits(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef).as_str(),
            "01234567-89ab-4def-8123-456789abcdef"
        );
        for bits in [1, u128::MAX >> 1, 0xF0F0_F0F0_F0F0_F0F0_F0F0_F0F0_F0F0_F0F0] {
            let rendered = RequestId::uuid_from_bits(bits).as_str().to_owned();
            assert_eq!(rendered.len(), 36, "{rendered}");
            let groups: Vec<&str> = rendered.split('-').collect();
            assert_eq!(groups.iter().map(|group| group.len()).collect::<Vec<_>>(), [8, 4, 4, 4, 12], "{rendered}");
            assert!(groups.get(2).is_some_and(|group| group.starts_with('4')), "{rendered}");
            assert!(
                matches!(groups.get(3).and_then(|group| group.bytes().next()), Some(b'8' | b'9' | b'a' | b'b')),
                "{rendered}"
            );
            assert!(
                rendered
                    .bytes()
                    .all(|byte| byte == b'-' || byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "{rendered}"
            );
        }
    }

    /// Negative — consecutive requests do not get consecutive identifiers. A counter rendered
    /// directly would pass every other test in this module and still let a caller mint the next
    /// identifier the service was going to hand out.
    #[test]
    fn consecutive_identifiers_are_not_adjacent() {
        let source = MintedTraces::new();
        let first = source.mint();
        let second = source.mint();
        let left = u64::from_str_radix(first.request_id().as_str(), 16).expect("hexadecimal");
        let right = u64::from_str_radix(second.request_id().as_str(), 16).expect("hexadecimal");
        assert_ne!(left, right);
        assert_ne!(right.wrapping_sub(left), 1, "the identifier is a counter in disguise");
    }

    /// The 128 bits of a UUID-shaped identifier, version and variant included, as two halves.
    fn uuid_halves(id: &RequestId) -> (u64, u64) {
        let digits: String = id.as_str().chars().filter(|character| *character != '-').collect();
        let high = u64::from_str_radix(digits.get(..16).expect("32 digits"), 16).expect("hexadecimal");
        let low = u64::from_str_radix(digits.get(16..).expect("32 digits"), 16).expect("hexadecimal");
        (high, low)
    }

    /// Negative — the UUID-shaped source is no counter either: neither half of consecutive
    /// identifiers steps by one, and a run of them has no repeat.
    #[test]
    fn uuid_request_ids_neither_repeat_nor_count() {
        let source = MintedTraces::with_uuid_request_ids();
        let mut previous = uuid_halves(source.mint().request_id());
        for _ in 0..64 {
            let next = uuid_halves(source.mint().request_id());
            assert_ne!(next.0.wrapping_sub(previous.0), 1, "the high half counts");
            assert_ne!(next.1.wrapping_sub(previous.1), 1, "the low half counts");
            assert_ne!(next.0, previous.0, "the high half does not move");
            assert_ne!(next.1, previous.1, "the low half does not move");
            previous = next;
        }
        let minted: BTreeSet<String> = (0..4096).map(|_| source.mint().request_id().as_str().to_owned()).collect();
        assert_eq!(minted.len(), 4096);
        assert!(minted.iter().all(|id| id.len() == 36 && id.get(14..15) == Some("4")), "{minted:?}");
    }

    /// Negative — two sources in one process do not agree, so an identifier does not leak which
    /// binary or which service instance answered.
    #[test]
    fn two_sources_do_not_mint_the_same_identifier() {
        assert_ne!(MintedTraces::new().mint().request_id(), MintedTraces::new().mint().request_id());
        assert_ne!(
            MintedTraces::with_uuid_request_ids().mint().request_id(),
            MintedTraces::with_uuid_request_ids().mint().request_id()
        );
    }

    /// Negative — a run of identifiers has no repeat. Correlation is the whole purpose, and a
    /// repeat joins two support conversations that have nothing to do with each other.
    #[test]
    fn a_run_of_identifiers_has_no_repeat() {
        let source = MintedTraces::new();
        let minted: BTreeSet<String> = (0..4096).map(|_| source.mint().request_id().as_str().to_owned()).collect();
        assert_eq!(minted.len(), 4096);
    }

    /// Negative — the request identifier and the host identifier of one trace are unrelated, so
    /// neither can be computed from the other.
    #[test]
    fn the_two_identifiers_of_one_trace_are_not_the_same_number() {
        let trace = MintedTraces::new().mint();
        assert!(!trace.host_id().as_str().contains(trace.request_id().as_str()));
    }

    /// Negative — applying a trace replaces an identifier that was already there instead of
    /// appending a second one, so a response can never carry two.
    #[test]
    fn applying_a_trace_replaces_an_identifier_already_present() {
        let mut headers = HeaderMap::new();
        headers.insert(REQUEST_ID_HEADER, HeaderValue::from_static("CALLERCHOSEN0000"));
        headers.append(REQUEST_ID_HEADER, HeaderValue::from_static("CALLERCHOSEN0001"));
        RequestTrace::from_bits(0xAAAA, 0xBBBB).apply(&mut headers);
        assert_eq!(headers.get_all(REQUEST_ID_HEADER).iter().count(), 1);
        assert_eq!(headers.get(REQUEST_ID_HEADER).map(HeaderValue::as_bytes), Some(&b"000000000000AAAA"[..]));
        assert_eq!(headers.get_all(HOST_ID_HEADER).iter().count(), 1);
    }

    /// Negative — a fixed source answers the same trace every time, which is what makes a pinned
    /// error document comparable, and is also exactly why it must not be deployed.
    #[test]
    fn a_fixed_source_does_not_move() {
        let source = FixedTrace::at(7, 9);
        assert_eq!(source.mint(), source.mint());
        assert_eq!(source.mint().request_id().as_str(), "0000000000000007");
        assert_eq!(source.trace(), &source.mint());
    }

    /// Positive — the default source is object safe through `Arc<dyn _>`, which is how the
    /// assembled service holds it.
    #[test]
    fn the_default_source_is_object_safe() {
        let source: std::sync::Arc<dyn TraceSource> = std::sync::Arc::new(MintedTraces::default());
        assert_eq!(source.mint().request_id().as_str().len(), RequestId::LEN);
    }

    /// Positive — the debug rendering shows the identifier and nothing else, so an event logged
    /// through `Debug` is still readable.
    #[test]
    fn the_debug_rendering_shows_the_identifier() {
        let rendered = format!("{:?}", RequestTrace::from_bits(0x1234, 0x5678));
        assert!(rendered.contains("0000000000001234"), "{rendered}");
        assert!(rendered.contains("00000000000000000000000000005678"), "{rendered}");
    }
}
