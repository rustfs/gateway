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
//! Responsible for: [`RequestId`] and [`HostId`] — opaque, server-minted, closed-alphabet values —
//! the [`RequestTrace`] that pairs them, the [`TraceSource`] that mints one per request, the
//! default [`MintedTraces`], and the substitutable [`FixedTrace`] a conformance case needs.
//! NOT responsible for: deciding when a request is identified (`crate::service` mints once, at the
//! top), or what an error document says (`crate::render`). Neither of those formats an identifier
//! itself: both read one out of a [`RequestTrace`].
//! Upstream: `http`, `std`. Downstream: `crate::builder`, `crate::service`, `crate::render`,
//! `crate::ext::observer`.
//!
//! # The invariant, in one sentence
//!
//! **A request is identified once, and the `x-amz-request-id` header, the `<RequestId>` element of
//! an error document and the audit event all carry that one value.**
//!
//! It is fixed by a type rather than by discipline. `crate::service` mints exactly one
//! [`RequestTrace`] per call and passes it by reference to the two places that write it out;
//! neither of them can obtain a second one, because neither holds a [`TraceSource`]. Two call
//! sites formatting from one value cannot drift; two call sites formatting from two sources can,
//! and would do so silently — the header and the body of the same response would name different
//! requests, which is worse than having no identifier at all, because an operator would trust it.
//!
//! # Why an echo is not writable
//!
//! Three independent reasons, each of which is sufficient on its own:
//!
//! 1. **[`TraceSource::mint`] takes no request.** Its only parameter is `&self`. An implementation
//!    that wanted to echo a header value has nothing to echo *from* — the signature does not admit
//!    the request, and widening it later would be the change to argue about, not a change to make
//!    quietly.
//! 2. **No constructor accepts text.** [`RequestId`] and [`HostId`] are built from integers and
//!    from nothing else. There is no `FromStr`, no `TryFrom<&str>`, no `From<HeaderValue>` and no
//!    deserializer, so there is no path from a byte the caller sent to one of these values that
//!    does not go through a number first.
//! 3. **The alphabet is closed.** Whatever integer a value holds, it renders as ASCII uppercase
//!    hexadecimal and only that — 16 digits for a [`RequestId`], 32 for a [`HostId`]. So even the
//!    round trip reason 2 leaves open (parse the caller's text as an integer, mint from it) cannot
//!    carry a quote, an angle bracket, a newline or a terminal escape into a log line or into an
//!    XML document. The property a log sink needs is not "the caller did not choose this" but "the
//!    caller cannot choose *what characters* this contains", and that one is enforced by the
//!    renderer, which is the single function [`RequestId::as_str`].
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

/// The header carrying the [`RequestId`].
pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-amz-request-id");

/// The header carrying the [`HostId`].
pub const HOST_ID_HEADER: HeaderName = HeaderName::from_static("x-amz-id-2");

/// The identifier of one request, as it appears on the wire.
///
/// Opaque: 16 ASCII uppercase hexadecimal digits, which is the shape AWS answers with and the
/// shape SDK diagnostics and support tooling already cope with. Nothing may parse it — this type
/// publishes no accessor that returns a number, precisely so that no downstream behaviour can come
/// to depend on the bits inside.
///
/// # Security
///
/// Server-minted, always. See the module documentation for the three reasons an echo of a
/// caller-supplied value is not writable through this type.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId([u8; RequestId::LEN]);

impl RequestId {
    /// The rendered length, in bytes. Fixed: every identifier is exactly this long.
    pub const LEN: usize = 16;

    /// Mints an identifier from 64 bits.
    ///
    /// Takes an integer rather than text, which is reason 2 of the module documentation. A caller
    /// holding a header value cannot reach this constructor without deciding, in writing, to turn
    /// that value into a number first.
    #[must_use]
    pub fn from_bits(bits: u64) -> Self {
        Self(hex_16(bits))
    }

    /// The rendered identifier.
    ///
    /// The one renderer. Both the header and the error document read this, which is what makes
    /// "the two agree" a property of the type rather than of two `format!` calls.
    #[must_use]
    pub fn as_str(&self) -> &str {
        as_ascii(self.0.as_slice(), ZEROS_16)
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

/// The pair minted once per request.
///
/// Passed by reference down the pipeline. A stage that writes an identifier out takes one of these
/// and never a [`TraceSource`], so no stage below the entry point is able to mint a second.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestTrace {
    request_id: RequestId,
    host_id: HostId,
}

impl RequestTrace {
    /// A trace from its two identifiers.
    #[must_use]
    pub const fn new(request_id: RequestId, host_id: HostId) -> Self {
        Self { request_id, host_id }
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

    /// Writes both identifiers into a response head, replacing anything already there.
    ///
    /// The one header writer, and it **replaces** rather than appends: an encoder that wrote its
    /// own `x-amz-request-id` loses, so the value a caller receives is always the value the service
    /// minted and put in its own audit event. A response carrying two of these headers is a
    /// response an intermediary is free to pick either half of.
    pub fn apply(&self, headers: &mut HeaderMap) {
        // Both values are ASCII hexadecimal by construction, so neither conversion can fail; a
        // header value only rejects control bytes and non-ASCII, and `hex_digit` emits neither.
        if let Ok(value) = HeaderValue::from_str(self.request_id.as_str()) {
            headers.insert(REQUEST_ID_HEADER, value);
        }
        if let Ok(value) = HeaderValue::from_str(self.host_id.as_str()) {
            headers.insert(HOST_ID_HEADER, value);
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
/// third-party implementation.
pub trait TraceSource: Send + Sync + 'static {
    /// Mints the identifiers for one request.
    fn mint(&self) -> RequestTrace;
}

impl<T: TraceSource + ?Sized> TraceSource for std::sync::Arc<T> {
    fn mint(&self) -> RequestTrace {
        (**self).mint()
    }
}

/// The default source: a per-process counter behind a per-process keyed hash.
///
/// Distinctness comes from the counter, opacity from the key. See the module documentation for
/// what this buys and, just as importantly, what it does not.
#[derive(Debug)]
pub struct MintedTraces {
    keys: RandomState,
    ordinal: AtomicU64,
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
        let host = (u128::from(self.keyed(HOST_HIGH_DOMAIN, ordinal)) << 64) | u128::from(self.keyed(HOST_LOW_DOMAIN, ordinal));
        RequestTrace::from_bits(request, host)
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
const HOST_HIGH_DOMAIN: u64 = 0x484f_5354_4849_4748; // "HOSTHIGH"
const HOST_LOW_DOMAIN: u64 = 0x484f_5354_5f4c_4f57; // "HOST_LOW"

/// One hexadecimal digit, by arithmetic rather than by table lookup.
///
/// Arithmetic because this crate denies `clippy::indexing_slicing`, and a table lookup indexed by
/// a runtime nibble is exactly the pattern that lint exists to question. It is also the whole of
/// the closed alphabet: `0`–`9` and `A`–`F`, with no input able to produce anything else.
const fn hex_digit(nibble: u8) -> u8 {
    if nibble < 10 { b'0' + nibble } else { b'A' + (nibble - 10) }
}

/// 64 bits as 16 uppercase hexadecimal digits, most significant first.
///
/// Written with `array::from_fn` rather than an indexed loop so that no `clippy::indexing_slicing`
/// waiver is needed anywhere in this module.
fn hex_16(bits: u64) -> [u8; 16] {
    core::array::from_fn(|index| hex_digit(nibble_of(u128::from(bits), 15, index)))
}

/// 128 bits as 32 uppercase hexadecimal digits, most significant first.
fn hex_32(bits: u128) -> [u8; 32] {
    core::array::from_fn(|index| hex_digit(nibble_of(bits, 31, index)))
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
/// Every byte reaching here came from [`hex_digit`], which emits `0`–`9` and `A`–`F` and nothing
/// else, so the conversion cannot fail. The fallback is a placeholder of the same length rather
/// than an empty string, because an identifier that silently became empty would look, in a log,
/// like a request that was never given one — and because the fixed length is a documented property
/// that even an unreachable branch should not break.
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

    /// Negative — two sources in one process do not agree, so an identifier does not leak which
    /// binary or which service instance answered.
    #[test]
    fn two_sources_do_not_mint_the_same_identifier() {
        assert_ne!(MintedTraces::new().mint(), MintedTraces::new().mint());
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
