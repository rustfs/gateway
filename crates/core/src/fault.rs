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

//! The two closed sets a refusal may add to itself: response headers, and error-document elements.
//!
//! Responsible for: [`ErrorHeader`] — the facts a refusal may put in its head, spelled as headers
//! by this module rather than by the caller — [`ErrorDetail`] — the elements an `<Error>` document
//! may carry beyond `Code` and `Message` — the canonical element order in [`ELEMENT_ORDER`], and
//! the two messages AWS pins for the refusals those elements belong to.
//! NOT responsible for: writing either of them. The facade's renderer does that, and it is also the
//! only thing that knows which headers the framework stamps on every response and therefore refuses
//! to let anything else write.
//! Upstream: `http`. Downstream: [`crate::handler::HandlerError`], and the facade's renderer.
//!
//! # Why neither of these is a map
//!
//! The obvious shape is `HeaderMap` plus `BTreeMap<String, String>`, and it is wrong in two
//! separate ways.
//!
//! A `HeaderMap` on a refusal is a backend's licence to write `x-amz-request-id`. That header is
//! minted by the service, written by one function, and quoted in support conversations; a backend
//! that can set it can make two requests claim the same identity, and the failure is invisible
//! until somebody tries to correlate a log. [`ErrorHeader`] is an enumeration instead, so the
//! header a backend cannot set is a header it *cannot name* — the same technique
//! `rustfs-gateway::RequestId` uses to make an echo unwritable. Widening the set is a visible edit
//! to this file, reviewed once, rather than a string a handler invents.
//!
//! Each variant also carries its **value**, typed, rather than a string. `Content-Range` on a `416`
//! is `bytes */<length>` and nothing else, so the variant holds the length and this module does the
//! spelling. Nothing a caller sent can reach a header value through this type, which is what makes
//! response splitting unreachable rather than merely unlikely.
//!
//! A free string map for the document is wrong for a quieter reason: `<ActualObjectSize>` and
//! `<ActualObjectsize>` both typecheck, and the difference is a client that reads one element fewer.
//! [`ErrorDetail`] fixes the spelling and [`ELEMENT_ORDER`] fixes the position, so the order of a
//! document is a function of *which* elements it carries and never of the order a handler happened
//! to add them in.
//!
//! # Where the 200-then-fail case will attach
//!
//! `CompleteMultipartUpload` commits its status before it knows whether it succeeded, so it needs
//! to answer `200` and then emit an `<Error>` document into the body. That is a change to *when* a
//! refusal is rendered, not to *what* it contains: the trailing document is the same document, with
//! the same elements in the same order. So [`ErrorDetail`] is deliberately free of any assumption
//! that a head accompanies it, and the facade's renderer exposes the document on its own for the
//! path that will need it. [`ErrorHeader`] is the half that does not carry over — a header cannot
//! be added to a head that has already gone out — which is why the two are separate lists here
//! rather than one "extras" bag.

use std::borrow::Cow;

use http::HeaderName;
use rustfs_gateway_types::{Timestamp, TimestampFormat};

/// The message AWS answers a range it cannot satisfy with.
///
/// Pinned here rather than written at each call site: the conformance suite compares the document
/// byte for byte, so this string is wire format, and a second spelling of it is a second answer.
pub const RANGE_NOT_SATISFIABLE_MESSAGE: &str = "The requested range is not satisfiable";

/// The message AWS answers a failed precondition with. Wire format, for [`RANGE_NOT_SATISFIABLE_MESSAGE`]'s reason.
pub const PRECONDITION_FAILED_MESSAGE: &str = "At least one of the pre-conditions you specified did not hold";

/// A region name a refusal may state, validated at construction.
///
/// Exists so that [`ErrorHeader::BucketRegion`] carries a value whose byte set is decided here
/// rather than by the caller: a region is lowercase ASCII letters, digits and hyphens, bounded, so
/// nothing that could split a header can reach the rendering. The value is backend knowledge — the
/// region the bucket actually lives in — never an echo of caller input.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RegionLabel(Box<str>);

impl RegionLabel {
    /// The longest region name this type accepts. Generous against AWS's own names.
    pub const MAX_LEN: usize = 64;

    /// Validates a region name.
    ///
    /// # Errors
    ///
    /// [`InvalidWireLabel`] when the name is empty, longer than [`Self::MAX_LEN`], or carries any
    /// byte outside lowercase ASCII letters, digits and `-`.
    pub fn new(text: &str) -> Result<Self, InvalidWireLabel> {
        let ok = !text.is_empty()
            && text.len() <= Self::MAX_LEN
            && text
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if !ok {
            return Err(InvalidWireLabel);
        }
        Ok(Self(Box::from(text)))
    }

    /// The validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The endpoint a redirect points at, validated at construction.
///
/// Carried by [`ErrorHeader::RedirectLocation`], the `Location` header of a `307
/// TemporaryRedirect`. Backend knowledge — where the bucket is served — with the byte set closed
/// here for the same reason as [`RegionLabel`]: ASCII graphic only, so a header split cannot be
/// spelled.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RedirectTarget(Box<str>);

impl RedirectTarget {
    /// The longest target this type accepts.
    pub const MAX_LEN: usize = 512;

    /// Validates a redirect target.
    ///
    /// # Errors
    ///
    /// [`InvalidWireLabel`] when the target is empty, longer than [`Self::MAX_LEN`], or carries
    /// any byte that is not ASCII graphic.
    pub fn new(text: &str) -> Result<Self, InvalidWireLabel> {
        let ok = !text.is_empty() && text.len() <= Self::MAX_LEN && text.bytes().all(|byte| byte.is_ascii_graphic());
        if !ok {
            return Err(InvalidWireLabel);
        }
        Ok(Self(Box::from(text)))
    }

    /// The validated target.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An instant a refusal may state, rendered once at construction.
///
/// Carried by [`ErrorHeader::LastModified`]. The stored value is the rendered RFC 9110 §5.6.7
/// `IMF-fixdate`, not the reading it came from, for the reason [`RegionLabel`] stores a validated
/// name: [`ErrorHeader::value`] is infallible, so a reading the wire format cannot express has to
/// be refused here rather than papered over there. A fallback date on a refusal is worse than no
/// header — SDKs and caches parse this field, and a value they cannot parse is one they may
/// substitute their own for.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HttpDate(Box<str>);

impl HttpDate {
    /// Renders a Unix second reading as an `IMF-fixdate`.
    ///
    /// # Errors
    ///
    /// [`InvalidWireLabel`] when the reading falls outside the four-digit year range the wire
    /// format can express.
    pub fn from_unix_seconds(seconds: i64) -> Result<Self, InvalidWireLabel> {
        let text = Timestamp::from_secs(seconds)
            .render(TimestampFormat::HttpDate)
            .map_err(|_| InvalidWireLabel)?;
        // Belt and braces against the one property `value()` promises: the renderer is this
        // repository's own and emits ASCII, and the assertion is what keeps that true if it changes.
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_graphic() || byte == b' ') {
            return Err(InvalidWireLabel);
        }
        Ok(Self(Box::from(text.as_str())))
    }

    /// The rendered date.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An object version id a refusal may state, validated at construction.
///
/// Carried by [`ErrorHeader::VersionId`], the `x-amz-version-id` of a delete-marker refusal. The
/// value is backend knowledge — the version the read found — and its byte set is closed here for
/// [`RegionLabel`]'s reason: visible ASCII only, bounded, so a header split cannot be spelled.
/// Every version id S3 mints, and RustFS's UUIDs and `null`, fall inside it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VersionIdLabel(Box<str>);

impl VersionIdLabel {
    /// The longest version id this type accepts; an object key's bound.
    pub const MAX_LEN: usize = 1024;

    /// Validates a version id.
    ///
    /// # Errors
    ///
    /// [`InvalidWireLabel`] when the id is empty, longer than [`Self::MAX_LEN`], or carries any
    /// byte that is not ASCII graphic.
    pub fn new(text: &str) -> Result<Self, InvalidWireLabel> {
        let ok = !text.is_empty() && text.len() <= Self::MAX_LEN && text.bytes().all(|byte| byte.is_ascii_graphic());
        if !ok {
            return Err(InvalidWireLabel);
        }
        Ok(Self(Box::from(text)))
    }

    /// The validated id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A value refused by [`RegionLabel::new`], [`RedirectTarget::new`], [`VersionIdLabel::new`] or
/// [`HttpDate::from_unix_seconds`].
///
/// Carries nothing on purpose: echoing the refused bytes back would hand the caller of a
/// diagnostic path the very bytes the validation exists to keep out of a header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidWireLabel;

impl std::fmt::Display for InvalidWireLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("not a value this wire label admits")
    }
}

impl std::error::Error for InvalidWireLabel {}

/// A fact a backend may add to the head of its own refusal.
///
/// A closed set, and every variant names a fact rather than a header: the wire spelling is this
/// module's, so a backend cannot choose the header name and cannot choose the value's syntax
/// either. See the module documentation for why this is an enumeration and not a `HeaderMap`.
///
/// # Admitting a new variant
///
/// Three questions, all of which must answer yes. Is the header required by a specification on a
/// status a handler can produce? Can the framework not compute it, because only the backend knows
/// the fact? And is the value expressible as a typed field rather than as a string the caller could
/// influence? A header that fails the third question does not belong here in any form.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ErrorHeader {
    /// `Content-Range: bytes */<complete_length>` — the unsatisfied form.
    ///
    /// RFC 9110 §14.4 requires it on a `416`, and it is the only way a client learns the length it
    /// should have asked for; without it the client retries the same impossible range for ever.
    UnsatisfiedRange {
        /// The current length of the selected representation, in bytes.
        complete_length: u64,
    },
    /// `Retry-After: <seconds>` — RFC 9110 §10.2.3.
    ///
    /// The one number that turns a `503 SlowDown` into something an SDK can back off against
    /// instead of guessing. Only the backend knows how long its own pressure will last.
    RetryAfter {
        /// How long the client should wait, in whole seconds.
        seconds: u32,
    },
    /// `x-amz-bucket-region: <region>` — where the bucket actually lives.
    ///
    /// Mandatory on the `301 PermanentRedirect` a path-style request for a bucket in another
    /// region receives: it is the only way an SDK learns the right endpoint, and without it the
    /// client fails outright instead of retrying. Only the backend knows the bucket's region.
    BucketRegion {
        /// The region of the bucket the request named.
        region: RegionLabel,
    },
    /// `Location: <endpoint>` — where a `307 TemporaryRedirect` sends the client.
    ///
    /// The shape of the redirect AWS answers during a new bucket's DNS propagation window. The
    /// trigger is the backend's knowledge of bucket placement; this variant only fixes what the
    /// response looks like when a backend has that knowledge.
    RedirectLocation {
        /// The endpoint the client should retry against.
        target: RedirectTarget,
    },
    /// `x-amz-delete-marker: true` — the version the read selected is a deletion, not data.
    ///
    /// The whole difference between the `405` a read of a delete marker gets and the `404` that
    /// means the version id is unknown: without it a client cannot tell a marker it should remove
    /// from a version id it should stop using, and a versioned restore cannot be driven. Only the
    /// backend knows a version is a marker, and the value is this module's literal `true`, never a
    /// reading of anything the caller sent.
    DeleteMarker,
    /// `x-amz-version-id: <id>` — which version the delete-marker refusal found.
    ///
    /// Rides with [`Self::DeleteMarker`] on both marker refusals: a client removing the marker to
    /// restore the object needs its id, and the `404` a read naming no version gets is where it
    /// learns it without listing versions. Only the backend knows the id; [`VersionIdLabel`] fixes
    /// the syntax.
    VersionId {
        /// The version id of the marker the read found.
        version_id: VersionIdLabel,
    },
    /// `Last-Modified: <IMF-fixdate>` — when the selected version was written.
    ///
    /// AWS answers it on the refusal a delete-marker read gets, and it is what lets a client
    /// decide whether the marker is the one it just created. Only the backend knows the instant;
    /// [`HttpDate`] fixes the syntax.
    LastModified {
        /// The instant the selected version was written.
        at: HttpDate,
    },
}

impl ErrorHeader {
    /// The header this fact is spelled as.
    #[must_use]
    pub const fn name(&self) -> HeaderName {
        match self {
            Self::UnsatisfiedRange { .. } => HeaderName::from_static("content-range"),
            Self::RetryAfter { .. } => HeaderName::from_static("retry-after"),
            Self::BucketRegion { .. } => HeaderName::from_static("x-amz-bucket-region"),
            Self::RedirectLocation { .. } => HeaderName::from_static("location"),
            Self::DeleteMarker => HeaderName::from_static("x-amz-delete-marker"),
            Self::VersionId { .. } => HeaderName::from_static("x-amz-version-id"),
            Self::LastModified { .. } => HeaderName::from_static("last-modified"),
        }
    }

    /// The header value, rendered.
    ///
    /// Every byte of the result comes from this function's own literals, from the decimal
    /// rendering of an integer, or from a value a constructor in this module validated to ASCII
    /// graphic characters — so the result is ASCII graphic characters and spaces only. That is
    /// the property that makes header injection unreachable through this type, and it is asserted
    /// rather than asserted-in-a-comment: see `every_rendered_value_is_a_usable_header_value`.
    #[must_use]
    pub fn value(&self) -> String {
        match self {
            Self::UnsatisfiedRange { complete_length } => format!("bytes */{complete_length}"),
            Self::RetryAfter { seconds } => seconds.to_string(),
            Self::BucketRegion { region } => region.as_str().to_owned(),
            Self::RedirectLocation { target } => target.as_str().to_owned(),
            Self::DeleteMarker => "true".to_owned(),
            Self::VersionId { version_id } => version_id.as_str().to_owned(),
            Self::LastModified { at } => at.as_str().to_owned(),
        }
    }
}

/// The element names an `<Error>` document may carry between `Message` and the two server-minted
/// identifiers, in the order they are written.
///
/// The order is a declared contract, not an implementation detail: conformance cases assert the
/// element sequence of a document byte for byte, so reordering this array is a wire change.
/// [`ErrorDetail::position`] is the index into it, and the two are kept in agreement by a test
/// rather than by discipline.
pub const ELEMENT_ORDER: [&str; 6] = [
    "Key",
    "BucketName",
    "Condition",
    "RangeRequested",
    "ActualObjectSize",
    "Region",
];

/// An element an `<Error>` document may carry beyond `Code` and `Message`.
///
/// The name is fixed by the variant and the position by [`ELEMENT_ORDER`], so neither is something
/// a handler can get wrong. The *text* is dynamic, and may be, for the reason
/// [`crate::handler::HandlerError`] may carry a dynamic message: by the time a handler runs the
/// caller has been authenticated and authorised, so an echo is an answer to somebody who is already
/// entitled to it rather than a reflection surface for anyone who can open a socket.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ErrorDetail {
    /// `<Key>` — the object key the refusal is about.
    Key(Cow<'static, str>),
    /// `<BucketName>` — the bucket the refusal is about.
    BucketName(Cow<'static, str>),
    /// `<Condition>` — which precondition failed, named as the request header that carried it
    /// (`If-Match`, `If-None-Match`, ...).
    Condition(Cow<'static, str>),
    /// `<RangeRequested>` — the `Range` header as it arrived, so a client logging the failure can
    /// see what it asked for.
    RangeRequested(Cow<'static, str>),
    /// `<ActualObjectSize>` — the current length of the object, in bytes.
    ActualObjectSize(u64),
    /// `<Region>` — the region the redirected request should have been sent to.
    ///
    /// The document twin of [`ErrorHeader::BucketRegion`]: a `301 PermanentRedirect` carries the
    /// region in its head because a `HEAD` has no body to carry it in, and may also state it here
    /// for the clients that read the document.
    Region(RegionLabel),
}

impl ErrorDetail {
    /// The element name, exactly as it goes on the wire.
    #[must_use]
    pub const fn element(&self) -> &'static str {
        match self {
            Self::Key(_) => "Key",
            Self::BucketName(_) => "BucketName",
            Self::Condition(_) => "Condition",
            Self::RangeRequested(_) => "RangeRequested",
            Self::ActualObjectSize(_) => "ActualObjectSize",
            Self::Region(_) => "Region",
        }
    }

    /// This element's index in [`ELEMENT_ORDER`], which is the position it is written at.
    #[must_use]
    pub const fn position(&self) -> usize {
        match self {
            Self::Key(_) => 0,
            Self::BucketName(_) => 1,
            Self::Condition(_) => 2,
            Self::RangeRequested(_) => 3,
            Self::ActualObjectSize(_) => 4,
            Self::Region(_) => 5,
        }
    }

    /// The element's text content, unescaped. The writer escapes it.
    #[must_use]
    pub fn text(&self) -> Cow<'_, str> {
        match self {
            Self::Key(text) | Self::BucketName(text) | Self::Condition(text) | Self::RangeRequested(text) => {
                Cow::Borrowed(text.as_ref())
            }
            Self::ActualObjectSize(size) => Cow::Owned(size.to_string()),
            Self::Region(region) => Cow::Borrowed(region.as_str()),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// One of every [`ErrorHeader`] variant.
    ///
    /// The match below has no wildcard arm, so a variant added without being added here fails to
    /// compile. That is the forcing function: a new header cannot slip past the guards below by
    /// being absent from the list they iterate.
    fn every_header() -> Vec<ErrorHeader> {
        let all = vec![
            ErrorHeader::UnsatisfiedRange { complete_length: 10 },
            ErrorHeader::RetryAfter { seconds: 3 },
            ErrorHeader::BucketRegion {
                region: RegionLabel::new("eu-west-1").expect("a valid region"),
            },
            ErrorHeader::RedirectLocation {
                target: RedirectTarget::new("https://b.s3.eu-west-1.example.com").expect("a valid target"),
            },
            ErrorHeader::DeleteMarker,
            ErrorHeader::VersionId {
                version_id: VersionIdLabel::new("3HL4kqtJlcpXroDTDmJ.rmSpXd3dIbrHY").expect("a valid version id"),
            },
            ErrorHeader::LastModified {
                at: HttpDate::from_unix_seconds(1_767_236_645).expect("a renderable instant"),
            },
        ];
        for header in &all {
            match header {
                ErrorHeader::UnsatisfiedRange { .. }
                | ErrorHeader::RetryAfter { .. }
                | ErrorHeader::BucketRegion { .. }
                | ErrorHeader::RedirectLocation { .. }
                | ErrorHeader::DeleteMarker
                | ErrorHeader::VersionId { .. }
                | ErrorHeader::LastModified { .. } => {}
            }
        }
        all
    }

    /// One of every [`ErrorDetail`] variant, on the same terms.
    fn every_detail() -> Vec<ErrorDetail> {
        let all = vec![
            ErrorDetail::Key(Cow::Borrowed("k")),
            ErrorDetail::BucketName(Cow::Borrowed("b")),
            ErrorDetail::Condition(Cow::Borrowed("If-Match")),
            ErrorDetail::RangeRequested(Cow::Borrowed("bytes=20-30")),
            ErrorDetail::ActualObjectSize(10),
            ErrorDetail::Region(RegionLabel::new("eu-west-1").expect("a valid region")),
        ];
        for detail in &all {
            match detail {
                ErrorDetail::Key(_)
                | ErrorDetail::BucketName(_)
                | ErrorDetail::Condition(_)
                | ErrorDetail::RangeRequested(_)
                | ErrorDetail::ActualObjectSize(_)
                | ErrorDetail::Region(_) => {}
            }
        }
        all
    }

    /// Negative — no variant names a header the framework stamps on every response. This is the
    /// assertion that stops the closed set from being widened into the one shape it exists to
    /// prevent: a backend that can overwrite the request identifier, the server name or the date.
    #[test]
    fn no_variant_names_a_header_the_framework_guarantees() {
        let framework_owned = [
            "x-amz-request-id",
            "x-amz-id-2",
            "server",
            "date",
            "content-type",
            "content-length",
        ];
        for header in every_header() {
            let name = header.name();
            assert!(
                !framework_owned.contains(&name.as_str()),
                "{name} is written by the framework and must not be nameable by a backend"
            );
        }
    }

    /// Negative — every rendered value fits in a header field, for every extreme of its typed
    /// input. A value that did not would be dropped at render time and the response would be
    /// missing a header a specification requires.
    #[test]
    fn every_rendered_value_is_a_usable_header_value() {
        let extremes = [
            ErrorHeader::UnsatisfiedRange { complete_length: 0 },
            ErrorHeader::UnsatisfiedRange {
                complete_length: u64::MAX,
            },
            ErrorHeader::RetryAfter { seconds: 0 },
            ErrorHeader::RetryAfter { seconds: u32::MAX },
        ];
        for header in extremes.into_iter().chain(every_header()) {
            let value = header.value();
            assert!(
                value.bytes().all(|byte| byte == b' ' || byte.is_ascii_graphic()),
                "{value:?} is not printable ASCII"
            );
            http::HeaderValue::from_str(&value).expect("a usable header value");
        }
    }

    /// Negative — nothing a caller sent can reach a header value, because no variant accepts text.
    /// The check is on the rendering rather than on the type, so it also covers a future variant
    /// that took a string: a CR or an LF in a header value is response splitting.
    #[test]
    fn no_rendered_value_can_carry_a_line_break() {
        for header in every_header() {
            let value = header.value();
            assert!(!value.contains('\r') && !value.contains('\n'), "{value:?}");
        }
    }

    /// Positive — the unsatisfied form is spelled as RFC 9110 §14.4 writes it.
    #[test]
    fn the_unsatisfied_range_renders_the_form_the_rfc_names() {
        assert_eq!(ErrorHeader::UnsatisfiedRange { complete_length: 10 }.value(), "bytes */10");
        assert_eq!(ErrorHeader::UnsatisfiedRange { complete_length: 0 }.value(), "bytes */0");
        assert_eq!(ErrorHeader::UnsatisfiedRange { complete_length: 10 }.name().as_str(), "content-range");
    }

    /// Negative — the declared order and the positions agree. Two sources of truth for the element
    /// order is exactly the drift that produces a document whose elements are in an order no case
    /// asserted.
    #[test]
    fn the_declared_order_and_the_positions_agree() {
        for detail in every_detail() {
            assert_eq!(
                ELEMENT_ORDER[detail.position()],
                detail.element(),
                "{:?} is at the wrong position",
                detail.element()
            );
        }
        assert_eq!(ELEMENT_ORDER.len(), every_detail().len());
    }

    /// Negative — no two variants share a position, so the order is total rather than merely
    /// declared. A tie would make the document order depend on a sort's stability.
    #[test]
    fn no_two_elements_claim_the_same_position() {
        let mut positions: Vec<usize> = every_detail().iter().map(ErrorDetail::position).collect();
        let count = positions.len();
        positions.sort_unstable();
        positions.dedup();
        assert_eq!(positions.len(), count);
    }

    /// Negative — the element names are the AWS spellings, asserted literally. A case-only typo is
    /// invisible in review and reads to a client as a missing element.
    #[test]
    fn the_element_names_are_the_spellings_a_client_reads() {
        assert_eq!(ErrorDetail::ActualObjectSize(0).element(), "ActualObjectSize");
        assert_eq!(ErrorDetail::RangeRequested(Cow::Borrowed("")).element(), "RangeRequested");
        assert_eq!(ErrorDetail::Condition(Cow::Borrowed("")).element(), "Condition");
        assert_eq!(ErrorDetail::Key(Cow::Borrowed("")).element(), "Key");
        assert_eq!(ErrorDetail::BucketName(Cow::Borrowed("")).element(), "BucketName");
        let region = RegionLabel::new("us-west-2").expect("a valid region");
        assert_eq!(ErrorDetail::Region(region).element(), "Region");
    }

    /// Negative — the two validated labels refuse every byte that could reach a header as a split
    /// or reach a document as markup noise: uppercase, spaces, CR, LF, and the empty string.
    #[test]
    fn a_wire_label_refuses_what_a_header_cannot_carry() {
        for hostile in ["", "EU", "us east 1", "us-east-1\r\nx-amz-request-id: forged", "üs-east-1"] {
            assert!(RegionLabel::new(hostile).is_err(), "{hostile:?} must be refused");
        }
        assert!(RegionLabel::new(&"a".repeat(RegionLabel::MAX_LEN + 1)).is_err());
        for hostile in ["", "https://x\r\nLocation: y", "with space"] {
            assert!(RedirectTarget::new(hostile).is_err(), "{hostile:?} must be refused");
        }
        assert!(RedirectTarget::new(&"a".repeat(RedirectTarget::MAX_LEN + 1)).is_err());
    }

    /// Positive — the labels accept the values the family actually produces.
    #[test]
    fn a_wire_label_accepts_the_values_the_family_produces() {
        assert_eq!(RegionLabel::new("us-east-1").expect("valid").as_str(), "us-east-1");
        assert_eq!(RegionLabel::new("eu-west-1").expect("valid").as_str(), "eu-west-1");
        let target = RedirectTarget::new("https://b.s3.eu-west-1.example.com").expect("valid");
        assert_eq!(target.as_str(), "https://b.s3.eu-west-1.example.com");
    }

    /// Positive — a numeric element renders as a bare decimal, with no separators and no unit.
    #[test]
    fn a_numeric_element_renders_as_a_bare_decimal() {
        assert_eq!(ErrorDetail::ActualObjectSize(0).text(), "0");
        assert_eq!(ErrorDetail::ActualObjectSize(1_048_576).text(), "1048576");
        assert_eq!(ErrorDetail::ActualObjectSize(u64::MAX).text(), "18446744073709551615");
    }
}
