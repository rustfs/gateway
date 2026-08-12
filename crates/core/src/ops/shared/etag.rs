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

//! Which entity-tag comparison each conditional header uses, and how its value is read.
//!
//! Shares: etag
//! Members: GetObject, HeadObject, PutObject
//!
//! CopyObject, UploadPartCopy, CompleteMultipartUpload and DeleteObject also carry
//! conditional headers, but none of them reaches this module yet. They are deliberately
//! absent from `Members:` above: the list states what the use graph is, not what it ought
//! to be, because a list that states intent cannot be checked against anything.
//!
//! Responsible for: naming the four conditional entity-tag headers, binding each to the RFC 9110
//! comparison function it is evaluated with, reading a header value into an
//! [`ETag`], and refusing the list form S3 does not implement.
//! NOT responsible for: the entity-tag type itself, its three wire spellings and the two
//! comparison functions (`rustfs-gateway-types`' `ETag` owns those), the order the conditions are
//! evaluated in ([`super::precondition`]), and reading the header off the request, which is the
//! generated decoder's job.
//! Upstream: `rustfs-gateway-types`' `ETag` and `ParseError`. Downstream: [`super::precondition`]
//! and, through it, every member operation above.
//!
//! # Why the comparison is a table and not an argument
//!
//! `If-Match` and `If-None-Match` differ on exactly one point — whether a weak validator may
//! satisfy the condition — and that point is invisible in a call that passes a `bool`. Two of the
//! failures this contract exists to prevent were spelled that way: an entity tag compared as a
//! `String`, so `"abc"` and `abc` did not match; and a typed entity tag whose wildcard variant was
//! forgotten, so `If-None-Match: *` regressed into a 400. Here the header names the comparison,
//! and there is no way to ask for a comparison without naming the header it belongs to.
//!
//! # What the members declare, and what is still declaration-only
//!
//! `GetObject`, `HeadObject` and `PutObject` `use` this module for the `CONDITIONS` list each of
//! them declares — which of the four headers that operation evaluates, and so implicitly which
//! representation each is evaluated against. The other four members do not `use` it yet.
//!
//! [`parse_conditional_etag`] and [`etag_matches`] are a different matter, and the reason is the
//! one recorded at length in [`super::precondition`]: both need a request or a stored tag in hand,
//! so their call site is the backend's, and the facade does not export this module for a backend
//! to reach. The guard that checks `Members:` against `Shares:` in both directions can land now
//! for the three operations above; it cannot yet be made total.

use rustfs_gateway_types::{ETag, ParseError, rules};

use crate::contracts::{
    BARE_CONDITIONAL_ETAG_POLICY, BareConditionalEtagPolicy, CONDITIONAL_WILDCARD_PARSE_POLICY, ConditionalWildcardParsePolicy,
    EtagComparisonStrengthPolicy, IF_MATCH_COMPARISON_STRENGTH, IF_NONE_MATCH_COMPARISON_STRENGTH,
    IfNoneMatchComparisonStrengthPolicy,
};

/// One of the four conditional entity-tag headers a request may carry.
///
/// The copy-source pair is listed because it is evaluated against a *different* representation —
/// the source object — with the same rules. Keeping them in one enum is what stops the copy family
/// from growing its own second answer to "does this tag match?".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConditionalHeader {
    /// `If-Match`, evaluated against the target representation.
    IfMatch,
    /// `If-None-Match`, evaluated against the target representation.
    IfNoneMatch,
    /// `x-amz-copy-source-if-match`, evaluated against the copy source.
    CopySourceIfMatch,
    /// `x-amz-copy-source-if-none-match`, evaluated against the copy source.
    CopySourceIfNoneMatch,
}

/// The RFC 9110 comparison function a condition is evaluated with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EtagComparison {
    /// Weak validators never match. Required for anything that selects or mutates a
    /// representation, because a weak tag says "semantically equivalent", not "the same bytes".
    Strong,
    /// Weakness is ignored; only the opaque tag has to agree.
    Weak,
}

impl ConditionalHeader {
    /// The header's lowercase wire name.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::IfMatch => "if-match",
            Self::IfNoneMatch => "if-none-match",
            Self::CopySourceIfMatch => "x-amz-copy-source-if-match",
            Self::CopySourceIfNoneMatch => "x-amz-copy-source-if-none-match",
        }
    }

    /// The comparison this header is evaluated with.
    ///
    /// `If-Match` is strong on every method: it is a compare-and-swap guard, and a weak validator
    /// cannot carry that promise. `If-None-Match` is weak, which is what lets a cache revalidate
    /// against a tag the origin marked as weak and still receive a 304.
    #[must_use]
    pub const fn comparison(self) -> EtagComparison {
        match self {
            Self::IfMatch | Self::CopySourceIfMatch => match IF_MATCH_COMPARISON_STRENGTH {
                EtagComparisonStrengthPolicy::Strong => EtagComparison::Strong,
                EtagComparisonStrengthPolicy::Weak => EtagComparison::Weak,
            },
            Self::IfNoneMatch | Self::CopySourceIfNoneMatch => match IF_NONE_MATCH_COMPARISON_STRENGTH {
                IfNoneMatchComparisonStrengthPolicy::Weak => EtagComparison::Weak,
                IfNoneMatchComparisonStrengthPolicy::Strong => EtagComparison::Strong,
            },
        }
    }

    /// Whether a match on this header satisfies the condition (`If-Match`) or fails it
    /// (`If-None-Match`).
    #[must_use]
    pub const fn match_satisfies(self) -> bool {
        matches!(self, Self::IfMatch | Self::CopySourceIfMatch)
    }
}

/// Reads a conditional header value into an [`ETag`].
///
/// Accepts all three wire spellings — `"v"`, `W/"v"` and a bare `v` — and the `*` wildcard.
/// Several widely deployed SDKs send the bare form, and rejecting it turns a working conditional
/// request into a 400 for clients that are otherwise correct; `*` is a value of these headers, not
/// a malformed tag, and reading it as one is a regression that has been shipped before.
///
/// # Errors
///
/// Returns a [`ParseError`] for a value the entity-tag grammar cannot carry — an unbalanced quote,
/// an empty tag, a control character — and for the RFC 9110 *list* form. A list is refused rather
/// than silently reduced to its first member: S3 evaluates one entity tag, and quietly dropping the
/// rest of a client's list answers a question it did not ask.
pub fn parse_conditional_etag(value: &str) -> Result<ETag, ParseError> {
    let trimmed = value.trim_matches(|c| c == ' ' || c == '\t');
    if trimmed.contains(',') {
        return Err(ParseError::new(
            "ETag",
            rules::RFC9110_ENTITY_TAG,
            "a conditional header carries one entity tag; the list form is not evaluated",
        ));
    }
    if trimmed == "*" && matches!(CONDITIONAL_WILDCARD_PARSE_POLICY, ConditionalWildcardParsePolicy::Reject) {
        return Err(ParseError::new(
            "ETag",
            rules::RFC9110_ENTITY_TAG,
            "the conditional wildcard is not accepted",
        ));
    }
    if !trimmed.starts_with('"')
        && !trimmed.starts_with("W/\"")
        && trimmed != "*"
        && matches!(BARE_CONDITIONAL_ETAG_POLICY, BareConditionalEtagPolicy::Reject)
    {
        return Err(ParseError::new(
            "ETag",
            rules::RFC9110_ENTITY_TAG,
            "a bare conditional entity tag is not accepted",
        ));
    }
    ETag::parse_http_header(trimmed)
}

/// Whether `requested` satisfies the entity-tag condition against `current`.
///
/// `current` is the entity tag of the representation that exists; a caller with no representation
/// must not reach this function, because `*` is defined as "any current representation" and would
/// otherwise report a match against nothing.
#[must_use]
pub fn etag_matches(comparison: EtagComparison, requested: &ETag, current: &ETag) -> bool {
    match comparison {
        EtagComparison::Strong => requested.matches_strong(current),
        EtagComparison::Weak => requested.matches_weak(current),
    }
}
