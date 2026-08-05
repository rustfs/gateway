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

//! The query string, indexed once and read without allocating.
//!
//! Responsible for: splitting a query string into parameters exactly once, refusing repeated
//! single-valued parameters and escaped parameter names, and handing out borrowed slices of the
//! original string.
//! NOT responsible for: percent-decoding (a value is decoded once, later, by whoever consumes
//! it), interpreting any parameter, or deciding which operation a query selects — that is the
//! route table's, in P4-01.
//! Upstream: this crate's `limits`, `reject` and `text`. Downstream: `wire`, the route table, and
//! the canonical-query-string builder in `rustfs-gateway-sig`.
//!
//! # Why an index and not a map
//!
//! A `HashMap<String, String>` costs two allocations per parameter — measured at roughly twelve
//! `malloc` calls for one `ListObjectsV2` request — and destroys the two things the layers above
//! need: the arrival order, which SigV4's canonical query string depends on, and the fact that a
//! parameter appeared twice, which is a rejection rather than a merge. [`QueryIndex`] stores
//! nothing but offsets into the string the request already owns, inline for the parameter counts
//! that actually occur.

use smallvec::SmallVec;

use crate::limits::{LimitKind, Limits};
use crate::reject::WireReject;
use crate::text::contains_forbidden_control;

/// How many parameters an index holds before it reaches for the heap.
const INLINE_PARAMS: usize = 8;

/// Query parameters whose S3 semantics are single-valued, and which are refused when repeated.
///
/// The same reasoning as [`SINGLE_VALUED_HEADERS`](crate::SINGLE_VALUED_HEADERS): a repeated
/// parameter is two answers to one question, and which one wins differs between the components
/// that will read this request (s3s#176). A pagination parameter is as dangerous as an identity
/// one here — a signer that canonicalises both copies and a lister that reads the first produce a
/// signature that covers a listing nobody performed.
pub const SINGLE_VALUED_QUERY_PARAMS: &[&str] = &[
    "versionId",
    "uploadId",
    "partNumber",
    "list-type",
    "max-keys",
    "max-parts",
    "max-uploads",
    "continuation-token",
    "start-after",
    "marker",
    "key-marker",
    "upload-id-marker",
    "version-id-marker",
    "part-number-marker",
    "prefix",
    "delimiter",
    "encoding-type",
    "response-content-type",
    "response-content-disposition",
    "X-Amz-Signature",
    "X-Amz-Credential",
    "X-Amz-Date",
    "X-Amz-Expires",
    "X-Amz-SignedHeaders",
    "X-Amz-Algorithm",
    "X-Amz-Security-Token",
];

/// One parameter's position within the query string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Param {
    key_start: u16,
    key_end: u16,
    value_start: u16,
    value_end: u16,
}

/// Offsets of every parameter in a query string.
///
/// Owned and `'static`, but holds no text: it indexes the query string stored alongside it on the
/// [`WireRequest`](crate::WireRequest). Offsets rather than references is what keeps the request
/// a plain struct instead of a self-referential one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueryIndex {
    params: SmallVec<[Param; INLINE_PARAMS]>,
}

impl QueryIndex {
    /// Indexes a query string, applying every acceptance-time query rule.
    ///
    /// Empty segments (`a=1&&b=2`) are skipped rather than indexed; a parameter with no `=` gets
    /// an empty value, which is how S3's flag parameters (`?acl`, `?uploads`) arrive.
    ///
    /// # Errors
    ///
    /// * [`WireReject::LimitExceeded`] — the query string or the parameter count is over budget.
    /// * [`WireReject::MalformedQuery`] — a control character in the query string.
    /// * [`WireReject::AmbiguousQueryParameterName`] — a percent-escape in a parameter *name*.
    ///   Real clients never escape one; an escaped spelling gives a parameter a second name, so a
    ///   duplicate check that runs before decoding and a lookup that runs after it disagree about
    ///   what the request contained.
    /// * [`WireReject::DuplicateSingleValuedQuery`] — a single-valued parameter appeared twice.
    pub fn parse(raw: &str, limits: &Limits) -> Result<Self, WireReject> {
        if raw.len() > limits.query_bytes() {
            return Err(WireReject::LimitExceeded(LimitKind::QueryBytes));
        }
        if contains_forbidden_control(raw.as_bytes()) {
            return Err(WireReject::MalformedQuery);
        }

        let mut params: SmallVec<[Param; INLINE_PARAMS]> = SmallVec::new();
        let mut offset = 0usize;
        for segment in raw.split('&') {
            let segment_start = offset;
            offset = offset.saturating_add(segment.len()).saturating_add(1);
            if segment.is_empty() {
                continue;
            }
            if params.len() >= limits.max_query_params {
                return Err(WireReject::LimitExceeded(LimitKind::QueryParams));
            }

            let (key, value_start_relative) = match segment.find('=') {
                Some(at) => (segment.get(..at).unwrap_or(""), at.saturating_add(1)),
                None => (segment, segment.len()),
            };
            if key.as_bytes().contains(&b'%') {
                return Err(WireReject::AmbiguousQueryParameterName);
            }
            if let Some(name) = single_valued_name(key)
                && contains_key(&params, raw, key)
            {
                return Err(WireReject::DuplicateSingleValuedQuery(name));
            }

            let key_start = to_offset(segment_start)?;
            let key_end = to_offset(segment_start.saturating_add(key.len()))?;
            let value_start = to_offset(segment_start.saturating_add(value_start_relative))?;
            let value_end = to_offset(segment_start.saturating_add(segment.len()))?;
            params.push(Param {
                key_start,
                key_end,
                value_start,
                value_end,
            });
        }
        Ok(Self { params })
    }

    /// How many parameters were indexed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.params.len()
    }

    /// Whether the query string held no parameters.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.params.is_empty()
    }

    /// Whether the index stayed inline, meaning indexing this query allocated nothing.
    ///
    /// Exposed so the allocation budget this layer promises can be asserted rather than claimed.
    #[must_use]
    pub fn is_inline(&self) -> bool {
        !self.params.spilled()
    }
}

/// Narrows an offset to the `u16` the index stores, which the query-byte ceiling guarantees fits.
fn to_offset(value: usize) -> Result<u16, WireReject> {
    u16::try_from(value).map_err(|_| WireReject::LimitExceeded(LimitKind::QueryBytes))
}

/// The canonical spelling of a single-valued parameter name, when `key` is one.
fn single_valued_name(key: &str) -> Option<&'static str> {
    SINGLE_VALUED_QUERY_PARAMS.iter().copied().find(|name| *name == key)
}

/// Whether an already-indexed parameter carries this name.
fn contains_key(params: &[Param], raw: &str, key: &str) -> bool {
    params.iter().any(|param| slice(raw, param.key_start, param.key_end) == key)
}

/// A borrowed slice of the query string, by stored offsets.
fn slice(raw: &str, start: u16, end: u16) -> &str {
    raw.get(usize::from(start)..usize::from(end)).unwrap_or("")
}

/// A borrowed, allocation-free view over one request's query parameters.
///
/// Values are returned exactly as they appeared, still percent-encoded. Decoding is a separate,
/// once-only step performed by whoever needs the decoded value; decoding here would mean every
/// consumer either decodes again or works from a value that no longer matches what was signed.
#[derive(Clone, Copy, Debug)]
pub struct QueryView<'a> {
    raw: &'a str,
    index: &'a QueryIndex,
}

impl<'a> QueryView<'a> {
    /// Pairs a query string with its index.
    #[must_use]
    pub fn new(raw: &'a str, index: &'a QueryIndex) -> Self {
        Self { raw, index }
    }

    /// The query string as it arrived.
    #[must_use]
    pub fn as_str(&self) -> &'a str {
        self.raw
    }

    /// How many parameters are present.
    #[must_use]
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// Whether there are no parameters.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Whether the underlying index stayed off the heap. See [`QueryIndex::is_inline`].
    #[must_use]
    pub fn is_inline(&self) -> bool {
        self.index.is_inline()
    }

    /// The first value for a name, still percent-encoded.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&'a str> {
        self.iter().find(|(name, _)| *name == key).map(|(_, value)| value)
    }

    /// Whether a name is present.
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.iter().any(|(name, _)| name == key)
    }

    /// How many times a name appears.
    #[must_use]
    pub fn count(&self, key: &str) -> usize {
        self.iter().filter(|(name, _)| *name == key).count()
    }

    /// Every parameter, in arrival order.
    ///
    /// Arrival order is preserved because SigV4's canonical query string is built from it and
    /// because a re-ordered view would hide a repeated parameter behind a merge.
    pub fn iter(&self) -> impl Iterator<Item = (&'a str, &'a str)> {
        let raw = self.raw;
        self.index
            .params
            .iter()
            .map(move |param| (slice(raw, param.key_start, param.key_end), slice(raw, param.value_start, param.value_end)))
    }
}
