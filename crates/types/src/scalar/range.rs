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

//! The `Range` request header: parsing it, and resolving it against a known object length.
//!
//! Responsible for: the three byte-range forms, the RFC 9110 rule that a *syntactically* broken
//! range is ignored rather than rejected, the S3 behaviour that a multi-range request yields the
//! whole object, clamping a range that runs past the end, computing the `Content-Range` value for
//! both the satisfied and the unsatisfiable case, and [`RangeSpec`] — the parse that keeps the
//! bytes it was parsed from.
//! NOT responsible for: reading bytes, choosing a status code (the caller maps
//! [`RangeOutcome`] to 200/206/416), and the `Range` + `partNumber` conflict, which is a
//! cross-field rule the operation layer enforces.
//! Upstream: [`super::parse_error`]. Downstream: `GetObject`, `HeadObject`, `UploadPartCopy`.
//!
//! # Named `ByteRange`, not `Range`
//!
//! The IR calls this type `Range`. In Rust that name collides with `std::ops::Range` at every
//! import site, and a mistaken `use` of the wrong one compiles surprisingly far. The IR name maps
//! to [`RangeSpec`]; the Rust spelling is unambiguous on purpose.
//!
//! # Why the binding is [`RangeSpec`] and not [`ByteRange`]
//!
//! Because a `416` has to echo the range **as the client wrote it**, and a parse cannot be asked
//! for that. `bytes=0-` and `bytes=0-99999` are one [`ByteRange`] against a hundred-byte object;
//! re-spelling either one out of the resolved value is a guess about the client's own bytes, and a
//! guess that agrees with our parser and with nothing else. So the third shape: the parse carries
//! the slice it came from. Neither half is optional and neither is derived from the other —
//! [`RangeSpec::as_str`] is what arrived, [`RangeSpec::resolve`] is what it means.
//!
//! The absence is now spelled once. `Option<RangeSpec>` is `None` exactly when there was no
//! `Range` header; a header that arrived and could not be honoured is `Some`, and resolves to
//! [`RangeOutcome::Full`]. The previous binding collapsed those two into `None`, which is how a
//! backend lost the text `<RangeRequested>` needs — and, with it, the ability to say anything at
//! all about a range it was sent.

use std::fmt::Write as _;

/// One byte range, exactly as the header expressed it — not yet resolved against an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ByteRange {
    /// `bytes=first-last`, both inclusive.
    FromTo {
        /// First byte offset, inclusive.
        first: u64,
        /// Last byte offset, inclusive.
        last: u64,
    },
    /// `bytes=first-`, to the end of the object.
    From {
        /// First byte offset, inclusive.
        first: u64,
    },
    /// `bytes=-length`, the last `length` bytes.
    Suffix {
        /// Number of trailing bytes requested.
        length: u64,
    },
}

/// What a `Range` header amounted to.
///
/// Three of the four variants mean "serve the whole object": absent, unparseable, and multi-range.
/// Keeping them apart rather than collapsing them into `None` is what lets an observer report
/// *why* a range request was not honoured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RangeParse {
    /// No `Range` header was sent.
    Absent,
    /// The header was present but syntactically invalid, or used a unit other than `bytes`.
    ///
    /// RFC 9110 requires an unparseable `Range` to be ignored, so this is a 200 with the whole
    /// object — not a 400. Rejecting it breaks clients that send a range their proxy rewrote.
    Ignore,
    /// The header asked for more than one range.
    ///
    /// S3 does not implement `multipart/byteranges`; it answers with the entire object and a 200.
    /// A client that expects a multipart body gets one part's worth of nothing, so this case is
    /// modelled explicitly rather than being lumped in with `Ignore`.
    MultiRange,
    /// Exactly one well-formed range.
    One(ByteRange),
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "unused variants are selected by the range contract mutation gate")]
enum MultiRangePolicy {
    ServeWhole,
    Reject,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "unused variants are selected by the range contract mutation gate")]
enum ExplicitEndOverflowPolicy {
    Clamp,
    Unsatisfiable,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "unused variants are selected by the range contract mutation gate")]
enum SuffixRangePolicy {
    Supported,
    Ignore,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "unused variants are selected by the range contract mutation gate")]
enum OversizeSuffixPolicy {
    ClampToWholePartial,
    Unsatisfiable,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "unused variants are selected by the range contract mutation gate")]
enum InvalidRangePolicy {
    ServeWhole,
    Reject,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "unused variants are selected by the range contract mutation gate")]
enum RangeStartBoundPolicy {
    AtOrBeyondUnsatisfiable,
    PastEndOnly,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "unused variants are selected by the range contract mutation gate")]
enum OpenEndedRangePolicy {
    ThroughLast,
    EmptyAtLast,
}

include!("../../../../generated/range_contracts.rs");

/// The result of resolving a range against a known object length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RangeOutcome {
    /// Serve the whole object with 200.
    Full,
    /// Serve `start..=end_inclusive` with 206.
    Satisfied {
        /// First byte to send, inclusive.
        start: u64,
        /// Last byte to send, inclusive.
        end_inclusive: u64,
    },
    /// Serve 416 with `Content-Range: bytes */actual`.
    Unsatisfiable {
        /// The object's real length, which the error body reports.
        actual: u64,
    },
}

impl RangeOutcome {
    /// The number of bytes to send, which is `end - start + 1` for a satisfied range.
    #[must_use]
    pub fn content_length(&self, object_len: u64) -> u64 {
        match self {
            Self::Full => object_len,
            Self::Satisfied { start, end_inclusive } => end_inclusive - start + 1,
            Self::Unsatisfiable { .. } => 0,
        }
    }

    /// The `Content-Range` header value, or `None` when the response carries no such header.
    #[must_use]
    pub fn content_range(&self, object_len: u64) -> Option<String> {
        let mut out = String::with_capacity(32);
        match self {
            Self::Full => None,
            Self::Satisfied { start, end_inclusive } => {
                let _ = write!(out, "bytes {start}-{end_inclusive}/{object_len}");
                Some(out)
            }
            Self::Unsatisfiable { actual } => {
                let _ = write!(out, "bytes */{actual}");
                Some(out)
            }
        }
    }
}

/// A `Range` header, parsed, holding on to the text it was parsed from.
///
/// This is the type a `Range` binding decodes to, and it exists because two different consumers
/// need two different things from one header and neither can produce the other's. The operation
/// needs the resolved window; the `416` document needs `<RangeRequested>`, which S3 defines as the
/// header **as it arrived**. A parse alone cannot answer the second — see the module documentation
/// for the pair of spellings that prove it — so the parse keeps its source rather than a caller
/// reconstructing one.
///
/// The source is a `Box<str>` and not a borrow: the header view it came from does not outlive the
/// decoder, and a lifetime here would put one on every generated input struct that binds a range.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RangeSpec {
    /// The header value exactly as it arrived, whitespace and all.
    raw: Box<str>,
    /// What it parsed to.
    parse: RangeParse,
}

impl RangeSpec {
    /// Parses a `Range` header value, keeping the value.
    ///
    /// Never fails, for the same reason [`RangeParse::parse`] never fails: RFC 9110 requires an
    /// uninterpretable `Range` to be ignored and the whole representation served. What is new is
    /// that "ignored" no longer means "forgotten" — the text survives, so a response that has to
    /// name it can.
    #[must_use]
    pub fn new(header: &str) -> Self {
        Self {
            raw: header.into(),
            parse: RangeParse::parse(header),
        }
    }

    /// The header exactly as it arrived.
    ///
    /// This is the value `<RangeRequested>` carries. It is returned verbatim rather than trimmed:
    /// the element reports what the client sent, and a server that tidies it up first is reporting
    /// its own reading back as though it were the request.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// What the header parsed to, before it meets an object.
    #[must_use]
    pub const fn parsed(&self) -> RangeParse {
        self.parse
    }

    /// Resolves the header against the object's length.
    ///
    /// Everything that is not exactly one range resolves to [`RangeOutcome::Full`], so an ignored
    /// `Range` and a multi-range request both serve the whole object without the caller writing
    /// either rule.
    #[must_use]
    pub fn resolve(&self, object_len: u64) -> RangeOutcome {
        self.parse.resolve(object_len)
    }
}

impl RangeParse {
    /// Parses a `Range` header value. Never fails: everything unusable becomes
    /// [`RangeParse::Ignore`].
    #[must_use]
    pub fn parse(header: &str) -> Self {
        let value = header.trim();
        let Some(set) = value.strip_prefix("bytes=") else {
            return Self::Ignore;
        };
        let mut ranges = set.split(',');
        let Some(first) = ranges.next() else {
            return Self::Ignore;
        };
        if ranges.next().is_some() {
            // Confirm the remaining specs are at least well formed before declaring a multi-range
            // request; `bytes=0-1,,` is malformed, not a multi-range.
            let all_valid = set.split(',').all(|spec| parse_one(spec).is_some());
            return if all_valid { Self::MultiRange } else { Self::Ignore };
        }
        match parse_one(first) {
            Some(range) => Self::One(range),
            None => Self::Ignore,
        }
    }

    /// Parses an optional header, so a caller can hand over `headers.get("range")` directly.
    #[must_use]
    pub fn parse_optional(header: Option<&str>) -> Self {
        match header {
            Some(value) => Self::parse(value),
            None => Self::Absent,
        }
    }

    /// Resolves the parse result against the object's length.
    ///
    /// Everything that is not exactly one range resolves to [`RangeOutcome::Full`], which is what
    /// makes "ignore a broken Range" and "answer a multi-range with the whole object" fall out of
    /// the type rather than out of a comment.
    #[must_use]
    pub fn resolve(&self, object_len: u64) -> RangeOutcome {
        match self {
            Self::One(range) => range.resolve(object_len),
            Self::MultiRange => match MULTI_RANGE_POLICY {
                MultiRangePolicy::ServeWhole => RangeOutcome::Full,
                MultiRangePolicy::Reject => RangeOutcome::Unsatisfiable { actual: object_len },
            },
            Self::Ignore => match INVALID_RANGE_POLICY {
                InvalidRangePolicy::ServeWhole => RangeOutcome::Full,
                InvalidRangePolicy::Reject => RangeOutcome::Unsatisfiable { actual: object_len },
            },
            Self::Absent => RangeOutcome::Full,
        }
    }
}

impl ByteRange {
    /// Resolves this range against the object's length.
    ///
    /// A range whose end runs past the object is clamped to the last byte and answered with 206;
    /// only a range that starts past the end, or a zero-length suffix, is unsatisfiable. Rejecting
    /// an overlong range instead of clamping it is the classic way to break resumable downloads,
    /// which routinely ask for more than is there.
    #[must_use]
    pub fn resolve(&self, object_len: u64) -> RangeOutcome {
        if object_len == 0 {
            return RangeOutcome::Unsatisfiable { actual: 0 };
        }
        let last_byte = object_len - 1;
        match *self {
            Self::FromTo { first, last } => {
                let starts_outside = match RANGE_START_BOUND {
                    RangeStartBoundPolicy::AtOrBeyondUnsatisfiable => first >= object_len,
                    RangeStartBoundPolicy::PastEndOnly => first > object_len,
                };
                if starts_outside {
                    return RangeOutcome::Unsatisfiable { actual: object_len };
                }
                if last > last_byte && matches!(EXPLICIT_END_OVERFLOW_POLICY, ExplicitEndOverflowPolicy::Unsatisfiable) {
                    return RangeOutcome::Unsatisfiable { actual: object_len };
                }
                RangeOutcome::Satisfied {
                    start: first,
                    end_inclusive: last.min(last_byte),
                }
            }
            Self::From { first } => {
                let starts_outside = match RANGE_START_BOUND {
                    RangeStartBoundPolicy::AtOrBeyondUnsatisfiable => first >= object_len,
                    RangeStartBoundPolicy::PastEndOnly => first > object_len,
                };
                if starts_outside {
                    return RangeOutcome::Unsatisfiable { actual: object_len };
                }
                RangeOutcome::Satisfied {
                    start: first,
                    end_inclusive: match OPEN_ENDED_RANGE_POLICY {
                        OpenEndedRangePolicy::ThroughLast => last_byte,
                        OpenEndedRangePolicy::EmptyAtLast => first.saturating_sub(1),
                    },
                }
            }
            Self::Suffix { length } => {
                if length == 0 {
                    return RangeOutcome::Unsatisfiable { actual: object_len };
                }
                if length > object_len && matches!(OVERSIZE_SUFFIX_POLICY, OversizeSuffixPolicy::Unsatisfiable) {
                    return RangeOutcome::Unsatisfiable { actual: object_len };
                }
                RangeOutcome::Satisfied {
                    start: object_len.saturating_sub(length),
                    end_inclusive: last_byte,
                }
            }
        }
    }
}

/// Parses one `first-last`, `first-` or `-suffix` spec.
fn parse_one(spec: &str) -> Option<ByteRange> {
    let spec = spec.trim();
    let (first, last) = spec.split_once('-')?;
    let first = first.trim_end();
    let last = last.trim_start();

    if first.is_empty() {
        if matches!(SUFFIX_RANGE_POLICY, SuffixRangePolicy::Ignore) {
            return None;
        }
        let length = parse_u64(last)?;
        return Some(ByteRange::Suffix { length });
    }
    let first = parse_u64(first)?;
    if last.is_empty() {
        return Some(ByteRange::From { first });
    }
    let last = parse_u64(last)?;
    // A descending range is syntactically valid but semantically empty; RFC 9110 says to ignore
    // it, which is why this returns None rather than an unsatisfiable range.
    if last < first {
        return None;
    }
    Some(ByteRange::FromTo { first, last })
}

fn parse_u64(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}
