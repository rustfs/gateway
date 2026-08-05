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
//! whole object, clamping a range that runs past the end, and computing the `Content-Range` value
//! for both the satisfied and the unsatisfiable case.
//! NOT responsible for: reading bytes, choosing a status code (the caller maps
//! [`RangeOutcome`] to 200/206/416), and the `Range` + `partNumber` conflict, which is a
//! cross-field rule the operation layer enforces.
//! Upstream: [`super::parse_error`]. Downstream: `GetObject`, `HeadObject`, `UploadPartCopy`.
//!
//! # Named `ByteRange`, not `Range`
//!
//! The IR calls this type `Range`. In Rust that name collides with `std::ops::Range` at every
//! import site, and a mistaken `use` of the wrong one compiles surprisingly far. The IR name maps
//! to this type; the Rust spelling is unambiguous on purpose.

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
            _ => RangeOutcome::Full,
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
                if first > last_byte {
                    return RangeOutcome::Unsatisfiable { actual: object_len };
                }
                RangeOutcome::Satisfied {
                    start: first,
                    end_inclusive: last.min(last_byte),
                }
            }
            Self::From { first } => {
                if first > last_byte {
                    return RangeOutcome::Unsatisfiable { actual: object_len };
                }
                RangeOutcome::Satisfied {
                    start: first,
                    end_inclusive: last_byte,
                }
            }
            Self::Suffix { length } => {
                if length == 0 {
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
