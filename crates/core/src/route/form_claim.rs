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

//! A dialect's form claims: a `POST` of one exact path whose `Content-Type` names
//! `application/x-www-form-urlencoded`, taken away from S3 routing on every host (ADR-0041).
//!
//! Responsible for: [`FormClaim`], its grammar ([`FormClaimRejection`]), the one test of whether a
//! request is inside it, and how an overlay records it.
//! NOT responsible for: the table that asks form claims before path claims and the S3 table
//! (`claimed`), whether a dialect may install one (`crate::dialect`), or what the operation behind
//! it does with the body.
//! Upstream: `selector`'s request parts. Downstream: `claimed`, `crate::dialect`.
//!
//! # Why a claim of its own rather than a path claim or an S3 row
//!
//! A path claim is a prefix of at least two segments, so it can never cover `/`. RustFS's STS
//! endpoint is `POST /` with a form body on any host, whatever the host's bucket label and whatever
//! the query: its router matches the request before its S3 path parser runs (rustfs/rustfs
//! `rustfs/src/server/layer.rs` `is_sts_query_request`). An S3-table row cannot express that
//! either: under legacy RustFS's operation selection a virtual-hosted `POST /?delete` is
//! `DeleteObjects` before any added row is asked, and a host naming an invalid bucket is refused
//! before routing. A form claim is asked first, on every host, exactly as that router asks.
//!
//! # What a form claim covers
//!
//! A `POST` whose raw path is the claim's path byte for byte, and whose first `Content-Type` value
//! is visible ASCII text naming `application/x-www-form-urlencoded`: the part before the first `;`,
//! with the surrounding spaces and tabs trimmed, compared ASCII case-insensitively. Parameters such
//! as `charset` are ignored; a longer media type such as `application/x-www-form-urlencoded-x` is
//! not covered. Host, endpoint face, query and every other header are not read.
//!
//! The media type is fixed and the path is `/` or at least two segments: S3 never sends a form body
//! (its browser upload is `multipart/form-data`), and a one-segment path is a bucket, so a claim can
//! take no S3 request that names its own media type or a bucket's own subresource.

use core::fmt;

use http::Method;
use http::header::CONTENT_TYPE;

use super::selector::RouteRequestParts;

/// The one media type a form claim covers.
const FORM_MEDIA_TYPE: &str = "application/x-www-form-urlencoded";

/// Why a [`FormClaim`] was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormClaimRejection {
    /// The path does not start with `/`.
    NotAbsolute,
    /// The path ends with `/` other than the root itself.
    TrailingSlash,
    /// Two adjacent separators.
    EmptySegment,
    /// A `.` or `..` segment.
    DotSegment,
    /// A path byte outside RFC 3986's unreserved set.
    ForbiddenCharacter,
    /// One segment: the bucket position, which only S3 routes.
    ShadowsABucket,
    /// No reason written.
    NoReason,
    /// No evidence, or a blank evidence entry.
    NoEvidence,
}

impl FormClaimRejection {
    /// Why, in one sentence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAbsolute => "a form claim names an absolute path, starting with '/'",
            Self::TrailingSlash => "a form claim's path does not end with '/' unless it is the root",
            Self::EmptySegment => "a form claim's path has no empty segment",
            Self::DotSegment => "a form claim's path has no '.' or '..' segment",
            Self::ForbiddenCharacter => {
                "a form claim's path spells only unreserved characters: letters, digits, '-', '.', '_', '~'"
            }
            Self::ShadowsABucket => "a form claim's path is '/' or at least two segments; one segment is a bucket",
            Self::NoReason => "a form claim says why the dialect owns these requests",
            Self::NoEvidence => "a form claim carries at least one source, and no blank one",
        }
    }
}

impl fmt::Display for FormClaimRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A `POST` of one exact path with a form body, which a dialect takes away from S3 routing on every
/// host (ADR-0041).
///
/// Reviewed data, like [`super::PathClaim`]: the dialect's overlay row records it, and the start-up
/// posture report lists every installed one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FormClaim {
    /// The raw path, compared byte for byte: `/`, or `/segment/segment[/…]` with no trailing `/`.
    pub path: &'static str,
    /// Why this dialect owns these requests. Written by a human; read by whoever changes it.
    pub reason: &'static str,
    /// Where the claim comes from: one URL per source. Must be non-empty.
    pub evidence: &'static [&'static str],
}

impl FormClaim {
    /// Why this claim cannot be installed, or `None` when it can.
    #[must_use]
    pub fn rejection(&self) -> Option<FormClaimRejection> {
        if let Some(rejection) = path_rejection(self.path) {
            return Some(rejection);
        }
        if self.reason.trim().is_empty() {
            return Some(FormClaimRejection::NoReason);
        }
        if self.evidence.is_empty() || self.evidence.iter().any(|source| source.trim().is_empty()) {
            return Some(FormClaimRejection::NoEvidence);
        }
        None
    }

    /// Whether the request is inside this claim: a `POST` of exactly this raw path whose first
    /// `Content-Type` value names `application/x-www-form-urlencoded`. Holds nothing, allocates
    /// nothing.
    #[must_use]
    pub fn covers(&self, request: &RouteRequestParts<'_>) -> bool {
        self.covers_head(request.method, request.path, request.headers.get_bytes(&CONTENT_TYPE))
    }

    /// [`FormClaim::covers`] over the three facts it reads, for a caller holding a request head
    /// rather than routing parts: the method, the raw path and the first `Content-Type` value.
    #[must_use]
    pub fn covers_head(&self, method: &Method, raw_path: &str, content_type: Option<&[u8]>) -> bool {
        *method == Method::POST && raw_path == self.path && content_type.is_some_and(names_form)
    }

    /// Whether one request could be inside both claims: the same path.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.path == other.path
    }

    /// The claim as an overlay row records it: `FormClaim(POST "/")`.
    #[must_use]
    pub fn render(&self) -> String {
        format!("FormClaim(POST {:?})", self.path)
    }
}

/// Why `path` cannot be a form claim's path, or `None`.
fn path_rejection(path: &str) -> Option<FormClaimRejection> {
    let Some(rest) = path.strip_prefix('/') else {
        return Some(FormClaimRejection::NotAbsolute);
    };
    if rest.is_empty() {
        return None;
    }
    if rest.ends_with('/') {
        return Some(FormClaimRejection::TrailingSlash);
    }
    for segment in rest.split('/') {
        if segment.is_empty() {
            return Some(FormClaimRejection::EmptySegment);
        }
        if segment == "." || segment == ".." {
            return Some(FormClaimRejection::DotSegment);
        }
        if !segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
        {
            return Some(FormClaimRejection::ForbiddenCharacter);
        }
    }
    if !rest.contains('/') {
        return Some(FormClaimRejection::ShadowsABucket);
    }
    None
}

/// Whether a `Content-Type` value names [`FORM_MEDIA_TYPE`], as legacy RustFS reads one: the value
/// must be visible ASCII text (a space or a tab allowed), and its part before the first `;`,
/// trimmed, equals the media type ASCII case-insensitively.
fn names_form(value: &[u8]) -> bool {
    if !value.iter().all(|&byte| byte == b'\t' || (b' '..=b'~').contains(&byte)) {
        return false;
    }
    let essence = value.split(|&byte| byte == b';').next().unwrap_or_default();
    essence.trim_ascii().eq_ignore_ascii_case(FORM_MEDIA_TYPE.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Positive and negative — the value test is legacy RustFS's: the first `;` ends the media type,
    /// spaces and tabs around it are ignored, case is not, and a value that is not visible ASCII
    /// names nothing.
    #[test]
    fn a_value_names_the_form_type_as_legacy_rustfs_reads_it() {
        for value in [
            &b"application/x-www-form-urlencoded"[..],
            b"APPLICATION/X-WWW-FORM-URLENCODED",
            b"application/x-www-form-urlencoded; charset=utf-8",
            b"application/x-www-form-urlencoded ;charset=utf-8",
            b" \tapplication/x-www-form-urlencoded\t ",
            b"application/x-www-form-urlencoded;",
        ] {
            assert!(names_form(value), "{}", String::from_utf8_lossy(value));
        }
        for value in [
            &b"application/x-www-form-urlencoded-x"[..],
            b"application/x-www-form-urlencodedx; charset=utf-8",
            b"application/x-www-form",
            b"multipart/form-data; boundary=x",
            b"",
            b";application/x-www-form-urlencoded",
            b"application/x-www-form-urlencoded; charset=\x80",
            b"application/x-www-form-urlencoded\x7f",
            b"application/x-www-form-urlencoded\x0b",
        ] {
            assert!(!names_form(value), "{}", String::from_utf8_lossy(value));
        }
    }
}
