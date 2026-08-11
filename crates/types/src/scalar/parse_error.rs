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

//! The one parse failure type every scalar returns.
//!
//! Responsible for: carrying *what* failed to parse, *why*, and *which written rule* the input
//! violated. The rule reference is mandatory rather than decorative: a diagnostic that cannot be
//! traced back to an RFC section or an AWS document is a diagnostic nobody can act on, and the
//! conformance suite asserts on it.
//! NOT responsible for: HTTP status selection (that is `ErrorCode::default_status`) and error body
//! rendering (`rustfs-gateway-xml`). A `ParseError` never reaches a client as-is.
//! Upstream: none. Downstream: every module in `scalar`, and the P3 ingest pipeline, which maps a
//! `ParseError` to an `ErrorCode` at the point where it knows which field was being parsed.

use std::borrow::Cow;
use std::fmt;

/// Stable identifiers for the written rules the scalars enforce.
///
/// These are diagnostic strings, not URLs to be fetched. They exist so that a failure message can
/// be grepped back to the paragraph that motivated the check.
pub mod rules {
    /// RFC 9110 §8.8.3 — `entity-tag` ABNF, `W/` weakness prefix, opaque-tag.
    pub const RFC9110_ENTITY_TAG: &str = "rfc9110#section-8.8.3";
    /// RFC 9110 §13.1.1/§13.1.2 — `If-Match` strong comparison, `If-None-Match` weak comparison.
    pub const RFC9110_PRECONDITION: &str = "rfc9110#section-13.1.1";
    /// RFC 9110 §14.1 — `Range` syntax; an unsatisfiable *syntax* must be ignored, not rejected.
    pub const RFC9110_RANGE: &str = "rfc9110#section-14.1";
    /// RFC 9110 §5.6.7 — HTTP-date: IMF-fixdate on output, three formats accepted on input.
    pub const RFC9110_HTTP_DATE: &str = "rfc9110#section-5.6.7";
    /// ISO 8601 date-time as S3 spells it in XML bodies and `x-amz-*-date` headers.
    pub const ISO8601: &str = "iso8601";
    /// AWS bucket naming rules.
    pub const AWS_BUCKET_NAMING: &str = "aws:bucketnamingrules";
    /// AWS object key guidelines — UTF-8, 1..=1024 bytes, no normalisation.
    pub const AWS_OBJECT_KEY: &str = "aws:object-keys";
    /// AWS object integrity — algorithms, base64 wire form, composite `-N` suffix.
    pub const AWS_CHECKSUM: &str = "aws:checking-object-integrity";
    /// RFC 4648 §4 — base64 with the standard alphabet and mandatory padding.
    pub const RFC4648_BASE64: &str = "rfc4648#section-4";
}

/// A scalar failed to parse.
///
/// Deliberately cheap to construct and cheap to move: one `&'static str` subject, one borrowed or
/// owned reason, one `&'static str` rule reference. Nothing here is allocated on the happy path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    subject: &'static str,
    reason: Cow<'static, str>,
    rule: &'static str,
}

impl ParseError {
    /// Builds a parse error. `subject` names the type, `rule` is one of [`rules`].
    #[must_use]
    pub fn new(subject: &'static str, rule: &'static str, reason: impl Into<Cow<'static, str>>) -> Self {
        Self {
            subject,
            reason: reason.into(),
            rule,
        }
    }

    /// The type that refused the input, e.g. `"ETag"`.
    #[must_use]
    pub fn subject(&self) -> &'static str {
        self.subject
    }

    /// Why the input was refused, in one clause.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// The rule reference, one of the constants in [`rules`].
    #[must_use]
    pub fn rule(&self) -> &'static str {
        self.rule
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid {}: {} [rule: {}]", self.subject, self.reason, self.rule)
    }
}

impl std::error::Error for ParseError {}
