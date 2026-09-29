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

//! The RustFS-profile reading of a conditional date: legacy RustFS's one spelling, and its refusal
//! of every other (rustfs/backlog#1677, ruling R14).
//!
//! Responsible for: [`ServiceBuilder::refuse_unreadable_date_conditions`], the closed set of
//! operations and headers it covers ([`STRICT_DATE_CONDITION_HEADERS`]), and the refusal an
//! assembly under it answers before decode with, in legacy RustFS's code and sentence.
//! NOT responsible for: the grammar (`rustfs_gateway_core::codec::strict_date`), handing the read
//! instant to the handler (`rustfs_gateway_core::codec::value::date_condition_in`, reached through
//! the view `super::ViewPolicy` marks), or evaluating a condition (the backend).
//! Upstream: `crate::builder::ServiceBuilder`. Downstream: `super::ViewPolicy`, which the
//! service asks for the refusal on the accepted head, after authorization and before decode.
//!
//! # What legacy RustFS answers, and where
//!
//! Legacy RustFS decodes these eight members after it has verified the signature and before its
//! access check or handler runs (rustfs/rustfs@e870a6d25b routes every S3 request through that
//! decode; its handlers read the four date members only as decoded values). For each header:
//!
//! * two field lines are `400 InvalidRequest` `duplicate header: <name>`, whatever they hold;
//! * one empty field line is the header not sent;
//! * a value that is not visible ASCII, or that its one spelling does not read, is
//!   `400 InvalidArgument` `invalid header: <name>: <value>`, the value written as the `http`
//!   crate's debug form of a header value (quoted, `"` as `\"`, any other byte outside visible
//!   ASCII and tab as `\x` and lowercase hex);
//! * the first header in its member order is the one answered: the modified-since form before the
//!   unmodified-since form.
//!
//! Observed on a legacy RustFS build for all four operations: `Invalid Date` (minio-js's
//! functional suite sends it), an RFC 850 and an asctime date are `400 InvalidArgument`; `+1994`
//! as the year, and an empty value, are served.
//!
//! The core default stays RFC 9110's: an unreadable date condition is ignored (`q-cond-0050`,
//! `q-copy-source-date-0159`).

use http::HeaderValue;
use rustfs_gateway_core::HandlerError;
use rustfs_gateway_core::codec::strict_http_date;
use rustfs_gateway_http::HeaderView;
use rustfs_gateway_types::ErrorCode;

use crate::builder::ServiceBuilder;

/// The date-condition headers the RustFS profile reads strictly, per operation, in the order legacy
/// RustFS decodes them; and no others.
pub const STRICT_DATE_CONDITION_HEADERS: [(&str, &str); 8] = [
    ("CopyObject", "x-amz-copy-source-if-modified-since"),
    ("CopyObject", "x-amz-copy-source-if-unmodified-since"),
    ("GetObject", "if-modified-since"),
    ("GetObject", "if-unmodified-since"),
    ("HeadObject", "if-modified-since"),
    ("HeadObject", "if-unmodified-since"),
    ("UploadPartCopy", "x-amz-copy-source-if-modified-since"),
    ("UploadPartCopy", "x-amz-copy-source-if-unmodified-since"),
];

/// Whether `operation` carries a date condition the RustFS profile reads strictly.
pub(crate) fn covers(operation: &str) -> bool {
    STRICT_DATE_CONDITION_HEADERS.iter().any(|(covered, _)| *covered == operation)
}

/// The refusal legacy RustFS answers `operation`'s date conditions with, if any.
///
/// `headers` is the accepted head the codec binds from.
pub(crate) fn refusal(operation: &str, headers: &HeaderView<'_>) -> Option<HandlerError> {
    STRICT_DATE_CONDITION_HEADERS
        .iter()
        .filter(|(covered, _)| *covered == operation)
        .find_map(|(_, name)| refusal_of(name, headers))
}

fn refusal_of(name: &'static str, headers: &HeaderView<'_>) -> Option<HandlerError> {
    let mut lines = headers
        .iter_raw()
        .filter(|(candidate, _)| candidate.as_str() == name)
        .map(|(_, value)| value);
    let value = lines.next()?;
    if lines.next().is_some() {
        return Some(HandlerError::new(ErrorCode::INVALID_REQUEST, format!("duplicate header: {name}")));
    }
    if value.is_empty() {
        return None;
    }
    let readable = value.to_str().ok().and_then(strict_http_date).is_some();
    // Legacy-compat (rustfs/backlog#2684): legacy RustFS refuses a date condition it cannot read,
    // and reads only one spelling, where RFC 9110 §13.1.3 and §13.1.4 say to ignore a condition
    // whose date is not valid: minio-js's `Invalid Date` is a 400 against it, and so is every
    // RFC 850 and asctime date a client may send. It also answers a copy-source date it does read
    // by never evaluating it (its copy handlers read no copy-source date member). Kept so no client
    // RustFS serves sees a different answer; the intended future behaviour is the core default
    // (`q-cond-0050`, `q-copy-source-date-0159`) and a backend that evaluates the copy-source dates.
    (!readable).then(|| invalid(name, value))
}

/// Legacy RustFS's sentence for a header value it could not read.
fn invalid(name: &str, value: &HeaderValue) -> HandlerError {
    HandlerError::new(ErrorCode::INVALID_ARGUMENT, format!("invalid header: {name}: {value:?}"))
}

impl ServiceBuilder {
    /// Reads the date conditions of exactly [`STRICT_DATE_CONDITION_HEADERS`] as legacy RustFS
    /// does: in its one HTTP-date spelling, refusing a value it cannot read or a header sent twice
    /// with its code and sentence (rustfs/backlog#1677, R14).
    ///
    /// Off by default: the core reads RFC 9110's three HTTP-date forms and ignores a condition it
    /// cannot read (`q-cond-0050`, `q-copy-source-date-0159`). The RustFS profile turns it on so a
    /// client sees the answer RustFS gives today: `400 InvalidArgument` for `Invalid Date` or an
    /// RFC 850 date, `400 InvalidRequest` for a repeated header, and a condition such as a signed
    /// `+1994` year read as the instant RustFS reads. The refusal is answered after authorization
    /// and before decode, which is where legacy RustFS answers it.
    #[must_use]
    pub fn refuse_unreadable_date_conditions(mut self) -> Self {
        self.view_policy.strict_date_conditions = true;
        self
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)] // Test code: fixed heads.
mod tests {
    use super::*;

    fn answer(operation: &str, lines: &[(&'static str, &[u8])]) -> Option<(String, String)> {
        let mut map = http::HeaderMap::new();
        for (name, value) in lines {
            map.append(*name, HeaderValue::from_bytes(value).expect("a representable header value"));
        }
        refusal(operation, &HeaderView::new(&map)).map(|error| (error.code().as_str().to_owned(), error.message().to_owned()))
    }

    const DATE: &[u8] = b"Sun, 06 Nov 1994 08:49:37 GMT";

    #[test]
    fn a_readable_absent_or_empty_condition_is_not_refused() {
        for operation in ["CopyObject", "UploadPartCopy", "GetObject", "HeadObject"] {
            assert_eq!(answer(operation, &[]), None, "{operation}");
        }
        assert_eq!(answer("CopyObject", &[("x-amz-copy-source-if-modified-since", DATE)]), None);
        assert_eq!(
            answer(
                "CopyObject",
                &[("x-amz-copy-source-if-unmodified-since", b"Sun, 06 Nov +1994 08:49:37 GMT")]
            ),
            None
        );
        assert_eq!(answer("GetObject", &[("if-modified-since", b"")]), None);
    }

    #[test]
    fn n_an_unreadable_condition_is_invalid_argument_quoting_the_value() {
        assert_eq!(
            answer("CopyObject", &[("x-amz-copy-source-if-modified-since", b"Invalid Date")]),
            Some((
                "InvalidArgument".to_owned(),
                "invalid header: x-amz-copy-source-if-modified-since: \"Invalid Date\"".to_owned()
            ))
        );
        assert_eq!(
            answer("HeadObject", &[("if-unmodified-since", b"Sunday, 06-Nov-94 08:49:37 GMT")]),
            Some((
                "InvalidArgument".to_owned(),
                "invalid header: if-unmodified-since: \"Sunday, 06-Nov-94 08:49:37 GMT\"".to_owned()
            ))
        );
    }

    #[test]
    fn n_the_quoted_value_escapes_quotes_and_bytes_outside_visible_ascii() {
        assert_eq!(
            answer("GetObject", &[("if-modified-since", b"say \"hi\"")]).map(|(_, message)| message),
            Some("invalid header: if-modified-since: \"say \\\"hi\\\"\"".to_owned())
        );
        assert_eq!(
            answer("GetObject", &[("if-modified-since", "Sun, 06 Nov 1994 08:49:37 GMT\u{e9}".as_bytes())])
                .map(|(_, message)| message),
            Some("invalid header: if-modified-since: \"Sun, 06 Nov 1994 08:49:37 GMT\\xc3\\xa9\"".to_owned())
        );
    }

    #[test]
    fn n_a_repeated_condition_is_invalid_request_whatever_it_holds() {
        for lines in [
            [
                ("x-amz-copy-source-if-modified-since", DATE),
                ("x-amz-copy-source-if-modified-since", DATE),
            ],
            [
                ("x-amz-copy-source-if-modified-since", b""),
                ("x-amz-copy-source-if-modified-since", b""),
            ],
        ] {
            assert_eq!(
                answer("UploadPartCopy", &lines),
                Some((
                    "InvalidRequest".to_owned(),
                    "duplicate header: x-amz-copy-source-if-modified-since".to_owned()
                ))
            );
        }
    }

    #[test]
    fn n_the_modified_since_form_is_answered_first() {
        let lines = [
            ("if-unmodified-since", b"garbage".as_slice()),
            ("if-modified-since", b"also garbage".as_slice()),
        ];
        assert_eq!(
            answer("GetObject", &lines).map(|(_, message)| message),
            Some("invalid header: if-modified-since: \"also garbage\"".to_owned())
        );
    }

    #[test]
    fn n_only_the_covered_operations_and_headers_are_read() {
        assert_eq!(answer("PutObject", &[("if-modified-since", b"garbage")]), None);
        assert_eq!(answer("CopyObject", &[("if-modified-since", b"garbage")]), None);
        assert_eq!(answer("GetObject", &[("x-amz-copy-source-if-modified-since", b"garbage")]), None);
        assert!(covers("HeadObject") && covers("UploadPartCopy"));
        assert!(!covers("PutObject") && !covers("DeleteObject"));
    }
}
