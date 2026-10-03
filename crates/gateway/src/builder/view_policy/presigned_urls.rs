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

//! The RustFS-profile switch that answers a SigV4 presigned URL legacy RustFS refuses before its
//! credential lookup with legacy RustFS's refusal, in its order (rustfs/gateway#1130).
//!
//! Responsible for: [`ServiceBuilder::answer_presigned_urls_as_legacy_rustfs`] and
//! [`PresignedRefusals::refusal`], which the pipeline asks before the security floor, beside the
//! header-signature refusals.
//! NOT responsible for: verifying anything. Nothing here derives a key, hashes a request or
//! compares a signature; a presigned URL this lets through is admitted, verified and served exactly
//! as it is without the switch. Which requests are presigned at all is the floor's
//! (`SecurityFloor::recognize_signatures_as_legacy_rustfs`), and SigV2's `Signature` URLs are not
//! read here.
//! Upstream: `super::ViewPolicy`. Downstream: `crate::service`.
//!
//! # What legacy RustFS does
//!
//! For a request whose query carries `X-Amz-Signature` (and no SigV2 `Signature`, no browser
//! form), the legacy stack reads the URL and, before it looks the access key up, refuses in this
//! order:
//!
//! 1. a URL that does not read — `X-Amz-Algorithm`, `X-Amz-Credential`, `X-Amz-Date`,
//!    `X-Amz-Expires`, `X-Amz-SignedHeaders` and `X-Amz-Signature` each present once, the credential
//!    in its grammar, the date `YYYYMMDDTHHMMSSZ` digits, the lifetime a whole number of seconds up
//!    to seven days, the list ASCII, the signature 64 lowercase hex digits: `400
//!    AuthorizationQueryParametersError` "The authorization query parameters that you provided are
//!    not valid.";
//! 2. an algorithm other than `AWS4-HMAC-SHA256`: `501 NotImplemented` "X-Amz-Algorithm other than
//!    AWS4-HMAC-SHA256 is not implemented";
//! 3. a scope date other than the `X-Amz-Date` day: `403 SignatureDoesNotMatch` "credential scope
//!    date does not match x-amz-date";
//! 4. an `x-amz-content-sha256` it cannot read: `403 SignatureDoesNotMatch` "invalid header:
//!    x-amz-content-sha256"; one declaring a streaming payload: `501 NotImplemented` "streaming
//!    payload for presigned URLs is not implemented";
//! 5. a date that names no instant (hour 24, second 60): `400 InvalidRequest` "invalid amz date";
//! 6. a date more than fifteen minutes ahead of its clock: `403 RequestTimeTooSkewed` "request date
//!    is later than server time too much";
//! 7. a URL older than its lifetime: `403 AccessDenied` "Request has expired" (read in whole
//!    seconds here: a lifetime ending within the current second is past, as legacy RustFS's
//!    sub-second clock almost always finds it).
//!
//! Observed against a legacy RustFS build (`RUSTFS_S3_STACK=legacy`, rustfs/rustfs `e870a6d25b`)
//! over raw sockets. The gateway refused the same URLs: the first two as a credential it cannot
//! read (`403 InvalidAccessKeyId`) or with its own sentence, the rest with its own sentences.

use http::Method;
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use rustfs_gateway_core::{HandlerError, ResponseKind};
use rustfs_gateway_sig::{AuthError, RawQuery, X_AMZ_SIGNATURE};
use rustfs_gateway_types::ErrorCode;

use super::super::ServiceBuilder;
use super::header_signatures::{SignedHead, is_amz_date_shape, is_malformed_payload, names_an_instant, unique_value};
use crate::ext::legacy_credential::read_scope;
use crate::render::{S3Error, from_handler};

/// The longest lifetime legacy RustFS reads, in seconds: seven days.
const MAX_EXPIRES: u64 = 7 * 24 * 60 * 60;

/// How far ahead of its clock legacy RustFS accepts a presigned URL's date, in seconds.
const MAX_FUTURE_SKEW: i64 = 15 * 60;

/// Whether an assembly answers a presigned URL's pre-lookup refusals as legacy RustFS does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum PresignedRefusals {
    /// The security floor and the authenticator answer them, as for every request.
    #[default]
    Gateway,
    /// Legacy RustFS's refusals answer them first, in its order.
    LegacyRustfs,
}

impl PresignedRefusals {
    /// Legacy RustFS's refusal of `head` before its credential lookup, when it refuses one and this
    /// assembly answers with it; `None` leaves the request to the floor and the authenticator.
    pub(crate) fn refusal(self, head: &SignedHead<'_>, response: ResponseKind, body_owed: bool) -> Option<S3Error> {
        if self == Self::Gateway {
            return None;
        }
        let (code, sentence) = legacy_refusal(head)?;
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS answers these before it has
        // authenticated anything, telling the holder of a URL which of its parameters was wrong.
        // The intended future behaviour is the security floor's own answers.
        Some(from_handler(
            HandlerError::new(code, sentence),
            response,
            crate::close::after_auth_failure(&AuthError::AuthorizationQueryParametersError, body_owed),
        ))
    }
}

/// The code and sentence of legacy RustFS's first pre-lookup refusal of the presigned URL `head`
/// carries, if it carries one and legacy RustFS refuses it.
fn legacy_refusal(head: &SignedHead<'_>) -> Option<(ErrorCode, &'static str)> {
    let query = RawQuery::new(head.query);
    let is_form = *head.method == Method::POST
        && head
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.trim_start().to_ascii_lowercase().starts_with("multipart/form-data"));
    let signed_url = query.decoded_value(X_AMZ_SIGNATURE).is_ok_and(|value| value.is_some());
    let sigv2_url = query.decoded_value("Signature").is_ok_and(|value| value.is_some());
    if is_form || !signed_url || sigv2_url || head.headers.contains_key(AUTHORIZATION) {
        return None;
    }
    let unique = |name: &str| query.decoded_value(name).ok().flatten();
    let unreadable = || {
        Some((
            ErrorCode::AUTHORIZATION_QUERY_PARAMETERS_ERROR,
            "The authorization query parameters that you provided are not valid.",
        ))
    };
    let (Some(algorithm), Some(credential), Some(date), Some(expires), Some(signed_headers), Some(signature)) = (
        unique("X-Amz-Algorithm"),
        unique("X-Amz-Credential"),
        unique("X-Amz-Date"),
        unique("X-Amz-Expires"),
        unique("X-Amz-SignedHeaders"),
        unique(X_AMZ_SIGNATURE),
    ) else {
        return unreadable();
    };
    let Some(scope) = read_scope(&credential) else {
        return unreadable();
    };
    let expires = expires
        .parse::<u32>()
        .ok()
        .map(u64::from)
        .filter(|seconds| *seconds <= MAX_EXPIRES);
    let signature_reads = signature.len() == 64 && signature.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    let (Some(expires), true, true, true) = (expires, is_amz_date_shape(&date), signed_headers.is_ascii(), signature_reads)
    else {
        return unreadable();
    };
    if algorithm != "AWS4-HMAC-SHA256" {
        return Some((
            ErrorCode::NOT_IMPLEMENTED,
            "X-Amz-Algorithm other than AWS4-HMAC-SHA256 is not implemented",
        ));
    }
    if date.get(..8) != Some(scope.date) {
        return Some((ErrorCode::SIGNATURE_DOES_NOT_MATCH, "credential scope date does not match x-amz-date"));
    }
    if let Some(declared) = unique_value(head.headers, "x-amz-content-sha256") {
        if is_malformed_payload(declared) {
            return Some((ErrorCode::SIGNATURE_DOES_NOT_MATCH, "invalid header: x-amz-content-sha256"));
        }
        if declared.starts_with("STREAMING-") {
            return Some((ErrorCode::NOT_IMPLEMENTED, "streaming payload for presigned URLs is not implemented"));
        }
    }
    if !names_an_instant(&date) {
        return Some((ErrorCode::INVALID_REQUEST, "invalid amz date"));
    }
    let age = head.now.unix_seconds() - unix_seconds(&date)?;
    if age < -MAX_FUTURE_SKEW {
        return Some((ErrorCode::REQUEST_TIME_TOO_SKEWED, "request date is later than server time too much"));
    }
    // Legacy RustFS compares the lifetime with a clock that reads fractions of a second, so a URL
    // whose lifetime ends within the current whole second is almost always past it already.
    if age >= i64::try_from(expires).unwrap_or(i64::MAX) {
        return Some((ErrorCode::ACCESS_DENIED, "Request has expired"));
    }
    None
}

/// The instant a `YYYYMMDDTHHMMSSZ` stamp that names one names, in seconds since the Unix epoch
/// (days from the civil date, proleptic Gregorian).
fn unix_seconds(stamp: &str) -> Option<i64> {
    let field = |range: core::ops::Range<usize>| stamp.get(range)?.parse::<i64>().ok();
    let (year, month, day) = (field(0..4)?, field(4..6)?, field(6..8)?);
    let (hour, minute, second) = (field(9..11)?, field(11..13)?, field(13..15)?);
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

impl ServiceBuilder {
    /// Answers a SigV4 presigned URL that legacy RustFS refuses before its credential lookup with
    /// legacy RustFS's code and sentence, in its order, as RustFS does today
    /// (rustfs/gateway#1130): a URL that does not read, another algorithm, a scope date other than
    /// its day, an unreadable or streaming `x-amz-content-sha256`, a date ahead of the clock, and an
    /// expired URL. The module documentation lists each answer.
    ///
    /// Off by default: the security floor and the authenticator refuse the same URLs with the
    /// gateway's codes and sentences. The switch only refuses: nothing refused without it is
    /// admitted with it, and a URL it lets through is admitted, verified and served exactly as
    /// before.
    #[must_use]
    pub fn answer_presigned_urls_as_legacy_rustfs(mut self) -> Self {
        self.view_policy.presigned_urls = PresignedRefusals::LegacyRustfs;
        self
    }
}

#[cfg(test)]
#[path = "presigned_urls_tests.rs"]
mod tests;
