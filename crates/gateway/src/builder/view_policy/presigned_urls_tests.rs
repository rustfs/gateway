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

//! The unit suite of the legacy presigned-URL refusals: each rule alone, their order, and the
//! requests the switch leaves to the security floor and the authenticator.
//!
//! Responsible for: `super::PresignedRefusals::refusal` over hand-built request heads.
//! NOT responsible for: the served assembly (`compat/sut`'s `presigned_refusal_tests.rs`).
//! Upstream: `super`. Downstream: Cargo's test harness.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use http::HeaderMap;
use rustfs_gateway_sig::{RequestNow, SkewWindow};

use super::*;

/// 2015-08-30T12:36:00Z, the instant the URLs below are signed at.
const NOW: i64 = 1_440_938_160;
const STAMP: &str = "20150830T123600Z";
const SIGNATURE: &str = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31";

/// A refusal as `(status, code, sentence)`, or none.
type Refusal = Option<(u16, String, String)>;

/// The six parameters of a readable presigned URL, as `(name, value)`, with `change` applied.
fn url(change: impl FnOnce(&mut Vec<(&'static str, String)>)) -> String {
    let mut pairs = vec![
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA256".to_owned()),
        ("X-Amz-Credential", "AKID%2F20150830%2Fus-east-1%2Fs3%2Faws4_request".to_owned()),
        ("X-Amz-Date", STAMP.to_owned()),
        ("X-Amz-Expires", "300".to_owned()),
        ("X-Amz-SignedHeaders", "host".to_owned()),
        ("X-Amz-Signature", SIGNATURE.to_owned()),
    ];
    change(&mut pairs);
    pairs
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn set(pairs: &mut Vec<(&'static str, String)>, name: &'static str, value: &str) {
    pairs.retain(|(existing, _)| *existing != name);
    pairs.push((name, value.to_owned()));
}

fn remove(pairs: &mut Vec<(&'static str, String)>, name: &str) {
    pairs.retain(|(existing, _)| *existing != name);
}

fn refusal_at(query: &str, headers: &HeaderMap, method: &Method, now: i64, mode: PresignedRefusals) -> Refusal {
    let head = SignedHead {
        method,
        headers,
        query,
        now: RequestNow::from_unix_seconds(now),
        window: SkewWindow::DEFAULT,
    };
    mode.refusal(&head, ResponseKind::Other, false).map(|error| {
        (
            error.status().as_u16(),
            error.code().map(|code| code.as_str().to_owned()).unwrap_or_default(),
            error.message().unwrap_or_default().to_owned(),
        )
    })
}

fn legacy(query: &str) -> Refusal {
    refusal_at(query, &HeaderMap::new(), &Method::GET, NOW, PresignedRefusals::LegacyRustfs)
}

fn answer(status: u16, code: &str, sentence: &str) -> Refusal {
    Some((status, code.to_owned(), sentence.to_owned()))
}

const UNREADABLE: &str = "The authorization query parameters that you provided are not valid.";

/// Positive — a readable, current URL, one signed an instant ahead within the window, and one with
/// a lifetime of zero read in its own second are left to the floor and the authenticator.
#[test]
fn a_url_legacy_rustfs_reads_is_left_to_the_pipeline() {
    assert_eq!(legacy(&url(|_| {})), None);
    assert_eq!(
        refusal_at(&url(|_| {}), &HeaderMap::new(), &Method::GET, NOW - 900, PresignedRefusals::LegacyRustfs),
        None
    );
    assert_eq!(
        refusal_at(
            &url(|pairs| set(pairs, "X-Amz-Expires", "0")),
            &HeaderMap::new(),
            &Method::GET,
            NOW - 1,
            PresignedRefusals::LegacyRustfs
        ),
        None
    );
    assert_eq!(legacy(&url(|pairs| set(pairs, "X-Amz-Expires", "604800"))), None);
}

/// Negative — each rule alone is answered as legacy RustFS answers it.
#[test]
fn n_each_rule_alone_is_answered_as_legacy_rustfs_answers_it() {
    for (query, expected) in [
        (
            url(|pairs| remove(pairs, "X-Amz-Algorithm")),
            answer(400, "AuthorizationQueryParametersError", UNREADABLE),
        ),
        (
            url(|pairs| remove(pairs, "X-Amz-Credential")),
            answer(400, "AuthorizationQueryParametersError", UNREADABLE),
        ),
        (
            url(|pairs| remove(pairs, "X-Amz-Date")),
            answer(400, "AuthorizationQueryParametersError", UNREADABLE),
        ),
        (
            url(|pairs| remove(pairs, "X-Amz-Expires")),
            answer(400, "AuthorizationQueryParametersError", UNREADABLE),
        ),
        (
            url(|pairs| remove(pairs, "X-Amz-SignedHeaders")),
            answer(400, "AuthorizationQueryParametersError", UNREADABLE),
        ),
        (
            url(|pairs| set(pairs, "X-Amz-Signature", "")),
            answer(400, "AuthorizationQueryParametersError", UNREADABLE),
        ),
        (
            url(|pairs| set(pairs, "X-Amz-Signature", &SIGNATURE.to_uppercase())),
            answer(400, "AuthorizationQueryParametersError", UNREADABLE),
        ),
        (
            url(|pairs| set(pairs, "X-Amz-Credential", "garbage")),
            answer(400, "AuthorizationQueryParametersError", UNREADABLE),
        ),
        (
            url(|pairs| set(pairs, "X-Amz-Date", "20150830")),
            answer(400, "AuthorizationQueryParametersError", UNREADABLE),
        ),
        (
            url(|pairs| set(pairs, "X-Amz-Date", "2015083OT123600Z")),
            answer(400, "AuthorizationQueryParametersError", UNREADABLE),
        ),
        (
            url(|pairs| set(pairs, "X-Amz-Date", "20150830T123660Z")),
            answer(400, "InvalidRequest", "invalid amz date"),
        ),
        (
            url(|pairs| set(pairs, "X-Amz-Date", "20151330T123600Z")),
            answer(403, "SignatureDoesNotMatch", "credential scope date does not match x-amz-date"),
        ),
        (
            url(|pairs| set(pairs, "X-Amz-Expires", "abc")),
            answer(400, "AuthorizationQueryParametersError", UNREADABLE),
        ),
        (
            url(|pairs| set(pairs, "X-Amz-Expires", "604801")),
            answer(400, "AuthorizationQueryParametersError", UNREADABLE),
        ),
        (
            url(|pairs| set(pairs, "X-Amz-SignedHeaders", "h%C3%B6st")),
            answer(400, "AuthorizationQueryParametersError", UNREADABLE),
        ),
        (
            url(|pairs| set(pairs, "X-Amz-Algorithm", "AWS4-HMAC-SHA512")),
            answer(501, "NotImplemented", "X-Amz-Algorithm other than AWS4-HMAC-SHA256 is not implemented"),
        ),
        (
            url(|pairs| set(pairs, "X-Amz-Credential", "AKID%2F20150829%2Fus-east-1%2Fs3%2Faws4_request")),
            answer(403, "SignatureDoesNotMatch", "credential scope date does not match x-amz-date"),
        ),
    ] {
        assert_eq!(legacy(&query), expected, "{query}");
    }
    let ahead = refusal_at(&url(|_| {}), &HeaderMap::new(), &Method::GET, NOW - 901, PresignedRefusals::LegacyRustfs);
    assert_eq!(
        ahead,
        answer(403, "RequestTimeTooSkewed", "request date is later than server time too much")
    );
    let expired = refusal_at(&url(|_| {}), &HeaderMap::new(), &Method::GET, NOW + 300, PresignedRefusals::LegacyRustfs);
    assert_eq!(expired, answer(403, "AccessDenied", "Request has expired"));
    let zero = refusal_at(
        &url(|pairs| set(pairs, "X-Amz-Expires", "0")),
        &HeaderMap::new(),
        &Method::GET,
        NOW,
        PresignedRefusals::LegacyRustfs,
    );
    assert_eq!(zero, answer(403, "AccessDenied", "Request has expired"));
    for (declared, expected) in [
        ("garbage", answer(403, "SignatureDoesNotMatch", "invalid header: x-amz-content-sha256")),
        (
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            answer(501, "NotImplemented", "streaming payload for presigned URLs is not implemented"),
        ),
    ] {
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-content-sha256", http::HeaderValue::from_static(declared));
        let refused = refusal_at(&url(|_| {}), &headers, &Method::PUT, NOW, PresignedRefusals::LegacyRustfs);
        assert_eq!(refused, expected, "{declared}");
    }
}

/// Negative — two faults at once are answered in legacy RustFS's order: the reading before the
/// algorithm, the algorithm before the scope date, the scope date before the clock.
#[test]
fn n_two_faults_are_answered_in_legacy_rustfs_order() {
    let unreadable_and_algorithm = url(|pairs| {
        set(pairs, "X-Amz-Algorithm", "AWS4-HMAC-SHA512");
        remove(pairs, "X-Amz-Expires");
    });
    assert_eq!(
        legacy(&unreadable_and_algorithm),
        answer(400, "AuthorizationQueryParametersError", UNREADABLE)
    );
    let algorithm_and_date = url(|pairs| {
        set(pairs, "X-Amz-Algorithm", "AWS4-HMAC-SHA512");
        set(pairs, "X-Amz-Credential", "AKID%2F20150829%2Fus-east-1%2Fs3%2Faws4_request");
    });
    assert_eq!(
        legacy(&algorithm_and_date),
        answer(501, "NotImplemented", "X-Amz-Algorithm other than AWS4-HMAC-SHA256 is not implemented")
    );
    let date_and_clock = url(|pairs| set(pairs, "X-Amz-Credential", "AKID%2F20150829%2Fus-east-1%2Fs3%2Faws4_request"));
    assert_eq!(
        refusal_at(
            &date_and_clock,
            &HeaderMap::new(),
            &Method::GET,
            NOW + 3_600,
            PresignedRefusals::LegacyRustfs
        ),
        answer(403, "SignatureDoesNotMatch", "credential scope date does not match x-amz-date")
    );
}

/// Negative — what is not a SigV4 presigned URL by legacy RustFS's reading is left alone: no
/// `X-Amz-Signature`, a SigV2 `Signature`, an `Authorization` header beside it, a browser form;
/// and without the switch nothing is answered here.
#[test]
fn n_what_is_not_a_presigned_url_is_left_alone() {
    let unsigned = url(|pairs| {
        remove(pairs, "X-Amz-Signature");
        remove(pairs, "X-Amz-Expires");
    });
    assert_eq!(legacy(&unsigned), None);
    assert_eq!(legacy(&format!("{}&Signature=abc", url(|pairs| remove(pairs, "X-Amz-Expires")))), None);
    let mut authorized = HeaderMap::new();
    authorized.insert(AUTHORIZATION, http::HeaderValue::from_static("AWS4-HMAC-SHA256 x"));
    let broken = url(|pairs| remove(pairs, "X-Amz-Expires"));
    assert_eq!(refusal_at(&broken, &authorized, &Method::GET, NOW, PresignedRefusals::LegacyRustfs), None);
    let mut form = HeaderMap::new();
    form.insert(CONTENT_TYPE, http::HeaderValue::from_static("multipart/form-data; boundary=x"));
    assert_eq!(refusal_at(&broken, &form, &Method::POST, NOW, PresignedRefusals::LegacyRustfs), None);
    assert_eq!(
        refusal_at(&broken, &HeaderMap::new(), &Method::GET, NOW, PresignedRefusals::Gateway),
        None
    );
    assert_eq!(PresignedRefusals::default(), PresignedRefusals::Gateway);
}

/// Positive — the instant a stamp names, against known epochs.
#[test]
fn a_stamp_names_its_unix_instant() {
    assert_eq!(unix_seconds(STAMP), Some(NOW));
    assert_eq!(unix_seconds("19700101T000000Z"), Some(0));
    assert_eq!(unix_seconds("20000229T235959Z"), Some(951_868_799));
}
