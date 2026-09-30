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

//! The header-signed SigV4 requests legacy RustFS refuses before its credential lookup, refused by
//! the RustFS-profile launcher with legacy RustFS's answers (rustfs/gateway#1130).
//!
//! Responsible for: pinning, through the served assembly, each pre-lookup refusal — the status, the
//! code and legacy RustFS's sentence — and that the ones the gateway used to verify (a SigV4 `Date`
//! in place of `x-amz-date`, a second 60, no `x-amz-content-sha256`, a SigV2 `x-amz-date` or `Date`
//! in another spelling) store nothing now; and, as the control, that a well-formed request, a
//! bodyless `sts` request without a payload declaration, and a SigV2 request dated as legacy RustFS
//! reads a date are still served.
//! NOT responsible for: the refusals RustFS's own guard answers first (another algorithm token, an
//! unreadable `AWS4-HMAC-SHA256` value, an unsigned `x-amz-*` header), or the presigned and POST
//! forms.
//! Upstream: the parent module's two-identity assembly and [`super::hand_signer`]. Downstream:
//! nothing.

use super::hand_signer::HandSigned;
use super::*;

use rustfs_gateway::sig::{RawQuery, SigV2Mode, SigV2Signer, SigV2StringToSignSpec};

async fn with_object(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/headers", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let stored = exchange(&service, as_main(http::Method::PUT, "/headers/k", Bytes::from_static(b"stored"))).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    service
}

fn get() -> HandSigned {
    HandSigned::new(http::Method::GET, "/headers/k", Bytes::new())
}

fn put(path: &'static str) -> HandSigned {
    HandSigned::new(http::Method::PUT, path, Bytes::from_static(b"replaced"))
}

/// The current second's `x-amz-date` with its last two digits replaced by `seconds`.
fn stamp_with_seconds(seconds: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs();
    let stamp = Timestamp::from_secs(i64::try_from(now).expect("a representable clock"))
        .render(TimestampFormat::Iso8601Basic)
        .expect("a representable signing stamp");
    format!("{}{seconds}Z", &stamp[..13])
}

fn refused(answer: &WireResponse, status: u16, code: &str, sentence: &str) {
    let body = body_of(answer);
    assert_eq!(answer.status(), status, "{sentence}: {body}");
    assert!(body.contains(&format!("<Code>{code}</Code>")), "{sentence}: {body}");
    assert!(body.contains(&format!("<Message>{sentence}</Message>")), "{sentence}: {body}");
}

/// Positive — the controls: a well-formed header signature is served, and so is a bodyless
/// `sts`-scoped read without a payload declaration, as legacy RustFS serves it.
#[tokio::test]
async fn a_request_legacy_rustfs_reads_is_still_served() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    for request in [
        get().request(),
        get().in_service("sts").without_payload_declaration().request(),
    ] {
        let answer = exchange(&service, request).await;
        assert_eq!((answer.status().as_u16(), body_of(&answer).as_str()), (200, "stored"));
    }
}

/// Negative — each pre-lookup refusal alone is answered with legacy RustFS's status, code and
/// sentence.
#[tokio::test]
async fn n_each_pre_lookup_refusal_is_answered_as_legacy_rustfs_answers_it() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let mut bearer = get().request();
    bearer
        .headers_mut()
        .insert(http::header::AUTHORIZATION, http::HeaderValue::from_static("Bearer token"));
    refused(&exchange(&service, bearer).await, 400, "InvalidRequest", "invalid header: authorization");
    for (request, status, code, sentence) in [
        (get().dated_by_the_date_header(), 400, "InvalidRequest", "missing header: x-amz-date"),
        (get().undated(), 400, "InvalidRequest", "missing header: x-amz-date"),
        (
            get().with_amz_date("Tue, 30 Sep 2026 08:00:00 GMT"),
            400,
            "InvalidRequest",
            "invalid header: x-amz-date",
        ),
        (
            get().scoped_to_day("20200101"),
            403,
            "SignatureDoesNotMatch",
            "credential scope date does not match x-amz-date",
        ),
        (get().with_amz_date(stamp_with_seconds("60")), 400, "InvalidRequest", "invalid amz date"),
        (
            get().at_offset(-16 * 60),
            403,
            "RequestTimeTooSkewed",
            "request time is too far from server time",
        ),
        (
            get().at_offset(16 * 60),
            403,
            "RequestTimeTooSkewed",
            "request time is too far from server time",
        ),
        (
            get().declaring(super::hand_signer::sha256_hex(b"").to_uppercase()),
            403,
            "SignatureDoesNotMatch",
            "invalid header: x-amz-content-sha256",
        ),
        (
            get().without_payload_declaration(),
            400,
            "InvalidRequest",
            "missing header: x-amz-content-sha256",
        ),
        (
            get().in_service("s3tables").without_payload_declaration(),
            400,
            "InvalidRequest",
            "missing header: x-amz-content-sha256",
        ),
    ] {
        refused(&exchange(&service, request.request()).await, status, code, sentence);
    }
}

/// Negative — the three requests the gateway used to verify are refused on a write too, and store
/// nothing: a new key stays absent and an overwrite leaves the stored bytes.
#[tokio::test]
async fn n_the_requests_the_gateway_used_to_verify_store_nothing() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    for path in ["/headers/absent", "/headers/k"] {
        for (request, sentence) in [
            (put(path).dated_by_the_date_header(), "missing header: x-amz-date"),
            (put(path).with_amz_date(stamp_with_seconds("60")), "invalid amz date"),
            (put(path).without_payload_declaration(), "missing header: x-amz-content-sha256"),
        ] {
            refused(&exchange(&service, request.request()).await, 400, "InvalidRequest", sentence);
        }
    }
    let absent = exchange(&service, as_main(http::Method::GET, "/headers/absent", Bytes::new())).await;
    assert_eq!(absent.status(), 404, "{}", body_of(&absent));
    let kept = exchange(&service, as_main(http::Method::GET, "/headers/k", Bytes::new())).await;
    assert_eq!((kept.status().as_u16(), body_of(&kept).as_str()), (200, "stored"));
}

/// Negative — two faults at once are answered in legacy RustFS's order: the service before the
/// timestamp, the timestamp before the payload declaration, the scope date before the clock.
#[tokio::test]
async fn n_two_faults_are_answered_in_legacy_rustfs_order() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let service_and_date = get().in_service("foo").undated().request();
    let answer = exchange(&service, service_and_date).await;
    assert_eq!(answer.status(), 501, "{}", body_of(&answer));
    let date_and_payload = get().undated().declaring("garbage").request();
    refused(
        &exchange(&service, date_and_payload).await,
        400,
        "InvalidRequest",
        "missing header: x-amz-date",
    );
    let scope_and_clock = get().at_offset(-16 * 60).scoped_to_day("20200101").request();
    refused(
        &exchange(&service, scope_and_clock).await,
        403,
        "SignatureDoesNotMatch",
        "credential scope date does not match x-amz-date",
    );
}

/// A header-signed SigV2 `method` of `path` carrying `body`, dated by the `Date` and `x-amz-date`
/// given, signed with the gateway's SigV2 signer over exactly those headers.
fn sigv2(
    method: http::Method,
    path: &str,
    body: &'static [u8],
    date: Option<&str>,
    amz_date: Option<&str>,
) -> http::Request<Bytes> {
    let mut map = http::HeaderMap::new();
    map.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    if let Some(date) = date {
        map.insert(http::header::DATE, http::HeaderValue::from_str(date).expect("a date value"));
    }
    if let Some(amz_date) = amz_date {
        map.insert("x-amz-date", http::HeaderValue::from_str(amz_date).expect("a date value"));
    }
    let query = RawQuery::new("");
    let spec = SigV2StringToSignSpec::new(SigV2Mode::HeaderAuth, &method, path, &query, &map, None);
    let authorization = SigV2Signer::new(MAIN_KEY, MAIN_SECRET.as_bytes())
        .expect("a valid access key id")
        .authorization(&spec)
        .expect("a signable request");
    let mut builder = http::Request::builder().method(method).uri(path);
    for (name, value) in &map {
        builder = builder.header(name, value);
    }
    builder
        .header(http::header::CONTENT_LENGTH, body.len().to_string())
        .header(http::header::AUTHORIZATION, authorization)
        .body(Bytes::from_static(body))
        .expect("a valid request")
}

/// The current second in the spellings a SigV2 date comes in.
fn sigv2_dates() -> (String, String) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs();
    let now = Timestamp::from_secs(i64::try_from(now).expect("a representable clock"));
    let http_date = now.render(TimestampFormat::HttpDate).expect("a representable HTTP-date");
    let basic = now.render(TimestampFormat::Iso8601Basic).expect("a representable stamp");
    (http_date, basic)
}

/// Positive — a SigV2 request dated as legacy RustFS reads a date is served: an IMF-fixdate `Date`
/// in `GMT`, and a SigV4-spelled `x-amz-date`.
#[tokio::test]
async fn a_sigv2_date_legacy_rustfs_reads_is_served() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let (http_date, basic) = sigv2_dates();
    for request in [
        sigv2(http::Method::GET, "/headers/k", b"", Some(&http_date), None),
        sigv2(http::Method::GET, "/headers/k", b"", None, Some(&basic)),
    ] {
        let answer = exchange(&service, request).await;
        assert_eq!((answer.status().as_u16(), body_of(&answer).as_str()), (200, "stored"));
    }
}

/// Negative — a SigV2 request whose date legacy RustFS cannot read is refused with its answer, and
/// an upload dated that way stores nothing: an RFC 1123 `x-amz-date` (which the gateway used to
/// verify), a `Date` in `+0000` or in the SigV4 spelling (the same), and no date at all.
#[tokio::test]
async fn n_a_sigv2_date_legacy_rustfs_cannot_read_is_refused_and_stores_nothing() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let (http_date, basic) = sigv2_dates();
    let plus = http_date.replace("GMT", "+0000");
    for path in ["/headers/absent", "/headers/k"] {
        for (method, body) in [(http::Method::GET, &b""[..]), (http::Method::PUT, &b"replaced"[..])] {
            for (date, amz_date, sentence) in [
                (None, Some(plus.as_str()), "invalid x-amz-date"),
                (None, Some(http_date.as_str()), "invalid x-amz-date"),
                (Some(plus.as_str()), None, "invalid date"),
                (Some(basic.as_str()), None, "invalid date"),
                (None, None, "missing date"),
            ] {
                let request = sigv2(method.clone(), path, body, date, amz_date);
                refused(&exchange(&service, request).await, 400, "InvalidRequest", sentence);
            }
        }
    }
    let absent = exchange(&service, as_main(http::Method::GET, "/headers/absent", Bytes::new())).await;
    assert_eq!(absent.status(), 404, "{}", body_of(&absent));
    let kept = exchange(&service, as_main(http::Method::GET, "/headers/k", Bytes::new())).await;
    assert_eq!((kept.status().as_u16(), body_of(&kept).as_str()), (200, "stored"));
}
