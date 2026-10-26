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

//! Explicit reference clock configuration through the actual launcher assembly.
//!
//! Responsible for: fixed-time signing acceptance, backend timestamps and skew/refusal controls.
//! NOT responsible for claiming the time of an independently managed endpoint or advancing clocks.
//! Upstream: launcher option parsing and service assembly. Downstream: the test harness.

use super::*;

const FIXED: &str = "2026-01-02T03:04:05Z";
const STAMP: &str = "20260102T030405Z";

fn request_at(stamp: &str, secret: &str, method: http::Method, target: &str, body: Bytes) -> http::Request<Bytes> {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    headers.insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_str(&body.len().to_string()).expect("length"),
    );
    let payload = PayloadMode::ExactSha256(Sha256::digest(&body).into());
    headers.insert(
        http::HeaderName::from_static("x-amz-content-sha256"),
        http::HeaderValue::from_str(payload.canonical_payload_token().as_str()).expect("body digest"),
    );
    let probe = http::Request::builder()
        .uri("/")
        .header(http::header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("host probe");
    let accepted = WireRequest::accept(probe, &Limits::default()).expect("accepted host");
    let stamp = AmzDate::parse(stamp).expect("declared signing instant");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("scope");
    let credentials = SigningCredentials::new(MAIN_KEY, secret.as_bytes()).expect("test credentials");
    let signing = SigningRequest::new(&method, target, "", &headers, accepted.host().raw_for_signing(), payload, stamp)
        .with_wire_content_length(body.len() as u64);
    let signed = SigV4Signer::new(credentials, scope)
        .sign_headers(&signing)
        .expect("signed request");
    let mut request = http::Request::builder().method(method).uri(target);
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    request.body(body).expect("fixed-time request")
}

fn parse_error(arguments: &[&str]) -> String {
    match parse_options(arguments) {
        Err(error) => error.to_string(),
        Ok(_) => panic!("invalid fixed-time configuration was accepted"),
    }
}

#[test]
fn n_fixed_time_rejects_invalid_and_lossy_utc_instants() {
    for value in [
        "",
        "today",
        "2026-02-30T03:04:05Z",
        "2026-01-02T03:04:05.1Z",
        "2026-01-02T03:04:05+00:00",
        "2026-01-02T03:04:60Z",
        "2026-01-02",
    ] {
        let error = parse_error(&["--fixed-time", value]);
        assert!(error.contains("UTC"), "{value:?}: {error}");
    }
}

#[test]
fn n_fixed_time_rejects_missing_and_repeated_values() {
    let error = parse_error(&["--fixed-time"]);
    assert!(error.contains("value"), "{error}");
    for second in [FIXED, "2026-01-02T03:04:06Z"] {
        let error = parse_error(&["--fixed-time", FIXED, "--fixed-time", second]);
        assert!(error.contains("once"), "{error}");
    }
}

#[test]
fn n_fixed_time_cannot_claim_to_configure_a_forwarded_endpoint() {
    for arguments in [
        ["--external", "http://127.0.0.1:9000", "--fixed-time", FIXED],
        ["--fixed-time", FIXED, "--external", "http://127.0.0.1:9000"],
    ] {
        let error = parse_error(&arguments);
        assert!(
            error.contains("--external") && error.contains("--fixed-time") && error.contains("backend"),
            "{error}"
        );
    }
}

#[tokio::test]
async fn p_fixed_time_drives_authentication_and_stored_object_timestamps() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &["--fixed-time", FIXED]);
    let (_backend, service) = assembled(&options);
    for (target, body) in [("/fixed-clock", b"".as_slice()), ("/fixed-clock/key", b"hello".as_slice())] {
        let response = exchange(
            &service,
            request_at(STAMP, MAIN_SECRET, http::Method::PUT, target, Bytes::copy_from_slice(body)),
        )
        .await;
        assert_eq!(response.status(), 200, "{}", body_of(&response));
    }
    let read = exchange(
        &service,
        request_at(STAMP, MAIN_SECRET, http::Method::GET, "/fixed-clock/key", Bytes::new()),
    )
    .await;
    assert_eq!(read.status(), 200, "{}", body_of(&read));
    assert_eq!(
        read.headers()
            .iter()
            .find(|(name, _)| name == http::header::LAST_MODIFIED)
            .and_then(|(_, value)| value.to_str().ok()),
        Some("Fri, 02 Jan 2026 03:04:05 GMT")
    );
    assert_eq!(read.body().as_ref(), b"hello");
    for target in ["/fixed-clock/key", "/fixed-clock"] {
        let deleted = exchange(&service, request_at(STAMP, MAIN_SECRET, http::Method::DELETE, target, Bytes::new())).await;
        assert_eq!(deleted.status(), 204, "{}", body_of(&deleted));
    }
}

#[tokio::test]
async fn n_fixed_time_keeps_past_and_future_signature_skew_rejections() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &["--fixed-time", FIXED]);
    let (_backend, service) = assembled(&options);
    for stamp in ["20260102T024805Z", "20260102T032005Z"] {
        let response = exchange(&service, request_at(stamp, MAIN_SECRET, http::Method::GET, "/", Bytes::new())).await;
        assert_eq!(response.status(), 403, "{}", body_of(&response));
        assert!(body_of(&response).contains("<Code>RequestTimeTooSkewed</Code>"), "{}", body_of(&response));
    }
}

#[tokio::test]
async fn n_fixed_time_does_not_bypass_signature_verification() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &["--fixed-time", FIXED]);
    let (_backend, service) = assembled(&options);
    let response = exchange(
        &service,
        request_at(STAMP, "a-different-test-secret", http::Method::GET, "/", Bytes::new()),
    )
    .await;
    assert_eq!(response.status(), 403, "{}", body_of(&response));
    assert!(
        body_of(&response).contains("<Code>SignatureDoesNotMatch</Code>"),
        "{}",
        body_of(&response)
    );
}

#[tokio::test]
async fn n_without_fixed_time_the_reference_keeps_wall_clock_skew_checks() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after epoch")
        .as_secs();
    let old = i64::try_from(now).expect("representable time") - 86_400;
    let stamp = Timestamp::from_secs(old)
        .render(TimestampFormat::Iso8601Basic)
        .expect("old stamp");
    let response = exchange(&service, request_at(&stamp, MAIN_SECRET, http::Method::GET, "/", Bytes::new())).await;
    assert_eq!(response.status(), 403, "{}", body_of(&response));
    assert!(body_of(&response).contains("<Code>RequestTimeTooSkewed</Code>"), "{}", body_of(&response));
}
