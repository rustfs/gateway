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

//! When the STS body digest counts as a signed body (rustfs/gateway#1587).
//!
//! Responsible for: `Authentication::signs_its_body` after a rejected STS-digest comparison, and
//! after a successful plain comparison that followed one, so a fallback cannot inherit it.
//! NOT responsible for: the positive path through an assembled service, which
//! `crates/gateway/tests/dialect_claims_signed_body.rs` pins.
//! Upstream: `super`. Downstream: Cargo's test harness.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use http::{HeaderMap, HeaderValue, Method};
use rustfs_gateway_core::BoxFuture;
use rustfs_gateway_http::RawHost;
use rustfs_gateway_sig::{Admission, OperationFloor, PayloadMode, RawQuery, RequestNow, SecurityFloor, SigService, WireView};
use sha2::{Digest as _, Sha256};

use super::super::{Authentication, Authenticator, RegionSet, SigV4Authenticator};
use crate::ext::credentials::{Credentials, StaticCredentials};
use crate::gate::{BodyCeilings, BodyTimeouts, StsBodyReader};
use crate::render::S3Error;

/// 2015-08-30T12:36:00Z, the instant the head is dated at.
const NOW: i64 = 1_440_938_160;
const STAMP: &str = "20150830T123600Z";

/// A body reader that answers the digest of a fixed body and counts how often it was asked.
struct Body(Mutex<usize>);

impl StsBodyReader for Body {
    fn digest(&self, _timeouts: BodyTimeouts, _ceilings: Option<BodyCeilings>) -> BoxFuture<'_, Result<[u8; 32], S3Error>> {
        *self.0.lock().expect("uncontended") += 1;
        Box::pin(async { Ok(Sha256::digest(b"Action=AssumeRole").into()) })
    }
}

fn legacy(secret: &[u8]) -> SigV4Authenticator {
    SigV4Authenticator::new(
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", secret).expect("valid"))),
        RegionSet::new(["us-east-1"]).expect("non-empty"),
    )
    .accept_legacy_rustfs_signing_services()
}

/// An `sts`-scoped header credential with no payload header and a signature that matches nothing.
fn head() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_static("s3.example.com"));
    headers.insert("x-amz-date", HeaderValue::from_static(STAMP));
    headers.insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(&format!(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/sts/aws4_request, \
             SignedHeaders=host;x-amz-date, Signature={}",
            "0".repeat(64)
        ))
        .expect("a header value"),
    );
    headers
}

/// Negative — a comparison that digested the STS body and was rejected leaves the body unsigned,
/// though the digest was computed; so does the same rejection asked a second time.
#[tokio::test]
async fn n_a_rejected_sts_digest_comparison_signs_no_body() {
    let headers = head();
    let floor = OperationFloor::builtin("acme:Form", SigService::Sts);
    let admitted = SecurityFloor::new()
        .admit(WireView::new(&headers, RawQuery::new("")), &floor, RequestNow::from_unix_seconds(NOW))
        .expect("a well-formed header credential is admitted");
    let Admission::Sealed(sealed) = admitted else { panic!("an AWS header credential is sealed") };
    let host = RawHost::from_host_header(b"s3.example.com").expect("valid host");
    let payload = PayloadMode::Empty;
    let body = Body(Mutex::new(0));
    let request = Authentication::new(&sealed, &Method::PUT, "/example/admin/v1/form", &host, &payload, Some(17))
        .with_sts_body_reader(Some(&body), "acme:Form", &crate::ServiceConfig::new(8192));
    for attempt in 0..2 {
        let outcome = legacy(b"secret").authenticate(&request).await.expect("an answer");
        assert!(
            !outcome.verdict().is_authenticated(),
            "attempt {attempt}: the forged signature is refused"
        );
        assert!(!request.signs_its_body(), "attempt {attempt}: a refused comparison signs no body");
    }
    assert_eq!(*body.0.lock().expect("uncontended"), 2, "the STS body digest was computed each time");
}

fn vectors_service() -> SigService {
    SigService::parse("s3vectors").expect("S3 Vectors has a typed signing service")
}

fn hmac_sha256(key: &[u8], value: &[u8]) -> [u8; 32] {
    let mut block = [0_u8; 64];
    block
        .get_mut(..key.len())
        .expect("the fixture key fits the HMAC block")
        .copy_from_slice(key);
    let mut inner = Sha256::new();
    inner.update(block.map(|byte| byte ^ 0x36));
    inner.update(value);
    let mut outer = Sha256::new();
    outer.update(block.map(|byte| byte ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A rest-json header signature, independently calculated from the request bytes.
fn vectors_head(service: &str, body: &[u8], declared_digest: bool, target: (&str, &str, &str)) -> HeaderMap {
    let scope = format!("20150830/us-east-1/{service}/aws4_request");
    let digest = hex(&Sha256::digest(body));
    let signed_headers = if declared_digest {
        "host;x-amz-content-sha256;x-amz-date"
    } else {
        "host;x-amz-date"
    };
    let payload_header = if declared_digest {
        format!("x-amz-content-sha256:{digest}\n")
    } else {
        String::new()
    };
    let (method, path, query) = target;
    let canonical = format!(
        "{method}\n{path}\n{query}\nhost:s3.example.com\n{payload_header}x-amz-date:{STAMP}\n\n{signed_headers}\n{digest}"
    );
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{STAMP}\n{scope}\n{}", hex(&Sha256::digest(canonical)));
    let mut key = hmac_sha256(b"AWS4secret", b"20150830");
    for value in ["us-east-1", service, "aws4_request"] {
        key = hmac_sha256(&key, value.as_bytes());
    }
    let signature = hex(&hmac_sha256(&key, string_to_sign.as_bytes()));
    let mut headers = HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("s3.example.com"));
    headers.insert("x-amz-date", HeaderValue::from_static(STAMP));
    if declared_digest {
        headers.insert("x-amz-content-sha256", HeaderValue::from_str(&digest).expect("a hex digest"));
    }
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
        ))
        .expect("a header signature"),
    );
    headers
}

async fn vectors_verdict(
    expected_service: SigService,
    presented_service: &str,
    signed_body: &[u8],
    received_body: &[u8],
    declared_digest: bool,
    legacy_services: bool,
    secret: &[u8],
) -> (bool, bool) {
    let headers = vectors_head(presented_service, signed_body, declared_digest, ("POST", "/PutVectors", ""));
    let floor = OperationFloor::builtin("example:PutVectors", expected_service).require_sigv4_under_every_policy();
    let admitted = SecurityFloor::new()
        .admit(WireView::new(&headers, RawQuery::new("")), &floor, RequestNow::from_unix_seconds(NOW))
        .expect("the header signature is structurally valid");
    let Admission::Sealed(sealed) = admitted else { panic!("a header signature is sealed") };
    let host = RawHost::from_host_header(b"s3.example.com").expect("a valid host");
    let payload = if declared_digest {
        PayloadMode::ExactSha256(Sha256::digest(signed_body).into())
    } else {
        PayloadMode::Empty
    };
    let body = crate::gate::SealedBody::seal(
        Some(http_body_util::Full::new(bytes::Bytes::copy_from_slice(received_body))),
        Some(received_body.len() as u64),
    );
    let request = Authentication::new(&sealed, &Method::POST, "/PutVectors", &host, &payload, Some(received_body.len() as u64))
        .with_sts_body_reader(Some(&body), "example:PutVectors", &crate::ServiceConfig::new(16384));
    let mut authenticator = SigV4Authenticator::new(
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", secret).expect("valid"))),
        RegionSet::new(["us-east-1"]).expect("non-empty"),
    );
    if legacy_services {
        authenticator = authenticator.accept_legacy_rustfs_signing_services();
    }
    let outcome = authenticator.authenticate(&request).await.expect("an authentication answer");
    (outcome.verdict().is_authenticated(), request.signs_its_body())
}

#[tokio::test]
async fn s3vectors_explicit_payload_hash_authenticates_under_each_service_policy() {
    for legacy_services in [false, true] {
        let result = vectors_verdict(vectors_service(), "s3vectors", b"{}", b"{}", true, legacy_services, b"secret").await;
        assert_eq!(result, (true, true), "legacy service switch: {legacy_services}");
    }
}

#[tokio::test]
async fn s3vectors_missing_payload_hash_authenticates_the_received_body() {
    for legacy_services in [false, true] {
        let result = vectors_verdict(vectors_service(), "s3vectors", b"{}", b"{}", false, legacy_services, b"secret").await;
        assert_eq!(result, (true, true), "legacy service switch: {legacy_services}");
    }
}

#[tokio::test]
async fn s3vectors_missing_payload_hash_accepts_a_body_larger_than_the_sts_limit() {
    let body = vec![b' '; 8193];
    let result = vectors_verdict(vectors_service(), "s3vectors", &body, &body, false, false, b"secret").await;
    assert_eq!(result, (true, true));
}

#[tokio::test]
async fn s3vectors_missing_payload_hash_accepts_the_exact_configured_body_limit() {
    let body = vec![b' '; 16384];
    assert_eq!(
        vectors_verdict(vectors_service(), "s3vectors", &body, &body, false, false, b"secret").await,
        (true, true)
    );
}

#[tokio::test]
async fn n_s3vectors_missing_payload_hash_refuses_one_byte_above_the_configured_limit() {
    let body = vec![b' '; 16385];
    assert_eq!(
        vectors_verdict(vectors_service(), "s3vectors", &body, &body, false, false, b"secret").await,
        (false, false)
    );
}

#[tokio::test]
async fn n_s3vectors_operation_refuses_other_signing_services() {
    for legacy_services in [false, true] {
        for service in ["s3", "sts", "s3tables"] {
            let (authenticated, _) =
                vectors_verdict(vectors_service(), service, b"{}", b"{}", true, legacy_services, b"secret").await;
            assert!(!authenticated, "service {service}, legacy service switch: {legacy_services}");
        }
    }
}

#[tokio::test]
async fn n_s3vectors_signature_cannot_authenticate_an_s3_operation() {
    let _ = vectors_service();
    for legacy_services in [false, true] {
        let (authenticated, _) =
            vectors_verdict(SigService::S3, "s3vectors", b"{}", b"{}", true, legacy_services, b"secret").await;
        assert!(!authenticated, "legacy service switch: {legacy_services}");
    }
}

#[tokio::test]
async fn n_s3vectors_missing_payload_hash_refuses_a_changed_body() {
    for legacy_services in [false, true] {
        let result = vectors_verdict(vectors_service(), "s3vectors", b"{}", b"[]", false, legacy_services, b"secret").await;
        assert_eq!(result, (false, false), "legacy service switch: {legacy_services}");
    }
}

#[tokio::test]
async fn n_s3vectors_missing_payload_hash_refuses_a_wrong_secret() {
    for legacy_services in [false, true] {
        let result = vectors_verdict(vectors_service(), "s3vectors", b"{}", b"{}", false, legacy_services, b"wrong-secret").await;
        assert_eq!(result, (false, false), "legacy service switch: {legacy_services}");
    }
}

#[tokio::test]
async fn n_s3vectors_missing_payload_hash_refuses_a_truncated_body() {
    let result = vectors_verdict(vectors_service(), "s3vectors", b"{}", b"{", false, false, b"secret").await;
    assert_eq!(result, (false, false));
}

#[tokio::test]
async fn n_s3vectors_missing_payload_hash_refuses_a_nonempty_body_signed_as_empty() {
    let result = vectors_verdict(vectors_service(), "s3vectors", b"", b"{}", false, false, b"secret").await;
    assert_eq!(result, (false, false));
}

#[tokio::test]
async fn n_s3_missing_payload_hash_keeps_its_existing_authentication_behavior() {
    for legacy_services in [false, true] {
        let result = vectors_verdict(SigService::S3, "s3", b"{}", b"{}", false, legacy_services, b"secret").await;
        assert_eq!(result, (false, false), "legacy service switch: {legacy_services}");
    }
}

async fn vectors_query_verdict(expected: SigService, presented: &str, query: &str, canonical: &str) -> bool {
    let headers = vectors_head(presented, b"", true, ("DELETE", "/tags/resource", canonical));
    let floor = OperationFloor::builtin("example:UntagResource", expected).require_sigv4_under_every_policy();
    let admitted =
        SecurityFloor::new().admit(WireView::new(&headers, RawQuery::new(query)), &floor, RequestNow::from_unix_seconds(NOW));
    let Ok(Admission::Sealed(sealed)) = admitted else { return false };
    let host = RawHost::from_host_header(b"s3.example.com").expect("a valid host");
    let payload = PayloadMode::ExactSha256(Sha256::digest(b"").into());
    let request = Authentication::new(&sealed, &Method::DELETE, "/tags/resource", &host, &payload, Some(0));
    let authenticator = SigV4Authenticator::new(
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid"))),
        RegionSet::new(["us-east-1"]).expect("non-empty"),
    );
    authenticator
        .authenticate(&request)
        .await
        .expect("an authentication answer")
        .verdict()
        .is_authenticated()
}

#[tokio::test]
async fn s3vectors_query_authenticates_every_tag_key_and_its_encoded_alias() {
    for query in ["tagKeys=b&tagKeys=a&tagKeys=a", "tag%4Beys=a&%74agKeys=b&tagKeys=a"] {
        assert!(vectors_query_verdict(vectors_service(), "s3vectors", query, "tagKeys=a&tagKeys=a&tagKeys=b").await);
    }
}

#[tokio::test]
async fn s3vectors_query_authenticates_a_single_tag_key_control() {
    assert!(vectors_query_verdict(vectors_service(), "s3vectors", "tagKeys=a", "tagKeys=a").await);
}

#[tokio::test]
async fn n_s3vectors_query_refuses_a_changed_tag_key() {
    assert!(!vectors_query_verdict(vectors_service(), "s3vectors", "tagKeys=a&tagKeys=c", "tagKeys=a&tagKeys=b").await);
}

#[tokio::test]
async fn n_s3vectors_query_refuses_a_changed_tag_key_count() {
    for query in ["tagKeys=a&tagKeys=b", "tagKeys=a&tagKeys=a&tagKeys=a&tagKeys=b"] {
        assert!(!vectors_query_verdict(vectors_service(), "s3vectors", query, "tagKeys=a&tagKeys=a&tagKeys=b").await);
    }
}

#[tokio::test]
async fn n_s3vectors_query_refuses_repeated_other_names_even_with_a_matching_signature() {
    for query in ["other=a&other=b", "TagKeys=a&TagKeys=b", "tagkeys=a&tagkeys=b"] {
        assert!(!vectors_query_verdict(vectors_service(), "s3vectors", query, query).await);
    }
}

#[tokio::test]
async fn n_s3vectors_query_refuses_repeated_signing_parameters() {
    for query in ["X-Amz-Date=a&X-Amz-Date=b", "X-Amz-Signature=a&X-Amz-Signature=b"] {
        assert!(!vectors_query_verdict(vectors_service(), "s3vectors", query, query).await);
    }
}

#[tokio::test]
async fn n_s3vectors_query_policy_does_not_admit_repeated_s3_parameters() {
    assert!(!vectors_query_verdict(SigService::S3, "s3", "tagKeys=a&tagKeys=b", "tagKeys=a&tagKeys=b").await);
}

#[tokio::test]
async fn n_s3vectors_query_policy_does_not_admit_a_different_presented_service() {
    assert!(!vectors_query_verdict(vectors_service(), "s3", "tagKeys=a&tagKeys=b", "tagKeys=a&tagKeys=b").await);
}
