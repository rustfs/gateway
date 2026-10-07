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

//! Signed POST-policy byte ceilings through the real multipart/authentication/handler pipeline.
//!
//! Responsible for: legacy byte limits reaching SigV2 and SigV4 authentication, final policy
//! enforcement, and object-path refusal, with defaults and no-write refusals as controls.
//! NOT responsible for: widening JSON, condition, depth, signature, or expiry semantics.
//! Upstream: the POST form profile. Downstream: the gateway integration target.

use super::*;

const LARGE: usize = 32 * 1024 + 1;
const LEGACY_DECODED_EDGE: usize = 1024 * 1024 / 4 * 3;
const V4_DOCUMENT: &str = r#"{"expiration":"2026-01-02T04:04:05Z","conditions":[{"bucket":"example-bucket"},{"key":"upload"},{"x-amz-algorithm":"AWS4-HMAC-SHA256"},{"x-amz-credential":"AKIDEXAMPLE/20260102/us-east-1/s3/aws4_request"},{"x-amz-date":"20260102T030405Z"},["content-length-range",1,16]]}"#;

// Independently computed with Python hashlib/hmac over the exact padded, base64-encoded JSON.
const V4_LARGE_SIGNATURE: &str = "84617331d82cefd7842743110784c8ea2d416bc1a9d04e14c72ac1c677bb4c8a";
const V4_EDGE_SIGNATURE: &str = "3019c3eb53691c768b6bc18fe19829f86f10adb1000bb0f499fc40b83795d01b";
const V4_OVER_SIGNATURE: &str = "cb5224bee9a079a6f48aa2459946eca538ab32effac295128715101702a55d40";
const V4_WRONG_SIGNATURE: &str = "db810c4a051490f7c7101447c6fc7d049cc1a68def108a1c7a857396d1fb71ae";

fn padded_policy<const N: usize>(document: &[u8]) -> String {
    let mut bytes = vec![b' '; N];
    bytes[..document.len()].copy_from_slice(document);
    let exact: &[u8; N] = bytes.as_slice().try_into().expect("the fixture has exactly N bytes");
    encode_base64_exact(exact)
}

fn v4_fields<'a>(policy: &'a str, signature: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("key", "upload"),
        ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
        ("x-amz-credential", "AKIDEXAMPLE/20260102/us-east-1/s3/aws4_request"),
        ("x-amz-date", "20260102T030405Z"),
        ("policy", policy),
        ("x-amz-signature", signature),
    ]
}

// Keep the streaming frame ceiling intact while delivering a complete large form.
pub(super) struct PolicyFrames(pub(super) Bytes);

impl http_body::Body for PolicyFrames {
    type Data = Bytes;
    type Error = core::convert::Infallible;

    fn poll_frame(
        mut self: core::pin::Pin<&mut Self>,
        _: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        let length = self.0.len().min(64 * 1024);
        core::task::Poll::Ready((length != 0).then(|| Ok(http_body::Frame::data(self.0.split_to(length)))))
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_empty()
    }
}

/// Positive — the same credentials and policy conditions verify before whitespace exceeds the cap.
#[tokio::test]
async fn a_short_sigv4_policy_proves_the_independent_signing_fixture() {
    let policy = encode_policy_document(V4_DOCUMENT);
    let (status, response, stored) = post(
        true,
        &v4_fields(&policy, "36571d19d6a9cf03afaa4dfac9a164397f46a3f2aa58f1a58f0d0bc8a1949d58"),
        "hello",
    )
    .await;
    assert_eq!(
        (status, stored),
        (StatusCode::NO_CONTENT, Some(("upload".to_owned(), b"hello".to_vec()))),
        "{response}"
    );
}

/// Positive — JSON whitespace raises the byte lengths without changing nodes or conditions.
#[tokio::test]
async fn legacy_policy_bytes_reach_sigv2_authentication_and_storage() {
    let policy = padded_policy::<LARGE>(POLICY);
    let signature = signed_policy(&policy);
    let (status, response, stored) = post(true, &fields(&policy, &signature), "hello").await;
    assert_eq!(
        (status, stored),
        (StatusCode::NO_CONTENT, Some(("upload".to_owned(), b"hello".to_vec()))),
        "{response}"
    );
}

/// Positive — exactly 1 MiB of encoded policy reaches the real SigV2 handler.
#[tokio::test]
async fn legacy_policy_bytes_at_one_mebibyte_reach_sigv2_storage() {
    let policy = padded_policy::<LEGACY_DECODED_EDGE>(POLICY);
    let signature = signed_policy(&policy);
    let (status, response, stored) = post(true, &fields(&policy, &signature), "hello").await;
    assert_eq!(
        (status, stored),
        (StatusCode::NO_CONTENT, Some(("upload".to_owned(), b"hello".to_vec()))),
        "{response}"
    );
}

/// Positive — the larger policy passes both SigV4 authentication and the final policy parser.
#[tokio::test]
async fn legacy_policy_bytes_reach_sigv4_authentication_and_storage() {
    let policy = padded_policy::<LARGE>(V4_DOCUMENT.as_bytes());
    let (status, response, stored) = post(true, &v4_fields(&policy, V4_LARGE_SIGNATURE), "hello").await;
    assert_eq!(
        (status, stored),
        (StatusCode::NO_CONTENT, Some(("upload".to_owned(), b"hello".to_vec()))),
        "{response}"
    );
}

/// Positive — exactly 1 MiB of encoded policy reaches the real SigV4 handler.
#[tokio::test]
async fn legacy_policy_bytes_at_one_mebibyte_reach_sigv4_storage() {
    let policy = padded_policy::<LEGACY_DECODED_EDGE>(V4_DOCUMENT.as_bytes());
    let (status, response, stored) = post(true, &v4_fields(&policy, V4_EDGE_SIGNATURE), "hello").await;
    assert_eq!(
        (status, stored),
        (StatusCode::NO_CONTENT, Some(("upload".to_owned(), b"hello".to_vec()))),
        "{response}"
    );
}

async fn generic_post(fields: &[(&str, &str)]) -> (StatusCode, String, Option<(String, Vec<u8>)>) {
    post_with_credentials(
        true,
        fields,
        "hello",
        Credentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials"),
        false,
    )
    .await
}

/// Negative — opting into SigV2 does not give generic forms larger byte ceilings.
#[tokio::test]
async fn n_generic_sigv2_policy_bytes_keep_the_existing_form_ceiling() {
    let policy = padded_policy::<LARGE>(POLICY);
    let signature = signed_policy(&policy);
    let (status, response, stored) = generic_post(&fields(&policy, &signature)).await;
    assert_eq!(
        (status, response.contains("<Code>MalformedPOSTRequest</Code>"), stored),
        (StatusCode::BAD_REQUEST, true, None),
        "{response}"
    );
}

/// Negative — generic SigV4 forms keep the existing policy ceiling too.
#[tokio::test]
async fn n_generic_sigv4_policy_bytes_keep_the_existing_form_ceiling() {
    let policy = padded_policy::<LARGE>(V4_DOCUMENT.as_bytes());
    let (status, response, stored) = generic_post(&v4_fields(&policy, V4_LARGE_SIGNATURE)).await;
    assert_eq!(
        (status, response.contains("<Code>MalformedPOSTRequest</Code>"), stored),
        (StatusCode::BAD_REQUEST, true, None),
        "{response}"
    );
}

/// Negative — valid JSON and a signature one base64 quartet past 1 MiB cannot write via SigV2.
#[tokio::test]
async fn n_legacy_sigv2_policy_bytes_above_one_mebibyte_cannot_write() {
    let policy = padded_policy::<{ LEGACY_DECODED_EDGE + 1 }>(POLICY);
    let signature = signed_policy(&policy);
    let (status, response, stored) = post(true, &fields(&policy, &signature), "hello").await;
    assert_eq!(
        (status, response.contains("<Code>MalformedPOSTRequest</Code>"), stored),
        (StatusCode::BAD_REQUEST, true, None),
        "{response}"
    );
}

/// Negative — the same one-quartet overrun cannot write via SigV4.
#[tokio::test]
async fn n_legacy_sigv4_policy_bytes_above_one_mebibyte_cannot_write() {
    let policy = padded_policy::<{ LEGACY_DECODED_EDGE + 1 }>(V4_DOCUMENT.as_bytes());
    let (status, response, stored) = post(true, &v4_fields(&policy, V4_OVER_SIGNATURE), "hello").await;
    assert_eq!(
        (status, response.contains("<Code>MalformedPOSTRequest</Code>"), stored),
        (StatusCode::BAD_REQUEST, true, None),
        "{response}"
    );
}

/// Negative — the larger SigV2 policy still owes its exact signature.
#[tokio::test]
async fn n_legacy_policy_bytes_do_not_bypass_sigv2_verification() {
    let policy = padded_policy::<LARGE>(POLICY);
    let signature = SigV2Signer::new("AKIDEXAMPLE", b"wrong")
        .expect("valid fixture signer")
        .post_policy_signature(&policy);
    let (status, response, stored) = post(true, &fields(&policy, &signature), "hello").await;
    assert_eq!(
        (status, response.contains("<Code>SignatureDoesNotMatch</Code>"), stored),
        (StatusCode::FORBIDDEN, true, None),
        "{response}"
    );
}

/// Negative — the larger SigV4 policy still owes its exact signature.
#[tokio::test]
async fn n_legacy_policy_bytes_do_not_bypass_sigv4_verification() {
    let policy = padded_policy::<LARGE>(V4_DOCUMENT.as_bytes());
    let (status, response, stored) = post(true, &v4_fields(&policy, V4_WRONG_SIGNATURE), "hello").await;
    assert_eq!(
        (status, response.contains("<Code>SignatureDoesNotMatch</Code>"), stored),
        (StatusCode::FORBIDDEN, true, None),
        "{response}"
    );
}

async fn object_path_post(signature: &str) -> (StatusCode, String, Option<(String, Vec<u8>)>) {
    let policy = padded_policy::<LARGE>(V4_DOCUMENT.as_bytes());
    post_at_uri(
        true,
        &v4_fields(&policy, signature),
        "hello",
        Credentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials"),
        true,
        "http://host.invalid/example-bucket/upload",
        true,
    )
    .await
}

/// Negative — a valid large object-path form is refused for its method after authenticating.
#[tokio::test]
async fn n_legacy_policy_bytes_reach_the_unrouted_method_refusal() {
    let (status, response, stored) = object_path_post(V4_LARGE_SIGNATURE).await;
    assert_eq!(
        (status, response.contains("<Code>MethodNotAllowed</Code>"), stored),
        (StatusCode::METHOD_NOT_ALLOWED, true, None),
        "{response}"
    );
}

/// Negative — object-path refusal cannot conceal a forged policy signature.
#[tokio::test]
async fn n_legacy_policy_bytes_do_not_bypass_unrouted_authentication() {
    let (status, response, stored) = object_path_post(V4_WRONG_SIGNATURE).await;
    assert_eq!(
        (status, response.contains("<Code>SignatureDoesNotMatch</Code>"), stored),
        (StatusCode::FORBIDDEN, true, None),
        "{response}"
    );
}
