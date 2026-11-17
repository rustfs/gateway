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

//! Signed browser forms whose key refers to the file-part name.
//!
//! Responsible for: checking the actual file name against the signed policy before storage.
//! NOT responsible for: individual multipart parser rules or signature primitives.
//! Upstream: a complete gateway service. Downstream: an in-memory observing handler.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use rustfs_gateway::dto::{PostObject, PostObjectOutput};
use rustfs_gateway::{Handler, HandlerError, HandlerResult, Req, Resp};
use rustfs_gateway_sig::codec::encode_base64_exact;
use sha2::{Digest as _, Sha256};

use crate::support;

const BOUNDARY: &str = "signed-filename";
const POLICY: &[u8; 257] = br#"{"expiration":"2026-01-02T04:04:05Z","conditions":[{"bucket":"example-bucket"},["starts-with","$key","uploads/"],{"x-amz-algorithm":"AWS4-HMAC-SHA256"},{"x-amz-credential":"AKIDEXAMPLE/20260102/us-east-1/s3/aws4_request"},{"x-amz-date":"20260102T030405Z"}]}"#;
const EXACT_POLICY: &[u8; 254] = br#"{"expiration":"2026-01-02T04:04:05Z","conditions":[{"bucket":"example-bucket"},{"key":"uploads/approved.txt"},{"x-amz-algorithm":"AWS4-HMAC-SHA256"},{"x-amz-credential":"AKIDEXAMPLE/20260102/us-east-1/s3/aws4_request"},{"x-amz-date":"20260102T030405Z"}]}"#;

#[derive(Default)]
struct Backend(Mutex<Vec<(String, Bytes)>>);

impl Handler<PostObject> for Backend {
    async fn call(&self, request: Req<PostObject>) -> HandlerResult<PostObject> {
        let constraints = request
            .context()
            .post_object_key_constraints()
            .ok_or_else(|| HandlerError::internal_error("the signed form key constraints are missing"))?;
        assert!(constraints.permits(request.input().key.as_str()));
        assert!(!constraints.permits("outside/untrusted"));
        let input = request.into_input();
        let key = input.key.as_str().to_owned();
        let bytes = input
            .body
            .into_body()
            .collect()
            .await
            .map_err(|_| HandlerError::internal_error("the form body failed"))?
            .to_bytes();
        self.0
            .lock()
            .map_err(|_| HandlerError::internal_error("the observation lock failed"))?
            .push((key, bytes));
        Ok(Resp::new(PostObjectOutput {
            e_tag: None,
            version_id: None,
        }))
    }
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut block = [0_u8; 64];
    block[..key.len()].copy_from_slice(key);
    let mut inner = Sha256::new();
    inner.update(block.map(|byte| byte ^ 0x36));
    inner.update(data);
    let mut outer = Sha256::new();
    outer.update(block.map(|byte| byte ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

fn signed_form(key: &str, filename: Option<&str>, tamper: bool, exact: bool) -> Vec<u8> {
    let policy = if exact {
        encode_base64_exact(EXACT_POLICY)
    } else {
        encode_base64_exact(POLICY)
    };
    let mut signing_key = hmac(b"AWS4secret", b"20260102");
    for part in ["us-east-1", "s3", "aws4_request"] {
        signing_key = hmac(&signing_key, part.as_bytes());
    }
    let signature: String = hmac(&signing_key, policy.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let signature = if tamper { "0".repeat(64) } else { signature };
    let fields = [
        ("bucket", "example-bucket"),
        ("key", key),
        ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
        ("x-amz-credential", "AKIDEXAMPLE/20260102/us-east-1/s3/aws4_request"),
        ("x-amz-date", "20260102T030405Z"),
        ("policy", policy.as_str()),
        ("x-amz-signature", signature.as_str()),
    ];
    let mut body = Vec::new();
    for (name, value) in fields {
        body.extend_from_slice(
            format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n").as_bytes(),
        );
    }
    let filename = filename.map_or_else(String::new, |value| format!("; filename=\"{value}\""));
    body.extend_from_slice(
        format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"{filename}\r\n\r\ncontent\r\n--{BOUNDARY}--\r\n")
            .as_bytes(),
    );
    body
}

async fn send(
    legacy: bool,
    declared: bool,
    key: &str,
    filename: Option<&str>,
    tamper: bool,
    exact: bool,
) -> (StatusCode, String, Vec<(String, Bytes)>) {
    let backend = Arc::new(Backend::default());
    let builder = support::wired_at_signed_time().register::<PostObject, _>(Arc::clone(&backend));
    let service = if legacy { builder.legacy_rustfs_post_forms() } else { builder }
        .build()
        .expect("complete service");
    let body = signed_form(key, filename, tamper, exact);
    let mut request = Request::builder()
        .method("POST")
        .uri("http://host.invalid/example-bucket")
        .header("host", "host.invalid")
        .header("content-type", format!("multipart/form-data; boundary={BOUNDARY}"));
    if declared {
        request = request.header("content-length", body.len());
    }
    let (status, body) = support::exchange(&service, request.body(Bytes::from(body)).expect("valid request")).await;
    let stored = backend.0.lock().expect("observation lock").clone();
    (status, body, stored)
}

#[tokio::test]
async fn signed_filename_is_resolved_for_both_profiles_and_body_lengths() {
    for legacy in [false, true] {
        for declared in [false, true] {
            let (status, _, stored) = send(legacy, declared, "uploads/${filename}", Some("report.txt"), false, false).await;
            assert_eq!(status, StatusCode::NO_CONTENT, "legacy={legacy}, declared={declared}");
            assert_eq!(stored, vec![("uploads/report.txt".to_owned(), Bytes::from_static(b"content"))]);
        }
    }
}

#[tokio::test]
async fn signed_filename_does_not_bypass_signature_verification() {
    let (status, body, stored) = send(true, true, "uploads/${filename}", Some("report.txt"), true, false).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"), "{body}");
    assert!(stored.is_empty());
}

#[tokio::test]
async fn signed_filename_does_not_bypass_the_key_prefix() {
    let (status, body, stored) = send(true, true, "other/${filename}", Some("report.txt"), false, false).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("<Code>InvalidAccessKeyId</Code>"), "{body}");
    assert!(stored.is_empty());
}

#[tokio::test]
async fn missing_filename_is_not_admitted_by_the_gateway_profile() {
    let (status, _, stored) = send(false, true, "uploads/${filename}", None, false, false).await;
    assert!(!status.is_success());
    assert!(stored.is_empty());
    let (status, _, stored) = send(false, true, "uploads/fixed", None, false, false).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(stored, vec![("uploads/fixed".to_owned(), Bytes::from_static(b"content"))]);
}

#[tokio::test]
async fn legacy_filename_cannot_change_the_stored_key_after_policy_resolution() {
    let (status, body, stored) = send(true, true, "uploads/${filename}", Some("../report.txt"), false, false).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert!(body.contains("<Code>NotImplemented</Code>"), "{body}");
    assert!(stored.is_empty());
}

#[tokio::test]
async fn signed_exact_key_requires_the_resolved_filename() {
    for legacy in [false, true] {
        let (status, _, stored) = send(legacy, true, "uploads/${filename}", Some("approved.txt"), false, true).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "legacy={legacy}");
        assert_eq!(stored, vec![("uploads/approved.txt".to_owned(), Bytes::from_static(b"content"))]);
        let (status, body, stored) = send(legacy, true, "uploads/${filename}", Some("other.txt"), false, true).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "legacy={legacy}");
        assert!(body.contains("<Code>InvalidAccessKeyId</Code>"), "{body}");
        assert!(stored.is_empty());
    }
}
