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

//! SigV2 browser forms through the real multipart reader and authentication pipeline.
//!
//! Responsible for: opt-in verification and for proving refusals never commit object bytes.
//! NOT responsible for: storage implementation or multipart grammar edge cases.
//! Upstream: the RustFS compatibility settings. Downstream: the integration test target.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use rustfs_gateway::dto::{PostObject, PostObjectOutput};
use rustfs_gateway::{
    Credentials, Handler, HandlerError, HandlerResult, RegionSet, Req, Resp, SigV4Authenticator, StaticCredentials, allow_when,
};
use rustfs_gateway_sig::{SecurityFloor, SessionBinding, SigV2Signer, codec::encode_base64_exact};

use crate::support;

const POLICY: &[u8; 127] = br#"{"expiration":"2026-01-02T04:04:05Z","conditions":[{"bucket":"example-bucket"},{"key":"upload"},["content-length-range",1,16]]}"#;
const BOUNDARY: &str = "sigv2-browser-form";

#[derive(Default)]
struct Backend {
    stored: Mutex<Option<(String, Vec<u8>)>>,
}

impl Handler<PostObject> for Backend {
    async fn call(&self, request: Req<PostObject>) -> HandlerResult<PostObject> {
        let input = request.into_input();
        let mut body = input.body.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| HandlerError::internal_error("the POST file stream failed"))?;
            if let Ok(data) = frame.into_data() {
                bytes.extend_from_slice(&data);
            }
        }
        *self.stored.lock().expect("observation lock") = Some((input.key.as_str().to_owned(), bytes));
        Ok(Resp::new(PostObjectOutput {
            e_tag: None,
            version_id: None,
        }))
    }
}

async fn post(opt_in: bool, fields: &[(&str, &str)], file: &str) -> (StatusCode, String, Option<(String, Vec<u8>)>) {
    post_with_credentials(
        opt_in,
        fields,
        file,
        Credentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials"),
        true,
    )
    .await
}

async fn post_with_credentials(
    opt_in: bool,
    fields: &[(&str, &str)],
    file: &str,
    credentials: Credentials,
    legacy_forms: bool,
) -> (StatusCode, String, Option<(String, Vec<u8>)>) {
    let backend = Arc::new(Backend::default());
    let floor = if opt_in {
        SecurityFloor::new()
            .enable_sigv2_presigned_compatibility()
            .recognize_signatures_as_legacy_rustfs()
    } else {
        SecurityFloor::new()
    };
    let builder = support::wired_at_signed_time()
        .authenticator(SigV4Authenticator::new(
            Arc::new(StaticCredentials::new().with(credentials)),
            RegionSet::new(["us-east-1"]).expect("non-empty"),
        ))
        .register::<PostObject, _>(Arc::clone(&backend))
        .security_floor(floor)
        .authorizer(allow_when(|request| request.identity.is_some()));
    let builder = if legacy_forms {
        builder.legacy_rustfs_post_forms()
    } else {
        builder
    };
    let service = builder.build().expect("complete service");
    let mut body = String::new();
    for (name, value) in fields {
        body.push_str(&format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        ));
    }
    body.push_str(&format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"upload\"\r\nContent-Type: application/octet-stream\r\n\r\n{file}\r\n--{BOUNDARY}--\r\n"));
    let request = Request::builder()
        .method("POST")
        .uri("http://host.invalid/example-bucket")
        .header("host", "host.invalid")
        .header("content-type", format!("multipart/form-data; boundary={BOUNDARY}"))
        .header("content-length", body.len())
        .body(Bytes::from(body))
        .expect("valid request");
    let (status, response) = support::exchange(&service, request).await;
    let stored = backend.stored.lock().expect("observation lock").clone();
    (status, response, stored)
}

fn fields<'a>(policy: &'a str, signature: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("key", "upload"),
        ("AWSAccessKeyId", "AKIDEXAMPLE"),
        ("policy", policy),
        ("signature", signature),
    ]
}

#[tokio::test]
async fn a_sigv2_browser_form_stores_only_after_authentication() {
    let policy = encode_base64_exact(POLICY);
    // Independently computed with Python hmac/hashlib over the base64 policy.
    let signature = "2ZkeVZV3N4SN7bWn9jlgrNF9b5A=";
    let (status, response, stored) = post(true, &fields(&policy, signature), "hello").await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{response}");
    assert_eq!(stored, Some(("upload".to_owned(), b"hello".to_vec())));
}

#[tokio::test]
async fn the_default_floor_refuses_sigv2_browser_forms() {
    let policy = encode_base64_exact(POLICY);
    let signature = SigV2Signer::new("AKIDEXAMPLE", b"secret")
        .expect("valid signer")
        .post_policy_signature(&policy);
    let (status, _, stored) = post(false, &fields(&policy, &signature), "hello").await;
    assert!(!status.is_success());
    assert_eq!(stored, None);
}

#[tokio::test]
async fn a_wrong_secret_cannot_store_an_object() {
    let policy = encode_base64_exact(POLICY);
    let signature = SigV2Signer::new("AKIDEXAMPLE", b"wrong")
        .expect("valid signer")
        .post_policy_signature(&policy);
    let (status, response, stored) = post(true, &fields(&policy, &signature), "hello").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(response.contains("<Code>SignatureDoesNotMatch</Code>"));
    assert_eq!(stored, None);
}

fn signed_policy(policy: &str) -> String {
    SigV2Signer::new("AKIDEXAMPLE", b"secret")
        .expect("valid signer")
        .post_policy_signature(policy)
}

#[tokio::test]
async fn an_expired_policy_cannot_store_an_object() {
    let policy = encode_base64_exact(
        br#"{"expiration":"2026-01-02T03:04:04Z","conditions":[{"bucket":"example-bucket"},{"key":"upload"}]}"#,
    );
    let signature = signed_policy(&policy);
    let (status, response, stored) = post(true, &fields(&policy, &signature), "hello").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(response.contains("<Code>AccessDenied</Code>"));
    assert_eq!(stored, None);
}

#[tokio::test]
async fn a_policy_for_another_bucket_cannot_store_an_object() {
    let policy = encode_base64_exact(
        br#"{"expiration":"2026-01-02T04:04:05Z","conditions":[{"bucket":"other-bucket"},{"key":"upload"}]}"#,
    );
    let signature = signed_policy(&policy);
    let (status, response, stored) = post(true, &fields(&policy, &signature), "hello").await;
    // Measured against legacy RustFS; gateway#1185 records the HTTP comparison.
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(response.contains("<Code>InvalidPolicyDocument</Code>"), "{response}");
    assert_eq!(stored, None);
}

#[tokio::test]
async fn changing_the_key_cannot_store_an_object() {
    let policy = encode_base64_exact(POLICY);
    let signature = signed_policy(&policy);
    let mut fields = fields(&policy, &signature);
    fields[0].1 = "another-key";
    let (status, response, stored) = post(true, &fields, "hello").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(response.contains("<Code>InvalidPolicyDocument</Code>"));
    assert_eq!(stored, None);
}

#[tokio::test]
async fn a_file_outside_the_policy_range_cannot_be_committed() {
    let policy = encode_base64_exact(POLICY);
    let signature = signed_policy(&policy);
    for (file, code) in [("", "EntityTooSmall"), ("12345678901234567", "EntityTooLarge")] {
        let (status, response, stored) = post(true, &fields(&policy, &signature), file).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
        assert!(response.contains(&format!("<Code>{code}</Code>")), "{response}");
        assert_eq!(stored, None);
    }
}

#[tokio::test]
async fn both_file_size_boundaries_are_accepted() {
    let policy = encode_base64_exact(POLICY);
    let signature = signed_policy(&policy);
    for file in ["1", "1234567890123456"] {
        let (status, response, stored) = post(true, &fields(&policy, &signature), file).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{response}");
        assert_eq!(stored, Some(("upload".to_owned(), file.as_bytes().to_vec())));
    }
}

fn temporary_credentials() -> Credentials {
    Credentials::new("AKIDEXAMPLE", b"secret")
        .expect("valid credentials")
        .with_session(
            "session-token",
            SessionBinding::new("sts.example.com", support::SIGNED_AT_UNIX_SECONDS + 3600).expect("valid session"),
        )
        .expect("valid token")
}

#[tokio::test]
async fn a_session_token_is_required_for_temporary_credentials() {
    let policy = encode_base64_exact(POLICY);
    let signature = signed_policy(&policy);
    for token in [None, Some("wrong-token")] {
        let mut fields = fields(&policy, &signature);
        if let Some(token) = token {
            fields.push(("x-amz-security-token", token));
        }
        let (status, response, stored) = post_with_credentials(true, &fields, "hello", temporary_credentials(), true).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(response.contains("<Code>InvalidAccessKeyId</Code>"));
        assert_eq!(stored, None);
    }
}

#[tokio::test]
async fn a_valid_session_token_allows_the_signed_upload() {
    let policy = encode_base64_exact(POLICY);
    let signature = signed_policy(&policy);
    let mut fields = fields(&policy, &signature);
    fields.push(("x-amz-security-token", "session-token"));
    let (status, response, stored) = post_with_credentials(true, &fields, "hello", temporary_credentials(), true).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{response}");
    assert_eq!(stored, Some(("upload".to_owned(), b"hello".to_vec())));
}

#[tokio::test]
async fn a_case_variant_cannot_hide_a_second_access_key() {
    let policy = encode_base64_exact(POLICY);
    let signature = signed_policy(&policy);
    let mut fields = fields(&policy, &signature);
    fields.push(("awsaccesskeyid", "AKIDEXAMPLE"));
    let (status, _, stored) = post(true, &fields, "hello").await;
    assert!(!status.is_success());
    assert_eq!(stored, None);
}

#[tokio::test]
async fn the_generic_form_grammar_keeps_its_stream_failure_code() {
    let policy = encode_base64_exact(POLICY);
    let signature = signed_policy(&policy);
    for file in ["", "12345678901234567"] {
        let (status, response, stored) = post_with_credentials(
            true,
            &fields(&policy, &signature),
            file,
            Credentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials"),
            false,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
        assert!(response.contains("<Code>IncompleteBody</Code>"), "{response}");
        assert_eq!(stored, None);
    }
}

// Ordering measured on legacy RustFS; gateway#1185 records the separate binary identity.
#[tokio::test]
async fn forged_signatures_hide_policy_document_failures() {
    let policies = [
        encode_base64_exact(POLICY),
        encode_base64_exact(br#"{"expiration":"2026-01-02T03:04:04Z","conditions":[{"key":"upload"}]}"#),
        encode_base64_exact(b"{"),
    ];
    for policy in policies {
        let signature = SigV2Signer::new("AKIDEXAMPLE", b"wrong")
            .expect("valid signer")
            .post_policy_signature(&policy);
        let mut fields = fields(&policy, &signature);
        fields[0].1 = "another-key";
        let (status, response, stored) = post(true, &fields, "hello").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{response}");
        assert!(response.contains("<Code>SignatureDoesNotMatch</Code>"), "{response}");
        assert_eq!(stored, None);
    }
}

#[tokio::test]
async fn signed_malformed_json_is_an_invalid_policy_document() {
    let policy = encode_base64_exact(b"{");
    let signature = signed_policy(&policy);
    let (status, response, stored) = post(true, &fields(&policy, &signature), "hello").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert!(response.contains("<Code>InvalidPolicyDocument</Code>"), "{response}");
    assert_eq!(stored, None);
}

#[tokio::test]
async fn invalid_policy_encoding_is_refused_before_signature_comparison() {
    for policy in ["not-base64", "e===", "e0==", "e30"] {
        for secret in [b"secret".as_slice(), b"wrong".as_slice()] {
            let signature = SigV2Signer::new("AKIDEXAMPLE", secret)
                .expect("valid signer")
                .post_policy_signature(policy);
            let (status, response, stored) = post(true, &fields(policy, &signature), "hello").await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
            assert!(response.contains("<Code>InvalidRequest</Code>"), "{response}");
            assert_eq!(stored, None);
        }
    }
}

#[tokio::test]
async fn generic_forms_keep_their_policy_condition_error() {
    let policy = encode_base64_exact(POLICY);
    let signature = signed_policy(&policy);
    let mut fields = fields(&policy, &signature);
    fields[0].1 = "another-key";
    let (status, response, stored) = post_with_credentials(
        true,
        &fields,
        "hello",
        Credentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials"),
        false,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{response}");
    assert!(response.contains("<Code>AccessDenied</Code>"), "{response}");
    assert_eq!(stored, None);
}
