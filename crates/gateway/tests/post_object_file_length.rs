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

//! The length a POST Object handler is handed for the file, under the RustFS profile
//! (rustfs/gateway#1167).
//!
//! Responsible for: `PostObjectInput::body` reporting the file's exact length when the request
//! declared its body's and the legacy grammar fixes the file's from it — preamble, padding and a
//! multi-frame file included — and no length otherwise; and the policy's size range judged on that
//! length before the handler runs.
//! NOT responsible for: the grammar (`post_object_legacy_form.rs`), the members a form sets
//! (`post_object_legacy_fields.rs`) or SigV2 verification (`post_object_sigv2.rs`).
//! Upstream: the facade's public API. Downstream: nothing.
//!
//! Evidence: legacy RustFS derives a form file's exact length as the declared body length less
//! every byte before the file and the closing `\r\n--boundary--\r\n`, hands its handler that
//! length, and judges the policy's conditions on it before the handler runs; without a declared
//! length it reads the whole file first (rustfs/gateway#1167, read against the legacy stack at
//! rustfs/rustfs `e870a6d25b` and confirmed on it). Its upload path refuses a form upload it is
//! handed no length for (`rustfs/src/app/object/put.rs:91-116` at rustfs/rustfs@95268a3b9).

#![allow(clippy::expect_used)]

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use rustfs_gateway::dto::{PostObject, PostObjectOutput};
use rustfs_gateway::{
    Credentials, Handler, HandlerError, HandlerResult, RegionSet, Req, Resp, S3Service, SigV4Authenticator, StaticCredentials,
    allow_when,
};
use rustfs_gateway_sig::{SecurityFloor, SigV2Signer, codec::encode_base64_exact};

use crate::support;

const BOUNDARY: &str = "file-length-form";
const POLICY: &[u8] =
    br#"{"expiration":"2026-01-02T04:04:05Z","conditions":[{"bucket":"example-bucket"},{"key":"upload"},["content-length-range",1,16]]}"#;

/// What the handler was handed: the body's remaining length on entry, and the bytes it then read.
#[derive(Default)]
struct Backend {
    handed: Mutex<Vec<(Option<u64>, Vec<u8>)>>,
}

impl Handler<PostObject> for Backend {
    async fn call(&self, request: Req<PostObject>) -> HandlerResult<PostObject> {
        let input = request.into_input();
        let length = input.body.remaining_length().get();
        let mut body = input.body.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| HandlerError::internal_error("the POST file stream failed"))?;
            if let Ok(data) = frame.into_data() {
                bytes.extend_from_slice(&data);
            }
        }
        self.handed.lock().expect("observation lock").push((length, bytes));
        Ok(Resp::new(PostObjectOutput {
            e_tag: None,
            version_id: None,
        }))
    }
}

fn service(backend: &Arc<Backend>, legacy_forms: bool) -> S3Service {
    let credentials = Credentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials");
    let builder = support::wired_at_signed_time()
        .authenticator(SigV4Authenticator::new(
            Arc::new(StaticCredentials::new().with(credentials)),
            RegionSet::new(["us-east-1"]).expect("non-empty"),
        ))
        .register::<PostObject, _>(Arc::clone(backend))
        .security_floor(
            SecurityFloor::new()
                .enable_sigv2_presigned_compatibility()
                .recognize_signatures_as_legacy_rustfs(),
        )
        .authorizer(allow_when(|_| true));
    let builder = if legacy_forms {
        builder.legacy_rustfs_post_forms()
    } else {
        builder
    };
    builder.build().expect("complete service")
}

/// A form with `fields` and then `file`, opened by `preamble` and with `padding` after each
/// boundary line.
fn form(preamble: &str, padding: &str, fields: &[(&str, &str)], file: &[u8]) -> Vec<u8> {
    let mut body = preamble.as_bytes().to_vec();
    for (name, value) in fields {
        body.extend_from_slice(
            format!("--{BOUNDARY}{padding}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n").as_bytes(),
        );
    }
    body.extend_from_slice(
        format!("--{BOUNDARY}{padding}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"upload\"\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(file);
    body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    body
}

/// Posts `body`, declaring its length when `declared`; the status, the answer and what the
/// handler was handed.
async fn post(legacy_forms: bool, body: Vec<u8>, declared: bool) -> (StatusCode, String, Vec<(Option<u64>, Vec<u8>)>) {
    let backend = Arc::new(Backend::default());
    let service = service(&backend, legacy_forms);
    let mut request = Request::builder()
        .method("POST")
        .uri("http://host.invalid/example-bucket")
        .header("host", "host.invalid")
        .header("content-type", format!("multipart/form-data; boundary={BOUNDARY}"));
    if declared {
        request = request.header("content-length", body.len());
    }
    let request = request.body(Bytes::from(body)).expect("valid request");
    let (status, answer) = support::exchange(&service, request).await;
    let handed = backend.handed.lock().expect("observation lock").clone();
    (status, answer, handed)
}

fn signed(policy: &str) -> Vec<(&'static str, String)> {
    let signature = SigV2Signer::new("AKIDEXAMPLE", b"secret")
        .expect("valid signer")
        .post_policy_signature(policy);
    vec![
        ("key", "upload".to_owned()),
        ("AWSAccessKeyId", "AKIDEXAMPLE".to_owned()),
        ("policy", policy.to_owned()),
        ("signature", signature),
    ]
}

/// Positive — with a declared length the handler is handed the file's exact length, whatever
/// precedes the file: a preamble, transport padding, a second field.
#[tokio::test]
async fn the_handler_is_handed_the_file_length_legacy_rustfs_derives() {
    for (preamble, padding) in [("", ""), ("a preamble\r\n", ""), ("", " \t"), ("x", "  ")] {
        let file = b"hello world";
        let body = form(preamble, padding, &[("key", "upload"), ("x-amz-meta-a", "b")], file);
        let (status, answer, handed) = post(true, body, true).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{preamble:?} {padding:?}: {answer}");
        assert_eq!(handed, vec![(Some(file.len() as u64), file.to_vec())], "{preamble:?} {padding:?}");
    }
}

/// Positive — a file the transport delivers across many frames is handed its exact length too.
#[tokio::test]
async fn a_large_file_is_handed_its_exact_length() {
    let file = vec![b'z'; 300 * 1024 + 7];
    let (status, answer, handed) = post(true, form("", "", &[("key", "upload")], &file), true).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{answer}");
    assert_eq!(handed, vec![(Some(file.len() as u64), file)]);
}

/// Negative — without a declared length nothing fixes the file's: no length is handed over.
#[tokio::test]
async fn n_a_form_without_a_declared_length_hands_no_length() {
    let (status, answer, handed) = post(true, form("", "", &[("key", "upload")], b"hello"), false).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{answer}");
    assert_eq!(handed, vec![(None, b"hello".to_vec())]);
}

/// Negative — the gateway's own grammar fixes no file length from a declared one.
#[tokio::test]
async fn n_the_gateway_grammar_hands_no_length() {
    let (status, answer, handed) = post(false, form("", "", &[("key", "upload")], b"hello"), true).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{answer}");
    assert_eq!(handed, vec![(None, b"hello".to_vec())]);
}

/// Negative — a file whose fixed length is outside the policy's range is refused with legacy
/// RustFS's code before the handler runs at all.
#[tokio::test]
async fn n_a_fixed_length_outside_the_policy_range_never_reaches_the_handler() {
    let policy = encode_base64_exact(POLICY);
    let fields = signed(&policy);
    let fields: Vec<(&str, &str)> = fields.iter().map(|(name, value)| (*name, value.as_str())).collect();
    for (file, code) in [
        (b"".as_slice(), "EntityTooSmall"),
        (b"12345678901234567".as_slice(), "EntityTooLarge"),
    ] {
        let (status, answer, handed) = post(true, form("", "", &fields, file), true).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
        assert!(answer.contains(&format!("<Code>{code}</Code>")), "{answer}");
        assert!(handed.is_empty(), "the handler ran for a file the policy refuses: {handed:?}");
    }
}

/// Positive — the control: a fixed length inside the range reaches the handler with that length.
#[tokio::test]
async fn a_fixed_length_inside_the_policy_range_reaches_the_handler() {
    let policy = encode_base64_exact(POLICY);
    let fields = signed(&policy);
    let fields: Vec<(&str, &str)> = fields.iter().map(|(name, value)| (*name, value.as_str())).collect();
    let (status, answer, handed) = post(true, form("", "", &fields, b"1234567890123456"), true).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{answer}");
    assert_eq!(handed, vec![(Some(16), b"1234567890123456".to_vec())]);
}

/// Negative — an empty file whose length the declared body fixes is legacy RustFS's
/// `400 UnexpectedContent` before the handler runs; without a declared length the handler reads it
/// and the refusal comes at its end, as `compat-sut`'s `post_form_file_tests.rs` pins.
#[tokio::test]
async fn n_a_fixed_empty_file_never_reaches_the_handler() {
    let (status, answer, handed) = post(true, form("", "", &[("key", "upload")], b""), true).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert!(answer.contains("<Code>UnexpectedContent</Code>"), "{answer}");
    assert!(handed.is_empty(), "the handler ran for an empty file: {handed:?}");
}
