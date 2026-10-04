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

//! RustFS's absent payload header under an STS-scoped header signature (rustfs/gateway#1230).
//!
//! Responsible for: the 8192-byte inclusive bound, lookup/read/comparison ordering, independent
//! body-digest signing and replay into streaming and buffered S3 operations.
//! NOT responsible for: STS operation selection or credentials issued by an STS backend.
//! Upstream: the assembled facade with the RustFS signature readings. Downstream: none.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use rustfs_gateway::{
    BoxFuture, CredentialLookup, CredentialProvider, Credentials, Handler, HandlerResult, ProviderError, Req, Resp, S3Service,
    ServiceBuilder, SigV4Authenticator, allow_when, dto,
};
use sha2::{Digest as _, Sha256};

use crate::support;

#[derive(Default)]
struct Record {
    events: Vec<&'static str>,
    stored: Vec<Vec<u8>>,
}

struct Backend(Arc<Mutex<Record>>);

impl Handler<dto::PutObject> for Backend {
    async fn call(&self, request: Req<dto::PutObject>) -> HandlerResult<dto::PutObject> {
        self.0.lock().expect("the record is never poisoned").events.push("handler");
        let bytes = request
            .into_input()
            .body
            .expect("the decoded upload has a body")
            .into_body()
            .collect()
            .await
            .expect("a verified fixture body")
            .to_bytes();
        self.0
            .lock()
            .expect("the record is never poisoned")
            .stored
            .push(bytes.to_vec());
        Ok(Resp::new(dto::PutObjectOutput::default()))
    }
}

impl Handler<dto::PutBucketPolicy> for Backend {
    async fn call(&self, request: Req<dto::PutBucketPolicy>) -> HandlerResult<dto::PutBucketPolicy> {
        let mut record = self.0.lock().expect("the record is never poisoned");
        record.events.push("handler");
        record.stored.push(request.into_input().policy.as_bytes().to_vec());
        Ok(Resp::new(dto::PutBucketPolicyOutput::default()))
    }
}

impl Handler<dto::PostObject> for Backend {
    async fn call(&self, _request: Req<dto::PostObject>) -> HandlerResult<dto::PostObject> {
        self.0.lock().expect("the record is never poisoned").events.push("handler");
        Ok(Resp::new(dto::PostObjectOutput::default()))
    }
}

struct Provider(Arc<Mutex<Record>>);

impl CredentialProvider for Provider {
    fn lookup<'a>(&'a self, access_key: &'a str) -> BoxFuture<'a, Result<CredentialLookup, ProviderError>> {
        Box::pin(async move {
            self.0.lock().expect("the record is never poisoned").events.push("lookup");
            Ok(if access_key == "AKIDEXAMPLE" {
                CredentialLookup::Found(Credentials::new(access_key, b"secret").expect("a valid credential"))
            } else {
                CredentialLookup::NotFound
            })
        })
    }
}

fn service() -> (S3Service, Arc<Mutex<Record>>) {
    let record = Arc::new(Mutex::new(Record::default()));
    let backend = Arc::new(Backend(Arc::clone(&record)));
    let service = ServiceBuilder::new()
        .authenticator(
            SigV4Authenticator::new(
                Arc::new(Provider(Arc::clone(&record))),
                rustfs_gateway::RegionSet::new(["us-east-1"]).expect("non-empty"),
            )
            .accept_legacy_rustfs_signing_services(),
        )
        .authorizer(allow_when(|_| true))
        .clock_with_skew_ack(
            support::fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .answer_header_signatures_as_legacy_rustfs()
        .answer_credential_refusals_with_legacy_rustfs_sentences()
        .accept_all_checksum_omissions()
        .register::<dto::PutObject, _>(Arc::clone(&backend))
        .register::<dto::PutBucketPolicy, _>(Arc::clone(&backend))
        .register::<dto::PostObject, _>(backend)
        .build()
        .expect("a complete assembly");
    (service, record)
}

struct Frames {
    frames: VecDeque<Bytes>,
    record: Arc<Mutex<Record>>,
}

impl http_body::Body for Frames {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: core::pin::Pin<&mut Self>,
        _context: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(bytes) = this.frames.pop_front() {
            this.record.lock().expect("the record is never poisoned").events.push("body");
            core::task::Poll::Ready(Some(Ok(http_body::Frame::data(bytes))))
        } else {
            core::task::Poll::Ready(None)
        }
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The signer is independent of the gateway's signer and canonical request builder.
fn signed(target: &str, service: &str, key_id: &str, secret: &str, signed_body: &[u8], body: Bytes) -> Request<Bytes> {
    signed_method(Method::PUT, target, service, key_id, secret, signed_body, body)
}

fn signed_method(
    method: Method,
    target: &str,
    service: &str,
    key_id: &str,
    secret: &str,
    signed_body: &[u8],
    body: Bytes,
) -> Request<Bytes> {
    let stamp = support::SIGNED_AT_STAMP;
    let day = &stamp[..8];
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let query = if query.is_empty() {
        String::new()
    } else {
        format!("{query}=")
    };
    let scope = format!("{day}/us-east-1/{service}/aws4_request");
    let canonical = format!(
        "{method}\n{path}\n{query}\nhost:s3.example.com\nx-amz-date:{stamp}\n\nhost;x-amz-date\n{}",
        hex(&Sha256::digest(signed_body))
    );
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}", hex(&Sha256::digest(canonical.as_bytes())));
    let mut key = hmac(format!("AWS4{secret}").as_bytes(), day.as_bytes());
    for part in ["us-east-1", service, "aws4_request"] {
        key = hmac(&key, part.as_bytes());
    }
    let signature = hex(&hmac(&key, string_to_sign.as_bytes()));
    Request::builder()
        .method(method)
        .uri(target)
        .header("host", "s3.example.com")
        .header("x-amz-date", stamp)
        .header(
            "authorization",
            format!("AWS4-HMAC-SHA256 Credential={key_id}/{scope}, SignedHeaders=host;x-amz-date, Signature={signature}"),
        )
        .body(body)
        .expect("a valid request")
}

async fn exchange(request: Request<Bytes>, chunked: bool) -> (StatusCode, String, Arc<Mutex<Record>>) {
    let (service, record) = service();
    let (mut parts, body) = request.into_parts();
    if chunked {
        parts
            .headers
            .insert("transfer-encoding", http::HeaderValue::from_static("chunked"));
    } else {
        parts
            .headers
            .insert("content-length", body.len().to_string().parse().expect("an integer length"));
    }
    let frames = if chunked {
        body.chunks(997).map(Bytes::copy_from_slice).collect()
    } else {
        VecDeque::from([body])
    };
    let response = service
        .call(Request::from_parts(
            parts,
            Frames {
                frames,
                record: Arc::clone(&record),
            },
        ))
        .await;
    let wire = rustfs_gateway::collect(response).await.expect("a complete response");
    (wire.status(), String::from_utf8(wire.body().to_vec()).expect("utf-8"), record)
}

fn refused(status: StatusCode, body: &str, record: &Arc<Mutex<Record>>, expected_status: StatusCode, code: &str) {
    let record = record.lock().expect("the record is never poisoned");
    assert!(!record.events.contains(&"handler"), "a refused request ran its handler");
    assert!(record.stored.is_empty(), "a refused request stored bytes");
    assert_eq!(status, expected_status, "{body}");
    assert!(body.contains(&format!("<Code>{code}</Code>")), "{body}");
}

/// Positive — the digest covers the actual body, at the inclusive boundary too; replay reaches
/// both a streaming upload and a buffered operation, under either HTTP framing.
#[tokio::test]
async fn the_sts_body_is_hashed_and_replayed_once_at_and_below_the_bound() {
    for size in [0, 3, 5000, 8192] {
        let bytes = Bytes::from(vec![b'a'; size]);
        let (status, body, record) =
            exchange(signed("/bucket/key", "sts", "AKIDEXAMPLE", "secret", &bytes, bytes.clone()), false).await;
        assert_eq!(status, StatusCode::OK, "{size}: {body}");
        let record = record.lock().expect("the record is never poisoned");
        assert_eq!(record.stored, vec![bytes.to_vec()]);
        assert_eq!(record.events.first(), Some(&"lookup"));
        assert_eq!(record.events.last(), Some(&"handler"), "body was not read before dispatch");
        assert_eq!(record.events.iter().filter(|event| **event == "body").count(), 1, "transport was reread");
    }
    for chunked in [false, true] {
        let mut policy = b"{\"Version\":\"2012-10-17\",\"Statement\":[]}".to_vec();
        policy.resize(8192, b' ');
        let policy = Bytes::from(policy);
        let (status, body, record) =
            exchange(signed("/bucket?policy", "sts", "AKIDEXAMPLE", "secret", &policy, policy.clone()), chunked).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(record.lock().expect("the record is never poisoned").stored, vec![policy.to_vec()]);
    }
}

/// Negative — the ordinary upload's length requirement stays in place after hashing; chunked
/// bodies reach the body-signature check, but do not acquire a Content-Length they never sent.
#[tokio::test]
async fn n_a_chunked_put_keeps_its_missing_length_refusal_after_sts_verification() {
    for size in [3, 8192] {
        let bytes = Bytes::from(vec![b'a'; size]);
        let (status, body, record) =
            exchange(signed("/bucket/key", "sts", "AKIDEXAMPLE", "secret", &bytes, bytes.clone()), true).await;
        refused(status, &body, &record, StatusCode::LENGTH_REQUIRED, "MissingContentLength");
        let record = record.lock().expect("the record is never poisoned");
        assert_eq!(record.events.first(), Some(&"lookup"));
        assert_eq!(record.events.iter().filter(|event| **event == "body").count(), size.div_ceil(997));
    }
}

/// Negative — a browser form keeps its existing signature refusal, rather than entering the
/// ordinary STS hash read. Its bounded credential prelude is still prepared first.
#[tokio::test]
async fn n_a_browser_form_does_not_enter_the_ordinary_sts_body_hash_read() {
    let body = Bytes::from(format!(
        "--form\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nk\r\n--form\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f\"\r\n\r\n{}\r\n--form--\r\n",
        "a".repeat(9000)
    ));
    let mut request = signed_method(Method::POST, "/bucket", "sts", "AKIDEXAMPLE", "secret", &body, body.clone());
    request
        .headers_mut()
        .insert("content-type", http::HeaderValue::from_static("multipart/form-data; boundary=form"));
    let (status, body, record) = exchange(request, false).await;
    refused(status, &body, &record, StatusCode::FORBIDDEN, "SignatureDoesNotMatch");
    assert_eq!(record.lock().expect("the record is never poisoned").events, ["body", "lookup"]);
}

/// Negative — the bound is decided before signature comparison, even for the wrong secret.
#[tokio::test]
async fn n_an_sts_body_past_the_bound_is_invalid_request_before_comparison() {
    for size in [8193, 9000, 100000] {
        for chunked in [false, true] {
            for secret in ["secret", "wrong-secret"] {
                let bytes = Bytes::from(vec![b'a'; size]);
                let (status, body, record) =
                    exchange(signed("/bucket/key", "sts", "AKIDEXAMPLE", secret, &bytes, bytes.clone()), chunked).await;
                refused(status, &body, &record, StatusCode::BAD_REQUEST, "InvalidRequest");
                assert!(
                    body.contains("<Message>failed to read STS request body: length limit exceeded</Message>"),
                    "{body}"
                );
                assert_eq!(record.lock().expect("the record is never poisoned").events.first(), Some(&"lookup"));
            }
        }
    }
}

/// Negative — an unknown key is refused before any body byte, even above the body bound.
#[tokio::test]
async fn n_an_unknown_sts_key_is_refused_without_polling_its_body() {
    for size in [3, 8193, 100000] {
        for chunked in [false, true] {
            let bytes = Bytes::from(vec![b'a'; size]);
            let (status, body, record) =
                exchange(signed("/bucket/key", "sts", "UNKNOWNKEY", "secret", &bytes, bytes.clone()), chunked).await;
            refused(status, &body, &record, StatusCode::FORBIDDEN, "InvalidAccessKeyId");
            assert_eq!(record.lock().expect("the record is never poisoned").events, ["lookup"]);
        }
    }
}

/// Negative — small bodies signed with another secret, with the empty digest, or over other
/// bytes are refused; the lookup and bounded read still precede that refusal.
#[tokio::test]
async fn n_a_wrong_sts_body_signature_cannot_execute_or_store_anything() {
    for chunked in [false, true] {
        for (secret, signed_bytes) in [("wrong-secret", b"abc".as_slice()), ("secret", b""), ("secret", b"abd")] {
            let (status, body, record) = exchange(
                signed("/bucket/key", "sts", "AKIDEXAMPLE", secret, signed_bytes, Bytes::from_static(b"abc")),
                chunked,
            )
            .await;
            refused(status, &body, &record, StatusCode::FORBIDDEN, "SignatureDoesNotMatch");
            assert_eq!(record.lock().expect("the record is never poisoned").events, ["lookup", "body"]);
        }
    }
}

/// Negative — this exception does not admit an absent payload header in either S3 scope.
#[tokio::test]
async fn n_s3_and_s3tables_keep_the_missing_payload_header_refusal() {
    for scope in ["s3", "s3tables"] {
        let (status, body, record) = exchange(
            signed("/bucket/key", scope, "AKIDEXAMPLE", "secret", b"abc", Bytes::from_static(b"abc")),
            false,
        )
        .await;
        refused(status, &body, &record, StatusCode::BAD_REQUEST, "InvalidRequest");
        assert!(body.contains("<Message>missing header: x-amz-content-sha256</Message>"), "{body}");
        assert!(record.lock().expect("the record is never poisoned").events.is_empty());
    }
}
