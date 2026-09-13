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

//! The run-time half of `BlockedEncryptionTypes` (rustfs/gateway#740), end to end.
//!
//! Responsible for: proving that an object write presenting a customer-provided key to a bucket
//! whose stored document blocks SSE-C is refused with `403 AccessDenied` and stores nothing, for
//! every write the reference backend serves that can carry SSE-C — PutObject, CopyObject's target,
//! CreateMultipartUpload — and the opposite direction for each: the same write without a key, and
//! the same keyed write to a bucket that blocks nothing, are served.
//! NOT responsible for: the document's codec (`c-encryption-0011`, `c-encryption-0025`,
//! `c-encryption-0027`, `c-encryption-0028`), the cleartext transport gate (`c-ssec-0001`), or
//! the rule itself, which is `rustfs_gateway::refuse_blocked_encryption_type` and unit-tested
//! beside its code.
//! Upstream: the published API of `rustfs_gateway` and `rustfs_gateway_conformance::fixture`.
//! Downstream: nothing.
//!
//! # Why this is a test and not a case
//!
//! The conformance runner is always cleartext, and over cleartext the framework refuses any
//! customer-provided key with `400 InvalidRequest` before a backend runs. A case asking for the
//! blocked-bucket `403` would observe that `400` and prove nothing about the block. So the
//! requests here carry `TransportSecurity::Encrypted` in their extensions, exactly as a
//! TLS-terminating transport does, and are really signed.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway::sig::{AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};
use rustfs_gateway::{
    Credentials, FixedClock, Limits, RegionSet, S3Service, ServiceBuilder, SigV4Authenticator, StaticCredentials,
    TransportSecurity, WireRequest, allow_when, collect, dto,
};
use rustfs_gateway_conformance::fixture::{Fixture, StoredObject, Stub};
use rustfs_gateway_conformance::inprocess::{HOST, VALID_ACCESS_KEY, VALID_SECRET};

const NOW: i64 = 1_767_322_845;
const NOW_STAMP: &str = "20260102T030405Z";
const REGION: &str = "us-east-1";
const BUCKET: &str = "blocked";

/// A 32-byte key and its true MD5.
const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const KEY_MD5: &str = "tP/LI3N87DFaSk0aoqYgzg==";
const TRIO: [(&str, &str); 3] = [
    ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
    ("x-amz-server-side-encryption-customer-key", KEY),
    ("x-amz-server-side-encryption-customer-key-md5", KEY_MD5),
];

const BLOCK_SSE_C: &[u8] = b"<ServerSideEncryptionConfiguration><Rule><BlockedEncryptionTypes><EncryptionType>SSE-C</EncryptionType></BlockedEncryptionTypes></Rule></ServerSideEncryptionConfiguration>";
const BLOCK_SSE_C_MD5: &str = "0LvETHq2V2xykcrGAD4gGw==";

fn blocking(entries: &[dto::EncryptionType]) -> dto::ServerSideEncryptionConfiguration {
    dto::ServerSideEncryptionConfiguration {
        rules: vec![dto::ServerSideEncryptionRule {
            blocked_encryption_types: Some(dto::BlockedEncryptionTypes {
                encryption_type: entries.to_vec(),
            }),
            ..dto::ServerSideEncryptionRule::default()
        }],
    }
}

struct Answer {
    status: u16,
    body: String,
}

struct Harness {
    service: S3Service,
    state: Arc<Mutex<Fixture>>,
}

impl Harness {
    /// One bucket holding one copy source, with the given stored default-encryption document.
    fn with(encryption: Option<dto::ServerSideEncryptionConfiguration>) -> Harness {
        let mut fixture = Fixture::at(NOW);
        fixture.declare_bucket(BUCKET, false);
        fixture.put_object(BUCKET, "source", StoredObject::new(b"source".to_vec(), None, NOW));
        if let Some(configuration) = encryption {
            fixture.set_encryption(BUCKET, configuration);
        }
        let state = Arc::new(Mutex::new(fixture));
        let backend = Arc::new(Stub::new(Arc::clone(&state)));
        let credentials =
            Arc::new(StaticCredentials::new().with(Credentials::new(VALID_ACCESS_KEY, VALID_SECRET).expect("a valid key id")));
        let service = ServiceBuilder::new()
            .register::<dto::PutBucketEncryption, _>(Arc::clone(&backend))
            .register::<dto::PutObject, _>(Arc::clone(&backend))
            .register::<dto::CopyObject, _>(Arc::clone(&backend))
            .register::<dto::CreateMultipartUpload, _>(Arc::clone(&backend))
            .authenticator(SigV4Authenticator::new(credentials, RegionSet::new([REGION]).expect("non-empty")))
            .authorizer(allow_when(|request| !request.is_anonymous()))
            .clock_with_skew_ack(
                FixedClock::at_unix_seconds(NOW),
                rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
            )
            .build()
            .expect("the service assembles");
        Harness { service, state }
    }

    /// Signs one request, declares the transport encrypted, and drains the answer.
    fn send(&self, method: &str, target: &str, headers: &[(&str, &str)], body: &'static [u8]) -> Answer {
        let (path, query) = target.split_once('?').map_or((target, ""), |(path, query)| (path, query));
        let mut map = http::HeaderMap::new();
        map.append(http::header::HOST, http::HeaderValue::from_static(HOST));
        map.append("content-length", http::HeaderValue::from(body.len()));
        for (name, value) in headers {
            map.append(
                http::HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
                http::HeaderValue::from_str(value).expect("a header value"),
            );
        }
        let probe = http::Request::builder()
            .method("GET")
            .uri("/")
            .header("host", HOST)
            .body(Bytes::new())
            .expect("a well-formed probe");
        let accepted = WireRequest::accept(probe, &Limits::default()).expect("the probe host is acceptable");
        let credentials = SigningCredentials::new(VALID_ACCESS_KEY, VALID_SECRET).expect("valid signing credentials");
        let stamp = AmzDate::parse(NOW_STAMP).expect("a SigV4 stamp");
        let scope = SigningScope::new(stamp.day(), REGION, SigService::S3).expect("a well-formed scope");
        let payload = if body.is_empty() {
            PayloadMode::Empty
        } else {
            PayloadMode::ExactSha256(rustfs_gateway_conformance::sha256::digest(body))
        };
        let method_value = http::Method::from_bytes(method.as_bytes()).expect("a method");
        let signing = SigningRequest::new(&method_value, path, query, &map, accepted.host().raw_for_signing(), payload, stamp)
            .with_wire_content_length(body.len() as u64);
        let signed = SigV4Signer::new(credentials, scope)
            .sign_headers(&signing)
            .expect("the request signs");
        let mut builder = http::Request::builder().method(method).uri(target);
        for (name, value) in signed.headers() {
            builder = builder.header(name, value);
        }
        let mut request = builder.body(Bytes::from_static(body)).expect("a well-formed request");
        // Exactly what a TLS-terminating transport does; without it the key never reaches a backend.
        request.extensions_mut().insert(TransportSecurity::Encrypted);
        // A served copy commits its response, which needs a Tokio runtime — the one the facade's own
        // in-process transport runs on.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a current-thread runtime");
        let response = runtime
            .block_on(async { collect(self.service.call_bytes(request).await).await })
            .expect("the body drains");
        Answer {
            status: response.status().as_u16(),
            body: String::from_utf8_lossy(response.body()).into_owned(),
        }
    }

    fn stored(&self, key: &str) -> bool {
        self.state
            .lock()
            .expect("the fixture is not poisoned")
            .object(BUCKET, key)
            .is_some()
    }
}

fn with_trio(extra: &[(&'static str, &'static str)]) -> Vec<(&'static str, &'static str)> {
    TRIO.iter().copied().chain(extra.iter().copied()).collect()
}

fn assert_access_denied(answer: &Answer) {
    assert_eq!(answer.status, 403, "{}", answer.body);
    assert!(answer.body.contains("<Code>AccessDenied</Code>"), "{}", answer.body);
    assert!(
        answer.body.contains("blocks writes that use SSE-C"),
        "the refusal names the block: {}",
        answer.body
    );
    assert!(!answer.body.contains(KEY) && !answer.body.contains(KEY_MD5), "{}", answer.body);
}

// ── PutObject ────────────────────────────────────────────────────────────────────────────────

#[test]
fn n_an_sse_c_put_into_a_bucket_that_blocks_sse_c_is_access_denied_and_stores_nothing() {
    let harness = Harness::with(Some(blocking(&[dto::EncryptionType::SSE_C])));
    assert_access_denied(&harness.send("PUT", "/blocked/keyed", &TRIO, b"payload"));
    assert!(!harness.stored("keyed"), "a refused write must not land");
}

#[test]
fn an_unencrypted_put_into_the_same_blocked_bucket_is_served() {
    let harness = Harness::with(Some(blocking(&[dto::EncryptionType::SSE_C])));
    let answer = harness.send("PUT", "/blocked/plain", &[], b"payload");
    assert_eq!(answer.status, 200, "{}", answer.body);
    assert!(harness.stored("plain"));
}

#[test]
fn an_sse_c_put_is_served_where_the_bucket_blocks_nothing() {
    for encryption in [Some(blocking(&[dto::EncryptionType::NONE])), Some(blocking(&[])), None] {
        let harness = Harness::with(encryption);
        let answer = harness.send("PUT", "/blocked/keyed", &TRIO, b"payload");
        assert_eq!(answer.status, 200, "{}", answer.body);
        assert!(harness.stored("keyed"));
    }
}

/// The document written through the S3 API — codec, validation, store — is the one enforced.
#[test]
fn n_a_block_stored_by_put_bucket_encryption_refuses_the_next_sse_c_put() {
    let harness = Harness::with(None);
    assert_eq!(harness.send("PUT", "/blocked/keyed", &TRIO, b"payload").status, 200);
    let stored = harness.send(
        "PUT",
        "/blocked?encryption",
        &[("content-type", "application/xml"), ("content-md5", BLOCK_SSE_C_MD5)],
        BLOCK_SSE_C,
    );
    assert_eq!(stored.status, 200, "{}", stored.body);
    assert_access_denied(&harness.send("PUT", "/blocked/after", &TRIO, b"payload"));
    assert!(!harness.stored("after"));
}

// ── CopyObject ───────────────────────────────────────────────────────────────────────────────

#[test]
fn n_an_sse_c_copy_target_in_a_blocked_bucket_is_access_denied_and_an_unkeyed_copy_is_served() {
    let harness = Harness::with(Some(blocking(&[dto::EncryptionType::SSE_C])));
    assert_access_denied(&harness.send("PUT", "/blocked/copy", &with_trio(&[("x-amz-copy-source", "/blocked/source")]), b""));
    assert!(!harness.stored("copy"));
    let served = harness.send("PUT", "/blocked/copy", &[("x-amz-copy-source", "/blocked/source")], b"");
    assert_eq!(served.status, 200, "{}", served.body);
    assert!(harness.stored("copy"));
}

// ── CreateMultipartUpload ────────────────────────────────────────────────────────────────────

#[test]
fn n_an_sse_c_multipart_initiation_in_a_blocked_bucket_is_access_denied_and_an_unkeyed_one_is_served() {
    let harness = Harness::with(Some(blocking(&[dto::EncryptionType::SSE_C])));
    let refused = harness.send("POST", "/blocked/multipart?uploads", &TRIO, b"");
    assert_access_denied(&refused);
    assert!(!refused.body.contains("<UploadId>"), "{}", refused.body);
    let served = harness.send("POST", "/blocked/multipart?uploads", &[], b"");
    assert_eq!(served.status, 200, "{}", served.body);
    assert!(served.body.contains("<UploadId>"), "{}", served.body);
}
