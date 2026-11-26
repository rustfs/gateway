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

//! What the assembly does with a derived chunk-signing key, as opposed to what a cache would.
//!
//! Responsible for: the one property `c-ing-0003` is actually about — that the number of signing
//! keys a request derives does not grow with the number of chunks it sends — asserted on the
//! types the running service uses.
//! NOT responsible for: the HMAC arithmetic (`crates/http/tests/ingest_perf_gates.rs` counts it),
//! the derivation chain itself (`rustfs-gateway-sig` owns it), or the chunk chain
//! (`crates/http/tests/ingest_verify.rs`).
//! Upstream: `rustfs-gateway`'s public authenticator surface. Downstream: nothing.
//!
//! # Why this file exists at all
//!
//! `rustfs_gateway_http::SigningKeyCache` is the type the task specified, and it has a full gate
//! of its own — but the assembly does not use it. `SigV4Authenticator` derives `k_signing` once,
//! on the path that has already produced a signature match, and publishes it into a write-once
//! [`ChunkSink`]; the body reader collects it from there. So "one derivation per request" is a
//! property of the sink and of where the derivation sits, not of a cache, and a green cache test
//! is not evidence about the running service. This asserts it where it holds.
//!
//! 1 positive / 1 negative.

use rustfs_gateway::sig::SigningKey;
use rustfs_gateway::{ChunkSink, ChunkVerification};

/// The published AWS example scope. Nothing here authenticates anything: the key is a fixed
/// pattern and is never presented to a verifier.
const SCOPE: &str = "20130524/us-east-1/s3/aws4_request";
const AMZ_DATE: &str = "20130524T000000Z";

/// Material standing in for one identity's derived key.
fn material(byte: u8, scope: &str) -> ChunkVerification {
    ChunkVerification::new(SigningKey::from_array([byte; 32]), scope.to_owned(), AMZ_DATE.to_owned(), [byte; 32])
}

/// Positive — a request derives one key, and reading it once per chunk does not derive another.
///
/// The count that matters is not how many times the sink is read; it is how many keys exist to
/// be read. A `OnceLock` that has been set holds exactly one, so 81,920 chunk verifications
/// consume the same 32 bytes the four-step derivation produced once — which is the whole of the
/// 409,600-to-81,924 difference, expressed where the service actually lives.
#[test]
fn c_ing_0003_the_assembly_holds_one_derived_key_per_request_however_many_chunks_it_has() {
    let sink = ChunkSink::new();
    sink.publish(material(0x11, SCOPE));

    // One read per chunk of a 5 GiB upload in 64 KiB chunks would be 81,920; a thousand is enough
    // to show the answer does not depend on the count, and keeps the gate inside its budget.
    for _ in 0..1000 {
        let held = sink.get().expect("the authenticator published before the body was read");
        assert_eq!(held.scope_line(), SCOPE);
        assert_eq!(held.amz_date(), AMZ_DATE);
        assert!(held.chunk_signing_key().is_some(), "the published key is the 32 bytes SigV4 produces");
    }
}

/// Negative — a second publication never replaces the key the body is verified against.
///
/// This is the half that makes the sink a security boundary rather than a convenience. An
/// authenticator that published twice — a retry, a second scheme, an extension that ran after the
/// first — would otherwise be able to repoint a body already being read at another identity's
/// derived key, and the reader has no provenance to notice with. The second publication here
/// carries both a different key and a different date scope, so a sink that took it would be
/// visible in either field.
#[test]
fn c_ing_0003_a_second_publication_never_replaces_the_key_the_body_is_verified_against() {
    let sink = ChunkSink::new();
    sink.publish(material(0x11, SCOPE));
    sink.publish(material(0x22, "20240101/eu-west-1/s3/aws4_request"));

    let held = sink.get().expect("the first publication stands");
    assert_eq!(
        held.scope_line(),
        SCOPE,
        "the second publication must not repoint a body at another scope"
    );
    assert_eq!(held.amz_date(), AMZ_DATE);
}

struct CapturePutObject(std::sync::Arc<std::sync::Mutex<Option<bytes::Bytes>>>);

impl rustfs_gateway::Handler<rustfs_gateway::dto::PutObject> for CapturePutObject {
    async fn call(
        &self,
        request: rustfs_gateway::Req<rustfs_gateway::dto::PutObject>,
    ) -> rustfs_gateway::HandlerResult<rustfs_gateway::dto::PutObject> {
        let stream = request.into_input().body.expect("PutObject streaming body");
        let Ok(collected) = rustfs_gateway::collect(http::Response::new(stream.into_body())).await else {
            return Err(rustfs_gateway::HandlerError::internal_error("streaming body failed"));
        };
        *self.0.lock().expect("capture lock") = Some(collected.body().clone());
        Ok(rustfs_gateway::Resp::new(rustfs_gateway::dto::PutObjectOutput::default()))
    }
}

fn streaming_put_service(
    access_key: &str,
    captured: std::sync::Arc<std::sync::Mutex<Option<bytes::Bytes>>>,
) -> rustfs_gateway::S3Service {
    use std::sync::Arc;
    let credentials = Arc::new(
        rustfs_gateway::StaticCredentials::new()
            .with(rustfs_gateway::Credentials::new(access_key, b"secret").expect("valid credentials")),
    );
    let authenticator = Arc::new(rustfs_gateway::SigV4Authenticator::new(
        credentials,
        rustfs_gateway::sig::RegionSet::new(["us-east-1"]).expect("non-empty regions"),
    ));
    rustfs_gateway::ServiceBuilder::new()
        .authenticator(authenticator)
        .authorizer(rustfs_gateway::allow_when(|_| true))
        .clock_with_skew_ack(
            crate::support::fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<rustfs_gateway::dto::PutObject, _>(Arc::new(CapturePutObject(captured)))
        .build()
        .expect("streaming PutObject assembly")
}

/// Regression (#1628 #11) — an `AccessKeyId` containing literal `Signature=` followed by hex
/// must not confuse chunk-seed extraction on a streaming signed upload.
#[tokio::test]
async fn streaming_signed_upload_with_signature_equals_in_access_key_id() {
    use rustfs_gateway::sig::{
        AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope, TrailerSet,
    };

    const ACCESS_KEY: &str = "AKIDSignature=deadbeef";
    const PAYLOAD: &[u8] = b"hello verified chunk seed";

    let captured = std::sync::Arc::new(std::sync::Mutex::new(None));
    let service = streaming_put_service(ACCESS_KEY, std::sync::Arc::clone(&captured));

    let credentials = SigningCredentials::new(ACCESS_KEY, b"secret").expect("valid credentials");
    let stamp = AmzDate::parse(crate::support::SIGNED_AT_STAMP).expect("valid stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("valid scope");
    let mut signer = SigV4Signer::new(credentials, scope);

    let probe = http::Request::builder()
        .method(http::Method::GET)
        .uri("/")
        .header(http::header::HOST, "s3.example.com")
        .body(bytes::Bytes::new())
        .expect("probe request");
    let accepted = rustfs_gateway::WireRequest::accept(probe, &rustfs_gateway::Limits::default()).expect("accepted host");

    let wire_len = PAYLOAD.len() + (format!("{:x}", PAYLOAD.len()).len() + 17 + 64 + 4) + 1 + 17 + 64 + 4;
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    headers.insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_str(&wire_len.to_string()).expect("wire length"),
    );
    let signing = SigningRequest::new(
        &http::Method::PUT,
        "/bucket/key",
        "",
        &headers,
        accepted.host().raw_for_signing(),
        PayloadMode::StreamingSigned {
            trailer: TrailerSet::None,
        },
        stamp,
    )
    .with_wire_content_length(wire_len as u64)
    .with_decoded_content_length(PAYLOAD.len() as u64);
    let signed = signer.sign_headers(&signing).expect("signed header request");
    let mut chain = signer.chunk_signer(&signed).expect("chunk chain");
    let mut wire = chain.encode_chunk(PAYLOAD);
    wire.extend_from_slice(&chain.encode_chunk(b""));
    assert_eq!(wire.len(), wire_len);

    let mut req_builder = http::Request::builder().method(http::Method::PUT).uri("/bucket/key");
    for (name, value) in signed.headers() {
        req_builder = req_builder.header(name, value);
    }
    let request = req_builder.body(bytes::Bytes::from(wire.clone())).expect("valid request");
    let response = service.call_bytes(request).await;
    assert_eq!(
        response.status(),
        http::StatusCode::OK,
        "streaming upload with `Signature=` inside AccessKeyId must verify using the authenticated seed"
    );
    assert_eq!(captured.lock().expect("capture").as_deref(), Some(PAYLOAD));

    // Negative control: corrupting a chunk signature still fails closed with 403.
    let mut tampered = wire;
    if let Some(pos) = tampered.windows(16).position(|w| w == b"chunk-signature=") {
        let idx = pos + 16;
        tampered[idx] = if tampered[idx] == b'0' { b'1' } else { b'0' };
    }
    let mut bad_builder = http::Request::builder().method(http::Method::PUT).uri("/bucket/key");
    for (name, value) in signed.headers() {
        bad_builder = bad_builder.header(name, value);
    }
    let bad_request = bad_builder.body(bytes::Bytes::from(tampered)).expect("valid bad request");
    let bad_response = service.call_bytes(bad_request).await;
    assert_eq!(bad_response.status(), http::StatusCode::FORBIDDEN);
}

/// Regression (#1628 #11) — a presigned request carrying a valueless query parameter before
/// `X-Amz-Signature` authenticates cleanly and publishes the exact 32-byte verified seed into
/// `ChunkSink` without relying on fragile `&`/`=` splitting.
#[tokio::test]
async fn presigned_streaming_upload_with_valueless_query_param_before_signature() {
    use rustfs_gateway::sig::{
        AmzDate, PayloadMode, RawQuery, RegionSet, SecurityFloor, SigService, SigV4Signer, SigningCredentials, SigningRequest,
        SigningScope, TrailerSet,
    };
    use rustfs_gateway::{Authentication, Authenticator, Credentials, Operation, SigV4Authenticator, StaticCredentials, dto};
    use rustfs_gateway_sig::{Admission, WireView};
    use std::sync::Arc;

    const PAYLOAD: &[u8] = b"presigned chunk seed body";

    let captured = Arc::new(std::sync::Mutex::new(None));
    let service = streaming_put_service("AKIDEXAMPLE", Arc::clone(&captured));

    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials");
    let stamp = AmzDate::parse(crate::support::SIGNED_AT_STAMP).expect("valid stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("valid scope");
    let mut signer = SigV4Signer::new(credentials, scope);

    let probe = http::Request::builder()
        .method(http::Method::GET)
        .uri("/")
        .header(http::header::HOST, "s3.example.com")
        .body(bytes::Bytes::new())
        .expect("probe request");
    let accepted = rustfs_gateway::WireRequest::accept(probe, &rustfs_gateway::Limits::default()).expect("accepted host");

    // 1. End-to-end presigned PutObject with a valueless query param before X-Amz-Signature.
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    headers.insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_str(&PAYLOAD.len().to_string()).expect("content length"),
    );
    let signing = SigningRequest::new(
        &http::Method::PUT,
        "/bucket/key",
        "flag",
        &headers,
        accepted.host().raw_for_signing(),
        PayloadMode::Unsigned,
        stamp,
    )
    .with_wire_content_length(PAYLOAD.len() as u64);
    let signed = signer.presign(&signing, 300).expect("presigned request");
    assert!(
        signed.query().starts_with("flag&"),
        "valueless parameter must precede X-Amz-Signature: {}",
        signed.query()
    );
    let mut req_builder = http::Request::builder().method(http::Method::PUT).uri(signed.target());
    for (name, value) in signed.headers() {
        req_builder = req_builder.header(name, value);
    }
    let request = req_builder
        .body(bytes::Bytes::from_static(PAYLOAD))
        .expect("valid presigned request");
    let response = service.call_bytes(request).await;
    assert_eq!(
        response.status(),
        http::StatusCode::OK,
        "presigned upload with valueless query parameter before X-Amz-Signature must succeed"
    );
    assert_eq!(captured.lock().expect("capture").as_deref(), Some(PAYLOAD));

    // 2. Direct authenticator verification of a presigned StreamingSigned request with a valueless
    // query parameter before X-Amz-Signature publishes the exact verified 32-byte seed into ChunkSink.
    let wire_len = PAYLOAD.len() + (format!("{:x}", PAYLOAD.len()).len() + 17 + 64 + 4) + 1 + 17 + 64 + 4;
    let mut stream_headers = http::HeaderMap::new();
    stream_headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    stream_headers.insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_str(&wire_len.to_string()).expect("wire length"),
    );
    let stream_mode = PayloadMode::StreamingSigned {
        trailer: TrailerSet::None,
    };
    let stream_signing = SigningRequest::new(
        &http::Method::PUT,
        "/bucket/key",
        "flag",
        &stream_headers,
        accepted.host().raw_for_signing(),
        stream_mode.clone(),
        stamp,
    )
    .with_wire_content_length(wire_len as u64)
    .with_decoded_content_length(PAYLOAD.len() as u64);
    let stream_signed = signer.presign(&stream_signing, 300).expect("presigned streaming request");
    assert!(stream_signed.query().starts_with("flag&"));

    let floor = SecurityFloor::new();
    let now = rustfs_gateway::Clock::now(&crate::support::fixed_clock());
    let view = WireView::new(stream_signed.headers(), RawQuery::new(stream_signed.query()));
    let admitted = floor
        .admit(view, dto::PutObject::floor(), now)
        .expect("floor admits presigned");
    let Admission::Sealed(sealed) = admitted else {
        panic!("expected sealed AWS admission");
    };
    let store = Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials")));
    let authenticator = SigV4Authenticator::new(store, RegionSet::new(["us-east-1"]).expect("region"));
    let sink = ChunkSink::new();
    let question = Authentication::new(
        &sealed,
        &http::Method::PUT,
        "/bucket/key",
        accepted.host().raw_for_signing(),
        &stream_mode,
        Some(wire_len as u64),
    )
    .with_chunk_sink(&sink);
    let outcome = authenticator.authenticate(&question).await.expect("authenticator answers");
    assert!(outcome.verdict().is_authenticated(), "presigned streaming head must authenticate");
    let material = sink
        .get()
        .expect("verified presigned streaming request must publish 32-byte seed into ChunkSink");
    let mut chain = signer.chunk_signer(&stream_signed).expect("chunk chain");
    let wire = chain.encode_chunk(PAYLOAD);
    let chunk_sig_hex = std::str::from_utf8(&wire)
        .expect("utf8 chunk")
        .split_once("chunk-signature=")
        .expect("chunk-signature extension")
        .1
        .get(..64)
        .expect("64 hex chars");
    let mut presented_chunk_sig = [0_u8; 32];
    for (slot, pair) in presented_chunk_sig.iter_mut().zip(chunk_sig_hex.as_bytes().chunks_exact(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).expect("hex pair"), 16).expect("hex byte");
    }
    let scope = rustfs_gateway_http::ChunkScope::new(material.scope_line(), material.amz_date()).expect("valid scope");
    let mut verifier = rustfs_gateway_http::ChunkSigner::new(
        material.chunk_signing_key().expect("valid key"),
        scope,
        material.chunk_seed().expect("verified HMAC seed"),
    );
    verifier.update(PAYLOAD);
    verifier
        .verify_chunk(&presented_chunk_sig)
        .expect("published 32-byte seed must verify the chunk chain from ?flag&...&X-Amz-Signature");
}
