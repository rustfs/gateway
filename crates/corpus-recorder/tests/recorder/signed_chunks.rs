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

//! Responsible for: the end-to-end proof — a real `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` upload,
//! signed chunk by chunk, served by the gateway's own `S3Service` behind the recorder, recorded,
//! and then taken through the same steps `corpus ingest` and `corpus verify` run (blind spot B,
//! a-cp-0005's shape).
//! Not responsible for: a third-party client on a real socket; `compat-sut` owns that.
//! Upstream: `rustfs_gateway::sig` for signing, `rustfs_gateway::ServiceBuilder` for the service.
//! Downstream: `rustfs_gateway_corpus::{redact, dedup, store, case}`.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use rustfs_gateway::sig::{
    AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope, TrailerSet,
};
use rustfs_gateway::{
    ClockSkewAck, Credentials, FixedClock, Handler, HandlerError, HandlerResult, RegionSet, Req, Resp, S3Service, ServiceBuilder,
    SigV4Authenticator, StaticCredentials, allow_when, dto,
};
use rustfs_gateway_corpus::redact::PLACEHOLDER;
use rustfs_gateway_corpus::{base64, case, dedup, redact, schema::Chunk, store};
use tower::{Layer as _, ServiceExt as _};

use crate::support::{TEST_KEY, config, entries, recorder, scratch, settle};

const SECRET: &[u8] = b"compat-matrix-secret-value";
const STAMP: &str = "20260102T030405Z";
const STAMP_UNIX_SECONDS: i64 = 1_767_323_045;
const CHUNK: usize = 16;

struct Store(Arc<Mutex<Vec<Vec<u8>>>>);

impl Handler<dto::PutObject> for Store {
    fn call(&self, request: Req<dto::PutObject>) -> impl core::future::Future<Output = HandlerResult<dto::PutObject>> + Send {
        let stored = Arc::clone(&self.0);
        let body = request.into_input().body;
        async move {
            let mut body = body
                .ok_or_else(|| HandlerError::internal_error("PutObject reached its handler without a body"))?
                .into_body();
            let mut bytes = Vec::new();
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|_| HandlerError::internal_error("the request body failed"))?;
                if let Ok(data) = frame.into_data() {
                    bytes.extend_from_slice(&data);
                }
            }
            stored.lock().expect("never poisoned").push(bytes);
            Ok(Resp::new(dto::PutObjectOutput::default()))
        }
    }
}

fn service() -> (S3Service, Arc<Mutex<Vec<Vec<u8>>>>) {
    let stored = Arc::new(Mutex::new(Vec::new()));
    let credentials = Arc::new(StaticCredentials::new().with(Credentials::new(TEST_KEY, SECRET).expect("a valid key")));
    let service = ServiceBuilder::new()
        .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("non-empty")))
        .authorizer(allow_when(|_| true))
        .clock_with_skew_ack(
            FixedClock::at_unix_seconds(STAMP_UNIX_SECONDS),
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<dto::PutObject, _>(Arc::new(Store(Arc::clone(&stored))))
        .build()
        .expect("a complete PutObject assembly");
    (service, stored)
}

/// A signed-chunk upload of `object`, and the wire body it carries.
fn streaming_put(object: &[u8]) -> (http::Request<Full<Bytes>>, Vec<u8>) {
    let credentials = SigningCredentials::new(TEST_KEY, SECRET).expect("valid credentials");
    let stamp = AmzDate::parse(STAMP).expect("a SigV4 stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a scope");
    let mut signer = SigV4Signer::new(credentials, scope);
    let mut map = http::HeaderMap::new();
    map.insert(http::header::HOST, http::HeaderValue::from_static("127.0.0.1:9000"));
    let method = http::Method::PUT;
    // The host is read back through the wire layer, which is the only thing that mints a
    // signing host.
    let probe = http::Request::builder()
        .uri("/")
        .header(http::header::HOST, "127.0.0.1:9000")
        .body(())
        .expect("a valid probe");
    let accepted = rustfs_gateway::WireRequest::accept(probe, &rustfs_gateway::Limits::default()).expect("a valid host");
    let signing = SigningRequest::new(
        &method,
        "/bucket/object",
        "",
        &map,
        accepted.host().raw_for_signing(),
        PayloadMode::StreamingSigned {
            trailer: TrailerSet::None,
        },
        stamp,
    )
    .with_decoded_content_length(object.len() as u64);
    let signed = signer.sign_headers(&signing).expect("a signable request");
    let mut chain = signer.chunk_signer(&signed).expect("a chunk chain");
    let mut body = Vec::new();
    for chunk in object.chunks(CHUNK) {
        body.extend_from_slice(&chain.encode_chunk(chunk));
    }
    body.extend_from_slice(&chain.encode_chunk(b""));
    let mut builder = http::Request::builder()
        .method(http::Method::PUT)
        .uri("/bucket/object")
        .header(http::header::CONTENT_LENGTH, body.len());
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    let request = builder.body(Full::new(Bytes::from(body.clone()))).expect("a valid request");
    (request, body)
}

/// Every run of 64 lowercase hex characters that follows `;chunk-signature=` in `wire`.
fn chunk_signatures(wire: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(wire);
    text.split(";chunk-signature=")
        .skip(1)
        .map(|rest| rest[..64].to_owned())
        .collect()
}

/// Positive — the signed upload is served (the handler receives the decoded object through the
/// tap), recorded with real aws-chunked framing and every signature redacted, admitted by the
/// corpus gate without `--sanitize`, bucketed, written, verified, and converted to a case draft
/// losslessly.
#[tokio::test]
async fn a_signed_chunk_upload_is_served_recorded_and_ingested() {
    let object: Vec<u8> = (0..40_u8).map(|index| b'a' + index % 26).collect();
    let (request, wire) = streaming_put(&object);
    let signatures = chunk_signatures(&wire);
    assert_eq!(signatures.len(), 4, "three data chunks and the final empty chunk are signed");

    let config = config("signed-chunks");
    let layer = recorder(config.clone());
    let (service, stored) = service();
    let response = layer.layer(service).oneshot(request).await.expect("an infallible service");
    assert_eq!(response.status(), 200);
    assert_eq!(*stored.lock().expect("never poisoned"), std::slice::from_ref(&object));

    settle(&layer, 1).await;
    let written = std::fs::read_to_string(&config.output).expect("an output file");
    for signature in &signatures {
        assert!(!written.contains(signature.as_str()), "a chunk signature reached the file");
    }
    assert!(!written.contains(std::str::from_utf8(SECRET).expect("ascii")));

    let recorded = entries(&config);
    let entry = &recorded[0];
    assert_eq!(entry.op, "PutObject");
    assert_eq!(
        entry.header_values("x-amz-content-sha256").collect::<Vec<_>>(),
        ["STREAMING-AWS4-HMAC-SHA256-PAYLOAD"]
    );
    assert_eq!(entry.header_values("authorization").collect::<Vec<_>>(), [PLACEHOLDER]);
    assert_eq!(entry.redacted, ["authorization", "chunk-signature"]);
    let Some(
        [
            Chunk::Data {
                bytes_b64,
                delay_ms: None,
            },
        ],
    ) = entry.chunks.as_deref()
    else {
        panic!("one whole-body data chunk expected: {:?}", entry.chunks);
    };
    let mut expected = String::from_utf8(wire).expect("ascii framing");
    for signature in &signatures {
        expected = expected.replacen(signature.as_str(), PLACEHOLDER, 1);
    }
    assert_eq!(
        String::from_utf8(base64::decode(bytes_b64).expect("base64")).expect("ascii"),
        expected,
        "the recorded body is the wire body with only the signature values replaced"
    );

    // What `corpus ingest` does without `--sanitize`, then what `corpus verify --strict` checks.
    for entry in &recorded {
        store::check_source(&entry.src).expect("an allowlisted source");
        redact::admit(entry).expect("the recorder's output passes the gate unassisted");
    }
    let root = scratch("signed-chunks-corpus");
    let (buckets, _) = dedup::bucketize(recorded.clone(), dedup::DEFAULT_BUCKET_CAP);
    store::write(&root, &buckets).expect("a written corpus");
    let report = store::verify(&root).expect("a verified corpus");
    assert_eq!((report.entries, report.chunk_framed), (1, 1));
    assert!(case::roundtrips(entry).expect("a head_full entry converts"));
}
