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

//! Production-registry contract for the filesystem reference backend.
//!
//! Responsible for: proving bucket and object CRUD through signed requests to a real `S3Service`,
//! including storage-boundary refusals and S3 not-found/idempotency behavior.
//! NOT responsible for: multipart uploads, versioning, lifecycle policy, or example binaries.
//! Upstream: `rustfs-gateway-fs` and the public gateway facade. Downstream: the crate verification gate.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use rustfs_gateway::sig::{AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};
use rustfs_gateway::{
    BucketName, ByteStream, ClockSkewAck, Credentials, FixedClock, Handler, Limits, ObjectKey, RegionSet, Req, S3Service,
    SigV4Authenticator, StaticCredentials, WireRequest, allow_when, collect, dto,
};
use rustfs_gateway_fs::FsBackend;
use sha2::{Digest as _, Sha256};

const SIGNED_AT_SECONDS: i64 = 1_767_323_045;
const SIGNED_AT: &str = "20260102T030405Z";
static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "rustfs-gateway-fs-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).expect("a unique test root");
        Self(path)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("the exact test root is removable");
    }
}

fn service(root: &TestRoot) -> (Arc<FsBackend>, S3Service) {
    let backend = Arc::new(FsBackend::open(&root.0).expect("a usable test root"));
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid fixture credentials")));
    let service = backend
        .register_crud(
            rustfs_gateway::ServiceBuilder::new()
                .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("one region")))
                .authorizer(allow_when(|_| true))
                .clock_with_skew_ack(
                    FixedClock::at_unix_seconds(SIGNED_AT_SECONDS),
                    ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
                ),
        )
        .build()
        .expect("the CRUD registry is a complete assembly");
    (backend, service)
}

fn signed(method: http::Method, target: &str, body: Bytes) -> http::Request<Bytes> {
    let (path, query) = target.split_once('?').map_or((target, ""), |(path, query)| (path, query));
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    let payload = if method == http::Method::PUT && target.matches('/').count() >= 2 {
        let digest: [u8; 32] = Sha256::digest(&body).into();
        let payload = PayloadMode::ExactSha256(digest);
        headers.insert(
            http::HeaderName::from_static("x-amz-content-sha256"),
            http::HeaderValue::from_str(payload.canonical_payload_token().as_str()).expect("a digest header"),
        );
        headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_str(&body.len().to_string()).expect("a content length"),
        );
        payload
    } else {
        PayloadMode::Empty
    };
    let probe = http::Request::builder()
        .uri("/")
        .header(http::header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("a valid host probe");
    let accepted = WireRequest::accept(probe, &Limits::default()).expect("an acceptable host");
    let stamp = AmzDate::parse(SIGNED_AT).expect("a valid signing stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a valid signing scope");
    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid signing credentials");
    let signing = SigningRequest::new(&method, path, query, &headers, accepted.host().raw_for_signing(), payload, stamp)
        .with_wire_content_length(body.len() as u64);
    let mut signer = SigV4Signer::new(credentials, scope);
    let signed = signer.sign_headers(&signing).expect("a signable request");
    let mut request = http::Request::builder().method(method).uri(target);
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    request.body(body).expect("a valid signed request")
}

async fn exchange(service: &S3Service, request: http::Request<Bytes>) -> rustfs_gateway::WireResponse {
    collect(service.call_bytes(request).await).await.expect("a finite response")
}

fn header<'a>(response: &'a rustfs_gateway::WireResponse, name: &str) -> Option<&'a http::HeaderValue> {
    response
        .headers()
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == name).then_some(value))
}

/// Positive — one real signed exchange exercises the complete bounded CRUD path.
#[tokio::test]
async fn bucket_and_object_crud_runs_through_the_production_registry() {
    let root = TestRoot::new();
    let (backend, service) = service(&root);
    assert_eq!(
        backend.supported_operations().collect::<Vec<_>>(),
        [
            "CreateBucket",
            "DeleteBucket",
            "DeleteObject",
            "GetObject",
            "HeadBucket",
            "HeadObject",
            "PutObject"
        ]
    );
    assert_eq!(
        service.operations().collect::<Vec<_>>(),
        backend.supported_operations().collect::<Vec<_>>()
    );

    let created = exchange(&service, signed(http::Method::PUT, "/photos", Bytes::new())).await;
    assert_eq!(created.status(), 200);
    assert_eq!(header(&created, "location").expect("a location"), "/photos");

    let stored = exchange(
        &service,
        signed(http::Method::PUT, "/photos/2026/kitten.txt", Bytes::from_static(b"kitten")),
    )
    .await;
    assert_eq!(stored.status(), 200);
    assert_eq!(header(&stored, "etag").expect("an entity tag"), "\"6da89cd09ab7937478a1d47d20938536\"");

    let fetched = exchange(&service, signed(http::Method::GET, "/photos/2026/kitten.txt", Bytes::new())).await;
    assert_eq!(fetched.status(), 200);
    assert_eq!(fetched.body().as_ref(), b"kitten");

    let headed = exchange(&service, signed(http::Method::HEAD, "/photos/2026/kitten.txt", Bytes::new())).await;
    assert_eq!(headed.status(), 200);
    assert_eq!(header(&headed, "content-length").expect("a length"), "6");

    assert_eq!(
        exchange(&service, signed(http::Method::DELETE, "/photos/2026/kitten.txt", Bytes::new()))
            .await
            .status(),
        204
    );
    assert_eq!(
        exchange(&service, signed(http::Method::GET, "/photos/2026/kitten.txt", Bytes::new()))
            .await
            .status(),
        404
    );
    assert_eq!(
        exchange(&service, signed(http::Method::DELETE, "/photos", Bytes::new()))
            .await
            .status(),
        204
    );
    assert_eq!(
        exchange(&service, signed(http::Method::HEAD, "/photos", Bytes::new()))
            .await
            .status(),
        404
    );
}

/// Negative — a missing bucket is resolved before an object write and no file is created.
#[tokio::test]
async fn put_into_a_missing_bucket_is_refused() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    let response = exchange(&service, signed(http::Method::PUT, "/missing/key", Bytes::from_static(b"no"))).await;
    assert_eq!(response.status(), 404, "{}", String::from_utf8_lossy(response.body()));
    assert!(String::from_utf8_lossy(response.body()).contains("<Code>NoSuchBucket</Code>"));
}

/// Negative — bucket deletion cannot discard live objects.
#[tokio::test]
async fn a_nonempty_bucket_is_not_deleted() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    assert_eq!(
        exchange(&service, signed(http::Method::PUT, "/kept", Bytes::new()))
            .await
            .status(),
        200
    );
    assert_eq!(
        exchange(&service, signed(http::Method::PUT, "/kept/key", Bytes::from_static(b"live")))
            .await
            .status(),
        200
    );
    let refused = exchange(&service, signed(http::Method::DELETE, "/kept", Bytes::new())).await;
    assert_eq!(refused.status(), 409);
    assert!(String::from_utf8_lossy(refused.body()).contains("<Code>BucketNotEmpty</Code>"));
    assert_eq!(
        exchange(&service, signed(http::Method::GET, "/kept/key", Bytes::new()))
            .await
            .status(),
        200
    );
}

/// Negative — even a decoded traversal-looking key handed directly to the backend remains data.
#[tokio::test]
async fn traversal_spelling_cannot_escape_the_backend_root() {
    let root = TestRoot::new();
    let (backend, service) = service(&root);
    assert_eq!(
        exchange(&service, signed(http::Method::PUT, "/safe", Bytes::new()))
            .await
            .status(),
        200
    );
    let bucket = BucketName::new("safe").expect("a valid bucket");
    let key = ObjectKey::new("../outside").expect("a valid opaque S3 key");
    let response = Handler::<dto::PutObject>::call(
        backend.as_ref(),
        Req::new(dto::PutObjectInput {
            bucket,
            key,
            body: Some(ByteStream::from_bytes(Bytes::from_static(b"inside"))),
            content_length: 6,
            ..dto::PutObjectInput::default()
        }),
    )
    .await
    .expect("the opaque key is stored");
    assert_eq!(response.status(), 200);
    let outside = root.0.join(format!("b-{}/outside", hex::encode("safe")));
    assert!(!outside.exists());
}

/// Negative — an absent object is distinguished from an absent bucket.
#[tokio::test]
async fn get_of_a_missing_key_reports_no_such_key() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    assert_eq!(
        exchange(&service, signed(http::Method::PUT, "/empty", Bytes::new()))
            .await
            .status(),
        200
    );
    let response = exchange(&service, signed(http::Method::GET, "/empty/missing", Bytes::new())).await;
    assert_eq!(response.status(), 404, "{}", String::from_utf8_lossy(response.body()));
    assert!(String::from_utf8_lossy(response.body()).contains("<Code>NoSuchKey</Code>"));
}

/// Negative — deleting an absent object is idempotent and leaves the bucket usable.
#[tokio::test]
async fn delete_of_a_missing_key_is_still_a_204() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    assert_eq!(
        exchange(&service, signed(http::Method::PUT, "/empty", Bytes::new()))
            .await
            .status(),
        200
    );
    let response = exchange(&service, signed(http::Method::DELETE, "/empty/missing", Bytes::new())).await;
    assert_eq!(response.status(), 204);
    assert_eq!(
        exchange(&service, signed(http::Method::HEAD, "/empty", Bytes::new()))
            .await
            .status(),
        200
    );
}

/// Negative — a symlink cannot be accepted as the backend root.
#[cfg(unix)]
#[test]
fn a_symlink_root_is_refused() {
    use std::os::unix::fs::symlink;

    let root = TestRoot::new();
    let link = root.0.with_extension("link");
    symlink(&root.0, &link).expect("a test symlink");
    let error = FsBackend::open(&link).err().expect("a symlink is refused");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    std::fs::remove_file(link).expect("the exact symlink is removable");
}

/// Negative — a pre-existing symlink cannot occupy a bucket's storage component.
#[cfg(unix)]
#[tokio::test]
async fn a_symlink_bucket_component_is_refused() {
    use std::os::unix::fs::symlink;

    let root = TestRoot::new();
    let outside = TestRoot::new();
    let bucket_component = root.0.join(format!("b-{}", hex::encode("linked")));
    symlink(&outside.0, &bucket_component).expect("a test symlink");
    let (_, service) = service(&root);
    let response = exchange(&service, signed(http::Method::PUT, "/linked", Bytes::new())).await;
    assert_eq!(response.status(), 400);
    assert!(String::from_utf8_lossy(response.body()).contains("<Code>InvalidRequest</Code>"));
}
