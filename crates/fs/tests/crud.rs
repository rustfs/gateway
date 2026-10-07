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
//! Responsible for: proving bucket, object, multipart, versioning, listing, tagging, and lifecycle CRUD through
//! signed requests to a real `S3Service`, including storage-boundary refusals and not-found behavior.
//! NOT responsible for: expanded example binaries or production durability.
//! Upstream: `rustfs-gateway-fs` and the public gateway facade. Downstream: the crate verification gate.

#[path = "crud/acl.rs"]
mod acl;
#[path = "crud/bucket_cors.rs"]
mod bucket_cors;
#[path = "crud/bucket_encryption.rs"]
mod bucket_encryption;
#[path = "crud/bucket_location.rs"]
mod bucket_location;
#[path = "crud/bucket_policy.rs"]
mod bucket_policy;
#[path = "crud/bucket_tagging.rs"]
mod bucket_tagging;
#[path = "crud/completion_parts.rs"]
mod completion_parts;
#[path = "crud/conditional_requests.rs"]
mod conditional_requests;
#[path = "crud/content_encoding.rs"]
mod content_encoding;
#[path = "crud/content_headers.rs"]
mod content_headers;
#[path = "crud/copy_object.rs"]
mod copy_object;
#[path = "crud/delete_conditions.rs"]
mod delete_conditions;
#[path = "crud/delete_objects.rs"]
mod delete_objects;
#[path = "crud/expiration_header.rs"]
mod expiration_header;
#[path = "crud/lifecycle.rs"]
mod lifecycle;
#[path = "crud/lifecycle_expiration.rs"]
mod lifecycle_expiration;
#[path = "crud/lifecycle_rustfs_rules.rs"]
mod lifecycle_rustfs_rules;
#[path = "crud/lifecycle_scheduler.rs"]
mod lifecycle_scheduler;
#[path = "crud/lifecycle_transitions.rs"]
mod lifecycle_transitions;
#[path = "crud/lifecycle_version_expiration.rs"]
mod lifecycle_version_expiration;
#[path = "crud/list_buckets.rs"]
mod list_buckets;
#[path = "crud/listing.rs"]
mod listing;
#[path = "crud/multipart_checksums.rs"]
mod multipart_checksums;
#[path = "crud/multipart_conditions.rs"]
mod multipart_conditions;
#[path = "crud/multipart_listing.rs"]
mod multipart_listing;
#[path = "crud/multipart_object_checksums.rs"]
mod multipart_object_checksums;
#[path = "crud/multipart_replay.rs"]
mod multipart_replay;
#[path = "crud/multipart_sizing.rs"]
mod multipart_sizing;
#[path = "crud/multipart_trailer_checksums.rs"]
mod multipart_trailer_checksums;
#[path = "crud/multipart_upload_ids.rs"]
mod multipart_upload_ids;
#[path = "crud/multipart_versioning.rs"]
mod multipart_versioning;
#[path = "crud/object_checksums.rs"]
mod object_checksums;
#[path = "crud/object_encryption.rs"]
mod object_encryption;
#[path = "crud/object_metadata.rs"]
mod object_metadata;
#[path = "crud/object_tagging.rs"]
mod object_tagging;
#[path = "crud/paging_limits.rs"]
mod paging_limits;
#[path = "crud/post_object.rs"]
mod post_object;
#[path = "crud/range_reads.rs"]
mod range_reads;
#[path = "crud/tag_order.rs"]
mod tag_order;
#[path = "crud/upload_part_copy.rs"]
mod upload_part_copy;
#[path = "crud/versioning.rs"]
mod versioning;
#[path = "crud/versioning_exclusions.rs"]
mod versioning_exclusions;
#[path = "crud/write_attributes.rs"]
mod write_attributes;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use rustfs_gateway::sig::{AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};
use rustfs_gateway::{
    BucketName, ByteStream, ClockSkewAck, Credentials, FixedClock, Handler, Limits, MetaView, ObjectKey, RegionSet, Req,
    S3Service, SigV4Authenticator, SseConfig, SseEnforced, StaticCredentials, TargetKind, TransportSecurity, WireRequest,
    allow_when, collect, dto,
};
use rustfs_gateway_fs::FsBackend;
use sha2::{Digest as _, Sha256};

const SIGNED_AT_SECONDS: i64 = 1_767_323_045;
const SIGNED_AT: &str = "20260102T030405Z";
static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

fn sse_proof() -> SseEnforced {
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri("/")
        .header("host", "s3.example.com")
        .body(Bytes::new())
        .expect("valid proof fixture");
    let wire = WireRequest::accept(request, &Limits::default()).expect("accepted proof fixture");
    let meta = MetaView::of(&wire, TargetKind::Service).expect("service proof fixture");
    rustfs_gateway::enforce_sse(&meta, TransportSecurity::Encrypted, &SseConfig::strict())
        .expect("an empty encrypted request passes SSE enforcement")
}

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
    let backend = Arc::new(
        FsBackend::open_with_clock(&root.0, Arc::new(FixedClock::at_unix_seconds(SIGNED_AT_SECONDS)))
            .expect("a usable test root"),
    );
    service_with_backend(backend)
}

/// The same fixture assembled for a deployment that serves `region` rather than us-east-1.
///
/// The signer still serves us-east-1 so that the shared `signed` helper keeps working; what this
/// varies is the backend's own answer to "where is this bucket", which is what `GetBucketLocation`
/// and `HeadBucket` report.
fn service_in_region(root: &TestRoot, region: &str) -> (Arc<FsBackend>, S3Service) {
    let backend = Arc::new(
        FsBackend::open_with_clock(&root.0, Arc::new(FixedClock::at_unix_seconds(SIGNED_AT_SECONDS)))
            .expect("a usable test root")
            .with_region(region)
            .expect("a region the model names"),
    );
    service_with_backend(backend)
}

fn service_with_backend(backend: Arc<FsBackend>) -> (Arc<FsBackend>, S3Service) {
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid fixture credentials")));
    service_with_backend_and_credentials(backend, credentials)
}

fn service_with_backend_and_credentials(
    backend: Arc<FsBackend>,
    credentials: Arc<StaticCredentials>,
) -> (Arc<FsBackend>, S3Service) {
    let builder = backend.register_crud(
        rustfs_gateway::ServiceBuilder::new()
            .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("one region")))
            .authorizer(allow_when(|_| true))
            .clock_with_skew_ack(
                FixedClock::at_unix_seconds(SIGNED_AT_SECONDS),
                ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
            ),
    );
    let service = backend
        .register_cors(backend.register_encryption(backend.register_policy(backend.register_acl(
            backend.register_tagging(
                backend.register_lifecycle(
                    backend.register_listing(backend.register_versioning(backend.register_multipart(builder))),
                ),
            ),
        ))))
        .build()
        .expect("the reference registry is a complete assembly");
    (backend, service)
}

fn signed(method: http::Method, target: &str, body: Bytes) -> http::Request<Bytes> {
    signed_with_headers(method, target, body, http::HeaderMap::new())
}

fn signed_as(access_key: &str, secret_key: &[u8], method: http::Method, target: &str, body: Bytes) -> http::Request<Bytes> {
    signed_as_with_headers(access_key, secret_key, method, target, body, http::HeaderMap::new())
}

fn signed_with_headers(method: http::Method, target: &str, body: Bytes, headers: http::HeaderMap) -> http::Request<Bytes> {
    signed_as_with_headers("AKIDEXAMPLE", b"secret", method, target, body, headers)
}

fn signed_as_with_headers(
    access_key: &str,
    secret_key: &[u8],
    method: http::Method,
    target: &str,
    body: Bytes,
    mut headers: http::HeaderMap,
) -> http::Request<Bytes> {
    let (path, query) = target.split_once('?').map_or((target, ""), |(path, query)| (path, query));
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    let payload = if (method == http::Method::PUT && target.matches('/').count() >= 2) || !body.is_empty() {
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
    let credentials = SigningCredentials::new(access_key, secret_key).expect("valid signing credentials");
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

fn element(body: &[u8], name: &str) -> Option<String> {
    let body = std::str::from_utf8(body).ok()?;
    let opening = format!("<{name}>");
    let closing = format!("</{name}>");
    let start = body.find(&opening)? + opening.len();
    let end = body[start..].find(&closing)? + start;
    Some(body[start..end].to_owned())
}

async fn create_bucket(service: &S3Service, bucket: &str) {
    let response = exchange(service, signed(http::Method::PUT, &format!("/{bucket}"), Bytes::new())).await;
    assert_eq!(response.status(), 200, "{}", String::from_utf8_lossy(response.body()));
}

async fn initiate(service: &S3Service, bucket: &str, key: &str) -> String {
    let response = exchange(service, signed(http::Method::POST, &format!("/{bucket}/{key}?uploads"), Bytes::new())).await;
    assert_eq!(response.status(), 200, "{}", String::from_utf8_lossy(response.body()));
    element(response.body(), "UploadId").expect("an upload id")
}

async fn upload_part(service: &S3Service, bucket: &str, key: &str, upload_id: &str, part: i32, body: &'static [u8]) -> String {
    let response = exchange(
        service,
        signed(
            http::Method::PUT,
            &format!("/{bucket}/{key}?partNumber={part}&uploadId={upload_id}"),
            Bytes::from_static(body),
        ),
    )
    .await;
    assert_eq!(response.status(), 200, "{}", String::from_utf8_lossy(response.body()));
    header(&response, "etag")
        .expect("a part entity tag")
        .to_str()
        .expect("an ASCII entity tag")
        .to_owned()
}

fn completion(parts: &[(i32, &str)]) -> Bytes {
    let mut body = String::from("<CompleteMultipartUpload>");
    for (number, entity_tag) in parts {
        body.push_str(&format!("<Part><PartNumber>{number}</PartNumber><ETag>{entity_tag}</ETag></Part>"));
    }
    body.push_str("</CompleteMultipartUpload>");
    Bytes::from(body)
}

async fn complete(
    service: &S3Service,
    bucket: &str,
    key: &str,
    upload_id: &str,
    parts: &[(i32, &str)],
) -> rustfs_gateway::WireResponse {
    exchange(
        service,
        signed(http::Method::POST, &format!("/{bucket}/{key}?uploadId={upload_id}"), completion(parts)),
    )
    .await
}

fn legacy_object_path(root: &TestRoot, bucket: &str, key: &str) -> PathBuf {
    let digest = Sha256::digest(key.as_bytes());
    root.0
        .join(format!("b-{}", hex::encode(bucket)))
        .join("objects")
        .join(format!("o-{}", hex::encode(digest)))
}

/// Positive — one real signed exchange exercises the complete bounded CRUD path.
#[tokio::test]
async fn bucket_and_object_crud_runs_through_the_production_registry() {
    let root = TestRoot::new();
    let (backend, service) = service(&root);
    assert_eq!(
        backend.supported_operations().collect::<Vec<_>>(),
        [
            "AbortMultipartUpload",
            "CompleteMultipartUpload",
            "CopyObject",
            "CreateBucket",
            "CreateMultipartUpload",
            "DeleteBucket",
            "DeleteBucketCors",
            "DeleteBucketEncryption",
            "DeleteBucketLifecycle",
            "DeleteBucketPolicy",
            "DeleteBucketTagging",
            "DeleteObject",
            "DeleteObjectTagging",
            "DeleteObjects",
            "DeletePublicAccessBlock",
            "GetBucketAcl",
            "GetBucketCors",
            "GetBucketEncryption",
            "GetBucketLifecycleConfiguration",
            "GetBucketLocation",
            "GetBucketPolicy",
            "GetBucketPolicyStatus",
            "GetBucketTagging",
            "GetBucketVersioning",
            "GetObject",
            "GetObjectAcl",
            "GetObjectTagging",
            "GetPublicAccessBlock",
            "HeadBucket",
            "HeadObject",
            "ListBuckets",
            "ListMultipartUploads",
            "ListObjectVersions",
            "ListObjects",
            "ListObjectsV2",
            "ListParts",
            "PostObject",
            "PutBucketAcl",
            "PutBucketCors",
            "PutBucketEncryption",
            "PutBucketLifecycleConfiguration",
            "PutBucketPolicy",
            "PutBucketTagging",
            "PutBucketVersioning",
            "PutObject",
            "PutObjectAcl",
            "PutObjectTagging",
            "PutPublicAccessBlock",
            "UploadPart",
            "UploadPartCopy"
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

/// Positive — parts remain private until one ordered completion publishes the final object.
#[tokio::test]
async fn multipart_parts_publish_once_through_the_production_registry() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "multipart").await;
    let upload_id = initiate(&service, "multipart", "joined.txt").await;
    assert_eq!(
        exchange(&service, signed(http::Method::GET, "/multipart/joined.txt", Bytes::new()))
            .await
            .status(),
        404
    );

    let first_body = Bytes::from(vec![b'h'; multipart_sizing::MIN_PART_SIZE]);
    let second = upload_part(&service, "multipart", "joined.txt", &upload_id, 2, b"world").await;
    let first = multipart_sizing::upload_owned(&service, "multipart", "joined.txt", &upload_id, 1, first_body.clone()).await;
    let listed = exchange(
        &service,
        signed(http::Method::GET, &format!("/multipart/joined.txt?uploadId={upload_id}"), Bytes::new()),
    )
    .await;
    assert_eq!(listed.status(), 200, "{}", String::from_utf8_lossy(listed.body()));
    let listed = String::from_utf8_lossy(listed.body());
    assert!(listed.find("<PartNumber>1</PartNumber>") < listed.find("<PartNumber>2</PartNumber>"));

    let completed = complete(&service, "multipart", "joined.txt", &upload_id, &[(1, &first), (2, &second)]).await;
    assert_eq!(completed.status(), 200, "{}", String::from_utf8_lossy(completed.body()));
    assert!(element(completed.body(), "ETag").is_some_and(|value| value.contains("-2")));
    let fetched = exchange(&service, signed(http::Method::GET, "/multipart/joined.txt", Bytes::new())).await;
    assert_eq!(fetched.status(), 200);
    let mut expected = first_body.to_vec();
    expected.extend_from_slice(b"world");
    assert_eq!(fetched.body().as_ref(), expected);
    let spent = exchange(
        &service,
        signed(http::Method::GET, &format!("/multipart/joined.txt?uploadId={upload_id}"), Bytes::new()),
    )
    .await;
    assert_eq!(spent.status(), 404);
    assert!(String::from_utf8_lossy(spent.body()).contains("<Code>NoSuchUpload</Code>"));
}

/// Negative — an unknown upload id creates no part and discloses no ownership detail.
#[tokio::test]
async fn upload_part_refuses_an_unknown_upload() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "unknown").await;
    let response = exchange(
        &service,
        signed(
            http::Method::PUT,
            "/unknown/key?partNumber=1&uploadId=not-minted",
            Bytes::from_static(b"part"),
        ),
    )
    .await;
    assert_eq!(response.status(), 404, "{}", String::from_utf8_lossy(response.body()));
    assert!(String::from_utf8_lossy(response.body()).contains("<Code>NoSuchUpload</Code>"));
    assert_eq!(
        exchange(&service, signed(http::Method::GET, "/unknown/key", Bytes::new()))
            .await
            .status(),
        404
    );
}

/// Negative — completion refuses a part that was never uploaded and leaves the upload active.
#[tokio::test]
async fn completion_refuses_a_missing_part_without_publishing() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "missing-part").await;
    let upload_id = initiate(&service, "missing-part", "key").await;
    let response = complete(&service, "missing-part", "key", &upload_id, &[(1, "\"deadbeef\"")]).await;
    assert_eq!(response.status(), 400);
    assert!(String::from_utf8_lossy(response.body()).contains("<Code>InvalidPart</Code>"));
    assert_eq!(
        exchange(
            &service,
            signed(http::Method::GET, &format!("/missing-part/key?uploadId={upload_id}"), Bytes::new(),),
        )
        .await
        .status(),
        200
    );
    assert_eq!(
        exchange(&service, signed(http::Method::GET, "/missing-part/key", Bytes::new()))
            .await
            .status(),
        404
    );
}

/// Negative — completion order is strictly increasing even when every named part exists.
#[tokio::test]
async fn completion_refuses_descending_parts() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "part-order").await;
    let upload_id = initiate(&service, "part-order", "key").await;
    let first = upload_part(&service, "part-order", "key", &upload_id, 1, b"one").await;
    let second = upload_part(&service, "part-order", "key", &upload_id, 2, b"two").await;
    let response = complete(&service, "part-order", "key", &upload_id, &[(2, &second), (1, &first)]).await;
    assert_eq!(response.status(), 400);
    assert!(String::from_utf8_lossy(response.body()).contains("<Code>InvalidPartOrder</Code>"));
    assert_eq!(
        exchange(&service, signed(http::Method::GET, "/part-order/key", Bytes::new()))
            .await
            .status(),
        404
    );
}

/// Negative — a duplicate part number is not accepted as two concatenation instructions.
#[tokio::test]
async fn completion_refuses_a_duplicate_part() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "duplicate-part").await;
    let upload_id = initiate(&service, "duplicate-part", "key").await;
    let first = upload_part(&service, "duplicate-part", "key", &upload_id, 1, b"one").await;
    let response = complete(&service, "duplicate-part", "key", &upload_id, &[(1, &first), (1, &first)]).await;
    assert_eq!(response.status(), 400);
    assert!(String::from_utf8_lossy(response.body()).contains("<Code>InvalidPartOrder</Code>"));
    assert_eq!(
        exchange(&service, signed(http::Method::GET, "/duplicate-part/key", Bytes::new()))
            .await
            .status(),
        404
    );
}

/// Negative — abort makes uploaded parts and their id unreachable without publishing an object.
#[tokio::test]
async fn abort_cleans_incomplete_state() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "aborted").await;
    let upload_id = initiate(&service, "aborted", "key").await;
    let _ = upload_part(&service, "aborted", "key", &upload_id, 1, b"uncommitted").await;
    assert_eq!(
        exchange(&service, signed(http::Method::GET, "/aborted/key", Bytes::new()))
            .await
            .status(),
        404
    );
    assert_eq!(
        exchange(
            &service,
            signed(http::Method::DELETE, &format!("/aborted/key?uploadId={upload_id}"), Bytes::new(),),
        )
        .await
        .status(),
        204
    );
    let listed = exchange(
        &service,
        signed(http::Method::GET, &format!("/aborted/key?uploadId={upload_id}"), Bytes::new()),
    )
    .await;
    assert_eq!(listed.status(), 404);
    assert!(String::from_utf8_lossy(listed.body()).contains("<Code>NoSuchUpload</Code>"));
}

/// Negative — production ingress refuses a traversal-shaped multipart key before storage.
#[tokio::test]
async fn multipart_traversal_spelling_is_refused_before_storage() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "multipart-safe").await;
    let response = exchange(
        &service,
        signed(http::Method::POST, "/multipart-safe/%2E%2E%2Foutside?uploads", Bytes::new()),
    )
    .await;
    assert_eq!(response.status(), 400);
    assert!(String::from_utf8_lossy(response.body()).contains("<Code>InvalidArgument</Code>"));
    assert!(!root.0.join("outside").exists());
}

/// Negative — the upload storage component may not redirect writes through a symbolic link.
#[cfg(unix)]
#[tokio::test]
async fn multipart_symlink_component_is_refused() {
    use std::os::unix::fs::symlink;

    let root = TestRoot::new();
    let outside = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "multipart-link").await;
    let uploads = root.0.join(format!("b-{}/uploads", hex::encode("multipart-link")));
    std::fs::remove_dir(&uploads).expect("an empty upload directory");
    symlink(&outside.0, &uploads).expect("a test symlink");
    let response = exchange(&service, signed(http::Method::POST, "/multipart-link/key?uploads", Bytes::new())).await;
    assert_eq!(response.status(), 400);
    assert!(String::from_utf8_lossy(response.body()).contains("<Code>InvalidRequest</Code>"));
    assert_eq!(std::fs::read_dir(&outside.0).expect("the outside directory").count(), 0);
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
        Req::new(
            dto::PutObjectInput {
                bucket,
                key,
                body: Some(ByteStream::from_bytes(Bytes::from_static(b"inside"))),
                content_length: 6,
                ..dto::PutObjectInput::default()
            },
            sse_proof(),
        ),
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
