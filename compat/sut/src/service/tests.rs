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

//! Signed requests driven through the served assembly, and the shared harness its topic files use.
//!
//! Responsible for: the two-identity command line, the signer and exchange helpers, and the
//! ownership, listing, lifecycle-cadence and capability cases of `super::build_service`; the
//! topic files beside this one (`tests/*.rs`) reuse the same harness through `use super::*`.
//! NOT responsible for: assembling anything of its own — every case goes through
//! `super::build_service` and `super::open_backend`, because an assembly written for a test proves
//! nothing about the one the suites are pointed at.
//! Upstream: `super`. Downstream: the topic files under `tests/`.

use super::{build_service, open_backend};
use crate::ownership::BucketOwners;
use crate::{Options, parse_options};

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use rustfs_gateway::sig::{AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};
use rustfs_gateway::{Limits, S3Service, Timestamp, TimestampFormat, WireRequest, WireResponse, collect};
use rustfs_gateway_fs::FsBackend;
use sha2::{Digest as _, Sha256};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

const MAIN_KEY: &str = "AKIAGATEWAYMAIN00000";
const MAIN_SECRET: &str = "gateway-main-secret-for-a-throwaway-service";
const ALT_KEY: &str = "AKIAGATEWAYALT000000";
const ALT_SECRET: &str = "gateway-alt-secret-for-a-throwaway-service";
const MAIN_OWNER: &str = "s3gate-main";
const ALT_OWNER: &str = "s3gate-alt";
const MAIN_DISPLAY_NAME: &str = "Main <Owner> & \"Friends\"";

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("compat-sut-{}-{}", std::process::id(), NEXT_ROOT.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir(&path).expect("a unique test root");
        Self(path)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("the exact test root is removable");
    }
}

/// The exact command line an external suite would use, parsed by the launcher's own parser.
fn two_identity_options(root: &TestRoot, extra: &[&str]) -> Options {
    let mut arguments = vec![
        "--data".to_owned(),
        root.0.to_string_lossy().into_owned(),
        "--access-key".to_owned(),
        MAIN_KEY.to_owned(),
        "--secret-key".to_owned(),
        MAIN_SECRET.to_owned(),
        "--owner-id".to_owned(),
        MAIN_OWNER.to_owned(),
        "--display-name".to_owned(),
        MAIN_DISPLAY_NAME.to_owned(),
        "--alt-access-key".to_owned(),
        ALT_KEY.to_owned(),
        "--alt-secret-key".to_owned(),
        ALT_SECRET.to_owned(),
        "--alt-owner-id".to_owned(),
        ALT_OWNER.to_owned(),
        "--alt-display-name".to_owned(),
        ALT_OWNER.to_owned(),
    ];
    arguments.extend(extra.iter().map(|argument| (*argument).to_owned()));
    parse_options(arguments).expect("a valid two-identity command line")
}

fn assembled(options: &Options) -> (Arc<FsBackend>, S3Service) {
    let backend = Arc::new(open_backend(options).expect("a usable data root"));
    let owners = Arc::new(BucketOwners::default());
    let service = build_service(options, &backend, &owners).expect("a complete assembly");
    (backend, service)
}

/// Signs one request as the named identity, using the same signer any SDK would.
fn signed(
    access_key: &str,
    secret_key: &str,
    method: http::Method,
    target: &str,
    body: Bytes,
    extra: &[(&str, &str)],
) -> http::Request<Bytes> {
    signed_in(Some("us-east-1"), access_key, secret_key, method, target, body, extra)
}

/// [`signed`], scoped to `region`; `None` signs with an empty region, as RustFS's replication
/// client does for a bucket target that names none.
fn signed_in(
    region: Option<&str>,
    access_key: &str,
    secret_key: &str,
    method: http::Method,
    target: &str,
    body: Bytes,
    extra: &[(&str, &str)],
) -> http::Request<Bytes> {
    let (path, query) = target.split_once('?').map_or((target, ""), |(path, query)| (path, query));
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    for (name, value) in extra {
        headers.append(
            http::HeaderName::from_bytes(name.as_bytes()).expect("a valid header name"),
            http::HeaderValue::from_str(value).expect("a valid header value"),
        );
    }
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
    // The assembled service uses the production system clock — `build_service` installs no
    // fixed one — so the request must be stamped now, or every case here would fail on skew
    // rather than on what it is written to measure.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs();
    let rendered = Timestamp::from_secs(i64::try_from(now).expect("a representable clock"))
        .render(TimestampFormat::Iso8601Basic)
        .expect("a representable signing stamp");
    let stamp = AmzDate::parse(&rendered).expect("a valid signing stamp");
    let scope = match region {
        Some(region) => SigningScope::new(stamp.day(), region, SigService::S3).expect("a valid signing scope"),
        None => SigningScope::with_empty_region(stamp.day(), SigService::S3),
    };
    let credentials = SigningCredentials::new(access_key, secret_key.as_bytes()).expect("valid signing credentials");
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

fn as_main(method: http::Method, target: &str, body: Bytes) -> http::Request<Bytes> {
    signed(MAIN_KEY, MAIN_SECRET, method, target, body, &[])
}

fn as_alt(method: http::Method, target: &str, body: Bytes) -> http::Request<Bytes> {
    signed(ALT_KEY, ALT_SECRET, method, target, body, &[])
}

async fn exchange(service: &S3Service, request: http::Request<Bytes>) -> WireResponse {
    collect(service.call_bytes(request).await).await.expect("a finite response")
}

fn body_of(response: &WireResponse) -> String {
    String::from_utf8_lossy(response.body()).into_owned()
}

/// The whole point of the second identity, end to end through the served assembly.
///
/// Positive halves and negative halves in one case on purpose: a refusal that is not paired
/// with the allowance it is supposed to be different from is satisfied by a service that
/// refuses everything.
#[tokio::test]
async fn n_the_second_identity_is_refused_on_the_first_identitys_bucket() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);

    // main owns it, and reaches it.
    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/main-bucket", Bytes::new()))
            .await
            .status(),
        200
    );
    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/main-bucket/key", Bytes::from_static(b"body")))
            .await
            .status(),
        200
    );
    let read = exchange(&service, as_main(http::Method::GET, "/main-bucket/key", Bytes::new())).await;
    assert_eq!(read.status(), 200);
    assert_eq!(read.body().as_ref(), b"body");

    // alt signs correctly, is authenticated, and is still refused.
    let refused = exchange(&service, as_alt(http::Method::GET, "/main-bucket/key", Bytes::new())).await;
    assert_eq!(refused.status(), 403, "{}", body_of(&refused));
    assert!(body_of(&refused).contains("AccessDenied"), "{}", body_of(&refused));
    let refused = exchange(&service, as_alt(http::Method::PUT, "/main-bucket/other", Bytes::from_static(b"x"))).await;
    assert_eq!(refused.status(), 403, "{}", body_of(&refused));
    let refused = exchange(&service, as_alt(http::Method::GET, "/main-bucket?list-type=2", Bytes::new())).await;
    assert_eq!(refused.status(), 403, "{}", body_of(&refused));
}

/// Negative — a secondary identity may request bucket creation as a guest, but the bucket
/// remains owned by the primary single-tenant data root. The guest is refused afterwards.
#[tokio::test]
async fn n_the_secondary_creator_is_refused_on_the_data_root_owners_bucket() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);

    assert_eq!(
        exchange(&service, as_alt(http::Method::PUT, "/alt-bucket", Bytes::new()))
            .await
            .status(),
        200
    );
    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/alt-bucket/key", Bytes::from_static(b"main")))
            .await
            .status(),
        200
    );
    let refused = exchange(&service, as_alt(http::Method::GET, "/alt-bucket/key", Bytes::new())).await;
    assert_eq!(refused.status(), 403, "{}", body_of(&refused));
    let allowed = exchange(&service, as_main(http::Method::GET, "/alt-bucket/key", Bytes::new())).await;
    assert_eq!(allowed.status(), 200, "{}", body_of(&allowed));
    assert_eq!(allowed.body().as_ref(), b"main");
}

/// Negative and positive control — a secondary identity may create a bucket for the
/// single-tenant data root, but it does not become that root's owner. The primary identity
/// must own authorization afterwards, the guest must be refused, and the listing wire must
/// report the same primary owner rather than the creating identity.
#[tokio::test]
async fn n_a_secondary_created_bucket_belongs_to_the_data_root_owner() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);

    assert_eq!(
        exchange(&service, as_alt(http::Method::PUT, "/guest-created", Bytes::new()))
            .await
            .status(),
        200
    );

    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/guest-created/key", Bytes::from_static(b"body")),)
            .await
            .status(),
        200
    );

    let mismatched = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::GET,
        "/guest-created?list-type=2&fetch-owner=true",
        Bytes::new(),
        &[("x-amz-expected-bucket-owner", ALT_OWNER)],
    );
    let refused = exchange(&service, mismatched).await;
    assert_eq!(refused.status(), 403, "{}", body_of(&refused));

    let listed = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::GET,
        "/guest-created?list-type=2&fetch-owner=true",
        Bytes::new(),
        &[("x-amz-expected-bucket-owner", MAIN_OWNER)],
    );
    let listed = exchange(&service, listed).await;
    let body = body_of(&listed);
    assert_eq!(listed.status(), 200, "{body}");
    assert!(body.contains("<ID>s3gate-main</ID>"), "{body}");
    assert!(
        body.contains("<DisplayName>Main &lt;Owner&gt; &amp; &quot;Friends&quot;</DisplayName>"),
        "{body}"
    );
}

/// Negative — the rustfs/gateway#811 repro: a bucket the primary identity created is
/// `409 BucketAlreadyExists` when the secondary identity asks to create it, and nothing is
/// deleted or transferred by the refusal. Positive control: the owner's own re-creation is the
/// us-east-1 `200`, so the refusal is about *who* asks and not about the name being taken.
#[tokio::test]
async fn n_another_identitys_re_creation_of_a_bucket_is_bucket_already_exists() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);

    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/taken", Bytes::new()))
            .await
            .status(),
        200
    );
    let refused = exchange(&service, as_alt(http::Method::PUT, "/taken", Bytes::new())).await;
    let body = body_of(&refused);
    assert_eq!(refused.status(), 409, "{body}");
    assert!(body.contains("<Code>BucketAlreadyExists</Code>"), "{body}");

    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/taken", Bytes::new()))
            .await
            .status(),
        200
    );
    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/taken/key", Bytes::from_static(b"body")))
            .await
            .status(),
        200
    );
}

/// Negative — the deleted bucket's name is free for the other identity, and a refused delete
/// keeps the owner: main creates and deletes `reused`, alt then creates it (`200`, not `409`);
/// main creates `kept` with an object in it, its delete is `409 BucketNotEmpty`, and alt is
/// still refused on it.
#[tokio::test]
async fn n_a_deleted_buckets_name_is_free_and_a_refused_delete_keeps_its_owner() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);

    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/reused", Bytes::new()))
            .await
            .status(),
        200
    );
    assert_eq!(
        exchange(&service, as_main(http::Method::DELETE, "/reused", Bytes::new()))
            .await
            .status(),
        204
    );
    let taken_again = exchange(&service, as_alt(http::Method::PUT, "/reused", Bytes::new())).await;
    assert_eq!(taken_again.status(), 200, "{}", body_of(&taken_again));
    let refused = exchange(&service, as_main(http::Method::PUT, "/reused/key", Bytes::from_static(b"x"))).await;
    assert_eq!(
        refused.status(),
        200,
        "the data-root owner still owns a guest-created bucket: {}",
        body_of(&refused)
    );

    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/kept", Bytes::new()))
            .await
            .status(),
        200
    );
    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/kept/key", Bytes::from_static(b"x")))
            .await
            .status(),
        200
    );
    let not_empty = exchange(&service, as_main(http::Method::DELETE, "/kept", Bytes::new())).await;
    assert_eq!(not_empty.status(), 409, "{}", body_of(&not_empty));
    let still_refused = exchange(&service, as_alt(http::Method::GET, "/kept/key", Bytes::new())).await;
    assert_eq!(still_refused.status(), 403, "{}", body_of(&still_refused));
}

/// Negative — a creation the backend refused leaves no owner record behind, so the same
/// identity may still create the bucket properly afterwards; the record follows the creation
/// and not the admission (rustfs/gateway#811).
#[tokio::test]
async fn n_a_refused_creation_records_no_owner() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let owners = Arc::new(BucketOwners::default());
    let backend = Arc::new(open_backend(&options).expect("a usable data root"));
    let service = build_service(&options, &backend, &owners).expect("a complete service");

    // Object Lock is what the reference backend refuses at creation; the RustFS profile no longer
    // refuses any `LocationConstraint` (rustfs/gateway#914), so that cannot be the trigger.
    let object_lock = [("x-amz-bucket-object-lock-enabled", "true")];
    let refused = exchange(
        &service,
        signed(ALT_KEY, ALT_SECRET, http::Method::PUT, "/unmade", Bytes::new(), &object_lock),
    )
    .await;
    assert_eq!(refused.status(), 501, "{}", body_of(&refused));
    {
        use rustfs_gateway::BucketOwnerSource as _;
        let name = rustfs_gateway::BucketName::new("unmade").expect("a valid bucket name");
        assert!(owners.owner(&name).await.is_err(), "a refused creation must not be recorded");
    }

    assert_eq!(
        exchange(&service, as_alt(http::Method::PUT, "/unmade", Bytes::new()))
            .await
            .status(),
        200
    );
}

/// Negative — with only one identity configured, no second identity can sign at all. This is
/// what a suite that forgot to configure the second identity must run into: a service that
/// cannot be reached as the second principal, rather than one that quietly serves it.
#[tokio::test]
async fn n_an_unconfigured_second_identity_cannot_authenticate() {
    let root = TestRoot::new();
    let options = parse_options([
        "--data",
        &root.0.to_string_lossy(),
        "--access-key",
        MAIN_KEY,
        "--secret-key",
        MAIN_SECRET,
    ])
    .expect("a valid single-identity command line");
    let (_backend, service) = assembled(&options);

    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/solo", Bytes::new()))
            .await
            .status(),
        200
    );
    let refused = exchange(&service, as_alt(http::Method::GET, "/solo", Bytes::new())).await;
    assert_eq!(refused.status(), 403, "{}", body_of(&refused));
}

/// Negative — an unsigned request reaches no bucket, owned or not.
#[tokio::test]
async fn n_an_anonymous_request_is_refused() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);

    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/main-bucket", Bytes::new()))
            .await
            .status(),
        200
    );
    let anonymous = http::Request::builder()
        .method(http::Method::GET)
        .uri("/main-bucket/key")
        .header(http::header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("a valid unsigned request");
    let refused = exchange(&service, anonymous).await;
    assert!(refused.status() == 403 || refused.status() == 401, "{}", refused.status());
}

/// Positive and negative — the configured owner id is the value a caller may assert with
/// `x-amz-expected-bucket-owner`, and the other identity's owner id is refused against the
/// same bucket. This is what makes `--owner-id` a value the wire can observe rather than a
/// string the launcher parsed and dropped.
#[tokio::test]
async fn the_configured_owner_id_answers_an_expected_bucket_owner_assertion() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);

    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/owned", Bytes::new()))
            .await
            .status(),
        200
    );
    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/owned/key", Bytes::from_static(b"body")))
            .await
            .status(),
        200
    );

    let matching = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::GET,
        "/owned/key",
        Bytes::new(),
        &[("x-amz-expected-bucket-owner", MAIN_OWNER)],
    );
    assert_eq!(exchange(&service, matching).await.status(), 200);

    let mismatched = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::GET,
        "/owned/key",
        Bytes::new(),
        &[("x-amz-expected-bucket-owner", ALT_OWNER)],
    );
    let refused = exchange(&service, mismatched).await;
    assert_eq!(refused.status(), 403, "{}", body_of(&refused));
}

/// Positive — the launcher-provided bucket owner reaches the serialized object entry, with
/// XML metacharacters escaped by the production response encoder.
#[tokio::test]
async fn configured_owner_reaches_list_objects_v2_wire() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);

    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/reported-owner", Bytes::new()))
            .await
            .status(),
        200
    );
    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/reported-owner/key", Bytes::from_static(b"body")),)
            .await
            .status(),
        200
    );

    let listed = exchange(
        &service,
        as_main(http::Method::GET, "/reported-owner?list-type=2&fetch-owner=true", Bytes::new()),
    )
    .await;
    let body = body_of(&listed);
    assert_eq!(listed.status(), 200, "{body}");
    assert!(body.contains("<ID>s3gate-main</ID>"), "{body}");
    assert!(
        body.contains("<DisplayName>Main &lt;Owner&gt; &amp; &quot;Friends&quot;</DisplayName>"),
        "{body}"
    );
}

/// Negative — configuring an owner does not bypass the ListObjectsV2 fetch-owner switch.
#[tokio::test]
async fn n_list_objects_v2_omits_owner_without_fetch_owner() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);

    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/owner-gated", Bytes::new()))
            .await
            .status(),
        200
    );
    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/owner-gated/key", Bytes::from_static(b"body")),)
            .await
            .status(),
        200
    );

    let listed = exchange(&service, as_main(http::Method::GET, "/owner-gated?list-type=2", Bytes::new())).await;
    let body = body_of(&listed);
    assert_eq!(listed.status(), 200, "{body}");
    assert!(!body.contains("<Owner>"), "{body}");
}

/// The same document and the same checksum the reference backend's own lifecycle tests use, so
/// that a failure here is about the launcher's wiring and not about a hand-rolled digest.
const EXPIRE_ALL: &str = concat!(
    "<LifecycleConfiguration><Rule><Expiration><Days>1</Days></Expiration>",
    "<ID>expire-all</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status>",
    "</Rule></LifecycleConfiguration>"
);
const EXPIRE_ALL_MD5: &str = "5Y4m5g4gmXjRJtprF5EAXA==";

async fn put_lifecycle(service: &S3Service, bucket: &str) {
    let request = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::PUT,
        &format!("/{bucket}?lifecycle"),
        Bytes::from_static(EXPIRE_ALL.as_bytes()),
        &[("content-md5", EXPIRE_ALL_MD5)],
    );
    let response = exchange(service, request).await;
    assert_eq!(response.status(), 200, "{}", body_of(&response));
}

/// Positive — `--lc-debug-interval` reaches the backend and the sweeper, end to end: a
/// one-day expiration rule retires an object within seconds instead of within a day.
#[tokio::test]
async fn the_lifecycle_debug_interval_expires_a_one_day_rule_in_seconds() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &["--lc-debug-interval", "1"]);
    let (backend, service) = assembled(&options);

    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/lc-debug", Bytes::new()))
            .await
            .status(),
        200
    );
    put_lifecycle(&service, "lc-debug").await;
    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/lc-debug/key", Bytes::from_static(b"body")))
            .await
            .status(),
        200
    );
    assert_eq!(
        exchange(&service, as_main(http::Method::GET, "/lc-debug/key", Bytes::new()))
            .await
            .status(),
        200
    );

    let scheduler = backend.start_lifecycle_scheduler().expect("a runtime is active");
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    let report = scheduler.shutdown().await.expect("the scheduler joins cleanly");

    assert!(report.sweeps >= 1, "no sweep ran: {report:?}");
    assert_eq!(report.failed_sweeps, 0, "{report:?}");
    assert_eq!(
        exchange(&service, as_main(http::Method::GET, "/lc-debug/key", Bytes::new()))
            .await
            .status(),
        404
    );
}

/// Negative — the same rule, the same wait, and no `--lc-debug-interval`: the object survives.
/// Without this half the case above is satisfied by a backend that expires everything.
#[tokio::test]
async fn n_without_the_debug_interval_a_one_day_rule_expires_nothing() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (backend, service) = assembled(&options);

    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/lc-debug", Bytes::new()))
            .await
            .status(),
        200
    );
    put_lifecycle(&service, "lc-debug").await;
    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/lc-debug/key", Bytes::from_static(b"body")))
            .await
            .status(),
        200
    );

    let scheduler = backend.start_lifecycle_scheduler().expect("a runtime is active");
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    let report = scheduler.shutdown().await.expect("the scheduler joins cleanly");

    assert_eq!(report.sweeps, 0, "a production cadence swept within seconds: {report:?}");
    assert_eq!(
        exchange(&service, as_main(http::Method::GET, "/lc-debug/key", Bytes::new()))
            .await
            .status(),
        200
    );
}

/// The bucket-policy enforcement cases, beside these in their own file.
#[path = "tests/policy_tests.rs"]
mod policy_tests;

/// What the RustFS profile accepts beyond the AWS defaults: MinIO checksum-less writes (#916), an
/// explicit us-east-1 constraint (#914), s3cmd's ACL writes (#912), SigV2 presigned URLs (#913),
/// an oversized `max-keys`, any and empty signing regions, every checksum-less write
/// (rustfs/backlog#1677).
mod checksum_omission_tests;
mod location_constraint_tests;
mod minio_checksum_tests;
mod page_size_tests;
mod s3cmd_acl_tests;
mod signing_region_tests;
mod sigv2_presigned_tests;

/// Listings under `encoding-type=url` rendered as legacy RustFS renders them (rustfs/gateway#1059).
mod listing_encoding_tests;

/// A presigned URL's lifetime, read as legacy RustFS reads it (rustfs/rustfs#5368).
mod presigned_expiry_tests;

/// Bucket-policy conditions on the request's encryption header (rustfs/gateway#979).
mod sse_condition_tests;

/// The path spelling a signature is verified over, as legacy RustFS verifies it (rustfs/rustfs#2593).
mod raw_path_tests;

/// A presigned upload's `x-amz-content-sha256`, read as legacy RustFS reads it (rustfs/rustfs#2379).
mod presigned_payload_tests;

/// An anonymous aws-chunked upload left undecoded, as legacy RustFS leaves it (rustfs/gateway#1060).
mod anonymous_chunked_tests;

/// An empty upload without `Content-Length`, stored as legacy RustFS stores it (rustfs/rustfs#6849).
mod empty_upload_tests;

/// The gateway's CORS answers over the backend's stored documents (rustfs/gateway#1004).
mod cors_tests;

/// Request-body refusals answered with legacy RustFS's sentences (rustfs/gateway#1099).
mod body_refusal_tests;

/// The signed digest of a request without a body, left uncompared as legacy RustFS leaves it
/// (rustfs/gateway#1099).
mod bodyless_digest_tests;

/// The request settings RustFS embeds the gateway with (rustfs/gateway#1070).
mod deadline_tests;

/// RustFS fixes of the legacy stack the RustFS profile already matches: ACL grantee namespaces,
/// `Expires` as sent, and `Last-Modified` through `If-Modified-Since` (rustfs/gateway#1099).
mod legacy_reading_tests;

/// `HEAD` answers and the bodyless statuses shaped as legacy RustFS shapes them (rustfs/gateway#1120).
mod head_bodyless_tests;

/// The object headers of a `304`, as legacy RustFS answers it (rustfs/gateway#1120).
mod not_modified_tests;

/// The header-signed SigV4 spellings the RustFS profile accepts and refuses as legacy RustFS does
/// (rustfs/gateway#1099).
mod sigv4_acceptance_tests;

/// Request-checksum failures answered with legacy RustFS's `BadDigest` (rustfs/gateway#1057), and
/// what each refusal leaves in storage.
mod bad_digest_tests;

/// An empty required enumeration element answered as legacy RustFS answers it, never with `500`
/// (rustfs/gateway#1078).
mod empty_enumeration_tests;
/// The framework governor sized as RustFS embeds it (rustfs/gateway#1067).
mod governor_tests;

/// RustFS's 5 GiB ceiling on an upload's object, measured as RustFS measures it (rustfs/rustfs#7635).
mod upload_ceiling_tests;

/// The slash rule legacy RustFS applies to an object key (rustfs/gateway#1101).
mod slash_rule_tests;

/// The object keys legacy RustFS accepts, round-tripped onto the backend (rustfs/gateway#1107).
mod legacy_key_tests;

/// A request path addressed as legacy RustFS addresses it (rustfs/gateway#1115).
mod legacy_addressing_tests;

/// The operation a request names, selected as legacy RustFS selects it (rustfs/gateway#1127).
mod legacy_selection_tests;
