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

//! Signed production-service evidence for `GetBucketLocation` and the region it reports.
//!
//! Responsible for: the two answers a location can have — the us-east-1 null spelling as exact
//! bytes and a named region — the `EU` alias, the constraints a `CreateBucket` accepts and refuses,
//! the refusal for a bucket that is not there, and the agreement between `HeadBucket`'s
//! `x-amz-bucket-region` and this operation's body.
//! NOT responsible for: the XML shape of the answer. That the body is one unwrapped
//! `LocationConstraint` element that is emitted even when empty is
//! `spec/operations/GetBucketLocation.toml` and the codec's; this file pins which value goes in it.
//! Upstream: the shared CRUD service fixture. Downstream: the crate verification gate.

use super::*;
use rustfs_gateway::RegionMatchPolicy;

/// The exact body AWS sends for a bucket with a null location constraint.
///
/// Pinned as bytes rather than by containment because containment cannot tell an emitted empty
/// element from an omitted one, and `q-empty-0002` is precisely that AWS emits it. A client that
/// branches on the element's presence to decide the read succeeded has to see it.
const EMPTY_CONSTRAINT: &str = concat!(
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
    "<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></LocationConstraint>"
);

/// The exact body for a bucket whose constraint names `region`.
///
/// Also exact bytes, and for the same reason as the empty spelling: the element carries the
/// document's namespace, so a containment check for `<LocationConstraint>` matches neither answer
/// and would have to be loosened to a substring that cannot tell the two apart.
fn named_constraint(region: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{region}</LocationConstraint>"
    )
}

fn configuration(constraint: &str) -> Bytes {
    Bytes::from(format!(
        "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <LocationConstraint>{constraint}</LocationConstraint></CreateBucketConfiguration>"
    ))
}

async fn create_with(service: &S3Service, bucket: &str, body: Bytes) -> rustfs_gateway::WireResponse {
    exchange(service, signed(http::Method::PUT, &format!("/{bucket}"), body)).await
}

async fn location(service: &S3Service, bucket: &str) -> rustfs_gateway::WireResponse {
    exchange(service, signed(http::Method::GET, &format!("/{bucket}?location"), Bytes::new())).await
}

/// Positive — a us-east-1 deployment answers the null spelling, byte for byte.
///
/// This is rustfs/gateway#627 in one exchange. The operation was not registered, so it resolved in
/// the route table and answered `501`; minio-go asks a server for a bucket's region before it
/// touches an object unless one is configured on the client, and `mc` exposes no region setting, so
/// every `mc` object command stopped at this refusal.
#[tokio::test]
async fn a_us_east_1_deployment_answers_the_empty_element() {
    let root = TestRoot::new();
    let (_backend, service) = service(&root);
    create_bucket(&service, "loc-home").await;
    let response = location(&service, "loc-home").await;
    assert_eq!(response.status(), 200, "{}", String::from_utf8_lossy(response.body()));
    assert_eq!(String::from_utf8_lossy(response.body()), EMPTY_CONSTRAINT);
}

/// Positive — a deployment serving another region answers that region's name.
///
/// The pair with the case above is the only reason either is evidence. A handler stuck on `None`
/// satisfies every test expecting the empty element, and the empty element is what most
/// deployments answer, so a one-directional check here would have proved nothing.
#[tokio::test]
async fn another_region_is_reported_by_name() {
    let root = TestRoot::new();
    let (_backend, service) = service_in_region(&root, "eu-west-1");
    create_bucket(&service, "loc-named").await;
    let response = location(&service, "loc-named").await;
    assert_eq!(response.status(), 200, "{}", String::from_utf8_lossy(response.body()));
    assert_eq!(String::from_utf8_lossy(response.body()), named_constraint("eu-west-1"));
}

/// Negative — the `EU` legacy alias names eu-west-1 and is reported as eu-west-1.
///
/// `q-region-0003`: `EU` denotes eu-west-1 rather than being a second region. A deployment that
/// stored the alias verbatim would report a name half of the enumeration's readers treat as
/// historical, for a bucket a client asked for by its modern name.
#[tokio::test]
async fn n_the_eu_alias_is_reported_as_eu_west_1() {
    let root = TestRoot::new();
    let (_backend, service) = service_in_region(&root, "EU");
    create_bucket(&service, "loc-alias").await;
    assert_eq!(
        String::from_utf8_lossy(location(&service, "loc-alias").await.body()),
        named_constraint("eu-west-1")
    );
}

/// Negative — a constraint naming the served region is accepted, and reported back.
#[tokio::test]
async fn n_a_constraint_naming_the_served_region_is_accepted() {
    let root = TestRoot::new();
    let (_backend, service) = service_in_region(&root, "eu-west-1");
    assert_eq!(create_with(&service, "loc-match", configuration("eu-west-1")).await.status(), 200);
    assert_eq!(
        String::from_utf8_lossy(location(&service, "loc-match").await.body()),
        named_constraint("eu-west-1")
    );
}

/// Negative — `us-east-1` written out is refused even by a us-east-1 deployment.
///
/// This is the rule reimplementations skip most often: the constraint enum has no us-east-1 value,
/// and a us-east-1 creation must omit it. Accepting it here would let a bucket be created whose
/// constraint `GetBucketLocation` can never echo back.
#[tokio::test]
async fn n_an_explicit_us_east_1_constraint_is_refused() {
    let root = TestRoot::new();
    let (_backend, service) = service(&root);
    let response = create_with(&service, "loc-explicit-home", configuration("us-east-1")).await;
    assert_eq!(response.status(), 400, "{}", String::from_utf8_lossy(response.body()));
    assert_eq!(element(response.body(), "Code").as_deref(), Some("InvalidLocationConstraint"));
}

/// The backend assembled with the RustFS-profile constraint posture (rustfs/gateway#914).
fn relaxed_service(root: &TestRoot, region: &str) -> (Arc<FsBackend>, S3Service) {
    let backend = FsBackend::open_with_clock(&root.0, Arc::new(FixedClock::at_unix_seconds(SIGNED_AT_SECONDS)))
        .expect("a usable test root")
        .with_region(region)
        .expect("a region the model names")
        .with_region_match_policy(RegionMatchPolicy::AcceptExplicitUsEast1);
    service_with_backend(Arc::new(backend))
}

/// Positive — under the relaxed posture, the explicit us-east-1 minio-java sends creates a bucket
/// that reports the us-east-1 null spelling, exactly as an omitted constraint would.
#[tokio::test]
async fn an_explicit_us_east_1_constraint_is_accepted_when_the_backend_opts_in() {
    let root = TestRoot::new();
    let (_backend, service) = relaxed_service(&root, "us-east-1");
    let response = create_with(&service, "loc-explicit-relaxed", configuration("us-east-1")).await;
    assert_eq!(response.status(), 200, "{}", String::from_utf8_lossy(response.body()));
    assert_eq!(
        String::from_utf8_lossy(location(&service, "loc-explicit-relaxed").await.body()),
        EMPTY_CONSTRAINT
    );
}

/// Negative — the relaxed posture changes the us-east-1 spelling only: an unserved region, and an
/// explicit us-east-1 sent to a deployment elsewhere, are still refused and leave no bucket.
#[tokio::test]
async fn n_the_relaxed_posture_refuses_everything_strict_refuses_but_the_spelling() {
    let home = TestRoot::new();
    let (_home_backend, home_service) = relaxed_service(&home, "us-east-1");
    let away = TestRoot::new();
    let (_away_backend, away_service) = relaxed_service(&away, "eu-west-1");
    for (service, constraint) in [
        (&home_service, "eu-west-1"),
        (&home_service, "US-EAST-1"),
        (&away_service, "us-east-1"),
    ] {
        let refused = create_with(service, "loc-relaxed-refused", configuration(constraint)).await;
        assert_eq!(refused.status(), 400, "{constraint}: {}", String::from_utf8_lossy(refused.body()));
        assert_eq!(element(refused.body(), "Code").as_deref(), Some("InvalidLocationConstraint"));
        let head = exchange(service, signed(http::Method::HEAD, "/loc-relaxed-refused", Bytes::new())).await;
        assert_eq!(head.status(), 404, "{constraint}: the refused creation left a bucket behind");
    }
}

/// Negative — a region the deployment does not serve is refused, and leaves no bucket behind.
///
/// The second half is the part a late check gets wrong. A constraint judged after the directories
/// exist leaves a bucket the caller was told does not exist, and the next `HEAD` on it succeeds.
#[tokio::test]
async fn n_an_unserved_region_is_refused_before_the_bucket_exists() {
    let root = TestRoot::new();
    let (_backend, service) = service(&root);
    let refused = create_with(&service, "loc-elsewhere", configuration("eu-west-1")).await;
    assert_eq!(refused.status(), 400, "{}", String::from_utf8_lossy(refused.body()));
    assert_eq!(element(refused.body(), "Code").as_deref(), Some("InvalidLocationConstraint"));
    assert_eq!(
        exchange(&service, signed(http::Method::HEAD, "/loc-elsewhere", Bytes::new()))
            .await
            .status(),
        404,
        "the refused creation left a bucket behind"
    );
}

/// Negative — an empty element on the way in means "unspecified", not a region named "".
///
/// Clients that serialise an absent field as an empty element send exactly this, and refusing it
/// would break them for no protocol reason.
#[tokio::test]
async fn n_an_empty_constraint_element_means_unspecified() {
    let root = TestRoot::new();
    let (_backend, service) = service(&root);
    assert_eq!(create_with(&service, "loc-empty", configuration("")).await.status(), 200);
    assert_eq!(String::from_utf8_lossy(location(&service, "loc-empty").await.body()), EMPTY_CONSTRAINT);
}

/// Negative — a bucket that does not exist is `NoSuchBucket`, not an empty constraint.
///
/// The empty element is a *successful* answer. Serving it for an absent bucket would tell `mc` the
/// bucket exists and is in us-east-1, and send it on to the object command that cannot work.
#[tokio::test]
async fn n_a_missing_bucket_is_refused_rather_than_answered_empty() {
    let root = TestRoot::new();
    let (_backend, service) = service(&root);
    let response = location(&service, "loc-absent").await;
    assert_eq!(response.status(), 404, "{}", String::from_utf8_lossy(response.body()));
    assert_eq!(element(response.body(), "Code").as_deref(), Some("NoSuchBucket"));
}

/// Negative — `HeadBucket` and `GetBucketLocation` report one region, in both directions.
///
/// `x-amz-bucket-region` was the literal `"us-east-1"` before this change. A second literal beside
/// the new answer would let a deployment tell a client its bucket is in one region through the
/// header and another through the body, and minio-go reads whichever it asked for first.
#[tokio::test]
async fn n_head_bucket_and_get_bucket_location_report_one_region() {
    let home = TestRoot::new();
    let (_home_backend, home_service) = service(&home);
    create_bucket(&home_service, "loc-agree-home").await;
    let head = exchange(&home_service, signed(http::Method::HEAD, "/loc-agree-home", Bytes::new())).await;
    assert_eq!(
        header(&head, "x-amz-bucket-region").and_then(|value| value.to_str().ok()),
        Some("us-east-1")
    );
    assert_eq!(
        String::from_utf8_lossy(location(&home_service, "loc-agree-home").await.body()),
        EMPTY_CONSTRAINT
    );

    let away = TestRoot::new();
    let (_away_backend, away_service) = service_in_region(&away, "eu-west-1");
    create_bucket(&away_service, "loc-agree-away").await;
    let head = exchange(&away_service, signed(http::Method::HEAD, "/loc-agree-away", Bytes::new())).await;
    assert_eq!(
        header(&head, "x-amz-bucket-region").and_then(|value| value.to_str().ok()),
        Some("eu-west-1")
    );
    assert_eq!(
        String::from_utf8_lossy(location(&away_service, "loc-agree-away").await.body()),
        named_constraint("eu-west-1")
    );
}

/// Negative — a region the enumeration cannot name is refused when the backend is assembled.
///
/// Refusing here rather than at request time is the whole point: a backend that accepted it would
/// have to fail or lie the first time a client asked where its buckets are, and by then the buckets
/// exist.
#[tokio::test]
async fn n_an_unnameable_region_is_refused_at_assembly() {
    let root = TestRoot::new();
    for hostile in ["mars-north-1", "", "US-WEST-2", "eu"] {
        let backend = FsBackend::open(&root.0).expect("a usable test root");
        assert!(
            backend.with_region(hostile).is_err(),
            "the backend accepted a region it cannot report: {hostile:?}"
        );
    }
    let accepted = FsBackend::open(&root.0)
        .expect("a usable test root")
        .with_region("us-west-2")
        .expect("a region the model names");
    assert_eq!(accepted.region(), "us-west-2");
}

/// Negative — re-creating your own bucket outside us-east-1 is `409 BucketAlreadyOwnedByYou`, the
/// operation's own status matrix (`crates/core/src/ops/create_bucket.rs`); the same request in
/// us-east-1 is the historical `200`. A backend that answered `200` everywhere hid the region half
/// of the matrix behind the one region every test happened to use.
#[tokio::test]
async fn n_recreating_an_owned_bucket_outside_us_east_1_is_already_owned_by_you() {
    let root = TestRoot::new();
    let (_backend, regional) = service_in_region(&root, "eu-west-1");
    create_bucket(&regional, "loc-owned").await;
    let again = create_with(&regional, "loc-owned", Bytes::new()).await;
    let body = String::from_utf8_lossy(again.body()).into_owned();
    assert_eq!(again.status(), 409, "{body}");
    assert!(body.contains("<Code>BucketAlreadyOwnedByYou</Code>"), "{body}");

    let root = TestRoot::new();
    let (_backend, historical) = service(&root);
    create_bucket(&historical, "loc-owned").await;
    let again = create_with(&historical, "loc-owned", Bytes::new()).await;
    assert_eq!(
        again.status(),
        200,
        "us-east-1 keeps the historical 200: {}",
        String::from_utf8_lossy(again.body())
    );
}

/// Negative — `GetBucketLocation` is in the advertised operation set.
///
/// The compatibility matrix decides whether a scenario runs at all from
/// `compat/capabilities.toml`, and `ci/compat/run_matrix.sh` refuses to run when that file and the
/// registry the launcher built disagree. A handler registered without appearing here is one the
/// matrix would keep recording as `unsupported`.
#[tokio::test]
async fn n_get_bucket_location_is_advertised_by_the_capability_list() {
    let root = TestRoot::new();
    let (backend, _service) = service(&root);
    assert!(
        backend.supported_operations().any(|name| name == "GetBucketLocation"),
        "the advertised set does not name the registered operation"
    );
}

async fn create_with_object_lock(service: &S3Service, bucket: &str, enabled: &'static str) -> rustfs_gateway::WireResponse {
    let mut headers = http::HeaderMap::new();
    headers.insert("x-amz-bucket-object-lock-enabled", http::HeaderValue::from_static(enabled));
    exchange(
        service,
        signed_with_headers(http::Method::PUT, &format!("/{bucket}"), Bytes::new(), headers),
    )
    .await
}

#[tokio::test]
async fn object_lock_creation_is_refused_without_creating_a_bucket() {
    let root = TestRoot::new();
    let (_backend, service) = service(&root);
    let response = create_with_object_lock(&service, "lock-new", "true").await;
    assert_eq!(response.status(), 501);
    let head = exchange(&service, signed(http::Method::HEAD, "/lock-new", Bytes::new())).await;
    assert_eq!(head.status(), 404, "a refused lock request must not create a bucket");
}

#[tokio::test]
async fn object_lock_creation_is_refused_for_an_existing_bucket() {
    let root = TestRoot::new();
    let (_backend, service) = service(&root);
    create_bucket(&service, "lock-existing").await;
    let response = create_with_object_lock(&service, "lock-existing", "true").await;
    assert_eq!(response.status(), 501, "an existing bucket must not bypass the capability refusal");
}

#[tokio::test]
async fn object_lock_false_and_absent_allow_ordinary_bucket_creation() {
    let root = TestRoot::new();
    let (_backend, service) = service(&root);
    let response = create_with_object_lock(&service, "lock-false", "false").await;
    assert_eq!(response.status(), 200);
    create_bucket(&service, "lock-absent").await;
}
