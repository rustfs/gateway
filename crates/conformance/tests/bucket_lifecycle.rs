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

//! The bucket lifecycle family end to end: route, codec, region rules, response bytes.
//!
//! Responsible for: the half of the status matrix the corpus cannot reach. The in-process
//! transport serves one region — `us-east-1`, the region every case signs for — so the two
//! outcomes that only exist *outside* us-east-1 (`BucketAlreadyOwnedByYou`) and the one that needs
//! a second account (`BucketAlreadyExists`) are asserted here, against a fixture whose home region
//! and ownership this test sets directly. The us-east-1 halves of the same contrasts live in
//! `conformance/cases/bkt/`, so each pair has one assertion in each place.
//! NOT responsible for: anything the corpus can express. A case belongs in `conformance/cases/bkt/`
//! whenever the in-process transport can run it, because a case is portable to another S3
//! implementation and a test in this file is not.
//! Upstream: the published API of `rustfs_gateway` and `rustfs_gateway_conformance::fixture`.
//! Downstream: nothing.
//!
//! # Why the service is assembled here rather than reused
//!
//! `InProcess::assemble` pins the region set to `us-east-1`, which is what makes it the transport
//! the corpus runs on. The region-dependent half of this family needs a deployment that serves
//! something else, and that is a different service — so it is built here, over the same [`Stub`]
//! and the same credentials, and every request is really signed because an unsigned one is refused
//! by the floor before routing.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway::sig::{AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};
use rustfs_gateway::{
    Credentials, FixedClock, Limits, RegionSet, S3Service, ServiceBuilder, SigV4Authenticator, StaticCredentials, WireRequest,
    allow_when, collect, dto,
};
use rustfs_gateway_conformance::exec::block_on;
use rustfs_gateway_conformance::fixture::{Fixture, StoredObject, Stub};
use rustfs_gateway_conformance::inprocess::{HOST, VALID_ACCESS_KEY, VALID_SECRET};

/// The instant every fixture below is pinned to, and the stamp its signatures carry.
const NOW: i64 = 1_767_322_845;
const NOW_STAMP: &str = "20260102T030405Z";

/// One assembled service over one fixture, and the state behind it.
struct Harness {
    service: S3Service,
    region: String,
    state: Arc<Mutex<Fixture>>,
}

/// What one exchange observed.
struct Answer {
    status: u16,
    body: String,
    headers: Vec<(String, String)>,
}

impl Answer {
    fn assert_contains(&self, needle: &str) {
        assert!(self.body.contains(needle), "the body does not contain {needle}: {}", self.body);
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

impl Harness {
    /// A deployment serving one region, with no buckets in it.
    fn serving(region: &str) -> Harness {
        let mut fixture = Fixture::at(NOW);
        fixture.home_region = region.to_owned();
        Harness::over(fixture, region)
    }

    fn over(fixture: Fixture, region: &str) -> Harness {
        let state = Arc::new(Mutex::new(fixture));
        let backend = Arc::new(Stub::new(Arc::clone(&state)));
        let credentials =
            Arc::new(StaticCredentials::new().with(Credentials::new(VALID_ACCESS_KEY, VALID_SECRET).expect("a valid key id")));
        let service = ServiceBuilder::new()
            .register::<dto::CreateBucket, _>(Arc::clone(&backend))
            .register::<dto::DeleteBucket, _>(Arc::clone(&backend))
            .register::<dto::HeadBucket, _>(Arc::clone(&backend))
            // The lifecycle read rides along for the recreation test below: the unconfigured 404
            // is the observable proof that a recreated bucket inherited no lifecycle document.
            .register::<dto::GetBucketLifecycleConfiguration, _>(Arc::clone(&backend))
            .register::<dto::PutObject, _>(Arc::clone(&backend))
            .authenticator(SigV4Authenticator::new(credentials, RegionSet::new([region]).expect("non-empty")))
            .authorizer(allow_when(|request| !request.is_anonymous()))
            .clock(FixedClock::at_unix_seconds(NOW))
            .build()
            .expect("the service assembles");
        Harness {
            service,
            region: region.to_owned(),
            state,
        }
    }

    /// Signs one request and drains what came back.
    fn send(&self, method: &str, target: &str, body: &'static [u8]) -> Answer {
        let (path, query) = target.split_once('?').map_or((target, ""), |(path, query)| (path, query));

        let mut map = http::HeaderMap::new();
        map.append(http::header::HOST, http::HeaderValue::from_static(HOST));
        map.append("content-length", http::HeaderValue::from(body.len()));

        let probe = http::Request::builder()
            .method("GET")
            .uri("/")
            .header("host", HOST)
            .body(Bytes::new())
            .expect("a well-formed probe");
        let accepted = WireRequest::accept(probe, &Limits::default()).expect("the probe host is acceptable");

        let credentials = SigningCredentials::new(VALID_ACCESS_KEY, VALID_SECRET).expect("valid signing credentials");
        let stamp = AmzDate::parse(NOW_STAMP).expect("a SigV4 stamp");
        let scope = SigningScope::new(stamp.day(), &self.region, SigService::S3).expect("a well-formed scope");
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
        let request = builder.body(Bytes::from_static(body)).expect("a well-formed request");
        let response = block_on(self.service.call_bytes(request));
        let (parts, payload) = response.into_parts();
        let status = parts.status.as_u16();
        let headers: Vec<(String, String)> = parts
            .headers
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), String::from_utf8_lossy(value.as_bytes()).into_owned()))
            .collect();
        let drained = block_on(collect(http::Response::from_parts(parts, payload))).expect("the body drains");
        Answer {
            status,
            body: String::from_utf8_lossy(drained.body()).into_owned(),
            headers,
        }
    }

    fn declare_bucket(&self, name: &str) {
        self.state
            .lock()
            .expect("the fixture is not poisoned")
            .declare_bucket(name, false);
    }

    fn has_bucket(&self, name: &str) -> bool {
        self.state.lock().expect("the fixture is not poisoned").has_bucket(name)
    }
}

/// Positive — a creation outside us-east-1 names the region in its constraint and succeeds with the
/// 200 and the `Location` header, exactly as the unconstrained us-east-1 form does.
#[test]
fn a_constrained_creation_in_the_served_region_succeeds() {
    let harness = Harness::serving("us-west-2");
    let answer = harness.send(
        "PUT",
        "/conf-bkt-west",
        b"<CreateBucketConfiguration><LocationConstraint>us-west-2</LocationConstraint></CreateBucketConfiguration>",
    );
    assert_eq!(answer.status, 200, "{}", answer.body);
    assert_eq!(answer.header("location"), Some("/conf-bkt-west"));
    assert!(harness.has_bucket("conf-bkt-west"));
}

/// Negative — re-creating your own bucket outside us-east-1 is `409 BucketAlreadyOwnedByYou`.
///
/// The us-east-1 half of this contrast is `c-bkt-0010`, which asserts the historical `200` for the
/// same request. The two together are the whole of the region-dependent rule, and an implementation
/// that answered one status everywhere would fail exactly one of them.
#[test]
fn n_recreating_your_own_bucket_outside_us_east_1_is_a_conflict() {
    let harness = Harness::serving("us-west-2");
    harness.declare_bucket("conf-bkt-dup");
    let answer = harness.send("PUT", "/conf-bkt-dup", b"");
    assert_eq!(answer.status, 409, "{}", answer.body);
    answer.assert_contains("BucketAlreadyOwnedByYou");
    assert!(harness.has_bucket("conf-bkt-dup"), "the bucket was removed by a refused creation");
}

/// Negative — a name held by another account is `409 BucketAlreadyExists`, a different code from
/// the one above. Conflating the two tells a caller to reuse a name that is not theirs to reuse.
#[test]
fn n_a_name_held_by_another_owner_is_a_different_conflict() {
    let mut fixture = Fixture::at(NOW);
    fixture.declare_bucket("conf-bkt-theirs", false);
    fixture.declare_bucket_owned_by_other("conf-bkt-theirs");
    let harness = Harness::over(fixture, "us-east-1");
    let answer = harness.send("PUT", "/conf-bkt-theirs", b"");
    assert_eq!(answer.status, 409, "{}", answer.body);
    answer.assert_contains("BucketAlreadyExists");
    assert!(!answer.body.contains("BucketAlreadyOwnedByYou"), "{}", answer.body);
}

/// Negative — outside us-east-1 the same duplicate creation is refused even for a bucket the
/// fixture placed in the served region: the region gate is about the *deployment*, not the bucket.
#[test]
fn n_the_duplicate_conflict_does_not_depend_on_the_buckets_own_placement() {
    let mut fixture = Fixture::at(NOW);
    fixture.home_region = "eu-west-1".to_owned();
    fixture.declare_bucket("conf-bkt-eu", false);
    fixture.set_bucket_region("conf-bkt-eu", "eu-west-1");
    let harness = Harness::over(fixture, "eu-west-1");
    let answer = harness.send("PUT", "/conf-bkt-eu", b"");
    assert_eq!(answer.status, 409, "{}", answer.body);
    answer.assert_contains("BucketAlreadyOwnedByYou");
}

/// Negative — the `EU` alias is accepted where eu-west-1 is served, which is the half a corpus case
/// signing for us-east-1 cannot show: `c-bkt-0014` asserts the alias is *refused* there, and the
/// two together prove the alias is normalised before the region is matched rather than special-cased.
#[test]
fn n_the_eu_alias_is_accepted_where_eu_west_1_is_served() {
    let harness = Harness::serving("eu-west-1");
    let answer = harness.send(
        "PUT",
        "/conf-bkt-alias",
        b"<CreateBucketConfiguration><LocationConstraint>EU</LocationConstraint></CreateBucketConfiguration>",
    );
    assert_eq!(answer.status, 200, "{}", answer.body);
    assert!(harness.has_bucket("conf-bkt-alias"));
}

/// Negative — a bucket the deployment does not hold is a `301` carrying `x-amz-bucket-region`, in
/// every method of the family. The header is the assertion: without it an SDK cannot re-target the
/// request and reports a failure instead of retrying.
#[test]
fn n_every_method_redirects_a_foreign_bucket_with_the_region_header() {
    let mut fixture = Fixture::at(NOW);
    fixture.declare_bucket("conf-bkt-far", false);
    fixture.set_bucket_region("conf-bkt-far", "eu-west-1");
    let harness = Harness::over(fixture, "us-east-1");
    for method in ["DELETE", "HEAD"] {
        let answer = harness.send(method, "/conf-bkt-far", b"");
        assert_eq!(answer.status, 301, "{method}: {}", answer.body);
        assert_eq!(
            answer.header("x-amz-bucket-region"),
            Some("eu-west-1"),
            "{method} must name the region the bucket is in"
        );
    }
}

/// Negative — the `301` document names the region as well, for the clients that read the body
/// rather than the head. A `HEAD` has no body to read, which is why the header is the mandatory
/// half and this is the additional one.
#[test]
fn n_the_redirect_document_also_names_the_region() {
    let mut fixture = Fixture::at(NOW);
    fixture.declare_bucket("conf-bkt-far", false);
    fixture.set_bucket_region("conf-bkt-far", "eu-west-1");
    let harness = Harness::over(fixture, "us-east-1");
    let answer = harness.send("DELETE", "/conf-bkt-far", b"");
    answer.assert_contains("<Code>PermanentRedirect</Code>");
    answer.assert_contains("<BucketName>conf-bkt-far</BucketName>");
    answer.assert_contains("<Region>eu-west-1</Region>");
}

/// Negative — a bucket holding an in-progress upload is not empty either, so its deletion is
/// refused. Objects are the obvious half; an upload is the half a store that counted only committed
/// keys would delete out from under the parts it is still holding.
#[test]
fn n_a_bucket_holding_only_an_upload_is_not_empty() {
    let mut fixture = Fixture::at(NOW);
    fixture.declare_bucket("conf-bkt-mpu", false);
    fixture.create_upload("conf-bkt-mpu", "pending");
    let harness = Harness::over(fixture, "us-east-1");
    let answer = harness.send("DELETE", "/conf-bkt-mpu", b"");
    assert_eq!(answer.status, 409, "{}", answer.body);
    answer.assert_contains("BucketNotEmpty");
    assert!(harness.has_bucket("conf-bkt-mpu"));
}

/// Negative — a versioned bucket whose only key is hidden behind a delete marker still holds
/// versions, so it is not empty. A store that listed live keys and saw none would delete a bucket
/// with a recoverable history in it.
#[test]
fn n_a_bucket_whose_keys_are_all_delete_markers_is_not_empty() {
    let mut fixture = Fixture::at(NOW);
    fixture.declare_bucket("conf-bkt-versions", true);
    fixture.put_object("conf-bkt-versions", "gone", StoredObject::new(b"bytes".to_vec(), None, NOW));
    fixture.remove_object("conf-bkt-versions", "gone");
    let harness = Harness::over(fixture, "us-east-1");
    let answer = harness.send("DELETE", "/conf-bkt-versions", b"");
    assert_eq!(answer.status, 409, "{}", answer.body);
    answer.assert_contains("BucketNotEmpty");
}

/// Positive — the region a `HeadBucket` reports is the deployment's, whichever region that is.
#[test]
fn the_head_response_reports_the_deployments_own_region() {
    let harness = Harness::serving("us-west-2");
    harness.declare_bucket("conf-bkt-here");
    let answer = harness.send("HEAD", "/conf-bkt-here", b"");
    assert_eq!(answer.status, 200, "{}", answer.body);
    assert_eq!(answer.header("x-amz-bucket-region"), Some("us-west-2"));
    assert!(answer.body.is_empty(), "a HEAD response must carry no body: {}", answer.body);
}

/// Negative — a creation naming a region this deployment does not serve is refused, and the bucket
/// is not created as a side effect of the refusal.
#[test]
fn n_a_creation_for_an_unserved_region_creates_nothing() {
    let harness = Harness::serving("us-west-2");
    let answer = harness.send(
        "PUT",
        "/conf-bkt-nope",
        b"<CreateBucketConfiguration><LocationConstraint>eu-west-1</LocationConstraint></CreateBucketConfiguration>",
    );
    assert_eq!(answer.status, 400, "{}", answer.body);
    answer.assert_contains("InvalidLocationConstraint");
    assert!(!harness.has_bucket("conf-bkt-nope"), "a refused creation created the bucket");
}

/// Negative — outside us-east-1 the explicit `us-east-1` constraint is refused too, and for the
/// same reason: the name is not a value the constraint may take at all.
#[test]
fn n_the_explicit_us_east_1_constraint_is_refused_everywhere() {
    let harness = Harness::serving("us-west-2");
    let answer = harness.send(
        "PUT",
        "/conf-bkt-east",
        b"<CreateBucketConfiguration><LocationConstraint>us-east-1</LocationConstraint></CreateBucketConfiguration>",
    );
    assert_eq!(answer.status, 400, "{}", answer.body);
    answer.assert_contains("InvalidLocationConstraint");
}

/// Negative — a deletion is not a creation's inverse for a bucket that was never there: a missing
/// bucket is a `404`, and nothing is minted on the way past.
#[test]
fn n_deleting_a_bucket_that_was_never_created_is_a_not_found() {
    let harness = Harness::serving("us-east-1");
    let answer = harness.send("DELETE", "/conf-bkt-absent", b"");
    assert_eq!(answer.status, 404, "{}", answer.body);
    answer.assert_contains("NoSuchBucket");
    assert!(!harness.has_bucket("conf-bkt-absent"));
}

/// Negative — a deleted bucket takes its configuration documents with it.
///
/// The CORS document, the tag set and the lifecycle document live inside the bucket's own state
/// entry, so removing the bucket removes them by construction — and this test is what keeps that
/// a fact rather than a coincidence of today's layout. The failure it guards against is
/// inheritance: delete a bucket, create a new one under the same name, and find it answering the
/// previous owner's CORS rules to browsers, the previous owner's tags to billing, and — worst of
/// the three — expiring the new owner's data on the previous owner's schedule. A name is not a
/// bucket.
#[test]
fn n_a_deleted_buckets_cors_tags_and_lifecycle_do_not_survive_into_a_recreation() {
    let mut fixture = Fixture::at(NOW);
    fixture.declare_bucket("conf-bkt-reborn", false);
    fixture.set_cors(
        "conf-bkt-reborn",
        dto::CorsConfiguration {
            cors_rules: vec![dto::CorsRule {
                allowed_methods: vec!["GET".to_owned()],
                allowed_origins: vec!["https://example.com".to_owned()],
                ..dto::CorsRule::default()
            }],
        },
    );
    fixture.set_bucket_tags("conf-bkt-reborn", Some(vec![("team".to_owned(), "storage".to_owned())]));
    fixture.set_lifecycle(
        "conf-bkt-reborn",
        dto::BucketLifecycleConfiguration {
            rules: vec![dto::LifecycleRule {
                prefix: Some("logs/".to_owned()),
                status: dto::Status::ENABLED,
                expiration: Some(dto::LifecycleExpiration {
                    days: Some(30),
                    ..dto::LifecycleExpiration::default()
                }),
                ..dto::LifecycleRule::default()
            }],
        },
        None,
    );
    let harness = Harness::over(fixture, "us-east-1");

    let deleted = harness.send("DELETE", "/conf-bkt-reborn", b"");
    assert_eq!(deleted.status, 204, "{}", deleted.body);

    let recreated = harness.send("PUT", "/conf-bkt-reborn", b"");
    assert_eq!(recreated.status, 200, "{}", recreated.body);

    let state = harness.state.lock().expect("the fixture is not poisoned");
    assert!(
        state.cors("conf-bkt-reborn").is_none(),
        "the recreated bucket inherited the deleted bucket's CORS document"
    );
    assert!(
        state.bucket_tags("conf-bkt-reborn").is_none(),
        "the recreated bucket inherited the deleted bucket's tag set"
    );
    drop(state);

    // The lifecycle half is asserted through the wire rather than through an accessor: the
    // recreated bucket must answer the family's unconfigured 404, which is the exact symptom a
    // client would see if inheritance ever crept in.
    let read = harness.send("GET", "/conf-bkt-reborn?lifecycle", b"");
    assert_eq!(read.status, 404, "{}", read.body);
    read.assert_contains("NoSuchLifecycleConfiguration");
}
