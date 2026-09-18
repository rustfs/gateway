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
    BoxFuture, BucketName, BucketOwnerError, BucketOwnerSource, Credentials, FixedClock, Limits, RegionSet, S3Service,
    ServiceBuilder, SigV4Authenticator, StaticCredentials, WireRequest, allow_when, collect, dto,
};
use rustfs_gateway_conformance::exec::block_on;
use rustfs_gateway_conformance::fixture::{Fixture, StoredObject, Stub};
use rustfs_gateway_conformance::inprocess::{HOST, VALID_ACCESS_KEY, VALID_SECRET};

/// The instant every fixture below is pinned to, and the stamp its signatures carry.
const NOW: i64 = 1_767_322_845;
const NOW_STAMP: &str = "20260102T030405Z";
const DATA_ROOT_OWNER: &str = "123456789012";

struct DataRootOwner;

impl BucketOwnerSource for DataRootOwner {
    fn owner<'a>(&'a self, _bucket: &'a BucketName) -> BoxFuture<'a, Result<Arc<str>, BucketOwnerError>> {
        Box::pin(async { Ok(Arc::from(DATA_ROOT_OWNER)) })
    }
}

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
        Harness::assembled(fixture, region, None)
    }

    /// The same deployment, with one bucket the authorizer refuses.
    ///
    /// A refusal is the only way to reach the `403` arm of the head, and the corpus has no
    /// vocabulary for "this principal may not see this bucket" — `setup.buckets` declares what
    /// exists, not who may look at it. So the refusal is staged here, and it is staged for *one*
    /// bucket rather than for the whole service: a harness that denied everything would answer
    /// `403` to a request that never reached the operation, which is a different code path from
    /// the one under test and would prove nothing about the head's response shape.
    fn refusing(fixture: Fixture, region: &str, denied: &'static str) -> Harness {
        Harness::assembled(fixture, region, Some(denied))
    }

    fn assembled(fixture: Fixture, region: &str, denied: Option<&'static str>) -> Harness {
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
            // The encryption read rides along for the same reason: the unconfigured 404 is the
            // observable proof that a recreated bucket inherited no default-encryption document.
            .register::<dto::GetBucketEncryption, _>(Arc::clone(&backend))
            // And the object-lock read, where inheritance would be worst: a recreated bucket
            // carrying the previous owner's COMPLIANCE default would apply WORM rules nobody
            // consented to and nobody can lift.
            .register::<dto::GetObjectLockConfiguration, _>(Arc::clone(&backend))
            // The replication read too: the unconfigured 404 is the observable proof that a
            // recreated bucket inherited no replication document.
            .register::<dto::GetBucketReplication, _>(Arc::clone(&backend))
            // And the ACL read, the one with no 404 to lean on: it answers 200 either way, so
            // the proof of non-inheritance has to be the document it answers with.
            .register::<dto::GetBucketAcl, _>(Arc::clone(&backend))
            // The bucket-configuration band contributes four reads, chosen because they answer
            // the two *different* unconfigured shapes: `?policy` and `?website` answer a 404, so
            // inheritance shows up as a 200; `?versioning` and `?logging` answer a 200 with an
            // empty document, so inheritance shows up inside a body that is a success either way.
            // A test that only watched the 404 kinds would not notice a recreated bucket still
            // logging to the previous owner's target.
            .register::<dto::GetBucketPolicy, _>(Arc::clone(&backend))
            .register::<dto::GetBucketWebsite, _>(Arc::clone(&backend))
            .register::<dto::GetBucketVersioning, _>(Arc::clone(&backend))
            .register::<dto::GetBucketLogging, _>(Arc::clone(&backend))
            .register::<dto::PutObject, _>(Arc::clone(&backend))
            .bucket_owner_source(DataRootOwner)
            .authenticator(SigV4Authenticator::new(credentials, RegionSet::new([region]).expect("non-empty")))
            .authorizer(allow_when(move |request| {
                !request.is_anonymous() && request.bucket.map(BucketName::as_str) != denied
            }))
            .clock_with_skew_ack(
                FixedClock::at_unix_seconds(NOW),
                rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
            )
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
        self.send_with_expected_owner(method, target, body, None)
    }

    fn send_with_expected_owner(&self, method: &str, target: &str, body: &'static [u8], expected_owner: Option<&str>) -> Answer {
        let (path, query) = target.split_once('?').map_or((target, ""), |(path, query)| (path, query));

        let mut map = http::HeaderMap::new();
        map.append(http::header::HOST, http::HeaderValue::from_static(HOST));
        map.append("content-length", http::HeaderValue::from(body.len()));
        if let Some(owner) = expected_owner {
            map.append(
                "x-amz-expected-bucket-owner",
                http::HeaderValue::from_str(owner).expect("a valid owner header"),
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

/// Negative — the expected-owner gate applies uniformly to all three bucket-lifetime operations.
///
/// The matching `HEAD` is the opposite-direction control: a gate stuck on `403` would satisfy all
/// three refusals while proving no owner comparison happened. The two mutating refusals also pin
/// that the handler never ran after the mismatch.
#[test]
fn n_mismatched_expected_owner_refuses_create_delete_and_head() {
    let harness = Harness::serving("us-east-1");
    harness.declare_bucket("conf-bkt-owner-delete");
    harness.declare_bucket("conf-bkt-owner-head");

    for (method, target) in [
        ("PUT", "/conf-bkt-owner-create"),
        ("DELETE", "/conf-bkt-owner-delete"),
        ("HEAD", "/conf-bkt-owner-head"),
    ] {
        let answer = harness.send_with_expected_owner(method, target, b"", Some("999999999999"));
        assert_eq!(answer.status, 403, "{method} {target}: {}", answer.body);
        if method != "HEAD" {
            answer.assert_contains("<Code>AccessDenied</Code>");
        }
    }

    assert!(!harness.has_bucket("conf-bkt-owner-create"), "a refused creation reached the handler");
    assert!(harness.has_bucket("conf-bkt-owner-delete"), "a refused deletion reached the handler");

    let matched = harness.send_with_expected_owner("HEAD", "/conf-bkt-owner-head", b"", Some(DATA_ROOT_OWNER));
    assert_eq!(matched.status, 200, "{}", matched.body);
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

/// Positive — an in-progress upload is not content: a bucket holding only one is deleted, and the
/// upload goes with it (rustfs/gateway#806, `c-bkt-0034`). The upload's absence is the half that
/// matters, since a store that answered 204 but kept it would hand it to a recreated bucket.
#[test]
fn a_bucket_holding_only_an_upload_is_deleted_with_it() {
    let mut fixture = Fixture::at(NOW);
    fixture.declare_bucket("conf-bkt-mpu", false);
    let upload = fixture.create_upload("conf-bkt-mpu", "pending");
    let harness = Harness::over(fixture, "us-east-1");
    let answer = harness.send("DELETE", "/conf-bkt-mpu", b"");
    assert_eq!(answer.status, 204, "{}", answer.body);
    assert!(!harness.has_bucket("conf-bkt-mpu"));
    let state = harness.state.lock().expect("the fixture is not poisoned");
    assert!(state.upload(&upload).is_none(), "the discarded upload survived its bucket");
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

/// Negative — a head the authorizer refuses answers `403` with nothing after the headers, and the
/// permitted head in the same deployment still answers `200`.
///
/// The third arm of the head's response shape, and the one the corpus cannot stage: `c-bkt-0008`
/// pins the `200` and `c-bkt-0025` the `404`, both with a zero-length body, and the `403` was
/// asserted nowhere. It is the arm most likely to regress, because it is the one an error renderer
/// reaches with a code, a message and every reason to write a document — RFC 9110 §9.3.2 forbids a
/// body on any response to `HEAD`, error responses included, and a `403` carrying an `<Error>`
/// document is what `HeadRequestBodyFixLayer` exists downstream to strip.
///
/// Both directions are asserted against one service on purpose. A harness that answered `403` to
/// everything would satisfy the refusal half while proving only that the authorizer was consulted;
/// the permitted head is what shows the refusal was about this bucket and that the head still works.
///
/// The framing header is the third thing asserted, and it is asserted against a measurement: the
/// same refusal delivered to a method that may carry content. `Content-Length` on a `HEAD` answer
/// is the length a `GET` would have sent and must survive the body being dropped
/// (`BodyAllowance::HeadOfContent`), so both failure directions are covered — a document left in
/// the response, and a number rewritten to `0` by something that mistook the rule for "a HEAD
/// answer is empty".
#[test]
fn n_a_refused_bucket_head_is_a_403_with_no_body_and_the_permitted_one_still_answers() {
    let mut fixture = Fixture::at(NOW);
    fixture.declare_bucket("conf-bkt-secret", false);
    fixture.declare_bucket("conf-bkt-open", false);
    let harness = Harness::refusing(fixture, "us-east-1", "conf-bkt-secret");

    let refused = harness.send("HEAD", "/conf-bkt-secret", b"");
    assert_eq!(refused.status, 403, "{}", refused.body);
    assert_eq!(
        refused.body.len(),
        0,
        "a refused HEAD carried {} bytes of body: {}",
        refused.body.len(),
        refused.body
    );
    assert!(
        !refused.body.contains("<Error"),
        "the refusal rendered an error document into a HEAD response: {}",
        refused.body
    );

    // The same refusal with a method that may carry content, so the `Content-Length` above can be
    // checked against a measurement rather than against a guess. `BodyAllowance::HeadOfContent` is
    // the rule: the bytes go, the number stays, because the number is the answer the `HEAD` asked
    // for. Rewriting it to `0` is the opposite defect from leaving the document in, and it reads
    // just as much like a fix, so both directions are pinned here.
    let visible = harness.send("DELETE", "/conf-bkt-secret", b"");
    assert_eq!(visible.status, 403, "{}", visible.body);
    visible.assert_contains("<Code>AccessDenied</Code>");
    assert!(!visible.body.is_empty(), "the non-HEAD refusal rendered no document at all");
    assert_eq!(
        refused.header("content-length"),
        Some(visible.body.len().to_string().as_str()),
        "the refused HEAD announced {:?} against a rendered refusal of {} bytes",
        refused.header("content-length"),
        visible.body.len()
    );

    let permitted = harness.send("HEAD", "/conf-bkt-open", b"");
    assert_eq!(permitted.status, 200, "{}", permitted.body);
    assert_eq!(permitted.header("x-amz-bucket-region"), Some("us-east-1"));
    assert!(permitted.body.is_empty(), "{}", permitted.body);
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
/// The CORS document, the tag set, the lifecycle document, the default-encryption document, the
/// replication document, the object-lock document, the access control policy and the whole
/// 200-249 configuration band all
/// live inside the bucket's own state entry, so removing the bucket removes them by construction
/// — and this test is what keeps that a fact rather than a coincidence of today's layout. The
/// failure it guards against is inheritance: delete a bucket, create a new one under the same
/// name, and find it answering the previous owner's CORS rules to browsers, the previous owner's
/// tags to billing, expiring the new owner's data on the previous owner's schedule — or
/// encrypting the new owner's objects to the previous owner's KMS key, which is inheritance of
/// *access*, not just behaviour — or shipping the new owner's objects to the previous
/// owner's destination bucket under the previous owner's IAM role, which is inheritance of
/// *exfiltration*. The object-lock document is the sharpest of the eight: a
/// recreated bucket that inherited a COMPLIANCE default would apply WORM retention the new owner
/// never asked for, and COMPLIANCE is by definition the mode nobody can lift. A name is not a
/// bucket.
///
/// Three of the eight answer no 404 at all, and they are the quiet ones. The access control
/// policy answers a `200` either way: an inherited grant to the previous owner's account, or to
/// AllUsers, looks exactly like a grant the new owner meant to make. The configuration band's
/// versioning and logging reads answer a **200 with an empty document** for the same reason, so
/// inheritance hides inside a response that is a success whichever way it goes, and only the
/// content separates them — an inherited logging destination keeps writing the new owner's
/// access log into the previous owner's bucket, which is a disclosure nobody sees happen. The
/// band's policy and website reads are the loud kind, a 404 turning into a 200 with a document.
/// All of them are asserted below, because a test that only watched the 404s would miss half.
#[test]
fn n_a_deleted_buckets_seven_documents_and_its_acl_do_not_survive_a_recreation() {
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
    fixture.set_encryption(
        "conf-bkt-reborn",
        dto::ServerSideEncryptionConfiguration {
            rules: vec![dto::ServerSideEncryptionRule {
                apply_server_side_encryption_by_default: Some(dto::ServerSideEncryptionByDefault {
                    sse_algorithm: dto::SseAlgorithm::AWS_KMS,
                    kms_master_key_id: Some("arn:aws:kms:us-east-1:111122223333:key/previous-owner".to_owned()),
                }),
                ..dto::ServerSideEncryptionRule::default()
            }],
        },
    );
    fixture.set_lock_configuration(
        "conf-bkt-reborn",
        dto::ObjectLockConfiguration {
            object_lock_enabled: Some(dto::ObjectLockEnabled::ENABLED),
            rule: Some(dto::ObjectLockRule {
                default_retention: Some(dto::DefaultRetention {
                    mode: Some(dto::Mode::COMPLIANCE),
                    years: Some(7),
                    days: None,
                    ..Default::default()
                }),
            }),
        },
    );
    fixture.set_replication(
        "conf-bkt-reborn",
        dto::ReplicationConfiguration {
            role: "arn:aws:iam::111122223333:role/previous-owner-role".to_owned(),
            rules: vec![dto::ReplicationRule {
                status: dto::Status::ENABLED,
                destination: dto::Destination {
                    bucket: "arn:aws:s3:::previous-owner-destination".to_owned(),
                    ..dto::Destination::default()
                },
                ..dto::ReplicationRule::default()
            }],
        },
    );
    fixture.set_bucket_acl(
        "conf-bkt-reborn",
        dto::AccessControlPolicy {
            owner: Some(dto::Owner {
                id: Some("previous-owner-canonical-id".to_owned()),
                display_name: Some("previous-owner".to_owned()),
            }),
            grants: vec![dto::Grant {
                grantee: Some(dto::Grantee {
                    uri: Some("http://acs.amazonaws.com/groups/global/AllUsers".to_owned()),
                    r#type: Some(dto::Type::GROUP),
                    ..dto::Grantee::default()
                }),
                permission: Some(dto::Permission::READ),
            }],
        },
    );
    fixture.set_policy(
        "conf-bkt-reborn",
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999988887777:root"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::conf-bkt-reborn/previous-owner-secret"}]}"#.to_owned(),
        true,
    );
    fixture.set_website(
        "conf-bkt-reborn",
        dto::WebsiteConfiguration {
            index_document: Some(dto::IndexDocument {
                suffix: "previous-owner-index.html".to_owned(),
            }),
            ..dto::WebsiteConfiguration::default()
        },
    );
    fixture.set_versioning(
        "conf-bkt-reborn",
        dto::VersioningConfiguration {
            status: Some(dto::Status::SUSPENDED),
            ..dto::VersioningConfiguration::default()
        },
    );
    fixture.set_logging(
        "conf-bkt-reborn",
        dto::BucketLoggingStatus {
            logging_enabled: Some(dto::LoggingEnabled {
                target_bucket: "previous-owner-log-target".to_owned(),
                target_prefix: "previous-owner/".to_owned(),
                ..dto::LoggingEnabled::default()
            }),
        },
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

    // The encryption half likewise: the recreated bucket must answer this family's unconfigured
    // 404, and the previous owner's KMS key id must be nowhere in the response.
    let read = harness.send("GET", "/conf-bkt-reborn?encryption", b"");
    assert_eq!(read.status, 404, "{}", read.body);
    read.assert_contains("ServerSideEncryptionConfigurationNotFoundError");
    assert!(
        !read.body.contains("previous-owner"),
        "the recreated bucket leaked the deleted bucket's KMS key id: {}",
        read.body
    );

    // The object-lock half: the recreated bucket must be unlocked, answering the bucket-level
    // 404 with no trace of the seven-year COMPLIANCE default the previous owner set.
    let read = harness.send("GET", "/conf-bkt-reborn?object-lock", b"");
    assert_eq!(read.status, 404, "{}", read.body);
    read.assert_contains("ObjectLockConfigurationNotFoundError");
    assert!(
        !read.body.contains("COMPLIANCE"),
        "the recreated bucket inherited the deleted bucket's WORM default: {}",
        read.body
    );

    // The replication half likewise: the recreated bucket must answer this family's unconfigured
    // 404, and neither the previous owner's IAM role nor its destination bucket may be anywhere
    // in the response — a recreated bucket that still names them is a bucket whose new data
    // ships to somebody else's account.
    let read = harness.send("GET", "/conf-bkt-reborn?replication", b"");
    assert_eq!(read.status, 404, "{}", read.body);
    read.assert_contains("ReplicationConfigurationNotFoundError");
    assert!(
        !read.body.contains("previous-owner"),
        "the recreated bucket leaked the deleted bucket's replication configuration: {}",
        read.body
    );

    // The access control half has no 404 to check, which is precisely why it needs its own
    // assertion: the read answers 200 whatever happened, so inheritance here is invisible to a
    // status. What must be gone is the previous owner's public grant and its identity, and what
    // must be there instead is the default policy a bucket is created with.
    let read = harness.send("GET", "/conf-bkt-reborn?acl", b"");
    assert_eq!(read.status, 200, "{}", read.body);
    assert!(
        !read.body.contains("AllUsers"),
        "the recreated bucket inherited the deleted bucket's public grant: {}",
        read.body
    );
    assert!(
        !read.body.contains("previous-owner"),
        "the recreated bucket named the deleted bucket's owner: {}",
        read.body
    );
    read.assert_contains("FULL_CONTROL");

    // The configuration band's loud half: two reads whose unconfigured answer is a 404, so a
    // recreated bucket that inherited either would answer 200 with the previous owner's document.
    // The policy is the worst of the whole test — it names a principal in another account.
    for (target, code) in [("?policy", "NoSuchBucketPolicy"), ("?website", "NoSuchWebsiteConfiguration")] {
        let read = harness.send("GET", &format!("/conf-bkt-reborn{target}"), b"");
        assert_eq!(read.status, 404, "{target}: {}", read.body);
        read.assert_contains(code);
        assert!(
            !read.body.contains("previous-owner") && !read.body.contains("999988887777"),
            "the recreated bucket leaked the deleted bucket's {target} document: {}",
            read.body
        );
    }

    // The quiet half, and the reason this test is not just a list of 404s. Both of these answer
    // 200 whether or not anything was inherited, so the status proves nothing and only the body
    // does: an empty document is the never-configured state, and anything the previous owner
    // wrote would be sitting inside a response that looks entirely successful.
    let read = harness.send("GET", "/conf-bkt-reborn?versioning", b"");
    assert_eq!(read.status, 200, "{}", read.body);
    assert!(
        !read.body.contains("Suspended") && !read.body.contains("<Status>"),
        "the recreated bucket inherited the deleted bucket's versioning state: {}",
        read.body
    );

    let read = harness.send("GET", "/conf-bkt-reborn?logging", b"");
    assert_eq!(read.status, 200, "{}", read.body);
    assert!(
        !read.body.contains("previous-owner") && !read.body.contains("<LoggingEnabled>"),
        "the recreated bucket is still logging to the deleted bucket's target: {}",
        read.body
    );
}
