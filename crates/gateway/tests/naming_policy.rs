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

//! The naming policy through the facade: one value, one floor, one decode, and where it happens.
//!
//! Responsible for: the assertions `conformance/cases/naming/**` cannot make, because the corpus
//! drives a service assembled with the default policy and has no knob for a second one — the
//! [`SlashPolicy::Collapse`] direction, a replaced [`NameValidator`] in both the looser and the
//! stricter direction, the identity of the value the authorizer is shown and the value the backend
//! receives, and the *position* of the naming refusal in the pipeline.
//! NOT responsible for: the rules themselves, which are unit-tested in `rustfs-gateway-types`, and
//! the wire shape of a refusal, which the corpus pins against a running service.
//! Upstream: `rustfs-gateway`. Downstream: nothing.
//!
//! # Why the ordering assertion is a pair of status codes
//!
//! A 400 proves the request was refused. It does not prove the refusal happened *before*
//! authentication and authorisation, and that ordering is the whole of `GHSA-f4vq-9ffr-m8m3`: there
//! the authorisation check ran on one spelling of a name and the storage layer ran on another.
//!
//! So the ordering is measured with two unsigned requests to the same service. The one naming a
//! traversal answers `400`, the one naming an ordinary key answers `403` — because the second got
//! as far as the signature and the first did not. Either half alone proves nothing: a service that
//! answered `400` to everything would satisfy the first, and one that ran the naming rules *after*
//! authentication would answer `403` to both.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use rustfs_gateway::{
    Authorizer, AuthzRequest, AwsNameValidator, BoxFuture, BucketName, Credentials, Decision, ErrorCode, Handler, HandlerResult,
    InputAuthzRequest, InputDecisions, Limits, MetaView, NamePolicy, NameRejection, NameValidator, ObjectKey, OperationCodec,
    RegionSet, Req, RequestBody, RequestContext, Resp, S3Service, ServiceBuilder, SigV4Authenticator, SlashPolicy,
    StaticCredentials, Stricter, TargetKind, WireRequest, dto,
};

// ── validators ─────────────────────────────────────────────────────────────────────────────────

/// Says yes to everything. The floor has to survive it.
#[derive(Debug)]
struct PermitEverything;

impl NameValidator for PermitEverything {
    fn check_bucket(&self, _name: &str) -> Stricter {
        Stricter::NoOpinion
    }

    fn check_key(&self, _key: &str) -> Stricter {
        Stricter::NoOpinion
    }
}

/// Narrower than the built-in rules: a key must live under `tenant/`.
#[derive(Debug)]
struct TenantPrefixOnly;

impl NameValidator for TenantPrefixOnly {
    fn check_bucket(&self, name: &str) -> Stricter {
        AwsNameValidator.check_bucket(name)
    }

    fn check_key(&self, key: &str) -> Stricter {
        if key.starts_with("tenant/") {
            Stricter::NoOpinion
        } else {
            Stricter::Reject(NameRejection::rejected_by_validator("a key must live under tenant/"))
        }
    }
}

fn aws() -> NamePolicy {
    NamePolicy::default()
}

fn collapsing() -> NamePolicy {
    NamePolicy::default().with_slash_policy(SlashPolicy::Collapse)
}

// ── part A: the view, which is where the single materialisation happens ────────────────────────

fn accepted(target: &str) -> WireRequest<()> {
    let request = http::Request::builder()
        .method("GET")
        .uri(format!("http://host.invalid{target}"))
        .header("host", "host.invalid")
        .body(())
        .expect("the fixture request is well formed");
    WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable")
}

/// The key a decoder is handed for `target` under `names`, or the code it was refused with.
///
/// Both halves come out of one call. `MetaView::key` is what the pipeline shows the authorizer and
/// `GetObject::decode` is what it hands the backend, so asserting them equal in every case below
/// is the single-value property stated where it can actually be observed.
fn key_of(target: &str, names: &NamePolicy) -> Result<String, ErrorCode> {
    let request = accepted(target);
    let view = MetaView::of_with(&request, TargetKind::Object, names).map_err(|error| error.code().clone())?;
    let shown_to_the_authorizer = view.key().expect("an object route has a key").as_str().to_owned();
    let handed_to_the_backend = dto::GetObject::decode(&view, RequestBody::None)
        .expect("a plain GET is not a refusal")
        .key;
    assert_eq!(
        shown_to_the_authorizer,
        handed_to_the_backend.as_str(),
        "the authorizer and the backend must read one value, not two that agree"
    );
    Ok(shown_to_the_authorizer)
}

#[test]
fn the_slash_policy_decides_in_both_directions() {
    // The leading empty segment: `PUT /bucket//key` stores `/key` on AWS and `key` on MinIO.
    assert_eq!(key_of("/bucket//key.txt", &aws()), Ok("/key.txt".to_owned()));
    assert_eq!(key_of("/bucket//key.txt", &collapsing()), Ok("key.txt".to_owned()));

    // The interior run, which decides whether `a//b` and `a/b` are one object or two.
    assert_eq!(key_of("/bucket/a//b", &aws()), Ok("a//b".to_owned()));
    assert_eq!(key_of("/bucket/a//b", &collapsing()), Ok("a/b".to_owned()));

    // A key with no run at all is untouched by either, which keeps the pairs above from passing
    // against an implementation that rewrote every key one way or the other.
    assert_eq!(key_of("/bucket/a/b", &aws()), Ok("a/b".to_owned()));
    assert_eq!(key_of("/bucket/a/b", &collapsing()), Ok("a/b".to_owned()));
}

#[test]
fn collapsing_is_not_cleaning() {
    // Collapse folds separators and removes nothing else, so the floor still runs on its output.
    // A policy that "tidied" the path would be a second normalisation wearing a compatibility flag.
    assert_eq!(key_of("/bucket/a//../b", &collapsing()), Err(ErrorCode::INVALID_ARGUMENT));
    assert_eq!(key_of("/bucket/a/../b", &collapsing()), Err(ErrorCode::INVALID_ARGUMENT));
}

#[test]
fn a_permissive_validator_cannot_reopen_the_floor() {
    // E-1: the framework runs the floor first and ANDs the two verdicts, so `NoOpinion` on every
    // one of these changes nothing.
    let permissive = NamePolicy::default().with_validator(Arc::new(PermitEverything));
    for target in [
        "/bucket/../x",
        "/bucket/a/../b",
        "/bucket/%2e%2e/x",
        "/bucket/%252e%252e/x",
        "/bucket/a%00b",
        "/bucket/a%01b",
        "/bucket/a%FFb",
        "/bucket/..%5Cx",
        "/bucket///server/share",
    ] {
        assert_eq!(
            key_of(target, &permissive),
            Err(ErrorCode::INVALID_ARGUMENT),
            "{target} was let through by a validator with no power to let it through"
        );
    }

    // The other direction. Without this the block above would pass against a validator that was
    // never consulted at all: uppercase is a validator rule, and the permissive one does widen it.
    assert_eq!(key_of("/MyBucket/key.txt", &aws()), Err(ErrorCode::INVALID_BUCKET_NAME));
    assert_eq!(key_of("/MyBucket/key.txt", &permissive), Ok("key.txt".to_owned()));
}

#[test]
fn a_stricter_validator_narrows_and_still_cannot_widen() {
    let strict = NamePolicy::default().with_validator(Arc::new(TenantPrefixOnly));
    assert_eq!(key_of("/bucket/tenant/a.txt", &strict), Ok("tenant/a.txt".to_owned()));
    assert_eq!(
        key_of("/bucket/other/a.txt", &strict),
        Err(ErrorCode::INVALID_ARGUMENT),
        "a validator may refuse what the floor allowed"
    );
    assert_eq!(
        key_of("/bucket/other/a.txt", &aws()),
        Ok("other/a.txt".to_owned()),
        "and the same key is fine under the default rules, so the refusal came from the validator"
    );
    assert_eq!(key_of("/bucket/tenant/../etc", &strict), Err(ErrorCode::INVALID_ARGUMENT));
}

#[test]
fn the_length_limit_is_bytes_and_the_boundary_is_inclusive() {
    let at_limit = "k".repeat(1024);
    assert_eq!(key_of(&format!("/bucket/{at_limit}"), &aws()), Ok(at_limit.clone()));

    let over_limit = "k".repeat(1025);
    assert_eq!(
        key_of(&format!("/bucket/{over_limit}"), &aws()),
        Err(ErrorCode::KEY_TOO_LONG),
        "and the code is the one an SDK branches on to shorten a key"
    );

    // Bytes, not characters: 342 three-byte characters is 342 characters and 1026 bytes.
    let multibyte = "%E2%82%AC".repeat(342);
    assert_eq!(key_of(&format!("/bucket/{multibyte}"), &aws()), Err(ErrorCode::KEY_TOO_LONG));

    // 341 of them is 1023 bytes, which is under it. Without this the assertion above would hold
    // for an implementation that refused every multi-byte key.
    let just_under = "%E2%82%AC".repeat(341);
    assert!(key_of(&format!("/bucket/{just_under}"), &aws()).is_ok());
}

/// The key a decoder is handed when the *host* named the bucket, so the whole path is the key.
fn vhost_key_of(target: &str, names: &NamePolicy) -> Result<String, ErrorCode> {
    let request = accepted(target);
    let bucket = BucketName::new("from-the-host").expect("a valid bucket name");
    let view = MetaView::addressed_with(&request, TargetKind::Object, Some(bucket), names).map_err(|e| e.code().clone())?;
    Ok(view.key().expect("an object route has a key").as_str().to_owned())
}

#[test]
fn a_virtual_hosted_key_goes_through_the_same_normalisation_under_the_same_policy() {
    // P6-04 gave a host-addressed request its own path into `MetaView`, where the whole path is the
    // key. That road must arrive at the same function *under the same policy* as the path-style
    // one. Reaching the same function with the default policy is not enough: it would make `a//b`
    // one object when the client addressed the bucket by host and another when it addressed it by
    // path, on a deployment that had chosen `Collapse` — a naming rule that depends on the URL
    // style, which is the drift this whole task is about.
    assert_eq!(vhost_key_of("/holder//b", &aws()), Ok("holder//b".to_owned()));
    assert_eq!(vhost_key_of("/holder//b", &collapsing()), Ok("holder/b".to_owned()));

    // The path-style reading of the same bytes differs — there the first label is the bucket — so
    // the two roads are genuinely doing different work and the pair above is not tautological.
    assert_eq!(key_of("/holder//b", &aws()), Ok("/b".to_owned()));

    // The floor is the floor on both roads, and a custom validator reaches both.
    assert_eq!(vhost_key_of("/../etc/passwd", &aws()), Err(ErrorCode::INVALID_ARGUMENT));
    assert_eq!(vhost_key_of("/%252e%252e/x", &aws()), Err(ErrorCode::INVALID_ARGUMENT));
    let strict = NamePolicy::default().with_validator(Arc::new(TenantPrefixOnly));
    assert_eq!(vhost_key_of("/tenant/a.txt", &strict), Ok("tenant/a.txt".to_owned()));
    assert_eq!(vhost_key_of("/other/a.txt", &strict), Err(ErrorCode::INVALID_ARGUMENT));
}

#[test]
fn the_encoded_spelling_survives_for_the_signature() {
    // The signature covers what arrived, not what normalisation produced. `ObjectKey` keeps both,
    // and the collapse policy is where the two genuinely differ.
    let request = accepted("/bucket/a//b");
    let view = MetaView::of_with(&request, TargetKind::Object, &collapsing()).expect("accepted");
    let key = view.key().expect("an object route has a key");
    assert_eq!(key.as_str(), "a/b", "authorisation and storage read the normalised value");
    assert_eq!(key.as_encoded(), "a//b", "the signature reads the spelling the client sent");
}

/// A key materialised from the wire and one built for a *response* are different things, and the
/// difference is deliberate.
#[test]
fn a_backend_may_still_name_an_object_the_floor_would_not_let_a_client_choose() {
    // `conformance/cases/list/c-list-0035` is an object stored under a key holding U+0001. The
    // floor refuses that key on the naming path, and a listing still has to be able to answer with
    // it — so the representation constructor keeps the wire-shape rules and nothing more. If this
    // starts failing, one badly named object has become unlistable.
    let stored = ObjectKey::new("ctrl\u{1}key.txt").expect("a stored key may hold what a client may not choose");
    assert!(stored.needs_url_encoding());
    assert_eq!(key_of("/bucket/ctrl%01key.txt", &aws()), Err(ErrorCode::INVALID_ARGUMENT));
}

// ── part B: the position of the refusal in the pipeline ────────────────────────────────────────

/// Counts the calls, and answers nothing useful: these two exist to be *not* reached.
#[derive(Default)]
struct Counter(AtomicUsize);

impl Counter {
    fn calls(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }

    fn hit(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct CountingAuthorizer(Arc<Counter>);

impl Authorizer for CountingAuthorizer {
    fn authorize_route<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        _request: &'a AuthzRequest<'a>,
    ) -> BoxFuture<'a, Decision> {
        self.0.hit();
        Box::pin(async { Decision::Allow })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        self.0.hit();
        let decisions = request.decide_all(Decision::Allow, |_| Decision::Allow);
        Box::pin(async move { decisions })
    }
}

struct CountingBackend(Arc<Counter>);

impl Handler<dto::GetObject> for CountingBackend {
    fn call(&self, _request: Req<dto::GetObject>) -> impl core::future::Future<Output = HandlerResult<dto::GetObject>> + Send {
        self.0.hit();
        async { Ok(Resp::new(dto::GetObjectOutput::default())) }
    }
}

fn assembled() -> (S3Service, Arc<Counter>, Arc<Counter>) {
    let authorizer_calls = Arc::new(Counter::default());
    let backend_calls = Arc::new(Counter::default());
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("a valid access key id")));
    let service = ServiceBuilder::new()
        .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("non-empty")))
        .authorizer(CountingAuthorizer(Arc::clone(&authorizer_calls)))
        .register::<dto::GetObject, _>(Arc::new(CountingBackend(Arc::clone(&backend_calls))))
        .build()
        .expect("a complete assembly");
    (service, authorizer_calls, backend_calls)
}

async fn status_of(service: &S3Service, target: &str) -> (http::StatusCode, String) {
    let request = http::Request::builder()
        .method("GET")
        .uri(target)
        .header("host", "s3.example.com")
        .body(Bytes::new())
        .expect("a valid request");
    let collected = rustfs_gateway::collect(service.call_bytes(request).await)
        .await
        .expect("an in-memory body");
    let body = String::from_utf8(collected.body().to_vec()).expect("utf-8");
    (collected.status(), body)
}

#[tokio::test]
async fn a_traversal_is_refused_before_the_request_is_authenticated() {
    let (service, authorizer, backend) = assembled();

    // Neither request is signed. The ordinary key reaches the security floor and is refused there;
    // the traversal never gets that far, and the difference between the two answers is the
    // measurement. A pipeline that named after authenticating would answer 403 to both.
    let (ordinary, _) = status_of(&service, "/bucket/ordinary.txt").await;
    assert_eq!(ordinary, http::StatusCode::FORBIDDEN, "an unsigned request reaches the floor");

    let (traversal, body) = status_of(&service, "/bucket/../other/obj").await;
    assert_eq!(traversal, http::StatusCode::BAD_REQUEST, "and the traversal does not");
    assert!(body.contains("<Code>InvalidArgument</Code>"), "{body}");
    assert!(!body.contains("../other/obj"), "the refusal must not echo the request back");

    // Neither reached a decision that is allowed to see a name, which is the other half: a 400
    // that arrived after the authorizer ran would still be a 400.
    assert_eq!(authorizer.calls(), 0);
    assert_eq!(backend.calls(), 0);
}

#[tokio::test]
async fn every_refused_spelling_is_refused_at_the_same_stage() {
    let (service, authorizer, backend) = assembled();
    for target in [
        "/bucket/../other/obj",
        "/bucket/%2e%2e/other/obj",
        "/bucket/%252e%252e/x",
        "/bucket/a%00b",
        "/bucket/a%01b",
        "/bucket/a%FFb",
        "/bucket/..%5Cx",
        "/bucket///server/share",
    ] {
        let (status, _) = status_of(&service, target).await;
        assert_eq!(
            status,
            http::StatusCode::BAD_REQUEST,
            "{target} was answered by a later stage than naming"
        );
    }
    assert_eq!(authorizer.calls(), 0);
    assert_eq!(backend.calls(), 0);
}

#[test]
fn the_builder_publishes_the_policy_as_an_extension_point() {
    // Assembling with each of the three setters has to be possible from outside this workspace; a
    // refusal here would mean the extension point exists and cannot be installed.
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("a valid access key id")));
    let built = ServiceBuilder::new()
        .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("non-empty")))
        .authorizer(CountingAuthorizer(Arc::new(Counter::default())))
        .slash_policy(SlashPolicy::Collapse)
        .name_validator(TenantPrefixOnly)
        .name_policy(NamePolicy::new(SlashPolicy::AwsPreserve, Arc::new(PermitEverything)))
        .register::<dto::GetObject, _>(Arc::new(CountingBackend(Arc::new(Counter::default()))))
        .build();
    assert!(built.is_ok());

    // And the persistence-affecting flag a start-up posture report reads answers differently for
    // the two policies, which is what makes it worth printing.
    assert!(!SlashPolicy::AwsPreserve.rewrites_keys());
    assert!(SlashPolicy::Collapse.rewrites_keys());
}
