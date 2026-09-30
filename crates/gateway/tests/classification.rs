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

//! `S3Service::classify` held to `S3Service::call` (rustfs/gateway#1141): for every request shape the
//! RustFS profile distinguishes, the classification of a head is the operation `call` routes the
//! request to, or the status and code `call` refuses it with before routing.
//!
//! Responsible for: that agreement, request by request, for the RustFS-profile assembly (path
//! addressing, operation selection, legacy virtual hosts) and the default one; and the two answers
//! `call` gives no operation for — a preflight, and a refusal before routing.
//! NOT responsible for: what each profile routes (`rustfs_addressing`, `rustfs_selection`,
//! `rustfs_vhost`), or anything after routing.
//! Upstream: `rustfs-gateway`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway::dto::{
    GetBucketAcl, GetBucketVersioning, GetObject, GetObjectTagging, ListBuckets, ListObjects, PutObject, PutObjectTagging,
};
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, Classification, Decision, ErrorCode, HandlerError, HandlerResult, InputAuthzRequest,
    InputDecisions, LegacyRustfsVirtualHosts, Observer, Req, RequestContext, RequestEvent, S3Service, SecurityFloor,
    ServiceBuilder, SlashPolicy,
};

use crate::support::exchange_wire;

struct Allow;

impl Authorizer for Allow {
    fn authorize_route<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        _request: &'a AuthzRequest<'a>,
    ) -> BoxFuture<'a, Decision> {
        Box::pin(async { Decision::Allow })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let decisions = request.decide_all(Decision::Allow, |_| Decision::Allow);
        Box::pin(async move { decisions })
    }
}

/// The operation `call` routed each request to.
#[derive(Default)]
struct Routed(Mutex<Vec<Option<String>>>);

impl Observer for Routed {
    fn on_response(&self, event: &RequestEvent<'_>) {
        self.0.lock().expect("not poisoned").push(event.operation.map(str::to_owned));
    }
}

struct Refuse;

fn answered<T>() -> Result<T, HandlerError> {
    Err(HandlerError::new(ErrorCode::NOT_IMPLEMENTED, "recorded"))
}

#[rustfs_gateway::handlers]
impl Refuse {
    async fn get_object(&self, _request: Req<GetObject>) -> HandlerResult<GetObject> {
        answered()
    }

    async fn put_object(&self, _request: Req<PutObject>) -> HandlerResult<PutObject> {
        answered()
    }

    async fn put_object_tagging(&self, _request: Req<PutObjectTagging>) -> HandlerResult<PutObjectTagging> {
        answered()
    }

    async fn get_object_tagging(&self, _request: Req<GetObjectTagging>) -> HandlerResult<GetObjectTagging> {
        answered()
    }

    async fn get_bucket_acl(&self, _request: Req<GetBucketAcl>) -> HandlerResult<GetBucketAcl> {
        answered()
    }

    async fn get_bucket_versioning(&self, _request: Req<GetBucketVersioning>) -> HandlerResult<GetBucketVersioning> {
        answered()
    }

    async fn list_objects(&self, _request: Req<ListObjects>) -> HandlerResult<ListObjects> {
        answered()
    }

    async fn list_buckets(&self, _request: Req<ListBuckets>) -> HandlerResult<ListBuckets> {
        answered()
    }
}

fn assembled(rustfs: bool) -> (S3Service, Arc<Routed>) {
    let routed = Arc::new(Routed::default());
    let handler = Arc::new(Refuse);
    let builder = ServiceBuilder::new()
        .security_floor(SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report())
        .authorizer(Allow)
        .observer(Arc::clone(&routed))
        .register::<GetObject, _>(Arc::clone(&handler))
        .register::<PutObject, _>(Arc::clone(&handler))
        .register::<PutObjectTagging, _>(Arc::clone(&handler))
        .register::<GetObjectTagging, _>(Arc::clone(&handler))
        .register::<GetBucketAcl, _>(Arc::clone(&handler))
        .register::<GetBucketVersioning, _>(Arc::clone(&handler))
        .register::<ListObjects, _>(Arc::clone(&handler))
        .register::<ListBuckets, _>(handler);
    let builder = if rustfs {
        builder
            .slash_policy(SlashPolicy::RustfsLegacy)
            .accept_legacy_rustfs_object_keys_after_listing_in_the_posture_report()
            .address_paths_as_legacy_rustfs()
            .select_operations_as_legacy_rustfs()
            .host_resolver(LegacyRustfsVirtualHosts::new(["s3.example.com"]).expect("a domain"))
    } else {
        builder
    };
    let credentials = std::sync::Arc::new(
        rustfs_gateway::StaticCredentials::new().with(rustfs_gateway::Credentials::new("AKIDEXAMPLE", b"secret").expect("a key")),
    );
    let builder = builder.authenticator(rustfs_gateway::SigV4Authenticator::new(
        credentials,
        rustfs_gateway::RegionSet::new(["us-east-1"]).expect("non-empty"),
    ));
    (builder.build().expect("a complete assembly"), routed)
}

fn request(method: &str, target: &str, host: &str, headers: &[(&str, &str)]) -> http::Request<Bytes> {
    let mut builder = http::Request::builder().method(method).uri(target).header("host", host);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(Bytes::new()).expect("a valid request")
}

/// The code of an S3 error document, if the body is one.
fn code_of(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    let start = text.find("<Code>")? + "<Code>".len();
    let end = text[start..].find("</Code>")? + start;
    Some(text[start..end].to_owned())
}

/// Classifies `request`, serves it, and fails unless the two agree.
async fn agree(service: &S3Service, routed: &Routed, request: http::Request<Bytes>) -> Classification {
    let label = format!("{} {} (host {:?})", request.method(), request.uri(), request.headers().get("host"));
    let (head, body) = request.into_parts();
    let classification = service.classify(&head);
    let answer = exchange_wire(service, http::Request::from_parts(head, body)).await;
    let operation = routed.0.lock().expect("not poisoned").pop().expect("one event per request");
    match &classification {
        Classification::Operation(name) => assert_eq!(operation.as_deref(), Some(*name), "{label}"),
        Classification::Refused { status, code } => {
            assert_eq!(operation, None, "{label}: served routed it");
            assert_eq!(answer.status(), *status, "{label}");
            assert_eq!(code.as_ref().map(|code| code.as_str().to_owned()), code_of(answer.body()), "{label}");
        }
        Classification::Preflight => assert_eq!(operation, None, "{label}: a preflight names no operation"),
        other => panic!("{label}: an answer this suite does not know: {other:?}"),
    }
    classification
}

fn operation(name: &'static str) -> Classification {
    Classification::Operation(name)
}

fn refused(status: u16, code: ErrorCode) -> Classification {
    Classification::Refused {
        status: http::StatusCode::from_u16(status).expect("a status"),
        code: Some(code),
    }
}

/// Positive — the RustFS profile: every operation `call` routes to is the classification.
#[tokio::test]
async fn a_rustfs_profile_classification_is_the_operation_served() {
    let (service, routed) = assembled(true);
    for (method, target, host, expected) in [
        ("GET", "/bkt/obj", "s3.example.com", "GetObject"),
        ("GET", "/bkt?acl&versioning", "s3.example.com", "GetBucketAcl"),
        ("PUT", "/bkt/obj?x-id=PutObjectTagging", "s3.example.com", "PutObjectTagging"),
        ("GET", "/bkt/obj?uploadId=u&tagging", "s3.example.com", "GetObjectTagging"),
        ("GET", "/bkt%2Fobj", "s3.example.com", "GetObject"),
        ("GET", "/obj", "vhb.s3.example.com", "GetObject"),
        ("GET", "//", "s3.example.com", "ListBuckets"),
        ("GET", "/", "s3.example.com", "ListBuckets"),
    ] {
        let classification = agree(&service, &routed, request(method, target, host, &[])).await;
        assert_eq!(classification, operation(expected), "{method} {target} {host}");
    }
}

/// Negative — every refusal before routing is classified with `call`'s status and code, and a
/// preflight is classified as one.
#[tokio::test]
async fn n_a_refusal_before_routing_is_classified_as_call_answers_it() {
    let (service, routed) = assembled(true);
    for (method, target, host, status, code) in [
        ("GET", "/bkt?x-id=NoSuchOp", "s3.example.com", 400, ErrorCode::INVALID_REQUEST),
        ("GET", "//bkt", "s3.example.com", 400, ErrorCode::INVALID_BUCKET_NAME),
        ("GET", "/bkt/a%FFb", "s3.example.com", 400, ErrorCode::INVALID_URI),
        ("GET", "/vhb/k", "my_host", 400, ErrorCode::INVALID_REQUEST),
        ("GET", "/k", "Bad_Bkt.s3.example.com", 400, ErrorCode::INVALID_BUCKET_NAME),
        ("PATCH", "/bkt/obj", "s3.example.com", 501, ErrorCode::NOT_IMPLEMENTED),
        ("PUT", "/bkt?analytics", "s3.example.com", 501, ErrorCode::NOT_IMPLEMENTED),
    ] {
        let classification = agree(&service, &routed, request(method, target, host, &[])).await;
        assert_eq!(classification, refused(status, code), "{method} {target} {host}");
    }
    let preflight = request(
        "OPTIONS",
        "/bkt/obj",
        "s3.example.com",
        &[("origin", "https://app.example"), ("access-control-request-method", "PUT")],
    );
    assert_eq!(agree(&service, &routed, preflight).await, Classification::Preflight);
    let headerless = request("OPTIONS", "/bkt/obj", "s3.example.com", &[]);
    assert_eq!(agree(&service, &routed, headerless).await, refused(400, ErrorCode::BAD_REQUEST));
}

/// Negative — the default assembly is classified by its own routing, `x-id` and all.
#[tokio::test]
async fn n_the_default_assembly_is_classified_by_its_own_routing() {
    let (service, routed) = assembled(false);
    for (method, target, expected) in [
        ("GET", "/bkt?acl&versioning", "GetBucketVersioning"),
        ("PUT", "/bkt/obj?x-id=PutObjectTagging", "PutObject"),
        ("GET", "/bkt?x-id=NoSuchOp", "ListObjects"),
        ("GET", "//", "ListBuckets"),
    ] {
        let classification = agree(&service, &routed, request(method, target, "s3.example.com", &[])).await;
        assert_eq!(classification, operation(expected), "{method} {target}");
    }
    // Routed as the literal split reads it — a bucket named `bkt%2Fobj` — and refused only when its
    // name is decoded, after routing: the classification is the operation, not the answer.
    let escaped = agree(&service, &routed, request("GET", "/bkt%2Fobj", "s3.example.com", &[])).await;
    assert_eq!(escaped, operation("ListObjects"));
}
