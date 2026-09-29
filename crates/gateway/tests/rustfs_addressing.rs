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

//! Legacy RustFS's path addressing through the facade (rustfs/gateway#1115): which operation, bucket
//! and key a path-style request reaches under `address_paths_as_legacy_rustfs`, and what legacy
//! RustFS refuses before routing.
//!
//! Responsible for: an escaped separator ending the bucket, an escaped bucket label decoded, an
//! empty bucket segment and a refused bucket answered `InvalidBucketName` before routing (so before
//! a `501`), an undecodable path answered `InvalidURI`, the buckets legacy RustFS creates that the
//! AWS rules reserve, and `GET //` answered as `GET /` with its signature verified over `/`; each
//! against the default assembly, which answers as it always has. Every expectation is legacy
//! RustFS's answer on a legacy build.
//! NOT responsible for: the split itself (`rustfs-gateway-core`'s `legacy_path` tests) or equality
//! with the bucket and key legacy RustFS hands its storage (the difftest RustFS-profile rows).
//! Upstream: `rustfs-gateway`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway::dto::{GetObject, ListBuckets, ListObjects, PutObject};
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, ClockSkewAck, Credentials, Decision, ErrorCode, HandlerError, HandlerResult,
    InputAuthzRequest, InputDecisions, RegionSet, Req, RequestContext, S3Service, SecurityFloor, ServiceBuilder,
    SigV4Authenticator, SlashPolicy, StaticCredentials,
};

use crate::support::{exchange, fixed_clock, signed};

/// What the handlers were handed: `operation bucket/key`.
#[derive(Default)]
struct Seen(Mutex<Vec<String>>);

impl Seen {
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.0.lock().expect("not poisoned"))
    }

    fn hand(&self, entry: String) {
        self.0.lock().expect("not poisoned").push(entry);
    }
}

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

struct Recorder(Arc<Seen>);

fn recorded<T>() -> Result<T, HandlerError> {
    Err(HandlerError::new(ErrorCode::NOT_IMPLEMENTED, "recorded"))
}

#[rustfs_gateway::handlers]
impl Recorder {
    async fn get_object(&self, request: Req<GetObject>) -> HandlerResult<GetObject> {
        let input = request.input();
        self.0
            .hand(format!("GetObject {}/{}", input.bucket.as_str(), input.key.as_str()));
        recorded()
    }

    async fn put_object(&self, request: Req<PutObject>) -> HandlerResult<PutObject> {
        let input = request.input();
        self.0
            .hand(format!("PutObject {}/{}", input.bucket.as_str(), input.key.as_str()));
        recorded()
    }

    async fn list_objects(&self, request: Req<ListObjects>) -> HandlerResult<ListObjects> {
        self.0.hand(format!("ListObjects {}", request.input().bucket.as_str()));
        recorded()
    }

    async fn list_buckets(&self, _request: Req<ListBuckets>) -> HandlerResult<ListBuckets> {
        self.0.hand("ListBuckets".to_owned());
        recorded()
    }
}

fn assembled(rustfs: bool) -> (S3Service, Arc<Seen>) {
    let seen = Arc::new(Seen::default());
    let credentials = Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid key")));
    let recorder = Arc::new(Recorder(Arc::clone(&seen)));
    let builder = ServiceBuilder::new()
        .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("non-empty")))
        .clock_with_skew_ack(fixed_clock(), ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry())
        .security_floor(SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report())
        .authorizer(Allow)
        .register::<GetObject, _>(Arc::clone(&recorder))
        .register::<PutObject, _>(Arc::clone(&recorder))
        .register::<ListObjects, _>(Arc::clone(&recorder))
        .register::<ListBuckets, _>(recorder);
    let builder = if rustfs {
        builder
            .slash_policy(SlashPolicy::RustfsLegacy)
            .accept_legacy_rustfs_object_keys_after_listing_in_the_posture_report()
            .address_paths_as_legacy_rustfs()
    } else {
        builder
    };
    (builder.build().expect("a complete assembly"), seen)
}

fn unsigned(method: &str, target: &str) -> http::Request<Bytes> {
    http::Request::builder()
        .method(method)
        .uri(target)
        .header("host", "s3.example.com")
        .header("content-length", "0")
        .body(Bytes::new())
        .expect("a valid request")
}

/// Positive — an escaped separator ends the bucket and an escaped bucket label is decoded, so the
/// handler is handed legacy RustFS's bucket and key.
#[tokio::test]
async fn an_escaped_separator_or_label_addresses_legacy_rustfs_s_object() {
    let (service, seen) = assembled(true);
    for (method, target, handed) in [
        ("GET", "/bkt%2Fsrc", "GetObject bkt/src"),
        ("GET", "/b%6Bt/src", "GetObject bkt/src"),
        ("GET", "/bkt%2F%2Fsrc", "GetObject bkt/src"),
        ("PUT", "/bkt%2Fsrc", "PutObject bkt/src"),
        ("GET", "/bkt%2F", "ListObjects bkt"),
    ] {
        let (status, body) = exchange(&service, unsigned(method, target)).await;
        assert_eq!(seen.take(), [handed], "{method} {target}: {status} {body}");
    }
}

/// Positive — the buckets legacy RustFS creates that the AWS rules reserve are reachable.
#[tokio::test]
async fn a_bucket_the_aws_rules_reserve_is_reachable() {
    let (service, seen) = assembled(true);
    for bucket in ["sthree-x", "abc-s3alias", "abc--x-s3", "abc--ol-s3", "01.2.3.4"] {
        let (status, body) = exchange(&service, unsigned("GET", &format!("/{bucket}/k"))).await;
        assert_eq!(seen.take(), [format!("GetObject {bucket}/k")], "{bucket}: {status} {body}");
    }
}

/// Positive — `GET //` signed over `/`, as the AWS S3 browser sends it, lists the buckets.
#[tokio::test]
async fn a_get_of_double_slash_signed_over_the_root_lists_the_buckets() {
    let (service, seen) = assembled(true);
    let mut request = signed(http::Method::GET, "/");
    *request.uri_mut() = "//".parse().expect("a valid target");
    let (status, body) = exchange(&service, request).await;
    assert_eq!(seen.take(), ["ListBuckets"], "{status} {body}");
}

/// Negative — `GET //` signed over `//` fails its signature, as it does on legacy RustFS: the
/// signature is verified over `/`.
#[tokio::test]
async fn n_a_get_of_double_slash_signed_over_itself_fails_its_signature() {
    let (service, seen) = assembled(true);
    let (status, body) = exchange(&service, signed(http::Method::GET, "//")).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"), "{body}");
    assert!(seen.take().is_empty());
}

/// Negative — an empty or refused bucket segment is `InvalidBucketName`, before routing: a method
/// no operation takes is still answered with the bucket's refusal, not `501`.
#[tokio::test]
async fn n_a_refused_bucket_segment_is_answered_before_routing() {
    let (service, seen) = assembled(true);
    for (method, target) in [
        ("GET", "//bkt"),
        ("GET", "//bkt/src"),
        ("GET", "///"),
        ("PUT", "//"),
        ("GET", "/%2Fbkt/src"),
        ("GET", "/Bad_Bucket/src"),
        ("PATCH", "/Bad_Bucket/src"),
        ("GET", "/1.2.3.4/src"),
    ] {
        let (status, body) = exchange(&service, unsigned(method, target)).await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST, "{method} {target}: {body}");
        assert!(body.contains("<Code>InvalidBucketName</Code>"), "{method} {target}: {body}");
    }
    let (status, _) = exchange(&service, unsigned("HEAD", "//")).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "HEAD //");
    assert!(seen.take().is_empty());
}

/// Negative — a path that is not UTF-8 once decoded is `InvalidURI`, before the bucket is judged.
#[tokio::test]
async fn n_an_undecodable_path_is_an_invalid_uri() {
    let (service, seen) = assembled(true);
    for target in ["/bkt/a%FFb", "/Bad_Bucket/a%FFb"] {
        let (status, body) = exchange(&service, unsigned("GET", target)).await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST, "{target}: {body}");
        assert!(body.contains("<Code>InvalidURI</Code>"), "{target}: {body}");
    }
    assert!(seen.take().is_empty());
}

/// Negative — the default assembly answers every one of these as it always has.
#[tokio::test]
async fn n_the_default_assembly_is_unchanged() {
    let (service, seen) = assembled(false);
    let (status, body) = exchange(&service, unsigned("GET", "/bkt%2Fsrc")).await;
    assert!(body.contains("<Code>InvalidBucketName</Code>"), "{status} {body}");
    let (status, _) = exchange(&service, unsigned("PATCH", "/Bad_Bucket/src")).await;
    assert_eq!(status, http::StatusCode::NOT_IMPLEMENTED);
    let (_, body) = exchange(&service, unsigned("GET", "/sthree-x/k")).await;
    assert!(body.contains("<Code>InvalidBucketName</Code>"), "{body}");
    assert!(seen.take().is_empty());
    let (status, body) = exchange(&service, signed(http::Method::GET, "//")).await;
    assert_eq!(seen.take(), ["ListBuckets"], "{status} {body}");
}
