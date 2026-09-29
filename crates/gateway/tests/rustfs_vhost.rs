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

//! Legacy RustFS's virtual hosts through the facade (rustfs/gateway#1136): which bucket and key a
//! request reaches, or what it is refused with, under `LegacyRustfsVirtualHosts` and the RustFS
//! profile's path addressing.
//!
//! Responsible for: a host under a configured domain naming its bucket whatever the port, a dotted
//! bucket and a CNAME-style host reaching their objects, an address read path-style, a host that is
//! no domain refused `InvalidRequest` and a refused host-named bucket `InvalidBucketName`, in legacy
//! RustFS's order after an undecodable path; each against `VirtualHostStyle`, which answers as it
//! always has. Every expectation is legacy RustFS's answer on a legacy build with
//! `RUSTFS_SERVER_DOMAINS=example.com:9411,example.com:9000,s3.local`.
//! NOT responsible for: the reading itself (`ext::legacy_vhost`'s tests) or the objects stored
//! (`compat/sut`'s cases).
//! Upstream: `rustfs-gateway`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway::dto::{GetObject, ListObjects};
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, ClockSkewAck, Credentials, Decision, ErrorCode, HandlerError, HandlerResult,
    HostResolver, InputAuthzRequest, InputDecisions, LegacyRustfsVirtualHosts, RegionSet, Req, RequestContext, S3Service,
    SecurityFloor, ServiceBuilder, SigV4Authenticator, SlashPolicy, StaticCredentials, VirtualHostStyle,
};

use crate::support::{exchange, fixed_clock};

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

    async fn list_objects(&self, request: Req<ListObjects>) -> HandlerResult<ListObjects> {
        self.0.hand(format!("ListObjects {}", request.input().bucket.as_str()));
        recorded()
    }
}

fn assembled(resolver: impl HostResolver) -> (S3Service, Arc<Seen>) {
    let seen = Arc::new(Seen::default());
    let recorder = Arc::new(Recorder(Arc::clone(&seen)));
    let credentials = Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid key")));
    let service = ServiceBuilder::new()
        .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("non-empty")))
        .clock_with_skew_ack(fixed_clock(), ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry())
        .security_floor(SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report())
        .authorizer(Allow)
        .register::<GetObject, _>(Arc::clone(&recorder))
        .register::<ListObjects, _>(recorder)
        .slash_policy(SlashPolicy::RustfsLegacy)
        .accept_legacy_rustfs_object_keys_after_listing_in_the_posture_report()
        .address_paths_as_legacy_rustfs()
        .select_operations_as_legacy_rustfs()
        .host_resolver(resolver)
        .build()
        .expect("a complete assembly");
    (service, seen)
}

fn rustfs() -> (S3Service, Arc<Seen>) {
    assembled(LegacyRustfsVirtualHosts::new(["example.com:9411", "example.com:9000", "s3.local"]).expect("RustFS's list"))
}

fn get(target: &str, host: &str) -> http::Request<Bytes> {
    http::Request::builder()
        .method(http::Method::GET)
        .uri(target)
        .header("host", host)
        .body(Bytes::new())
        .expect("a valid request")
}

/// Positive — a host under a domain names its bucket whatever the port; the whole prefix is the
/// bucket; a bucket-shaped host outside every domain is its own bucket; an address is path-style.
#[tokio::test]
async fn a_host_reaches_the_bucket_legacy_rustfs_reads_out_of_it() {
    let (service, seen) = rustfs();
    for (target, host, expected) in [
        ("/k", "vhb.example.com:9411", "GetObject vhb/k"),
        ("/k", "vhb.example.com:1234", "GetObject vhb/k"),
        ("/k", "vhb.s3.local", "GetObject vhb/k"),
        ("/k", "my.dotted.bkt.example.com:9411", "GetObject my.dotted.bkt/k"),
        ("/k", "vhb.s3.us-west-2.example.com:9411", "GetObject vhb.s3.us-west-2/k"),
        ("/k", "localhost", "GetObject localhost/k"),
        ("/vhb/k", "localhost:9411", "GetObject vhb/k"),
        ("/vhb/k", "127.0.0.1:9411", "GetObject vhb/k"),
        ("/vhb/k", "example.com:9411", "GetObject vhb/k"),
    ] {
        let (status, body) = exchange(&service, get(target, host)).await;
        assert_eq!(seen.take(), [expected], "{host} {target}: {status} {body}");
    }
}

/// Negative — a host that is no domain is `InvalidRequest`, a bucket a host names that legacy
/// RustFS's rules refuse is `InvalidBucketName`, and an undecodable path is `InvalidURI` first.
#[tokio::test]
async fn n_a_host_legacy_rustfs_refuses_is_refused_before_routing() {
    let (service, seen) = rustfs();
    for (target, host, code) in [
        ("/vhb/k", "my_host:9411", "InvalidRequest"),
        ("/k", "VHB.example.com:9411", "InvalidBucketName"),
        ("/k", "Bad_Bkt.example.com", "InvalidBucketName"),
        ("/a%FFb", "my_host:9411", "InvalidURI"),
        ("/a%FFb", "VHB.example.com", "InvalidURI"),
    ] {
        let (status, body) = exchange(&service, get(target, host)).await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST, "{host} {target}: {body}");
        assert!(body.contains(&format!("<Code>{code}</Code>")), "{host} {target}: {body}");
    }
    let (_, body) = exchange(&service, get("/vhb/k", "my_host:9411")).await;
    assert!(body.contains("<Message>Invalid host header</Message>"), "{body}");
    assert!(seen.take().is_empty());
}

/// Negative — `VirtualHostStyle` answers every one of these as it always has.
#[tokio::test]
async fn n_the_default_resolver_is_unchanged() {
    let (service, seen) = assembled(VirtualHostStyle::new(["example.com", "s3.local"]).expect("valid domains"));
    for (target, host, expected) in [
        ("/k", "vhb.example.com:9411", "GetObject vhb/k"),
        ("/k", "vhb.s3.us-west-2.example.com:9411", "GetObject vhb/k"),
        ("/vhb/k", "my_host:9411", "GetObject vhb/k"),
        ("/vhb/k", "other.domain.org", "GetObject vhb/k"),
    ] {
        let (status, body) = exchange(&service, get(target, host)).await;
        assert_eq!(seen.take(), [expected], "{host} {target}: {status} {body}");
    }
    assert!(VirtualHostStyle::new(["example.com:9411"]).is_err(), "a port is still no base domain");
}
