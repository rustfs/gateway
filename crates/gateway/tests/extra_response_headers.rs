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

//! Response headers a handler adds beyond its operation's output (rustfs/gateway#1018), through
//! both dispatch paths.
//!
//! Responsible for: proving that `Resp::with_extra_headers` reaches the wire on the registry and the
//! monomorphic path, every value kept, and that a name the gateway owns, a name the encoder already
//! wrote, or any extra header on a committed answer is a `500` that carries none of them.
//! NOT responsible for: the owned-name list itself, which `rustfs-gateway-core`'s
//! `codec::extra_headers` unit tests hold name by name.
//! Upstream: `tests/support`. Downstream: nothing.

use crate::support;

use std::sync::Arc;

use rustfs_gateway::dto::{CopyObject, CopyObjectOutput, ListBuckets, ListBucketsOutput};
use rustfs_gateway::{
    Body, Handler, HandlerResult, HeadPart, MonomorphicService, OperationSetEnd, OperationSetNode, Req, Resp, S3Service,
    WireResponse,
};

/// A ListBuckets backend that answers with these extra headers.
struct Extras(fn() -> http::HeaderMap);

impl Handler<ListBuckets> for Extras {
    async fn call(&self, _request: Req<ListBuckets>) -> HandlerResult<ListBuckets> {
        Ok(Resp::new(ListBucketsOutput::default()).with_extra_headers((self.0)()))
    }
}

impl Handler<CopyObject> for Extras {
    async fn call(&self, _request: Req<CopyObject>) -> HandlerResult<CopyObject> {
        let head = HeadPart::new(http::HeaderMap::new()).expect("an empty generated operation head");
        Ok(Resp::commit(head, Box::pin(async { Ok(CopyObjectOutput::default()) })).with_extra_headers((self.0)()))
    }
}

fn lines(pairs: &[(&'static str, &'static str)]) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    for (name, value) in pairs {
        headers.append(http::HeaderName::from_static(name), http::HeaderValue::from_static(value));
    }
    headers
}

fn legacy_headers() -> http::HeaderMap {
    lines(&[
        ("access-control-allow-origin", "https://app.example"),
        ("access-control-expose-headers", "ETag"),
        ("vary", "Origin"),
        ("vary", "Access-Control-Request-Method"),
        ("x-amz-restore-request-date", "Fri, 02 Jan 2026 03:04:05 GMT"),
        ("x-amz-checksum-crc32", "AAAAAA=="),
    ])
}

/// One assembled service, whichever builder made it.
enum Assembled {
    Registry(S3Service),
    Monomorphic(MonomorphicService<Extras, OperationSetNode<ListBuckets, OperationSetEnd>>),
}

impl Assembled {
    async fn call(&self, request: http::Request<bytes::Bytes>) -> http::Response<Body> {
        match self {
            Self::Registry(service) => service.call_bytes(request).await,
            Self::Monomorphic(service) => service.call_bytes(request).await,
        }
    }
}

fn registry(extra: fn() -> http::HeaderMap) -> Assembled {
    Assembled::Registry(registry_service(extra))
}

fn registry_service(extra: fn() -> http::HeaderMap) -> S3Service {
    support::wired_at_signed_time()
        .register::<ListBuckets, _>(Arc::new(Extras(extra)))
        .build()
        .expect("a complete assembly")
}

fn monomorphic(extra: fn() -> http::HeaderMap) -> Assembled {
    let backend = Arc::new(Extras(extra));
    Assembled::Monomorphic(
        support::wired_at_signed_time()
            .register::<ListBuckets, _>(Arc::clone(&backend))
            .build_monomorphic::<_, OperationSetNode<ListBuckets, OperationSetEnd>>(backend)
            .expect("a complete static assembly"),
    )
}

async fn list(service: &Assembled) -> WireResponse {
    let response = service.call(support::signed(http::Method::GET, "/")).await;
    rustfs_gateway::collect(response).await.expect("an in-memory body")
}

fn values<'a>(response: &'a WireResponse, name: &str) -> Vec<&'a [u8]> {
    response
        .headers()
        .iter()
        .filter(|(line, _)| line.as_str() == name)
        .map(|(_, value)| value.as_bytes())
        .collect()
}

fn first<'a>(response: &'a WireResponse, name: &str) -> Option<&'a [u8]> {
    values(response, name).first().copied()
}

/// The refusal a conflicting extra header earns: a `500` whose head carries none of the extras.
fn assert_refused_without_extras(response: &WireResponse, label: &str) {
    assert_eq!(response.status(), http::StatusCode::INTERNAL_SERVER_ERROR, "{label}");
    for name in [
        "access-control-allow-origin",
        "x-amz-restore-request-date",
        "x-amz-checksum-crc32",
    ] {
        assert!(first(response, name).is_none(), "{label}: {name} leaked onto the refusal");
    }
}

#[tokio::test]
async fn extra_headers_reach_the_wire_on_both_dispatch_paths_with_every_value() {
    for (label, service) in [
        ("registry", registry(legacy_headers)),
        ("monomorphic", monomorphic(legacy_headers)),
    ] {
        let response = list(&service).await;
        assert_eq!(response.status(), http::StatusCode::OK, "{label}");
        assert_eq!(values(&response, "access-control-allow-origin"), [&b"https://app.example"[..]], "{label}");
        assert_eq!(values(&response, "vary"), [&b"Origin"[..], b"Access-Control-Request-Method"], "{label}");
        assert_eq!(values(&response, "x-amz-checksum-crc32"), [&b"AAAAAA=="[..]], "{label}");
        assert_eq!(
            values(&response, "content-type"),
            [&b"application/xml"[..]],
            "{label}: the encoder's own header is untouched"
        );
        assert!(response.body().starts_with(b"<?xml"), "{label}: the document is still encoded");
    }
}

#[tokio::test]
async fn n_an_extra_header_the_gateway_owns_is_a_500_on_both_paths() {
    fn framing() -> http::HeaderMap {
        let mut headers = legacy_headers();
        headers.insert(http::header::TRANSFER_ENCODING, http::HeaderValue::from_static("chunked"));
        headers
    }
    fn request_id() -> http::HeaderMap {
        let mut headers = legacy_headers();
        headers.insert("x-amz-request-id", http::HeaderValue::from_static("FORGEDREQUESTID0"));
        headers
    }
    fn cookie() -> http::HeaderMap {
        let mut headers = legacy_headers();
        headers.insert(http::header::SET_COOKIE, http::HeaderValue::from_static("session=1"));
        headers
    }
    for (label, extra) in [
        ("framing", framing as fn() -> http::HeaderMap),
        ("request id", request_id),
        ("cookie", cookie),
    ] {
        for (path, service) in [("registry", registry(extra)), ("monomorphic", monomorphic(extra))] {
            let response = list(&service).await;
            let label = format!("{path}, {label}");
            assert_refused_without_extras(&response, &label);
            assert!(first(&response, "set-cookie").is_none(), "{label}");
            assert_ne!(first(&response, "x-amz-request-id"), Some(&b"FORGEDREQUESTID0"[..]), "{label}");
        }
    }
}

#[tokio::test]
async fn n_an_extra_header_the_encoder_already_wrote_is_a_500_on_both_paths() {
    fn content_type() -> http::HeaderMap {
        let mut headers = legacy_headers();
        headers.insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("text/plain"));
        headers
    }
    for (path, service) in [
        ("registry", registry(content_type)),
        ("monomorphic", monomorphic(content_type)),
    ] {
        let response = list(&service).await;
        assert_refused_without_extras(&response, path);
        assert_ne!(first(&response, "content-type"), Some(&b"text/plain"[..]), "{path}");
    }
}

/// Sends one signed CopyObject through a registry or a monomorphic assembly whose committed answer
/// carries these extra headers.
async fn copy(extra: fn() -> http::HeaderMap, monomorphic: bool) -> WireResponse {
    let backend = Arc::new(Extras(extra));
    let builder = support::wired_at_signed_time().register::<CopyObject, _>(Arc::clone(&backend));
    let request = support::signed_with(http::Method::PUT, "/destination/key", &[("x-amz-copy-source", "/source/key")]);
    let response = if monomorphic {
        builder
            .build_monomorphic::<_, OperationSetNode<CopyObject, OperationSetEnd>>(backend)
            .expect("a complete static assembly")
            .call_bytes(request)
            .await
    } else {
        builder.build().expect("a complete assembly").call_bytes(request).await
    };
    rustfs_gateway::collect(response).await.expect("an in-memory body")
}

/// A committed head has gone out before the work ends, and it is checked against the work's own
/// headers; extra headers have no place in it, so they are refused before anything is sent.
#[tokio::test]
async fn n_extra_headers_on_a_committed_answer_are_a_500_on_both_paths() {
    for monomorphic in [false, true] {
        assert_refused_without_extras(&copy(legacy_headers, monomorphic).await, &format!("monomorphic={monomorphic}"));
    }
}

/// The control for the refusal above: the same committed answer with no extra headers is a `200`.
#[tokio::test]
async fn a_committed_answer_without_extra_headers_is_unaffected_on_both_paths() {
    for monomorphic in [false, true] {
        assert_eq!(
            copy(http::HeaderMap::new, monomorphic).await.status(),
            http::StatusCode::OK,
            "monomorphic={monomorphic}"
        );
    }
}
