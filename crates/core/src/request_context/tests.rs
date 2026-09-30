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

//! Unit tests for the handler request context (ADR-0022).
//!
//! Responsible for: what `RequestContextView::from_pipeline` builds from a verdict and an accepted
//! request — no context for a rejected verdict; no principal, scope or secret for an anonymous
//! one; every accepted line byte for byte — and that `Debug` prints no header value or query.
//! NOT responsible for: the pipeline that builds one context per request (the facade's
//! `request_context_runtime` test) or the compile-time guarantees (the doctests on the types).
//! Upstream: `super`. Downstream: nothing.

use bytes::Bytes;
use rustfs_gateway_http::Limits;
use rustfs_gateway_sig::{
    Admission, AuthError, OperationFloor, RawQuery, RequestNow, SecurityFloor, SigService, Verdict, WireView,
};

use super::*;

fn wire(target: &str, headers: &[(&str, &[u8])]) -> WireRequest<Bytes> {
    let mut builder = http::Request::builder()
        .method(Method::HEAD)
        .uri(target)
        .header("host", "s3.example.com");
    for (name, value) in headers {
        builder = builder.header(*name, http::HeaderValue::from_bytes(value).expect("a fixture value"));
    }
    let request = builder.body(Bytes::new()).expect("a fixture request");
    WireRequest::accept(request, &Limits::default()).expect("an accepted fixture")
}

/// An anonymous verdict, obtained the only way one can be: a floor that admits a request which
/// presented nothing.
fn anonymous_verdict(wire: &WireRequest<Bytes>) -> Verdict {
    let headers = {
        let mut map = HeaderMap::new();
        for (name, value) in wire.headers().iter_raw() {
            map.append(name.clone(), value.clone());
        }
        map
    };
    let floor = SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report();
    let view = WireView::new(&headers, RawQuery::new(wire.query().as_str()));
    match floor.admit(
        view,
        &OperationFloor::builtin("HeadObject", SigService::S3),
        RequestNow::from_unix_seconds(0),
    ) {
        Ok(Admission::Anonymous(evidence)) => Verdict::anonymous(evidence),
        _ => panic!("the fixture presents no credentials"),
    }
}

fn path_style() -> Addressed {
    Addressed {
        style: AddressingStyle::Path,
        bucket: None,
        key: None,
    }
}

/// Negative — a rejected verdict builds no context, so a handler is never handed one.
#[test]
fn a_rejected_verdict_builds_no_context() {
    let wire = wire("/photos/a.jpg", &[]);
    let verdict = Verdict::reject(AuthError::SignatureDoesNotMatch);
    assert!(RequestContextView::from_pipeline("HeadObject", &wire, path_style(), &verdict, None).is_none());
}

/// Negative — a secret handed to an anonymous request is dropped: there is no principal to
/// carry it, and no scope either.
#[test]
fn an_anonymous_context_has_no_principal_scope_or_secret_even_when_handed_one() {
    let wire = wire("/photos/a.jpg", &[]);
    let verdict = anonymous_verdict(&wire);
    let context = RequestContextView::from_pipeline(
        "HeadObject",
        &wire,
        path_style(),
        &verdict,
        Some(SecretBytes::new(b"handed-to-nobody")),
    )
    .expect("an anonymous request has a context");
    assert!(context.is_anonymous());
    assert!(context.principal().is_none());
    assert!(context.verified_scope().is_none());
    assert!(!format!("{context:?}").contains("handed-to-nobody"));
}

/// Negative — a detached context is anonymous and carries no line, no bucket and no key.
#[test]
fn a_detached_context_is_anonymous_and_carries_nothing() {
    let context = RequestContextView::detached("HeadObject");
    assert_eq!(context.operation(), "HeadObject");
    assert!(context.is_anonymous() && context.verified_scope().is_none());
    assert_eq!(context.headers().iter_raw().count(), 0);
    assert!(context.bucket().is_none() && context.key().is_none());
}

/// Negative — `Debug` prints header names and the query's length, never a value: a query value
/// and an SSE-C key header stay out of the rendering.
#[test]
fn debug_prints_no_header_value_and_no_query() {
    let wire = wire(
        "/photos/a.jpg?uploadId=querysignaturevalue",
        &[("x-amz-server-side-encryption-customer-key", b"customerkeyvalue")],
    );
    let verdict = anonymous_verdict(&wire);
    let context = RequestContextView::from_pipeline("HeadObject", &wire, path_style(), &verdict, None).expect("a context");
    let rendering = format!("{context:?}");
    assert!(!rendering.contains("querysignaturevalue"), "{rendering}");
    assert!(!rendering.contains("customerkeyvalue"), "{rendering}");
    assert!(rendering.contains("x-amz-server-side-encryption-customer-key"), "{rendering}");
}

/// Positive — every accepted line is copied byte for byte, an unreadable unrelated value and
/// both lines of a repeated name included.
#[test]
fn every_accepted_line_is_copied_byte_for_byte() {
    let wire = wire("/photos/a.jpg", &[("x-proxy-note", b"caf\xe9"), ("x-list", b"one"), ("x-list", b"two")]);
    let verdict = anonymous_verdict(&wire);
    let context = RequestContextView::from_pipeline("HeadObject", &wire, path_style(), &verdict, None).expect("a context");
    let lines: Vec<(&str, &[u8])> = context
        .headers()
        .iter_raw()
        .map(|(name, value)| (name.as_str(), value.as_bytes()))
        .collect();
    let expected: Vec<(&str, &[u8])> = wire
        .headers()
        .iter_raw()
        .map(|(name, value)| (name.as_str(), value.as_bytes()))
        .collect();
    assert_eq!(lines, expected);
    assert!(lines.contains(&("x-proxy-note", b"caf\xe9".as_slice())));
}

#[derive(Clone, Debug)]
struct TransportNote(&'static str);

fn transport_wire() -> WireRequest<Bytes> {
    let request = http::Request::builder()
        .method(Method::HEAD)
        .uri("/photos/a.jpg")
        .header("host", "s3.example.com")
        .extension(TransportNote("transport-secret-sentinel"))
        .body(Bytes::new())
        .expect("fixture request");
    WireRequest::accept(request, &Limits::default()).expect("accepted transport request")
}

#[test]
fn transport_values_keep_their_identity_across_body_mapping_and_handler_context() {
    let wire = transport_wire();
    let view = wire.transport_extensions().clone();
    let original = view.get::<TransportNote>().expect("transport marker");
    let wire = wire.map_body(|body| body);
    let verdict = anonymous_verdict(&wire);
    let context =
        RequestContextView::from_pipeline("HeadObject", &wire, path_style(), &verdict, None).expect("an accepted context");
    let received = context.transport_extensions().get::<TransportNote>().expect("handler marker");
    assert!(core::ptr::eq(original, received));
    assert_eq!(received.0, "transport-secret-sentinel");
}

#[test]
fn absent_transport_types_are_not_invented() {
    let wire = transport_wire();
    let verdict = anonymous_verdict(&wire);
    let context =
        RequestContextView::from_pipeline("HeadObject", &wire, path_style(), &verdict, None).expect("an accepted context");
    assert!(context.transport_extensions().get::<usize>().is_none());
    assert!(
        RequestContextView::detached("HeadObject")
            .transport_extensions()
            .get::<TransportNote>()
            .is_none()
    );
}

#[test]
fn transport_values_do_not_leak_through_debug() {
    let wire = transport_wire();
    let verdict = anonymous_verdict(&wire);
    let context =
        RequestContextView::from_pipeline("HeadObject", &wire, path_style(), &verdict, None).expect("an accepted context");
    for rendered in [format!("{:?}", wire.transport_extensions()), format!("{context:?}")] {
        assert!(!rendered.contains("transport-secret-sentinel"));
    }
}

#[test]
fn rejected_transport_requests_cannot_construct_a_handler_context() {
    let wire = transport_wire();
    let verdict = Verdict::reject(AuthError::SignatureDoesNotMatch);
    assert!(RequestContextView::from_pipeline("HeadObject", &wire, path_style(), &verdict, None).is_none());
}

/// The request target a handler must rebuild what it was sent from (rustfs/gateway#1148): an
/// origin-form HTTP/1.1 target names no scheme and no authority, an absolute-form one names both,
/// and an HTTP/2 request names both and its version.
#[test]
fn the_context_holds_the_target_as_the_transport_handed_it_over() {
    let origin = wire("/photos/a.jpg", &[]);
    let context = RequestContextView::from_pipeline("HeadObject", &origin, path_style(), &anonymous_verdict(&origin), None)
        .expect("an anonymous context");
    assert_eq!(
        (context.version(), context.target_scheme(), context.target_authority()),
        (Version::HTTP_11, None, None)
    );

    let absolute = wire("http://s3.example.com/photos/a.jpg", &[]);
    let context = RequestContextView::from_pipeline("HeadObject", &absolute, path_style(), &anonymous_verdict(&absolute), None)
        .expect("an anonymous context");
    assert_eq!(
        (context.target_scheme(), context.target_authority()),
        (Some("http"), Some("s3.example.com"))
    );

    let request = http::Request::builder()
        .method(Method::HEAD)
        .version(Version::HTTP_2)
        .uri("https://s3.example.com:9000/photos/a.jpg")
        .body(Bytes::new())
        .expect("a fixture request");
    let h2 = WireRequest::accept(request, &Limits::default()).expect("an accepted fixture");
    let context = RequestContextView::from_pipeline("HeadObject", &h2, path_style(), &anonymous_verdict(&h2), None)
        .expect("an anonymous context");
    assert_eq!(
        (context.version(), context.target_scheme(), context.target_authority()),
        (Version::HTTP_2, Some("https"), Some("s3.example.com:9000"))
    );
}

/// Negative — a detached context names no target, and `Debug` states whether a target authority
/// was carried rather than printing a second copy of the host.
#[test]
fn n_a_detached_context_names_no_target_and_debug_prints_only_the_authoritys_presence() {
    let detached = RequestContextView::detached("HeadObject");
    assert_eq!(
        (detached.version(), detached.target_scheme(), detached.target_authority()),
        (Version::HTTP_11, None, None)
    );
    let absolute = wire("http://s3.example.com/photos/a.jpg", &[]);
    let context = RequestContextView::from_pipeline("HeadObject", &absolute, path_style(), &anonymous_verdict(&absolute), None)
        .expect("an anonymous context");
    let printed = format!("{context:?}");
    assert!(printed.contains("target_authority: true"), "{printed}");
    assert!(printed.contains("target_scheme: Some(\"http\")"), "{printed}");
    let origin = wire("/photos/a.jpg", &[]);
    let context = RequestContextView::from_pipeline("HeadObject", &origin, path_style(), &anonymous_verdict(&origin), None)
        .expect("an anonymous context");
    assert!(format!("{context:?}").contains("target_authority: false"));
}
