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

//! RustFS's STS endpoint behind the dialect's form claim (ADR-0041): which requests reach it with
//! the dialect installed, which do not, and what the operation declares.
//!
//! Responsible for: routing `POST /` form requests through core's router — path-style, on a
//! virtual host whose bucket label RustFS would refuse, and whatever the query, under both
//! operation selections — the near misses that stay where they were, and the operation's floor,
//! action, codec and record.
//! NOT responsible for: authentication, the body read, the authorizer and the answer through an
//! assembled service (`rustfs-gateway-goldens`'s `rustfs_admin_dialect::sts_tests`), or the
//! binding to the recorded inventory (goldens).
//! Upstream: this crate's public surface and `rustfs-gateway-core`'s router. Downstream: nothing.

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Request};
use rustfs_gateway_core::codec::{MetaView, OperationCodec, RequestBody, RequestBodyMode, ResponseBody};
use rustfs_gateway_core::op::{Operation, ResourceShape};
use rustfs_gateway_core::registry::RouterBuilder;
use rustfs_gateway_core::route::{HostClass, RouteRequestParts, Selection, TargetKind};
use rustfs_gateway_dialect_rustfs_admin::admin::AdminResponse;
use rustfs_gateway_dialect_rustfs_admin::ops::sts_form_post::{self, CLAIM, StsFormPost};
use rustfs_gateway_dialect_rustfs_admin::{BodyKind, FORM_ROUTES, OVERLAY};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_sig::{
    AuthScheme, CtBytes, Identity, RawQuery, SigFamily, SigIdentity, SigLocation, SigService, Signature, Verdict, WireView,
    detect_aws_credential_marker,
};

use super::dialect;

const FORM: &str = "application/x-www-form-urlencoded";

/// The operation `method target` reaches with `content_type`, read path-style or as a virtual host
/// naming a bucket, under `selection`, with the dialect installed or not.
fn reach(
    installed: bool,
    selection: Selection,
    virtual_hosted: bool,
    method: &str,
    target: &str,
    content_type: Option<&str>,
) -> Option<&'static str> {
    let mut builder = RouterBuilder::new().selecting(selection);
    let dialect = dialect();
    if installed {
        builder = builder.dialect(&dialect);
    }
    let router = builder.build().expect("the router builds");
    let mut request = Request::builder()
        .method(method)
        .uri(format!("http://s3.example.com{target}"))
        .header("host", "s3.example.com");
    if let Some(content_type) = content_type {
        request = request.header("content-type", content_type);
    }
    let request = request.body(()).expect("a fixture request");
    let wire = WireRequest::accept(request, &Limits::default()).expect("an acceptable fixture request");
    let path = wire.raw_path().as_str();
    let parts = RouteRequestParts {
        method: wire.method(),
        path,
        target: if virtual_hosted {
            if path == "/" { TargetKind::Bucket } else { TargetKind::Object }
        } else {
            super::path_style_target(path)
        },
        host_class: HostClass::Standard,
        arn_form: None,
        query: wire.query(),
        headers: wire.headers(),
        host_named_bucket: virtual_hosted,
    };
    router.resolve(&parts).map(|entry| entry.op_name)
}

/// Positive — a form `POST /` reaches the STS operation path-style and virtual-hosted, whatever the
/// query names, under the table's selection and legacy RustFS's.
#[test]
fn a_form_post_of_the_root_is_the_sts_endpoint_on_every_host() {
    for selection in [Selection::Table, Selection::RustfsLegacy] {
        for virtual_hosted in [false, true] {
            for target in ["/", "/?delete", "/?Action=AssumeRole", "/?uploads&x-id=DeleteObjects"] {
                for content_type in [
                    FORM,
                    "APPLICATION/X-WWW-FORM-URLENCODED",
                    "application/x-www-form-urlencoded; charset=utf-8",
                ] {
                    assert_eq!(
                        reach(true, selection, virtual_hosted, "POST", target, Some(content_type)),
                        Some("rustfs:StsFormPost"),
                        "{selection:?} {virtual_hosted} {target} {content_type}"
                    );
                }
            }
        }
    }
}

/// Negative — every near miss reaches exactly what it reaches without the dialect: another path,
/// another method, another or no media type, or an admin path whose own row or fallback answers.
#[test]
fn n_a_near_miss_of_the_sts_endpoint_is_not_taken() {
    let near_misses: &[(&str, &str, Option<&str>)] = &[
        ("POST", "//", Some(FORM)),
        ("POST", "/%2F", Some(FORM)),
        ("POST", "/bucket", Some(FORM)),
        ("POST", "/bucket?delete", Some(FORM)),
        ("POST", "/bucket/key", Some(FORM)),
        ("PUT", "/", Some(FORM)),
        ("GET", "/", Some(FORM)),
        ("DELETE", "/", Some(FORM)),
        ("POST", "/", None),
        ("POST", "/", Some("application/x-www-form-urlencoded-x")),
        ("POST", "/", Some("multipart/form-data; boundary=x")),
        ("POST", "/", Some("application/xml")),
        ("POST", "/", Some("")),
    ];
    for selection in [Selection::Table, Selection::RustfsLegacy] {
        for &(method, target, content_type) in near_misses {
            assert_eq!(
                reach(true, selection, false, method, target, content_type),
                reach(false, selection, false, method, target, content_type),
                "{selection:?} {method} {target} {content_type:?}"
            );
            assert_ne!(reach(true, selection, false, method, target, content_type), Some("rustfs:StsFormPost"));
        }
    }
    // An admin path keeps its own operation or fallback, whatever its media type.
    for (target, expected) in [
        ("/rustfs/admin/v3/add-user", Some("rustfs:PutV3AddUser")),
        ("/rustfs/admin/v3/no-such-route", Some("rustfs:AdminFallback")),
    ] {
        let method = if expected == Some("rustfs:PutV3AddUser") {
            "PUT"
        } else {
            "POST"
        };
        assert_eq!(
            reach(true, Selection::RustfsLegacy, false, method, target, Some(FORM)),
            expected,
            "{target}"
        );
    }
}

/// Positive and negative — the operation is the dialect's one form claim: `POST /` with the form
/// media type, recorded as its overlay selector, reachable anonymously by its own floor, not
/// privileged, signed under `sts`, authorised by its vendor label on no bucket, and recorded as the
/// inventory's buffered `AssumeRoleHandle` route.
#[test]
fn the_sts_operation_declares_its_claim_floor_action_and_record() {
    let dialect = dialect();
    let forms = dialect.form_operations();
    assert_eq!(forms.len(), 1);
    assert_eq!((forms[0].name(), *forms[0].claim()), ("rustfs:StsFormPost", CLAIM));
    assert_eq!(CLAIM.path, "/");
    assert!(CLAIM.rejection().is_none());
    let row = OVERLAY
        .operations
        .iter()
        .find(|row| row.name == "rustfs:StsFormPost")
        .expect("the overlay records the STS operation");
    assert_eq!(row.selector, CLAIM.render());
    assert!(row.anonymous);
    let floor = StsFormPost::floor();
    assert!(floor.allows_anonymous());
    assert!(!floor.privileged(), "the shared envelope preserves Web Identity admission");
    assert_eq!(floor.service(), SigService::Sts);
    assert!(
        !floor.allowed_schemes().allows_presigned(),
        "presigned only under the assembly's own policy"
    );
    let auth = StsFormPost::spec().auth.expect("an action");
    assert_eq!(
        (auth.render(), auth.resource),
        ("rustfs:AssumeRoleHandle".to_owned(), ResourceShape::Service)
    );
    assert!(!StsFormPost::spec().receives_caller_secret());
    assert_eq!(StsFormPost::REQUEST_BODY, RequestBodyMode::Full);
    assert_eq!(FORM_ROUTES, [sts_form_post::RECORD]);
    let record = sts_form_post::RECORD;
    assert_eq!(
        (record.operation, record.group, record.method, record.path, record.action),
        ("rustfs:StsFormPost", "sts", "POST", "/", "rustfs:AssumeRoleHandle")
    );
    assert_eq!(record.rustfs_handler, "AssumeRoleHandle");
    assert_eq!((record.request_body, record.response_body), (BodyKind::Buffered, BodyKind::Buffered));
}

/// Positive — the codec hands the body over as it arrived and answers what the handler answers.
#[test]
fn the_sts_codec_hands_the_body_over_unchanged() {
    let body = Bytes::from_static(b"Action=AssumeRole&Version=2011-06-15&DurationSeconds=900");
    let request = Request::builder()
        .method("POST")
        .uri("http://s3.example.com/")
        .header("host", "s3.example.com")
        .header("content-type", FORM)
        .header("authorization", "AWS fixture:fixture")
        .body(())
        .expect("a fixture request");
    let wire = WireRequest::accept(request, &Limits::default()).expect("an acceptable fixture request");
    let meta = MetaView::of(&wire, TargetKind::Service).expect("a view");
    let meta = sec1_authenticated(meta, "AWS fixture:fixture");
    let decoded = StsFormPost::decode(&meta, RequestBody::Buffered(body.clone())).expect("the body decodes");
    assert_eq!(decoded, body);
    let encoded = StsFormPost::encode(AdminResponse::bytes("text/xml", b"<AssumeRoleResponse/>".to_vec()), &meta, 200)
        .expect("the answer encodes");
    assert_eq!(encoded.status, 200);
    assert!(matches!(&encoded.body, ResponseBody::Complete(bytes) if bytes.as_slice() == b"<AssumeRoleResponse/>"));
}

/// Install a matching signature-proof fixture for codec tests, without claiming a real request verification.
fn sec1_authenticated<'a>(meta: MetaView<'a>, authorization: &str) -> MetaView<'a> {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::AUTHORIZATION, HeaderValue::from_str(authorization).expect("fixture header"));
    let marker = detect_aws_credential_marker(&WireView::new(&headers, RawQuery::new("")));
    let family = if authorization.starts_with("AWS4-") {
        SigFamily::V4
    } else {
        SigFamily::V2
    };
    let signature = Signature::HmacSha256(CtBytes::from_array([3; 32]));
    let proof = signature.ct_verify(&signature).expect("matching fixture proof");
    let verdict = Verdict::authenticated(
        Identity::new("fixture-access").expect("fixture identity"),
        AuthScheme::new(family, SigLocation::Header, SigIdentity::LongTerm, SigService::Sts),
        proof,
    );
    meta.with_authenticated_aws_marker(&verdict, marker)
}

/// Decode the bounded form with the request metadata the signature stage accepted.
/// These codec tests use proof fixtures; assembled-service tests verify actual signatures.
fn sec1_decode(body: &'static [u8], query: &str, authorization: Option<&str>) -> Result<Bytes, rustfs_gateway_core::CodecError> {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("http://s3.example.com/?{query}"))
        .header("host", "s3.example.com")
        .header("content-type", FORM);
    if let Some(authorization) = authorization {
        request = request.header("authorization", authorization);
    }
    let wire = WireRequest::accept(request.body(()).expect("a fixture request"), &Limits::default())
        .expect("an acceptable fixture request");
    let meta = MetaView::of(&wire, TargetKind::Service).expect("a service view");
    let meta = match authorization {
        Some(authorization) => sec1_authenticated(meta, authorization),
        None => meta,
    };
    StsFormPost::decode(&meta, RequestBody::Buffered(Bytes::from_static(body)))
}

const SEC1_ORDINARY: &[u8] = b"Action=AssumeRole&Version=2011-06-15";
const SEC1_WEB_IDENTITY: &[u8] = b"Action=AssumeRoleWithWebIdentity&Version=2011-06-15&WebIdentityToken=fixture";

fn sec1_denied(body: &'static [u8], query: &str) {
    let error = sec1_decode(body, query, None).expect_err("ordinary AssumeRole requires header authentication");
    assert_eq!(error.status().as_u16(), 403);
    assert_eq!(error.code().as_str(), "AccessDenied");
}

/// Negative — an ordinary action without a header credential is refused by its codec.
#[test]
fn sec1_01() {
    sec1_denied(SEC1_ORDINARY, "");
}

/// Negative — a SigV4 query credential does not satisfy the ordinary action contract.
#[test]
fn sec1_02() {
    sec1_denied(
        SEC1_ORDINARY,
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=fixture&X-Amz-Signature=fixture",
    );
}

/// Negative — a SigV2 query credential does not satisfy the ordinary action contract.
#[test]
fn sec1_03() {
    sec1_denied(SEC1_ORDINARY, "AWSAccessKeyId=fixture&Expires=1&Signature=fixture");
}

/// Negative — action names and values are interpreted after form decoding.
#[test]
fn sec1_04() {
    for body in [
        &b"%41ction=AssumeRole&Version=2011-06-15"[..],
        &b"Action=Assume%52ole&Version=2011-06-15"[..],
    ] {
        sec1_denied(body, "");
    }
}

/// Negative — duplicate actions cannot choose different contracts at two decoding stages.
#[test]
fn sec1_05() {
    for body in [
        &b"Action=AssumeRoleWithWebIdentity&Action=AssumeRole"[..],
        &b"Action=AssumeRole&Action=AssumeRoleWithWebIdentity"[..],
        &b"Action=AssumeRoleWithWebIdentity&%41ction=AssumeRole"[..],
    ] {
        let error = sec1_decode(body, "", None).expect_err("duplicate actions are refused");
        assert_eq!(error.status().as_u16(), 400);
        assert_eq!(error.code().as_str(), "InvalidRequest");
    }
}

/// Negative — a query action cannot select the body action's authentication contract.
#[test]
fn sec1_06() {
    sec1_denied(SEC1_ORDINARY, "Action=AssumeRoleWithWebIdentity");
}

/// Positive — ordinary header credential modes retain the exact form bytes.
#[test]
fn sec1_07() {
    for authorization in [
        "AWS4-HMAC-SHA256 Credential=fixture/20261026/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=fixture",
        "AWS fixture:fixture",
    ] {
        let body = sec1_decode(SEC1_ORDINARY, "", Some(authorization)).expect("the header action decodes");
        assert_eq!(body.as_ref(), SEC1_ORDINARY);
    }
}

/// Positive — Web Identity keeps its unsigned form and downstream token bytes unchanged.
#[test]
fn sec1_08() {
    for body in [
        SEC1_WEB_IDENTITY,
        &b"%41ction=AssumeRoleWithWebIdentity&WebIdentityToken=fixture%2Btoken"[..],
    ] {
        let decoded = sec1_decode(body, "Action=AssumeRole", None).expect("Web Identity retains its separate contract");
        assert!(decoded.as_ref() == body, "Web Identity form bytes remain unchanged");
    }
}
