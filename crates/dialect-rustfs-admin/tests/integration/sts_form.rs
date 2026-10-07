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
use http::Request;
use rustfs_gateway_core::codec::{MetaView, OperationCodec, RequestBody, RequestBodyMode, ResponseBody};
use rustfs_gateway_core::op::{Operation, ResourceShape};
use rustfs_gateway_core::registry::RouterBuilder;
use rustfs_gateway_core::route::{HostClass, RouteRequestParts, Selection, TargetKind};
use rustfs_gateway_dialect_rustfs_admin::admin::AdminResponse;
use rustfs_gateway_dialect_rustfs_admin::ops::sts_form_post::{self, CLAIM, StsFormPost};
use rustfs_gateway_dialect_rustfs_admin::{BodyKind, FORM_ROUTES, OVERLAY};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_sig::SigService;

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
    assert!(!floor.privileged(), "legacy RustFS verifies a presigned URL on its STS endpoint");
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
        .body(())
        .expect("a fixture request");
    let wire = WireRequest::accept(request, &Limits::default()).expect("an acceptable fixture request");
    let meta = MetaView::of(&wire, TargetKind::Service).expect("a view");
    let decoded = StsFormPost::decode(&meta, RequestBody::Buffered(body.clone())).expect("the body decodes");
    assert_eq!(decoded, body);
    let encoded = StsFormPost::encode(AdminResponse::bytes("text/xml", b"<AssumeRoleResponse/>".to_vec()), &meta, 200)
        .expect("the answer encodes");
    assert_eq!(encoded.status, 200);
    assert!(matches!(&encoded.body, ResponseBody::Complete(bytes) if bytes.as_slice() == b"<AssumeRoleResponse/>"));
}
