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

//! Generation of the one operation the dialect serves behind a form claim: RustFS's STS endpoint
//! (ADR-0041).
//!
//! Responsible for: checking that the inventory still records the route as the ruling expects,
//! and rendering its operation module from the inventory's facts.
//! NOT responsible for: choosing which routes are form routes (`super::rulings::FORMS`), the claim
//! grammar or matching (`rustfs-gateway-core`), or installing a handler.
//! Upstream: `super::plan`. Downstream: `super::generate` and `super::render`.

use std::fmt::Write as _;

use super::Route;

/// The module the operation is generated into.
pub(super) const STEM: &str = "sts_form_post";
/// Its type and operation name.
const TYPE: &str = "StsFormPost";
/// Its precedence in the overlay's record: one before the first path-claimed operation. A form
/// claim overlaps no row, so the number orders nothing.
const PRECEDENCE: u16 = super::FIRST_PRECEDENCE - 1;
/// The media type RustFS's STS predicate compares, ASCII case-insensitively.
const MEDIA_TYPE: &str = "application/x-www-form-urlencoded";
/// The ADR this operation's shape follows.
pub(super) const EVIDENCE: &str =
    "https://github.com/rustfs/gateway/blob/main/docs/adr/0041-form-claims-and-the-rustfs-sts-endpoint.md";

/// One inventory route served behind a form claim, with the facts its module is rendered from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Formed {
    pub(super) method: String,
    pub(super) path: String,
    pub(super) group: String,
    pub(super) handler: String,
    handler_url: String,
    layer_url: String,
    router_url: String,
}

impl Formed {
    /// The form route `route`, which the inventory must still record as anonymous with the
    /// custom-auth class `detail`, a buffered request and a buffered response.
    pub(super) fn of(route: &Route, detail: &str, at: &str, commit: &str) -> Result<Self, String> {
        if route.method != "POST" || route.path != "/" {
            return Err(format!("{at}: only RustFS's STS endpoint, POST /, is served behind a form claim"));
        }
        if route.auth_mode != "anonymous" || route.auth_detail.as_deref() != Some(detail) {
            return Err(format!(
                "{at}: ruled as an anonymous {detail:?} route, but the inventory now records {:?} {:?}",
                route.auth_mode, route.auth_detail
            ));
        }
        if route.request_body != "buffered" || route.response_body != "buffered" || route.caller_secret_body != "none" {
            return Err(format!(
                "{at}: the inventory no longer records a buffered request and response with no secret"
            ));
        }
        let source = |file: &str| format!("https://github.com/rustfs/rustfs/blob/{commit}/{file}");
        Ok(Self {
            method: route.method.clone(),
            path: route.path.clone(),
            group: route.group.clone(),
            handler: route.handler.clone(),
            handler_url: source(&route.handler_file),
            layer_url: source("rustfs/src/server/layer.rs"),
            router_url: source(super::RUSTFS_ROUTER),
        })
    }

    /// The operation module, before rustfmt.
    pub(super) fn render(&self, license: &str) -> String {
        let mut out = String::from(license);
        let name = format!("{}:{TYPE}", super::VENDOR);
        let label = format!("{}:{}", super::VENDOR, self.handler.trim_end_matches("Handler"));
        let Self {
            method,
            path,
            group,
            handler,
            handler_url,
            layer_url,
            router_url,
        } = self;
        let selector = format!("FormClaim(POST {path:?})");
        let _ = write!(
            out,
            r#"//! `{name}`: `{method} {path}` with an `{MEDIA_TYPE}` body on every host, registration group `{group}`
//! (ADR-0041).
//!
//! Responsible for: the operation's type, name, form claim, action, specification, floor and codec, as the
//! inventory records RustFS's `{handler}` route.
//! NOT responsible for: the handler, which the deployment registers, or matching the claim
//! (`rustfs_gateway_core::route::FormClaim`).
//! Upstream: the recorded inventory, ADR-0041 and `crate::admin`. Downstream: `crate::dialect`, which declares
//! it behind [`CLAIM`], and a deployment that registers a handler for [`{TYPE}`].
//!
//! RustFS's STS endpoint. Its router takes the request before its S3 path parser runs, whatever the host's
//! bucket label and whatever the query, verifies whatever signature it carries (a header signature under any
//! service RustFS accepts, a presigned URL, SigV2), and then lets an unsigned request through as well: the
//! handler reads `Action` from the body, refuses `AssumeRole` without credentials, and authenticates
//! `AssumeRoleWithWebIdentity` by the token in the body. So the operation is reachable anonymously, its action
//! is the vendor label `{label}`, the authorizer is still asked, with no identity, and the body is handed over
//! as it arrived.

use bytes::Bytes;
use rustfs_gateway_core::codec::{{CodecError, EncodedResponse, MetaView, OperationCodec, RequestBody, RequestBodyMode}};
use rustfs_gateway_core::dialect::{{FormRoute, OverlayRow}};
use rustfs_gateway_core::op::{{AuthRequirement, Operation, ResourceShape}};
use rustfs_gateway_core::registry::OperationSpec;
use rustfs_gateway_core::route::FormClaim;
use rustfs_gateway_core::{{DerivedResourceError, NoDerived}};
use rustfs_gateway_sig::{{OperationFloor, SigService}};

use crate::admin::{{self, AdminResponse}};
use crate::record::{{self, BodyKind, FormRouteRecord}};

/// The operation name.
pub const NAME: &str = {name:?};

/// What authorises it, on no bucket: the vendor label of RustFS's handler, which makes no IAM check
/// before it reads the body.
pub const AUTH: AuthRequirement = AuthRequirement::new({label:?}, ResourceShape::Service);

/// RustFS's STS predicate: a `POST` of exactly `/` whose first `Content-Type` value names the form media
/// type, on every host and whatever the query.
pub static CLAIM: FormClaim = FormClaim {{
    path: {path:?},
    reason: "RustFS's router takes a form POST of / as its STS endpoint before its S3 path parser runs, on every host and whatever the query.",
    evidence: &[{layer_url:?}, {router_url:?}],
}};

/// Where the dialect serves it.
pub const ROUTE: FormRoute = FormRoute {{ precedence: {PRECEDENCE}, claim: &CLAIM }};

/// `{method} {path}` with a form body.
#[derive(Debug)]
pub struct {TYPE};

static SPEC: OperationSpec = admin::spec(NAME, AUTH, false);

/// Not privileged, and reachable anonymously by its own opt-in, which the start-up posture report lists: a
/// header signature, a presigned URL where the assembly admits one on a standard operation, SigV2 where the
/// floor admits it, or nothing at all.
///
/// Legacy-compat (rustfs/backlog#2684): legacy RustFS verifies a presigned URL (SigV4 or SigV2) on its STS
/// endpoint and hands the handler its credentials. A presigned URL signs neither the `Content-Type` nor the
/// body, and the claim reads neither host nor query, so any `POST` URL presigned for the path `/` (one for
/// `POST /`, or a virtual-hosted `DeleteObjects` URL, `POST /?delete` on a bucket's host) resent with a form
/// body lets whoever holds it choose the `Action`, the session policy and the duration of the credentials it
/// mints under the signer's identity. Kept so a client that presigns its STS call keeps working; the intended
/// future behaviour is a privileged floor, header signatures only.
static FLOOR: OperationFloor =
    OperationFloor::builtin(NAME, SigService::Sts).allow_anonymous_after_listing_in_the_posture_report();

impl Operation for {TYPE} {{
    const NAME: &'static str = NAME;

    /// The form body, as it arrived.
    type Input = Bytes;
    type Output = AdminResponse;
    type DerivedResources = NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, DerivedResourceError> {{
        Ok(NoDerived)
    }}

    fn seal_derived_input(_input: &mut Self::Input) {{}}

    fn spec() -> &'static OperationSpec {{
        &SPEC
    }}

    fn floor() -> &'static OperationFloor {{
        &FLOOR
    }}
}}

impl OperationCodec for {TYPE} {{
    const REQUEST_BODY: RequestBodyMode = RequestBodyMode::Full;

    fn decode(_request: &MetaView<'_>, body: RequestBody) -> Result<Self::Input, CodecError> {{
        admin::buffered(body)
    }}

    fn encode(output: Self::Output, _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {{
        admin::encode(output, status)
    }}
}}

/// This operation's row in the dialect's overlay, as a reviewer reads it.
pub const OVERLAY_ROW: OverlayRow = OverlayRow {{
    name: NAME,
    precedence: {PRECEDENCE},
    selector: {selector:?},
    action: {label:?},
    resource: ResourceShape::Service,
    success_status: 200,
    anonymous: true,
    evidence: &[{handler_url:?}, {EVIDENCE:?}, record::ISSUE],
}};

/// The inventory row this operation was generated from.
pub const RECORD: FormRouteRecord = FormRouteRecord {{
    operation: NAME,
    group: {group:?},
    method: {method:?},
    path: {path:?},
    action: {label:?},
    rustfs_handler: {handler:?},
    request_body: BodyKind::Buffered,
    response_body: BodyKind::Buffered,
}};
"#
        );
        out
    }
}
