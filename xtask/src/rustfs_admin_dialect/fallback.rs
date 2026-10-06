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

//! Generation of the two synthetic admin fallback operations (ADR-0039).
//!
//! Responsible for: their fixed declarations, codecs and handlers, and identifying the concrete
//! routes that must declare precedence over them. NOT responsible for: native route inventory
//! entries, policy decisions or installing handlers in a deployment.
//! Upstream: ADR-0039 and `super::plan`. Downstream: `super::generate` and `super::render`.

use std::fmt::Write as _;

use super::Declared;

pub(super) const EVIDENCE: &str = "https://github.com/rustfs/gateway/blob/main/docs/adr/0039-authenticated-admin-fallbacks.md";

pub(super) struct Fallback {
    pub(super) stem: &'static str,
    pub(super) ty: &'static str,
    pub(super) name: &'static str,
    v4: bool,
    precedence: u16,
    status: u16,
}

pub(super) const FALLBACKS: &[Fallback] = &[
    Fallback {
        stem: "admin_v4_fallback",
        ty: "AdminV4Fallback",
        name: "rustfs:AdminV4Fallback",
        v4: true,
        precedence: u16::MAX - 1,
        status: 426,
    },
    Fallback {
        stem: "admin_fallback",
        ty: "AdminFallback",
        name: "rustfs:AdminFallback",
        v4: false,
        precedence: u16::MAX,
        status: 501,
    },
];

/// Real rows retain their method/query predicates and stand ahead of every overlapping fallback.
pub(super) fn shadowed_by(declared: &Declared) -> impl Iterator<Item = &'static Fallback> {
    FALLBACKS.iter().filter(move |fallback| {
        let Some(rest) = declared.path.strip_prefix("/rustfs/admin") else { return false };
        if fallback.v4 {
            rest == "/v4" || rest.starts_with("/v4/")
        } else {
            rest.is_empty() || rest.starts_with('/')
        }
    })
}

impl Fallback {
    pub(super) fn render(&self, license: &str) -> String {
        let mut out = license.replace(
            "from\n// crates/goldens/src/migration_inventory/rustfs_admin_routes.json.",
            "from ADR-0039.",
        );
        let name = self.name;
        let ty = self.ty;
        let status = self.status;
        let precedence = self.precedence;
        let suffix = if self.v4 { "/v4" } else { "" };
        let templates: Vec<_> = ["/rustfs/admin", "/minio/admin"]
            .into_iter()
            .flat_map(|prefix| {
                [
                    format!("{prefix}{suffix}"),
                    format!("{prefix}{suffix}/"),
                    format!("{prefix}{suffix}/{{*remainder}}"),
                ]
            })
            .collect();
        let rows = templates
            .iter()
            .map(|path| format!("ClaimedRow {{ template: {path:?}, selector: &[] }}"))
            .collect::<Vec<_>>()
            .join(",\n");
        let selector = templates
            .iter()
            .map(|path| format!("PathTemplate({path:?})"))
            .collect::<Vec<_>>()
            .join(" ∨ ");
        let shadows = if self.v4 {
            format!(
                "ShadowingDecl {{ winner: NAME, shadowed: \"rustfs:AdminFallback\", reason: \"The v4 downgrade signal precedes the general unmatched-admin error.\", evidence: &[{EVIDENCE:?}] }}"
            )
        } else {
            String::new()
        };
        let answer = if self.v4 {
            "Ok(Resp::new(()))"
        } else {
            "Err(HandlerError::not_implemented(\"A header you provided implies functionality that is not implemented.\"))"
        };
        let shadow_import = if self.v4 {
            "use rustfs_gateway_core::route::ShadowingDecl;"
        } else {
            ""
        };
        let response_import = if self.v4 { "Resp" } else { "HandlerError" };
        let _ = write!(
            out,
            r#"//! `{name}`: the authenticated {status} answer for unmatched admin requests.
//!
//! Responsible for: its rows, caller-only authorization, bodyless codec and fixed handler.
//! NOT responsible for: authentication, policy decisions or deployment registration.
//! Upstream: ADR-0039 and the generator. Downstream: the dialect and a registering deployment.

use rustfs_gateway_core::codec::{{CodecError, EncodedResponse, MetaView, OperationCodec, RequestBody, RequestBodyMode}};
use rustfs_gateway_core::dialect::{{ClaimedRoute, ClaimedRow, OverlayRow}};
use rustfs_gateway_core::op::{{AuthRequirement, Operation, ResourceShape}};
use rustfs_gateway_core::registry::{{HandlerDeadlineClass, OperationSpec}};
{shadow_import}
use rustfs_gateway_core::{{DerivedResourceError, Handler, HandlerResult, NoDerived, Req, {response_import}, SubjectRule}};
use rustfs_gateway_sig::OperationFloor;

/// The operation name and its vendor authorization label.
pub const NAME: &str = {name:?};
/// Exact, trailing-slash and descendant forms under both admin aliases; all methods.
pub static ROWS: &[ClaimedRow] = &[{rows}];
/// The reviewed placement after the real operations.
pub const ROUTE: ClaimedRoute = ClaimedRoute {{ precedence: {precedence}, rows: ROWS, shadows: &[{shadows}], bucket_param: None }};
/// The independent overlay record for this synthetic operation, not a native inventory row.
pub const OVERLAY_ROW: OverlayRow = OverlayRow {{ name: NAME, precedence: {precedence}, selector: {selector:?}, action: "{name} about caller", resource: ResourceShape::Service, success_status: {status}, anonymous: false, evidence: &[{EVIDENCE:?}] }};

static SPEC: OperationSpec = OperationSpec::builder(NAME, {status}, None)
    .handler_deadline_class(HandlerDeadlineClass::Standard)
    .required_params(&[])
    .auth(AuthRequirement::new(NAME, ResourceShape::Service).about_subject(SubjectRule::Caller))
    .build();
static FLOOR: OperationFloor = crate::admin::floor(NAME);

/// The fallback operation and its fixed handler; register this value for this operation type.
///
/// It is deliberately outside `fold_every_operation`, whose handlers serve inventory routes.
/// Both authorization stages run before this handler, and no caller secret is requested.
#[derive(Debug)]
pub struct {ty};

impl Operation for {ty} {{
    const NAME: &'static str = NAME;
    type Input = ();
    type Output = ();
    type DerivedResources = NoDerived;
    fn derive_resources(_input: &Self::Input) -> Result<NoDerived, DerivedResourceError> {{ Ok(NoDerived) }}
    fn seal_derived_input(_input: &mut Self::Input) {{}}
    fn spec() -> &'static OperationSpec {{ &SPEC }}
    fn floor() -> &'static OperationFloor {{ &FLOOR }}
}}

impl OperationCodec for {ty} {{
    const REQUEST_BODY: RequestBodyMode = RequestBodyMode::None;
    fn decode(_request: &MetaView<'_>, _body: RequestBody) -> Result<(), CodecError> {{ Ok(()) }}
    fn encode(_output: (), _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {{ Ok(EncodedResponse::of(status)) }}
}}

impl Handler<{ty}> for {ty} {{
    async fn call(&self, _request: Req<{ty}>) -> HandlerResult<{ty}> {{ {answer} }}
}}
"#
        );
        out
    }
}
