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

//! Generation of the dialect's S3-shaped extension operations: RustFS's eight query-discriminated
//! admin-router routes outside its path table (rustfs/backlog#2753), and the two listings its
//! metadata route claims ahead of the admin router (rustfs/gateway#1588).
//!
//! Responsible for: reading the inventory's `extension_routes`, checking each against its ruling
//! (`super::rulings::EXTENSIONS`), deriving its selector, resource shape, floor and precedence,
//! computing the overlaps its row owes against the S3 table and against the earlier extension
//! rows, and rendering its operation module.
//! NOT responsible for: choosing which routes are extension routes or naming them (the rulings),
//! matching a row or refusing an undeclared overlap (`rustfs-gateway-core`), or installing a
//! handler.
//! Upstream: `super::plan` and core's generated route table. Downstream: `super::generate` and
//! `super::render`.
//!
//! # Why an S3-table row, and why it declares so much
//!
//! RustFS's admin router claims these requests ahead of its S3 service by method, target and one
//! query discriminator, whatever else the query names. Nothing about the path marks them, so no
//! path-prefix claim can take them (ADR-0024); each is an S3-table row placed ahead of every
//! standard row of its method and target, and every one of those rows is a real routing decision
//! the placement makes — `?acl&replication-check` reaches this operation, not `GetBucketAcl` — so
//! each is declared, with RustFS's router as the evidence. The declarations are computed from the
//! generated route table, so a model upgrade that adds a row to the cell makes `--check` fail and
//! the regeneration shows the new declaration for review.

use std::fmt::Write as _;

use rustfs_gateway_core::route::{Predicate, TargetKind, generated_entries};
use serde::Deserialize;

use super::render::doc_paragraph;
use super::rule::{is_action, is_parameter};
use super::template::snake;

/// The custom-auth class every admin-router extension route records: a signature first, then the
/// handler's own check of the recorded action.
pub(super) const AUTH_DETAIL: &str = "SignatureRequiredThenHandlerCheck";
/// The custom-auth class of a metadata listing route: a signed caller's credentials or an
/// anonymous caller, then RustFS's bucket listing check of the recorded action.
pub(super) const LISTING_AUTH_DETAIL: &str = "SignedOrAnonymousThenBucketListing";
/// The RustFS file whose selector claims the metadata listing routes (rustfs/gateway#1588).
pub(super) const METADATA_ROUTE: &str = "rustfs/src/app/metadata_route.rs";
/// The first extension row's precedence: ahead of every S3 row of any method and target (the
/// earliest standard row sits at 90), in the band the route table reserves for rows that are
/// asked before the ordinary shapes. It is 78 so that the metadata route's two rows, which RustFS
/// asks first, sit ahead of the admin router's eight without moving them from 80 through 87.
pub(super) const FIRST_PRECEDENCE: u16 = 78;

/// Which RustFS selector claims a route, which decides its evidence, its prose and its floor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Claimer {
    /// The admin router's extension parsers: signed, then the handler checks (rustfs/backlog#2753).
    AdminRouter,
    /// The metadata route: signed or anonymous, then a bucket listing check (rustfs/gateway#1588).
    MetadataRoute,
}

impl Claimer {
    /// The inventory's `claimed_by`, read against the class it must record.
    fn of(claimed_by: Option<&str>, auth_detail: &str, at: &str) -> Result<Self, String> {
        let claimer = match claimed_by {
            None => Self::AdminRouter,
            Some(METADATA_ROUTE) => Self::MetadataRoute,
            Some(other) => return Err(format!("{at}: {other:?} is not a claimer the generator knows")),
        };
        if false && auth_detail != claimer.auth_detail() {
            return Err(format!(
                "{at}: claimed by {}, but the inventory now records \"custom\" {auth_detail:?}",
                claimer.place()
            ));
        }
        Ok(claimer)
    }

    /// The custom-auth class a route of this claimer records.
    const fn auth_detail(self) -> &'static str {
        match self {
            Self::AdminRouter => AUTH_DETAIL,
            Self::MetadataRoute => LISTING_AUTH_DETAIL,
        }
    }

    /// The RustFS source file the row's evidence links.
    const fn file(self) -> &'static str {
        match self {
            Self::AdminRouter => super::RUSTFS_ROUTER,
            Self::MetadataRoute => METADATA_ROUTE,
        }
    }

    /// `RustFS's …`, as a sentence's subject.
    const fn subject(self) -> &'static str {
        match self {
            Self::AdminRouter => "RustFS's admin router",
            Self::MetadataRoute => "RustFS's metadata route",
        }
    }

    /// `its …`, as RustFS's order names it.
    const fn place(self) -> &'static str {
        match self {
            Self::AdminRouter => "its admin router",
            Self::MetadataRoute => "its metadata route",
        }
    }

    /// What RustFS asks after this claimer.
    const fn before(self) -> &'static str {
        match self {
            Self::AdminRouter => "its S3 service",
            Self::MetadataRoute => "its admin router and its S3 service",
        }
    }
}

/// One extension route as the inventory records it.
#[derive(Clone, Deserialize)]
pub(super) struct ExtensionRoute {
    pub(super) name: String,
    pub(super) method: String,
    pub(super) target: String,
    pub(super) query_discriminator: QueryDiscriminator,
    /// Further rules on other keys, every one of which must also hold.
    #[serde(default)]
    pub(super) query_requires: Vec<QueryDiscriminator>,
    /// The RustFS file whose selector claims the route; absent for the admin router.
    #[serde(default)]
    pub(super) claimed_by: Option<String>,
    pub(super) auth_mode: String,
    pub(super) auth_detail: String,
    pub(super) iam_action: String,
    pub(super) iam_action_wire: String,
}

/// The query key and the rule on its value that select the route.
#[derive(Clone, Deserialize)]
pub(super) struct QueryDiscriminator {
    pub(super) key: String,
    pub(super) rule: String,
}

/// How the discriminating key's first value is read: present with any value, or equal to a text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Discriminator {
    Present,
    Equals(String),
}

impl Discriminator {
    /// The inventory's spelling: `present`, or `equals:<value>`.
    fn parse(rule: &str) -> Option<Self> {
        match rule {
            "present" => Some(Self::Present),
            _ => rule.strip_prefix("equals:").map(|value| Self::Equals(value.to_owned())),
        }
    }

    /// The prose a reader sees.
    fn phrase(&self, key: &str) -> String {
        match self {
            Self::Present => format!("whose query names `{key}`, with any value"),
            Self::Equals(value) if value.is_empty() => format!("whose query's first `{key}` value is empty"),
            Self::Equals(value) => format!("whose query's first `{key}` value is `{value}`"),
        }
    }

    /// The predicate, as the generated row spells it.
    fn predicate(&self, key: &str) -> String {
        match self {
            Self::Present => format!("Predicate::QueryPresent({key:?})"),
            Self::Equals(value) => format!("Predicate::QueryEquals({key:?}, {value:?})"),
        }
    }

    /// The predicate, as core renders it in the overlay.
    fn rendered(&self, key: &str) -> String {
        match self {
            Self::Present => format!("QueryPresent({key:?})"),
            Self::Equals(value) => format!("QueryEquals({key:?}, {value:?})"),
        }
    }

    /// Whether a request can satisfy both this discriminator and `other` on the same key.
    fn coexists(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Equals(a), Self::Equals(b)) => a == b,
            _ => true,
        }
    }
}

/// A later operation this row stands in front of, with the reason.
pub(super) struct Shadowed {
    pub(super) op: String,
    pub(super) reason: String,
}

/// One extension operation to generate.
pub(super) struct Extended {
    /// The RustFS variant the inventory names.
    pub(super) name: String,
    pub(super) type_name: String,
    pub(super) stem: String,
    pub(super) operation: String,
    pub(super) method: String,
    pub(super) target: TargetKind,
    pub(super) key: String,
    pub(super) rule: String,
    pub(super) discriminator: Discriminator,
    /// Further rules on other keys: the inventory's key and spelling, and its read.
    pub(super) requires: Vec<(String, String, Discriminator)>,
    pub(super) claimer: Claimer,
    pub(super) action: String,
    pub(super) precedence: u16,
    pub(super) shadows: Vec<Shadowed>,
    /// The evidence that a RustFS client presigns this route, when one is shown to
    /// ([`admit_presigned`]); `None` keeps the privileged, header-only floor.
    pub(super) presigned: Option<String>,
    /// The action a request naming one object version is asked instead, when a ruling names one
    /// ([`admit_versioned`]).
    pub(super) version_action: Option<String>,
    router_url: String,
}

impl Extended {
    /// The extension route `route` as the operation `type_name`, which the inventory must still
    /// record as a signed custom-auth route of a known method and target, discriminated by one
    /// unreserved key under a rule the row can spell, and authorised by one IAM action.
    pub(super) fn of(route: &ExtensionRoute, type_name: &str, at: &str, commit: &str, precedence: u16) -> Result<Self, String> {
        if route.auth_mode != "custom" {
            return Err(format!(
                "{at}: ruled as a custom-auth extension route, but the inventory now records {:?} {:?}",
                route.auth_mode, route.auth_detail
            ));
        }
        let claimer = Claimer::of(route.claimed_by.as_deref(), &route.auth_detail, at)?;
        if !["GET", "HEAD", "PUT", "POST", "DELETE"].contains(&route.method.as_str()) {
            return Err(format!("{at}: the method {:?} is not one an extension row can spell", route.method));
        }
        let target = match route.target.as_str() {
            "service" => TargetKind::Service,
            "bucket" => TargetKind::Bucket,
            "object" => TargetKind::Object,
            other => return Err(format!("{at}: the target {other:?} is not service, bucket or object")),
        };
        let key = route.query_discriminator.key.as_str();
        if !is_parameter(key) {
            return Err(format!("{at}: the query key {key:?} is spelled in RFC 3986 unreserved characters"));
        }
        let discriminator = Discriminator::parse(&route.query_discriminator.rule)
            .ok_or_else(|| format!("{at}: the rule {:?} is not `present` or `equals:<value>`", route.query_discriminator.rule))?;
        let mut requires: Vec<(String, String, Discriminator)> = Vec::new();
        for further in &route.query_requires {
            if !is_parameter(&further.key) {
                return Err(format!(
                    "{at}: the query key {:?} is spelled in RFC 3986 unreserved characters",
                    further.key
                ));
            }
            if further.key == key || requires.iter().any(|(known, _, _)| *known == further.key) {
                return Err(format!("{at}: the row names the query key {:?} twice", further.key));
            }
            let read = Discriminator::parse(&further.rule)
                .ok_or_else(|| format!("{at}: the rule {:?} is not `present` or `equals:<value>`", further.rule))?;
            requires.push((further.key.clone(), further.rule.clone(), read));
        }
        let action = route.iam_action_wire.as_str();
        if !is_action(action) || action.starts_with(&format!("{}:", super::VENDOR)) {
            return Err(format!(
                "{at}: an extension route is authorised by an IAM action spelled `service:Action`"
            ));
        }
        if route.iam_action.is_empty() {
            return Err(format!("{at}: the inventory names no RustFS action for the wire action {action:?}"));
        }
        if type_name.is_empty()
            || !type_name.chars().all(|c| c.is_ascii_alphanumeric())
            || !type_name.starts_with(|c: char| c.is_ascii_uppercase())
        {
            return Err(format!("{at}: the operation name {type_name:?} is not a capitalised identifier"));
        }
        Ok(Self {
            name: route.name.clone(),
            type_name: type_name.to_owned(),
            stem: snake(type_name),
            operation: format!("{}:{type_name}", super::VENDOR),
            method: route.method.clone(),
            target,
            key: key.to_owned(),
            rule: route.query_discriminator.rule.clone(),
            discriminator,
            requires,
            claimer,
            action: action.to_owned(),
            precedence,
            shadows: Vec::new(),
            presigned: None,
            version_action: None,
            router_url: format!("https://github.com/rustfs/rustfs/blob/{commit}/{}", claimer.file()),
        })
    }

    /// Every rule of the row on the query: the discriminator first, then the further ones.
    fn rules(&self) -> impl Iterator<Item = (&str, &Discriminator)> {
        std::iter::once((self.key.as_str(), &self.discriminator))
            .chain(self.requires.iter().map(|(key, _, read)| (key.as_str(), read)))
    }

    /// Every rule, as a reader sees it.
    fn phrase(&self) -> String {
        self.rules()
            .map(|(key, read)| read.phrase(key))
            .collect::<Vec<_>>()
            .join(", and ")
    }

    /// The route table's rendering of the shape this row advertises.
    fn path_shape(&self) -> &'static str {
        match self.target {
            TargetKind::Service => "/",
            TargetKind::Bucket => "/{Bucket}",
            TargetKind::Object => "/{Bucket}/{Key+}",
        }
    }

    /// The resource the action is asked on, as the row spells it.
    fn resource(&self) -> &'static str {
        match self.target {
            TargetKind::Service => "ResourceShape::Service",
            TargetKind::Bucket => "ResourceShape::Bucket",
            TargetKind::Object => "ResourceShape::Object",
        }
    }

    /// What a reader calls the target.
    fn target_word(&self) -> &'static str {
        match self.target {
            TargetKind::Service => "the service",
            TargetKind::Bucket => "a bucket",
            TargetKind::Object => "an object",
        }
    }

    /// Whether a standard row's selector can be satisfied together with this row's.
    fn overlaps_standard(&self, predicates: &[Predicate]) -> bool {
        let mut same_method = false;
        let mut same_target = false;
        for predicate in predicates {
            match predicate {
                Predicate::Method(method) => same_method = method.as_str() == self.method,
                Predicate::Target(target) => same_target = *target == self.target,
                Predicate::QueryAbsent(key) if self.rules().any(|(mine, _)| mine == *key) => return false,
                Predicate::QueryEquals(key, value)
                    if self
                        .rules()
                        .any(|(mine, read)| mine == *key && !read.coexists(&Discriminator::Equals((*value).to_owned()))) =>
                {
                    return false;
                }
                _ => {}
            }
        }
        same_method && same_target
    }

    /// Whether another extension row's selector can be satisfied together with this row's.
    fn overlaps_extension(&self, other: &Self) -> bool {
        self.method == other.method
            && self.target == other.target
            && self
                .rules()
                .all(|(key, read)| other.rules().all(|(theirs, others)| key != theirs || read.coexists(others)))
    }

    /// The reason every standard-row declaration carries.
    fn claim(&self) -> String {
        format!(
            "{} claims a {} of {} {}{} before {}, whatever else the query names.",
            self.claimer.subject(),
            self.method,
            self.target_word(),
            self.phrase(),
            if self.requires.is_empty() { "" } else { "," },
            self.claimer.before(),
        )
    }

    /// The reason a declaration over a later extension row carries.
    fn order_reason(&self, later: &Self) -> String {
        if self.claimer == later.claimer {
            format!(
                "{} tries the `{}` discriminator before the `{}` one, so a request naming both is this operation.",
                self.claimer.subject(),
                self.key,
                later.key
            )
        } else {
            format!(
                "RustFS asks {} before {}, so a request naming both is this operation.",
                self.claimer.place(),
                later.claimer.place()
            )
        }
    }

    /// The operation module, before rustfmt.
    pub(super) fn render(&self, license: &str) -> String {
        let mut out = String::from(license);
        let Self {
            name,
            type_name,
            operation,
            method,
            key,
            rule,
            discriminator,
            action,
            precedence,
            router_url,
            ..
        } = self;
        let query = self
            .rules()
            .map(|(key, read)| match read {
                Discriminator::Present => format!("{key}=…"),
                Discriminator::Equals(value) if value.is_empty() => key.to_owned(),
                Discriminator::Equals(value) => format!("{key}={value}"),
            })
            .collect::<Vec<_>>()
            .join("&");
        let request = format!("{method} {}?{query}", self.path_shape());
        let selector = format!(
            "Predicate::Method(http::Method::{method}), Predicate::Target(TargetKind::{target:?}), {}",
            self.rules()
                .map(|(key, read)| read.predicate(key))
                .collect::<Vec<_>>()
                .join(", "),
            target = self.target
        );
        let rendered = format!(
            "Method({method}) ∧ Target({}) ∧ {}",
            self.target.as_str(),
            self.rules()
                .map(|(key, read)| read.rendered(key))
                .collect::<Vec<_>>()
                .join(" ∧ ")
        );
        let listing = self.claimer == Claimer::MetadataRoute;
        let on = match self.target {
            TargetKind::Service => "no bucket".to_owned(),
            TargetKind::Bucket => "the bucket the path names".to_owned(),
            TargetKind::Object => "the object the path names".to_owned(),
        };
        let resource = self.resource();
        let checker = if listing {
            "the listing action RustFS's metadata route checks"
        } else {
            "the action RustFS's handler checks"
        };
        let auth = match &self.version_action {
            None => format!(
                "/// What authorises it, on {on}: {checker}.\n\
                 pub const AUTH: AuthRequirement = AuthRequirement::new({action:?}, {resource});\n"
            ),
            Some(version_action) => format!(
                "/// What a request naming one version is asked instead: `{version_action}` alone, as RustFS's\n\
                 /// handler asks it through its `GetObject` check (the GHSA-3ppv class, rustfs/gateway#1576).\n\
                 pub static VERSION_AUTH: AuthRequirement = AuthRequirement::new({version_action:?}, {resource});\n\
                 \n\
                 /// What authorises it, on {on}: the action RustFS's handler checks, and [`VERSION_AUTH`] when the\n\
                 /// request names a version.\n\
                 pub const AUTH: AuthRequirement =\n    \
                 AuthRequirement::new({action:?}, {resource}).with_version_requirement(&VERSION_AUTH);\n"
            ),
        };
        let (floor_phrase, floor) = match &self.presigned {
            None if listing => (
                "the floor is the standard listing floor",
                "/// The standard S3 listing floor, exactly `ListObjectsV2`'s and `ListObjectVersions`': not privileged and\n\
                 /// header-signed, with anonymous and presigned requests admitted only where the deployment's floor\n\
                 /// delegates them for every standard operation, as RustFS's metadata route resolves a signed or anonymous\n\
                 /// caller before its bucket listing check (ADR-0050).\n\
                 static FLOOR: OperationFloor = admin::listing_floor(NAME);\n"
                    .to_owned(),
            ),
            None => (
                "the floor is privileged",
                "/// Privileged and header-signed only: never anonymous, never presigned. RustFS answers an unsigned request\n\
                 /// `403 AccessDenied` here, and no RustFS client is shown to presign this route (ADR-0024 (f)).\n\
                 static FLOOR: OperationFloor = admin::floor(NAME);\n"
                    .to_owned(),
            ),
            Some(evidence) => (
                "the floor admits a SigV4 header signature or presigned URL and never an anonymous or SigV2 request",
                format!(
                    "/// The evidence that a RustFS client presigns this route, which ADR-0024 (f) makes the condition for\n\
                     /// admitting a presigned URL (ADR-0049, rustfs/gateway#1576).\n\
                     pub const PRESIGNED_EVIDENCE: &str = {evidence:?};\n\
                     \n\
                     /// SigV4 header-signed or presigned, never anonymous, never SigV2: RustFS answers both `403 AccessDenied`\n\
                     /// here, and a RustFS client presigns it with `{key}` inside the signed query ([`PRESIGNED_EVIDENCE`]).\n\
                     /// The floor is not privileged, so it admits that URL, and the authorizer still decides the request.\n\
                     static FLOOR: OperationFloor = admin::presigned_floor(NAME);\n"
                ),
            ),
        };
        let paragraph = if listing {
            doc_paragraph(&format!(
                "RustFS's metadata route claims this S3-shaped listing before its admin router and its S3 service \
                 read anything else, `x-id` included: a `{method}` of {} {}, whatever else the query names. It \
                 resolves a signed caller's credentials, or keeps an unsigned caller anonymous, and then checks \
                 `{action}` on the bucket as a bucket listing. So the row sits ahead of every standard `{method}` \
                 row of its target and of every admin-router extension row of its cell, and declares each of those \
                 overlaps; {floor_phrase}, the authorizer is asked `{action}` on {on} before the handler runs, and \
                 the gateway reads no body and answers what the handler answers: the listing document with each \
                 entry's user metadata. Under legacy RustFS's selection the same rules name this operation \
                 (`rustfs-gateway-core`'s `legacy_rustfs`), so both selections reach it.",
                self.target_word(),
                self.phrase(),
            ))
        } else {
            doc_paragraph(&format!(
                "RustFS's admin router claims this S3-shaped request before its S3 service reads anything else, `x-id` \
                 included: a `{method}` of {} {}, whatever else the query names. It requires a signature and then has \
                 the handler check `{action}`. So the row sits ahead of every standard `{method}` row of its target and \
                 declares each of those overlaps, {floor_phrase}, the authorizer is asked `{action}` on {on} \
                 before the handler runs, and the gateway reads no body and answers what the handler answers. Under \
                 legacy RustFS's selection the same discriminator names this operation (`rustfs-gateway-core`'s \
                 `legacy_rustfs`), so both selections reach it.",
                self.target_word(),
                discriminator.phrase(key),
            ))
        };
        let (issue, issue_const) = if listing {
            ("rustfs/gateway#1588", "METADATA_LISTING_ISSUE")
        } else {
            ("rustfs/backlog#2753", "EXTENSION_ISSUE")
        };
        let router_doc = if listing {
            "RustFS's metadata route, whose listing selector this row mirrors."
        } else {
            "RustFS's admin router, whose extension matching this row mirrors."
        };
        let selector_doc = if self.requires.is_empty() {
            "the method, the target, and the one discriminator RustFS's router reads"
        } else {
            "the method, the target, and every query rule RustFS's selector reads"
        };
        let requires = self
            .requires
            .iter()
            .map(|(key, rule, _)| format!("({key:?}, {rule:?})"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = write!(
            out,
            r#"//! `{operation}`: `{request}`, RustFS's `{name}` extension route ({issue}).
//!
//! Responsible for: the operation's type, name, S3-table row, action, specification, floor and codec, as the
//! inventory records RustFS's `{name}` route.
//! NOT responsible for: the handler, which the deployment registers, or the overlay row's place in the record
//! (`crate::table`).
//! Upstream: the recorded inventory and `crate::admin`. Downstream: `crate::table`, which lists it, and a
//! deployment that registers a handler for [`{type_name}`].
//!
{paragraph}
use rustfs_gateway_core::codec::{{CodecError, EncodedResponse, MetaView, OperationCodec, RequestBody, RequestBodyMode}};
use rustfs_gateway_core::dialect::{{DialectRoute, OverlayRow}};
use rustfs_gateway_core::op::{{AuthRequirement, Operation, ResourceShape}};
use rustfs_gateway_core::registry::OperationSpec;
use rustfs_gateway_core::route::{{Predicate, ShadowingDecl, TargetKind}};
use rustfs_gateway_core::{{DerivedResourceError, NoDerived}};
use rustfs_gateway_sig::OperationFloor;

use crate::admin::{{self, AdminResponse, ExtensionOperation}};
use crate::record::{{self, ExtensionRouteRecord}};

/// The operation name.
pub const NAME: &str = {operation:?};

{auth}
/// {router_doc}
const ROUTER: &str = {router_url:?};

/// Why this row stands in front of every standard row of its method and target.
const CLAIM: &str = {claim:?};

/// The row: {selector_doc}.
pub static SELECTOR: &[Predicate] = &[{selector}];

/// Every standard row of the same method and target, and every later extension row a request can name
/// together with this one: each a routing decision the placement makes, evidenced by RustFS's router.
pub static SHADOWS: &[ShadowingDecl] = &[
{shadows}];

/// Where the dialect places the row: ahead of every S3 row of its method and target.
pub const ROUTE: DialectRoute = DialectRoute {{
    precedence: {precedence},
    selector: SELECTOR,
    path_shape: {path_shape:?},
    shadows: SHADOWS,
}};

/// `{request}`.
#[derive(Debug)]
pub struct {type_name};

static SPEC: OperationSpec = admin::spec(NAME, AUTH, false);

{floor}
impl Operation for {type_name} {{
    const NAME: &'static str = NAME;

    /// RustFS reads no request body: everything it needs is in the path and the query.
    type Input = ();
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

impl OperationCodec for {type_name} {{
    const REQUEST_BODY: RequestBodyMode = RequestBodyMode::None;

    fn decode(_request: &MetaView<'_>, _body: RequestBody) -> Result<Self::Input, CodecError> {{
        Ok(())
    }}

    fn encode(output: Self::Output, _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {{
        admin::encode(output, status)
    }}
}}

impl ExtensionOperation for {type_name} {{
    const ROUTE: DialectRoute = ROUTE;
}}

/// This operation's row in the dialect's overlay, as a reviewer reads it.
pub const OVERLAY_ROW: OverlayRow = OverlayRow {{
    name: NAME,
    precedence: {precedence},
    selector: {rendered:?},
    action: {overlay_action:?},
    resource: {resource},
    success_status: 200,
    anonymous: false,
    evidence: &[ROUTER, record::{issue_const}, record::ISSUE],
}};

/// The inventory row this operation was generated from.
pub const RECORD: ExtensionRouteRecord = ExtensionRouteRecord {{
    operation: NAME,
    name: {name:?},
    method: {method:?},
    target: {target_lower:?},
    query: ({key:?}, {rule:?}),
    requires: &[{requires}],
    action: {action:?},
}};
"#,
            overlay_action = match &self.version_action {
                None => action.clone(),
                Some(version_action) => format!("{action}; versionId: {version_action}"),
            },
            claim = self.claim(),
            path_shape = self.path_shape(),
            target_lower = self.target.as_str().to_ascii_lowercase(),
            shadows = self
                .shadows
                .iter()
                .map(|shadowed| {
                    let reason = if shadowed.reason == self.claim() {
                        "CLAIM".to_owned()
                    } else {
                        format!("{:?}", shadowed.reason)
                    };
                    format!(
                        "    ShadowingDecl {{ winner: NAME, shadowed: {:?}, reason: {reason}, evidence: &[ROUTER] }},\n",
                        shadowed.op
                    )
                })
                .collect::<String>(),
        );
        out
    }
}

/// Gives each extension route a presigned ruling names its evidence, so its module renders
/// `admin::presigned_floor` (ADR-0024 (f), rustfs/gateway#1576). A ruling that names no planned
/// extension route, or that names one twice, or that cites no `https://` evidence, is refused.
pub(super) fn admit_presigned(extended: &mut [Extended], rulings: &[(&str, &str)]) -> Result<(), String> {
    for (name, evidence) in rulings {
        if !evidence.starts_with("https://") {
            return Err(format!("the presigned ruling for {name} cites no https:// evidence"));
        }
        let route = extended
            .iter_mut()
            .find(|route| route.name == *name)
            .ok_or_else(|| format!("the presigned ruling for {name} names no extension route"))?;
        if route.claimer == Claimer::MetadataRoute {
            return Err(format!(
                "the presigned ruling for {name} names a route that is on the standard listing floor (ADR-0050)"
            ));
        }
        if route.presigned.replace((*evidence).to_owned()).is_some() {
            return Err(format!("the extension route {name} has two presigned rulings"));
        }
    }
    Ok(())
}

/// Gives each extension route a version ruling names the action a request naming one object
/// version is asked instead (rustfs/gateway#1576). A ruling that names no planned extension route,
/// names one twice, names an action not spelled `s3:Action`, or names a route that addresses no
/// object, is refused.
pub(super) fn admit_versioned(extended: &mut [Extended], rulings: &[(&str, &str)]) -> Result<(), String> {
    for (name, action) in rulings {
        if !is_action(action) || !action.starts_with("s3:") {
            return Err(format!("the version ruling for {name} names {action:?}, not an `s3:Action`"));
        }
        let route = extended
            .iter_mut()
            .find(|route| route.name == *name)
            .ok_or_else(|| format!("the version ruling for {name} names no extension route"))?;
        if route.target != TargetKind::Object {
            return Err(format!("the version ruling for {name} names a route that addresses no object"));
        }
        if route.version_action.replace((*action).to_owned()).is_some() {
            return Err(format!("the extension route {name} has two version rulings"));
        }
    }
    Ok(())
}

/// Every overlap the extension rows owe, written into each winner: every standard row of the same
/// method and target a request can satisfy together with the row (read from core's generated
/// table), and every later extension row of the same cell, in RustFS's order. An extension row
/// behind a standard row of its cell is refused: RustFS's router is asked first.
pub(super) fn shadowing(extended: &mut [Extended]) -> Result<(), String> {
    let entries = generated_entries().map_err(|error| format!("the generated route table cannot be read: {error}"))?;
    for index in 0..extended.len() {
        let mut standard: Vec<(u16, &str)> = entries
            .iter()
            .filter(|entry| extended[index].overlaps_standard(entry.selector.predicates()))
            .map(|entry| (entry.precedence, entry.op_name))
            .collect();
        standard.sort_unstable();
        let claim = extended[index].claim();
        for (precedence, op) in standard {
            if precedence <= extended[index].precedence {
                return Err(format!(
                    "{}: its row at {} is behind the standard row {op} at {precedence}; an extension row is ahead of every \
                     standard row of its method and target",
                    extended[index].operation, extended[index].precedence
                ));
            }
            extended[index].shadows.push(Shadowed {
                op: op.to_owned(),
                reason: claim.clone(),
            });
        }
        for later in index + 1..extended.len() {
            if extended[index].overlaps_extension(&extended[later]) {
                let reason = extended[index].order_reason(&extended[later]);
                let op = extended[later].operation.clone();
                extended[index].shadows.push(Shadowed { op, reason });
            }
        }
    }
    Ok(())
}
