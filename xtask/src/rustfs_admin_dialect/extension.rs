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
//! routes outside its path table (rustfs/backlog#2753).
//!
//! Responsible for: reading the inventory's `extension_routes`, checking each against its ruling
//! (`super::rulings::EXTENSIONS`), deriving its selector, resource shape and precedence, computing
//! the overlaps its row owes against the S3 table and against the earlier extension rows, and
//! rendering its operation module.
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

/// The custom-auth class every extension route records: a signature first, then the handler's
/// own check of the recorded action.
pub(super) const AUTH_DETAIL: &str = "SignatureRequiredThenHandlerCheck";
/// The first extension row's precedence: ahead of every S3 row of any method and target (the
/// earliest standard row sits at 90), in the band the route table reserves for rows that are
/// asked before the ordinary shapes.
pub(super) const FIRST_PRECEDENCE: u16 = 80;

/// One extension route as the inventory records it.
#[derive(Clone, Deserialize)]
pub(super) struct ExtensionRoute {
    pub(super) name: String,
    pub(super) method: String,
    pub(super) target: String,
    pub(super) query_discriminator: QueryDiscriminator,
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
    pub(super) action: String,
    pub(super) precedence: u16,
    pub(super) shadows: Vec<Shadowed>,
    router_url: String,
}

impl Extended {
    /// The extension route `route` as the operation `type_name`, which the inventory must still
    /// record as a signed custom-auth route of a known method and target, discriminated by one
    /// unreserved key under a rule the row can spell, and authorised by one IAM action.
    pub(super) fn of(route: &ExtensionRoute, type_name: &str, at: &str, commit: &str, precedence: u16) -> Result<Self, String> {
        if route.auth_mode != "custom" || route.auth_detail != AUTH_DETAIL {
            return Err(format!(
                "{at}: ruled as a signed custom-auth extension route, but the inventory now records {:?} {:?}",
                route.auth_mode, route.auth_detail
            ));
        }
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
            action: action.to_owned(),
            precedence,
            shadows: Vec::new(),
            router_url: format!("https://github.com/rustfs/rustfs/blob/{commit}/{}", super::RUSTFS_ROUTER),
        })
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
                Predicate::QueryAbsent(key) if *key == self.key => return false,
                Predicate::QueryEquals(key, value)
                    if *key == self.key && !self.discriminator.coexists(&Discriminator::Equals((*value).to_owned())) =>
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
            && (self.key != other.key || self.discriminator.coexists(&other.discriminator))
    }

    /// The reason every standard-row declaration carries.
    fn claim(&self) -> String {
        format!(
            "RustFS's admin router claims a {} of {} {} before its S3 service, whatever else the query names.",
            self.method,
            self.target_word(),
            self.discriminator.phrase(&self.key)
        )
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
        let request = format!(
            "{method} {}?{key}{}",
            self.path_shape(),
            match discriminator {
                Discriminator::Present => "=…".to_owned(),
                Discriminator::Equals(value) if value.is_empty() => String::new(),
                Discriminator::Equals(value) => format!("={value}"),
            }
        );
        let selector = format!(
            "Predicate::Method(http::Method::{method}), Predicate::Target(TargetKind::{target:?}), {}",
            discriminator.predicate(key),
            target = self.target
        );
        let rendered = format!("Method({method}) ∧ Target({}) ∧ {}", self.target.as_str(), discriminator.rendered(key));
        let on = match self.target {
            TargetKind::Service => "no bucket".to_owned(),
            TargetKind::Bucket => "the bucket the path names".to_owned(),
            TargetKind::Object => "the object the path names".to_owned(),
        };
        let paragraph = doc_paragraph(&format!(
            "RustFS's admin router claims this S3-shaped request before its S3 service reads anything else, `x-id` \
             included: a `{method}` of {} {}, whatever else the query names. It requires a signature and then has \
             the handler check `{action}`. So the row sits ahead of every standard `{method}` row of its target and \
             declares each of those overlaps, the floor is privileged, the authorizer is asked `{action}` on {on} \
             before the handler runs, and the gateway reads no body and answers what the handler answers. Under \
             legacy RustFS's selection the same discriminator names this operation (`rustfs-gateway-core`'s \
             `legacy_rustfs`), so both selections reach it.",
            self.target_word(),
            discriminator.phrase(key),
        ));
        let _ = write!(
            out,
            r#"//! `{operation}`: `{request}`, RustFS's `{name}` extension route (rustfs/backlog#2753).
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

/// What authorises it, on {on}: the action RustFS's handler checks.
pub const AUTH: AuthRequirement = AuthRequirement::new({action:?}, {resource});

/// RustFS's admin router, whose extension matching this row mirrors.
const ROUTER: &str = {router_url:?};

/// Why this row stands in front of every standard row of its method and target.
const CLAIM: &str = {claim:?};

/// The row: the method, the target, and the one discriminator RustFS's router reads.
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

/// Privileged and header-signed only: never anonymous, never presigned. RustFS answers an unsigned request
/// `403 AccessDenied` here, and no RustFS client is shown to presign an extension route (ADR-0024 (f)).
static FLOOR: OperationFloor = admin::floor(NAME);

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
    action: {action:?},
    resource: {resource},
    success_status: 200,
    anonymous: false,
    evidence: &[ROUTER, record::EXTENSION_ISSUE, record::ISSUE],
}};

/// The inventory row this operation was generated from.
pub const RECORD: ExtensionRouteRecord = ExtensionRouteRecord {{
    operation: NAME,
    name: {name:?},
    method: {method:?},
    target: {target_lower:?},
    query: ({key:?}, {rule:?}),
    action: {action:?},
}};
"#,
            resource = self.resource(),
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
                let reason = format!(
                    "RustFS's admin router tries the `{}` discriminator before the `{}` one, so a request naming both is this \
                     operation.",
                    extended[index].key, extended[later].key
                );
                let op = extended[later].operation.clone();
                extended[index].shadows.push(Shadowed { op, reason });
            }
        }
    }
    Ok(())
}
