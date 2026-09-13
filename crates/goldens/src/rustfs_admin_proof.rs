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

//! RustFS admin routes as gateway extension operations: the P10-01 proof (rustfs/backlog#1744), on
//! ADR-0024's path-prefix claims.
//!
//! Responsible for: four representative RustFS admin routes registered as `rustfs:` extension
//! operations through the ordinary dialect mechanism, and a real assembled service to drive them:
//!
//! - [`ServerInfo`], `GET /rustfs/admin/v3/info` and its `/minio/admin` alias: a plain JSON read
//!   under `admin:ServerInfo`.
//! - [`AddServiceAccount`], `PUT /rustfs/admin/v3/add-service-account` and its `/minio/admin` alias,
//!   where RustFS seals both bodies with the caller's secret key, under `admin:CreateServiceAccount`.
//!   The one operation here that opts in to the caller's secret.
//! - [`GetTier`], `GET /rustfs/admin/v3/tier/{tier}` and its alias: a templated read under
//!   `admin:ListTier`, whose handler reads the tier from the typed path parameters.
//! - [`ReplicationMetricsV2`], `GET /{bucket}?replication-metrics=2`: an S3-shaped read the RustFS
//!   admin router claims by query value, under `s3:GetReplicationConfiguration` on the bucket.
//!
//! The first three are claimed rows inside the dialect's two path-prefix claims, `/rustfs/admin` and
//! `/minio/admin`. The fourth is an S3-table row. The service is the facade's own: the SigV4
//! authenticator, a recording authorizer, and a backend that records what each handler was handed.
//! NOT responsible for: what RustFS does behind these handlers; the madmin sealing format (the seal
//! here is a keyed stand-in, because the claim under test is who holds the key, not the cipher);
//! production wiring (this module exists only under `cfg(test)`); or any other route.
//! Upstream: `rustfs-gateway-core`'s dialect mechanism, `rustfs-gateway`'s assembly, the request
//! signer of `operation_diff::context`, and the recorded inventory the actions are bound to.
//! Downstream: the ring-2 admin migration of rustfs/backlog#1744.
//!
//! # Why only the S3-shaped row declares overlaps
//!
//! A claimed row cannot overlap an S3 row: the router asks the claim first, and a request inside
//! `/rustfs/admin` or `/minio/admin` is answered by a claimed row or by nothing. RustFS's own
//! router behaves the same way: it takes the whole admin prefix ahead of its S3 service. The 21
//! declarations the #778 slice owed for its two path-literal rows are therefore gone.
//! `ReplicationMetricsV2` is a different case. It is an S3-shaped request by design, and every overlap
//! its placement creates, such as `?acl&replication-metrics=2`, is a real routing decision that
//! stays declared: 34 of them, one per standard `GET` bucket row.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::Method;
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, Credentials, Decision, ErrorCode, Handler, HandlerContext, HandlerError, HandlerResult,
    InputAuthzRequest, InputDecisions, Req, RequestContext, RequestContextView, Resp, S3Service, ServiceBuilder,
    SigV4Authenticator, StaticCredentials, dto,
};
use rustfs_gateway_core::codec::{
    CodecError, EncodedResponse, MetaView, OperationCodec, RequestBody, RequestBodyMode, ResponseBody,
};
use rustfs_gateway_core::dialect::{ClaimedRoute, ClaimedRow, Dialect, DialectError, DialectOverlay, DialectRoute, OverlayRow};
use rustfs_gateway_core::op::{AuthRequirement, Operation, ResourceShape};
use rustfs_gateway_core::registry::{HandlerDeadlineClass, OperationSpec};
use rustfs_gateway_core::route::{PathClaim, Predicate, ShadowingDecl, TargetKind};
use rustfs_gateway_core::{DerivedResourceError, NoDerived};
use rustfs_gateway_sig::{OperationFloor, RegionSet, SecurityFloor, SigService};
use rustfs_gateway_types::BucketName;

use crate::operation_diff::s3s_f3e17541::context::{ACCESS_KEY, REGIONS, SECRET_KEY};

mod seal;

pub(crate) use self::seal::{open, same_bytes, seal};

/// The RustFS router whose `is_match` claims the admin prefixes and the extension queries before
/// its S3 service, at the commit the inventory was generated from.
const RUSTFS_ROUTER: &str =
    "https://github.com/rustfs/rustfs/blob/736e4fb8e8e5d527c25e4e56f352536b311b6daf/rustfs/src/admin/router.rs";
/// The migration issue.
const ISSUE: &str = "https://github.com/rustfs/backlog/issues/1744";
const ROUTER_EVIDENCE: &[&str] = &[RUSTFS_ROUTER];

const RUSTFS_PREFIX_CLAIM: &str = "RustFS's admin router answers every path-style request under this prefix before its S3 \
                                   service, whatever the query.";
const MINIO_PREFIX_CLAIM: &str = "RustFS serves its admin API a second time under the MinIO prefix, and seals admin \
                                  bodies with the caller's secret only there.";
const EXTENSION_CLAIM: &str = "RustFS's admin router answers a bucket GET carrying replication-metrics=2 before its S3 \
                               service, whatever else the query carries.";

/// The two prefixes the dialect takes away from S3 routing.
pub(crate) const CLAIMS: &[PathClaim] = &[
    PathClaim {
        prefix: "/rustfs/admin",
        reason: RUSTFS_PREFIX_CLAIM,
        evidence: ROUTER_EVIDENCE,
    },
    PathClaim {
        prefix: "/minio/admin",
        reason: MINIO_PREFIX_CLAIM,
        evidence: ROUTER_EVIDENCE,
    },
];

/// `rustfs:ServerInfo`.
pub(crate) const SERVER_INFO: &str = "rustfs:ServerInfo";
/// Its path, which the inventory records.
pub(crate) const SERVER_INFO_PATH: &str = "/rustfs/admin/v3/info";
/// Its MinIO alias.
pub(crate) const SERVER_INFO_ALIAS: &str = "/minio/admin/v3/info";
/// Its action.
pub(crate) const SERVER_INFO_ACTION: &str = "admin:ServerInfo";
const SERVER_INFO_PRECEDENCE: u16 = 10;

/// `rustfs:AddServiceAccount`.
pub(crate) const ADD_SERVICE_ACCOUNT: &str = "rustfs:AddServiceAccount";
/// The path the inventory records.
pub(crate) const ADD_SERVICE_ACCOUNT_PATH: &str = "/rustfs/admin/v3/add-service-account";
/// The alias where RustFS seals the bodies with the caller's secret.
pub(crate) const ADD_SERVICE_ACCOUNT_ALIAS: &str = "/minio/admin/v3/add-service-account";
/// Its action.
pub(crate) const ADD_SERVICE_ACCOUNT_ACTION: &str = "admin:CreateServiceAccount";
const ADD_SERVICE_ACCOUNT_PRECEDENCE: u16 = 11;

/// `rustfs:GetTier`.
pub(crate) const GET_TIER: &str = "rustfs:GetTier";
/// The template the inventory records.
pub(crate) const GET_TIER_TEMPLATE: &str = "/rustfs/admin/v3/tier/{tier}";
/// Its MinIO alias.
pub(crate) const GET_TIER_ALIAS: &str = "/minio/admin/v3/tier/{tier}";
/// Its action.
pub(crate) const GET_TIER_ACTION: &str = "admin:ListTier";
const GET_TIER_PRECEDENCE: u16 = 12;

/// `rustfs:ReplicationMetricsV2`.
pub(crate) const REPLICATION_METRICS_V2: &str = "rustfs:ReplicationMetricsV2";
/// The discriminating query key and value.
pub(crate) const REPLICATION_METRICS_QUERY: (&str, &str) = ("replication-metrics", "2");
/// Its action.
pub(crate) const REPLICATION_METRICS_ACTION: &str = "s3:GetReplicationConfiguration";
/// In front of every bucket GET (200 and up), behind the service rows (90, 100) it cannot overlap.
const REPLICATION_METRICS_PRECEDENCE: u16 = 195;

// ── what the handlers answer ──────────────────────────────────────────────────────────────────

/// An admin answer: the bytes and their content type.
pub(crate) struct AdminBody {
    content_type: &'static str,
    bytes: Vec<u8>,
}

fn encode_admin(output: AdminBody, status: u16) -> Result<EncodedResponse, CodecError> {
    let mut encoded = EncodedResponse::of(status);
    encoded.set_header("content-type", output.content_type);
    encoded.body = ResponseBody::Complete(output.bytes);
    Ok(encoded)
}

fn json(value: &serde_json::Value) -> AdminBody {
    AdminBody {
        content_type: "application/json",
        bytes: value.to_string().into_bytes(),
    }
}

// ── the operations ────────────────────────────────────────────────────────────────────────────

// The whole module is test-only through `lib.rs`; the operations also sit inside their own
// `#[cfg(test)]` item because `check_op_file_shape.sh` admits an `impl Operation` outside an ops
// tree only as an in-file test fixture, and these are fixtures.
#[cfg(test)]
mod operations {
    use super::*;

    /// `GET /rustfs/admin/v3/info`.
    pub(crate) struct ServerInfo;

    static SERVER_INFO_SPEC: OperationSpec = OperationSpec::builder(SERVER_INFO, 200, None)
        .handler_deadline_class(HandlerDeadlineClass::Standard)
        .required_params(&[])
        .auth(AuthRequirement::new(SERVER_INFO_ACTION, ResourceShape::Service))
        .build();

    /// Privileged and header-signed: a third-party operation is never anonymous by default.
    static SERVER_INFO_FLOOR: OperationFloor = OperationFloor::custom(SERVER_INFO, SigService::S3);

    impl Operation for ServerInfo {
        const NAME: &'static str = SERVER_INFO;

        type Input = ();
        type Output = AdminBody;
        type DerivedResources = NoDerived;

        fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, DerivedResourceError> {
            Ok(NoDerived)
        }

        fn seal_derived_input(_input: &mut Self::Input) {}

        fn spec() -> &'static OperationSpec {
            &SERVER_INFO_SPEC
        }

        fn floor() -> &'static OperationFloor {
            &SERVER_INFO_FLOOR
        }
    }

    impl OperationCodec for ServerInfo {
        const REQUEST_BODY: RequestBodyMode = RequestBodyMode::None;

        fn decode(_request: &MetaView<'_>, _body: RequestBody) -> Result<Self::Input, CodecError> {
            Ok(())
        }

        fn encode(output: Self::Output, _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
            encode_admin(output, status)
        }
    }

    /// `PUT /minio/admin/v3/add-service-account`, whose body is sealed with the caller's secret.
    pub(crate) struct AddServiceAccount;

    /// The one spec here that opts in to the caller's secret (ADR-0024).
    static ADD_SERVICE_ACCOUNT_SPEC: OperationSpec = OperationSpec::builder(ADD_SERVICE_ACCOUNT, 200, None)
        .handler_deadline_class(HandlerDeadlineClass::Standard)
        .required_params(&[])
        .auth(AuthRequirement::new(ADD_SERVICE_ACCOUNT_ACTION, ResourceShape::Service))
        .hand_caller_secret_to_handler()
        .build();

    static ADD_SERVICE_ACCOUNT_FLOOR: OperationFloor = OperationFloor::custom(ADD_SERVICE_ACCOUNT, SigService::S3);

    impl Operation for AddServiceAccount {
        const NAME: &'static str = ADD_SERVICE_ACCOUNT;

        /// The sealed body, exactly as it arrived.
        type Input = Bytes;
        type Output = AdminBody;
        type DerivedResources = NoDerived;

        fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, DerivedResourceError> {
            Ok(NoDerived)
        }

        fn seal_derived_input(_input: &mut Self::Input) {}

        fn spec() -> &'static OperationSpec {
            &ADD_SERVICE_ACCOUNT_SPEC
        }

        fn floor() -> &'static OperationFloor {
            &ADD_SERVICE_ACCOUNT_FLOOR
        }
    }

    impl OperationCodec for AddServiceAccount {
        fn decode(_request: &MetaView<'_>, body: RequestBody) -> Result<Self::Input, CodecError> {
            body.into_buffered()
        }

        fn encode(output: Self::Output, _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
            encode_admin(output, status)
        }
    }

    /// `GET /rustfs/admin/v3/tier/{tier}`.
    pub(crate) struct GetTier;

    static GET_TIER_SPEC: OperationSpec = OperationSpec::builder(GET_TIER, 200, None)
        .handler_deadline_class(HandlerDeadlineClass::Standard)
        .required_params(&[])
        .auth(AuthRequirement::new(GET_TIER_ACTION, ResourceShape::Service))
        .build();

    static GET_TIER_FLOOR: OperationFloor = OperationFloor::custom(GET_TIER, SigService::S3);

    impl Operation for GetTier {
        const NAME: &'static str = GET_TIER;

        type Input = ();
        type Output = AdminBody;
        type DerivedResources = NoDerived;

        fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, DerivedResourceError> {
            Ok(NoDerived)
        }

        fn seal_derived_input(_input: &mut Self::Input) {}

        fn spec() -> &'static OperationSpec {
            &GET_TIER_SPEC
        }

        fn floor() -> &'static OperationFloor {
            &GET_TIER_FLOOR
        }
    }

    impl OperationCodec for GetTier {
        const REQUEST_BODY: RequestBodyMode = RequestBodyMode::None;

        fn decode(_request: &MetaView<'_>, _body: RequestBody) -> Result<Self::Input, CodecError> {
            Ok(())
        }

        fn encode(output: Self::Output, _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
            encode_admin(output, status)
        }
    }

    /// `GET /{bucket}?replication-metrics=2`.
    pub(crate) struct ReplicationMetricsV2;

    static REPLICATION_METRICS_SPEC: OperationSpec = OperationSpec::builder(REPLICATION_METRICS_V2, 200, None)
        .handler_deadline_class(HandlerDeadlineClass::Standard)
        .required_params(&[])
        .auth(AuthRequirement::new(REPLICATION_METRICS_ACTION, ResourceShape::Bucket))
        .build();

    static REPLICATION_METRICS_FLOOR: OperationFloor = OperationFloor::custom(REPLICATION_METRICS_V2, SigService::S3);

    impl Operation for ReplicationMetricsV2 {
        const NAME: &'static str = REPLICATION_METRICS_V2;

        type Input = BucketName;
        type Output = AdminBody;
        type DerivedResources = NoDerived;

        fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, DerivedResourceError> {
            Ok(NoDerived)
        }

        fn seal_derived_input(_input: &mut Self::Input) {}

        fn spec() -> &'static OperationSpec {
            &REPLICATION_METRICS_SPEC
        }

        fn floor() -> &'static OperationFloor {
            &REPLICATION_METRICS_FLOOR
        }
    }

    impl OperationCodec for ReplicationMetricsV2 {
        const REQUEST_BODY: RequestBodyMode = RequestBodyMode::None;

        fn decode(request: &MetaView<'_>, _body: RequestBody) -> Result<Self::Input, CodecError> {
            request.require_bucket()
        }

        fn encode(output: Self::Output, _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
            encode_admin(output, status)
        }
    }
}

pub(crate) use operations::{AddServiceAccount, GetTier, ReplicationMetricsV2, ServerInfo};

// ── the rows ──────────────────────────────────────────────────────────────────────────────────

static GET: &[Predicate] = &[Predicate::Method(Method::GET)];
static PUT: &[Predicate] = &[Predicate::Method(Method::PUT)];

/// The canonical row, then the MinIO alias.
pub(crate) static SERVER_INFO_ROWS: &[ClaimedRow] = &[
    ClaimedRow {
        template: SERVER_INFO_PATH,
        selector: GET,
    },
    ClaimedRow {
        template: SERVER_INFO_ALIAS,
        selector: GET,
    },
];

/// The canonical row, then the MinIO alias where the bodies are sealed.
pub(crate) static ADD_SERVICE_ACCOUNT_ROWS: &[ClaimedRow] = &[
    ClaimedRow {
        template: ADD_SERVICE_ACCOUNT_PATH,
        selector: PUT,
    },
    ClaimedRow {
        template: ADD_SERVICE_ACCOUNT_ALIAS,
        selector: PUT,
    },
];

/// The canonical template, then the MinIO alias.
pub(crate) static GET_TIER_ROWS: &[ClaimedRow] = &[
    ClaimedRow {
        template: GET_TIER_TEMPLATE,
        selector: GET,
    },
    ClaimedRow {
        template: GET_TIER_ALIAS,
        selector: GET,
    },
];

static REPLICATION_METRICS_SELECTOR: &[Predicate] = &[
    Predicate::Method(Method::GET),
    Predicate::Target(TargetKind::Bucket),
    Predicate::QueryEquals(REPLICATION_METRICS_QUERY.0, REPLICATION_METRICS_QUERY.1),
];

const fn ahead_of(shadowed: &'static str) -> ShadowingDecl {
    ShadowingDecl {
        winner: REPLICATION_METRICS_V2,
        shadowed,
        reason: EXTENSION_CLAIM,
        evidence: ROUTER_EVIDENCE,
    }
}

/// Every standard `GET` row on a bucket: the S3-shaped row's real routing decisions.
pub(crate) static REPLICATION_METRICS_SHADOWS: &[ShadowingDecl] = &[
    ahead_of("GetBucketAccelerateConfiguration"),
    ahead_of("GetBucketLogging"),
    ahead_of("GetBucketNotificationConfiguration"),
    ahead_of("GetBucketPolicy"),
    ahead_of("GetBucketPolicyStatus"),
    ahead_of("GetPublicAccessBlock"),
    ahead_of("GetBucketRequestPayment"),
    ahead_of("GetBucketVersioning"),
    ahead_of("GetBucketWebsite"),
    ahead_of("GetBucketAcl"),
    ahead_of("GetBucketOwnershipControls"),
    ahead_of("GetBucketIntelligentTieringConfiguration"),
    ahead_of("ListBucketIntelligentTieringConfigurations"),
    ahead_of("GetBucketAnalyticsConfiguration"),
    ahead_of("ListBucketAnalyticsConfigurations"),
    ahead_of("GetBucketAbac"),
    ahead_of("GetBucketInventoryConfiguration"),
    ahead_of("ListBucketInventoryConfigurations"),
    ahead_of("CreateSession"),
    ahead_of("GetBucketMetadataConfiguration"),
    ahead_of("GetBucketMetadataTableConfiguration"),
    ahead_of("GetBucketMetricsConfiguration"),
    ahead_of("ListBucketMetricsConfigurations"),
    ahead_of("GetBucketLocation"),
    ahead_of("GetBucketCors"),
    ahead_of("GetBucketTagging"),
    ahead_of("GetBucketLifecycleConfiguration"),
    ahead_of("GetBucketEncryption"),
    ahead_of("GetBucketReplication"),
    ahead_of("GetObjectLockConfiguration"),
    ahead_of("ListMultipartUploads"),
    ahead_of("ListObjectsV2"),
    ahead_of("ListObjectVersions"),
    ahead_of("ListObjects"),
];

/// The reviewed record: the two claims and the four operations, alias rows included.
static OVERLAY: DialectOverlay = DialectOverlay {
    name: "rustfs-admin-proof",
    vendor: "rustfs",
    claims: CLAIMS,
    operations: &[
        OverlayRow {
            name: SERVER_INFO,
            precedence: SERVER_INFO_PRECEDENCE,
            selector: "PathTemplate(\"/rustfs/admin/v3/info\") ∧ Method(GET) ∨ \
                       PathTemplate(\"/minio/admin/v3/info\") ∧ Method(GET)",
            action: SERVER_INFO_ACTION,
            resource: ResourceShape::Service,
            success_status: 200,
            anonymous: false,
            evidence: &[RUSTFS_ROUTER, ISSUE],
        },
        OverlayRow {
            name: ADD_SERVICE_ACCOUNT,
            precedence: ADD_SERVICE_ACCOUNT_PRECEDENCE,
            selector: "PathTemplate(\"/rustfs/admin/v3/add-service-account\") ∧ Method(PUT) ∨ \
                       PathTemplate(\"/minio/admin/v3/add-service-account\") ∧ Method(PUT)",
            action: ADD_SERVICE_ACCOUNT_ACTION,
            resource: ResourceShape::Service,
            success_status: 200,
            anonymous: false,
            evidence: &[RUSTFS_ROUTER, ISSUE],
        },
        OverlayRow {
            name: GET_TIER,
            precedence: GET_TIER_PRECEDENCE,
            selector: "PathTemplate(\"/rustfs/admin/v3/tier/{tier}\") ∧ Method(GET) ∨ \
                       PathTemplate(\"/minio/admin/v3/tier/{tier}\") ∧ Method(GET)",
            action: GET_TIER_ACTION,
            resource: ResourceShape::Service,
            success_status: 200,
            anonymous: false,
            evidence: &[RUSTFS_ROUTER, ISSUE],
        },
        OverlayRow {
            name: REPLICATION_METRICS_V2,
            precedence: REPLICATION_METRICS_PRECEDENCE,
            selector: "Method(GET) ∧ Target(Bucket) ∧ QueryEquals(\"replication-metrics\", \"2\")",
            action: REPLICATION_METRICS_ACTION,
            resource: ResourceShape::Bucket,
            success_status: 200,
            anonymous: false,
            evidence: &[RUSTFS_ROUTER, ISSUE],
        },
    ],
};

/// The four operations, with `replication_metrics` as the S3-shaped row's declarations; tests
/// swap them to prove each is needed.
pub(crate) fn admin_dialect_with(replication_metrics: &'static [ShadowingDecl]) -> Result<Dialect, Vec<DialectError>> {
    Dialect::assemble(&OVERLAY)
        .declare_claimed::<ServerInfo>(ClaimedRoute {
            precedence: SERVER_INFO_PRECEDENCE,
            rows: SERVER_INFO_ROWS,
            shadows: &[],
        })
        .declare_claimed::<AddServiceAccount>(ClaimedRoute {
            precedence: ADD_SERVICE_ACCOUNT_PRECEDENCE,
            rows: ADD_SERVICE_ACCOUNT_ROWS,
            shadows: &[],
        })
        .declare_claimed::<GetTier>(ClaimedRoute {
            precedence: GET_TIER_PRECEDENCE,
            rows: GET_TIER_ROWS,
            shadows: &[],
        })
        .declare::<ReplicationMetricsV2>(DialectRoute {
            precedence: REPLICATION_METRICS_PRECEDENCE,
            selector: REPLICATION_METRICS_SELECTOR,
            path_shape: "/{Bucket}",
            shadows: replication_metrics,
        })
        .build()
}

/// The four operations with the reviewed declarations.
pub(crate) fn admin_dialect() -> Dialect {
    admin_dialect_with(REPLICATION_METRICS_SHADOWS).expect("the record and the declarations state the same facts")
}

// ── the authorizer and the backend ────────────────────────────────────────────────────────────

/// One question the authorizer was asked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthzCall {
    /// `route`, `input` or `resource`.
    pub(crate) stage: &'static str,
    pub(crate) operation: String,
    pub(crate) action: String,
    pub(crate) caller: Option<String>,
    pub(crate) bucket: Option<String>,
    pub(crate) key: Option<String>,
}

type Policy = Box<dyn Fn(&AuthzRequest<'_>) -> bool + Send + Sync>;

/// Records every question and answers it with `policy`.
struct RecordingAuthorizer {
    policy: Policy,
    calls: Arc<Mutex<Vec<AuthzCall>>>,
}

impl RecordingAuthorizer {
    fn decide(&self, stage: &'static str, request: &AuthzRequest<'_>) -> Decision {
        self.calls.lock().expect("uncontended").push(AuthzCall {
            stage,
            operation: request.operation.to_owned(),
            action: request.action.to_owned(),
            caller: request.identity.map(|identity| identity.access_key_id().to_owned()),
            bucket: request.bucket.map(|bucket| bucket.as_str().to_owned()),
            key: request.key.map(|key| key.as_str().to_owned()),
        });
        if (self.policy)(request) {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }
}

impl Authorizer for RecordingAuthorizer {
    fn authorize_route<'a>(&'a self, _context: &'a RequestContext<'a>, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        let decision = self.decide("route", request);
        Box::pin(async move { decision })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let stage = self.decide("input", request.route());
        let decisions = request.decide_all(stage, |resource| self.decide("resource", resource));
        Box::pin(async move { decisions })
    }
}

/// What one handler was handed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Seen {
    pub(crate) operation: &'static str,
    pub(crate) caller: Option<String>,
    pub(crate) holds_secret: bool,
    pub(crate) secret_is_the_callers: bool,
    pub(crate) context_debug_shows_secret: bool,
    pub(crate) raw_path: String,
    pub(crate) bucket: Option<String>,
    pub(crate) key: Option<String>,
    pub(crate) params: Vec<(String, String)>,
}

/// A backend that records what each handler was handed, and every account it created.
#[derive(Default)]
pub(crate) struct Backend {
    seen: Mutex<Vec<Seen>>,
    created: Mutex<Vec<String>>,
}

impl Backend {
    pub(crate) fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("uncontended").clone()
    }

    pub(crate) fn created(&self) -> Vec<String> {
        self.created.lock().expect("uncontended").clone()
    }

    fn see(&self, context: &RequestContextView) {
        let principal = context.principal();
        let secret = principal.and_then(|principal| principal.secret_key_from_authenticator_lookup());
        self.seen.lock().expect("uncontended").push(Seen {
            operation: context.operation(),
            caller: principal.map(|principal| principal.access_key_id().to_owned()),
            holds_secret: secret.is_some(),
            secret_is_the_callers: secret.is_some_and(|secret| same_bytes(secret.expose_secret(), SECRET_KEY.as_bytes())),
            context_debug_shows_secret: format!("{context:?}").contains(SECRET_KEY),
            raw_path: context.raw_path().to_owned(),
            bucket: context.bucket().map(|bucket| bucket.as_str().to_owned()),
            key: context.key().map(|key| key.as_str().to_owned()),
            params: context
                .path_params()
                .iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
        });
    }

    fn server_info(&self, request: &Req<ServerInfo>) -> HandlerResult<ServerInfo> {
        self.see(request.context());
        Ok(Resp::new(json(&serde_json::json!({"mode": "online", "servers": 1}))))
    }

    fn add_service_account(&self, request: &Req<AddServiceAccount>) -> HandlerResult<AddServiceAccount> {
        self.see(request.context());
        // Fail closed: without the caller's secret the body cannot be opened, and nothing may be
        // created from a body nobody could read.
        let secret = request
            .context()
            .principal()
            .and_then(|principal| principal.secret_key_from_authenticator_lookup())
            .ok_or_else(|| HandlerError::internal_error("the caller's secret was not handed to this handler"))?;
        let plain = open(secret.expose_secret(), request.input()).ok_or_else(|| {
            HandlerError::new(ErrorCode::INVALID_REQUEST, "the admin payload does not open under the caller's key")
        })?;
        let asked: serde_json::Value = serde_json::from_slice(&plain)
            .map_err(|_| HandlerError::new(ErrorCode::INVALID_REQUEST, "the admin payload is not JSON"))?;
        let access_key = asked["accessKey"]
            .as_str()
            .ok_or_else(|| HandlerError::new(ErrorCode::INVALID_REQUEST, "the admin payload names no access key"))?
            .to_owned();
        self.created.lock().expect("uncontended").push(access_key.clone());
        let answer = serde_json::json!({"credentials": {"accessKey": access_key}}).to_string();
        Ok(Resp::new(AdminBody {
            content_type: "application/octet-stream",
            bytes: seal(secret.expose_secret(), answer.as_bytes()),
        }))
    }

    fn get_tier(&self, request: &Req<GetTier>) -> HandlerResult<GetTier> {
        self.see(request.context());
        // The typed value the template extracted, decoded once; never a second parse of the path.
        let tier: String = request
            .context()
            .path_params()
            .parse("tier")
            .map_err(|_| HandlerError::internal_error("the template bound no tier"))?;
        Ok(Resp::new(json(&serde_json::json!({"tier": tier, "status": "online"}))))
    }

    fn replication_metrics(&self, request: &Req<ReplicationMetricsV2>) -> HandlerResult<ReplicationMetricsV2> {
        self.see(request.context());
        Ok(Resp::new(json(&serde_json::json!({"bucket": request.input().as_str(), "version": 2}))))
    }
}

macro_rules! handler {
    ($operation:ty, $method:ident) => {
        impl Handler<$operation> for Backend {
            async fn call(&self, request: Req<$operation>) -> HandlerResult<$operation> {
                self.$method(&request)
            }

            async fn call_with_context(&self, request: Req<$operation>, _context: HandlerContext) -> HandlerResult<$operation> {
                self.$method(&request)
            }
        }
    };
}

handler!(ServerInfo, server_info);
handler!(AddServiceAccount, add_service_account);
handler!(GetTier, get_tier);
handler!(ReplicationMetricsV2, replication_metrics);

impl Backend {
    fn get_object(&self, request: &Req<dto::GetObject>) -> HandlerResult<dto::GetObject> {
        self.see(request.context());
        Ok(Resp::new(dto::GetObjectOutput::default()))
    }

    fn list_objects(&self, request: &Req<dto::ListObjects>) -> HandlerResult<dto::ListObjects> {
        self.see(request.context());
        Ok(Resp::new(dto::ListObjectsOutput::default()))
    }
}

handler!(dto::GetObject, get_object);
handler!(dto::ListObjects, list_objects);

// ── the assembled service ─────────────────────────────────────────────────────────────────────

/// How one service is assembled.
#[derive(Clone, Copy)]
pub(crate) struct Options {
    /// Whether the authenticator hands the caller's secret over. The assembly keeps ADR-0024's
    /// default scope, so an operation receives it only when its spec opted in.
    pub(crate) secret_hand_off: bool,
    /// Whether anonymous admission is delegated to the authorizer (ADR-0021).
    pub(crate) delegate_anonymous: bool,
}

/// A service with the admin dialect and two S3 neighbours, and what it records.
pub(crate) struct Assembled {
    pub(crate) service: S3Service,
    pub(crate) backend: Arc<Backend>,
    pub(crate) calls: Arc<Mutex<Vec<AuthzCall>>>,
}

impl Assembled {
    pub(crate) fn calls(&self) -> Vec<AuthzCall> {
        self.calls.lock().expect("uncontended").clone()
    }
}

/// The facade's own SigV4 authenticator over the shared credential, an authorizer that answers
/// with `policy`, the admin dialect, and `GetObject` / `ListObjects` beside it.
pub(crate) fn assemble(options: Options, policy: impl Fn(&AuthzRequest<'_>) -> bool + Send + Sync + 'static) -> Assembled {
    let credentials = Credentials::new(ACCESS_KEY, SECRET_KEY.as_bytes()).expect("a fixture credential");
    let regions = RegionSet::new(REGIONS).expect("fixture regions");
    let mut authenticator = SigV4Authenticator::new(Arc::new(StaticCredentials::new().with(credentials)), regions);
    if options.secret_hand_off {
        authenticator = authenticator.hand_caller_secret_to_handlers();
    }
    let calls = Arc::new(Mutex::new(Vec::new()));
    let backend = Arc::new(Backend::default());
    let mut builder = ServiceBuilder::new()
        .authenticator(authenticator)
        .authorizer(RecordingAuthorizer {
            policy: Box::new(policy),
            calls: Arc::clone(&calls),
        })
        .dialect(&admin_dialect())
        .register::<ServerInfo, _>(Arc::clone(&backend))
        .register::<AddServiceAccount, _>(Arc::clone(&backend))
        .register::<GetTier, _>(Arc::clone(&backend))
        .register::<ReplicationMetricsV2, _>(Arc::clone(&backend))
        .register::<dto::GetObject, _>(Arc::clone(&backend))
        .register::<dto::ListObjects, _>(Arc::clone(&backend));
    if options.delegate_anonymous {
        builder =
            builder.security_floor(SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report());
    }
    Assembled {
        service: builder.build().expect("a complete assembly"),
        backend,
        calls,
    }
}

#[cfg(test)]
mod tests;
