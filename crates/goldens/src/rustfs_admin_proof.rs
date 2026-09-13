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

//! RustFS admin routes as gateway extension operations: the P10-01 proof slice
//! (rustfs/backlog#1744).
//!
//! Responsible for: three representative RustFS admin routes registered as `rustfs:` extension
//! operations through the ordinary dialect mechanism, each with every overlap its route row
//! creates declared, and a real assembled service to drive them:
//!
//! - [`ServerInfo`], `GET /rustfs/admin/v3/info`: a plain JSON read under `admin:ServerInfo`.
//! - [`AddServiceAccount`], `PUT /minio/admin/v3/add-service-account`: the MinIO alias, where
//!   RustFS seals both bodies with the caller's secret key, under `admin:CreateServiceAccount`.
//! - [`ReplicationMetricsV2`], `GET /{bucket}?replication-metrics=2`: an S3-shaped read the RustFS
//!   admin router claims by query value, under `s3:GetReplicationConfiguration` on the bucket.
//!
//! The service is the facade's own: the SigV4 authenticator, a recording authorizer, and a backend
//! that records what each handler was handed.
//! NOT responsible for: what RustFS does behind these handlers; the madmin sealing format (the seal
//! here is a keyed stand-in, because the claim under test is who holds the key, not the cipher);
//! production wiring (this module exists only under `cfg(test)`); or any other route.
//! Upstream: `rustfs-gateway-core`'s dialect mechanism, `rustfs-gateway`'s assembly, the request
//! signer of `operation_diff::context`, and the recorded inventory the three actions are bound to.
//! Downstream: the ring-2 admin migration of rustfs/backlog#1744.
//!
//! # Why every overlap is declared
//!
//! The route lattice treats the path and the target as independent dimensions, so a row pinned to
//! a path literal still overlaps every standard row on the same method and target: a client may
//! name `/rustfs/admin/v3/info?tagging`, and both rows accept it. RustFS answers such a request
//! from its admin router, which claims the whole prefix before its S3 service, whatever the query.
//! The faithful rows therefore sit in front of those standard rows and declare each overlap. The
//! count is the finding: under `ShadowingPolicy::EveryOverlap` a path-literal GET admin row owes
//! 10 declarations and a PUT row 11, one per standard row in that method-and-target cell.

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
use rustfs_gateway_core::dialect::{Dialect, DialectError, DialectOverlay, DialectRoute, OverlayRow};
use rustfs_gateway_core::op::{AuthRequirement, Operation, ResourceShape};
use rustfs_gateway_core::registry::{HandlerDeadlineClass, OperationSpec};
use rustfs_gateway_core::route::{Predicate, ShadowingDecl, TargetKind};
use rustfs_gateway_core::{DerivedResourceError, NoDerived};
use rustfs_gateway_sig::{OperationFloor, RegionSet, SecurityFloor, SigService};
use rustfs_gateway_types::BucketName;
use sha2::{Digest, Sha256};

use crate::operation_diff::s3s_f3e17541::context::{ACCESS_KEY, REGIONS, SECRET_KEY};

/// The RustFS router whose `is_match` claims the admin prefixes and the extension queries before
/// its S3 service, at the commit the inventory was generated from.
const RUSTFS_ROUTER: &str =
    "https://github.com/rustfs/rustfs/blob/736e4fb8e8e5d527c25e4e56f352536b311b6daf/rustfs/src/admin/router.rs";
/// The migration issue.
const ISSUE: &str = "https://github.com/rustfs/backlog/issues/1744";
const ROUTER_EVIDENCE: &[&str] = &[RUSTFS_ROUTER];

const ADMIN_PATH_CLAIM: &str = "RustFS's admin router answers every request on this admin path before its S3 service, \
                                whatever the query, so this key is not reachable through S3 on RustFS either.";
const EXTENSION_CLAIM: &str = "RustFS's admin router answers a bucket GET carrying replication-metrics=2 before its S3 \
                               service, whatever else the query carries.";

/// `rustfs:ServerInfo`.
pub(crate) const SERVER_INFO: &str = "rustfs:ServerInfo";
/// Its path, which the inventory records.
pub(crate) const SERVER_INFO_PATH: &str = "/rustfs/admin/v3/info";
/// Its action.
pub(crate) const SERVER_INFO_ACTION: &str = "admin:ServerInfo";
const SERVER_INFO_PRECEDENCE: u16 = 60;

/// `rustfs:AddServiceAccount`.
pub(crate) const ADD_SERVICE_ACCOUNT: &str = "rustfs:AddServiceAccount";
/// The path the inventory records; RustFS serves it at the MinIO alias too.
pub(crate) const ADD_SERVICE_ACCOUNT_PATH: &str = "/rustfs/admin/v3/add-service-account";
/// The alias this slice registers: the one where RustFS seals the bodies with the caller's secret.
pub(crate) const ADD_SERVICE_ACCOUNT_ALIAS: &str = "/minio/admin/v3/add-service-account";
/// Its action.
pub(crate) const ADD_SERVICE_ACCOUNT_ACTION: &str = "admin:CreateServiceAccount";
const ADD_SERVICE_ACCOUNT_PRECEDENCE: u16 = 61;

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

// ── the three operations ──────────────────────────────────────────────────────────────────────

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

    static ADD_SERVICE_ACCOUNT_SPEC: OperationSpec = OperationSpec::builder(ADD_SERVICE_ACCOUNT, 200, None)
        .handler_deadline_class(HandlerDeadlineClass::Standard)
        .required_params(&[])
        .auth(AuthRequirement::new(ADD_SERVICE_ACCOUNT_ACTION, ResourceShape::Service))
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

pub(crate) use operations::{AddServiceAccount, ReplicationMetricsV2, ServerInfo};

// ── the route rows and what each one hides ────────────────────────────────────────────────────

static SERVER_INFO_SELECTOR: &[Predicate] = &[
    Predicate::Method(Method::GET),
    Predicate::Target(TargetKind::Object),
    Predicate::PathLiteral(SERVER_INFO_PATH),
];

static ADD_SERVICE_ACCOUNT_SELECTOR: &[Predicate] = &[
    Predicate::Method(Method::PUT),
    Predicate::Target(TargetKind::Object),
    Predicate::PathLiteral(ADD_SERVICE_ACCOUNT_ALIAS),
];

static REPLICATION_METRICS_SELECTOR: &[Predicate] = &[
    Predicate::Method(Method::GET),
    Predicate::Target(TargetKind::Bucket),
    Predicate::QueryEquals(REPLICATION_METRICS_QUERY.0, REPLICATION_METRICS_QUERY.1),
];

const fn claims(winner: &'static str, shadowed: &'static str, reason: &'static str) -> ShadowingDecl {
    ShadowingDecl {
        winner,
        shadowed,
        reason,
        evidence: ROUTER_EVIDENCE,
    }
}

/// Every standard `GET` row on an object.
pub(crate) static SERVER_INFO_SHADOWS: &[ShadowingDecl] = &[
    claims(SERVER_INFO, "ListParts", ADMIN_PATH_CLAIM),
    claims(SERVER_INFO, "GetObjectAttributes", ADMIN_PATH_CLAIM),
    claims(SERVER_INFO, "GetObjectTagging", ADMIN_PATH_CLAIM),
    claims(SERVER_INFO, "GetObjectRetention", ADMIN_PATH_CLAIM),
    claims(SERVER_INFO, "GetObjectLegalHold", ADMIN_PATH_CLAIM),
    claims(SERVER_INFO, "GetObjectAcl", ADMIN_PATH_CLAIM),
    claims(SERVER_INFO, "GetObjectAnnotation", ADMIN_PATH_CLAIM),
    claims(SERVER_INFO, "ListObjectAnnotations", ADMIN_PATH_CLAIM),
    claims(SERVER_INFO, "GetObjectTorrent", ADMIN_PATH_CLAIM),
    claims(SERVER_INFO, "GetObject", ADMIN_PATH_CLAIM),
];

/// Every standard `PUT` row on an object.
pub(crate) static ADD_SERVICE_ACCOUNT_SHADOWS: &[ShadowingDecl] = &[
    claims(ADD_SERVICE_ACCOUNT, "UploadPartCopy", ADMIN_PATH_CLAIM),
    claims(ADD_SERVICE_ACCOUNT, "UploadPart", ADMIN_PATH_CLAIM),
    claims(ADD_SERVICE_ACCOUNT, "PutObjectTagging", ADMIN_PATH_CLAIM),
    claims(ADD_SERVICE_ACCOUNT, "PutObjectRetention", ADMIN_PATH_CLAIM),
    claims(ADD_SERVICE_ACCOUNT, "PutObjectLegalHold", ADMIN_PATH_CLAIM),
    claims(ADD_SERVICE_ACCOUNT, "PutObjectAcl", ADMIN_PATH_CLAIM),
    claims(ADD_SERVICE_ACCOUNT, "PutObjectAnnotation", ADMIN_PATH_CLAIM),
    claims(ADD_SERVICE_ACCOUNT, "UpdateObjectEncryption", ADMIN_PATH_CLAIM),
    claims(ADD_SERVICE_ACCOUNT, "RenameObject", ADMIN_PATH_CLAIM),
    claims(ADD_SERVICE_ACCOUNT, "CopyObject", ADMIN_PATH_CLAIM),
    claims(ADD_SERVICE_ACCOUNT, "PutObject", ADMIN_PATH_CLAIM),
];

/// Every standard `GET` row on a bucket.
pub(crate) static REPLICATION_METRICS_SHADOWS: &[ShadowingDecl] = &[
    claims(REPLICATION_METRICS_V2, "GetBucketAccelerateConfiguration", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "GetBucketLogging", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "GetBucketNotificationConfiguration", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "GetBucketPolicy", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "GetBucketPolicyStatus", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "GetPublicAccessBlock", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "GetBucketRequestPayment", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "GetBucketVersioning", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "GetBucketWebsite", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "GetBucketAcl", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "GetBucketOwnershipControls", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "GetBucketIntelligentTieringConfiguration", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "ListBucketIntelligentTieringConfigurations", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "GetBucketAnalyticsConfiguration", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "ListBucketAnalyticsConfigurations", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "GetBucketAbac", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "GetBucketInventoryConfiguration", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "ListBucketInventoryConfigurations", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "CreateSession", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "GetBucketMetadataConfiguration", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "GetBucketMetadataTableConfiguration", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "GetBucketMetricsConfiguration", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "ListBucketMetricsConfigurations", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "GetBucketLocation", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "GetBucketCors", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "GetBucketTagging", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "GetBucketLifecycleConfiguration", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "GetBucketEncryption", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "GetBucketReplication", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "GetObjectLockConfiguration", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "ListMultipartUploads", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "ListObjectsV2", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "ListObjectVersions", EXTENSION_CLAIM),
    claims(REPLICATION_METRICS_V2, "ListObjects", EXTENSION_CLAIM),
];

/// The reviewed record of the three rows.
static OVERLAY: DialectOverlay = DialectOverlay {
    name: "rustfs-admin-proof",
    vendor: "rustfs",
    operations: &[
        OverlayRow {
            name: SERVER_INFO,
            precedence: SERVER_INFO_PRECEDENCE,
            selector: "Method(GET) ∧ Target(Object) ∧ PathLiteral(\"/rustfs/admin/v3/info\")",
            action: SERVER_INFO_ACTION,
            resource: ResourceShape::Service,
            success_status: 200,
            anonymous: false,
            evidence: &[RUSTFS_ROUTER, ISSUE],
        },
        OverlayRow {
            name: ADD_SERVICE_ACCOUNT,
            precedence: ADD_SERVICE_ACCOUNT_PRECEDENCE,
            selector: "Method(PUT) ∧ Target(Object) ∧ PathLiteral(\"/minio/admin/v3/add-service-account\")",
            action: ADD_SERVICE_ACCOUNT_ACTION,
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

/// The declarations each row carries; tests swap one set to prove each declaration is needed.
#[derive(Clone, Copy)]
pub(crate) struct Shadows {
    pub(crate) server_info: &'static [ShadowingDecl],
    pub(crate) add_service_account: &'static [ShadowingDecl],
    pub(crate) replication_metrics: &'static [ShadowingDecl],
}

impl Shadows {
    /// The reviewed declarations.
    pub(crate) const DECLARED: Self = Self {
        server_info: SERVER_INFO_SHADOWS,
        add_service_account: ADD_SERVICE_ACCOUNT_SHADOWS,
        replication_metrics: REPLICATION_METRICS_SHADOWS,
    };
}

/// The three rows with `shadows`.
pub(crate) fn admin_dialect_with(shadows: Shadows) -> Result<Dialect, Vec<DialectError>> {
    Dialect::assemble(&OVERLAY)
        .declare::<ServerInfo>(DialectRoute {
            precedence: SERVER_INFO_PRECEDENCE,
            selector: SERVER_INFO_SELECTOR,
            path_shape: SERVER_INFO_PATH,
            shadows: shadows.server_info,
        })
        .declare::<AddServiceAccount>(DialectRoute {
            precedence: ADD_SERVICE_ACCOUNT_PRECEDENCE,
            selector: ADD_SERVICE_ACCOUNT_SELECTOR,
            path_shape: ADD_SERVICE_ACCOUNT_ALIAS,
            shadows: shadows.add_service_account,
        })
        .declare::<ReplicationMetricsV2>(DialectRoute {
            precedence: REPLICATION_METRICS_PRECEDENCE,
            selector: REPLICATION_METRICS_SELECTOR,
            path_shape: "/{Bucket}",
            shadows: shadows.replication_metrics,
        })
        .build()
}

/// The three rows with the reviewed declarations.
pub(crate) fn admin_dialect() -> Dialect {
    admin_dialect_with(Shadows::DECLARED).expect("the record and the declarations state the same facts")
}

// ── the caller-secret seal ────────────────────────────────────────────────────────────────────

const TAG_LENGTH: usize = 32;

fn keystream(secret: &[u8], length: usize) -> Vec<u8> {
    let mut stream = Vec::with_capacity(length + TAG_LENGTH);
    let mut counter = 0_u64;
    while stream.len() < length {
        let mut block = Sha256::new();
        block.update(b"rustfs-admin-proof keystream");
        block.update(secret);
        block.update(counter.to_be_bytes());
        stream.extend_from_slice(&block.finalize());
        counter += 1;
    }
    stream.truncate(length);
    stream
}

fn tag(secret: &[u8], plain: &[u8]) -> [u8; TAG_LENGTH] {
    let mut tag = Sha256::new();
    tag.update(b"rustfs-admin-proof tag");
    tag.update(secret);
    tag.update(plain);
    tag.finalize().into()
}

/// Seals `plain` under `secret`, the way a madmin client seals an admin body (a stand-in cipher).
pub(crate) fn seal(secret: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut sealed = tag(secret, plain).to_vec();
    sealed.extend(plain.iter().zip(keystream(secret, plain.len())).map(|(byte, key)| byte ^ key));
    sealed
}

/// Opens a body sealed under `secret`, or `None` when it was sealed under another key.
pub(crate) fn open(secret: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    let (expected, cipher) = sealed.split_at_checked(TAG_LENGTH)?;
    let plain = cipher
        .iter()
        .zip(keystream(secret, cipher.len()))
        .map(|(byte, key)| byte ^ key)
        .collect::<Vec<_>>();
    same_bytes(&tag(secret, &plain), expected).then_some(plain)
}

/// A comparison that reads every byte, for key material and tags.
pub(crate) fn same_bytes(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.iter().zip(right).fold(0_u8, |acc, (a, b)| acc | (a ^ b)) == 0
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
    /// Whether the authenticator hands the caller's secret to handlers (ADR-0022).
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
