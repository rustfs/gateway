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
//! - One route from each custom-auth class of the inventory, and the bound bucket, on ADR-0025's
//!   rules; the three bulk access-key routes about a set of accounts, and the quota route whose
//!   bucket is in the query, and RustFS's four anonymous OIDC bootstrap routes, on ADR-0026's:
//!   `classes.rs`. The overlay record for all seventeen is `overlay.rs`.
//!
//! The first three are claimed rows inside the dialect's two path-prefix claims, `/rustfs/admin` and
//! `/minio/admin`. The fourth is an S3-table row. The service, in `service.rs`, is the facade's own:
//! the SigV4 authenticator, a recording authorizer, and a backend that records what each handler
//! was handed.
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

use bytes::Bytes;
use http::Method;
use rustfs_gateway_core::codec::{
    CodecError, EncodedResponse, MetaView, OperationCodec, RequestBody, RequestBodyMode, ResponseBody,
};
use rustfs_gateway_core::dialect::ClaimedRow;
use rustfs_gateway_core::op::{AuthRequirement, Operation, ResourceShape};
use rustfs_gateway_core::registry::{HandlerDeadlineClass, OperationSpec};
use rustfs_gateway_core::route::{PathClaim, Predicate, ShadowingDecl, TargetKind};
use rustfs_gateway_core::{DerivedResourceError, NoDerived};
use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::BucketName;

mod overlay;
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

pub(crate) use self::overlay::{admin_dialect, admin_dialect_bound, admin_dialect_with};

mod classes;
mod service;

pub(crate) use self::classes::{OidcAuthorize, OidcCallback, OidcListProviders, OidcLogout};

pub(crate) use self::classes::{
    GetBucketQuota, GetBucketQuotaByQuery, GetUserInfo, ListAccessKeysBulk, ListAccessKeysLdapBulk, ListAccessKeysOpenidBulk,
    ListPools, SelfAccountInfo, ServiceRestart,
};

pub(crate) use self::service::{Assembled, AuthzCall, Backend, Options, assemble};

#[cfg(test)]
mod anonymous_tests;
#[cfg(test)]
mod class_tests;
#[cfg(test)]
mod set_tests;
#[cfg(test)]
mod tests;
