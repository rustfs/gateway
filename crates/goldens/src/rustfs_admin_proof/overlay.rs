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

//! The proof dialect's reviewed record and its declarations: nine operations, two claims.
//!
//! Responsible for: [`OVERLAY`] — every row as a reviewer reads it, the rendered action rule,
//! subject and bucket binding included (ADR-0024, ADR-0025) — and the functions that declare the
//! operations against it.
//! NOT responsible for: the operations (`super` and `super::classes`) or the assembly (`super`).
//! Upstream: `super`, `super::classes`. Downstream: `super::assemble`, the proof's tests.

use rustfs_gateway_core::dialect::{ClaimedRoute, Dialect, DialectError, DialectOverlay, DialectRoute, OverlayRow};
use rustfs_gateway_core::op::ResourceShape;
use rustfs_gateway_core::route::ShadowingDecl;

use super::classes::{
    FIRST_PRECEDENCE, GET_BUCKET_QUOTA, GET_USER_INFO, GetBucketQuota, GetUserInfo, LIST_POOLS, ListPools, SELF_ACCOUNT_INFO,
    SERVICE_RESTART, SelfAccountInfo, ServiceRestart, routes,
};
use super::{
    ADD_SERVICE_ACCOUNT, ADD_SERVICE_ACCOUNT_ACTION, ADD_SERVICE_ACCOUNT_PRECEDENCE, ADD_SERVICE_ACCOUNT_ROWS, AddServiceAccount,
    CLAIMS, GET_TIER, GET_TIER_ACTION, GET_TIER_PRECEDENCE, GET_TIER_ROWS, GetTier, ISSUE, REPLICATION_METRICS_ACTION,
    REPLICATION_METRICS_PRECEDENCE, REPLICATION_METRICS_SELECTOR, REPLICATION_METRICS_SHADOWS, REPLICATION_METRICS_V2,
    RUSTFS_ROUTER, ReplicationMetricsV2, SERVER_INFO, SERVER_INFO_ACTION, SERVER_INFO_PRECEDENCE, SERVER_INFO_ROWS, ServerInfo,
};

const HANDLERS: &str = "https://github.com/rustfs/rustfs/blob/736e4fb8e8e5d527c25e4e56f352536b311b6daf/rustfs/src/admin/handlers";
const POOLS: &str =
    "https://github.com/rustfs/rustfs/blob/736e4fb8e8e5d527c25e4e56f352536b311b6daf/rustfs/src/admin/handlers/pools.rs";
const ACCOUNT: &str =
    "https://github.com/rustfs/rustfs/blob/736e4fb8e8e5d527c25e4e56f352536b311b6daf/rustfs/src/admin/handlers/account.rs";
const USER: &str =
    "https://github.com/rustfs/rustfs/blob/736e4fb8e8e5d527c25e4e56f352536b311b6daf/rustfs/src/admin/handlers/user.rs";
const QUOTA: &str =
    "https://github.com/rustfs/rustfs/blob/736e4fb8e8e5d527c25e4e56f352536b311b6daf/rustfs/src/admin/handlers/quota.rs";
const SYSTEM: &str =
    "https://github.com/rustfs/rustfs/blob/736e4fb8e8e5d527c25e4e56f352536b311b6daf/rustfs/src/admin/handlers/system.rs";

const fn claimed_row(
    name: &'static str,
    precedence: u16,
    selector: &'static str,
    action: &'static str,
    resource: ResourceShape,
    evidence: &'static [&'static str],
) -> OverlayRow {
    OverlayRow {
        name,
        precedence,
        selector,
        action,
        resource,
        success_status: 200,
        anonymous: false,
        evidence,
    }
}

/// The reviewed record: the two claims and the nine operations, alias rows included.
pub(crate) static OVERLAY: DialectOverlay = DialectOverlay {
    name: "rustfs-admin-proof",
    vendor: "rustfs",
    claims: CLAIMS,
    operations: &[
        claimed_row(
            SERVER_INFO,
            SERVER_INFO_PRECEDENCE,
            "PathTemplate(\"/rustfs/admin/v3/info\") ∧ Method(GET) ∨ PathTemplate(\"/minio/admin/v3/info\") ∧ Method(GET)",
            SERVER_INFO_ACTION,
            ResourceShape::Service,
            &[RUSTFS_ROUTER, ISSUE],
        ),
        claimed_row(
            ADD_SERVICE_ACCOUNT,
            ADD_SERVICE_ACCOUNT_PRECEDENCE,
            "PathTemplate(\"/rustfs/admin/v3/add-service-account\") ∧ Method(PUT) ∨ \
             PathTemplate(\"/minio/admin/v3/add-service-account\") ∧ Method(PUT)",
            ADD_SERVICE_ACCOUNT_ACTION,
            ResourceShape::Service,
            &[RUSTFS_ROUTER, ISSUE],
        ),
        claimed_row(
            GET_TIER,
            GET_TIER_PRECEDENCE,
            "PathTemplate(\"/rustfs/admin/v3/tier/{tier}\") ∧ Method(GET) ∨ \
             PathTemplate(\"/minio/admin/v3/tier/{tier}\") ∧ Method(GET)",
            GET_TIER_ACTION,
            ResourceShape::Service,
            &[RUSTFS_ROUTER, ISSUE],
        ),
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
        // ADR-0025: one route per custom-auth class, each action rule spelled out.
        claimed_row(
            LIST_POOLS,
            FIRST_PRECEDENCE,
            "PathTemplate(\"/rustfs/admin/v3/pools/list\") ∧ Method(GET) ∨ \
             PathTemplate(\"/minio/admin/v3/pools/list\") ∧ Method(GET)",
            "anyOf(admin:ServerInfo, admin:Decommission)",
            ResourceShape::Service,
            &[POOLS, ISSUE],
        ),
        claimed_row(
            SELF_ACCOUNT_INFO,
            FIRST_PRECEDENCE + 1,
            "PathTemplate(\"/rustfs/admin/v3/account/info\") ∧ Method(GET) ∨ \
             PathTemplate(\"/minio/admin/v3/account/info\") ∧ Method(GET)",
            "rustfs:SelfAccountInfo about caller",
            ResourceShape::Service,
            &[ACCOUNT, ISSUE],
        ),
        claimed_row(
            GET_USER_INFO,
            FIRST_PRECEDENCE + 2,
            "PathTemplate(\"/rustfs/admin/v3/user-info\") ∧ Method(GET) ∨ \
             PathTemplate(\"/minio/admin/v3/user-info\") ∧ Method(GET)",
            "admin:GetUser about query(accessKey, absent=refused)",
            ResourceShape::Service,
            &[USER, ISSUE],
        ),
        claimed_row(
            GET_BUCKET_QUOTA,
            FIRST_PRECEDENCE + 3,
            "PathTemplate(\"/rustfs/admin/v3/quota/{bucket}\") ∧ Method(GET) ∨ \
             PathTemplate(\"/minio/admin/v3/quota/{bucket}\") ∧ Method(GET) ⇒ BucketParam(\"bucket\")",
            "s3:GetBucketQuota",
            ResourceShape::Bucket,
            &[QUOTA, ISSUE],
        ),
        claimed_row(
            SERVICE_RESTART,
            FIRST_PRECEDENCE + 4,
            "PathTemplate(\"/rustfs/admin/v3/service\") ∧ Method(POST) ∧ QueryEquals(\"action\", \"restart\") ∨ \
             PathTemplate(\"/minio/admin/v3/service\") ∧ Method(POST) ∧ QueryEquals(\"action\", \"restart\")",
            "admin:ServiceRestart",
            ResourceShape::Service,
            &[SYSTEM, HANDLERS, ISSUE],
        ),
    ],
};

/// The nine operations, with `replication_metrics` as the S3-shaped row's declarations and
/// `quota_bucket` as the quota route's binding; tests swap either to prove it is needed.
pub(crate) fn admin_dialect_bound(
    replication_metrics: &'static [ShadowingDecl],
    quota_bucket: Option<&'static str>,
) -> Result<Dialect, Vec<DialectError>> {
    let [pools, account, user, quota, restart] = routes(quota_bucket);
    Dialect::assemble(&OVERLAY)
        .declare_claimed::<ServerInfo>(ClaimedRoute {
            precedence: SERVER_INFO_PRECEDENCE,
            rows: SERVER_INFO_ROWS,
            shadows: &[],
            bucket_param: None,
        })
        .declare_claimed::<AddServiceAccount>(ClaimedRoute {
            precedence: ADD_SERVICE_ACCOUNT_PRECEDENCE,
            rows: ADD_SERVICE_ACCOUNT_ROWS,
            shadows: &[],
            bucket_param: None,
        })
        .declare_claimed::<GetTier>(ClaimedRoute {
            precedence: GET_TIER_PRECEDENCE,
            rows: GET_TIER_ROWS,
            shadows: &[],
            bucket_param: None,
        })
        .declare::<ReplicationMetricsV2>(DialectRoute {
            precedence: REPLICATION_METRICS_PRECEDENCE,
            selector: REPLICATION_METRICS_SELECTOR,
            path_shape: "/{Bucket}",
            shadows: replication_metrics,
        })
        .declare_claimed::<ListPools>(pools)
        .declare_claimed::<SelfAccountInfo>(account)
        .declare_claimed::<GetUserInfo>(user)
        .declare_claimed::<GetBucketQuota>(quota)
        .declare_claimed::<ServiceRestart>(restart)
        .build()
}

/// The nine operations, with `replication_metrics` as the S3-shaped row's declarations.
pub(crate) fn admin_dialect_with(replication_metrics: &'static [ShadowingDecl]) -> Result<Dialect, Vec<DialectError>> {
    admin_dialect_bound(replication_metrics, Some("bucket"))
}

/// The nine operations with the reviewed declarations.
pub(crate) fn admin_dialect() -> Dialect {
    admin_dialect_with(REPLICATION_METRICS_SHADOWS).expect("the record and the declarations state the same facts")
}
