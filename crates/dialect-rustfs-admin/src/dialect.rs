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

//! The `rustfs` dialect: its claims, its reviewed record, and its assembly.
//!
//! Responsible for: [`CLAIMS`], the path prefixes RustFS's admin router answers ahead of its S3
//! service; [`OVERLAY`], the record of every generated operation; and [`rustfs_admin_dialect`],
//! which declares each against it — the claimed operations inside the claims, the eight
//! S3-shaped extension operations as S3-table rows (rustfs/backlog#2753), the two authenticated
//! fallbacks, and the STS endpoint behind its own form claim (ADR-0041).
//! NOT responsible for: the operations or their record rows (generated: [`crate::ops`] and
//! `crate::table`), or registering handlers (the deployment).
//! Upstream: `rustfs-gateway-core`'s dialect mechanism and the generated table. Downstream: a
//! deployment that installs the dialect with `ServiceBuilder::dialect`.
//!
//! A claimed row cannot overlap an S3 row: the router asks the claim first, and a request inside
//! `/rustfs/admin`, `/minio/admin`, `/_iceberg/v1`, `/iceberg/v1`, `/profile/cpu` or `/profile/memory` is answered by a claimed row or
//! by nothing, which is how RustFS's own router takes those prefixes ahead of its S3 service. So
//! no claimed operation declares a shadowing decision against S3, and a path-style bucket named
//! `rustfs`, `minio`, `iceberg` or `profile` loses these keys, as it does on RustFS today (ADR-0024,
//! ADR-0031, ADR-0032).
//!
//! The extension operations are the other case: RustFS's router claims `PUT /{bucket}?replication-reset`,
//! `GET /{bucket}?replication-metrics=2`, `GET /{bucket}/{key}?lambdaArn=…`, `GET /?events=…` and the
//! rest by one query discriminator, so nothing in the path marks them and no claim can take them.
//! Each is an S3-table row placed ahead of every standard row of its method and target, and every
//! one of those overlaps is a real routing decision the row declares, computed from the generated
//! route table by the generator and refused by core when stale or missing.

use rustfs_gateway_core::dialect::{ClaimedRoute, Dialect, DialectBuilder, DialectError, DialectOverlay};
use rustfs_gateway_core::route::PathClaim;

use crate::admin::{AdminOperation, ExtensionFold, ExtensionOperation, OperationFold};
use crate::ops::{admin_fallback, admin_v4_fallback, sts_form_post};
use crate::table::{OVERLAY_ROWS, fold_every_extension, fold_every_operation};

/// The RustFS router that answers the admin prefixes ahead of its S3 service, at the commit the
/// inventory was recorded from.
const RUSTFS_ROUTER: &str =
    "https://github.com/rustfs/rustfs/blob/736e4fb8e8e5d527c25e4e56f352536b311b6daf/rustfs/src/admin/router.rs";
const ROUTER_EVIDENCE: &[&str] = &[RUSTFS_ROUTER];

/// The six prefixes the dialect takes away from S3 routing: the admin API under its RustFS and
/// MinIO spellings, the Iceberg REST table catalog under its RustFS and compat spellings, and the
/// two profiling triggers (ADR-0024, ADR-0031, ADR-0032).
pub static CLAIMS: &[PathClaim] = &[
    PathClaim {
        prefix: "/rustfs/admin",
        reason: "RustFS's admin router answers every path-style request under this prefix before its S3 service, \
                 whatever the query.",
        evidence: ROUTER_EVIDENCE,
    },
    PathClaim {
        prefix: "/minio/admin",
        reason: "RustFS serves its admin API a second time under the MinIO prefix, for MinIO admin clients.",
        evidence: ROUTER_EVIDENCE,
    },
    PathClaim {
        prefix: "/_iceberg/v1",
        reason: "RustFS's admin router answers the Iceberg REST table catalog under this prefix before its S3 \
                 service; `_iceberg` is no legal bucket name, so no bucket loses a key.",
        evidence: ROUTER_EVIDENCE,
    },
    PathClaim {
        prefix: "/iceberg/v1",
        reason: "RustFS serves the table catalog a second time under this compat prefix, so a path-style bucket \
                 named `iceberg` loses its `v1/…` keys, as it does on RustFS today.",
        evidence: ROUTER_EVIDENCE,
    },
    PathClaim {
        prefix: "/profile/cpu",
        reason: "RustFS's admin router answers its CPU profiling trigger here before its S3 service, so a \
                 path-style bucket named `profile` loses its `cpu` keys, as it does on RustFS today.",
        evidence: ROUTER_EVIDENCE,
    },
    PathClaim {
        prefix: "/profile/memory",
        reason: "RustFS's admin router answers its memory profiling trigger here before its S3 service, so a \
                 path-style bucket named `profile` loses its `memory` keys, as it does on RustFS today.",
        evidence: ROUTER_EVIDENCE,
    },
];

/// The table catalog's two prefixes, whose SigV4 paths legacy RustFS verifies as generic AWS
/// SigV4 signs them (rustfs/rustfs#8291): what a RustFS assembly hands
/// `SigV4Authenticator::verify_paths_double_encoded_under` (rustfs/gateway#1232). Both are claims
/// in [`CLAIMS`].
pub static TABLE_CATALOG_PREFIXES: &[&str] = &["/_iceberg/v1", "/iceberg/v1"];

/// The reviewed record: the six claims and every generated operation.
pub static OVERLAY: DialectOverlay = DialectOverlay {
    name: "rustfs-admin",
    vendor: "rustfs",
    claims: CLAIMS,
    operations: OVERLAY_ROWS,
};

/// Declares one operation's rows at its precedence.
struct Declare;

impl OperationFold for Declare {
    type Carry = DialectBuilder;

    fn step<O: AdminOperation>(&mut self, carry: DialectBuilder) -> DialectBuilder {
        carry.declare_claimed::<O>(ClaimedRoute {
            precedence: O::PRECEDENCE,
            rows: O::rows(),
            shadows: O::shadows(),
            // A `{bucket}` template parameter or a listed query parameter is the operation's
            // bucket (ADR-0030); every other operation is service-level (ADR-0027).
            bucket_param: O::BUCKET,
        })
    }
}

/// Declares one extension operation's S3-table row, with the overlaps it owes.
struct DeclareExtension;

impl ExtensionFold for DeclareExtension {
    type Carry = DialectBuilder;

    fn step<O: ExtensionOperation>(&mut self, carry: DialectBuilder) -> DialectBuilder {
        carry.declare::<O>(O::ROUTE)
    }
}

/// The `rustfs` dialect: its claims, every generated operation declared against [`OVERLAY`] —
/// the claimed ones inside the claims and the extension ones as S3-table rows — and RustFS's STS
/// endpoint behind its form claim (ADR-0041).
///
/// Installing it is the deployment's choice (`ServiceBuilder::dialect`), and so is each handler;
/// an operation installed without one answers `501`.
///
/// # Errors
///
/// Every refusal [`DialectBuilder::build`] finds. None is expected: the record and the
/// declarations are generated from the same inventory rows, and the tests pin that they agree.
pub fn rustfs_admin_dialect() -> Result<Dialect, Vec<DialectError>> {
    let builder = fold_every_operation(&mut Declare, Dialect::assemble(&OVERLAY));
    fold_every_extension(&mut DeclareExtension, builder)
        .declare_claimed::<admin_v4_fallback::AdminV4Fallback>(admin_v4_fallback::ROUTE)
        .declare_claimed::<admin_fallback::AdminFallback>(admin_fallback::ROUTE)
        .declare_form::<sts_form_post::StsFormPost>(sts_form_post::ROUTE)
        .build()
}
