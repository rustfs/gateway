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

//! One RustFS admin route from each custom-auth class of the inventory, and one bound-bucket
//! route, as proof operations on ADR-0025's rules.
//!
//! Responsible for: five `rustfs:` operations, their rows and their handler:
//!
//! - `MultipleActions`: [`ListPools`], `GET /rustfs/admin/v3/pools/list`, allowed when either
//!   `admin:ServerInfo` or `admin:Decommission` is (RustFS's `evaluate_admin_actions` is any-of).
//! - `CredentialOnly`: [`SelfAccountInfo`], `GET /rustfs/admin/v3/account/info`, about the caller
//!   only, under the own-account label `rustfs:SelfAccountInfo`.
//! - `ContextualAuthorization`: [`GetUserInfo`], `GET /rustfs/admin/v3/user-info?accessKey=…`,
//!   under `admin:GetUser` about the account `accessKey` names; absent is a `400`, as in RustFS.
//! - `S3Action`, and the bound bucket: [`GetBucketQuota`], `GET /rustfs/admin/v3/quota/{bucket}`,
//!   under `s3:GetBucketQuota` on the bucket its template parameter names.
//! - `NotImplemented`: [`ServiceRestart`], `POST /rustfs/admin/v3/service?action=restart`. The
//!   inventory's label is stale — RustFS implements the route and picks the action by the query —
//!   so the proof splits it by a query predicate, and any other `action` is the claim's `501`.
//!
//! Each is also served at its `/minio/admin` alias. One generic marker and one handler serve all
//! five, because what is under test is authorisation, not the bodies.
//! NOT responsible for: the overlay record (`super::overlay`), the assembly (`super`), or what
//! RustFS answers behind these routes.
//! Upstream: `rustfs-gateway-core`'s rules and dialect types. Downstream: `super::overlay`,
//! `super::class_tests`.

use http::Method;
use rustfs_gateway::{Handler, HandlerContext, HandlerResult, Req, Resp};
use rustfs_gateway_core::dialect::{ClaimedRoute, ClaimedRow};
use rustfs_gateway_core::op::{AuthRequirement, ResourceShape};
use rustfs_gateway_core::route::Predicate;
use rustfs_gateway_core::{SubjectRule, WhenAbsent};

use super::{Backend, json};

/// `rustfs:ListPools`.
pub(crate) const LIST_POOLS: &str = "rustfs:ListPools";
pub(crate) const LIST_POOLS_PATH: &str = "/rustfs/admin/v3/pools/list";
/// Either suffices, as in RustFS's `pools.rs`.
pub(crate) const LIST_POOLS_ACTIONS: &[&str] = &["admin:ServerInfo", "admin:Decommission"];

/// `rustfs:SelfAccountInfo`.
pub(crate) const SELF_ACCOUNT_INFO: &str = "rustfs:SelfAccountInfo";
pub(crate) const SELF_ACCOUNT_INFO_PATH: &str = "/rustfs/admin/v3/account/info";
/// An own-account label, in the vendor's namespace: RustFS evaluates no IAM action here.
pub(crate) const SELF_ACCOUNT_INFO_ACTION: &str = "rustfs:SelfAccountInfo";

/// `rustfs:GetUserInfo`.
pub(crate) const GET_USER_INFO: &str = "rustfs:GetUserInfo";
pub(crate) const GET_USER_INFO_PATH: &str = "/rustfs/admin/v3/user-info";
pub(crate) const GET_USER_INFO_ACTION: &str = "admin:GetUser";
/// The account `user-info` is about.
pub(crate) const USER_SUBJECT: SubjectRule = SubjectRule::Query {
    param: "accessKey",
    when_absent: WhenAbsent::Refuse,
};

/// `rustfs:GetBucketQuota`.
pub(crate) const GET_BUCKET_QUOTA: &str = "rustfs:GetBucketQuota";
pub(crate) const GET_BUCKET_QUOTA_TEMPLATE: &str = "/rustfs/admin/v3/quota/{bucket}";
pub(crate) const GET_BUCKET_QUOTA_ACTION: &str = "s3:GetBucketQuota";

/// `rustfs:ServiceRestart`.
pub(crate) const SERVICE_RESTART: &str = "rustfs:ServiceRestart";
pub(crate) const SERVICE_PATH: &str = "/rustfs/admin/v3/service";
pub(crate) const SERVICE_RESTART_ACTION: &str = "admin:ServiceRestart";

/// The five names, by marker index.
const NAMES: [&str; 5] = [
    LIST_POOLS,
    SELF_ACCOUNT_INFO,
    GET_USER_INFO,
    GET_BUCKET_QUOTA,
    SERVICE_RESTART,
];

/// The five requirements, by marker index.
pub(crate) const REQUIREMENTS: [AuthRequirement; 5] = [
    AuthRequirement::any_of(LIST_POOLS_ACTIONS, ResourceShape::Service),
    AuthRequirement::new(SELF_ACCOUNT_INFO_ACTION, ResourceShape::Service).about_subject(SubjectRule::Caller),
    AuthRequirement::new(GET_USER_INFO_ACTION, ResourceShape::Service).about_subject(USER_SUBJECT),
    AuthRequirement::new(GET_BUCKET_QUOTA_ACTION, ResourceShape::Bucket),
    AuthRequirement::new(SERVICE_RESTART_ACTION, ResourceShape::Service),
];

/// The first precedence; the five take the next five.
pub(crate) const FIRST_PRECEDENCE: u16 = 20;

pub(crate) use operations::Class;

/// `MultipleActions`.
pub(crate) type ListPools = Class<0>;
/// `CredentialOnly`.
pub(crate) type SelfAccountInfo = Class<1>;
/// `ContextualAuthorization`.
pub(crate) type GetUserInfo = Class<2>;
/// `S3Action`, with the bound bucket.
pub(crate) type GetBucketQuota = Class<3>;
/// `NotImplemented`, as implemented today.
pub(crate) type ServiceRestart = Class<4>;

// ── the rows ──────────────────────────────────────────────────────────────────────────────────

static GET: &[Predicate] = &[Predicate::Method(Method::GET)];
static RESTART: &[Predicate] = &[Predicate::Method(Method::POST), Predicate::QueryEquals("action", "restart")];

const fn row(template: &'static str, selector: &'static [Predicate]) -> ClaimedRow {
    ClaimedRow { template, selector }
}

static LIST_POOLS_ROWS: &[ClaimedRow] = &[row(LIST_POOLS_PATH, GET), row("/minio/admin/v3/pools/list", GET)];
static SELF_ACCOUNT_INFO_ROWS: &[ClaimedRow] = &[row(SELF_ACCOUNT_INFO_PATH, GET), row("/minio/admin/v3/account/info", GET)];
static GET_USER_INFO_ROWS: &[ClaimedRow] = &[row(GET_USER_INFO_PATH, GET), row("/minio/admin/v3/user-info", GET)];
static GET_BUCKET_QUOTA_ROWS: &[ClaimedRow] = &[
    row(GET_BUCKET_QUOTA_TEMPLATE, GET),
    row("/minio/admin/v3/quota/{bucket}", GET),
];
static SERVICE_RESTART_ROWS: &[ClaimedRow] = &[row(SERVICE_PATH, RESTART), row("/minio/admin/v3/service", RESTART)];

/// The five routes, by marker index; `bucket` is the quota route's binding, which tests swap.
pub(crate) fn routes(bucket: Option<&'static str>) -> [ClaimedRoute; 5] {
    let route = |index: u16, rows, bucket_param| ClaimedRoute {
        precedence: FIRST_PRECEDENCE + index,
        rows,
        shadows: &[],
        bucket_param,
    };
    [
        route(0, LIST_POOLS_ROWS, None),
        route(1, SELF_ACCOUNT_INFO_ROWS, None),
        route(2, GET_USER_INFO_ROWS, None),
        route(3, GET_BUCKET_QUOTA_ROWS, bucket),
        route(4, SERVICE_RESTART_ROWS, None),
    ]
}

// ── the handler ───────────────────────────────────────────────────────────────────────────────

impl Backend {
    /// Records what it was handed and answers with the bucket and subject it acts on, read from
    /// the context and never from the query.
    fn class<const N: usize>(&self, request: &Req<Class<N>>) -> HandlerResult<Class<N>> {
        let context = request.context();
        self.see(context);
        Ok(Resp::new(json(&serde_json::json!({
            "operation": context.operation(),
            "bucket": context.bucket().map(|bucket| bucket.as_str().to_owned()),
            "subject": context.subject().and_then(|subject| subject.name().map(str::to_owned)),
        }))))
    }
}

impl<const N: usize> Handler<Class<N>> for Backend {
    async fn call(&self, request: Req<Class<N>>) -> HandlerResult<Class<N>> {
        self.class(&request)
    }

    async fn call_with_context(&self, request: Req<Class<N>>, _context: HandlerContext) -> HandlerResult<Class<N>> {
        self.class(&request)
    }
}

// Test-only, and inside its own `#[cfg(test)]` item for `check_op_file_shape.sh`, like the parent's.
#[cfg(test)]
mod operations {
    use rustfs_gateway_core::codec::{CodecError, EncodedResponse, MetaView, OperationCodec, RequestBody, RequestBodyMode};
    use rustfs_gateway_core::op::Operation;
    use rustfs_gateway_core::registry::{HandlerDeadlineClass, OperationSpec};
    use rustfs_gateway_core::{DerivedResourceError, NoDerived};
    use rustfs_gateway_sig::{OperationFloor, SigService};

    use super::{NAMES, REQUIREMENTS};
    use crate::rustfs_admin_proof::{AdminBody, encode_admin};

    /// One bodiless admin read or command per index.
    pub(crate) struct Class<const N: usize>;

    const fn spec(index: usize) -> OperationSpec {
        OperationSpec::builder(NAMES[index], 200, None)
            .handler_deadline_class(HandlerDeadlineClass::Standard)
            .required_params(&[])
            .auth(REQUIREMENTS[index])
            .build()
    }

    static SPECS: [OperationSpec; 5] = [spec(0), spec(1), spec(2), spec(3), spec(4)];

    /// Privileged and header-signed only, like every claimed operation until a client presigns.
    static FLOORS: [OperationFloor; 5] = [
        OperationFloor::custom(NAMES[0], SigService::S3),
        OperationFloor::custom(NAMES[1], SigService::S3),
        OperationFloor::custom(NAMES[2], SigService::S3),
        OperationFloor::custom(NAMES[3], SigService::S3),
        OperationFloor::custom(NAMES[4], SigService::S3),
    ];

    impl<const N: usize> Operation for Class<N> {
        const NAME: &'static str = NAMES[N];

        type Input = ();
        type Output = AdminBody;
        type DerivedResources = NoDerived;

        fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, DerivedResourceError> {
            Ok(NoDerived)
        }

        fn seal_derived_input(_input: &mut Self::Input) {}

        fn spec() -> &'static OperationSpec {
            &SPECS[N]
        }

        fn floor() -> &'static OperationFloor {
            &FLOORS[N]
        }
    }

    impl<const N: usize> OperationCodec for Class<N> {
        const REQUEST_BODY: RequestBodyMode = RequestBodyMode::None;

        fn decode(_request: &MetaView<'_>, _body: RequestBody) -> Result<Self::Input, CodecError> {
            Ok(())
        }

        fn encode(output: Self::Output, _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
            encode_admin(output, status)
        }
    }
}
