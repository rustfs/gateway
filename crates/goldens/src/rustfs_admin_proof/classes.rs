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

//! One RustFS admin route from each custom-auth class of the inventory, one bound-bucket route,
//! the three bulk access-key routes, the query-bound quota route and the four anonymous OIDC
//! bootstrap routes, as proof operations on ADR-0025's and ADR-0026's rules.
//!
//! Responsible for: thirteen `rustfs:` operations, their rows (each with its `/minio/admin`
//! alias) and their one generic handler:
//!
//! - `MultipleActions`: [`ListPools`], any-of `admin:ServerInfo` / `admin:Decommission`.
//! - `CredentialOnly`: [`SelfAccountInfo`], about the caller under `rustfs:SelfAccountInfo`.
//! - `ContextualAuthorization`: [`GetUserInfo`], `admin:GetUser` about `accessKey` (absent: `400`).
//! - `S3Action`: [`GetBucketQuota`], `s3:GetBucketQuota` on the `{bucket}` template parameter, and
//!   [`GetBucketQuotaByQuery`], the same on the `bucket` query parameter (ADR-0026).
//! - `NotImplemented` (a stale label): [`ServiceRestart`], `POST service?action=restart`; any
//!   other `action` is the claim's `501`.
//! - Bulk listings (ADR-0026): [`ListAccessKeysBulk`], [`ListAccessKeysLdapBulk`] and
//!   [`ListAccessKeysOpenidBulk`], `admin:ListServiceAccounts` about each `users` account, and
//!   `admin:ListUsers` as well for `all=true`.
//! - `OidcBootstrap` (ADR-0026): [`OidcListProviders`], [`OidcAuthorize`], [`OidcCallback`] and
//!   [`OidcLogout`], each anonymous by its own floor opt-in and still an authorizer question under
//!   its own vendor label.
//!
//! NOT responsible for: the overlay record (`super::overlay`), the assembly (`super`), the bodies
//! (not under test), or what RustFS answers behind these routes.
//! Upstream: `rustfs-gateway-core`'s rules and dialect types. Downstream: `super::overlay`,
//! `super::class_tests`, `super::set_tests`, `super::anonymous_tests`.

use http::Method;
use rustfs_gateway::{Handler, HandlerContext, HandlerResult, Req, Resp};
use rustfs_gateway_core::dialect::{BucketParam, ClaimedRoute, ClaimedRow};
use rustfs_gateway_core::op::{AuthRequirement, ResourceShape};
use rustfs_gateway_core::route::Predicate;
use rustfs_gateway_core::{Everyone, Subject, SubjectRule, Subjects, WhenAbsent};

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

/// `rustfs:ListAccessKeysBulk`.
pub(crate) const LIST_ACCESS_KEYS_BULK: &str = "rustfs:ListAccessKeysBulk";
pub(crate) const LIST_ACCESS_KEYS_BULK_PATH: &str = "/rustfs/admin/v3/list-access-keys-bulk";
/// `rustfs:ListAccessKeysLdapBulk`.
pub(crate) const LIST_ACCESS_KEYS_LDAP_BULK: &str = "rustfs:ListAccessKeysLdapBulk";
pub(crate) const LIST_ACCESS_KEYS_LDAP_BULK_PATH: &str = "/rustfs/admin/v3/idp/ldap/list-access-keys-bulk";
/// `rustfs:ListAccessKeysOpenidBulk`.
pub(crate) const LIST_ACCESS_KEYS_OPENID_BULK: &str = "rustfs:ListAccessKeysOpenidBulk";
pub(crate) const LIST_ACCESS_KEYS_OPENID_BULK_PATH: &str = "/rustfs/admin/v3/idp/openid/list-access-keys-bulk";
/// Asked about every account a bulk listing names; RustFS evaluates it deny-only for the caller.
pub(crate) const LIST_ACCESS_KEYS_ACTION: &str = "admin:ListServiceAccounts";
/// What every account needs on top: RustFS's `all` gate.
pub(crate) const LIST_USERS_ACTION: &str = "admin:ListUsers";
/// The accounts a bulk listing names: `users`, repeated, or every account with `all=true`.
pub(crate) const USERS_SUBJECTS: SubjectRule = SubjectRule::Set {
    param: "users",
    everyone: Some(Everyone {
        param: "all",
        action: LIST_USERS_ACTION,
    }),
};

/// `rustfs:GetBucketQuotaByQuery`.
pub(crate) const GET_BUCKET_QUOTA_BY_QUERY: &str = "rustfs:GetBucketQuotaByQuery";
pub(crate) const GET_BUCKET_QUOTA_BY_QUERY_PATH: &str = "/rustfs/admin/v3/get-bucket-quota";

/// `rustfs:OidcListProviders`, and the rest of RustFS's OIDC bootstrap: each action is the
/// operation's own vendor label, because RustFS evaluates no IAM action on these routes.
pub(crate) const OIDC_LIST_PROVIDERS: &str = "rustfs:OidcListProviders";
pub(crate) const OIDC_LIST_PROVIDERS_PATH: &str = "/rustfs/admin/v3/oidc/providers";
/// `rustfs:OidcAuthorize`.
pub(crate) const OIDC_AUTHORIZE: &str = "rustfs:OidcAuthorize";
pub(crate) const OIDC_AUTHORIZE_TEMPLATE: &str = "/rustfs/admin/v3/oidc/authorize/{provider_id}";
/// `rustfs:OidcCallback`.
pub(crate) const OIDC_CALLBACK: &str = "rustfs:OidcCallback";
pub(crate) const OIDC_CALLBACK_TEMPLATE: &str = "/rustfs/admin/v3/oidc/callback/{provider_id}";
/// `rustfs:OidcLogout`.
pub(crate) const OIDC_LOGOUT: &str = "rustfs:OidcLogout";
pub(crate) const OIDC_LOGOUT_PATH: &str = "/rustfs/admin/v3/oidc/logout";
/// The four anonymous operations, which the posture report must name and nothing else here may add.
pub(crate) const OIDC_BOOTSTRAP: [&str; 4] = [OIDC_AUTHORIZE, OIDC_CALLBACK, OIDC_LIST_PROVIDERS, OIDC_LOGOUT];

/// The thirteen names, by marker index.
const NAMES: [&str; 13] = [
    LIST_POOLS,
    SELF_ACCOUNT_INFO,
    GET_USER_INFO,
    GET_BUCKET_QUOTA,
    SERVICE_RESTART,
    LIST_ACCESS_KEYS_BULK,
    LIST_ACCESS_KEYS_LDAP_BULK,
    LIST_ACCESS_KEYS_OPENID_BULK,
    GET_BUCKET_QUOTA_BY_QUERY,
    OIDC_LIST_PROVIDERS,
    OIDC_AUTHORIZE,
    OIDC_CALLBACK,
    OIDC_LOGOUT,
];

const BULK: AuthRequirement = AuthRequirement::new(LIST_ACCESS_KEYS_ACTION, ResourceShape::Service).about_subject(USERS_SUBJECTS);

/// The thirteen requirements, by marker index.
pub(crate) const REQUIREMENTS: [AuthRequirement; 13] = [
    AuthRequirement::any_of(LIST_POOLS_ACTIONS, ResourceShape::Service),
    AuthRequirement::new(SELF_ACCOUNT_INFO_ACTION, ResourceShape::Service).about_subject(SubjectRule::Caller),
    AuthRequirement::new(GET_USER_INFO_ACTION, ResourceShape::Service).about_subject(USER_SUBJECT),
    AuthRequirement::new(GET_BUCKET_QUOTA_ACTION, ResourceShape::Bucket),
    AuthRequirement::new(SERVICE_RESTART_ACTION, ResourceShape::Service),
    BULK,
    BULK,
    BULK,
    AuthRequirement::new(GET_BUCKET_QUOTA_ACTION, ResourceShape::Bucket),
    AuthRequirement::new(OIDC_LIST_PROVIDERS, ResourceShape::Service),
    AuthRequirement::new(OIDC_AUTHORIZE, ResourceShape::Service),
    AuthRequirement::new(OIDC_CALLBACK, ResourceShape::Service),
    AuthRequirement::new(OIDC_LOGOUT, ResourceShape::Service),
];

/// The first precedence; the thirteen take the next thirteen.
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
/// `MultipleActions`, about a set of accounts.
pub(crate) type ListAccessKeysBulk = Class<5>;
/// The LDAP variant.
pub(crate) type ListAccessKeysLdapBulk = Class<6>;
/// The OpenID variant.
pub(crate) type ListAccessKeysOpenidBulk = Class<7>;
/// `S3Action`, with the bucket in the query.
pub(crate) type GetBucketQuotaByQuery = Class<8>;
/// `OidcBootstrap`: the provider listing.
pub(crate) type OidcListProviders = Class<9>;
/// `OidcBootstrap`: the redirect to the provider.
pub(crate) type OidcAuthorize = Class<10>;
/// `OidcBootstrap`: the provider's redirect back.
pub(crate) type OidcCallback = Class<11>;
/// `OidcBootstrap`: the logout redirect.
pub(crate) type OidcLogout = Class<12>;

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
static LIST_ACCESS_KEYS_BULK_ROWS: &[ClaimedRow] = &[
    row(LIST_ACCESS_KEYS_BULK_PATH, GET),
    row("/minio/admin/v3/list-access-keys-bulk", GET),
];
static LIST_ACCESS_KEYS_LDAP_BULK_ROWS: &[ClaimedRow] = &[
    row(LIST_ACCESS_KEYS_LDAP_BULK_PATH, GET),
    row("/minio/admin/v3/idp/ldap/list-access-keys-bulk", GET),
];
static LIST_ACCESS_KEYS_OPENID_BULK_ROWS: &[ClaimedRow] = &[
    row(LIST_ACCESS_KEYS_OPENID_BULK_PATH, GET),
    row("/minio/admin/v3/idp/openid/list-access-keys-bulk", GET),
];
static GET_BUCKET_QUOTA_BY_QUERY_ROWS: &[ClaimedRow] = &[
    row(GET_BUCKET_QUOTA_BY_QUERY_PATH, GET),
    row("/minio/admin/v3/get-bucket-quota", GET),
];
static OIDC_LIST_PROVIDERS_ROWS: &[ClaimedRow] =
    &[row(OIDC_LIST_PROVIDERS_PATH, GET), row("/minio/admin/v3/oidc/providers", GET)];
static OIDC_AUTHORIZE_ROWS: &[ClaimedRow] = &[
    row(OIDC_AUTHORIZE_TEMPLATE, GET),
    row("/minio/admin/v3/oidc/authorize/{provider_id}", GET),
];
static OIDC_CALLBACK_ROWS: &[ClaimedRow] = &[
    row(OIDC_CALLBACK_TEMPLATE, GET),
    row("/minio/admin/v3/oidc/callback/{provider_id}", GET),
];
static OIDC_LOGOUT_ROWS: &[ClaimedRow] = &[row(OIDC_LOGOUT_PATH, GET), row("/minio/admin/v3/oidc/logout", GET)];

/// The thirteen routes, by marker index. `quota` is the template-bound quota route's binding and
/// `by_query` the query-bound one's; tests swap either.
pub(crate) fn routes(quota: Option<BucketParam>, by_query: Option<BucketParam>) -> [ClaimedRoute; 13] {
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
        route(3, GET_BUCKET_QUOTA_ROWS, quota),
        route(4, SERVICE_RESTART_ROWS, None),
        route(5, LIST_ACCESS_KEYS_BULK_ROWS, None),
        route(6, LIST_ACCESS_KEYS_LDAP_BULK_ROWS, None),
        route(7, LIST_ACCESS_KEYS_OPENID_BULK_ROWS, None),
        route(8, GET_BUCKET_QUOTA_BY_QUERY_ROWS, by_query),
        route(9, OIDC_LIST_PROVIDERS_ROWS, None),
        route(10, OIDC_AUTHORIZE_ROWS, None),
        route(11, OIDC_CALLBACK_ROWS, None),
        route(12, OIDC_LOGOUT_ROWS, None),
    ]
}

// ── the handler ───────────────────────────────────────────────────────────────────────────────

/// The accounts a context carries, as the handler answers them: `"caller"`, the named accounts
/// in order, or `"everyone"`.
fn subjects_json(subjects: Option<&Subjects>) -> serde_json::Value {
    match subjects {
        None => serde_json::Value::Null,
        Some(Subjects::One(Subject::Caller)) => serde_json::json!("caller"),
        Some(Subjects::One(subject)) => serde_json::json!([subject.name()]),
        Some(Subjects::Each(each)) => serde_json::json!(each.iter().filter_map(Subject::name).collect::<Vec<_>>()),
        Some(Subjects::Everyone) => serde_json::json!("everyone"),
    }
}

impl Backend {
    /// Records what it was handed and answers with the bucket and accounts it acts on, read from
    /// the context and never from the query.
    fn class<const N: usize>(&self, request: &Req<Class<N>>) -> HandlerResult<Class<N>> {
        let context = request.context();
        self.see(context);
        Ok(Resp::new(json(&serde_json::json!({
            "operation": context.operation(),
            "bucket": context.bucket().map(|bucket| bucket.as_str().to_owned()),
            "subject": context.subject().and_then(|subject| subject.name().map(str::to_owned)),
            "subjects": subjects_json(context.subjects()),
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

    static SPECS: [OperationSpec; 13] = [
        spec(0),
        spec(1),
        spec(2),
        spec(3),
        spec(4),
        spec(5),
        spec(6),
        spec(7),
        spec(8),
        spec(9),
        spec(10),
        spec(11),
        spec(12),
    ];

    /// Privileged and header-signed only, like every claimed operation until a client presigns;
    /// the four OIDC bootstrap operations also admit anonymous requests, each by its own opt-in,
    /// which the posture report lists and the overlay acknowledges.
    static FLOORS: [OperationFloor; 13] = [
        OperationFloor::custom(NAMES[0], SigService::S3),
        OperationFloor::custom(NAMES[1], SigService::S3),
        OperationFloor::custom(NAMES[2], SigService::S3),
        OperationFloor::custom(NAMES[3], SigService::S3),
        OperationFloor::custom(NAMES[4], SigService::S3),
        OperationFloor::custom(NAMES[5], SigService::S3),
        OperationFloor::custom(NAMES[6], SigService::S3),
        OperationFloor::custom(NAMES[7], SigService::S3),
        OperationFloor::custom(NAMES[8], SigService::S3),
        OperationFloor::custom(NAMES[9], SigService::S3).allow_anonymous_after_listing_in_the_posture_report(),
        OperationFloor::custom(NAMES[10], SigService::S3).allow_anonymous_after_listing_in_the_posture_report(),
        OperationFloor::custom(NAMES[11], SigService::S3).allow_anonymous_after_listing_in_the_posture_report(),
        OperationFloor::custom(NAMES[12], SigService::S3).allow_anonymous_after_listing_in_the_posture_report(),
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
