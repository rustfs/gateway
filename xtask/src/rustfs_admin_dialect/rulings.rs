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

//! The rulings for the migrated groups' custom-auth routes, which the inventory records without an
//! action: ADR-0025's action and subject rules, ADR-0026's account set, ADR-0028's order-4
//! readings of both, and ADR-0030's order-5 bucket rulings; and the routes whose bucket is a query
//! parameter (ADR-0026 (e), ADR-0030).
//!
//! Responsible for: [`RULINGS`], one per custom-auth route of a migrated group, and the shapes a
//! ruling is written in: an action rule, an optional subject rule, and the query value that
//! selects a form; [`QUERY_BUCKETS`], the routes that name their bucket in the query; [`STAYS`],
//! the routes that stay with RustFS; and [`FORMS`], the routes served behind a form claim.
//! NOT responsible for: matching a ruling or a query bucket to its route, refusing a stale or
//! missing one, or checking a rule's shape (`super::plan` and `super::Rule::fault`).
//! Upstream: the ADRs, read against RustFS's handlers at the inventory's commit. Downstream:
//! `super::plan`.

/// An action rule a ruling decides.
#[derive(Clone, Copy)]
pub(super) enum Ruled {
    One(&'static str),
    AnyOf(&'static [&'static str]),
}

/// What an absent or empty subject parameter means (core's `WhenAbsent`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Absent {
    /// The caller's own account.
    Caller,
    /// A `400` before authentication.
    Refuse,
}

/// Whose account a ruled operation acts on (core's `SubjectRule`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum About {
    /// Only the caller's own account, under the operation's own vendor label (ADR-0025).
    Caller,
    /// The account one query parameter names, under its canonical spelling or one of RustFS's
    /// alias spellings (ADR-0025, ADR-0029).
    Query {
        param: &'static str,
        aliases: &'static [&'static str],
        absent: Absent,
    },
    /// Each account a repeated parameter names, or every account under a flag that needs a
    /// broader action on top: `(flag, action)` (ADR-0026).
    Set {
        param: &'static str,
        everyone: Option<(&'static str, &'static str)>,
    },
}

/// One form of a ruled route: the query value that selects it, its action rule, and whose
/// account it acts on.
pub(super) struct Form {
    pub(super) query: Option<(&'static str, &'static str)>,
    pub(super) rule: Ruled,
    pub(super) about: Option<About>,
    /// Whether the operation opts in to anonymous requests (ADR-0026 (f)): only a route the
    /// inventory records as anonymous, and only under a label in the dialect's own namespace.
    pub(super) anonymous: bool,
}

/// ADR-0025's ruling for a custom-auth route, which the inventory records without an action.
pub(super) struct Ruling {
    pub(super) method: &'static str,
    pub(super) path: &'static str,
    /// The custom-auth class the inventory must still record, so a changed row reopens the ruling.
    pub(super) auth_detail: &'static str,
    pub(super) forms: &'static [Form],
}

const fn one(action: &'static str) -> Form {
    Form {
        query: None,
        rule: Ruled::One(action),
        about: None,
        anonymous: false,
    }
}

const fn any_of(actions: &'static [&'static str]) -> Form {
    Form {
        query: None,
        rule: Ruled::AnyOf(actions),
        about: None,
        anonymous: false,
    }
}

const fn service(value: &'static str, action: &'static str) -> Form {
    Form {
        query: Some(("action", value)),
        rule: Ruled::One(action),
        about: None,
        anonymous: false,
    }
}

/// An own-account operation: RustFS evaluates no IAM action, so its action is a label in the
/// dialect's own namespace, RustFS's handler name without `Handler` (ADR-0025 (d), ADR-0028 (a)).
const fn own(label: &'static str) -> Form {
    Form {
        query: None,
        rule: Ruled::One(label),
        about: Some(About::Caller),
        anonymous: false,
    }
}

/// An anonymous bootstrap operation: RustFS makes no IAM check, so its action is a label in the
/// dialect's own namespace, RustFS's handler name without `Handler`; the floor opts in to
/// anonymous requests and the authorizer is still asked, with no identity (ADR-0026 (f),
/// ADR-0032 (a)).
const fn bootstrap(label: &'static str) -> Form {
    Form {
        query: None,
        rule: Ruled::One(label),
        about: None,
        anonymous: true,
    }
}

/// `action` about the account the query parameter `param`, or one of its `aliases`, names
/// (ADR-0025 (d), ADR-0028 (b), ADR-0029).
const fn named(action: &'static str, param: &'static str, aliases: &'static [&'static str], absent: Absent) -> Form {
    Form {
        query: None,
        rule: Ruled::One(action),
        about: Some(About::Query { param, aliases, absent }),
        anonymous: false,
    }
}

/// `accessKey` and RustFS's serde alias for it, `access-key` (`AccessKeyQuery`, `AddUserQuery`).
const ACCESS_KEY: &[&str] = &["access-key"];
/// RustFS's `SingleUserAccessKeysQuery` reads the DN as `userDN`, `user-dn` or `user`.
const USER_DN: &[&str] = &["user-dn", "user"];

/// The three bulk access-key listings: `admin:ListServiceAccounts` about each `users` account,
/// and `admin:ListUsers` on top for `all=true` (ADR-0026 (c)).
const BULK: &[Form] = &[Form {
    query: None,
    rule: Ruled::One("admin:ListServiceAccounts"),
    about: Some(About::Set {
        param: "users",
        everyone: Some(("all", "admin:ListUsers")),
    }),
    anonymous: false,
}];

/// RustFS's policy-entities gate: any one of the three listing actions (`policies.rs`).
const POLICY_ENTITIES: &[Form] = &[any_of(&["admin:ListGroups", "admin:ListUsers", "admin:ListUserPolicies"])];

const fn ruling(method: &'static str, path: &'static str, auth_detail: &'static str, forms: &'static [Form]) -> Ruling {
    Ruling {
        method,
        path,
        auth_detail,
        forms,
    }
}

/// The routes that name their bucket in a query parameter, read exactly once before
/// authentication (`BucketParam::Query`, ADR-0026 (e), ADR-0030 (b)): `(method, path, parameter)`.
/// Both are the `quota_handler` group's compat spellings of the `quota/{bucket}` routes, whose
/// handlers read `bucket` from the query when the template has none (`quota.rs`,
/// `bucket_from_params_or_query`).
pub(super) const QUERY_BUCKETS: &[(&str, &str, &str)] = &[
    ("GET", "/rustfs/admin/v3/get-bucket-quota", "bucket"),
    ("PUT", "/rustfs/admin/v3/set-bucket-quota", "bucket"),
];

/// The routes that stay with RustFS, each for a recorded reason (ADR-0026 (g), (h), ADR-0032 (b)):
/// `(method, path, reason)`. They are declared as no operation and listed in the dialect's
/// `STAYING`, so the census stays exact.
pub(super) const STAYS: &[(&str, &str, &str)] = &[
    (
        "GET",
        "/rustfs/admin/v3/object-zip-downloads/{id}.zip",
        "An affixed `{id}.zip` parameter and a bearer token in the query: it needs a per-operation bearer scheme on the floor (ADR-0026 (g)).",
    ),
    (
        "POST",
        "/rustfs/admin/v3/object-zip-downloads",
        "It authorises S3 resources named in its body and only mints the token the download route consumes, which stays with RustFS (ADR-0025 (d), ADR-0026 (g), ADR-0032 (b)).",
    ),
    (
        "GET",
        "/health",
        "The server's probe layer, ahead of the S3 service; a one-segment path is no claim (ADR-0026 (h)).",
    ),
    (
        "HEAD",
        "/health",
        "The server's probe layer, ahead of the S3 service; a one-segment path is no claim (ADR-0026 (h)).",
    ),
    (
        "GET",
        "/health/ready",
        "The server's probe layer, ahead of the S3 service (ADR-0026 (h)).",
    ),
    (
        "HEAD",
        "/health/ready",
        "The server's probe layer, ahead of the S3 service (ADR-0026 (h)).",
    ),
];

/// The routes the dialect serves behind a form claim rather than a path claim (ADR-0041):
/// `(method, path, auth_detail)`, the custom-auth class the inventory must still record, so a changed
/// row reopens the ruling. Each is one generated operation outside `fold_every_operation`.
pub(super) const FORMS: &[(&str, &str, &str)] = &[("POST", "/", "StsFormPost")];

/// The rulings for the migrated groups' custom-auth routes, in the inventory's order within each
/// migrated order.
pub(super) const RULINGS: &[Ruling] = &[
    // ── order 1 and 3 (ADR-0025) ──
    ruling(
        "GET",
        "/rustfs/admin/v3/datausageinfo",
        "MultipleActions",
        &[any_of(&["admin:DataUsageInfo", "s3:ListBucket"])],
    ),
    ruling("GET", "/rustfs/admin/v3/inspect-data", "NotImplemented", &[one("admin:InspectData")]),
    ruling("POST", "/rustfs/admin/v3/inspect-data", "NotImplemented", &[one("admin:InspectData")]),
    ruling(
        "POST",
        "/rustfs/admin/v3/service",
        "NotImplemented",
        &[
            service("restart", "admin:ServiceRestart"),
            service("stop", "admin:ServiceStop"),
            service("freeze", "admin:ServiceFreeze"),
            service("unfreeze", "admin:ServiceFreeze"),
        ],
    ),
    ruling(
        "GET",
        "/rustfs/admin/v3/pools/list",
        "MultipleActions",
        &[any_of(&["admin:ServerInfo", "admin:Decommission"])],
    ),
    ruling(
        "GET",
        "/rustfs/admin/v3/pools/status",
        "MultipleActions",
        &[any_of(&["admin:ServerInfo", "admin:Decommission"])],
    ),
    // ── order 4: own-account (ADR-0025 (d), ADR-0028 (a)) ──
    ruling("GET", "/rustfs/admin/v3/account/info", "CredentialOnly", &[own("rustfs:SelfAccountInfo")]),
    ruling("GET", "/rustfs/admin/v3/account/mfa", "CredentialOnly", &[own("rustfs:AccountMfaStatus")]),
    ruling("GET", "/rustfs/admin/v3/accountinfo", "S3Action", &[own("rustfs:AccountInfo")]),
    ruling("GET", "/rustfs/admin/v3/mfa/challenge", "CredentialOnly", &[own("rustfs:MfaChallenge")]),
    ruling(
        "POST",
        "/rustfs/admin/v3/account/mfa/activate",
        "CredentialOnly",
        &[own("rustfs:AccountMfaActivate")],
    ),
    ruling(
        "POST",
        "/rustfs/admin/v3/account/mfa/disable",
        "CredentialOnly",
        &[own("rustfs:AccountMfaDisable")],
    ),
    ruling(
        "POST",
        "/rustfs/admin/v3/account/mfa/enroll",
        "CredentialOnly",
        &[own("rustfs:AccountMfaEnroll")],
    ),
    ruling(
        "POST",
        "/rustfs/admin/v3/account/mfa/recovery-codes",
        "CredentialOnly",
        &[own("rustfs:AccountMfaRecoveryCodes")],
    ),
    ruling(
        "POST",
        "/rustfs/admin/v3/account/password",
        "CredentialOnly",
        &[own("rustfs:ChangeOwnPassword")],
    ),
    // ── order 4: misclassified as own-account; RustFS checks the action (ADR-0025 (d)) ──
    ruling(
        "GET",
        "/rustfs/admin/v3/list-remote-targets",
        "CredentialOnly",
        &[one("admin:GetBucketTarget")],
    ),
    // ── order 4: the account a query parameter names (ADR-0025 (d), ADR-0028 (b)), in every
    //    spelling RustFS reads (ADR-0029) ──
    ruling(
        "DELETE",
        "/rustfs/admin/v3/delete-service-account",
        "ContextualAuthorization",
        &[named("admin:RemoveServiceAccount", "accessKey", ACCESS_KEY, Absent::Refuse)],
    ),
    ruling(
        "DELETE",
        "/rustfs/admin/v3/delete-service-accounts",
        "ContextualAuthorization",
        &[named("admin:RemoveServiceAccount", "accessKey", ACCESS_KEY, Absent::Refuse)],
    ),
    ruling(
        "GET",
        "/rustfs/admin/v3/idp/ldap/list-access-keys",
        "ContextualAuthorization",
        &[named("admin:ListServiceAccounts", "userDN", USER_DN, Absent::Caller)],
    ),
    ruling(
        "GET",
        "/rustfs/admin/v3/info-access-key",
        "ContextualAuthorization",
        &[named("admin:ListServiceAccounts", "accessKey", ACCESS_KEY, Absent::Caller)],
    ),
    ruling(
        "GET",
        "/rustfs/admin/v3/info-service-account",
        "ContextualAuthorization",
        &[named("admin:ListServiceAccounts", "accessKey", ACCESS_KEY, Absent::Refuse)],
    ),
    ruling(
        "GET",
        "/rustfs/admin/v3/list-service-accounts",
        "ContextualAuthorization",
        &[named("admin:ListServiceAccounts", "user", &[], Absent::Caller)],
    ),
    ruling(
        "GET",
        "/rustfs/admin/v3/user-info",
        "ContextualAuthorization",
        &[named("admin:GetUser", "accessKey", ACCESS_KEY, Absent::Refuse)],
    ),
    ruling(
        "POST",
        "/rustfs/admin/v3/update-service-account",
        "ContextualAuthorization",
        &[named("admin:UpdateServiceAccount", "accessKey", ACCESS_KEY, Absent::Refuse)],
    ),
    ruling(
        "PUT",
        "/rustfs/admin/v3/add-user",
        "ContextualAuthorization",
        &[named("admin:CreateUser", "accessKey", ACCESS_KEY, Absent::Refuse)],
    ),
    // ── order 4: any-of listings and account sets (ADR-0025 (d), ADR-0026 (c)) ──
    ruling("GET", "/rustfs/admin/v3/idp/builtin/policy-entities", "MultipleActions", POLICY_ENTITIES),
    ruling("GET", "/rustfs/admin/v3/idp/ldap/policy-entities", "MultipleActions", POLICY_ENTITIES),
    ruling("GET", "/rustfs/admin/v3/list-access-keys-bulk", "MultipleActions", BULK),
    ruling("GET", "/rustfs/admin/v3/idp/ldap/list-access-keys-bulk", "MultipleActions", BULK),
    ruling("GET", "/rustfs/admin/v3/idp/openid/list-access-keys-bulk", "MultipleActions", BULK),
    // ── order 5: the S3 quota action on the bound bucket (ADR-0025 (d), ADR-0030) ──
    ruling("GET", "/rustfs/admin/v3/get-bucket-quota", "S3Action", &[one("s3:GetBucketQuota")]),
    ruling("GET", "/rustfs/admin/v3/quota-stats/{bucket}", "S3Action", &[one("s3:GetBucketQuota")]),
    ruling("GET", "/rustfs/admin/v3/quota/{bucket}", "S3Action", &[one("s3:GetBucketQuota")]),
    ruling("POST", "/rustfs/admin/v3/quota-check/{bucket}", "S3Action", &[one("s3:GetBucketQuota")]),
    // ── order 5: the usage gate, any-of and bound to the bucket RustFS ignores (ADR-0025 (d)) ──
    ruling(
        "GET",
        "/rustfs/admin/v3/usage/{bucket}",
        "MultipleActions",
        &[any_of(&["admin:DataUsageInfo", "s3:ListBucket"])],
    ),
    // ── order 7: the anonymous OIDC bootstrap (ADR-0026 (f), ADR-0032 (a)) ──
    ruling(
        "GET",
        "/rustfs/admin/v3/oidc/authorize/{provider_id}",
        "OidcBootstrap",
        &[bootstrap("rustfs:OidcAuthorize")],
    ),
    ruling(
        "GET",
        "/rustfs/admin/v3/oidc/callback/{provider_id}",
        "OidcBootstrap",
        &[bootstrap("rustfs:OidcCallback")],
    ),
    ruling("GET", "/rustfs/admin/v3/oidc/logout", "OidcBootstrap", &[bootstrap("rustfs:OidcLogout")]),
    ruling(
        "GET",
        "/rustfs/admin/v3/oidc/providers",
        "OidcBootstrap",
        &[bootstrap("rustfs:ListOidcProviders")],
    ),
];
