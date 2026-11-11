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
//! the routes that stay with RustFS; [`FORMS`], the routes served behind a form claim; and
//! [`EXTENSIONS`], the S3-shaped extension routes and the operation each becomes;
//! [`PRESIGNED_EXTENSIONS`], the ones a RustFS client is shown to presign; and [`RETAINED`], the
//! checks RustFS's handlers keep that the floor does not represent.
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
    /// A paragraph the generated module's documentation carries, when the ruling needs one that
    /// its shape alone does not say; empty for almost every ruling.
    pub(super) note: &'static str,
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
        note: "",
    }
}

/// `ruling` with a paragraph for the generated module's documentation.
const fn noted(ruling: Ruling, note: &'static str) -> Ruling {
    Ruling { note, ..ruling }
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

/// RustFS's S3-shaped extension routes (rustfs/backlog#2753): the variant name the inventory
/// records, and the operation it becomes. The inventory's order is the order RustFS's router tries
/// the discriminators in, which is the order of the generated rows.
pub(super) const EXTENSIONS: &[(&str, &str)] = &[
    ("ReplicationExtRoute::ResetStart", "ResetBucketReplication"),
    ("ReplicationExtRoute::ResetStatus", "GetReplicationResetStatus"),
    ("ReplicationExtRoute::MetricsV2", "GetReplicationMetricsV2"),
    ("ReplicationExtRoute::MetricsV1", "GetReplicationMetrics"),
    ("ReplicationExtRoute::Check", "CheckReplication"),
    ("MiscExtRoute::ObjectLambda[object]", "InvokeObjectLambda"),
    ("MiscExtRoute::ListenNotification[service]", "ListenNotification"),
    ("MiscExtRoute::ListenNotification[bucket]", "ListenBucketNotification"),
];

/// The extension routes a RustFS client is shown to presign, which ADR-0024 (f) makes the
/// condition for admitting a presigned URL (rustfs/gateway#1576): the variant name the inventory
/// records, and the evidence. Each gets `admin::presigned_floor`; every other extension route
/// keeps the privileged, header-only floor.
pub(super) const PRESIGNED_EXTENSIONS: &[(&str, &str)] = &[(
    "MiscExtRoute::ObjectLambda[object]",
    // RustFS's end-to-end test presigns `GET /{bucket}/{key}?lambdaArn=…` with `lambdaArn` inside
    // the signed query and expects `200`.
    "https://github.com/rustfs/rustfs/blob/443e8afee194fe38b32d62a9289a99c1f703715c/crates/e2e_test/src/object_lambda_test.rs#L608-L636",
)];

/// The extension routes whose request may name one object version, and the action RustFS asks
/// such a request instead of the route's own (rustfs/gateway#1576): RustFS's object lambda handler
/// authorises through its `GetObject` check, which asks `s3:GetObjectVersion` when `versionId` is
/// present (GHSA-3ppv). Each renders `AuthRequirement::with_version_requirement`.
pub(super) const VERSIONED_EXTENSIONS: &[(&str, &str)] = &[("MiscExtRoute::ObjectLambda[object]", "s3:GetObjectVersion")];

/// A check RustFS's handler makes that the gateway's floor does not represent, so the floor is
/// never read as the route's whole authorisation (rustfs/gateway#1232). The check stays with the
/// handler; `hand_on_body` makes the gateway hand the body on unread, so that check still runs
/// before anything reads what the body carries.
#[derive(Clone, Copy)]
pub(super) struct Retained {
    pub(super) method: &'static str,
    pub(super) path: &'static str,
    /// Stable labels, recorded in the operation's `RouteRecord::retained`.
    pub(super) checks: &'static [&'static str],
    pub(super) hand_on_body: bool,
    /// The paragraph the generated module's documentation carries.
    pub(super) note: &'static str,
}

/// RustFS refuses unless its own listener completed TLS (`tls_certificate.rs`, `require_native_tls`).
pub(super) const NATIVE_TLS: &str = "native-tls-listener";
/// RustFS refuses root, temporary (session-token) and service-account callers before the action
/// check (`plugin_delegation.rs`, `owner`).
pub(super) const ORIGINAL_USER: &str = "original-user";
/// RustFS refuses when an external policy plugin is configured (`plugin_attempt.rs`,
/// `require_builtin_authorization`).
pub(super) const BUILTIN_IAM: &str = "builtin-iam";

const TLS_NOTE: &str = "RustFS's handler also refuses unless its own listener completed TLS (`tls_certificate.rs`, `require_native_tls`); a forwarded `https` header does not count. That check is retained in the handler: the gateway's floor cannot require it, because the gateway's \"transport was secure\" fact also counts TLS declared by a fronting proxy, which RustFS refuses here.";
const TLS_PUBLISH_NOTE: &str = "RustFS's handler also refuses unless its own listener completed TLS (`tls_certificate.rs`, `require_native_tls`), and checks that before it reads the body, which carries `private_key_pem`. That check is retained in the handler: the gateway's floor cannot require it, because the gateway's \"transport was secure\" fact also counts TLS declared by a fronting proxy, which RustFS refuses here. So the gateway hands the body on unread rather than buffering it, and a private key sent over a cleartext connection is never read before the handler refuses it.";
const ORIGINAL_USER_NOTE: &str = "RustFS's handler also refuses the root credential, temporary (session-token) credentials and service accounts before it checks the action (`plugin_delegation.rs`, `owner`). That check is retained in the handler: the gateway's floor has no rule on the kind of principal, so the floor admits callers RustFS refuses here.";
const ISSUE_ATTEMPT_NOTE: &str = "RustFS's handler also refuses when an external policy plugin is configured (`plugin_attempt.rs`, `require_builtin_authorization`), and refuses the root credential, temporary (session-token) credentials and service accounts before it checks the action (`plugin_delegation.rs`, `owner`). Both checks are retained in the handler: the gateway's floor has no rule on either, so the floor admits callers RustFS refuses here.";

const fn delegation(method: &'static str, path: &'static str) -> Retained {
    Retained {
        method,
        path,
        checks: &[ORIGINAL_USER],
        hand_on_body: false,
        note: ORIGINAL_USER_NOTE,
    }
}

/// Every route whose RustFS handler keeps a check the floor does not represent.
pub(super) const RETAINED: &[Retained] = &[
    Retained {
        method: "GET",
        path: "/rustfs/admin/v3/tls/certificate-state",
        checks: &[NATIVE_TLS],
        hand_on_body: false,
        note: TLS_NOTE,
    },
    Retained {
        method: "POST",
        path: "/rustfs/admin/v3/tls/certificate",
        checks: &[NATIVE_TLS],
        hand_on_body: true,
        note: TLS_PUBLISH_NOTE,
    },
    delegation("POST", "/rustfs/admin/v3/plugin-delegations"),
    delegation("GET", "/rustfs/admin/v3/plugin-delegations/{id}"),
    delegation("POST", "/rustfs/admin/v3/plugin-delegations/{id}/revoke"),
    delegation("POST", "/rustfs/admin/v3/plugin-delegations/{id}/submit"),
    delegation("POST", "/rustfs/admin/v3/plugin-delegations/{id}/runs/cancel"),
    delegation("POST", "/rustfs/admin/v3/plugin-delegations/{id}/runs/history"),
    delegation("POST", "/rustfs/admin/v3/plugin-delegations/{id}/runs/page"),
    delegation("POST", "/rustfs/admin/v3/plugin-delegations/{id}/runs/query"),
    delegation("POST", "/rustfs/admin/v3/plugin-delegations/{id}/runs/replay"),
    Retained {
        method: "POST",
        path: "/rustfs/admin/v3/plugin-delegations/{id}/issue-attempt",
        checks: &[ORIGINAL_USER, BUILTIN_IAM],
        hand_on_body: false,
        note: ISSUE_ATTEMPT_NOTE,
    },
];

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
    noted(
        ruling(
            "PUT",
            "/rustfs/admin/v3/update-group-members",
            "MultipleActions",
            &[any_of(&["admin:AddUserToGroup", "admin:RemoveUserFromGroup"])],
        ),
        "RustFS's handler first admits the caller on either group-membership action, and only after reading the JSON body asks again for the one its `isRemove` field selects (`group.rs`, `UpdateGroupMembers`); the gateway cannot ask the second question before the body is read (ADR-0025 (d), ADR-0032 (b)), so its floor is the first, any-of gate, and the body goes to the handler for the second.",
    ),
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
    // ── order 7: the object-zip-download pair, under the caller's own vendor labels
    //    (rustfs/backlog#2753). Both floors are privileged: ADR-0026 (g) refused admitting the
    //    download anonymously; the download's floor adds ADR-0042's `token` bearer claim. ──
    noted(
        ruling(
            "POST",
            "/rustfs/admin/v3/object-zip-downloads",
            "S3Action",
            &[own("rustfs:CreateObjectZipDownload")],
        ),
        "RustFS's handler authorises `s3:ListBucket` and `s3:GetObject` on each resource the JSON body names, after reading it, and then mints a download token for the caller; the gateway cannot ask those questions before the body is read (ADR-0025 (d), ADR-0032 (b)), so it authorises the caller's own label and hands the body over for the handler's own checks (rustfs/backlog#2753).",
    ),
    noted(
        ruling(
            "GET",
            "/rustfs/admin/v3/object-zip-downloads/{id}.zip",
            "CredentialOnly",
            &[own("rustfs:DownloadObjectZip")],
        ),
        "RustFS answers this route to whoever presents the `token` query parameter the POST minted, with no signature. Admitting it anonymously was refused (ADR-0026 (g)), so the floor stays privileged and header-signed and adds a `token` query bearer claim (ADR-0042, rustfs/gateway#1400): a request presenting no AWS credential and exactly one non-empty `token` is admitted only as far as the host's installed bearer verifier, which binds it to the path's last raw segment less its literal `.zip` and authenticates the principal the token was issued to. Without that verifier the minted URL is `403`; with it, a header-signed request must also carry a token issued to its signed principal. The `{id}.zip` segment is matched as one opaque `{+id}` capture (ADR-0040): the handler reads `id` as the whole segment, suffix included.",
    ),
];
