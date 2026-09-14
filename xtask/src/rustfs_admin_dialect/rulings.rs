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
//! action: ADR-0025's action and subject rules, ADR-0026's account set, and ADR-0028's order-4
//! readings of both.
//!
//! Responsible for: [`RULINGS`], one per custom-auth route of a migrated group, and the shapes a
//! ruling is written in: an action rule, an optional subject rule, and the query value that
//! selects a form.
//! NOT responsible for: matching a ruling to its route, refusing a stale or missing one, or
//! checking a rule's shape (`super::plan` and `super::Rule::fault`).
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
    /// The account one query parameter names (ADR-0025).
    Query { param: &'static str, absent: Absent },
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
    }
}

const fn any_of(actions: &'static [&'static str]) -> Form {
    Form {
        query: None,
        rule: Ruled::AnyOf(actions),
        about: None,
    }
}

const fn service(value: &'static str, action: &'static str) -> Form {
    Form {
        query: Some(("action", value)),
        rule: Ruled::One(action),
        about: None,
    }
}

/// An own-account operation: RustFS evaluates no IAM action, so its action is a label in the
/// dialect's own namespace, RustFS's handler name without `Handler` (ADR-0025 (d), ADR-0028 (a)).
const fn own(label: &'static str) -> Form {
    Form {
        query: None,
        rule: Ruled::One(label),
        about: Some(About::Caller),
    }
}

/// `action` about the account the query parameter `param` names (ADR-0025 (d), ADR-0028 (b)).
const fn named(action: &'static str, param: &'static str, absent: Absent) -> Form {
    Form {
        query: None,
        rule: Ruled::One(action),
        about: Some(About::Query { param, absent }),
    }
}

/// The three bulk access-key listings: `admin:ListServiceAccounts` about each `users` account,
/// and `admin:ListUsers` on top for `all=true` (ADR-0026 (c)).
const BULK: &[Form] = &[Form {
    query: None,
    rule: Ruled::One("admin:ListServiceAccounts"),
    about: Some(About::Set {
        param: "users",
        everyone: Some(("all", "admin:ListUsers")),
    }),
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
    // ── order 4: the account a query parameter names (ADR-0025 (d), ADR-0028 (b)) ──
    ruling(
        "DELETE",
        "/rustfs/admin/v3/delete-service-account",
        "ContextualAuthorization",
        &[named("admin:RemoveServiceAccount", "accessKey", Absent::Refuse)],
    ),
    ruling(
        "DELETE",
        "/rustfs/admin/v3/delete-service-accounts",
        "ContextualAuthorization",
        &[named("admin:RemoveServiceAccount", "accessKey", Absent::Refuse)],
    ),
    ruling(
        "GET",
        "/rustfs/admin/v3/idp/ldap/list-access-keys",
        "ContextualAuthorization",
        &[named("admin:ListServiceAccounts", "userDN", Absent::Caller)],
    ),
    ruling(
        "GET",
        "/rustfs/admin/v3/info-access-key",
        "ContextualAuthorization",
        &[named("admin:ListServiceAccounts", "accessKey", Absent::Caller)],
    ),
    ruling(
        "GET",
        "/rustfs/admin/v3/info-service-account",
        "ContextualAuthorization",
        &[named("admin:ListServiceAccounts", "accessKey", Absent::Refuse)],
    ),
    ruling(
        "GET",
        "/rustfs/admin/v3/list-service-accounts",
        "ContextualAuthorization",
        &[named("admin:ListServiceAccounts", "user", Absent::Caller)],
    ),
    ruling(
        "GET",
        "/rustfs/admin/v3/user-info",
        "ContextualAuthorization",
        &[named("admin:GetUser", "accessKey", Absent::Refuse)],
    ),
    ruling(
        "POST",
        "/rustfs/admin/v3/update-service-account",
        "ContextualAuthorization",
        &[named("admin:UpdateServiceAccount", "accessKey", Absent::Refuse)],
    ),
    ruling(
        "PUT",
        "/rustfs/admin/v3/add-user",
        "ContextualAuthorization",
        &[named("admin:CreateUser", "accessKey", Absent::Refuse)],
    ),
    // ── order 4: any-of listings and account sets (ADR-0025 (d), ADR-0026 (c)) ──
    ruling("GET", "/rustfs/admin/v3/idp/builtin/policy-entities", "MultipleActions", POLICY_ENTITIES),
    ruling("GET", "/rustfs/admin/v3/idp/ldap/policy-entities", "MultipleActions", POLICY_ENTITIES),
    ruling("GET", "/rustfs/admin/v3/list-access-keys-bulk", "MultipleActions", BULK),
    ruling("GET", "/rustfs/admin/v3/idp/ldap/list-access-keys-bulk", "MultipleActions", BULK),
    ruling("GET", "/rustfs/admin/v3/idp/openid/list-access-keys-bulk", "MultipleActions", BULK),
];
