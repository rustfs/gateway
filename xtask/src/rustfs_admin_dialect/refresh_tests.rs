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

//! The routes RustFS gained after the first pinned inventory (rustfs/gateway#1232): each declared
//! operation mirrors RustFS's own gate, never a more permissive one.
//!
//! Responsible for: those assertions over the recorded plan, and the refusal of a ruling that
//! drops one of the group-membership actions. NOT responsible for: the fixtures (`tests.rs`), or
//! routing the generated operations (the dialect crate's tests).
//! Upstream: `super`, `super::rulings` and `super::tests`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use super::render::render_operation;
use super::retain;
use super::rulings::{NATIVE_TLS, ORIGINAL_USER, RETAINED, RULINGS, Retained};
use super::tests::recorded_plan;

/// Every operation of the refreshed groups, with the order it is planned at and the rule its floor
/// asks: RustFS's own route-policy action, or for the one custom route the any-of gate RustFS's
/// handler asks before it reads the body.
const REFRESHED: &[(&str, u8, &str)] = &[
    ("rustfs:DeleteIcebergBucketsByWarehouse", 6, "admin:SetTableBucket"),
    ("rustfs:DeleteIcebergByWarehouseCatalogDirectory", 6, "admin:MigrateTableCatalog"),
    ("rustfs:GetIcebergByWarehouseCatalogDirectory", 6, "admin:GetTableCatalog"),
    ("rustfs:GetV3PluginDelegationsById", 3, "admin:GetPluginDelegation"),
    ("rustfs:GetV3TierByTierDeletionCheck", 3, "admin:ListTier"),
    ("rustfs:GetV3TlsCertificateState", 2, "admin:TLSCertificateStatus"),
    ("rustfs:PostIcebergByWarehouseCatalogBackup", 6, "admin:MigrateTableCatalog"),
    ("rustfs:PostIcebergByWarehouseCatalogBackupExport", 6, "admin:MigrateTableCatalog"),
    ("rustfs:PostIcebergByWarehouseCatalogBackupImport", 6, "admin:MigrateTableCatalog"),
    ("rustfs:PostIcebergByWarehouseCatalogBackupPrepare", 6, "admin:MigrateTableCatalog"),
    ("rustfs:PostIcebergByWarehouseCatalogDirectory", 6, "admin:MigrateTableCatalog"),
    ("rustfs:PostIcebergByWarehouseCatalogRestore", 6, "admin:MigrateTableCatalog"),
    ("rustfs:PostV3PluginDelegations", 3, "admin:CreatePluginDelegation"),
    ("rustfs:PostV3PluginDelegationsByIdIssueAttempt", 3, "admin:IssuePluginAttempt"),
    ("rustfs:PostV3PluginDelegationsByIdRevoke", 3, "admin:RevokePluginDelegation"),
    ("rustfs:PostV3PluginDelegationsByIdRunsCancel", 3, "admin:CancelPluginRun"),
    ("rustfs:PostV3PluginDelegationsByIdRunsHistory", 3, "admin:ListPluginRuns"),
    ("rustfs:PostV3PluginDelegationsByIdRunsPage", 3, "admin:ListPluginRuns"),
    ("rustfs:PostV3PluginDelegationsByIdRunsQuery", 3, "admin:GetPluginRun"),
    ("rustfs:PostV3PluginDelegationsByIdRunsReplay", 3, "admin:ReplayPluginRun"),
    ("rustfs:PostV3PluginDelegationsByIdSubmit", 3, "admin:SubmitPluginJob"),
    ("rustfs:PostV3QuotaMigration", 5, "admin:SetBucketQuota"),
    ("rustfs:PostV3RecoverOrphanedBucketByBucket", 5, "admin:RecoverOrphanedBucket"),
    ("rustfs:PostV3TierByTierCleanupRetry", 3, "admin:SetTier"),
    ("rustfs:PostV3TlsCertificate", 2, "admin:TLSCertificatePublish"),
    (
        "rustfs:PutV3UpdateGroupMembers",
        4,
        "anyOf(admin:AddUserToGroup, admin:RemoveUserFromGroup)",
    ),
];

/// Positive and negative — every refreshed operation is declared at its order under exactly the
/// rule RustFS asks, privileged and with no subject rule; only the custom route carries a ruling,
/// and the recovery route alone binds its bucket.
#[test]
fn the_refreshed_operations_mirror_rustfs_and_no_more() {
    let plan = recorded_plan();
    for (name, order, rule) in REFRESHED {
        let declared = plan
            .declared
            .iter()
            .find(|declared| declared.name == *name)
            .unwrap_or_else(|| panic!("{name} is declared"));
        assert_eq!(declared.order, *order, "{name}");
        assert_eq!(declared.rule.render(), *rule, "{name}");
        // RustFS seals only the recovery answer, through its shared `owned_admin_json_response`.
        let sealed = *name == "rustfs:PostV3RecoverOrphanedBucketByBucket";
        assert_eq!(declared.caller_secret, sealed, "{name}");
        let custom = *name == "rustfs:PutV3UpdateGroupMembers";
        assert_eq!(declared.ruled.as_deref(), custom.then_some("MultipleActions"), "{name}");
        let bound = *name == "rustfs:PostV3RecoverOrphanedBucketByBucket" || name.contains("Iceberg");
        assert_eq!(declared.bucket.is_some(), bound, "{name}");
    }
    assert!(
        plan.declared
            .iter()
            .all(|declared| !declared.name.contains("CatalogMigration"))
    );
}

/// Negative — the group-membership ruling names both actions RustFS's first gate admits on, and
/// nothing else: dropping one would refuse a caller RustFS admits, adding one would admit a caller
/// RustFS refuses.
#[test]
fn n_the_group_membership_gate_is_exactly_rustfs_first_gate() {
    let ruling = RULINGS
        .iter()
        .find(|ruling| ruling.path == "/rustfs/admin/v3/update-group-members")
        .expect("the update-group-members ruling");
    assert_eq!((ruling.method, ruling.auth_detail), ("PUT", "MultipleActions"));
    assert_eq!(ruling.forms.len(), 1);
    let form = &ruling.forms[0];
    assert!(!form.anonymous);
    assert!(form.about.is_none());
    assert!(form.query.is_none());
    assert!(matches!(
        form.rule,
        super::rulings::Ruled::AnyOf(&["admin:AddUserToGroup", "admin:RemoveUserFromGroup"])
    ));
    assert!(ruling.note.contains("isRemove"));
}

/// Positive — the recorded plan carries every handler-retained check of [`RETAINED`] on its
/// operation, and only there; the certificate POST alone hands its body on unread, and its module
/// says why, while its record keeps RustFS's own body fact.
#[test]
fn the_recorded_retained_checks_are_planned() {
    let plan = recorded_plan();
    let retained: Vec<(&str, Vec<&str>)> = plan
        .declared
        .iter()
        .filter_map(|declared| {
            declared
                .retained
                .map(|retained| (declared.name.as_str(), retained.checks.to_vec()))
        })
        .collect();
    assert_eq!(retained.len(), 12, "{retained:?}");
    assert_eq!(retained.len(), RETAINED.len());
    for (name, checks) in &retained {
        assert_eq!(checks.contains(&NATIVE_TLS), name.contains("TlsCertificate"), "{name}");
        assert_eq!(checks.contains(&ORIGINAL_USER), name.contains("PluginDelegations"), "{name}");
    }
    let handed: Vec<&str> = plan
        .declared
        .iter()
        .filter(|declared| declared.retained.is_some_and(|retained| retained.hand_on_body))
        .map(|declared| declared.name.as_str())
        .collect();
    assert_eq!(handed, ["rustfs:PostV3TlsCertificate"]);
    let publish = plan
        .declared
        .iter()
        .find(|declared| declared.name == "rustfs:PostV3TlsCertificate")
        .expect("the certificate POST is declared");
    let source = render_operation(publish);
    assert!(source.contains("RequestBodyMode::Streaming"), "{source}");
    assert!(source.contains("request_body: BodyKind::Buffered"), "{source}");
    assert!(source.contains(r#"retained: &["native-tls-listener"]"#), "{source}");
    assert!(source.contains("fronting proxy"), "{source}");
}

/// Negative — a retained check is refused when it names no declared operation, when it hands on a
/// body RustFS does not buffer, when it names no check, and when two name one route.
#[test]
fn n_a_retained_check_outside_its_shape_is_refused() {
    const fn entry(method: &'static str, path: &'static str, checks: &'static [&'static str], hand_on_body: bool) -> Retained {
        Retained {
            method,
            path,
            checks,
            hand_on_body,
            note: "a note",
        }
    }
    const STATE: &str = "/rustfs/admin/v3/tls/certificate-state";
    let unretained = || {
        let mut plan = recorded_plan();
        for declared in &mut plan.declared {
            declared.retained = None;
        }
        plan
    };
    let refusal = |retained: &[Retained]| retain(&mut unretained().declared, retained).expect_err("refused");
    let stale = refusal(&[entry("GET", "/rustfs/admin/v3/gone", &[NATIVE_TLS], false)]);
    assert!(stale.contains("names no declared operation"), "{stale}");
    let unread = refusal(&[entry("GET", STATE, &[NATIVE_TLS], true)]);
    assert!(unread.contains("does not buffer"), "{unread}");
    let empty = refusal(&[entry("GET", STATE, &[], false)]);
    assert!(empty.contains("names no check"), "{empty}");
    let twice = refusal(&[
        entry("GET", STATE, &[NATIVE_TLS], false),
        entry("GET", STATE, &[NATIVE_TLS], false),
    ]);
    assert!(twice.contains("twice"), "{twice}");
    retain(&mut unretained().declared, &[entry("GET", STATE, &[NATIVE_TLS], false)]).expect("one well-formed entry is accepted");
}
