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

use super::rulings::RULINGS;
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
        assert!(!declared.caller_secret, "{name}");
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
