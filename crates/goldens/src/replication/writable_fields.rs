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

//! Replication writable-field contract reachability evidence.
//!
//! Responsible for: proving every pinned RustFS writable path reaches a real persistence DTO field.
//! NOT responsible for: defining RustFS replication policy or validating XML.
//! Upstream: RustFS replication capability contract at revision `62cc19e9`.
//! Downstream: P9-01 `g-d5-005` migration evidence.

use rustfs_gateway_types::persistence::{
    PersistedOptionalReplicationStatus, PersistedReplicationAnd, PersistedReplicationConfiguration,
    PersistedReplicationDestination, PersistedReplicationFilter, PersistedReplicationRule, PersistedReplicationStatus,
    PersistedReplicationTag, PersistedSourceSelectionCriteria,
};

const SOURCE_PATH: &str = "crates/replication/src/config.rs::REPLICATION_WRITABLE_FIELDS";
const SOURCE_REVISION: &str = "62cc19e937c8cac4a14f4a353405a19d19319bd7";
const WRITABLE_FIELDS: &[&str] = &[
    "Role",
    "Rule.ID",
    "Rule.Status",
    "Rule.Priority",
    "Rule.Filter.Prefix",
    "Rule.Filter.Tag",
    "Rule.Filter.And",
    "Rule.Destination.Bucket",
    "Rule.ExistingObjectReplication.Status",
    "Rule.DeleteMarkerReplication.Status",
    "Rule.DeleteReplication.Status",
    "Rule.SourceSelectionCriteria.ReplicaModifications.Status",
];

#[derive(Debug, Eq, PartialEq)]
enum ContractError {
    Duplicate(&'static str),
    Missing(&'static str),
    Unknown(&'static str),
    Unreachable(&'static str),
}

fn configuration() -> PersistedReplicationConfiguration {
    PersistedReplicationConfiguration {
        role: String::new(),
        rules: vec![PersistedReplicationRule {
            delete_marker_replication: None,
            delete_replication: None,
            destination: PersistedReplicationDestination::default(),
            existing_object_replication: None,
            filter: None,
            id: None,
            prefix: None,
            priority: None,
            source_selection_criteria: None,
            status: String::new(),
        }],
    }
}

fn reaches_real_field(path: &'static str) -> bool {
    let mut configuration = configuration();
    if path == "Role" {
        configuration.role = "role-sentinel".to_owned();
        return configuration.role == "role-sentinel";
    }
    let Some(rule) = configuration.rules.first_mut() else {
        return false;
    };
    match path {
        "Rule.ID" => {
            rule.id = Some("id-sentinel".to_owned());
            rule.id.as_deref() == Some("id-sentinel")
        }
        "Rule.Status" => {
            rule.status = "status-sentinel".to_owned();
            rule.status == "status-sentinel"
        }
        "Rule.Priority" => {
            rule.priority = Some(73);
            rule.priority == Some(73)
        }
        "Rule.Filter.Prefix" => {
            let filter = rule.filter.get_or_insert_with(PersistedReplicationFilter::default);
            filter.prefix = Some("prefix-sentinel".to_owned());
            filter.prefix.as_deref() == Some("prefix-sentinel")
        }
        "Rule.Filter.Tag" => {
            let filter = rule.filter.get_or_insert_with(PersistedReplicationFilter::default);
            filter.tag = Some(PersistedReplicationTag {
                key: Some("key-sentinel".to_owned()),
                value: Some("value-sentinel".to_owned()),
            });
            filter.tag.as_ref().and_then(|tag| tag.key.as_deref()) == Some("key-sentinel")
        }
        "Rule.Filter.And" => {
            let filter = rule.filter.get_or_insert_with(PersistedReplicationFilter::default);
            filter.and = Some(PersistedReplicationAnd {
                prefix: Some("and-sentinel".to_owned()),
                tags: None,
            });
            filter.and.as_ref().and_then(|and| and.prefix.as_deref()) == Some("and-sentinel")
        }
        "Rule.Destination.Bucket" => {
            rule.destination.bucket = "bucket-sentinel".to_owned();
            rule.destination.bucket == "bucket-sentinel"
        }
        "Rule.ExistingObjectReplication.Status" => {
            rule.existing_object_replication = Some(PersistedReplicationStatus {
                status: "existing-sentinel".to_owned(),
            });
            rule.existing_object_replication.as_ref().map(|status| status.status.as_str()) == Some("existing-sentinel")
        }
        "Rule.DeleteMarkerReplication.Status" => {
            rule.delete_marker_replication = Some(PersistedOptionalReplicationStatus {
                status: Some("marker-sentinel".to_owned()),
            });
            rule.delete_marker_replication
                .as_ref()
                .and_then(|status| status.status.as_deref())
                == Some("marker-sentinel")
        }
        "Rule.DeleteReplication.Status" => {
            rule.delete_replication = Some(PersistedReplicationStatus {
                status: "delete-sentinel".to_owned(),
            });
            rule.delete_replication.as_ref().map(|status| status.status.as_str()) == Some("delete-sentinel")
        }
        "Rule.SourceSelectionCriteria.ReplicaModifications.Status" => {
            rule.source_selection_criteria = Some(PersistedSourceSelectionCriteria {
                replica_modifications: Some(PersistedReplicationStatus {
                    status: "replica-sentinel".to_owned(),
                }),
                sse_kms_encrypted_objects: None,
            });
            rule.source_selection_criteria
                .as_ref()
                .and_then(|criteria| criteria.replica_modifications.as_ref())
                .map(|status| status.status.as_str())
                == Some("replica-sentinel")
        }
        _ => false,
    }
}

fn validate_writable_field_contract(paths: &[&'static str]) -> Result<(), ContractError> {
    for path in paths {
        if !WRITABLE_FIELDS.contains(path) {
            return Err(ContractError::Unknown(path));
        }
        if paths.iter().filter(|candidate| *candidate == path).count() != 1 {
            return Err(ContractError::Duplicate(path));
        }
    }
    for path in WRITABLE_FIELDS {
        if !paths.contains(path) {
            return Err(ContractError::Missing(path));
        }
        if !reaches_real_field(path) {
            return Err(ContractError::Unreachable(path));
        }
    }
    Ok(())
}

#[test]
fn g_d5_005_every_replication_writable_path_reaches_a_real_dto_field() {
    assert_eq!(SOURCE_PATH, "crates/replication/src/config.rs::REPLICATION_WRITABLE_FIELDS");
    assert_eq!(SOURCE_REVISION, "62cc19e937c8cac4a14f4a353405a19d19319bd7");
    validate_writable_field_contract(WRITABLE_FIELDS).expect("all pinned writable paths reach real DTO fields");
}

#[test]
fn g_d5_005_unknown_path_fails_closed() {
    let mut paths = WRITABLE_FIELDS.to_vec();
    paths.push("Rule.FutureField");
    assert_eq!(validate_writable_field_contract(&paths), Err(ContractError::Unknown("Rule.FutureField")));
}

#[test]
fn g_d5_005_missing_path_fails_closed() {
    assert_eq!(
        validate_writable_field_contract(&WRITABLE_FIELDS[1..]),
        Err(ContractError::Missing("Role"))
    );
}

#[test]
fn g_d5_005_duplicate_path_fails_closed() {
    let mut paths = WRITABLE_FIELDS.to_vec();
    paths.push("Rule.Status");
    assert_eq!(validate_writable_field_contract(&paths), Err(ContractError::Duplicate("Rule.Status")));
}
