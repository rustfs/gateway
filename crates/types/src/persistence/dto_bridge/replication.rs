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

//! Replication generated DTO persistence bridge.
//!
//! Responsible for: lossless conversion through the existing historical Replication codec.
//! NOT responsible for: XML parsing rules, HTTP validation, or runtime replication decisions.
//! Upstream: Replication persistence codec. Downstream: generated DTO metadata consumers.

use super::PersistenceBridgeError;
use crate::persistence::{
    PersistedAccessControlTranslation, PersistedEncryptionConfiguration, PersistedOptionalReplicationStatus,
    PersistedReplicationAnd, PersistedReplicationConfiguration, PersistedReplicationDestination, PersistedReplicationFilter,
    PersistedReplicationMetrics, PersistedReplicationRule, PersistedReplicationStatus, PersistedReplicationTag,
    PersistedReplicationTime, PersistedReplicationTimeValue, PersistedSourceSelectionCriteria, parse_replication,
    serialize_replication,
};

/// Parses persisted Replication bytes directly into the generated HTTP DTO.
///
/// # Errors
///
/// Returns [`PersistenceBridgeError::Codec`] when the historical codec rejects the document, or
/// [`PersistenceBridgeError::UnsupportedPersistedMember`] when an old-only member would be lost.
pub fn parse_replication_dto(input: &[u8]) -> Result<crate::dto::ReplicationConfiguration, PersistenceBridgeError> {
    let persisted = parse_replication(input)?;
    Ok(crate::dto::ReplicationConfiguration {
        role: persisted.role,
        rules: persisted.rules.into_iter().map(to_dto_rule).collect::<Result<Vec<_>, _>>()?,
    })
}

fn to_dto_rule(value: PersistedReplicationRule) -> Result<crate::dto::ReplicationRule, PersistenceBridgeError> {
    if value.delete_replication.is_some() {
        return Err(PersistenceBridgeError::UnsupportedPersistedMember("ReplicationRule.DeleteReplication"));
    }
    Ok(crate::dto::ReplicationRule {
        delete_marker_replication: value
            .delete_marker_replication
            .map(|wrapper| crate::dto::DeleteMarkerReplication {
                status: wrapper.status.map(crate::dto::Status::custom),
            }),
        destination: to_dto_destination(value.destination),
        existing_object_replication: value
            .existing_object_replication
            .map(|wrapper| crate::dto::ExistingObjectReplication {
                status: crate::dto::Status::custom(wrapper.status),
            }),
        filter: value.filter.map(to_dto_filter).transpose()?,
        id: value.id,
        prefix: value.prefix,
        priority: value.priority,
        source_selection_criteria: value.source_selection_criteria.map(to_dto_source_selection),
        status: crate::dto::Status::custom(value.status),
    })
}

fn to_dto_destination(value: PersistedReplicationDestination) -> crate::dto::Destination {
    crate::dto::Destination {
        access_control_translation: value
            .access_control_translation
            .map(|translation| crate::dto::AccessControlTranslation {
                owner: translation.owner,
            }),
        account: value.account,
        bucket: value.bucket,
        encryption_configuration: value
            .encryption_configuration
            .map(|configuration| crate::dto::EncryptionConfiguration {
                replica_kms_key_id: configuration.replica_kms_key_id,
            }),
        metrics: value.metrics.map(|metrics| crate::dto::Metrics {
            event_threshold: metrics.event_threshold.map(|threshold| crate::dto::ReplicationTimeValue {
                minutes: threshold.minutes,
            }),
            status: crate::dto::Status::custom(metrics.status),
        }),
        replication_time: value.replication_time.map(|replication_time| crate::dto::ReplicationTime {
            status: crate::dto::Status::custom(replication_time.status),
            time: crate::dto::ReplicationTimeValue {
                minutes: replication_time.time.minutes,
            },
        }),
        storage_class: value.storage_class.map(crate::dto::StorageClass::custom),
    }
}

fn to_dto_filter(value: PersistedReplicationFilter) -> Result<crate::dto::ReplicationRuleFilter, PersistenceBridgeError> {
    Ok(crate::dto::ReplicationRuleFilter {
        and: value
            .and
            .map(|and| -> Result<_, PersistenceBridgeError> {
                Ok(crate::dto::ReplicationRuleAndOperator {
                    prefix: and.prefix,
                    tags: and
                        .tags
                        .unwrap_or_default()
                        .into_iter()
                        .map(|tag| to_dto_tag(tag, "ReplicationRule.Filter.And.Tag.Key", "ReplicationRule.Filter.And.Tag.Value"))
                        .collect::<Result<Vec<_>, _>>()?,
                })
            })
            .transpose()?,
        prefix: value.prefix,
        tag: value
            .tag
            .map(|tag| to_dto_tag(tag, "ReplicationRule.Filter.Tag.Key", "ReplicationRule.Filter.Tag.Value"))
            .transpose()?,
    })
}

fn to_dto_tag(
    value: PersistedReplicationTag,
    key_path: &'static str,
    value_path: &'static str,
) -> Result<crate::dto::Tag, PersistenceBridgeError> {
    let key = value
        .key
        .ok_or(PersistenceBridgeError::UnsupportedPersistedMember(key_path))?;
    let value = value
        .value
        .ok_or(PersistenceBridgeError::UnsupportedPersistedMember(value_path))?;
    Ok(crate::dto::Tag { key, value })
}

fn to_dto_source_selection(value: PersistedSourceSelectionCriteria) -> crate::dto::SourceSelectionCriteria {
    crate::dto::SourceSelectionCriteria {
        replica_modifications: value.replica_modifications.map(|wrapper| crate::dto::ReplicaModifications {
            status: crate::dto::Status::custom(wrapper.status),
        }),
        sse_kms_encrypted_objects: value
            .sse_kms_encrypted_objects
            .map(|wrapper| crate::dto::SseKmsEncryptedObjects {
                status: crate::dto::Status::custom(wrapper.status),
            }),
    }
}

/// Serializes the generated Replication DTO with the historical persistence writer.
///
/// # Errors
///
/// Returns [`PersistenceBridgeError::Codec`] when the historical writer rejects the value.
pub fn serialize_replication_dto(value: &crate::dto::ReplicationConfiguration) -> Result<Vec<u8>, PersistenceBridgeError> {
    serialize_replication(&PersistedReplicationConfiguration {
        role: value.role.clone(),
        rules: value.rules.iter().map(from_dto_rule).collect(),
    })
    .map_err(Into::into)
}

fn from_dto_rule(value: &crate::dto::ReplicationRule) -> PersistedReplicationRule {
    PersistedReplicationRule {
        delete_marker_replication: value
            .delete_marker_replication
            .as_ref()
            .map(|wrapper| PersistedOptionalReplicationStatus {
                status: wrapper.status.as_ref().map(|status| status.as_str().to_owned()),
            }),
        delete_replication: None,
        destination: from_dto_destination(&value.destination),
        existing_object_replication: value
            .existing_object_replication
            .as_ref()
            .map(|wrapper| PersistedReplicationStatus {
                status: wrapper.status.as_str().to_owned(),
            }),
        filter: value.filter.as_ref().map(from_dto_filter),
        id: value.id.clone(),
        prefix: value.prefix.clone(),
        priority: value.priority,
        source_selection_criteria: value.source_selection_criteria.as_ref().map(from_dto_source_selection),
        status: value.status.as_str().to_owned(),
    }
}

fn from_dto_destination(value: &crate::dto::Destination) -> PersistedReplicationDestination {
    PersistedReplicationDestination {
        access_control_translation: value.access_control_translation.as_ref().map(|translation| {
            PersistedAccessControlTranslation {
                owner: translation.owner.clone(),
            }
        }),
        account: value.account.clone(),
        bucket: value.bucket.clone(),
        encryption_configuration: value
            .encryption_configuration
            .as_ref()
            .map(|configuration| PersistedEncryptionConfiguration {
                replica_kms_key_id: configuration.replica_kms_key_id.clone(),
            }),
        metrics: value.metrics.as_ref().map(|metrics| PersistedReplicationMetrics {
            event_threshold: metrics
                .event_threshold
                .as_ref()
                .map(|threshold| PersistedReplicationTimeValue {
                    minutes: threshold.minutes,
                }),
            status: metrics.status.as_str().to_owned(),
        }),
        replication_time: value
            .replication_time
            .as_ref()
            .map(|replication_time| PersistedReplicationTime {
                status: replication_time.status.as_str().to_owned(),
                time: PersistedReplicationTimeValue {
                    minutes: replication_time.time.minutes,
                },
            }),
        storage_class: value
            .storage_class
            .as_ref()
            .map(|storage_class| storage_class.as_str().to_owned()),
    }
}

fn from_dto_filter(value: &crate::dto::ReplicationRuleFilter) -> PersistedReplicationFilter {
    PersistedReplicationFilter {
        and: value.and.as_ref().map(|and| PersistedReplicationAnd {
            prefix: and.prefix.clone(),
            tags: (!and.tags.is_empty()).then(|| and.tags.iter().map(from_dto_tag).collect()),
        }),
        prefix: value.prefix.clone(),
        tag: value.tag.as_ref().map(from_dto_tag),
    }
}

fn from_dto_tag(value: &crate::dto::Tag) -> PersistedReplicationTag {
    PersistedReplicationTag {
        key: Some(value.key.clone()),
        value: Some(value.value.clone()),
    }
}

fn from_dto_source_selection(value: &crate::dto::SourceSelectionCriteria) -> PersistedSourceSelectionCriteria {
    PersistedSourceSelectionCriteria {
        replica_modifications: value
            .replica_modifications
            .as_ref()
            .map(|wrapper| PersistedReplicationStatus {
                status: wrapper.status.as_str().to_owned(),
            }),
        sse_kms_encrypted_objects: value
            .sse_kms_encrypted_objects
            .as_ref()
            .map(|wrapper| PersistedReplicationStatus {
                status: wrapper.status.as_str().to_owned(),
            }),
    }
}

#[cfg(test)]
mod tests {
    use crate::dto::ReplicationConfiguration;

    use super::{parse_replication_dto, serialize_replication_dto};
    use crate::persistence::{PersistenceBridgeError, PersistenceCodecError};

    const HISTORICAL: &[u8] = b"<ReplicationConfiguration><Role>arn:aws:iam::123456789012:role/replication</Role><Rule><DeleteMarkerReplication><Status>FutureDelete</Status></DeleteMarkerReplication><Destination><AccessControlTranslation><Owner>FutureOwner</Owner></AccessControlTranslation><Account>123456789012</Account><Bucket>arn:aws:s3:::backup</Bucket><EncryptionConfiguration><ReplicaKmsKeyID>kms-key</ReplicaKmsKeyID></EncryptionConfiguration><Metrics><EventThreshold><Minutes>15</Minutes></EventThreshold><Status>FutureMetrics</Status></Metrics><ReplicationTime><Status>FutureRtc</Status><Time><Minutes>15</Minutes></Time></ReplicationTime><StorageClass>FutureStorage</StorageClass></Destination><ExistingObjectReplication><Status>FutureExisting</Status></ExistingObjectReplication><Filter><And><Prefix></Prefix><Tag><Key>team</Key><Value>storage</Value></Tag></And></Filter><ID>archive</ID><Prefix></Prefix><Priority>7</Priority><SourceSelectionCriteria><ReplicaModifications><Status>FutureReplica</Status></ReplicaModifications><SseKmsEncryptedObjects><Status>FutureKms</Status></SseKmsEncryptedObjects></SourceSelectionCriteria><Status>FutureRule</Status></Rule></ReplicationConfiguration>";

    #[test]
    fn replication_dto_bridge_preserves_nested_fields_empty_prefixes_unknown_enums_and_old_order() {
        let parsed = parse_replication_dto(HISTORICAL).expect("the historical document is representable");
        assert_eq!(parsed.role, "arn:aws:iam::123456789012:role/replication");
        let rule = &parsed.rules[0];
        assert_eq!(rule.prefix.as_deref(), Some(""));
        assert_eq!(rule.status.as_str(), "FutureRule");
        assert_eq!(
            rule.delete_marker_replication
                .as_ref()
                .and_then(|value| value.status.as_ref())
                .map(|value| value.as_str()),
            Some("FutureDelete")
        );
        assert_eq!(rule.destination.storage_class.as_ref().map(|value| value.as_str()), Some("FutureStorage"));
        let and = rule
            .filter
            .as_ref()
            .and_then(|filter| filter.and.as_ref())
            .expect("the And selector remains present");
        assert_eq!(and.prefix.as_deref(), Some(""));
        assert_eq!(and.tags[0].key, "team");
        assert_eq!(and.tags[0].value, "storage");
        assert_eq!(serialize_replication_dto(&parsed).expect("the DTO remains representable"), HISTORICAL);
    }

    #[test]
    fn replication_dto_bridge_rejects_a_wrong_family() {
        assert_eq!(
            parse_replication_dto(b"<NotificationConfiguration></NotificationConfiguration>")
                .expect_err("a different family must fail"),
            PersistenceBridgeError::Codec(PersistenceCodecError::WrongRoot)
        );
    }

    #[test]
    fn replication_dto_bridge_rejects_a_missing_rule() {
        assert_eq!(
            parse_replication_dto(b"<ReplicationConfiguration><Role>role</Role></ReplicationConfiguration>")
                .expect_err("at least one rule is required"),
            PersistenceBridgeError::Codec(PersistenceCodecError::MissingReplicationRule)
        );
    }

    #[test]
    fn replication_dto_bridge_rejects_the_minio_only_delete_replication_member() {
        assert_eq!(
            parse_replication_dto(b"<ReplicationConfiguration><Role>role</Role><Rule><DeleteReplication><Status>Enabled</Status></DeleteReplication><Destination><Bucket>arn:aws:s3:::backup</Bucket></Destination><Status>Enabled</Status></Rule></ReplicationConfiguration>")
                .expect_err("the generated DTO cannot retain the extension"),
            PersistenceBridgeError::UnsupportedPersistedMember("ReplicationRule.DeleteReplication")
        );
    }

    #[test]
    fn replication_dto_bridge_rejects_a_tag_without_a_key() {
        assert_eq!(
            parse_replication_dto(b"<ReplicationConfiguration><Role>role</Role><Rule><Destination><Bucket>arn:aws:s3:::backup</Bucket></Destination><Filter><Tag><Value>storage</Value></Tag></Filter><Status>Enabled</Status></Rule></ReplicationConfiguration>")
                .expect_err("the generated tag requires a key"),
            PersistenceBridgeError::UnsupportedPersistedMember("ReplicationRule.Filter.Tag.Key")
        );
    }

    #[test]
    fn replication_dto_bridge_rejects_a_tag_without_a_value() {
        assert_eq!(
            parse_replication_dto(b"<ReplicationConfiguration><Role>role</Role><Rule><Destination><Bucket>arn:aws:s3:::backup</Bucket></Destination><Filter><Tag><Key>team</Key></Tag></Filter><Status>Enabled</Status></Rule></ReplicationConfiguration>")
                .expect_err("the generated tag requires a value"),
            PersistenceBridgeError::UnsupportedPersistedMember("ReplicationRule.Filter.Tag.Value")
        );
    }

    #[test]
    fn replication_dto_bridge_rejects_an_invalid_priority() {
        assert_eq!(
            parse_replication_dto(b"<ReplicationConfiguration><Role>role</Role><Rule><Destination><Bucket>arn:aws:s3:::backup</Bucket></Destination><Priority>high</Priority><Status>Enabled</Status></Rule></ReplicationConfiguration>")
                .expect_err("an invalid integer must fail"),
            PersistenceBridgeError::Codec(PersistenceCodecError::InvalidReplicationInteger)
        );
    }

    #[test]
    fn replication_dto_bridge_rejects_serializing_an_empty_rule_list() {
        let dto = ReplicationConfiguration {
            role: "role".to_owned(),
            rules: Vec::new(),
        };
        assert_eq!(
            serialize_replication_dto(&dto).expect_err("historical persistence requires a rule"),
            PersistenceBridgeError::Codec(PersistenceCodecError::MissingReplicationRule)
        );
    }
}
