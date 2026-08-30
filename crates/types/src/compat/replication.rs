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

//! Pinned-s3s Replication persistence oracle.
//!
//! Responsible for: observing and writing Replication through the pinned old DTO and XML codec.
//! NOT responsible for: production parsing, policy validation, or golden verdicts.
//! Upstream: pinned s3s revision and persistence value shapes. Downstream: migration goldens.

use s3s::dto::{
    AccessControlTranslation, DeleteMarkerReplication, DeleteMarkerReplicationStatus, DeleteReplication, DeleteReplicationStatus,
    Destination, EncryptionConfiguration, ExistingObjectReplication, ExistingObjectReplicationStatus, Metrics, MetricsStatus,
    OwnerOverride, ReplicaModifications, ReplicaModificationsStatus, ReplicationConfiguration, ReplicationRule,
    ReplicationRuleAndOperator, ReplicationRuleFilter, ReplicationRuleStatus, ReplicationTime, ReplicationTimeStatus,
    ReplicationTimeValue, SourceSelectionCriteria, SseKmsEncryptedObjects, SseKmsEncryptedObjectsStatus, StorageClass, Tag,
};
use s3s::xml::{Deserialize, Deserializer, Serialize, Serializer};

use super::CompatCodecError;
use crate::persistence::{
    PersistedAccessControlTranslation, PersistedEncryptionConfiguration, PersistedOptionalReplicationStatus,
    PersistedReplicationAnd, PersistedReplicationConfiguration, PersistedReplicationDestination, PersistedReplicationFilter,
    PersistedReplicationMetrics, PersistedReplicationRule, PersistedReplicationStatus, PersistedReplicationTag,
    PersistedReplicationTime, PersistedReplicationTimeValue, PersistedSourceSelectionCriteria, ReplicationBehaviorProjection,
    ReplicationRuleBehaviorProjection,
};

/// Independent old-codec Replication observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3sReplicationObservation {
    /// Complete parsed persistence structure.
    pub structure: PersistedReplicationConfiguration,
    /// Runtime-relevant rule projection made from the old DTO.
    pub behavior: ReplicationBehaviorProjection,
}

/// Parses Replication bytes with the pinned old persistence decoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when s3s rejects the document or trailing input.
pub fn parse_s3s_replication(input: &[u8]) -> Result<S3sReplicationObservation, CompatCodecError> {
    let mut deserializer = Deserializer::new(input);
    let value = ReplicationConfiguration::deserialize(&mut deserializer).map_err(CompatCodecError::old_codec)?;
    deserializer.expect_eof().map_err(CompatCodecError::old_codec)?;
    let behavior = old_behavior(&value);
    let structure = from_old_configuration(value);
    Ok(S3sReplicationObservation { structure, behavior })
}

fn old_behavior(value: &ReplicationConfiguration) -> ReplicationBehaviorProjection {
    ReplicationBehaviorProjection {
        role: value.role.clone(),
        rules: value
            .rules
            .iter()
            .map(|rule| ReplicationRuleBehaviorProjection {
                status: rule.status.as_str().to_owned(),
                priority: rule.priority,
                destination_bucket: rule.destination.bucket.clone(),
                storage_class: rule.destination.storage_class.as_ref().map(|value| value.as_str().to_owned()),
                delete_marker_status: rule
                    .delete_marker_replication
                    .as_ref()
                    .and_then(|value| value.status.as_ref())
                    .map(|value| value.as_str().to_owned()),
                existing_object_status: rule
                    .existing_object_replication
                    .as_ref()
                    .map(|value| value.status.as_str().to_owned()),
                replica_modifications_status: rule
                    .source_selection_criteria
                    .as_ref()
                    .and_then(|criteria| criteria.replica_modifications.as_ref())
                    .map(|value| value.status.as_str().to_owned()),
                sse_kms_encrypted_objects_status: rule
                    .source_selection_criteria
                    .as_ref()
                    .and_then(|criteria| criteria.sse_kms_encrypted_objects.as_ref())
                    .map(|value| value.status.as_str().to_owned()),
            })
            .collect(),
    }
}

/// Serializes a Replication value with the pinned old persistence encoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when s3s cannot render the value.
pub fn serialize_s3s_replication(value: &PersistedReplicationConfiguration) -> Result<Vec<u8>, CompatCodecError> {
    let old_value = to_old_configuration(value);
    let mut output = Vec::with_capacity(1024);
    let mut serializer = Serializer::new(&mut output);
    old_value.serialize(&mut serializer).map_err(CompatCodecError::old_codec)?;
    Ok(output)
}

fn from_old_configuration(value: ReplicationConfiguration) -> PersistedReplicationConfiguration {
    PersistedReplicationConfiguration {
        role: value.role,
        rules: value.rules.into_iter().map(from_old_rule).collect(),
    }
}

fn from_old_rule(value: ReplicationRule) -> PersistedReplicationRule {
    PersistedReplicationRule {
        delete_marker_replication: value
            .delete_marker_replication
            .map(|wrapper| PersistedOptionalReplicationStatus {
                status: wrapper.status.map(|status| status.as_str().to_owned()),
            }),
        delete_replication: value.delete_replication.map(|wrapper| PersistedReplicationStatus {
            status: wrapper.status.as_str().to_owned(),
        }),
        destination: from_old_destination(value.destination),
        existing_object_replication: value.existing_object_replication.map(|wrapper| PersistedReplicationStatus {
            status: wrapper.status.as_str().to_owned(),
        }),
        filter: value.filter.map(from_old_filter),
        id: value.id,
        prefix: value.prefix,
        priority: value.priority,
        source_selection_criteria: value.source_selection_criteria.map(from_old_source_selection),
        status: value.status.as_str().to_owned(),
    }
}

fn from_old_destination(value: Destination) -> PersistedReplicationDestination {
    PersistedReplicationDestination {
        access_control_translation: value
            .access_control_translation
            .map(|translation| PersistedAccessControlTranslation {
                owner: translation.owner.as_str().to_owned(),
            }),
        account: value.account,
        bucket: value.bucket,
        encryption_configuration: value
            .encryption_configuration
            .map(|configuration| PersistedEncryptionConfiguration {
                replica_kms_key_id: configuration.replica_kms_key_id,
            }),
        metrics: value.metrics.map(|metrics| PersistedReplicationMetrics {
            event_threshold: metrics.event_threshold.map(|threshold| PersistedReplicationTimeValue {
                minutes: threshold.minutes,
            }),
            status: metrics.status.as_str().to_owned(),
        }),
        replication_time: value.replication_time.map(|replication_time| PersistedReplicationTime {
            status: replication_time.status.as_str().to_owned(),
            time: PersistedReplicationTimeValue {
                minutes: replication_time.time.minutes,
            },
        }),
        storage_class: value.storage_class.map(|storage_class| storage_class.as_str().to_owned()),
    }
}

fn from_old_filter(value: ReplicationRuleFilter) -> PersistedReplicationFilter {
    PersistedReplicationFilter {
        and: value.and.map(|and| PersistedReplicationAnd {
            prefix: and.prefix,
            tags: and.tags.map(|tags| tags.into_iter().map(from_old_tag).collect()),
        }),
        prefix: value.prefix,
        tag: value.tag.map(from_old_tag),
    }
}

fn from_old_tag(value: Tag) -> PersistedReplicationTag {
    PersistedReplicationTag {
        key: value.key,
        value: value.value,
    }
}

fn from_old_source_selection(value: SourceSelectionCriteria) -> PersistedSourceSelectionCriteria {
    PersistedSourceSelectionCriteria {
        replica_modifications: value.replica_modifications.map(|wrapper| PersistedReplicationStatus {
            status: wrapper.status.as_str().to_owned(),
        }),
        sse_kms_encrypted_objects: value.sse_kms_encrypted_objects.map(|wrapper| PersistedReplicationStatus {
            status: wrapper.status.as_str().to_owned(),
        }),
    }
}

fn to_old_configuration(value: &PersistedReplicationConfiguration) -> ReplicationConfiguration {
    ReplicationConfiguration {
        role: value.role.clone(),
        rules: value.rules.iter().map(to_old_rule).collect(),
    }
}

fn to_old_rule(value: &PersistedReplicationRule) -> ReplicationRule {
    #[allow(clippy::needless_update)]
    ReplicationRule {
        delete_marker_replication: value
            .delete_marker_replication
            .as_ref()
            .map(|wrapper| DeleteMarkerReplication {
                status: wrapper.status.clone().map(DeleteMarkerReplicationStatus::from),
                ..DeleteMarkerReplication::default()
            }),
        delete_replication: value.delete_replication.as_ref().map(|wrapper| DeleteReplication {
            status: DeleteReplicationStatus::from(wrapper.status.clone()),
        }),
        destination: to_old_destination(&value.destination),
        existing_object_replication: value
            .existing_object_replication
            .as_ref()
            .map(|wrapper| ExistingObjectReplication {
                status: ExistingObjectReplicationStatus::from(wrapper.status.clone()),
            }),
        filter: value.filter.as_ref().map(to_old_filter),
        id: value.id.clone(),
        prefix: value.prefix.clone(),
        priority: value.priority,
        source_selection_criteria: value.source_selection_criteria.as_ref().map(to_old_source_selection),
        status: ReplicationRuleStatus::from(value.status.clone()),
    }
}

fn to_old_destination(value: &PersistedReplicationDestination) -> Destination {
    #[allow(clippy::needless_update)]
    Destination {
        access_control_translation: value
            .access_control_translation
            .as_ref()
            .map(|translation| AccessControlTranslation {
                owner: OwnerOverride::from(translation.owner.clone()),
            }),
        account: value.account.clone(),
        bucket: value.bucket.clone(),
        encryption_configuration: value
            .encryption_configuration
            .as_ref()
            .map(|configuration| EncryptionConfiguration {
                replica_kms_key_id: configuration.replica_kms_key_id.clone(),
                ..EncryptionConfiguration::default()
            }),
        metrics: value.metrics.as_ref().map(|metrics| Metrics {
            event_threshold: metrics.event_threshold.as_ref().map(|threshold| ReplicationTimeValue {
                minutes: threshold.minutes,
            }),
            status: MetricsStatus::from(metrics.status.clone()),
        }),
        replication_time: value.replication_time.as_ref().map(|replication_time| ReplicationTime {
            status: ReplicationTimeStatus::from(replication_time.status.clone()),
            time: ReplicationTimeValue {
                minutes: replication_time.time.minutes,
            },
        }),
        storage_class: value.storage_class.clone().map(StorageClass::from),
        ..Destination::default()
    }
}

fn to_old_filter(value: &PersistedReplicationFilter) -> ReplicationRuleFilter {
    #[allow(clippy::needless_update)]
    ReplicationRuleFilter {
        and: value.and.as_ref().map(|and| ReplicationRuleAndOperator {
            prefix: and.prefix.clone(),
            tags: and.tags.as_ref().map(|tags| tags.iter().map(to_old_tag).collect()),
            ..ReplicationRuleAndOperator::default()
        }),
        prefix: value.prefix.clone(),
        tag: value.tag.as_ref().map(to_old_tag),
        ..ReplicationRuleFilter::default()
    }
}

fn to_old_tag(value: &PersistedReplicationTag) -> Tag {
    Tag {
        key: value.key.clone(),
        value: value.value.clone(),
    }
}

fn to_old_source_selection(value: &PersistedSourceSelectionCriteria) -> SourceSelectionCriteria {
    #[allow(clippy::needless_update)]
    SourceSelectionCriteria {
        replica_modifications: value.replica_modifications.as_ref().map(|wrapper| ReplicaModifications {
            status: ReplicaModificationsStatus::from(wrapper.status.clone()),
        }),
        sse_kms_encrypted_objects: value
            .sse_kms_encrypted_objects
            .as_ref()
            .map(|wrapper| SseKmsEncryptedObjects {
                status: SseKmsEncryptedObjectsStatus::from(wrapper.status.clone()),
            }),
        ..SourceSelectionCriteria::default()
    }
}
