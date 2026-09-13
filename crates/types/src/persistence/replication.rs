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

//! Persisted Replication XML below the HTTP policy layer.
//!
//! Responsible for: lossless known-field parsing and old-order serialization of Replication data.
//! NOT responsible for: validating replication policy combinations or executing replication.
//! Upstream: bounded gateway XML nodes. Downstream: RustFS metadata persistence and goldens.

use rustfs_gateway_xml::{XmlLimits, XmlNode, XmlWriter, parse_with_limits};

use core::fmt;

use super::{PersistenceCodecError, RedactedKeyId, optional_child, strip_inert_doctype};

/// The complete persisted Replication configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedReplicationConfiguration {
    /// IAM role ARN used for replication.
    pub role: String,
    /// Rules in persisted order.
    pub rules: Vec<PersistedReplicationRule>,
}

/// One persisted Replication rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedReplicationRule {
    /// Delete-marker replication policy.
    pub delete_marker_replication: Option<PersistedOptionalReplicationStatus>,
    /// MinIO delete replication policy.
    pub delete_replication: Option<PersistedReplicationStatus>,
    /// Required destination.
    pub destination: PersistedReplicationDestination,
    /// Existing-object replication policy.
    pub existing_object_replication: Option<PersistedReplicationStatus>,
    /// Optional selector.
    pub filter: Option<PersistedReplicationFilter>,
    /// Optional identifier.
    pub id: Option<String>,
    /// Legacy prefix selector.
    pub prefix: Option<String>,
    /// Optional rule priority.
    pub priority: Option<i32>,
    /// Optional source-selection criteria.
    pub source_selection_criteria: Option<PersistedSourceSelectionCriteria>,
    /// Required rule status, including old-readable unknown values.
    pub status: String,
}

/// A nested status wrapper used by several Replication features.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedReplicationStatus {
    /// Status string, including old-readable unknown values.
    pub status: String,
}

/// The historical delete-marker wrapper whose status itself was optional.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedOptionalReplicationStatus {
    /// Optional status string, including old-readable unknown values.
    pub status: Option<String>,
}

/// A persisted Replication destination.
///
/// `Debug` is written by hand because the destination account id is, beside the replica KMS key
/// id, one of the two configuration secrets `q-repl-0010` names: it renders as presence and length
/// only, and every other member renders as a derived `Debug` would.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct PersistedReplicationDestination {
    /// Destination account identifier.
    pub account: Option<String>,
    /// Destination ownership override.
    pub access_control_translation: Option<PersistedAccessControlTranslation>,
    /// Required destination bucket ARN.
    pub bucket: String,
    /// Destination KMS configuration.
    pub encryption_configuration: Option<PersistedEncryptionConfiguration>,
    /// Replication metrics configuration.
    pub metrics: Option<PersistedReplicationMetrics>,
    /// Replication-time-control configuration.
    pub replication_time: Option<PersistedReplicationTime>,
    /// Destination storage class.
    pub storage_class: Option<String>,
}

impl fmt::Debug for PersistedReplicationDestination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistedReplicationDestination")
            .field("account", &RedactedKeyId(self.account.as_deref()))
            .field("access_control_translation", &self.access_control_translation)
            .field("bucket", &self.bucket)
            .field("encryption_configuration", &self.encryption_configuration)
            .field("metrics", &self.metrics)
            .field("replication_time", &self.replication_time)
            .field("storage_class", &self.storage_class)
            .finish()
    }
}

/// Ownership override for replicated objects.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedAccessControlTranslation {
    /// Owner override string.
    pub owner: String,
}

/// KMS settings for replicated objects.
///
/// `Debug` is written by hand for the same reason as `PersistedEncryptionByDefault`: the replica
/// KMS key id is a secret, so it renders as presence and length only.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct PersistedEncryptionConfiguration {
    /// Replica KMS key identifier.
    pub replica_kms_key_id: Option<String>,
}

impl fmt::Debug for PersistedEncryptionConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistedEncryptionConfiguration")
            .field("replica_kms_key_id", &RedactedKeyId(self.replica_kms_key_id.as_deref()))
            .finish()
    }
}

/// Replication metrics settings.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedReplicationMetrics {
    /// Event-threshold minutes.
    pub event_threshold: Option<PersistedReplicationTimeValue>,
    /// Metrics status.
    pub status: String,
}

/// Replication-time-control settings.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedReplicationTime {
    /// RTC status.
    pub status: String,
    /// Required guaranteed replication-time wrapper.
    pub time: PersistedReplicationTimeValue,
}

/// Minutes wrapper used by Replication metrics and RTC.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedReplicationTimeValue {
    /// Optional minutes value retained independently from wrapper presence.
    pub minutes: Option<i32>,
}

/// A persisted Replication rule filter.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedReplicationFilter {
    /// Conjunctive selector.
    pub and: Option<PersistedReplicationAnd>,
    /// Prefix selector.
    pub prefix: Option<String>,
    /// Single tag selector.
    pub tag: Option<PersistedReplicationTag>,
}

/// Conjunctive Replication filter.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedReplicationAnd {
    /// Prefix selector.
    pub prefix: Option<String>,
    /// Tag selectors in persisted order.
    pub tags: Option<Vec<PersistedReplicationTag>>,
}

/// Replication tag selector.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedReplicationTag {
    /// Tag key.
    pub key: Option<String>,
    /// Tag value.
    pub value: Option<String>,
}

/// Source-side selection criteria.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedSourceSelectionCriteria {
    /// Replica-modification replication policy.
    pub replica_modifications: Option<PersistedReplicationStatus>,
    /// SSE-KMS object selection policy.
    pub sse_kms_encrypted_objects: Option<PersistedReplicationStatus>,
}

/// Runtime-relevant Replication behavior projected independently by each codec.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReplicationBehaviorProjection {
    /// IAM role selected for replication.
    pub role: String,
    /// Rule decisions in persisted order.
    pub rules: Vec<ReplicationRuleBehaviorProjection>,
}

/// Runtime-relevant decisions for one Replication rule.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReplicationRuleBehaviorProjection {
    /// Rule status.
    pub status: String,
    /// Rule priority.
    pub priority: Option<i32>,
    /// Destination bucket ARN.
    pub destination_bucket: String,
    /// Destination storage class.
    pub storage_class: Option<String>,
    /// Delete-marker replication status.
    pub delete_marker_status: Option<String>,
    /// Existing-object replication status.
    pub existing_object_status: Option<String>,
    /// Replica-modification replication status.
    pub replica_modifications_status: Option<String>,
    /// SSE-KMS source-selection status.
    pub sse_kms_encrypted_objects_status: Option<String>,
}

impl PersistedReplicationConfiguration {
    /// Projects fields used by runtime rule selection and destination routing.
    #[must_use]
    pub fn behavior(&self) -> ReplicationBehaviorProjection {
        ReplicationBehaviorProjection {
            role: self.role.clone(),
            rules: self
                .rules
                .iter()
                .map(|rule| ReplicationRuleBehaviorProjection {
                    status: rule.status.clone(),
                    priority: rule.priority,
                    destination_bucket: rule.destination.bucket.clone(),
                    storage_class: rule.destination.storage_class.clone(),
                    delete_marker_status: rule.delete_marker_replication.as_ref().and_then(|value| value.status.clone()),
                    existing_object_status: rule.existing_object_replication.as_ref().map(|value| value.status.clone()),
                    replica_modifications_status: rule
                        .source_selection_criteria
                        .as_ref()
                        .and_then(|criteria| criteria.replica_modifications.as_ref())
                        .map(|value| value.status.clone()),
                    sse_kms_encrypted_objects_status: rule
                        .source_selection_criteria
                        .as_ref()
                        .and_then(|criteria| criteria.sse_kms_encrypted_objects.as_ref())
                        .map(|value| value.status.clone()),
                })
                .collect(),
        }
    }
}

/// Parses persisted Replication bytes without applying HTTP policy validation.
///
/// Unknown top-level elements and attributes are ignored. Unknown nested elements and repeated
/// optional known fields are rejected, while Rule and And/Tag lists preserve document order.
///
/// # Errors
///
/// Returns [`PersistenceCodecError`] for malformed XML, wrong root, missing required members,
/// duplicate structural fields, or invalid integer lexemes.
pub fn parse_replication(input: &[u8]) -> Result<PersistedReplicationConfiguration, PersistenceCodecError> {
    let bound = input.len().max(1);
    let Some(limits) = XmlLimits::new(bound, bound, bound, bound, bound) else {
        unreachable!("max(1) makes every persistence XML limit non-zero");
    };
    let body = strip_inert_doctype(input, "ReplicationConfiguration");
    let root = parse_with_limits(body.as_ref(), limits)?;
    if root.name != "ReplicationConfiguration" {
        return Err(PersistenceCodecError::WrongRoot);
    }
    let rules = root.children_named("Rule").map(parse_rule).collect::<Result<Vec<_>, _>>()?;
    if rules.is_empty() {
        return Err(PersistenceCodecError::MissingReplicationRule);
    }
    Ok(PersistedReplicationConfiguration {
        role: required_text(&root, "Role")?,
        rules,
    })
}

fn parse_rule(node: &XmlNode) -> Result<PersistedReplicationRule, PersistenceCodecError> {
    reject_unknown(
        node,
        &[
            "DeleteMarkerReplication",
            "DeleteReplication",
            "Destination",
            "ExistingObjectReplication",
            "Filter",
            "ID",
            "Prefix",
            "Priority",
            "SourceSelectionCriteria",
            "Status",
        ],
    )?;
    Ok(PersistedReplicationRule {
        delete_marker_replication: optional_child(node, "DeleteMarkerReplication")?
            .map(parse_optional_status)
            .transpose()?,
        delete_replication: optional_child(node, "DeleteReplication")?.map(parse_status).transpose()?,
        destination: parse_destination(required_child(node, "Destination")?)?,
        existing_object_replication: optional_child(node, "ExistingObjectReplication")?
            .map(parse_status)
            .transpose()?,
        filter: optional_child(node, "Filter")?.map(parse_filter).transpose()?,
        id: optional_text(node, "ID")?,
        prefix: optional_text(node, "Prefix")?,
        priority: optional_i32(node, "Priority")?,
        source_selection_criteria: optional_child(node, "SourceSelectionCriteria")?
            .map(parse_source_selection)
            .transpose()?,
        status: required_text(node, "Status")?,
    })
}

fn parse_destination(node: &XmlNode) -> Result<PersistedReplicationDestination, PersistenceCodecError> {
    reject_unknown(
        node,
        &[
            "AccessControlTranslation",
            "Account",
            "Bucket",
            "EncryptionConfiguration",
            "Metrics",
            "ReplicationTime",
            "StorageClass",
        ],
    )?;
    Ok(PersistedReplicationDestination {
        access_control_translation: optional_child(node, "AccessControlTranslation")?
            .map(parse_access_control_translation)
            .transpose()?,
        account: optional_text(node, "Account")?,
        bucket: required_text(node, "Bucket")?,
        encryption_configuration: optional_child(node, "EncryptionConfiguration")?
            .map(parse_encryption_configuration)
            .transpose()?,
        metrics: optional_child(node, "Metrics")?.map(parse_metrics).transpose()?,
        replication_time: optional_child(node, "ReplicationTime")?
            .map(parse_replication_time)
            .transpose()?,
        storage_class: optional_text(node, "StorageClass")?,
    })
}

fn parse_access_control_translation(node: &XmlNode) -> Result<PersistedAccessControlTranslation, PersistenceCodecError> {
    reject_unknown(node, &["Owner"])?;
    Ok(PersistedAccessControlTranslation {
        owner: required_text(node, "Owner")?,
    })
}

fn parse_encryption_configuration(node: &XmlNode) -> Result<PersistedEncryptionConfiguration, PersistenceCodecError> {
    reject_unknown(node, &["ReplicaKmsKeyID"])?;
    Ok(PersistedEncryptionConfiguration {
        replica_kms_key_id: optional_text(node, "ReplicaKmsKeyID")?,
    })
}

fn parse_metrics(node: &XmlNode) -> Result<PersistedReplicationMetrics, PersistenceCodecError> {
    reject_unknown(node, &["EventThreshold", "Status"])?;
    Ok(PersistedReplicationMetrics {
        event_threshold: optional_child(node, "EventThreshold")?
            .map(|threshold| -> Result<_, PersistenceCodecError> {
                reject_unknown(threshold, &["Minutes"])?;
                Ok(PersistedReplicationTimeValue {
                    minutes: optional_i32(threshold, "Minutes")?,
                })
            })
            .transpose()?,
        status: required_text(node, "Status")?,
    })
}

fn parse_replication_time(node: &XmlNode) -> Result<PersistedReplicationTime, PersistenceCodecError> {
    reject_unknown(node, &["Status", "Time"])?;
    Ok(PersistedReplicationTime {
        status: required_text(node, "Status")?,
        time: {
            let time = required_child(node, "Time")?;
            reject_unknown(time, &["Minutes"])?;
            PersistedReplicationTimeValue {
                minutes: optional_i32(time, "Minutes")?,
            }
        },
    })
}

fn parse_filter(node: &XmlNode) -> Result<PersistedReplicationFilter, PersistenceCodecError> {
    reject_unknown(node, &["And", "Prefix", "Tag"])?;
    Ok(PersistedReplicationFilter {
        and: optional_child(node, "And")?.map(parse_and).transpose()?,
        prefix: optional_text(node, "Prefix")?,
        tag: optional_child(node, "Tag")?.map(parse_tag).transpose()?,
    })
}

fn parse_and(node: &XmlNode) -> Result<PersistedReplicationAnd, PersistenceCodecError> {
    reject_unknown(node, &["Prefix", "Tag"])?;
    let tags = node.children_named("Tag").map(parse_tag).collect::<Result<Vec<_>, _>>()?;
    Ok(PersistedReplicationAnd {
        prefix: optional_text(node, "Prefix")?,
        tags: (!tags.is_empty()).then_some(tags),
    })
}

fn parse_tag(node: &XmlNode) -> Result<PersistedReplicationTag, PersistenceCodecError> {
    reject_unknown(node, &["Key", "Value"])?;
    Ok(PersistedReplicationTag {
        key: optional_text(node, "Key")?,
        value: optional_text(node, "Value")?,
    })
}

fn parse_source_selection(node: &XmlNode) -> Result<PersistedSourceSelectionCriteria, PersistenceCodecError> {
    reject_unknown(node, &["ReplicaModifications", "SseKmsEncryptedObjects"])?;
    Ok(PersistedSourceSelectionCriteria {
        replica_modifications: optional_child(node, "ReplicaModifications")?.map(parse_status).transpose()?,
        sse_kms_encrypted_objects: optional_child(node, "SseKmsEncryptedObjects")?
            .map(parse_status)
            .transpose()?,
    })
}

fn parse_status(node: &XmlNode) -> Result<PersistedReplicationStatus, PersistenceCodecError> {
    reject_unknown(node, &["Status"])?;
    Ok(PersistedReplicationStatus {
        status: required_text(node, "Status")?,
    })
}

fn parse_optional_status(node: &XmlNode) -> Result<PersistedOptionalReplicationStatus, PersistenceCodecError> {
    reject_unknown(node, &["Status"])?;
    Ok(PersistedOptionalReplicationStatus {
        status: optional_text(node, "Status")?,
    })
}

fn required_child<'a>(parent: &'a XmlNode, name: &'a str) -> Result<&'a XmlNode, PersistenceCodecError> {
    optional_child(parent, name)?.ok_or(PersistenceCodecError::MissingRequiredField)
}

fn required_text(parent: &XmlNode, name: &str) -> Result<String, PersistenceCodecError> {
    optional_text(parent, name)?.ok_or(PersistenceCodecError::MissingRequiredField)
}

fn optional_i32(parent: &XmlNode, name: &str) -> Result<Option<i32>, PersistenceCodecError> {
    optional_text(parent, name)?
        .map(|value| value.parse().map_err(|_| PersistenceCodecError::InvalidReplicationInteger))
        .transpose()
}

fn optional_text(parent: &XmlNode, name: &str) -> Result<Option<String>, PersistenceCodecError> {
    let Some(child) = optional_child(parent, name)? else {
        return Ok(None);
    };
    if !child.children.is_empty() {
        return Err(PersistenceCodecError::UnexpectedScalarElement);
    }
    Ok(Some(child.text.clone()))
}

fn reject_unknown(parent: &XmlNode, allowed: &[&str]) -> Result<(), PersistenceCodecError> {
    if parent.children.iter().any(|child| !allowed.contains(&child.name.as_str())) {
        return Err(PersistenceCodecError::UnexpectedReplicationElement);
    }
    Ok(())
}

/// Serializes Replication into the exact old persistence field order and element form.
///
/// # Errors
///
/// Returns [`PersistenceCodecError`] when required rules are absent.
pub fn serialize_replication(value: &PersistedReplicationConfiguration) -> Result<Vec<u8>, PersistenceCodecError> {
    if value.rules.is_empty() {
        return Err(PersistenceCodecError::MissingReplicationRule);
    }
    let mut writer = XmlWriter::fragment();
    writer.open("ReplicationConfiguration", None);
    writer.element("Role", &value.role);
    for rule in &value.rules {
        write_rule(&mut writer, rule);
    }
    writer.close();
    Ok(writer.finish().into_bytes())
}

fn write_rule(writer: &mut XmlWriter, value: &PersistedReplicationRule) {
    writer.open("Rule", None);
    if let Some(value) = value.delete_marker_replication.as_ref() {
        writer.open("DeleteMarkerReplication", None);
        write_optional(writer, "Status", value.status.as_deref());
        writer.close();
    }
    write_status_wrapper(writer, "DeleteReplication", value.delete_replication.as_ref());
    write_destination(writer, &value.destination);
    write_status_wrapper(writer, "ExistingObjectReplication", value.existing_object_replication.as_ref());
    if let Some(filter) = value.filter.as_ref() {
        write_filter(writer, filter);
    }
    write_optional(writer, "ID", value.id.as_deref());
    write_optional(writer, "Prefix", value.prefix.as_deref());
    write_i32(writer, "Priority", value.priority);
    if let Some(criteria) = value.source_selection_criteria.as_ref() {
        writer.open("SourceSelectionCriteria", None);
        write_status_wrapper(writer, "ReplicaModifications", criteria.replica_modifications.as_ref());
        write_status_wrapper(writer, "SseKmsEncryptedObjects", criteria.sse_kms_encrypted_objects.as_ref());
        writer.close();
    }
    writer.element("Status", &value.status);
    writer.close();
}

fn write_destination(writer: &mut XmlWriter, value: &PersistedReplicationDestination) {
    writer.open("Destination", None);
    if let Some(translation) = value.access_control_translation.as_ref() {
        writer.open("AccessControlTranslation", None);
        writer.element("Owner", &translation.owner);
        writer.close();
    }
    write_optional(writer, "Account", value.account.as_deref());
    writer.element("Bucket", &value.bucket);
    if let Some(encryption) = value.encryption_configuration.as_ref() {
        writer.open("EncryptionConfiguration", None);
        write_optional(writer, "ReplicaKmsKeyID", encryption.replica_kms_key_id.as_deref());
        writer.close();
    }
    if let Some(metrics) = value.metrics.as_ref() {
        writer.open("Metrics", None);
        if let Some(event_threshold) = metrics.event_threshold.as_ref() {
            writer.open("EventThreshold", None);
            write_i32(writer, "Minutes", event_threshold.minutes);
            writer.close();
        }
        writer.element("Status", &metrics.status);
        writer.close();
    }
    if let Some(replication_time) = value.replication_time.as_ref() {
        writer.open("ReplicationTime", None);
        writer.element("Status", &replication_time.status);
        writer.open("Time", None);
        write_i32(writer, "Minutes", replication_time.time.minutes);
        writer.close();
        writer.close();
    }
    write_optional(writer, "StorageClass", value.storage_class.as_deref());
    writer.close();
}

fn write_filter(writer: &mut XmlWriter, value: &PersistedReplicationFilter) {
    writer.open("Filter", None);
    if let Some(and) = value.and.as_ref() {
        writer.open("And", None);
        write_optional(writer, "Prefix", and.prefix.as_deref());
        if let Some(tags) = and.tags.as_deref() {
            for tag in tags {
                write_tag(writer, tag);
            }
        }
        writer.close();
    }
    write_optional(writer, "Prefix", value.prefix.as_deref());
    if let Some(tag) = value.tag.as_ref() {
        write_tag(writer, tag);
    }
    writer.close();
}

fn write_tag(writer: &mut XmlWriter, value: &PersistedReplicationTag) {
    writer.open("Tag", None);
    write_optional(writer, "Key", value.key.as_deref());
    write_optional(writer, "Value", value.value.as_deref());
    writer.close();
}

fn write_status_wrapper(writer: &mut XmlWriter, name: &str, value: Option<&PersistedReplicationStatus>) {
    if let Some(value) = value {
        writer.open(name, None);
        writer.element("Status", &value.status);
        writer.close();
    }
}

fn write_optional(writer: &mut XmlWriter, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        writer.element(name, value);
    }
}

fn write_i32(writer: &mut XmlWriter, name: &str, value: Option<i32>) {
    if let Some(value) = value {
        writer.element(name, &value.to_string());
    }
}
