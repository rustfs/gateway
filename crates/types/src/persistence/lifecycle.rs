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

//! Persisted Lifecycle XML below the HTTP policy layer.
//!
//! Responsible for: lossless known-field parsing and old-order serialization of Lifecycle data.
//! NOT responsible for: validating S3 lifecycle policy combinations or invoking the s3s oracle.
//! Upstream: bounded gateway XML nodes. Downstream: RustFS metadata persistence and goldens.

use rustfs_gateway_xml::{XmlLimits, XmlNode, XmlWriter, parse_with_limits};

use super::{PersistenceCodecError, optional_child, optional_child_text};
use crate::ext::{CodecPolicy, ExtError, Extensions, PersistedXml};
use crate::{Timestamp, TimestampFormat};

/// The complete Lifecycle configuration persisted by the old RustFS path.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedLifecycleConfiguration {
    /// Server-maintained lifecycle update timestamp in s3s DateTime form.
    pub expiry_updated_at: Option<String>,
    /// Lifecycle rules in their persisted order.
    pub rules: Vec<PersistedLifecycleRule>,
}

/// A persisted Lifecycle configuration plus per-rule runtime extension values.
#[derive(Debug)]
pub struct ExtensibleLifecycleConfiguration {
    /// Static known fields decoded by the production Lifecycle codec.
    pub configuration: PersistedLifecycleConfiguration,
    /// Runtime extension values, one entry for each rule at the same index.
    pub rule_extensions: Vec<Extensions>,
}

/// One persisted Lifecycle rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedLifecycleRule {
    /// Multipart-upload abort action.
    pub abort_incomplete_multipart_upload: Option<PersistedAbortIncompleteMultipartUpload>,
    /// MinIO delete-marker expiration extension.
    pub del_marker_expiration: Option<PersistedDelMarkerExpiration>,
    /// Current-version expiration action.
    pub expiration: Option<PersistedLifecycleExpiration>,
    /// Rule selection filter.
    pub filter: Option<PersistedLifecycleFilter>,
    /// Optional rule identifier.
    pub id: Option<String>,
    /// Noncurrent-version expiration action.
    pub noncurrent_version_expiration: Option<PersistedNoncurrentVersionExpiration>,
    /// Noncurrent-version transition actions in persisted order.
    pub noncurrent_version_transitions: Option<Vec<PersistedNoncurrentVersionTransition>>,
    /// Legacy prefix selector.
    pub prefix: Option<String>,
    /// Required rule status, including unknown values accepted by the old string newtype.
    pub status: String,
    /// Current-version transition actions in persisted order.
    pub transitions: Option<Vec<PersistedTransition>>,
}

impl PersistedLifecycleRule {
    /// Whether this rule participates in Lifecycle evaluation.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.status == "Enabled"
    }
}

/// Abort-incomplete-multipart-upload action.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedAbortIncompleteMultipartUpload {
    /// Days after initiation before abort.
    pub days_after_initiation: Option<i32>,
}

/// MinIO delete-marker expiration extension.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedDelMarkerExpiration {
    /// Days before deleting a marker.
    pub days: Option<i32>,
}

/// Current-version expiration action.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedLifecycleExpiration {
    /// Absolute expiration date in s3s DateTime form.
    pub date: Option<String>,
    /// Relative expiration age in days.
    pub days: Option<i32>,
    /// Whether every expired version is removed.
    pub expired_object_all_versions: Option<bool>,
    /// Whether an expired delete marker is removed.
    pub expired_object_delete_marker: Option<bool>,
}

/// Rule filter.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedLifecycleFilter {
    /// Conjunctive filter wrapper.
    pub and: Option<PersistedLifecycleAnd>,
    /// Inclusive lower object-size boundary.
    pub object_size_greater_than: Option<i64>,
    /// Exclusive upper object-size boundary.
    pub object_size_less_than: Option<i64>,
    /// Prefix selector.
    pub prefix: Option<String>,
    /// Single tag selector.
    pub tag: Option<PersistedLifecycleTag>,
}

/// Conjunctive rule filter.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedLifecycleAnd {
    /// Inclusive lower object-size boundary.
    pub object_size_greater_than: Option<i64>,
    /// Exclusive upper object-size boundary.
    pub object_size_less_than: Option<i64>,
    /// Prefix selector.
    pub prefix: Option<String>,
    /// Tag selectors in persisted order.
    pub tags: Option<Vec<PersistedLifecycleTag>>,
}

/// Lifecycle tag selector.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedLifecycleTag {
    /// Tag key; an explicit empty value remains present.
    pub key: Option<String>,
    /// Tag value; an explicit empty value remains present.
    pub value: Option<String>,
}

/// Noncurrent-version expiration action.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedNoncurrentVersionExpiration {
    /// Number of newer noncurrent versions to retain.
    pub newer_noncurrent_versions: Option<i32>,
    /// Age in days before expiration.
    pub noncurrent_days: Option<i32>,
}

/// Noncurrent-version transition action.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedNoncurrentVersionTransition {
    /// Number of newer noncurrent versions to retain.
    pub newer_noncurrent_versions: Option<i32>,
    /// Age in days before transition.
    pub noncurrent_days: Option<i32>,
    /// Target storage class, including old-readable unknown values.
    pub storage_class: Option<String>,
}

/// Current-version transition action.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedTransition {
    /// Absolute transition date in s3s DateTime form.
    pub date: Option<String>,
    /// Relative transition age in days.
    pub days: Option<i32>,
    /// Target storage class, including old-readable unknown values.
    pub storage_class: Option<String>,
}

/// Parses persisted Lifecycle bytes without applying HTTP policy validation.
///
/// Unknown top-level elements and attributes are ignored. Unknown nested elements and repeated
/// optional known fields are rejected, while list fields retain every occurrence in document order.
///
/// # Errors
///
/// Returns [`PersistenceCodecError`] for malformed XML, a wrong root, a missing rule status,
/// duplicate optional fields, or invalid integer/boolean lexemes.
pub fn parse_lifecycle(input: &[u8]) -> Result<PersistedLifecycleConfiguration, PersistenceCodecError> {
    let bound = input.len().max(1);
    let Some(limits) = XmlLimits::new(bound, bound, bound, bound, bound) else {
        unreachable!("max(1) makes every persistence XML limit non-zero");
    };
    let root = parse_with_limits(input, limits)?;
    if root.name != "LifecycleConfiguration" {
        return Err(PersistenceCodecError::WrongRoot);
    }
    let rules = root.children_named("Rule").map(parse_rule).collect::<Result<Vec<_>, _>>()?;
    if rules.is_empty() {
        return Err(PersistenceCodecError::MissingLifecycleRule);
    }
    Ok(PersistedLifecycleConfiguration {
        expiry_updated_at: optional_timestamp(&root, "ExpiryUpdatedAt")?,
        rules,
    })
}

/// Decodes persisted Lifecycle bytes with a borrowed runtime extension policy.
///
/// The exact input is retained even when the static parent codec, one extension vtable, or one
/// unregistered child refuses the document. Callers can inspect that refusal but cannot replace
/// the stored bytes through [`PersistedXml::replacement`].
#[must_use]
pub fn parse_lifecycle_with_policy(input: &[u8], policy: &CodecPolicy) -> PersistedXml<ExtensibleLifecycleConfiguration> {
    PersistedXml::decode(input.to_vec(), |source| parse_extensible_lifecycle(source, policy))
}

fn parse_extensible_lifecycle(input: &[u8], policy: &CodecPolicy) -> Result<ExtensibleLifecycleConfiguration, ExtError> {
    let bound = input.len().max(1);
    let Some(limits) = XmlLimits::new(bound, bound, bound, bound, bound) else {
        unreachable!("max(1) makes every persistence XML limit non-zero");
    };
    let root = parse_with_limits(input, limits).map_err(|_| ExtError::ParentCodec)?;
    if root.name != "LifecycleConfiguration" {
        return Err(ExtError::ParentCodec);
    }
    let mut rules = Vec::new();
    let mut rule_extensions = Vec::new();
    for rule in root.children_named("Rule") {
        let (rule, extensions) = parse_extensible_rule(rule, policy)?;
        rules.push(rule);
        rule_extensions.push(extensions);
    }
    if rules.is_empty() {
        return Err(ExtError::ParentCodec);
    }
    let expiry_updated_at = optional_timestamp(&root, "ExpiryUpdatedAt").map_err(|_| ExtError::ParentCodec)?;
    Ok(ExtensibleLifecycleConfiguration {
        configuration: PersistedLifecycleConfiguration {
            expiry_updated_at,
            rules,
        },
        rule_extensions,
    })
}

const STATIC_RULE_CHILDREN: &[&str] = &[
    "AbortIncompleteMultipartUpload",
    "Expiration",
    "Filter",
    "ID",
    "NoncurrentVersionExpiration",
    "NoncurrentVersionTransition",
    "Prefix",
    "Status",
    "Transition",
];

fn parse_extensible_rule(rule: &XmlNode, policy: &CodecPolicy) -> Result<(PersistedLifecycleRule, Extensions), ExtError> {
    let mut static_rule = rule.clone();
    static_rule
        .children
        .retain(|child| STATIC_RULE_CHILDREN.contains(&child.name.as_str()));
    let parsed = parse_rule(&static_rule).map_err(|_| ExtError::ParentCodec)?;
    let mut extensions = Extensions::default();
    for child in rule
        .children
        .iter()
        .filter(|child| !STATIC_RULE_CHILDREN.contains(&child.name.as_str()))
    {
        policy.decode_unknown("LifecycleRule", child, &mut extensions)?;
    }
    Ok((parsed, extensions))
}

fn parse_rule(rule: &XmlNode) -> Result<PersistedLifecycleRule, PersistenceCodecError> {
    reject_unknown(
        rule,
        &[
            "AbortIncompleteMultipartUpload",
            "DelMarkerExpiration",
            "Expiration",
            "Filter",
            "ID",
            "NoncurrentVersionExpiration",
            "NoncurrentVersionTransition",
            "Prefix",
            "Status",
            "Transition",
        ],
    )?;
    Ok(PersistedLifecycleRule {
        abort_incomplete_multipart_upload: optional_child(rule, "AbortIncompleteMultipartUpload")?
            .map(parse_abort)
            .transpose()?,
        del_marker_expiration: optional_child(rule, "DelMarkerExpiration")?
            .map(parse_del_marker_expiration)
            .transpose()?,
        expiration: optional_child(rule, "Expiration")?.map(parse_expiration).transpose()?,
        filter: optional_child(rule, "Filter")?.map(parse_filter).transpose()?,
        id: optional_child_text(rule, "ID")?,
        noncurrent_version_expiration: optional_child(rule, "NoncurrentVersionExpiration")?
            .map(parse_noncurrent_expiration)
            .transpose()?,
        noncurrent_version_transitions: optional_vec(rule, "NoncurrentVersionTransition", parse_noncurrent_transition)?,
        prefix: optional_child_text(rule, "Prefix")?,
        status: optional_child_text(rule, "Status")?.ok_or(PersistenceCodecError::MissingLifecycleStatus)?,
        transitions: optional_vec(rule, "Transition", parse_transition)?,
    })
}

fn parse_abort(node: &XmlNode) -> Result<PersistedAbortIncompleteMultipartUpload, PersistenceCodecError> {
    reject_unknown(node, &["DaysAfterInitiation"])?;
    Ok(PersistedAbortIncompleteMultipartUpload {
        days_after_initiation: optional_i32(node, "DaysAfterInitiation")?,
    })
}

fn parse_del_marker_expiration(node: &XmlNode) -> Result<PersistedDelMarkerExpiration, PersistenceCodecError> {
    reject_unknown(node, &["Days"])?;
    Ok(PersistedDelMarkerExpiration {
        days: optional_i32(node, "Days")?,
    })
}

fn parse_expiration(node: &XmlNode) -> Result<PersistedLifecycleExpiration, PersistenceCodecError> {
    reject_unknown(node, &["Date", "Days", "ExpiredObjectAllVersions", "ExpiredObjectDeleteMarker"])?;
    Ok(PersistedLifecycleExpiration {
        date: optional_timestamp(node, "Date")?,
        days: optional_i32(node, "Days")?,
        expired_object_all_versions: optional_bool(node, "ExpiredObjectAllVersions")?,
        expired_object_delete_marker: optional_bool(node, "ExpiredObjectDeleteMarker")?,
    })
}

fn parse_filter(node: &XmlNode) -> Result<PersistedLifecycleFilter, PersistenceCodecError> {
    reject_unknown(node, &["And", "ObjectSizeGreaterThan", "ObjectSizeLessThan", "Prefix", "Tag"])?;
    Ok(PersistedLifecycleFilter {
        and: optional_child(node, "And")?.map(parse_and).transpose()?,
        object_size_greater_than: optional_i64(node, "ObjectSizeGreaterThan")?,
        object_size_less_than: optional_i64(node, "ObjectSizeLessThan")?,
        prefix: optional_child_text(node, "Prefix")?,
        tag: optional_child(node, "Tag")?.map(parse_tag).transpose()?,
    })
}

fn parse_and(node: &XmlNode) -> Result<PersistedLifecycleAnd, PersistenceCodecError> {
    reject_unknown(node, &["ObjectSizeGreaterThan", "ObjectSizeLessThan", "Prefix", "Tag"])?;
    Ok(PersistedLifecycleAnd {
        object_size_greater_than: optional_i64(node, "ObjectSizeGreaterThan")?,
        object_size_less_than: optional_i64(node, "ObjectSizeLessThan")?,
        prefix: optional_child_text(node, "Prefix")?,
        tags: optional_vec(node, "Tag", parse_tag)?,
    })
}

fn parse_tag(node: &XmlNode) -> Result<PersistedLifecycleTag, PersistenceCodecError> {
    reject_unknown(node, &["Key", "Value"])?;
    Ok(PersistedLifecycleTag {
        key: optional_child_text(node, "Key")?,
        value: optional_child_text(node, "Value")?,
    })
}

fn parse_noncurrent_expiration(node: &XmlNode) -> Result<PersistedNoncurrentVersionExpiration, PersistenceCodecError> {
    reject_unknown(node, &["NewerNoncurrentVersions", "NoncurrentDays"])?;
    Ok(PersistedNoncurrentVersionExpiration {
        newer_noncurrent_versions: optional_i32(node, "NewerNoncurrentVersions")?,
        noncurrent_days: optional_i32(node, "NoncurrentDays")?,
    })
}

fn parse_noncurrent_transition(node: &XmlNode) -> Result<PersistedNoncurrentVersionTransition, PersistenceCodecError> {
    reject_unknown(node, &["NewerNoncurrentVersions", "NoncurrentDays", "StorageClass"])?;
    Ok(PersistedNoncurrentVersionTransition {
        newer_noncurrent_versions: optional_i32(node, "NewerNoncurrentVersions")?,
        noncurrent_days: optional_i32(node, "NoncurrentDays")?,
        storage_class: optional_child_text(node, "StorageClass")?,
    })
}

fn parse_transition(node: &XmlNode) -> Result<PersistedTransition, PersistenceCodecError> {
    reject_unknown(node, &["Date", "Days", "StorageClass"])?;
    Ok(PersistedTransition {
        date: optional_timestamp(node, "Date")?,
        days: optional_i32(node, "Days")?,
        storage_class: optional_child_text(node, "StorageClass")?,
    })
}

fn optional_vec<T>(
    parent: &XmlNode,
    name: &str,
    parse: fn(&XmlNode) -> Result<T, PersistenceCodecError>,
) -> Result<Option<Vec<T>>, PersistenceCodecError> {
    let values = parent.children_named(name).map(parse).collect::<Result<Vec<_>, _>>()?;
    Ok((!values.is_empty()).then_some(values))
}

fn reject_unknown(parent: &XmlNode, allowed: &[&str]) -> Result<(), PersistenceCodecError> {
    if parent.children.iter().any(|child| !allowed.contains(&child.name.as_str())) {
        return Err(PersistenceCodecError::UnexpectedLifecycleElement);
    }
    Ok(())
}

fn optional_i32(parent: &XmlNode, name: &str) -> Result<Option<i32>, PersistenceCodecError> {
    optional_number(parent, name)
}

fn optional_i64(parent: &XmlNode, name: &str) -> Result<Option<i64>, PersistenceCodecError> {
    optional_number(parent, name)
}

fn optional_number<T: core::str::FromStr>(parent: &XmlNode, name: &str) -> Result<Option<T>, PersistenceCodecError> {
    optional_child_text(parent, name)?
        .map(|value| value.parse().map_err(|_| PersistenceCodecError::InvalidLifecycleInteger))
        .transpose()
}

fn optional_bool(parent: &XmlNode, name: &str) -> Result<Option<bool>, PersistenceCodecError> {
    optional_child_text(parent, name)?
        .map(|value| match value.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(PersistenceCodecError::InvalidLifecycleBoolean),
        })
        .transpose()
}

fn optional_timestamp(parent: &XmlNode, name: &str) -> Result<Option<String>, PersistenceCodecError> {
    optional_child_text(parent, name)?
        .map(|value| canonical_timestamp(&value))
        .transpose()
}

fn canonical_timestamp(value: &str) -> Result<String, PersistenceCodecError> {
    // The pinned time/RFC3339 parser accepts a space separator and renders it back with `T`.
    let normalized = (value.as_bytes().get(10) == Some(&b' ')).then(|| {
        let mut normalized = value.to_owned();
        normalized.replace_range(10..11, "T");
        normalized
    });
    Timestamp::parse(normalized.as_deref().unwrap_or(value), TimestampFormat::Iso8601)
        .and_then(|timestamp| timestamp.render(TimestampFormat::Iso8601))
        .map_err(|_| PersistenceCodecError::InvalidLifecycleTimestamp)
}

/// Serializes Lifecycle into the exact old persistence field order and element form.
pub fn serialize_lifecycle(value: &PersistedLifecycleConfiguration) -> Result<Vec<u8>, PersistenceCodecError> {
    if value.rules.is_empty() {
        return Err(PersistenceCodecError::MissingLifecycleRule);
    }
    let mut writer = XmlWriter::fragment();
    writer.open("LifecycleConfiguration", None);
    write_timestamp(&mut writer, "ExpiryUpdatedAt", value.expiry_updated_at.as_deref())?;
    for rule in &value.rules {
        write_rule(&mut writer, rule)?;
    }
    writer.close();
    Ok(writer.finish().into_bytes())
}

/// Serializes a completely decoded Lifecycle document with registered extensions.
///
/// Registered fields are emitted only at a sibling slot the static parent declares. The
/// `LifecycleRule` parent exposes `Expiration` as the insertion point before `Filter`, `ID`, and
/// `Status`; every other requested slot fails closed.
pub fn serialize_lifecycle_with_policy(
    value: &ExtensibleLifecycleConfiguration,
    policy: &CodecPolicy,
) -> Result<Vec<u8>, ExtError> {
    if value.configuration.rules.is_empty() || value.configuration.rules.len() != value.rule_extensions.len() {
        return Err(ExtError::ParentCodec);
    }
    policy.validate_slots("LifecycleRule", &["Expiration"])?;
    let mut writer = XmlWriter::fragment();
    writer.open("LifecycleConfiguration", None);
    write_timestamp(&mut writer, "ExpiryUpdatedAt", value.configuration.expiry_updated_at.as_deref())
        .map_err(|_| ExtError::ParentCodec)?;
    for (rule, extensions) in value.configuration.rules.iter().zip(&value.rule_extensions) {
        write_extensible_rule(&mut writer, rule, extensions, policy)?;
    }
    writer.close();
    Ok(writer.finish().into_bytes())
}

fn write_extensible_rule(
    writer: &mut XmlWriter,
    value: &PersistedLifecycleRule,
    extensions: &Extensions,
    policy: &CodecPolicy,
) -> Result<(), ExtError> {
    writer.open("Rule", None);
    if let Some(action) = value.abort_incomplete_multipart_upload.as_ref() {
        writer.open("AbortIncompleteMultipartUpload", None);
        write_number(writer, "DaysAfterInitiation", action.days_after_initiation);
        writer.close();
    }
    if let Some(action) = value.expiration.as_ref() {
        writer.open("Expiration", None);
        write_timestamp(writer, "Date", action.date.as_deref()).map_err(|_| ExtError::ParentCodec)?;
        write_number(writer, "Days", action.days);
        write_bool(writer, "ExpiredObjectAllVersions", action.expired_object_all_versions);
        write_bool(writer, "ExpiredObjectDeleteMarker", action.expired_object_delete_marker);
        writer.close();
    }
    policy.encode_after("LifecycleRule", "Expiration", extensions, writer)?;
    if let Some(filter) = value.filter.as_ref() {
        write_filter(writer, filter);
    }
    write_optional(writer, "ID", value.id.as_deref());
    if let Some(action) = value.noncurrent_version_expiration.as_ref() {
        writer.open("NoncurrentVersionExpiration", None);
        write_number(writer, "NewerNoncurrentVersions", action.newer_noncurrent_versions);
        write_number(writer, "NoncurrentDays", action.noncurrent_days);
        writer.close();
    }
    if let Some(actions) = value.noncurrent_version_transitions.as_deref() {
        for action in actions {
            writer.open("NoncurrentVersionTransition", None);
            write_number(writer, "NewerNoncurrentVersions", action.newer_noncurrent_versions);
            write_number(writer, "NoncurrentDays", action.noncurrent_days);
            write_optional(writer, "StorageClass", action.storage_class.as_deref());
            writer.close();
        }
    }
    write_optional(writer, "Prefix", value.prefix.as_deref());
    writer.element("Status", &value.status);
    if let Some(actions) = value.transitions.as_deref() {
        for action in actions {
            writer.open("Transition", None);
            write_timestamp(writer, "Date", action.date.as_deref()).map_err(|_| ExtError::ParentCodec)?;
            write_number(writer, "Days", action.days);
            write_optional(writer, "StorageClass", action.storage_class.as_deref());
            writer.close();
        }
    }
    writer.close();
    Ok(())
}

fn write_rule(writer: &mut XmlWriter, value: &PersistedLifecycleRule) -> Result<(), PersistenceCodecError> {
    writer.open("Rule", None);
    if let Some(action) = value.abort_incomplete_multipart_upload.as_ref() {
        writer.open("AbortIncompleteMultipartUpload", None);
        write_number(writer, "DaysAfterInitiation", action.days_after_initiation);
        writer.close();
    }
    if let Some(action) = value.del_marker_expiration.as_ref() {
        writer.open("DelMarkerExpiration", None);
        write_number(writer, "Days", action.days);
        writer.close();
    }
    if let Some(action) = value.expiration.as_ref() {
        writer.open("Expiration", None);
        write_timestamp(writer, "Date", action.date.as_deref())?;
        write_number(writer, "Days", action.days);
        write_bool(writer, "ExpiredObjectAllVersions", action.expired_object_all_versions);
        write_bool(writer, "ExpiredObjectDeleteMarker", action.expired_object_delete_marker);
        writer.close();
    }
    if let Some(filter) = value.filter.as_ref() {
        write_filter(writer, filter);
    }
    write_optional(writer, "ID", value.id.as_deref());
    if let Some(action) = value.noncurrent_version_expiration.as_ref() {
        writer.open("NoncurrentVersionExpiration", None);
        write_number(writer, "NewerNoncurrentVersions", action.newer_noncurrent_versions);
        write_number(writer, "NoncurrentDays", action.noncurrent_days);
        writer.close();
    }
    if let Some(actions) = value.noncurrent_version_transitions.as_deref() {
        for action in actions {
            writer.open("NoncurrentVersionTransition", None);
            write_number(writer, "NewerNoncurrentVersions", action.newer_noncurrent_versions);
            write_number(writer, "NoncurrentDays", action.noncurrent_days);
            write_optional(writer, "StorageClass", action.storage_class.as_deref());
            writer.close();
        }
    }
    write_optional(writer, "Prefix", value.prefix.as_deref());
    writer.element("Status", &value.status);
    if let Some(actions) = value.transitions.as_deref() {
        for action in actions {
            writer.open("Transition", None);
            write_timestamp(writer, "Date", action.date.as_deref())?;
            write_number(writer, "Days", action.days);
            write_optional(writer, "StorageClass", action.storage_class.as_deref());
            writer.close();
        }
    }
    writer.close();
    Ok(())
}

fn write_filter(writer: &mut XmlWriter, value: &PersistedLifecycleFilter) {
    writer.open("Filter", None);
    if let Some(and) = value.and.as_ref() {
        writer.open("And", None);
        write_number(writer, "ObjectSizeGreaterThan", and.object_size_greater_than);
        write_number(writer, "ObjectSizeLessThan", and.object_size_less_than);
        write_optional(writer, "Prefix", and.prefix.as_deref());
        if let Some(tags) = and.tags.as_deref() {
            for tag in tags {
                write_tag(writer, tag);
            }
        }
        writer.close();
    }
    write_number(writer, "ObjectSizeGreaterThan", value.object_size_greater_than);
    write_number(writer, "ObjectSizeLessThan", value.object_size_less_than);
    write_optional(writer, "Prefix", value.prefix.as_deref());
    if let Some(tag) = value.tag.as_ref() {
        write_tag(writer, tag);
    }
    writer.close();
}

fn write_tag(writer: &mut XmlWriter, value: &PersistedLifecycleTag) {
    writer.open("Tag", None);
    write_optional(writer, "Key", value.key.as_deref());
    write_optional(writer, "Value", value.value.as_deref());
    writer.close();
}

fn write_optional(writer: &mut XmlWriter, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        writer.element(name, value);
    }
}

fn write_timestamp(writer: &mut XmlWriter, name: &str, value: Option<&str>) -> Result<(), PersistenceCodecError> {
    if let Some(value) = value {
        writer.element(name, &canonical_timestamp(value)?);
    }
    Ok(())
}

fn write_number<T: ToString>(writer: &mut XmlWriter, name: &str, value: Option<T>) {
    if let Some(value) = value {
        writer.element(name, &value.to_string());
    }
}

fn write_bool(writer: &mut XmlWriter, name: &str, value: Option<bool>) {
    if let Some(value) = value {
        writer.element_bool(name, value);
    }
}
