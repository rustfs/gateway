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

//! Pinned-s3s Lifecycle persistence adapter.
//!
//! Responsible for: translating pinned-s3s Lifecycle XML observations into owned persistence
//! structures and decisions. NOT responsible for: production parsing, policy validation, or golden
//! assertions. Upstream: the s3s revision bound by the enclosing oracle instance. Downstream: the compat facade.

use super::s3s::dto::{
    AbortIncompleteMultipartUpload, BucketLifecycleConfiguration, DelMarkerExpiration, ExpirationStatus, LifecycleExpiration,
    LifecycleRule, LifecycleRuleAndOperator, LifecycleRuleFilter, NoncurrentVersionExpiration, NoncurrentVersionTransition, Tag,
    Timestamp, TimestampFormat, Transition, TransitionStorageClass,
};
use super::s3s::xml::{Deserialize, Deserializer, Serialize, Serializer};
use crate::persistence::{
    PersistedAbortIncompleteMultipartUpload, PersistedDelMarkerExpiration, PersistedLifecycleAnd,
    PersistedLifecycleConfiguration, PersistedLifecycleExpiration, PersistedLifecycleFilter, PersistedLifecycleRule,
    PersistedLifecycleTag, PersistedNoncurrentVersionExpiration, PersistedNoncurrentVersionTransition, PersistedTransition,
};
use rustfs_gateway_xml::XmlWriter;

use crate::compat::{CompatCodecError, S3sLifecycleObservation};

/// Parses Lifecycle bytes with the pinned s3s persistence decoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when s3s rejects the document, a timestamp cannot be rendered,
/// or trailing input remains.
pub(crate) fn parse_s3s_lifecycle(input: &[u8]) -> Result<S3sLifecycleObservation, CompatCodecError> {
    let mut deserializer = Deserializer::new(input);
    let value = BucketLifecycleConfiguration::deserialize(&mut deserializer).map_err(CompatCodecError::old_codec)?;
    deserializer.expect_eof().map_err(CompatCodecError::old_codec)?;
    let rule_enabled = value
        .rules
        .iter()
        .map(|rule| rule.status.as_str() == ExpirationStatus::ENABLED)
        .collect();
    Ok(S3sLifecycleObservation {
        structure: from_s3s_lifecycle(value)?,
        rule_enabled,
    })
}

/// Serializes a Lifecycle value with the pinned s3s persistence encoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when a timestamp is not old-readable or s3s cannot render the value.
pub(crate) fn serialize_s3s_lifecycle(value: &PersistedLifecycleConfiguration) -> Result<Vec<u8>, CompatCodecError> {
    let old_value = BucketLifecycleConfiguration {
        expiry_updated_at: value.expiry_updated_at.as_deref().map(parse_s3s_timestamp).transpose()?,
        rules: value.rules.iter().map(to_s3s_rule).collect::<Result<_, _>>()?,
    };
    let mut output = Vec::with_capacity(1024);
    let mut serializer = Serializer::new(&mut output);
    old_value.serialize(&mut serializer).map_err(CompatCodecError::old_codec)?;
    Ok(output)
}

fn from_s3s_lifecycle(value: BucketLifecycleConfiguration) -> Result<PersistedLifecycleConfiguration, CompatCodecError> {
    Ok(PersistedLifecycleConfiguration {
        expiry_updated_at: value.expiry_updated_at.as_ref().map(format_s3s_timestamp).transpose()?,
        rules: value.rules.into_iter().map(from_s3s_rule).collect::<Result<_, _>>()?,
    })
}

fn from_s3s_rule(value: LifecycleRule) -> Result<PersistedLifecycleRule, CompatCodecError> {
    Ok(PersistedLifecycleRule {
        abort_incomplete_multipart_upload: value.abort_incomplete_multipart_upload.map(|action| {
            PersistedAbortIncompleteMultipartUpload {
                days_after_initiation: action.days_after_initiation,
            }
        }),
        del_marker_expiration: value
            .del_marker_expiration
            .map(|action| PersistedDelMarkerExpiration { days: action.days }),
        expiration: value
            .expiration
            .map(|action| {
                Ok(PersistedLifecycleExpiration {
                    date: action.date.as_ref().map(format_s3s_timestamp).transpose()?,
                    days: action.days,
                    expired_object_all_versions: action.expired_object_all_versions,
                    expired_object_delete_marker: action.expired_object_delete_marker,
                })
            })
            .transpose()?,
        filter: value.filter.map(from_s3s_filter),
        id: value.id,
        noncurrent_version_expiration: value
            .noncurrent_version_expiration
            .map(|action| PersistedNoncurrentVersionExpiration {
                newer_noncurrent_versions: action.newer_noncurrent_versions,
                noncurrent_days: action.noncurrent_days,
            }),
        noncurrent_version_transitions: value.noncurrent_version_transitions.map(|actions| {
            actions
                .into_iter()
                .map(|action| PersistedNoncurrentVersionTransition {
                    newer_noncurrent_versions: action.newer_noncurrent_versions,
                    noncurrent_days: action.noncurrent_days,
                    storage_class: action.storage_class.map(|class| class.as_str().to_owned()),
                })
                .collect()
        }),
        prefix: value.prefix,
        status: value.status.as_str().to_owned(),
        transitions: value
            .transitions
            .map(|actions| actions.into_iter().map(from_s3s_transition).collect::<Result<_, _>>())
            .transpose()?,
    })
}

fn from_s3s_filter(value: LifecycleRuleFilter) -> PersistedLifecycleFilter {
    PersistedLifecycleFilter {
        and: value.and.map(|and| PersistedLifecycleAnd {
            object_size_greater_than: and.object_size_greater_than,
            object_size_less_than: and.object_size_less_than,
            prefix: and.prefix,
            tags: and.tags.map(|tags| tags.into_iter().map(from_s3s_tag).collect()),
        }),
        object_size_greater_than: value.object_size_greater_than,
        object_size_less_than: value.object_size_less_than,
        prefix: value.prefix,
        tag: value.tag.map(from_s3s_tag),
    }
}

fn from_s3s_tag(value: Tag) -> PersistedLifecycleTag {
    PersistedLifecycleTag {
        key: value.key,
        value: value.value,
    }
}

fn from_s3s_transition(value: Transition) -> Result<PersistedTransition, CompatCodecError> {
    Ok(PersistedTransition {
        date: value.date.as_ref().map(format_s3s_timestamp).transpose()?,
        days: value.days,
        storage_class: value.storage_class.map(|class| class.as_str().to_owned()),
    })
}

fn to_s3s_rule(value: &PersistedLifecycleRule) -> Result<LifecycleRule, CompatCodecError> {
    Ok(LifecycleRule {
        abort_incomplete_multipart_upload: value.abort_incomplete_multipart_upload.as_ref().map(|action| {
            AbortIncompleteMultipartUpload {
                days_after_initiation: action.days_after_initiation,
            }
        }),
        del_marker_expiration: value
            .del_marker_expiration
            .as_ref()
            .map(|action| DelMarkerExpiration { days: action.days }),
        expiration: value
            .expiration
            .as_ref()
            .map(|action| {
                Ok(LifecycleExpiration {
                    date: action.date.as_deref().map(parse_s3s_timestamp).transpose()?,
                    days: action.days,
                    expired_object_all_versions: action.expired_object_all_versions,
                    expired_object_delete_marker: action.expired_object_delete_marker,
                })
            })
            .transpose()?,
        filter: value.filter.as_ref().map(to_s3s_filter),
        id: value.id.clone(),
        noncurrent_version_expiration: value
            .noncurrent_version_expiration
            .as_ref()
            .map(|action| NoncurrentVersionExpiration {
                newer_noncurrent_versions: action.newer_noncurrent_versions,
                noncurrent_days: action.noncurrent_days,
            }),
        noncurrent_version_transitions: value.noncurrent_version_transitions.as_ref().map(|actions| {
            actions
                .iter()
                .map(|action| NoncurrentVersionTransition {
                    newer_noncurrent_versions: action.newer_noncurrent_versions,
                    noncurrent_days: action.noncurrent_days,
                    storage_class: action.storage_class.clone().map(TransitionStorageClass::from),
                })
                .collect()
        }),
        prefix: value.prefix.clone(),
        status: ExpirationStatus::from(value.status.clone()),
        transitions: value
            .transitions
            .as_ref()
            .map(|actions| actions.iter().map(to_s3s_transition).collect::<Result<_, _>>())
            .transpose()?,
    })
}

fn to_s3s_filter(value: &PersistedLifecycleFilter) -> LifecycleRuleFilter {
    LifecycleRuleFilter {
        and: value.and.as_ref().map(|and| LifecycleRuleAndOperator {
            object_size_greater_than: and.object_size_greater_than,
            object_size_less_than: and.object_size_less_than,
            prefix: and.prefix.clone(),
            tags: and.tags.as_ref().map(|tags| tags.iter().map(to_s3s_tag).collect()),
        }),
        object_size_greater_than: value.object_size_greater_than,
        object_size_less_than: value.object_size_less_than,
        prefix: value.prefix.clone(),
        tag: value.tag.as_ref().map(to_s3s_tag),
        ..LifecycleRuleFilter::default()
    }
}

fn to_s3s_tag(value: &PersistedLifecycleTag) -> Tag {
    Tag {
        key: value.key.clone(),
        value: value.value.clone(),
    }
}

fn to_s3s_transition(value: &PersistedTransition) -> Result<Transition, CompatCodecError> {
    Ok(Transition {
        date: value.date.as_deref().map(parse_s3s_timestamp).transpose()?,
        days: value.days,
        storage_class: value.storage_class.clone().map(TransitionStorageClass::from),
    })
}

fn format_s3s_timestamp(value: &Timestamp) -> Result<String, CompatCodecError> {
    let mut bytes = Vec::new();
    value
        .format(TimestampFormat::DateTime, &mut bytes)
        .map_err(CompatCodecError::old_codec)?;
    String::from_utf8(bytes).map_err(CompatCodecError::old_codec)
}

fn parse_s3s_timestamp(value: &str) -> Result<Timestamp, CompatCodecError> {
    let mut writer = XmlWriter::fragment();
    writer.open("LifecycleConfiguration", None);
    writer.element("ExpiryUpdatedAt", value);
    writer.open("Rule", None);
    writer.element("Status", "Enabled");
    writer.close();
    writer.close();
    let bytes = writer.finish();
    let mut deserializer = Deserializer::new(bytes.as_bytes());
    let parsed = BucketLifecycleConfiguration::deserialize(&mut deserializer).map_err(CompatCodecError::old_codec)?;
    deserializer.expect_eof().map_err(CompatCodecError::old_codec)?;
    parsed
        .expiry_updated_at
        .ok_or_else(|| CompatCodecError::old_codec("pinned s3s dropped a Lifecycle timestamp"))
}
