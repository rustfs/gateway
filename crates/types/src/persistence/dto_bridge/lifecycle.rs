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

//! Lifecycle generated DTO persistence bridge.
//!
//! Responsible for: lossless conversion through the existing historical Lifecycle codec.
//! NOT responsible for: XML parsing rules, HTTP validation, extension registration, or lifecycle evaluation.
//! Upstream: Lifecycle persistence codec. Downstream: generated DTO metadata consumers.

use super::PersistenceBridgeError;
use crate::persistence::{
    PersistedAbortIncompleteMultipartUpload, PersistedDelMarkerExpiration, PersistedLifecycleAnd,
    PersistedLifecycleConfiguration, PersistedLifecycleExpiration, PersistedLifecycleFilter, PersistedLifecycleRule,
    PersistedLifecycleTag, PersistedNoncurrentVersionExpiration, PersistedNoncurrentVersionTransition, PersistedTransition,
    PersistenceCodecError, parse_lifecycle, serialize_lifecycle,
};
use crate::{Timestamp, TimestampFormat};

/// Parses persisted Lifecycle bytes directly into the generated HTTP DTO.
///
/// # Errors
///
/// Returns [`PersistenceBridgeError::Codec`] when the historical codec rejects the document, or
/// [`PersistenceBridgeError::UnsupportedPersistedMember`] when an old-only member would be lost.
pub fn parse_lifecycle_dto(input: &[u8]) -> Result<crate::dto::BucketLifecycleConfiguration, PersistenceBridgeError> {
    let persisted = parse_lifecycle(input)?;
    Ok(crate::dto::BucketLifecycleConfiguration {
        expiry_updated_at: persisted.expiry_updated_at.as_deref().map(parse_timestamp).transpose()?,
        rules: persisted.rules.into_iter().map(to_dto_rule).collect::<Result<Vec<_>, _>>()?,
    })
}

fn to_dto_rule(value: PersistedLifecycleRule) -> Result<crate::dto::LifecycleRule, PersistenceBridgeError> {
    Ok(crate::dto::LifecycleRule {
        del_marker_expiration: value
            .del_marker_expiration
            .map(|action| crate::dto::DelMarkerExpiration { days: action.days }),
        abort_incomplete_multipart_upload: value.abort_incomplete_multipart_upload.map(|action| {
            crate::dto::AbortIncompleteMultipartUpload {
                days_after_initiation: action.days_after_initiation,
            }
        }),
        expiration: value.expiration.map(to_dto_expiration).transpose()?,
        filter: value.filter.map(to_dto_filter).transpose()?,
        id: value.id,
        noncurrent_version_expiration: value.noncurrent_version_expiration.map(|action| {
            crate::dto::NoncurrentVersionExpiration {
                newer_noncurrent_versions: action.newer_noncurrent_versions,
                noncurrent_days: action.noncurrent_days,
            }
        }),
        noncurrent_version_transitions: value
            .noncurrent_version_transitions
            .unwrap_or_default()
            .into_iter()
            .map(|action| crate::dto::NoncurrentVersionTransition {
                newer_noncurrent_versions: action.newer_noncurrent_versions,
                noncurrent_days: action.noncurrent_days,
                storage_class: action.storage_class.map(crate::dto::StorageClass::custom),
            })
            .collect(),
        prefix: value.prefix,
        status: crate::dto::Status::custom(value.status),
        transitions: value
            .transitions
            .unwrap_or_default()
            .into_iter()
            .map(to_dto_transition)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn to_dto_expiration(value: PersistedLifecycleExpiration) -> Result<crate::dto::LifecycleExpiration, PersistenceBridgeError> {
    Ok(crate::dto::LifecycleExpiration {
        date: value.date.as_deref().map(parse_timestamp).transpose()?,
        days: value.days,
        expired_object_all_versions: value.expired_object_all_versions,
        expired_object_delete_marker: value.expired_object_delete_marker,
    })
}

fn to_dto_filter(value: PersistedLifecycleFilter) -> Result<crate::dto::LifecycleRuleFilter, PersistenceBridgeError> {
    Ok(crate::dto::LifecycleRuleFilter {
        and: value.and.map(to_dto_and).transpose()?,
        object_size_greater_than: value.object_size_greater_than,
        object_size_less_than: value.object_size_less_than,
        prefix: value.prefix,
        tag: value
            .tag
            .map(|tag| to_dto_tag(tag, "LifecycleRule.Filter.Tag.Key", "LifecycleRule.Filter.Tag.Value"))
            .transpose()?,
    })
}

fn to_dto_and(value: PersistedLifecycleAnd) -> Result<crate::dto::LifecycleRuleAndOperator, PersistenceBridgeError> {
    Ok(crate::dto::LifecycleRuleAndOperator {
        object_size_greater_than: value.object_size_greater_than,
        object_size_less_than: value.object_size_less_than,
        prefix: value.prefix,
        tags: value
            .tags
            .unwrap_or_default()
            .into_iter()
            .map(|tag| to_dto_tag(tag, "LifecycleRule.Filter.And.Tag.Key", "LifecycleRule.Filter.And.Tag.Value"))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn to_dto_tag(
    value: PersistedLifecycleTag,
    key_path: &'static str,
    value_path: &'static str,
) -> Result<crate::dto::Tag, PersistenceBridgeError> {
    Ok(crate::dto::Tag {
        key: value
            .key
            .ok_or(PersistenceBridgeError::UnsupportedPersistedMember(key_path))?,
        value: value
            .value
            .ok_or(PersistenceBridgeError::UnsupportedPersistedMember(value_path))?,
    })
}

fn to_dto_transition(value: PersistedTransition) -> Result<crate::dto::Transition, PersistenceBridgeError> {
    Ok(crate::dto::Transition {
        date: value.date.as_deref().map(parse_timestamp).transpose()?,
        days: value.days,
        storage_class: value.storage_class.map(crate::dto::StorageClass::custom),
    })
}

/// Serializes the generated Lifecycle DTO with the historical persistence writer.
///
/// # Errors
///
/// Returns [`PersistenceBridgeError::Codec`] when a timestamp or the historical writer rejects
/// the value.
pub fn serialize_lifecycle_dto(value: &crate::dto::BucketLifecycleConfiguration) -> Result<Vec<u8>, PersistenceBridgeError> {
    let persisted = PersistedLifecycleConfiguration {
        expiry_updated_at: value.expiry_updated_at.as_ref().map(render_timestamp).transpose()?,
        rules: value.rules.iter().map(from_dto_rule).collect::<Result<Vec<_>, _>>()?,
    };
    serialize_lifecycle(&persisted).map_err(Into::into)
}

fn from_dto_rule(value: &crate::dto::LifecycleRule) -> Result<PersistedLifecycleRule, PersistenceBridgeError> {
    Ok(PersistedLifecycleRule {
        abort_incomplete_multipart_upload: value.abort_incomplete_multipart_upload.as_ref().map(|action| {
            PersistedAbortIncompleteMultipartUpload {
                days_after_initiation: action.days_after_initiation,
            }
        }),
        del_marker_expiration: value
            .del_marker_expiration
            .as_ref()
            .map(|action| PersistedDelMarkerExpiration { days: action.days }),
        expiration: value.expiration.as_ref().map(from_dto_expiration).transpose()?,
        filter: value.filter.as_ref().map(from_dto_filter),
        id: value.id.clone(),
        noncurrent_version_expiration: value.noncurrent_version_expiration.as_ref().map(|action| {
            PersistedNoncurrentVersionExpiration {
                newer_noncurrent_versions: action.newer_noncurrent_versions,
                noncurrent_days: action.noncurrent_days,
            }
        }),
        noncurrent_version_transitions: (!value.noncurrent_version_transitions.is_empty()).then(|| {
            value
                .noncurrent_version_transitions
                .iter()
                .map(|action| PersistedNoncurrentVersionTransition {
                    newer_noncurrent_versions: action.newer_noncurrent_versions,
                    noncurrent_days: action.noncurrent_days,
                    storage_class: action
                        .storage_class
                        .as_ref()
                        .map(|storage_class| storage_class.as_str().to_owned()),
                })
                .collect()
        }),
        prefix: value.prefix.clone(),
        status: value.status.as_str().to_owned(),
        transitions: (!value.transitions.is_empty())
            .then(|| {
                value
                    .transitions
                    .iter()
                    .map(from_dto_transition)
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?,
    })
}

fn from_dto_expiration(value: &crate::dto::LifecycleExpiration) -> Result<PersistedLifecycleExpiration, PersistenceBridgeError> {
    Ok(PersistedLifecycleExpiration {
        date: value.date.as_ref().map(render_timestamp).transpose()?,
        days: value.days,
        expired_object_all_versions: value.expired_object_all_versions,
        expired_object_delete_marker: value.expired_object_delete_marker,
    })
}

fn from_dto_filter(value: &crate::dto::LifecycleRuleFilter) -> PersistedLifecycleFilter {
    PersistedLifecycleFilter {
        and: value.and.as_ref().map(|and| PersistedLifecycleAnd {
            object_size_greater_than: and.object_size_greater_than,
            object_size_less_than: and.object_size_less_than,
            prefix: and.prefix.clone(),
            tags: (!and.tags.is_empty()).then(|| and.tags.iter().map(from_dto_tag).collect()),
        }),
        object_size_greater_than: value.object_size_greater_than,
        object_size_less_than: value.object_size_less_than,
        prefix: value.prefix.clone(),
        tag: value.tag.as_ref().map(from_dto_tag),
    }
}

fn from_dto_tag(value: &crate::dto::Tag) -> PersistedLifecycleTag {
    PersistedLifecycleTag {
        key: Some(value.key.clone()),
        value: Some(value.value.clone()),
    }
}

fn from_dto_transition(value: &crate::dto::Transition) -> Result<PersistedTransition, PersistenceBridgeError> {
    Ok(PersistedTransition {
        date: value.date.as_ref().map(render_timestamp).transpose()?,
        days: value.days,
        storage_class: value
            .storage_class
            .as_ref()
            .map(|storage_class| storage_class.as_str().to_owned()),
    })
}

fn parse_timestamp(value: &str) -> Result<Timestamp, PersistenceBridgeError> {
    Timestamp::parse(value, TimestampFormat::Iso8601)
        .map_err(|_| PersistenceBridgeError::Codec(PersistenceCodecError::InvalidLifecycleTimestamp))
}

fn render_timestamp(value: &Timestamp) -> Result<String, PersistenceBridgeError> {
    value
        .render(TimestampFormat::Iso8601)
        .map_err(|_| PersistenceBridgeError::Codec(PersistenceCodecError::InvalidLifecycleTimestamp))
}

#[cfg(test)]
mod tests {
    use super::{parse_lifecycle_dto, serialize_lifecycle_dto};
    use crate::dto;
    use crate::persistence::{PersistenceBridgeError, PersistenceCodecError};

    const HISTORICAL: &[u8] = b"<LifecycleConfiguration><Rule><AbortIncompleteMultipartUpload><DaysAfterInitiation>7</DaysAfterInitiation></AbortIncompleteMultipartUpload><Expiration><Date>2030-01-01T00:00:00.000Z</Date><ExpiredObjectDeleteMarker>false</ExpiredObjectDeleteMarker></Expiration><Filter><And><ObjectSizeGreaterThan>1</ObjectSizeGreaterThan><ObjectSizeLessThan>99</ObjectSizeLessThan><Prefix></Prefix><Tag><Key>team</Key><Value>storage</Value></Tag></And></Filter><ID>archive</ID><NoncurrentVersionExpiration><NewerNoncurrentVersions>2</NewerNoncurrentVersions><NoncurrentDays>30</NoncurrentDays></NoncurrentVersionExpiration><NoncurrentVersionTransition><NewerNoncurrentVersions>3</NewerNoncurrentVersions><NoncurrentDays>60</NoncurrentDays><StorageClass>FutureNoncurrent</StorageClass></NoncurrentVersionTransition><Prefix></Prefix><Status>FutureStatus</Status><Transition><Date>2031-01-01T00:00:00.000Z</Date><Days>90</Days><StorageClass>FutureCurrent</StorageClass></Transition></Rule></LifecycleConfiguration>";

    #[test]
    fn lifecycle_dto_bridge_preserves_nested_fields_empty_prefixes_unknown_enums_and_old_order() {
        let parsed = parse_lifecycle_dto(HISTORICAL).expect("the historical document is representable");
        assert_eq!(serialize_lifecycle_dto(&parsed).expect("the DTO remains representable"), HISTORICAL);
    }

    #[test]
    fn lifecycle_dto_bridge_rejects_a_wrong_family() {
        assert_eq!(
            parse_lifecycle_dto(b"<NotificationConfiguration></NotificationConfiguration>")
                .expect_err("a different family must fail"),
            PersistenceBridgeError::Codec(PersistenceCodecError::WrongRoot)
        );
    }

    #[test]
    fn lifecycle_dto_bridge_rejects_a_missing_rule() {
        assert_eq!(
            parse_lifecycle_dto(b"<LifecycleConfiguration></LifecycleConfiguration>").expect_err("at least one rule is required"),
            PersistenceBridgeError::Codec(PersistenceCodecError::MissingLifecycleRule)
        );
    }

    /// The MinIO members are DTO members since rd-cfg-0002..0004: each crosses the bridge and back
    /// to the same persisted bytes.
    #[test]
    fn lifecycle_dto_bridge_keeps_the_minio_members_byte_for_byte() {
        let bytes: &[u8] = b"<LifecycleConfiguration><ExpiryUpdatedAt>2030-01-01T00:00:00.000Z</ExpiryUpdatedAt><Rule><DelMarkerExpiration><Days>7</Days></DelMarkerExpiration><Expiration><ExpiredObjectAllVersions>true</ExpiredObjectAllVersions></Expiration><Status>Enabled</Status></Rule></LifecycleConfiguration>";
        let parsed = parse_lifecycle_dto(bytes).expect("every MinIO member has a DTO member");
        let rule = &parsed.rules[0];
        assert_eq!(rule.del_marker_expiration.as_ref().and_then(|action| action.days), Some(7));
        assert_eq!(rule.expiration.as_ref().and_then(|e| e.expired_object_all_versions), Some(true));
        assert!(parsed.expiry_updated_at.is_some());
        let rewritten = serialize_lifecycle_dto(&parsed).expect("the bridge writes what it read");
        assert_eq!(
            crate::persistence::parse_lifecycle(&rewritten),
            crate::persistence::parse_lifecycle(bytes)
        );
    }

    /// MinIO writes `ExpiryUpdatedAt` with six fractional digits; the persisted codec already
    /// normalizes it, and the bridge carries the normalized instant through unchanged.
    #[test]
    fn lifecycle_dto_bridge_keeps_a_six_digit_server_timestamp_as_the_codec_reads_it() {
        let bytes: &[u8] = b"<LifecycleConfiguration><ExpiryUpdatedAt>2026-08-30T12:34:56.123456Z</ExpiryUpdatedAt><Rule><Status>Enabled</Status></Rule></LifecycleConfiguration>";
        let parsed = parse_lifecycle_dto(bytes).expect("the codec reads the MinIO timestamp");
        let rewritten = serialize_lifecycle_dto(&parsed).expect("the bridge writes what it read");
        assert_eq!(
            crate::persistence::parse_lifecycle(&rewritten),
            crate::persistence::parse_lifecycle(bytes)
        );
    }

    #[test]
    fn lifecycle_dto_bridge_rejects_a_tag_without_a_key() {
        assert_eq!(
            parse_lifecycle_dto(b"<LifecycleConfiguration><Rule><Filter><Tag><Value>storage</Value></Tag></Filter><Status>Enabled</Status></Rule></LifecycleConfiguration>")
                .expect_err("the generated tag requires a key"),
            PersistenceBridgeError::UnsupportedPersistedMember("LifecycleRule.Filter.Tag.Key")
        );
    }

    #[test]
    fn lifecycle_dto_bridge_rejects_an_and_tag_without_a_value() {
        assert_eq!(
            parse_lifecycle_dto(b"<LifecycleConfiguration><Rule><Filter><And><Tag><Key>team</Key></Tag></And></Filter><Status>Enabled</Status></Rule></LifecycleConfiguration>")
                .expect_err("the generated tag requires a value"),
            PersistenceBridgeError::UnsupportedPersistedMember("LifecycleRule.Filter.And.Tag.Value")
        );
    }

    #[test]
    fn lifecycle_dto_bridge_rejects_an_invalid_integer() {
        assert_eq!(
            parse_lifecycle_dto(b"<LifecycleConfiguration><Rule><Expiration><Days>soon</Days></Expiration><Status>Enabled</Status></Rule></LifecycleConfiguration>")
                .expect_err("an invalid integer must fail"),
            PersistenceBridgeError::Codec(PersistenceCodecError::InvalidLifecycleInteger)
        );
    }

    #[test]
    fn lifecycle_dto_bridge_rejects_serializing_an_empty_rule_list() {
        let dto = dto::BucketLifecycleConfiguration {
            rules: Vec::new(),
            ..Default::default()
        };
        assert_eq!(
            serialize_lifecycle_dto(&dto).expect_err("historical persistence requires a rule"),
            PersistenceBridgeError::Codec(PersistenceCodecError::MissingLifecycleRule)
        );
    }
}
