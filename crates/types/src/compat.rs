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

//! Temporary adapters to the pinned s3s persistence oracle.
//!
//! Responsible for: invoking exact old persistence codecs and exposing family-scoped adapters.
//! NOT responsible for: production XML behavior, golden assertions, or exposing s3s DTOs.
//! Upstream: pinned s3s revision `9c4690d8`. Downstream: `rustfs-gateway-goldens`; this module is
//! deleted by P9-09.

use core::fmt;

use crate::cors_tagging::{
    CorsBehaviorProjection, PersistedCorsConfiguration, PersistedCorsRule, PersistedTag, PersistedTagging,
};
use crate::persistence::{
    PersistedBucketEncryptionConfiguration, PersistedBucketEncryptionRule, PersistedDefaultRetention,
    PersistedEncryptionByDefault, PersistedObjectLockConfiguration, PersistedObjectLockRule,
    PersistedPublicAccessBlockConfiguration, PersistedVersioningConfiguration,
};
use s3s::dto::{
    BucketVersioningStatus, CORSConfiguration, CORSRule, DefaultRetention, ExcludedPrefix, MFADelete, ObjectLockConfiguration,
    ObjectLockEnabled, ObjectLockRetentionMode, ObjectLockRule, PublicAccessBlockConfiguration, ServerSideEncryption,
    ServerSideEncryptionByDefault, ServerSideEncryptionConfiguration, ServerSideEncryptionRule, Tag, Tagging,
    VersioningConfiguration,
};
use s3s::xml::{Deserialize, Deserializer, Serialize, Serializer};

mod accelerate_payment;
mod lifecycle;

pub use accelerate_payment::{
    S3sAccelerateObservation, S3sRequestPaymentObservation, parse_s3s_accelerate, parse_s3s_request_payment,
    serialize_s3s_accelerate, serialize_s3s_request_payment,
};
pub use lifecycle::{S3sLifecycleObservation, parse_s3s_lifecycle, serialize_s3s_lifecycle};

/// One old-codec observation before the golden harness normalizes either side.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3sVersioningObservation {
    /// Complete parsed persistence structure.
    pub structure: PersistedVersioningConfiguration,
    /// Whether the pinned old implementation interprets the status as enabled.
    pub versioning_enabled: bool,
    /// The exact old versioning status used by its behavior decision.
    pub versioning_status: Option<String>,
    /// The exact old MFA delete state used by its behavior decision.
    pub mfa_delete: Option<String>,
}

/// One old-codec Object Lock observation before either side is normalized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3sObjectLockObservation {
    /// Complete parsed persistence structure.
    pub structure: PersistedObjectLockConfiguration,
    /// Whether the pinned old implementation interprets Object Lock as enabled.
    pub object_lock_enabled: bool,
}

/// One old-codec Bucket Encryption observation before either side is normalized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3sBucketEncryptionObservation {
    /// Complete parsed persistence structure.
    pub structure: PersistedBucketEncryptionConfiguration,
    /// Runtime-relevant algorithm, KMS key, and bucket-key decisions per stored rule.
    pub behavior: Vec<(Option<String>, Option<String>, Option<bool>)>,
}

/// One old-codec Public Access Block observation before either side is normalized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3sPublicAccessBlockObservation {
    /// Complete parsed persistence structure.
    pub structure: PersistedPublicAccessBlockConfiguration,
    /// The four effective access decisions in stable field order.
    pub behavior: (bool, bool, bool, bool),
}

/// One old-codec CORS observation before either side is normalized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3sCorsObservation {
    /// Complete parsed persistence structure.
    pub structure: PersistedCorsConfiguration,
    /// Independently projected runtime CORS behavior.
    pub behavior: CorsBehaviorProjection,
}

/// One old-codec Tagging observation before either side is normalized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3sTaggingObservation {
    /// Complete parsed persistence structure.
    pub structure: PersistedTagging,
    /// Independently projected complete tag set.
    pub tags: Vec<(Option<String>, Option<String>)>,
}

/// Failure raised by the pinned old persistence codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompatCodecError {
    message: String,
}

impl CompatCodecError {
    fn old_codec(error: impl fmt::Display) -> Self {
        Self {
            message: format!("pinned s3s persistence codec failed: {error}"),
        }
    }
}

impl fmt::Display for CompatCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CompatCodecError {}

/// Parses Versioning bytes with the pinned s3s persistence decoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when s3s rejects the document or trailing input.
pub fn parse_s3s_versioning(input: &[u8]) -> Result<S3sVersioningObservation, CompatCodecError> {
    let mut deserializer = Deserializer::new(input);
    let value = VersioningConfiguration::deserialize(&mut deserializer).map_err(CompatCodecError::old_codec)?;
    deserializer.expect_eof().map_err(CompatCodecError::old_codec)?;
    let versioning_status = value.status.as_ref().map(|status| status.as_str().to_owned());
    let mfa_delete = value.mfa_delete.as_ref().map(|status| status.as_str().to_owned());
    Ok(S3sVersioningObservation {
        versioning_enabled: value
            .status
            .as_ref()
            .is_some_and(|status| status.as_str() == BucketVersioningStatus::ENABLED),
        versioning_status: versioning_status.clone(),
        mfa_delete: mfa_delete.clone(),
        structure: PersistedVersioningConfiguration {
            status: versioning_status,
            mfa_delete,
            exclude_folders: value.exclude_folders,
            excluded_prefixes: value
                .excluded_prefixes
                .map(|prefixes| prefixes.into_iter().map(|prefix| prefix.prefix).collect()),
        },
    })
}

/// Serializes a Versioning value with the pinned s3s persistence encoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when s3s cannot render the value.
pub fn serialize_s3s_versioning(value: &PersistedVersioningConfiguration) -> Result<Vec<u8>, CompatCodecError> {
    #[allow(clippy::needless_update)] // Keep a default tail for the generated old DTO.
    let old_value = VersioningConfiguration {
        exclude_folders: value.exclude_folders,
        excluded_prefixes: value
            .excluded_prefixes
            .clone()
            .map(|prefixes| prefixes.into_iter().map(|prefix| ExcludedPrefix { prefix }).collect()),
        status: value.status.clone().map(BucketVersioningStatus::from),
        mfa_delete: value.mfa_delete.clone().map(MFADelete::from),
        ..VersioningConfiguration::default()
    };
    let mut output = Vec::with_capacity(256);
    let mut serializer = Serializer::new(&mut output);
    old_value.serialize(&mut serializer).map_err(CompatCodecError::old_codec)?;
    Ok(output)
}

/// Parses Object Lock bytes with the pinned s3s persistence decoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when s3s rejects the document or trailing input.
pub fn parse_s3s_object_lock(input: &[u8]) -> Result<S3sObjectLockObservation, CompatCodecError> {
    let mut deserializer = Deserializer::new(input);
    let value = ObjectLockConfiguration::deserialize(&mut deserializer).map_err(CompatCodecError::old_codec)?;
    deserializer.expect_eof().map_err(CompatCodecError::old_codec)?;
    let object_lock_enabled = value.object_lock_enabled.as_ref().map(|enabled| enabled.as_str().to_owned());
    Ok(S3sObjectLockObservation {
        object_lock_enabled: object_lock_enabled.as_deref() == Some(ObjectLockEnabled::ENABLED),
        structure: PersistedObjectLockConfiguration {
            object_lock_enabled,
            rule: value.rule.map(|rule| PersistedObjectLockRule {
                default_retention: rule.default_retention.map(|retention| PersistedDefaultRetention {
                    mode: retention.mode.map(|mode| mode.as_str().to_owned()),
                    days: retention.days,
                    years: retention.years,
                }),
            }),
        },
    })
}

/// Serializes an Object Lock value with the pinned s3s persistence encoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when s3s cannot render the value.
pub fn serialize_s3s_object_lock(value: &PersistedObjectLockConfiguration) -> Result<Vec<u8>, CompatCodecError> {
    #[allow(clippy::needless_update)] // Keep a default tail for the generated old DTO.
    let old_value = ObjectLockConfiguration {
        object_lock_enabled: value.object_lock_enabled.clone().map(ObjectLockEnabled::from),
        rule: value.rule.clone().map(|rule| ObjectLockRule {
            default_retention: rule.default_retention.map(|retention| DefaultRetention {
                mode: retention.mode.map(ObjectLockRetentionMode::from),
                days: retention.days,
                years: retention.years,
                ..DefaultRetention::default()
            }),
            ..ObjectLockRule::default()
        }),
        ..ObjectLockConfiguration::default()
    };
    let mut output = Vec::with_capacity(256);
    let mut serializer = Serializer::new(&mut output);
    old_value.serialize(&mut serializer).map_err(CompatCodecError::old_codec)?;
    Ok(output)
}

/// Parses Bucket Encryption bytes with the pinned s3s persistence decoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when s3s rejects the document or trailing input.
pub fn parse_s3s_bucket_encryption(input: &[u8]) -> Result<S3sBucketEncryptionObservation, CompatCodecError> {
    let mut deserializer = Deserializer::new(input);
    let value = ServerSideEncryptionConfiguration::deserialize(&mut deserializer).map_err(CompatCodecError::old_codec)?;
    deserializer.expect_eof().map_err(CompatCodecError::old_codec)?;
    let behavior = value
        .rules
        .iter()
        .map(|rule| {
            let default = rule.apply_server_side_encryption_by_default.as_ref();
            (
                default.map(|value| value.sse_algorithm.as_str().to_owned()),
                default.and_then(|value| value.kms_master_key_id.clone()),
                rule.bucket_key_enabled,
            )
        })
        .collect();
    let rules = value
        .rules
        .into_iter()
        .map(|rule| PersistedBucketEncryptionRule {
            apply_server_side_encryption_by_default: rule.apply_server_side_encryption_by_default.map(|default| {
                PersistedEncryptionByDefault {
                    sse_algorithm: default.sse_algorithm.as_str().to_owned(),
                    kms_master_key_id: default.kms_master_key_id,
                }
            }),
            bucket_key_enabled: rule.bucket_key_enabled,
        })
        .collect::<Vec<_>>();
    let structure = PersistedBucketEncryptionConfiguration { rules };
    Ok(S3sBucketEncryptionObservation { structure, behavior })
}

/// Serializes a Bucket Encryption value with the pinned s3s persistence encoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when s3s cannot render the value.
pub fn serialize_s3s_bucket_encryption(value: &PersistedBucketEncryptionConfiguration) -> Result<Vec<u8>, CompatCodecError> {
    let old_value = ServerSideEncryptionConfiguration {
        rules: value
            .rules
            .iter()
            .map(|rule| ServerSideEncryptionRule {
                apply_server_side_encryption_by_default: rule.apply_server_side_encryption_by_default.as_ref().map(|default| {
                    ServerSideEncryptionByDefault {
                        kms_master_key_id: default.kms_master_key_id.clone(),
                        sse_algorithm: ServerSideEncryption::from(default.sse_algorithm.clone()),
                    }
                }),
                bucket_key_enabled: rule.bucket_key_enabled,
            })
            .collect(),
    };
    let mut output = Vec::with_capacity(256);
    let mut serializer = Serializer::new(&mut output);
    old_value.serialize(&mut serializer).map_err(CompatCodecError::old_codec)?;
    Ok(output)
}

/// Parses CORS bytes with the pinned s3s persistence decoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when s3s rejects the document or trailing input.
pub fn parse_s3s_cors(input: &[u8]) -> Result<S3sCorsObservation, CompatCodecError> {
    let mut deserializer = Deserializer::new(input);
    let value = CORSConfiguration::deserialize(&mut deserializer).map_err(CompatCodecError::old_codec)?;
    deserializer.expect_eof().map_err(CompatCodecError::old_codec)?;
    let behavior = value
        .cors_rules
        .iter()
        .map(|rule| {
            (
                rule.allowed_origins.clone(),
                rule.allowed_methods.clone(),
                rule.allowed_headers.clone(),
                rule.expose_headers.clone(),
                rule.max_age_seconds,
            )
        })
        .collect();
    let structure = PersistedCorsConfiguration {
        cors_rules: value
            .cors_rules
            .into_iter()
            .map(|rule| PersistedCorsRule {
                allowed_headers: rule.allowed_headers,
                allowed_methods: rule.allowed_methods,
                allowed_origins: rule.allowed_origins,
                expose_headers: rule.expose_headers,
                id: rule.id,
                max_age_seconds: rule.max_age_seconds,
            })
            .collect(),
    };
    Ok(S3sCorsObservation { structure, behavior })
}

/// Serializes CORS with the pinned s3s persistence encoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when s3s cannot render the value.
pub fn serialize_s3s_cors(value: &PersistedCorsConfiguration) -> Result<Vec<u8>, CompatCodecError> {
    #[allow(clippy::needless_update)] // Keep a default tail for the generated old DTO.
    let old_value = CORSConfiguration {
        cors_rules: value
            .cors_rules
            .clone()
            .into_iter()
            .map(|rule| CORSRule {
                allowed_headers: rule.allowed_headers,
                allowed_methods: rule.allowed_methods,
                allowed_origins: rule.allowed_origins,
                expose_headers: rule.expose_headers,
                id: rule.id,
                max_age_seconds: rule.max_age_seconds,
                ..CORSRule::default()
            })
            .collect(),
        ..CORSConfiguration::default()
    };
    let mut output = Vec::with_capacity(512);
    let mut serializer = Serializer::new(&mut output);
    old_value.serialize(&mut serializer).map_err(CompatCodecError::old_codec)?;
    Ok(output)
}

/// Parses Public Access Block bytes with the pinned s3s persistence decoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when s3s rejects the document or trailing input.
pub fn parse_s3s_public_access_block(input: &[u8]) -> Result<S3sPublicAccessBlockObservation, CompatCodecError> {
    let mut deserializer = Deserializer::new(input);
    let value = PublicAccessBlockConfiguration::deserialize(&mut deserializer).map_err(CompatCodecError::old_codec)?;
    deserializer.expect_eof().map_err(CompatCodecError::old_codec)?;
    let behavior = (
        value.block_public_acls.unwrap_or(false),
        value.ignore_public_acls.unwrap_or(false),
        value.block_public_policy.unwrap_or(false),
        value.restrict_public_buckets.unwrap_or(false),
    );
    let structure = PersistedPublicAccessBlockConfiguration {
        block_public_acls: value.block_public_acls,
        ignore_public_acls: value.ignore_public_acls,
        block_public_policy: value.block_public_policy,
        restrict_public_buckets: value.restrict_public_buckets,
    };
    Ok(S3sPublicAccessBlockObservation { structure, behavior })
}

/// Serializes a Public Access Block value with the pinned s3s persistence encoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when s3s cannot render the value.
pub fn serialize_s3s_public_access_block(value: &PersistedPublicAccessBlockConfiguration) -> Result<Vec<u8>, CompatCodecError> {
    let old_value = PublicAccessBlockConfiguration {
        block_public_acls: value.block_public_acls,
        ignore_public_acls: value.ignore_public_acls,
        block_public_policy: value.block_public_policy,
        restrict_public_buckets: value.restrict_public_buckets,
    };
    let mut output = Vec::with_capacity(256);
    let mut serializer = Serializer::new(&mut output);
    old_value.serialize(&mut serializer).map_err(CompatCodecError::old_codec)?;
    Ok(output)
}

/// Parses Tagging bytes with the pinned s3s persistence decoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when s3s rejects the document or trailing input.
pub fn parse_s3s_tagging(input: &[u8]) -> Result<S3sTaggingObservation, CompatCodecError> {
    let mut deserializer = Deserializer::new(input);
    let value = Tagging::deserialize(&mut deserializer).map_err(CompatCodecError::old_codec)?;
    deserializer.expect_eof().map_err(CompatCodecError::old_codec)?;
    let tags = value.tag_set.iter().map(|tag| (tag.key.clone(), tag.value.clone())).collect();
    let structure = PersistedTagging {
        tag_set: value
            .tag_set
            .into_iter()
            .map(|tag| PersistedTag {
                key: tag.key,
                value: tag.value,
            })
            .collect(),
    };
    Ok(S3sTaggingObservation { structure, tags })
}

/// Serializes Tagging with the pinned s3s persistence encoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when s3s cannot render the value.
pub fn serialize_s3s_tagging(value: &PersistedTagging) -> Result<Vec<u8>, CompatCodecError> {
    #[allow(clippy::needless_update)] // Keep a default tail for the generated old DTO.
    let old_value = Tagging {
        tag_set: value
            .tag_set
            .clone()
            .into_iter()
            .map(|tag| Tag {
                key: tag.key,
                value: tag.value,
                ..Tag::default()
            })
            .collect(),
        ..Tagging::default()
    };
    let mut output = Vec::with_capacity(512);
    let mut serializer = Serializer::new(&mut output);
    old_value.serialize(&mut serializer).map_err(CompatCodecError::old_codec)?;
    Ok(output)
}
