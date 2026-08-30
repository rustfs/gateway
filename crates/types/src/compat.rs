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

use crate::persistence::{
    PersistedDefaultRetention, PersistedObjectLockConfiguration, PersistedObjectLockRule, PersistedVersioningConfiguration,
};
use s3s::dto::{
    BucketVersioningStatus, DefaultRetention, ExcludedPrefix, MFADelete, ObjectLockConfiguration, ObjectLockEnabled,
    ObjectLockRetentionMode, ObjectLockRule, VersioningConfiguration,
};
use s3s::xml::{Deserialize, Deserializer, Serialize, Serializer};

mod lifecycle;

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
