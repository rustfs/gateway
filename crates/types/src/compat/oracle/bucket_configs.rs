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

//! Old-codec adapters for the eight persisted families with no nested adapter of their own.
//!
//! Responsible for: invoking one s3s revision's Versioning, Object Lock, Bucket Encryption, CORS,
//! Public Access Block, Tagging, Bucket Logging and Website codecs and projecting each result into
//! owned persistence structures. NOT responsible for: choosing the revision, production XML
//! behavior, or golden assertions. Upstream: the s3s revision bound by the enclosing oracle
//! instance. Downstream: the dispatching facade in `compat.rs`.

use super::s3s::dto::{
    BucketLoggingStatus, BucketLogsPermission, BucketVersioningStatus, CORSConfiguration, CORSRule, Condition, DefaultRetention,
    ErrorDocument, ExcludedPrefix, Grantee, IndexDocument, LoggingEnabled, MFADelete, ObjectLockConfiguration, ObjectLockEnabled,
    ObjectLockRetentionMode, ObjectLockRule, PartitionDateSource, PartitionedPrefix, Protocol, PublicAccessBlockConfiguration,
    Redirect, RedirectAllRequestsTo, RoutingRule, ServerSideEncryption, ServerSideEncryptionByDefault,
    ServerSideEncryptionConfiguration, SimplePrefix, Tag, Tagging, TargetGrant, TargetObjectKeyFormat, Type,
    VersioningConfiguration, WebsiteConfiguration,
};
use super::s3s::xml::{Deserialize, Deserializer, Serialize, Serializer};
use crate::compat::{
    CompatCodecError, S3sBucketEncryptionObservation, S3sBucketLoggingObservation, S3sCorsObservation, S3sObjectLockObservation,
    S3sPublicAccessBlockObservation, S3sTaggingObservation, S3sVersioningObservation, S3sWebsiteObservation,
};
use crate::cors_tagging::{PersistedCorsConfiguration, PersistedCorsRule, PersistedTag, PersistedTagging};
use crate::persistence::{
    PersistedBlockedEncryptionTypes, PersistedBucketEncryptionConfiguration, PersistedBucketEncryptionRule,
    PersistedBucketLoggingStatus, PersistedDefaultRetention, PersistedEncryptionByDefault, PersistedErrorDocument,
    PersistedGrantee, PersistedIndexDocument, PersistedLoggingEnabled, PersistedLoggingGrant, PersistedObjectLockConfiguration,
    PersistedObjectLockRule, PersistedPublicAccessBlockConfiguration, PersistedRedirect, PersistedRedirectAllRequestsTo,
    PersistedRoutingRule, PersistedRoutingRuleCondition, PersistedTargetObjectKeyFormat, PersistedVersioningConfiguration,
    PersistedWebsiteConfiguration,
};

/// Parses Versioning bytes with the pinned s3s persistence decoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when s3s rejects the document or trailing input.
pub(crate) fn parse_s3s_versioning(input: &[u8]) -> Result<S3sVersioningObservation, CompatCodecError> {
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
pub(crate) fn serialize_s3s_versioning(value: &PersistedVersioningConfiguration) -> Result<Vec<u8>, CompatCodecError> {
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
pub(crate) fn parse_s3s_object_lock(input: &[u8]) -> Result<S3sObjectLockObservation, CompatCodecError> {
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
pub(crate) fn serialize_s3s_object_lock(value: &PersistedObjectLockConfiguration) -> Result<Vec<u8>, CompatCodecError> {
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
pub(crate) fn parse_s3s_bucket_encryption(input: &[u8]) -> Result<S3sBucketEncryptionObservation, CompatCodecError> {
    let mut deserializer = Deserializer::new(input);
    let value = ServerSideEncryptionConfiguration::deserialize(&mut deserializer).map_err(CompatCodecError::old_codec)?;
    deserializer.expect_eof().map_err(CompatCodecError::old_codec)?;
    // Each revision splits its own Rule with an exhaustive destructure, so a revision that grows
    // another member stops compiling here instead of dropping it.
    let split = value.rules.into_iter().map(super::split_encryption_rule).collect::<Vec<_>>();
    let behavior = split
        .iter()
        .map(|(default, blocked, bucket_key_enabled)| {
            (
                default.as_ref().map(|value| value.sse_algorithm.as_str().to_owned()),
                default.as_ref().and_then(|value| value.kms_master_key_id.clone()),
                *bucket_key_enabled,
                blocked.clone(),
            )
        })
        .collect();
    let rules = split
        .into_iter()
        .map(|(default, blocked, bucket_key_enabled)| PersistedBucketEncryptionRule {
            apply_server_side_encryption_by_default: default.map(|default| PersistedEncryptionByDefault {
                sse_algorithm: default.sse_algorithm.as_str().to_owned(),
                kms_master_key_id: default.kms_master_key_id,
            }),
            bucket_key_enabled,
            blocked_encryption_types: blocked.map(|encryption_types| PersistedBlockedEncryptionTypes { encryption_types }),
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
pub(crate) fn serialize_s3s_bucket_encryption(
    value: &PersistedBucketEncryptionConfiguration,
) -> Result<Vec<u8>, CompatCodecError> {
    let old_value = ServerSideEncryptionConfiguration {
        rules: value
            .rules
            .iter()
            .map(|rule| {
                super::encryption_rule(
                    rule.apply_server_side_encryption_by_default
                        .as_ref()
                        .map(|default| ServerSideEncryptionByDefault {
                            kms_master_key_id: default.kms_master_key_id.clone(),
                            sse_algorithm: ServerSideEncryption::from(default.sse_algorithm.clone()),
                        }),
                    rule.blocked_encryption_types
                        .as_ref()
                        .map(|blocked| blocked.encryption_types.clone()),
                    rule.bucket_key_enabled,
                )
            })
            .collect::<Result<_, _>>()?,
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
pub(crate) fn parse_s3s_cors(input: &[u8]) -> Result<S3sCorsObservation, CompatCodecError> {
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
pub(crate) fn serialize_s3s_cors(value: &PersistedCorsConfiguration) -> Result<Vec<u8>, CompatCodecError> {
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
pub(crate) fn parse_s3s_public_access_block(input: &[u8]) -> Result<S3sPublicAccessBlockObservation, CompatCodecError> {
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
pub(crate) fn serialize_s3s_public_access_block(
    value: &PersistedPublicAccessBlockConfiguration,
) -> Result<Vec<u8>, CompatCodecError> {
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
pub(crate) fn parse_s3s_tagging(input: &[u8]) -> Result<S3sTaggingObservation, CompatCodecError> {
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
pub(crate) fn serialize_s3s_tagging(value: &PersistedTagging) -> Result<Vec<u8>, CompatCodecError> {
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

/// Parses Bucket Logging bytes with the pinned s3s persistence decoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when s3s rejects the document or trailing input.
pub(crate) fn parse_s3s_bucket_logging(input: &[u8]) -> Result<S3sBucketLoggingObservation, CompatCodecError> {
    let mut deserializer = Deserializer::new(input);
    let value = BucketLoggingStatus::deserialize(&mut deserializer).map_err(CompatCodecError::old_codec)?;
    deserializer.expect_eof().map_err(CompatCodecError::old_codec)?;
    let logging_enabled = value.logging_enabled.map(|logging| PersistedLoggingEnabled {
        target_bucket: logging.target_bucket,
        target_grants: logging.target_grants.map(|grants| {
            grants
                .into_iter()
                .map(|grant| PersistedLoggingGrant {
                    grantee: grant.grantee.map(|grantee| PersistedGrantee {
                        display_name: grantee.display_name,
                        email_address: grantee.email_address,
                        id: grantee.id,
                        grantee_type: grantee.type_.as_str().to_owned(),
                        uri: grantee.uri,
                    }),
                    permission: grant.permission.map(|value| value.as_str().to_owned()),
                })
                .collect()
        }),
        target_object_key_format: logging.target_object_key_format.map(|format| PersistedTargetObjectKeyFormat {
            partition_date_source: format
                .partitioned_prefix
                .map(|partitioned| partitioned.partition_date_source.map(|value| value.as_str().to_owned())),
            simple_prefix: format.simple_prefix.is_some(),
        }),
        target_prefix: logging.target_prefix,
    });
    Ok(S3sBucketLoggingObservation {
        structure: PersistedBucketLoggingStatus {
            logging_enabled: logging_enabled.clone(),
        },
        behavior: logging_enabled,
    })
}

/// Parses Website bytes with the pinned s3s persistence decoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when s3s rejects the document or trailing input.
pub(crate) fn parse_s3s_website(input: &[u8]) -> Result<S3sWebsiteObservation, CompatCodecError> {
    let mut deserializer = Deserializer::new(input);
    let value = WebsiteConfiguration::deserialize(&mut deserializer).map_err(CompatCodecError::old_codec)?;
    deserializer.expect_eof().map_err(CompatCodecError::old_codec)?;
    let structure = PersistedWebsiteConfiguration {
        error_document: value
            .error_document
            .map(|document| PersistedErrorDocument { key: document.key }),
        index_document: value
            .index_document
            .map(|document| PersistedIndexDocument { suffix: document.suffix }),
        redirect_all_requests_to: value.redirect_all_requests_to.map(|redirect| PersistedRedirectAllRequestsTo {
            host_name: redirect.host_name,
            protocol: redirect.protocol.map(|value| value.as_str().to_owned()),
        }),
        routing_rules: value.routing_rules.map(|rules| {
            rules
                .into_iter()
                .map(|rule| PersistedRoutingRule {
                    condition: rule.condition.map(|condition| PersistedRoutingRuleCondition {
                        http_error_code_returned_equals: condition.http_error_code_returned_equals,
                        key_prefix_equals: condition.key_prefix_equals,
                    }),
                    redirect: PersistedRedirect {
                        host_name: rule.redirect.host_name,
                        http_redirect_code: rule.redirect.http_redirect_code,
                        protocol: rule.redirect.protocol.map(|value| value.as_str().to_owned()),
                        replace_key_prefix_with: rule.redirect.replace_key_prefix_with,
                        replace_key_with: rule.redirect.replace_key_with,
                    },
                })
                .collect()
        }),
    };
    Ok(S3sWebsiteObservation {
        structure: structure.clone(),
        behavior: structure,
    })
}

/// Serializes a Bucket Logging value with the pinned s3s persistence encoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when s3s cannot render the value.
pub(crate) fn serialize_s3s_bucket_logging(value: &PersistedBucketLoggingStatus) -> Result<Vec<u8>, CompatCodecError> {
    let old_value = BucketLoggingStatus {
        logging_enabled: value.logging_enabled.as_ref().map(|logging| LoggingEnabled {
            target_bucket: logging.target_bucket.clone(),
            target_grants: logging.target_grants.as_ref().map(|grants| {
                grants
                    .iter()
                    .map(|grant| TargetGrant {
                        grantee: grant.grantee.as_ref().map(|grantee| Grantee {
                            display_name: grantee.display_name.clone(),
                            email_address: grantee.email_address.clone(),
                            id: grantee.id.clone(),
                            type_: Type::from(grantee.grantee_type.clone()),
                            uri: grantee.uri.clone(),
                        }),
                        permission: grant.permission.clone().map(BucketLogsPermission::from),
                    })
                    .collect()
            }),
            target_object_key_format: logging.target_object_key_format.as_ref().map(|format| TargetObjectKeyFormat {
                partitioned_prefix: format.partition_date_source.as_ref().map(|source| PartitionedPrefix {
                    partition_date_source: source.clone().map(PartitionDateSource::from),
                }),
                simple_prefix: format.simple_prefix.then(SimplePrefix::default),
            }),
            target_prefix: logging.target_prefix.clone(),
        }),
    };
    let mut output = Vec::with_capacity(512);
    let mut serializer = Serializer::new(&mut output);
    old_value.serialize(&mut serializer).map_err(CompatCodecError::old_codec)?;
    Ok(output)
}

/// Serializes a Website value with the pinned s3s persistence encoder.
///
/// # Errors
///
/// Returns [`CompatCodecError`] when s3s cannot render the value.
pub(crate) fn serialize_s3s_website(value: &PersistedWebsiteConfiguration) -> Result<Vec<u8>, CompatCodecError> {
    let old_value = WebsiteConfiguration {
        error_document: value.error_document.as_ref().map(|document| ErrorDocument {
            key: document.key.clone(),
        }),
        index_document: value.index_document.as_ref().map(|document| IndexDocument {
            suffix: document.suffix.clone(),
        }),
        redirect_all_requests_to: value.redirect_all_requests_to.as_ref().map(|redirect| RedirectAllRequestsTo {
            host_name: redirect.host_name.clone(),
            protocol: redirect.protocol.clone().map(Protocol::from),
        }),
        routing_rules: value.routing_rules.as_ref().map(|rules| {
            rules
                .iter()
                .map(|rule| RoutingRule {
                    condition: rule.condition.as_ref().map(|condition| Condition {
                        http_error_code_returned_equals: condition.http_error_code_returned_equals.clone(),
                        key_prefix_equals: condition.key_prefix_equals.clone(),
                    }),
                    redirect: Redirect {
                        host_name: rule.redirect.host_name.clone(),
                        http_redirect_code: rule.redirect.http_redirect_code.clone(),
                        protocol: rule.redirect.protocol.clone().map(Protocol::from),
                        replace_key_prefix_with: rule.redirect.replace_key_prefix_with.clone(),
                        replace_key_with: rule.redirect.replace_key_with.clone(),
                    },
                })
                .collect()
        }),
    };
    let mut output = Vec::with_capacity(512);
    let mut serializer = Serializer::new(&mut output);
    old_value.serialize(&mut serializer).map_err(CompatCodecError::old_codec)?;
    Ok(output)
}
