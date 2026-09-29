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

//! Generated DTO bridges for historical persistence XML.
//!
//! Responsible for: lossless conversion between generated HTTP DTOs and persisted bucket-configuration shapes.
//! NOT responsible for: parsing XML directly, HTTP policy, routing, or migration-oracle comparison.
//! Upstream: sibling persistence codecs. Downstream: RustFS metadata consumers using generated DTOs.

mod cors_object_lock;
mod lifecycle;
mod logging_website;
mod notification;
mod replication;

pub use cors_object_lock::{parse_cors_dto, parse_object_lock_dto, serialize_cors_dto, serialize_object_lock_dto};
pub use lifecycle::{parse_lifecycle_dto, serialize_lifecycle_dto};
pub use logging_website::{parse_bucket_logging_dto, parse_website_dto, serialize_bucket_logging_dto, serialize_website_dto};
pub use notification::{parse_notification_dto, serialize_notification_dto};
pub use replication::{parse_replication_dto, serialize_replication_dto};

use core::fmt;

use crate::cors_tagging::{CorsTaggingCodecError, PersistedTag, PersistedTagging, parse_tagging, serialize_tagging};

use super::{
    PersistedAccelerateConfiguration, PersistedBlockedEncryptionTypes, PersistedBucketEncryptionConfiguration,
    PersistedBucketEncryptionRule, PersistedEncryptionByDefault, PersistedPublicAccessBlockConfiguration,
    PersistedRequestPaymentConfiguration, PersistedVersioningConfiguration, PersistenceCodecError, parse_accelerate,
    parse_bucket_encryption, parse_public_access_block, parse_request_payment, parse_versioning, serialize_accelerate,
    serialize_bucket_encryption, serialize_public_access_block, serialize_request_payment, serialize_versioning,
};

/// A generated DTO cannot be represented by the historical persistence shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PersistenceBridgeError {
    /// The underlying persistence codec refused the value.
    Codec(PersistenceCodecError),
    /// A present generated DTO member has no lossless historical persistence representation.
    UnsupportedMember(&'static str),
    /// A present persisted member has no lossless generated DTO representation.
    UnsupportedPersistedMember(&'static str),
}

impl fmt::Display for PersistenceBridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => write!(formatter, "persistence codec refused the DTO: {error}"),
            Self::UnsupportedMember(member) => write!(formatter, "persistence format cannot represent DTO member {member}"),
            Self::UnsupportedPersistedMember(member) => {
                write!(formatter, "generated DTO cannot represent persisted member {member}")
            }
        }
    }
}

impl std::error::Error for PersistenceBridgeError {}

impl From<PersistenceCodecError> for PersistenceBridgeError {
    fn from(error: PersistenceCodecError) -> Self {
        Self::Codec(error)
    }
}

/// A persisted Tagging document cannot be represented by the generated DTO.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaggingBridgeError {
    /// The historical Tagging codec refused the bytes.
    Codec(CorsTaggingCodecError),
    /// A generated required member is absent in historically accepted persistence bytes.
    MissingRequiredMember(&'static str),
}

impl fmt::Display for TaggingBridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => write!(formatter, "Tagging persistence codec refused the DTO: {error}"),
            Self::MissingRequiredMember(member) => write!(formatter, "persisted Tagging document is missing DTO member {member}"),
        }
    }
}

impl std::error::Error for TaggingBridgeError {}

impl From<CorsTaggingCodecError> for TaggingBridgeError {
    fn from(error: CorsTaggingCodecError) -> Self {
        Self::Codec(error)
    }
}

/// Parses persisted Tagging bytes directly into the generated HTTP DTO.
///
/// # Errors
///
/// Returns [`TaggingBridgeError::Codec`] when the historical parser rejects the bytes, and
/// [`TaggingBridgeError::MissingRequiredMember`] when historically accepted optional tag fields
/// cannot satisfy the generated DTO's required members.
pub fn parse_tagging_dto(input: &[u8]) -> Result<crate::dto::Tagging, TaggingBridgeError> {
    let persisted = parse_tagging(input)?;
    let tag_set = persisted
        .tag_set
        .into_iter()
        .map(|tag| {
            Ok(crate::dto::Tag {
                key: tag.key.ok_or(TaggingBridgeError::MissingRequiredMember("Tag.Key"))?,
                value: tag.value.ok_or(TaggingBridgeError::MissingRequiredMember("Tag.Value"))?,
            })
        })
        .collect::<Result<Vec<_>, TaggingBridgeError>>()?;
    Ok(crate::dto::Tagging { tag_set })
}

/// Serializes the generated Tagging DTO with the historical persistence writer.
#[must_use]
pub fn serialize_tagging_dto(value: &crate::dto::Tagging) -> Vec<u8> {
    serialize_tagging(&PersistedTagging {
        tag_set: value
            .tag_set
            .iter()
            .map(|tag| PersistedTag {
                key: Some(tag.key.clone()),
                value: Some(tag.value.clone()),
            })
            .collect(),
    })
}

/// Parses persisted Versioning bytes directly into the generated HTTP DTO.
///
/// # Errors
///
/// Returns [`PersistenceBridgeError::Codec`] when the historical parser rejects the bytes, and
/// never [`PersistenceBridgeError::UnsupportedPersistedMember`]: the generated DTO carries MinIO's
/// `ExcludedPrefixes` and `ExcludeFolders` (rd-cfg-0006).
pub fn parse_versioning_dto(input: &[u8]) -> Result<crate::dto::VersioningConfiguration, PersistenceBridgeError> {
    let persisted = parse_versioning(input)?;
    Ok(crate::dto::VersioningConfiguration {
        mfa_delete: persisted.mfa_delete.map(crate::dto::MfaDelete::custom),
        status: persisted.status.map(crate::dto::Status::custom),
        excluded_prefixes: persisted
            .excluded_prefixes
            .unwrap_or_default()
            .into_iter()
            .map(|prefix| crate::dto::ExcludedPrefix { prefix })
            .collect(),
        exclude_folders: persisted.exclude_folders,
    })
}

/// Serializes the generated Versioning DTO with the historical persistence writer.
#[must_use]
pub fn serialize_versioning_dto(value: &crate::dto::VersioningConfiguration) -> Vec<u8> {
    serialize_versioning(&PersistedVersioningConfiguration {
        status: value.status.as_ref().map(|status| status.as_str().to_owned()),
        mfa_delete: value.mfa_delete.as_ref().map(|state| state.as_str().to_owned()),
        exclude_folders: value.exclude_folders,
        excluded_prefixes: (!value.excluded_prefixes.is_empty())
            .then(|| value.excluded_prefixes.iter().map(|entry| entry.prefix.clone()).collect()),
    })
}

/// Parses persisted Transfer Acceleration bytes directly into the generated HTTP DTO.
///
/// # Errors
///
/// Returns [`PersistenceCodecError`] under the same conditions as [`parse_accelerate`].
pub fn parse_accelerate_dto(input: &[u8]) -> Result<crate::dto::AccelerateConfiguration, PersistenceCodecError> {
    let persisted = parse_accelerate(input)?;
    Ok(crate::dto::AccelerateConfiguration {
        status: persisted.status.map(crate::dto::Status::custom),
    })
}

/// Serializes the generated Transfer Acceleration DTO with the historical persistence writer.
#[must_use]
pub fn serialize_accelerate_dto(value: &crate::dto::AccelerateConfiguration) -> Vec<u8> {
    serialize_accelerate(&PersistedAccelerateConfiguration {
        status: value.status.as_ref().map(|status| status.as_str().to_owned()),
    })
}

/// Parses persisted Request Payment bytes directly into the generated HTTP DTO.
///
/// # Errors
///
/// Returns [`PersistenceCodecError`] under the same conditions as [`parse_request_payment`].
pub fn parse_request_payment_dto(input: &[u8]) -> Result<crate::dto::RequestPaymentConfiguration, PersistenceCodecError> {
    let persisted = parse_request_payment(input)?;
    Ok(crate::dto::RequestPaymentConfiguration {
        payer: crate::dto::Payer::custom(persisted.payer),
    })
}

/// Serializes the generated Request Payment DTO with the historical persistence writer.
#[must_use]
pub fn serialize_request_payment_dto(value: &crate::dto::RequestPaymentConfiguration) -> Vec<u8> {
    serialize_request_payment(&PersistedRequestPaymentConfiguration {
        payer: value.payer.as_str().to_owned(),
    })
}

/// Parses persisted Bucket Encryption bytes directly into the generated HTTP DTO.
///
/// `BlockedEncryptionTypes` is carried entry for entry, so a bucket whose owner blocked SSE-C
/// stays blocked after migration (rustfs/gateway#740).
///
/// # Errors
///
/// Returns [`PersistenceCodecError`] under the same conditions as
/// [`parse_bucket_encryption`].
pub fn parse_bucket_encryption_dto(input: &[u8]) -> Result<crate::dto::ServerSideEncryptionConfiguration, PersistenceCodecError> {
    let persisted = parse_bucket_encryption(input)?;
    Ok(crate::dto::ServerSideEncryptionConfiguration {
        rules: persisted
            .rules
            .into_iter()
            .map(|rule| crate::dto::ServerSideEncryptionRule {
                apply_server_side_encryption_by_default: rule.apply_server_side_encryption_by_default.map(|default| {
                    crate::dto::ServerSideEncryptionByDefault {
                        sse_algorithm: crate::dto::SseAlgorithm::custom(default.sse_algorithm),
                        kms_master_key_id: default.kms_master_key_id,
                    }
                }),
                bucket_key_enabled: rule.bucket_key_enabled,
                blocked_encryption_types: rule
                    .blocked_encryption_types
                    .map(|blocked| crate::dto::BlockedEncryptionTypes {
                        encryption_type: blocked
                            .encryption_types
                            .into_iter()
                            .map(crate::dto::EncryptionType::custom)
                            .collect(),
                    }),
            })
            .collect(),
    })
}

/// Serializes the generated Bucket Encryption DTO with the historical persistence writer.
///
/// # Errors
///
/// None today; the `Result` is kept so a future DTO member with no persisted slot is refused
/// rather than dropped.
pub fn serialize_bucket_encryption_dto(
    value: &crate::dto::ServerSideEncryptionConfiguration,
) -> Result<Vec<u8>, PersistenceBridgeError> {
    let rules = value
        .rules
        .iter()
        .map(|rule| PersistedBucketEncryptionRule {
            apply_server_side_encryption_by_default: rule.apply_server_side_encryption_by_default.as_ref().map(|default| {
                PersistedEncryptionByDefault {
                    sse_algorithm: default.sse_algorithm.as_str().to_owned(),
                    kms_master_key_id: default.kms_master_key_id.clone(),
                }
            }),
            bucket_key_enabled: rule.bucket_key_enabled,
            blocked_encryption_types: rule
                .blocked_encryption_types
                .as_ref()
                .map(|blocked| PersistedBlockedEncryptionTypes {
                    encryption_types: blocked
                        .encryption_type
                        .iter()
                        .map(|entry| entry.as_str().to_owned())
                        .collect(),
                }),
        })
        .collect();
    Ok(serialize_bucket_encryption(&PersistedBucketEncryptionConfiguration { rules }))
}

/// Parses persisted Public Access Block bytes directly into the generated HTTP DTO.
///
/// This is the production persistence bridge: it keeps the old persistence parser as the one
/// byte-level authority while letting metadata consumers use the same typed shape as the PUT and
/// GET operation codecs.
///
/// # Errors
///
/// Returns [`PersistenceCodecError`] under the same malformed, wrong-root, duplicate-field, and
/// invalid-boolean conditions as [`parse_public_access_block`].
pub fn parse_public_access_block_dto(input: &[u8]) -> Result<crate::dto::PublicAccessBlockConfiguration, PersistenceCodecError> {
    let persisted = parse_public_access_block(input)?;
    Ok(crate::dto::PublicAccessBlockConfiguration {
        block_public_acls: persisted.block_public_acls,
        ignore_public_acls: persisted.ignore_public_acls,
        block_public_policy: persisted.block_public_policy,
        restrict_public_buckets: persisted.restrict_public_buckets,
    })
}

/// Serializes the generated Public Access Block DTO with the historical persistence writer.
///
/// Field presence is retained: an omitted switch remains absent rather than being materialized as
/// `false`. The resulting member order is the old-writer persistence contract, not the HTTP GET
/// response order.
#[must_use]
pub fn serialize_public_access_block_dto(value: &crate::dto::PublicAccessBlockConfiguration) -> Vec<u8> {
    serialize_public_access_block(&PersistedPublicAccessBlockConfiguration {
        block_public_acls: value.block_public_acls,
        ignore_public_acls: value.ignore_public_acls,
        block_public_policy: value.block_public_policy,
        restrict_public_buckets: value.restrict_public_buckets,
    })
}

#[cfg(test)]
mod tests {
    use crate::dto::{
        AccelerateConfiguration, BlockedEncryptionTypes, EncryptionType, Payer, PublicAccessBlockConfiguration,
        RequestPaymentConfiguration, ServerSideEncryptionByDefault, ServerSideEncryptionConfiguration, ServerSideEncryptionRule,
        SseAlgorithm, Tag, Tagging, VersioningConfiguration,
    };

    use super::{
        PersistenceBridgeError, PersistenceCodecError, TaggingBridgeError, parse_accelerate_dto, parse_bucket_encryption_dto,
        parse_public_access_block_dto, parse_request_payment_dto, parse_tagging_dto, parse_versioning_dto,
        serialize_accelerate_dto, serialize_bucket_encryption_dto, serialize_public_access_block_dto,
        serialize_request_payment_dto, serialize_tagging_dto, serialize_versioning_dto,
    };

    #[test]
    fn tagging_dto_bridge_preserves_required_members_and_the_old_writer_order() {
        let dto = Tagging {
            tag_set: vec![Tag {
                key: "project".to_owned(),
                value: "launch".to_owned(),
            }],
        };

        let bytes = serialize_tagging_dto(&dto);
        assert_eq!(
            bytes,
            b"<Tagging><TagSet><Tag><Key>project</Key><Value>launch</Value></Tag></TagSet></Tagging>"
        );
        let parsed = parse_tagging_dto(&bytes).expect("the bridge reads its own persistence bytes");
        assert_eq!(parsed.tag_set[0].key, "project");
        assert_eq!(parsed.tag_set[0].value, "launch");
    }

    #[test]
    fn tagging_dto_bridge_rejects_a_wrong_family() {
        assert_eq!(
            parse_tagging_dto(b"<VersioningConfiguration></VersioningConfiguration>").expect_err("a different family must fail"),
            TaggingBridgeError::Codec(crate::cors_tagging::CorsTaggingCodecError::WrongRoot)
        );
    }

    #[test]
    fn tagging_dto_bridge_rejects_a_missing_tag_set() {
        assert_eq!(
            parse_tagging_dto(b"<Tagging></Tagging>").expect_err("the required wrapper must be present"),
            TaggingBridgeError::Codec(crate::cors_tagging::CorsTaggingCodecError::MissingField("TagSet"))
        );
    }

    #[test]
    fn tagging_dto_bridge_rejects_a_missing_required_tag_member() {
        assert_eq!(
            parse_tagging_dto(b"<Tagging><TagSet><Tag><Value>value</Value></Tag></TagSet></Tagging>")
                .expect_err("a generated required key cannot be invented"),
            TaggingBridgeError::MissingRequiredMember("Tag.Key")
        );
    }

    #[test]
    fn versioning_dto_bridge_preserves_presence_and_the_old_writer_order() {
        let dto = VersioningConfiguration {
            mfa_delete: Some("FutureMfa".into()),
            status: Some("FutureStatus".into()),
            ..VersioningConfiguration::default()
        };

        let bytes = serialize_versioning_dto(&dto);
        assert_eq!(
            bytes,
            b"<VersioningConfiguration><MfaDelete>FutureMfa</MfaDelete><Status>FutureStatus</Status></VersioningConfiguration>"
        );
        let parsed = parse_versioning_dto(&bytes).expect("the bridge reads its own persistence bytes");
        assert_eq!(parsed.mfa_delete.as_ref().map(|value| value.as_str()), Some("FutureMfa"));
        assert_eq!(parsed.status.as_ref().map(|value| value.as_str()), Some("FutureStatus"));
    }

    #[test]
    fn versioning_dto_bridge_rejects_a_wrong_family() {
        assert_eq!(
            parse_versioning_dto(b"<Tagging></Tagging>").expect_err("a different family must fail"),
            PersistenceBridgeError::Codec(PersistenceCodecError::WrongRoot)
        );
    }

    #[test]
    fn versioning_dto_bridge_rejects_a_duplicate_status() {
        assert_eq!(
            parse_versioning_dto(
                b"<VersioningConfiguration><Status>Enabled</Status><Status>Suspended</Status></VersioningConfiguration>"
            )
            .expect_err("a repeated status must fail"),
            PersistenceBridgeError::Codec(PersistenceCodecError::DuplicateField)
        );
    }

    /// MinIO's `ExcludeFolders` and flattened `ExcludedPrefixes` are DTO members since rd-cfg-0006
    /// and cross both ways, every prefix kept in order.
    #[test]
    fn versioning_dto_bridge_keeps_the_minio_exclusions() {
        let bytes: &[u8] = b"<VersioningConfiguration><Status>Enabled</Status><ExcludedPrefixes><Prefix>tmp/</Prefix></ExcludedPrefixes><ExcludedPrefixes><Prefix>cache/</Prefix></ExcludedPrefixes><ExcludeFolders>true</ExcludeFolders></VersioningConfiguration>";
        let parsed = parse_versioning_dto(bytes).expect("both members have DTO members");
        let prefixes: Vec<_> = parsed.excluded_prefixes.iter().map(|entry| entry.prefix.as_deref()).collect();
        assert_eq!(prefixes, [Some("tmp/"), Some("cache/")]);
        assert_eq!(parsed.exclude_folders, Some(true));
        assert_eq!(
            crate::persistence::parse_versioning(&serialize_versioning_dto(&parsed)),
            crate::persistence::parse_versioning(bytes)
        );
    }

    #[test]
    fn accelerate_dto_bridge_preserves_presence_and_the_old_writer_order() {
        let dto = AccelerateConfiguration {
            status: Some("Future".into()),
        };

        let bytes = serialize_accelerate_dto(&dto);
        assert_eq!(bytes, b"<AccelerateConfiguration><Status>Future</Status></AccelerateConfiguration>");
        let parsed = parse_accelerate_dto(&bytes).expect("the bridge reads its own persistence bytes");
        assert_eq!(parsed.status.as_ref().map(|status| status.as_str()), Some("Future"));
    }

    #[test]
    fn accelerate_dto_bridge_rejects_a_wrong_family() {
        assert_eq!(
            parse_accelerate_dto(b"<Tagging></Tagging>").expect_err("a different family must fail"),
            PersistenceCodecError::WrongRoot
        );
    }

    #[test]
    fn accelerate_dto_bridge_rejects_a_duplicate_status() {
        assert_eq!(
            parse_accelerate_dto(
                b"<AccelerateConfiguration><Status>Enabled</Status><Status>Suspended</Status></AccelerateConfiguration>"
            )
            .expect_err("a repeated status must fail"),
            PersistenceCodecError::DuplicateField
        );
    }

    #[test]
    fn accelerate_dto_bridge_rejects_nested_status_content() {
        assert_eq!(
            parse_accelerate_dto(b"<AccelerateConfiguration><Status><Future>Enabled</Future></Status></AccelerateConfiguration>")
                .expect_err("a scalar cannot carry nested content"),
            PersistenceCodecError::UnexpectedScalarElement
        );
    }

    #[test]
    fn request_payment_dto_bridge_preserves_the_required_payer_and_old_writer_order() {
        let dto = RequestPaymentConfiguration {
            payer: Payer::custom("Future"),
        };

        let bytes = serialize_request_payment_dto(&dto);
        assert_eq!(bytes, b"<RequestPaymentConfiguration><Payer>Future</Payer></RequestPaymentConfiguration>");
        let parsed = parse_request_payment_dto(&bytes).expect("the bridge reads its own persistence bytes");
        assert_eq!(parsed.payer.as_str(), "Future");
    }

    #[test]
    fn request_payment_dto_bridge_rejects_a_wrong_family() {
        assert_eq!(
            parse_request_payment_dto(b"<Tagging></Tagging>").expect_err("a different family must fail"),
            PersistenceCodecError::WrongRoot
        );
    }

    #[test]
    fn request_payment_dto_bridge_rejects_a_missing_payer() {
        assert_eq!(
            parse_request_payment_dto(b"<RequestPaymentConfiguration></RequestPaymentConfiguration>")
                .expect_err("the required payer must be present"),
            PersistenceCodecError::MissingRequiredField
        );
    }

    #[test]
    fn request_payment_dto_bridge_rejects_a_duplicate_payer() {
        assert_eq!(
            parse_request_payment_dto(
                b"<RequestPaymentConfiguration><Payer>Requester</Payer><Payer>BucketOwner</Payer></RequestPaymentConfiguration>"
            )
            .expect_err("a repeated payer must fail"),
            PersistenceCodecError::DuplicateField
        );
    }

    #[test]
    fn public_access_block_dto_bridge_preserves_presence_and_old_writer_order() {
        let dto = PublicAccessBlockConfiguration {
            block_public_acls: Some(true),
            ignore_public_acls: Some(false),
            block_public_policy: Some(true),
            restrict_public_buckets: None,
        };

        let bytes = serialize_public_access_block_dto(&dto);
        assert_eq!(
            bytes,
            b"<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><IgnorePublicAcls>false</IgnorePublicAcls></PublicAccessBlockConfiguration>"
        );
        let parsed = parse_public_access_block_dto(&bytes).expect("the bridge reads its own persistence bytes");
        assert_eq!(parsed.block_public_acls, dto.block_public_acls);
        assert_eq!(parsed.ignore_public_acls, dto.ignore_public_acls);
        assert_eq!(parsed.block_public_policy, dto.block_public_policy);
        assert_eq!(parsed.restrict_public_buckets, dto.restrict_public_buckets);
    }

    #[test]
    fn public_access_block_dto_bridge_rejects_a_wrong_family() {
        assert_eq!(
            parse_public_access_block_dto(b"<Tagging></Tagging>").expect_err("a different family must fail"),
            PersistenceCodecError::WrongRoot
        );
    }

    #[test]
    fn public_access_block_dto_bridge_rejects_a_duplicate_switch() {
        assert_eq!(
            parse_public_access_block_dto(
                b"<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls><BlockPublicAcls>false</BlockPublicAcls></PublicAccessBlockConfiguration>"
            )
            .expect_err("a repeated switch must fail"),
            PersistenceCodecError::DuplicateField
        );
    }

    #[test]
    fn public_access_block_dto_bridge_accepts_exactly_the_four_boolean_spellings() {
        // The lexical forms `PersistenceCodecError::InvalidBoolean` documents: the pinned old
        // decoder takes `true`, `false`, `TRUE`, `FALSE` and nothing else (rustfs/gateway#465).
        let parse = |text: &str| {
            parse_public_access_block_dto(
                format!(
                    "<PublicAccessBlockConfiguration><BlockPublicAcls>{text}</BlockPublicAcls></PublicAccessBlockConfiguration>"
                )
                .as_bytes(),
            )
        };
        for (text, expected) in [("true", true), ("TRUE", true), ("false", false), ("FALSE", false)] {
            assert_eq!(parse(text).expect(text).block_public_acls, Some(expected), "{text}");
        }
        for text in ["True", "False", " true", "true ", "tRUE", "yes", ""] {
            assert_eq!(parse(text).expect_err(text), PersistenceCodecError::InvalidBoolean, "{text:?}");
        }
    }

    #[test]
    fn public_access_block_dto_bridge_rejects_a_noncanonical_boolean() {
        assert_eq!(
            parse_public_access_block_dto(
                b"<PublicAccessBlockConfiguration><RestrictPublicBuckets>1</RestrictPublicBuckets></PublicAccessBlockConfiguration>"
            )
            .expect_err("numeric boolean syntax must fail"),
            PersistenceCodecError::InvalidBoolean
        );
    }

    #[test]
    fn bucket_encryption_dto_bridge_preserves_the_old_writer_order() {
        let dto = ServerSideEncryptionConfiguration {
            rules: vec![ServerSideEncryptionRule {
                apply_server_side_encryption_by_default: Some(ServerSideEncryptionByDefault {
                    sse_algorithm: SseAlgorithm::AWS_KMS,
                    kms_master_key_id: Some("key-id".to_owned()),
                }),
                bucket_key_enabled: Some(true),
                blocked_encryption_types: None,
            }],
        };

        let bytes = serialize_bucket_encryption_dto(&dto).expect("the standard DTO is persistence-representable");
        assert_eq!(
            bytes,
            b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><KMSMasterKeyID>key-id</KMSMasterKeyID><SSEAlgorithm>aws:kms</SSEAlgorithm></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>true</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>"
        );
        let parsed = parse_bucket_encryption_dto(&bytes).expect("the bridge reads its own persistence bytes");
        assert_eq!(parsed.rules.len(), 1);
        let rule = &parsed.rules[0];
        assert_eq!(rule.bucket_key_enabled, Some(true));
        let default = rule
            .apply_server_side_encryption_by_default
            .as_ref()
            .expect("the default encryption action remains present");
        assert_eq!(default.sse_algorithm.as_str(), "aws:kms");
        assert_eq!(default.kms_master_key_id.as_deref(), Some("key-id"));
        assert!(rule.blocked_encryption_types.is_none());
    }

    #[test]
    fn bucket_encryption_dto_bridge_rejects_a_wrong_family() {
        assert_eq!(
            parse_bucket_encryption_dto(b"<Tagging></Tagging>").expect_err("a different family must fail"),
            PersistenceCodecError::WrongRoot
        );
    }

    /// rustfs/gateway#740: the wrapper RustFS rc.6 and `main` persist survives both directions, in
    /// the s3s member order, entry for entry. An empty wrapper stays a present wrapper, because
    /// "blocks nothing, explicitly" and "never configured" are different stored states.
    #[test]
    fn bucket_encryption_dto_bridge_carries_blocked_encryption_types_losslessly() {
        for (blocked, wire) in [
            (
                vec![EncryptionType::SSE_C],
                "<BlockedEncryptionTypes><EncryptionType>SSE-C</EncryptionType></BlockedEncryptionTypes>",
            ),
            (
                vec![EncryptionType::NONE, EncryptionType::SSE_C],
                "<BlockedEncryptionTypes><EncryptionType>NONE</EncryptionType><EncryptionType>SSE-C</EncryptionType></BlockedEncryptionTypes>",
            ),
            (Vec::new(), "<BlockedEncryptionTypes></BlockedEncryptionTypes>"),
        ] {
            let dto = ServerSideEncryptionConfiguration {
                rules: vec![ServerSideEncryptionRule {
                    apply_server_side_encryption_by_default: Some(ServerSideEncryptionByDefault {
                        sse_algorithm: SseAlgorithm::AES256,
                        kms_master_key_id: None,
                    }),
                    bucket_key_enabled: Some(false),
                    blocked_encryption_types: Some(BlockedEncryptionTypes {
                        encryption_type: blocked.clone(),
                    }),
                }],
            };
            let bytes = serialize_bucket_encryption_dto(&dto).expect("the wrapper has a persisted slot");
            let expected = format!(
                "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault>{wire}<BucketKeyEnabled>false</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>"
            );
            assert_eq!(String::from_utf8_lossy(&bytes), expected);
            let parsed = parse_bucket_encryption_dto(&bytes).expect("the bridge reads its own persistence bytes");
            let entries = parsed.rules[0]
                .blocked_encryption_types
                .as_ref()
                .expect("the wrapper stays present")
                .encryption_type
                .iter()
                .map(EncryptionType::as_str)
                .collect::<Vec<_>>();
            assert_eq!(entries, blocked.iter().map(EncryptionType::as_str).collect::<Vec<_>>(), "{wire}");
            assert_eq!(parsed.rules[0].bucket_key_enabled, Some(false));
            assert_eq!(
                serialize_bucket_encryption_dto(&parsed).expect("the parsed DTO writes back"),
                bytes,
                "{wire}"
            );
        }
    }

    #[test]
    fn n_the_rustfs_rc6_blocked_sse_c_witness_decodes_as_blocked_not_as_absent() {
        let parsed = parse_bucket_encryption_dto(
            b"<ServerSideEncryptionConfiguration><Rule><BlockedEncryptionTypes><EncryptionType>SSE-C</EncryptionType></BlockedEncryptionTypes></Rule></ServerSideEncryptionConfiguration>",
        )
        .expect("the persisted #740 witness is readable");
        let blocked = parsed.rules[0]
            .blocked_encryption_types
            .as_ref()
            .expect("skipping the wrapper would silently unblock SSE-C");
        assert_eq!(blocked.encryption_type.len(), 1);
        assert_eq!(blocked.encryption_type[0].as_str(), "SSE-C");
    }

    #[test]
    fn n_the_blocked_wrapper_refuses_foreign_children_duplicates_and_nested_values() {
        for (document, error) in [
            (
                "<Rule><BlockedEncryptionTypes><Future>x</Future></BlockedEncryptionTypes></Rule>",
                PersistenceCodecError::UnexpectedBucketEncryptionElement,
            ),
            (
                "<Rule><BlockedEncryptionTypes></BlockedEncryptionTypes><BlockedEncryptionTypes></BlockedEncryptionTypes></Rule>",
                PersistenceCodecError::DuplicateField,
            ),
            (
                "<Rule><BlockedEncryptionTypes><EncryptionType><X>SSE-C</X></EncryptionType></BlockedEncryptionTypes></Rule>",
                PersistenceCodecError::UnexpectedScalarElement,
            ),
        ] {
            let bytes = format!("<ServerSideEncryptionConfiguration>{document}</ServerSideEncryptionConfiguration>");
            assert_eq!(
                parse_bucket_encryption_dto(bytes.as_bytes()).expect_err("the wrapper is refused"),
                error,
                "{document}"
            );
        }
    }

    #[test]
    fn bucket_encryption_dto_bridge_rejects_a_duplicate_nested_switch() {
        assert_eq!(
            parse_bucket_encryption_dto(
                b"<ServerSideEncryptionConfiguration><Rule><BucketKeyEnabled>true</BucketKeyEnabled><BucketKeyEnabled>false</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>"
            )
            .expect_err("a duplicate nested switch must fail"),
            PersistenceCodecError::DuplicateField
        );
    }
}
