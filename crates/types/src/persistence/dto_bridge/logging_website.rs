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

//! Bucket Logging and Website generated DTO persistence bridges.
//!
//! Responsible for: lossless conversion through the historical Logging and Website codecs.
//! NOT responsible for: XML parsing rules, HTTP validation, log delivery, or website routing.
//! Upstream: Logging and Website persistence codecs. Downstream: generated DTO metadata consumers.

use super::PersistenceBridgeError;
use crate::persistence::{
    PersistedBucketLoggingStatus, PersistedErrorDocument, PersistedGrantee, PersistedIndexDocument, PersistedLoggingEnabled,
    PersistedLoggingGrant, PersistedRedirect, PersistedRedirectAllRequestsTo, PersistedRoutingRule,
    PersistedRoutingRuleCondition, PersistedTargetObjectKeyFormat, PersistedWebsiteConfiguration, parse_bucket_logging,
    parse_website, serialize_bucket_logging, serialize_website,
};

/// Parses persisted Bucket Logging bytes directly into the generated HTTP DTO.
///
/// # Errors
///
/// Returns [`PersistenceBridgeError::Codec`] when the historical persistence parser rejects the
/// bytes.
pub fn parse_bucket_logging_dto(input: &[u8]) -> Result<crate::dto::BucketLoggingStatus, PersistenceBridgeError> {
    let persisted = parse_bucket_logging(input)?;
    Ok(crate::dto::BucketLoggingStatus {
        logging_enabled: persisted.logging_enabled.map(|logging| crate::dto::LoggingEnabled {
            target_bucket: logging.target_bucket,
            target_grants: logging
                .target_grants
                .unwrap_or_default()
                .into_iter()
                .map(|grant| crate::dto::TargetGrant {
                    grantee: grant.grantee.map(|grantee| crate::dto::Grantee {
                        display_name: grantee.display_name,
                        email_address: grantee.email_address,
                        id: grantee.id,
                        r#type: Some(crate::dto::Type::custom(grantee.grantee_type)),
                        uri: grantee.uri,
                    }),
                    permission: grant.permission.map(crate::dto::Permission::custom),
                })
                .collect(),
            target_object_key_format: logging
                .target_object_key_format
                .map(|format| crate::dto::TargetObjectKeyFormat {
                    partitioned_prefix: format.partition_date_source.map(|source| crate::dto::PartitionedPrefix {
                        partition_date_source: source.map(crate::dto::PartitionDateSource::custom),
                    }),
                    simple_prefix: format.simple_prefix.then_some(crate::dto::SimplePrefix {}),
                }),
            target_prefix: logging.target_prefix,
        }),
    })
}

/// Serializes the generated Bucket Logging DTO with the historical persistence writer.
///
/// # Errors
///
/// Returns [`PersistenceBridgeError::UnsupportedMember`] when a present generated grantee omits
/// the discriminator required by the historical persistence format.
pub fn serialize_bucket_logging_dto(value: &crate::dto::BucketLoggingStatus) -> Result<Vec<u8>, PersistenceBridgeError> {
    let logging_enabled = value
        .logging_enabled
        .as_ref()
        .map(|logging| {
            let target_grants = (!logging.target_grants.is_empty())
                .then(|| {
                    logging
                        .target_grants
                        .iter()
                        .map(persisted_logging_grant)
                        .collect::<Result<Vec<_>, PersistenceBridgeError>>()
                })
                .transpose()?;
            Ok::<_, PersistenceBridgeError>(PersistedLoggingEnabled {
                target_bucket: logging.target_bucket.clone(),
                target_grants,
                target_object_key_format: logging.target_object_key_format.as_ref().map(|format| {
                    PersistedTargetObjectKeyFormat {
                        partition_date_source: format.partitioned_prefix.as_ref().map(|partitioned| {
                            partitioned
                                .partition_date_source
                                .as_ref()
                                .map(|source| source.as_str().to_owned())
                        }),
                        simple_prefix: format.simple_prefix.is_some(),
                    }
                }),
                target_prefix: logging.target_prefix.clone(),
            })
        })
        .transpose()?;
    Ok(serialize_bucket_logging(&PersistedBucketLoggingStatus { logging_enabled }))
}

fn persisted_logging_grant(grant: &crate::dto::TargetGrant) -> Result<PersistedLoggingGrant, PersistenceBridgeError> {
    let grantee = grant
        .grantee
        .as_ref()
        .map(|grantee| {
            let grantee_type = grantee
                .r#type
                .as_ref()
                .ok_or(PersistenceBridgeError::UnsupportedMember("LoggingEnabled.TargetGrants.Grantee.Type"))?;
            Ok::<_, PersistenceBridgeError>(PersistedGrantee {
                display_name: grantee.display_name.clone(),
                email_address: grantee.email_address.clone(),
                id: grantee.id.clone(),
                grantee_type: grantee_type.as_str().to_owned(),
                uri: grantee.uri.clone(),
            })
        })
        .transpose()?;
    Ok(PersistedLoggingGrant {
        grantee,
        permission: grant.permission.as_ref().map(|permission| permission.as_str().to_owned()),
    })
}

/// Parses persisted Website bytes directly into the generated HTTP DTO.
///
/// # Errors
///
/// Returns [`PersistenceBridgeError::Codec`] when the historical persistence parser rejects the
/// bytes, and [`PersistenceBridgeError::UnsupportedPersistedMember`] when a persisted error key
/// cannot satisfy the generated [`crate::ObjectKey`] representation.
pub fn parse_website_dto(input: &[u8]) -> Result<crate::dto::WebsiteConfiguration, PersistenceBridgeError> {
    let persisted = parse_website(input)?;
    let error_document = persisted
        .error_document
        .map(|error| {
            crate::ObjectKey::new(error.key)
                .map(|key| crate::dto::ErrorDocument { key })
                .map_err(|_| PersistenceBridgeError::UnsupportedPersistedMember("WebsiteConfiguration.ErrorDocument.Key"))
        })
        .transpose()?;
    Ok(crate::dto::WebsiteConfiguration {
        error_document,
        index_document: persisted
            .index_document
            .map(|index| crate::dto::IndexDocument { suffix: index.suffix }),
        redirect_all_requests_to: persisted
            .redirect_all_requests_to
            .map(|redirect| crate::dto::RedirectAllRequestsTo {
                host_name: redirect.host_name,
                protocol: redirect.protocol.map(crate::dto::Protocol::custom),
            }),
        routing_rules: persisted
            .routing_rules
            .unwrap_or_default()
            .into_iter()
            .map(|rule| crate::dto::RoutingRule {
                condition: rule.condition.map(|condition| crate::dto::Condition {
                    http_error_code_returned_equals: condition.http_error_code_returned_equals,
                    key_prefix_equals: condition.key_prefix_equals,
                }),
                redirect: crate::dto::Redirect {
                    host_name: rule.redirect.host_name,
                    http_redirect_code: rule.redirect.http_redirect_code,
                    protocol: rule.redirect.protocol.map(crate::dto::Protocol::custom),
                    replace_key_prefix_with: rule.redirect.replace_key_prefix_with,
                    replace_key_with: rule.redirect.replace_key_with,
                },
            })
            .collect(),
    })
}

/// Serializes the generated Website DTO with the historical persistence writer.
#[must_use]
pub fn serialize_website_dto(value: &crate::dto::WebsiteConfiguration) -> Vec<u8> {
    serialize_website(&PersistedWebsiteConfiguration {
        error_document: value.error_document.as_ref().map(|error| PersistedErrorDocument {
            key: error.key.as_str().to_owned(),
        }),
        index_document: value.index_document.as_ref().map(|index| PersistedIndexDocument {
            suffix: index.suffix.clone(),
        }),
        redirect_all_requests_to: value
            .redirect_all_requests_to
            .as_ref()
            .map(|redirect| PersistedRedirectAllRequestsTo {
                host_name: redirect.host_name.clone(),
                protocol: redirect.protocol.as_ref().map(|protocol| protocol.as_str().to_owned()),
            }),
        routing_rules: (!value.routing_rules.is_empty()).then(|| {
            value
                .routing_rules
                .iter()
                .map(|rule| PersistedRoutingRule {
                    condition: rule.condition.as_ref().map(|condition| PersistedRoutingRuleCondition {
                        http_error_code_returned_equals: condition.http_error_code_returned_equals.clone(),
                        key_prefix_equals: condition.key_prefix_equals.clone(),
                    }),
                    redirect: PersistedRedirect {
                        host_name: rule.redirect.host_name.clone(),
                        http_redirect_code: rule.redirect.http_redirect_code.clone(),
                        protocol: rule.redirect.protocol.as_ref().map(|protocol| protocol.as_str().to_owned()),
                        replace_key_prefix_with: rule.redirect.replace_key_prefix_with.clone(),
                        replace_key_with: rule.redirect.replace_key_with.clone(),
                    },
                })
                .collect()
        }),
    })
}

#[cfg(test)]
mod tests {
    use crate::ObjectKey;
    use crate::dto::{
        BucketLoggingStatus, Condition, ErrorDocument, Grantee, IndexDocument, LoggingEnabled, PartitionedPrefix, Permission,
        Protocol, Redirect, RoutingRule, SimplePrefix, TargetGrant, TargetObjectKeyFormat, Type, WebsiteConfiguration,
    };
    use crate::persistence::{PersistenceBridgeError, PersistenceCodecError};

    use super::{parse_bucket_logging_dto, parse_website_dto, serialize_bucket_logging_dto, serialize_website_dto};

    #[test]
    fn logging_dto_bridge_preserves_nested_members_and_the_old_writer_order() {
        let dto = BucketLoggingStatus {
            logging_enabled: Some(LoggingEnabled {
                target_bucket: "logs".to_owned(),
                target_grants: vec![TargetGrant {
                    grantee: Some(Grantee {
                        id: Some("abc".to_owned()),
                        r#type: Some(Type::custom("FutureUser")),
                        ..Grantee::default()
                    }),
                    permission: Some(Permission::custom("FuturePermission")),
                }],
                target_object_key_format: Some(TargetObjectKeyFormat {
                    partitioned_prefix: Some(PartitionedPrefix {
                        partition_date_source: Some(crate::dto::PartitionDateSource::custom("FutureDate")),
                    }),
                    simple_prefix: Some(SimplePrefix {}),
                }),
                target_prefix: "access/".to_owned(),
            }),
        };

        let bytes = serialize_bucket_logging_dto(&dto).expect("the required grantee type is present");
        assert_eq!(
            bytes,
            b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket><TargetGrants><Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"FutureUser\"><ID>abc</ID></Grantee><Permission>FuturePermission</Permission></Grant></TargetGrants><TargetObjectKeyFormat><PartitionedPrefix><PartitionDateSource>FutureDate</PartitionDateSource></PartitionedPrefix><SimplePrefix></SimplePrefix></TargetObjectKeyFormat><TargetPrefix>access/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>"
        );
        let parsed = parse_bucket_logging_dto(&bytes).expect("the bridge reads its own persistence bytes");
        let enabled = parsed.logging_enabled.expect("logging remains enabled");
        assert_eq!(enabled.target_bucket, "logs");
        assert_eq!(enabled.target_prefix, "access/");
        let grant = &enabled.target_grants[0];
        assert_eq!(grant.grantee.as_ref().and_then(|value| value.id.as_deref()), Some("abc"));
        assert_eq!(
            grant
                .grantee
                .as_ref()
                .and_then(|value| value.r#type.as_ref())
                .map(|value| value.as_str()),
            Some("FutureUser")
        );
        assert_eq!(grant.permission.as_ref().map(|value| value.as_str()), Some("FuturePermission"));
    }

    #[test]
    fn logging_dto_bridge_rejects_a_wrong_family() {
        assert_eq!(
            parse_bucket_logging_dto(b"<WebsiteConfiguration></WebsiteConfiguration>").expect_err("a different family must fail"),
            PersistenceBridgeError::Codec(PersistenceCodecError::WrongRoot)
        );
    }

    #[test]
    fn logging_dto_bridge_rejects_a_missing_target_bucket() {
        assert_eq!(
            parse_bucket_logging_dto(
                b"<BucketLoggingStatus><LoggingEnabled><TargetPrefix>access/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>"
            )
            .expect_err("the target bucket is required"),
            PersistenceBridgeError::Codec(PersistenceCodecError::MissingRequiredField)
        );
    }

    #[test]
    fn logging_dto_bridge_rejects_a_persisted_grantee_without_its_type() {
        assert_eq!(
            parse_bucket_logging_dto(
                b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket><TargetGrants><Grant><Grantee><ID>abc</ID></Grantee></Grant></TargetGrants><TargetPrefix>access/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>"
            )
            .expect_err("the historical grantee type is required"),
            PersistenceBridgeError::Codec(PersistenceCodecError::MissingRequiredField)
        );
    }

    #[test]
    fn logging_dto_bridge_refuses_to_invent_a_generated_grantee_type() {
        let dto = BucketLoggingStatus {
            logging_enabled: Some(LoggingEnabled {
                target_bucket: "logs".to_owned(),
                target_grants: vec![TargetGrant {
                    grantee: Some(Grantee::default()),
                    permission: None,
                }],
                target_object_key_format: None,
                target_prefix: String::new(),
            }),
        };
        assert_eq!(
            serialize_bucket_logging_dto(&dto).expect_err("a required discriminator cannot be invented"),
            PersistenceBridgeError::UnsupportedMember("LoggingEnabled.TargetGrants.Grantee.Type")
        );
    }

    #[test]
    fn website_dto_bridge_preserves_nested_members_and_the_old_writer_order() {
        let dto = WebsiteConfiguration {
            error_document: Some(ErrorDocument {
                key: ObjectKey::new("error.html").expect("the key is valid"),
            }),
            index_document: Some(IndexDocument {
                suffix: "index.html".to_owned(),
            }),
            redirect_all_requests_to: None,
            routing_rules: vec![RoutingRule {
                condition: Some(Condition {
                    http_error_code_returned_equals: None,
                    key_prefix_equals: Some("docs/".to_owned()),
                }),
                redirect: Redirect {
                    host_name: Some("docs.example.test".to_owned()),
                    http_redirect_code: Some("302".to_owned()),
                    protocol: Some(Protocol::custom("FutureProtocol")),
                    replace_key_prefix_with: Some("published/".to_owned()),
                    replace_key_with: None,
                },
            }],
        };

        let bytes = serialize_website_dto(&dto);
        assert_eq!(
            bytes,
            b"<WebsiteConfiguration><ErrorDocument><Key>error.html</Key></ErrorDocument><IndexDocument><Suffix>index.html</Suffix></IndexDocument><RoutingRules><RoutingRule><Condition><KeyPrefixEquals>docs/</KeyPrefixEquals></Condition><Redirect><HostName>docs.example.test</HostName><HttpRedirectCode>302</HttpRedirectCode><Protocol>FutureProtocol</Protocol><ReplaceKeyPrefixWith>published/</ReplaceKeyPrefixWith></Redirect></RoutingRule></RoutingRules></WebsiteConfiguration>"
        );
        let parsed = parse_website_dto(&bytes).expect("the bridge reads its own persistence bytes");
        assert_eq!(parsed.error_document.as_ref().map(|value| value.key.as_str()), Some("error.html"));
        assert_eq!(parsed.index_document.as_ref().map(|value| value.suffix.as_str()), Some("index.html"));
        let rule = &parsed.routing_rules[0];
        assert_eq!(
            rule.condition.as_ref().and_then(|value| value.key_prefix_equals.as_deref()),
            Some("docs/")
        );
        assert_eq!(rule.redirect.protocol.as_ref().map(|value| value.as_str()), Some("FutureProtocol"));
    }

    #[test]
    fn website_dto_bridge_rejects_a_wrong_family() {
        assert_eq!(
            parse_website_dto(b"<BucketLoggingStatus></BucketLoggingStatus>").expect_err("a different family must fail"),
            PersistenceBridgeError::Codec(PersistenceCodecError::WrongRoot)
        );
    }

    #[test]
    fn website_dto_bridge_rejects_an_unrepresentable_error_key() {
        assert_eq!(
            parse_website_dto(b"<WebsiteConfiguration><ErrorDocument><Key></Key></ErrorDocument></WebsiteConfiguration>")
                .expect_err("an empty generated object key must fail"),
            PersistenceBridgeError::UnsupportedPersistedMember("WebsiteConfiguration.ErrorDocument.Key")
        );
    }

    #[test]
    fn website_dto_bridge_rejects_a_routing_rule_without_a_redirect() {
        assert_eq!(
            parse_website_dto(
                b"<WebsiteConfiguration><RoutingRules><RoutingRule><Condition></Condition></RoutingRule></RoutingRules></WebsiteConfiguration>"
            )
            .expect_err("the redirect is required"),
            PersistenceBridgeError::Codec(PersistenceCodecError::MissingRequiredField)
        );
    }

    #[test]
    fn website_dto_bridge_rejects_a_duplicate_index_document() {
        assert_eq!(
            parse_website_dto(
                b"<WebsiteConfiguration><IndexDocument><Suffix>a</Suffix></IndexDocument><IndexDocument><Suffix>b</Suffix></IndexDocument></WebsiteConfiguration>"
            )
            .expect_err("a repeated structure must fail"),
            PersistenceBridgeError::Codec(PersistenceCodecError::DuplicateField)
        );
    }
}
