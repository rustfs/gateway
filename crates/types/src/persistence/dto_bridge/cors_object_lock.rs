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

//! CORS and Object Lock generated DTO persistence bridges.
//!
//! Responsible for: lossless conversion through the existing historical CORS and Object Lock codecs.
//! NOT responsible for: XML parsing rules, HTTP validation, or runtime policy decisions.
//! Upstream: CORS and Object Lock persistence codecs. Downstream: generated DTO metadata consumers.

use crate::cors_tagging::{CorsTaggingCodecError, PersistedCorsConfiguration, PersistedCorsRule, parse_cors, serialize_cors};

use super::PersistenceBridgeError;
use crate::persistence::{
    PersistedDefaultRetention, PersistedObjectLockConfiguration, PersistedObjectLockRule, parse_object_lock,
    serialize_object_lock,
};

/// Parses persisted CORS bytes directly into the generated HTTP DTO.
///
/// # Errors
///
/// Returns [`CorsTaggingCodecError`] when the historical persistence parser rejects the bytes.
pub fn parse_cors_dto(input: &[u8]) -> Result<crate::dto::CorsConfiguration, CorsTaggingCodecError> {
    let persisted = parse_cors(input)?;
    Ok(crate::dto::CorsConfiguration {
        cors_rules: persisted
            .cors_rules
            .into_iter()
            .map(|rule| crate::dto::CorsRule {
                allowed_headers: rule.allowed_headers.unwrap_or_default(),
                allowed_methods: rule.allowed_methods,
                allowed_origins: rule.allowed_origins,
                expose_headers: rule.expose_headers.unwrap_or_default(),
                id: rule.id,
                max_age_seconds: rule.max_age_seconds,
            })
            .collect(),
    })
}

/// Serializes the generated CORS DTO with the historical persistence writer.
#[must_use]
pub fn serialize_cors_dto(value: &crate::dto::CorsConfiguration) -> Vec<u8> {
    serialize_cors(&PersistedCorsConfiguration {
        cors_rules: value
            .cors_rules
            .iter()
            .map(|rule| PersistedCorsRule {
                allowed_headers: (!rule.allowed_headers.is_empty()).then(|| rule.allowed_headers.clone()),
                allowed_methods: rule.allowed_methods.clone(),
                allowed_origins: rule.allowed_origins.clone(),
                expose_headers: (!rule.expose_headers.is_empty()).then(|| rule.expose_headers.clone()),
                id: rule.id.clone(),
                max_age_seconds: rule.max_age_seconds,
            })
            .collect(),
    })
}

/// Parses persisted Object Lock bytes directly into the generated HTTP DTO.
///
/// # Errors
///
/// Returns [`PersistenceBridgeError::Codec`] when the historical persistence parser rejects the
/// bytes.
pub fn parse_object_lock_dto(input: &[u8]) -> Result<crate::dto::ObjectLockConfiguration, PersistenceBridgeError> {
    let persisted = parse_object_lock(input)?;
    Ok(crate::dto::ObjectLockConfiguration {
        object_lock_enabled: persisted.object_lock_enabled.map(crate::dto::ObjectLockEnabled::custom),
        rule: persisted.rule.map(|rule| crate::dto::ObjectLockRule {
            default_retention: rule.default_retention.map(|retention| crate::dto::DefaultRetention {
                mode: retention.mode.map(crate::dto::Mode::custom),
                days: retention.days,
                years: retention.years,
            }),
        }),
    })
}

/// Serializes the generated Object Lock DTO with the historical persistence writer.
#[must_use]
pub fn serialize_object_lock_dto(value: &crate::dto::ObjectLockConfiguration) -> Vec<u8> {
    serialize_object_lock(&PersistedObjectLockConfiguration {
        object_lock_enabled: value.object_lock_enabled.as_ref().map(|enabled| enabled.as_str().to_owned()),
        rule: value.rule.as_ref().map(|rule| PersistedObjectLockRule {
            default_retention: rule.default_retention.as_ref().map(|retention| PersistedDefaultRetention {
                mode: retention.mode.as_ref().map(|mode| mode.as_str().to_owned()),
                days: retention.days,
                years: retention.years,
            }),
        }),
    })
}

#[cfg(test)]
mod tests {
    use crate::cors_tagging::CorsTaggingCodecError;
    use crate::dto::{
        CorsConfiguration, CorsRule, DefaultRetention, Mode, ObjectLockConfiguration, ObjectLockEnabled, ObjectLockRule,
    };

    use super::{parse_cors_dto, parse_object_lock_dto, serialize_cors_dto, serialize_object_lock_dto};
    use crate::persistence::{PersistenceBridgeError, PersistenceCodecError};

    #[test]
    fn cors_dto_bridge_preserves_every_member_and_the_old_writer_order() {
        let dto = CorsConfiguration {
            cors_rules: vec![CorsRule {
                allowed_headers: vec!["x-amz-*".to_owned()],
                allowed_methods: vec!["GET".to_owned()],
                allowed_origins: vec!["https://example.test".to_owned()],
                expose_headers: vec!["ETag".to_owned()],
                id: Some("read".to_owned()),
                max_age_seconds: Some(300),
            }],
        };

        let bytes = serialize_cors_dto(&dto);
        assert_eq!(
            bytes,
            b"<CORSConfiguration><CORSRule><AllowedHeader>x-amz-*</AllowedHeader><AllowedMethod>GET</AllowedMethod><AllowedOrigin>https://example.test</AllowedOrigin><ExposeHeader>ETag</ExposeHeader><ID>read</ID><MaxAgeSeconds>300</MaxAgeSeconds></CORSRule></CORSConfiguration>"
        );
        let parsed = parse_cors_dto(&bytes).expect("the bridge reads its own persistence bytes");
        let rule = &parsed.cors_rules[0];
        assert_eq!(rule.allowed_headers, ["x-amz-*"]);
        assert_eq!(rule.allowed_methods, ["GET"]);
        assert_eq!(rule.allowed_origins, ["https://example.test"]);
        assert_eq!(rule.expose_headers, ["ETag"]);
        assert_eq!(rule.id.as_deref(), Some("read"));
        assert_eq!(rule.max_age_seconds, Some(300));
    }

    #[test]
    fn cors_dto_bridge_rejects_a_wrong_family() {
        assert_eq!(
            parse_cors_dto(b"<Tagging><TagSet></TagSet></Tagging>").expect_err("a different family must fail"),
            CorsTaggingCodecError::WrongRoot
        );
    }

    #[test]
    fn cors_dto_bridge_rejects_a_missing_rule() {
        assert_eq!(
            parse_cors_dto(b"<CORSConfiguration></CORSConfiguration>").expect_err("a rule is required"),
            CorsTaggingCodecError::MissingField("CORSRule")
        );
    }

    #[test]
    fn cors_dto_bridge_rejects_an_invalid_max_age() {
        assert_eq!(
            parse_cors_dto(
                b"<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin><MaxAgeSeconds>soon</MaxAgeSeconds></CORSRule></CORSConfiguration>"
            )
            .expect_err("an invalid duration must fail"),
            CorsTaggingCodecError::InvalidMaxAge
        );
    }

    #[test]
    fn object_lock_dto_bridge_preserves_presence_unknown_enums_and_old_writer_order() {
        let dto = ObjectLockConfiguration {
            object_lock_enabled: Some(ObjectLockEnabled::custom("FutureEnabled")),
            rule: Some(ObjectLockRule {
                default_retention: Some(DefaultRetention {
                    mode: Some(Mode::custom("FutureMode")),
                    days: Some(7),
                    years: Some(2),
                }),
            }),
        };

        let bytes = serialize_object_lock_dto(&dto);
        assert_eq!(
            bytes,
            b"<ObjectLockConfiguration><ObjectLockEnabled>FutureEnabled</ObjectLockEnabled><Rule><DefaultRetention><Days>7</Days><Mode>FutureMode</Mode><Years>2</Years></DefaultRetention></Rule></ObjectLockConfiguration>"
        );
        let parsed = parse_object_lock_dto(&bytes).expect("the bridge reads its own persistence bytes");
        assert_eq!(parsed.object_lock_enabled.as_ref().map(|value| value.as_str()), Some("FutureEnabled"));
        let retention = parsed
            .rule
            .as_ref()
            .and_then(|rule| rule.default_retention.as_ref())
            .expect("the retention remains present");
        assert_eq!(retention.mode.as_ref().map(|value| value.as_str()), Some("FutureMode"));
        assert_eq!(retention.days, Some(7));
        assert_eq!(retention.years, Some(2));
    }

    #[test]
    fn object_lock_dto_bridge_rejects_a_wrong_family() {
        assert_eq!(
            parse_object_lock_dto(b"<VersioningConfiguration></VersioningConfiguration>")
                .expect_err("a different family must fail"),
            PersistenceBridgeError::Codec(PersistenceCodecError::WrongRoot)
        );
    }

    #[test]
    fn object_lock_dto_bridge_rejects_duplicate_enabled_members() {
        assert_eq!(
            parse_object_lock_dto(
                b"<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>"
            )
            .expect_err("a repeated scalar must fail"),
            PersistenceBridgeError::Codec(PersistenceCodecError::DuplicateField)
        );
    }

    #[test]
    fn object_lock_dto_bridge_rejects_an_unknown_nested_member() {
        assert_eq!(
            parse_object_lock_dto(b"<ObjectLockConfiguration><Rule><FutureRule></FutureRule></Rule></ObjectLockConfiguration>")
                .expect_err("a nested unknown field must fail"),
            PersistenceBridgeError::Codec(PersistenceCodecError::UnexpectedObjectLockElement)
        );
    }

    #[test]
    fn object_lock_dto_bridge_rejects_an_invalid_duration() {
        assert_eq!(
            parse_object_lock_dto(
                b"<ObjectLockConfiguration><Rule><DefaultRetention><Days>forever</Days></DefaultRetention></Rule></ObjectLockConfiguration>"
            )
            .expect_err("an invalid duration must fail"),
            PersistenceBridgeError::Codec(PersistenceCodecError::InvalidObjectLockDuration)
        );
    }
}
