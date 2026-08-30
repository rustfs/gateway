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

//! CORS persistence compatibility evidence.
//!
//! Responsible for: D1-D5 evidence over independently observed old and new CORS codecs.
//! NOT responsible for: either codec implementation or HTTP CORS enforcement.
//! Upstream: pinned-s3s observations and gateway persistence codecs. Downstream: the migration
//! golden gate.

use rustfs_gateway_types::compat::{S3sCorsObservation, parse_s3s_cors, serialize_s3s_cors};
use rustfs_gateway_types::cors_tagging::{PersistedCorsConfiguration, parse_cors, serialize_cors};

use crate::{ConfigKind, FourWayCodec, GoldenFailure, GoldenSample, assert_four_way};

#[derive(Clone, Copy, Debug)]
struct CorsCodec;

/// Runs D1-D5 against the pinned old and production CORS persistence codecs.
///
/// # Errors
///
/// Returns an invalid-provenance or first D1-D5 failure.
pub fn assert_cors_four_way(sample: &GoldenSample<PersistedCorsConfiguration>) -> Result<(), GoldenFailure> {
    assert_four_way(&CorsCodec, sample)
}

impl FourWayCodec for CorsCodec {
    const KIND: ConfigKind = ConfigKind::Cors;
    type Value = PersistedCorsConfiguration;
    type OldParsed = S3sCorsObservation;
    type NewParsed = PersistedCorsConfiguration;
    type Structure = PersistedCorsConfiguration;
    type Behavior = Vec<(Vec<String>, Vec<String>, Option<Vec<String>>, Option<Vec<String>>, Option<i32>)>;

    fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
        parse_s3s_cors(bytes).map_err(|error| error.to_string())
    }
    fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
        parse_cors(bytes).map_err(|error| error.to_string())
    }
    fn old_structure(&self, value: &Self::OldParsed) -> Self::Structure {
        value.structure.clone()
    }
    fn new_structure(&self, value: &Self::NewParsed) -> Self::Structure {
        value.clone()
    }
    fn expected_structure(&self, value: &Self::Value) -> Self::Structure {
        value.clone()
    }
    fn old_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
        serialize_s3s_cors(value).map_err(|error| error.to_string())
    }
    fn new_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
        Ok(serialize_cors(value))
    }
    fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior {
        value.behavior.clone()
    }
    fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior {
        value.behavior_projection()
    }
}

#[cfg(test)]
mod tests {
    use rustfs_gateway_types::cors_tagging::PersistedCorsRule;

    use super::*;
    use crate::{Direction, SampleOrigin};

    const REPRESENTATIVE: &[u8] = b"<CORSConfiguration><CORSRule><AllowedHeader>x-amz-*</AllowedHeader><AllowedMethod>GET</AllowedMethod><AllowedMethod>PUT</AllowedMethod><AllowedOrigin>https://example.test</AllowedOrigin><ExposeHeader>ETag</ExposeHeader><ID>primary</ID><MaxAgeSeconds>3600</MaxAgeSeconds></CORSRule></CORSConfiguration>";
    const EMPTY: &[u8] = b"<CORSConfiguration></CORSConfiguration>";
    const EMPTY_RULE: &[u8] = b"<CORSConfiguration><CORSRule></CORSRule></CORSConfiguration>";
    const UNKNOWN_TOP: &[u8] = b"<CORSConfiguration><Future>future</Future><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin></CORSRule></CORSConfiguration>";
    const UNKNOWN_NESTED: &[u8] = b"<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod><Future>future</Future><AllowedOrigin>*</AllowedOrigin></CORSRule></CORSConfiguration>";
    const UNKNOWN_ATTRIBUTES: &[u8] = b"<CORSConfiguration future=\"root\"><CORSRule future=\"rule\"><AllowedMethod future=\"method\">GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin></CORSRule></CORSConfiguration>";
    const ALTERNATE_ORDER: &[u8] = b"<CORSConfiguration><CORSRule><MaxAgeSeconds>-1</MaxAgeSeconds><AllowedOrigin>*</AllowedOrigin><ID>x</ID><AllowedMethod>HEAD</AllowedMethod></CORSRule></CORSConfiguration>";

    fn value() -> PersistedCorsConfiguration {
        PersistedCorsConfiguration {
            cors_rules: vec![PersistedCorsRule {
                allowed_headers: Some(vec!["x-amz-*".to_owned()]),
                allowed_methods: vec!["GET".to_owned(), "PUT".to_owned()],
                allowed_origins: vec!["https://example.test".to_owned()],
                expose_headers: Some(vec!["ETag".to_owned()]),
                id: Some("primary".to_owned()),
                max_age_seconds: Some(3600),
            }],
        }
    }

    fn traced(
        bytes: &[u8],
        sha256: &str,
        value: PersistedCorsConfiguration,
        notes: &str,
    ) -> GoldenSample<PersistedCorsConfiguration> {
        GoldenSample {
            kind: ConfigKind::Cors,
            bytes: bytes.to_vec(),
            value,
            origin: SampleOrigin {
                source: "P9 CORS persistence matrix".to_owned(),
                producer: "pinned s3s XML behavior".to_owned(),
                version: "s3s@9c4690d8e73fc8d184031a19b2c4539ebc77d180".to_owned(),
                sha256: sha256.to_owned(),
            },
            notes: notes.to_owned(),
        }
    }

    fn sample() -> GoldenSample<PersistedCorsConfiguration> {
        traced(
            UNKNOWN_ATTRIBUTES,
            "a3ce2be903f0059e260a7e5b5e779a98cf28c36a9b7b21f1e0fe81ff3e02736b",
            value(),
            "old-readable attributes exercise D4 independently from canonical D2 bytes",
        )
    }

    #[test]
    fn cors_sample_matrix_passes_all_five_directions() {
        let minimal = |method: &str, origin: &str| PersistedCorsConfiguration {
            cors_rules: vec![PersistedCorsRule {
                allowed_methods: vec![method.to_owned()],
                allowed_origins: vec![origin.to_owned()],
                ..PersistedCorsRule::default()
            }],
        };
        let cases = [
            traced(
                REPRESENTATIVE,
                "03e02728783595d08321ee1e224b29a1e006bc741b1d3a47ce5947d1eab339f1",
                value(),
                "all behavior-bearing CORS fields",
            ),
            traced(
                UNKNOWN_TOP,
                "2cf2c8e727d1b27a3ba5086dc2d48288e85467636945993ba2a3a9f797812aad",
                minimal("GET", "*"),
                "old-readable unknown top-level element",
            ),
            traced(
                UNKNOWN_ATTRIBUTES,
                "a3ce2be903f0059e260a7e5b5e779a98cf28c36a9b7b21f1e0fe81ff3e02736b",
                minimal("GET", "*"),
                "old-readable attributes at structural and scalar levels",
            ),
            traced(
                ALTERNATE_ORDER,
                "f03a0252235828ccadc2852b9be5affcb872ef7d232bdaf1d06a0794ddea550d",
                PersistedCorsConfiguration {
                    cors_rules: vec![PersistedCorsRule {
                        allowed_methods: vec!["HEAD".to_owned()],
                        allowed_origins: vec!["*".to_owned()],
                        id: Some("x".to_owned()),
                        max_age_seconds: Some(-1),
                        ..PersistedCorsRule::default()
                    }],
                },
                "old-readable noncanonical field order and signed max age",
            ),
        ];
        for case in cases {
            assert_cors_four_way(&case).unwrap_or_else(|error| panic!("CORS {}: {error}", case.notes));
        }
    }

    #[test]
    fn repeated_lists_are_preserved_but_repeated_scalars_are_rejected() {
        let repeated_lists = b"<CORSConfiguration><CORSRule><AllowedHeader>a</AllowedHeader><AllowedHeader>b</AllowedHeader><AllowedMethod>GET</AllowedMethod><AllowedMethod>PUT</AllowedMethod><AllowedOrigin>a</AllowedOrigin><AllowedOrigin>b</AllowedOrigin><ExposeHeader>a</ExposeHeader><ExposeHeader>b</ExposeHeader></CORSRule></CORSConfiguration>";
        let old = CorsCodec
            .old_parse(repeated_lists)
            .expect("old parser accepts repeated list members");
        let new = CorsCodec
            .new_parse(repeated_lists)
            .expect("new parser accepts repeated list members");
        assert_eq!(old.structure, new);

        for (field, xml) in [
            ("ID", b"<CORSConfiguration><CORSRule><ID>a</ID><ID>b</ID></CORSRule></CORSConfiguration>".as_slice()),
            ("MaxAgeSeconds", b"<CORSConfiguration><CORSRule><MaxAgeSeconds>1</MaxAgeSeconds><MaxAgeSeconds>2</MaxAgeSeconds></CORSRule></CORSConfiguration>".as_slice()),
        ] {
            assert!(CorsCodec.old_parse(xml).is_err(), "old parser accepted duplicate {field}");
            assert!(CorsCodec.new_parse(xml).is_err(), "new parser accepted duplicate {field}");
        }
    }

    #[test]
    fn exact_old_cors_serializer_order_is_pinned() {
        assert_eq!(
            CorsCodec.old_serialize(&value()).expect("old serializer accepts full rule"),
            REPRESENTATIVE
        );
        assert_eq!(CorsCodec.new_serialize(&value()).expect("new serializer is infallible"), REPRESENTATIVE);
    }

    #[test]
    fn missing_required_cors_lists_match_the_old_refusal_boundary() {
        for (description, xml) in [
            ("empty configuration", EMPTY),
            ("empty rule", EMPTY_RULE),
            (
                "missing method",
                b"<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin></CORSRule></CORSConfiguration>".as_slice(),
            ),
            (
                "missing origin",
                b"<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>".as_slice(),
            ),
        ] {
            assert!(CorsCodec.old_parse(xml).is_err(), "old parser accepted {description}");
            assert!(CorsCodec.new_parse(xml).is_err(), "new parser accepted {description}");
        }
    }

    #[test]
    fn nested_unknown_cors_element_matches_the_old_refusal_boundary() {
        assert!(CorsCodec.old_parse(UNKNOWN_NESTED).is_err());
        assert!(CorsCodec.new_parse(UNKNOWN_NESTED).is_err());
    }

    #[test]
    fn max_age_lexemes_match_the_pinned_old_oracle() {
        for (description, lexeme, expected) in [
            ("negative", "-1", Some(-1)),
            ("explicit plus", "+1", Some(1)),
            ("surrounding whitespace", " 1 ", None),
            ("minimum", "-2147483648", Some(i32::MIN)),
            ("maximum", "2147483647", Some(i32::MAX)),
            ("below minimum", "-2147483649", None),
            ("above maximum", "2147483648", None),
        ] {
            let xml = format!(
                "<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin><MaxAgeSeconds>{lexeme}</MaxAgeSeconds></CORSRule></CORSConfiguration>"
            );
            let old = CorsCodec.old_parse(xml.as_bytes());
            let new = CorsCodec.new_parse(xml.as_bytes());
            match expected {
                Some(value) => {
                    assert_eq!(old.expect(description).structure.cors_rules[0].max_age_seconds, Some(value));
                    assert_eq!(new.expect(description).cors_rules[0].max_age_seconds, Some(value));
                }
                None => {
                    assert!(old.is_err(), "old accepted {description}");
                    assert!(new.is_err(), "new accepted {description}");
                }
            }
        }
    }

    #[test]
    fn persisted_cors_accepts_an_eight_kibibyte_origin_without_http_limits() {
        let origin = "x".repeat(8 * 1024);
        let xml = format!(
            "<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>{origin}</AllowedOrigin></CORSRule></CORSConfiguration>"
        );
        let old = CorsCodec
            .old_parse(xml.as_bytes())
            .expect("old persistence parser accepts 8 KiB origin");
        let new = CorsCodec
            .new_parse(xml.as_bytes())
            .expect("new persistence parser accepts 8 KiB origin");
        assert_eq!(old.structure, new);
        assert_eq!(new.cors_rules[0].allowed_origins[0].len(), 8 * 1024);
    }

    struct Mutant {
        d1: bool,
        d2: bool,
        d3: bool,
        d4: bool,
        d5: bool,
        panic_old: bool,
    }

    impl FourWayCodec for Mutant {
        const KIND: ConfigKind = ConfigKind::Cors;
        type Value = PersistedCorsConfiguration;
        type OldParsed = S3sCorsObservation;
        type NewParsed = PersistedCorsConfiguration;
        type Structure = PersistedCorsConfiguration;
        type Behavior = <CorsCodec as FourWayCodec>::Behavior;

        fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
            assert!(!self.panic_old, "codec observation must not run");
            if self.d3 && bytes == CorsCodec.new_serialize(&value())? {
                return Err("mutation: rollback refusal".to_owned());
            }
            CorsCodec.old_parse(bytes)
        }
        fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
            if self.d4 && bytes == UNKNOWN_ATTRIBUTES {
                return Err("mutation: stricter parser".to_owned());
            }
            let mut parsed = CorsCodec.new_parse(bytes)?;
            if self.d1 {
                parsed.cors_rules[0].allowed_methods.clear();
            }
            Ok(parsed)
        }
        fn old_structure(&self, value: &Self::OldParsed) -> Self::Structure {
            CorsCodec.old_structure(value)
        }
        fn new_structure(&self, value: &Self::NewParsed) -> Self::Structure {
            CorsCodec.new_structure(value)
        }
        fn expected_structure(&self, value: &Self::Value) -> Self::Structure {
            CorsCodec.expected_structure(value)
        }
        fn old_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
            let mut bytes = CorsCodec.old_serialize(value)?;
            if self.d2 {
                bytes.push(b' ');
            }
            Ok(bytes)
        }
        fn new_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
            CorsCodec.new_serialize(value)
        }
        fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior {
            CorsCodec.old_behavior(value)
        }
        fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior {
            let mut behavior = CorsCodec.new_behavior(value);
            if self.d5 {
                behavior[0].4 = Some(7);
            }
            behavior
        }
    }

    fn mutant() -> Mutant {
        Mutant {
            d1: false,
            d2: false,
            d3: false,
            d4: false,
            d5: false,
            panic_old: false,
        }
    }

    #[test]
    fn every_cors_direction_has_a_mutation_control() {
        for (direction, mutate) in [
            (Direction::D1CompatibleRead, 1),
            (Direction::D2ByteWrite, 2),
            (Direction::D3RollbackRead, 3),
            (Direction::D4NotStricter, 4),
            (Direction::D5Behavior, 5),
        ] {
            let mut codec = mutant();
            match mutate {
                1 => codec.d1 = true,
                2 => codec.d2 = true,
                3 => codec.d3 = true,
                4 => codec.d4 = true,
                5 => codec.d5 = true,
                _ => unreachable!(),
            }
            let failure = assert_four_way(&codec, &sample()).expect_err("mutation must make its direction red");
            assert_eq!(failure.direction, direction);
        }
    }

    #[test]
    fn wrong_family_fails_before_codec_observation() {
        let mut invalid = sample();
        invalid.kind = ConfigKind::Tagging;
        let mut codec = mutant();
        codec.panic_old = true;
        let failure = assert_four_way(&codec, &invalid).expect_err("wrong kind must fail closed");
        assert_eq!(failure.direction, Direction::Input);
    }
}
