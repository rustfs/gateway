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
use rustfs_gateway_types::cors_tagging::{PersistedCorsConfiguration, PersistedCorsRule, parse_cors, serialize_cors};

use crate::{
    ConfigKind, CorpusCaseEvidence, CorpusCoverageError, CorpusVariant, FamilyCorpusEvidence, FourWayCodec, GoldenFailure,
    GoldenSample, RejectedGoldenSample, SampleOrigin, assert_four_way,
};

const REPRESENTATIVE: &[u8] = b"<CORSConfiguration><CORSRule><AllowedHeader>x-amz-*</AllowedHeader><AllowedMethod>GET</AllowedMethod><AllowedMethod>PUT</AllowedMethod><AllowedOrigin>https://example.test</AllowedOrigin><ExposeHeader>ETag</ExposeHeader><ID>primary</ID><MaxAgeSeconds>3600</MaxAgeSeconds></CORSRule></CORSConfiguration>";
const EMPTY: &[u8] = b"<CORSConfiguration></CORSConfiguration>";
const EMPTY_RULE: &[u8] = b"<CORSConfiguration><CORSRule></CORSRule></CORSConfiguration>";
const UNKNOWN_TOP: &[u8] = b"<CORSConfiguration><Future>future</Future><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin></CORSRule></CORSConfiguration>";
const UNKNOWN_NESTED: &[u8] = b"<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod><Future>future</Future><AllowedOrigin>*</AllowedOrigin></CORSRule></CORSConfiguration>";
const UNKNOWN_ATTRIBUTES: &[u8] = b"<CORSConfiguration future=\"root\"><CORSRule future=\"rule\"><AllowedMethod future=\"method\">GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin></CORSRule></CORSConfiguration>";
const ALTERNATE_ORDER: &[u8] = b"<CORSConfiguration><CORSRule><MaxAgeSeconds>-1</MaxAgeSeconds><AllowedOrigin>*</AllowedOrigin><ID>x</ID><AllowedMethod>HEAD</AllowedMethod></CORSRule></CORSConfiguration>";
const SOURCE_B_BOTO3: &[u8] = b"<CORSConfiguration><CORSRule><AllowedHeader>authorization</AllowedHeader><AllowedHeader>content-type</AllowedHeader><AllowedHeader>x-amz-date</AllowedHeader><AllowedMethod>GET</AllowedMethod><AllowedMethod>PUT</AllowedMethod><AllowedOrigin>https://source-b.example.test</AllowedOrigin><ExposeHeader>etag</ExposeHeader><ExposeHeader>x-amz-version-id</ExposeHeader><ID>boto3-cors</ID><MaxAgeSeconds>600</MaxAgeSeconds></CORSRule></CORSConfiguration>";
const SOURCE_B_AWS_CLI: &[u8] = b"<CORSConfiguration><CORSRule><AllowedHeader>range</AllowedHeader><AllowedHeader>x-amz-meta-*</AllowedHeader><AllowedMethod>GET</AllowedMethod><AllowedMethod>HEAD</AllowedMethod><AllowedMethod>POST</AllowedMethod><AllowedOrigin>https://cli.example.test</AllowedOrigin><AllowedOrigin>https://fallback.example.test</AllowedOrigin><ExposeHeader>x-amz-request-id</ExposeHeader><ID>aws-cli-cors</ID><MaxAgeSeconds>321</MaxAgeSeconds></CORSRule></CORSConfiguration>";

type AcceptedCorsCase = (GoldenSample<PersistedCorsConfiguration>, &'static [CorpusVariant]);
type RejectedCorsCase = (RejectedGoldenSample, &'static [CorpusVariant]);

fn minimal(method: &str, origin: &str) -> PersistedCorsConfiguration {
    PersistedCorsConfiguration {
        cors_rules: vec![PersistedCorsRule {
            allowed_methods: vec![method.to_owned()],
            allowed_origins: vec![origin.to_owned()],
            ..PersistedCorsRule::default()
        }],
    }
}

fn representative_value() -> PersistedCorsConfiguration {
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

fn origin(sha256: &str) -> SampleOrigin {
    SampleOrigin {
        source: "P9 CORS persistence matrix".to_owned(),
        producer: "pinned s3s XML behavior".to_owned(),
        version: "s3s@9c4690d8e73fc8d184031a19b2c4539ebc77d180".to_owned(),
        sha256: sha256.to_owned(),
    }
}

fn accepted(
    bytes: Vec<u8>,
    sha256: &str,
    value: PersistedCorsConfiguration,
    notes: &str,
    variants: &'static [CorpusVariant],
) -> AcceptedCorsCase {
    (
        GoldenSample {
            kind: ConfigKind::Cors,
            bytes,
            value,
            origin: origin(sha256),
            notes: notes.to_owned(),
        },
        variants,
    )
}

fn rejected(bytes: &[u8], sha256: &str, notes: &str, variants: &'static [CorpusVariant]) -> RejectedCorsCase {
    (
        RejectedGoldenSample {
            kind: ConfigKind::Cors,
            bytes: bytes.to_vec(),
            origin: origin(sha256),
            notes: notes.to_owned(),
        },
        variants,
    )
}

fn accepted_cases() -> Vec<AcceptedCorsCase> {
    let large_origin = "x".repeat(8 * 1024);
    let large_xml = format!(
        "<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>{large_origin}</AllowedOrigin></CORSRule></CORSConfiguration>"
    );
    let mut cases: Vec<AcceptedCorsCase> = vec![
        (
            GoldenSample {
                kind: ConfigKind::Cors,
                bytes: SOURCE_B_AWS_CLI.to_vec(),
                value: PersistedCorsConfiguration {
                    cors_rules: vec![PersistedCorsRule {
                        allowed_headers: Some(vec!["range".to_owned(), "x-amz-meta-*".to_owned()]),
                        allowed_methods: vec!["GET".to_owned(), "HEAD".to_owned(), "POST".to_owned()],
                        allowed_origins: vec![
                            "https://cli.example.test".to_owned(),
                            "https://fallback.example.test".to_owned(),
                        ],
                        expose_headers: Some(vec!["x-amz-request-id".to_owned()]),
                        id: Some("aws-cli-cors".to_owned()),
                        max_age_seconds: Some(321),
                    }],
                },
                origin: SampleOrigin {
                    source: "Source-(b) live aws-cli client matrix capture".to_owned(),
                    producer: "aws-cli 1.44.87 against disposable RustFS; rustfs-cli raw export".to_owned(),
                    version: "botocore@1.42.97; rustfs-server@sha256:1174803fcd0051a4a008fdaaed29fc7e8e7e16b07abdf8108553a439523e998a; rustfs-cli@c876df53f5097618b1817568a471cbb8b4f26ee8".to_owned(),
                    sha256: "47bacc6af5e2106e50ac20da793aede81416437e92df757f8a1682b315782da3".to_owned(),
                },
                notes: "byte-exact CORS XML persisted after an aws-cli put-bucket-cors request".to_owned(),
            },
            &[CorpusVariant::Canonical],
        ),
        (
            GoldenSample {
                kind: ConfigKind::Cors,
                bytes: SOURCE_B_BOTO3.to_vec(),
                value: PersistedCorsConfiguration {
                    cors_rules: vec![PersistedCorsRule {
                        allowed_headers: Some(vec![
                            "authorization".to_owned(),
                            "content-type".to_owned(),
                            "x-amz-date".to_owned(),
                        ]),
                        allowed_methods: vec!["GET".to_owned(), "PUT".to_owned()],
                        allowed_origins: vec!["https://source-b.example.test".to_owned()],
                        expose_headers: Some(vec!["etag".to_owned(), "x-amz-version-id".to_owned()]),
                        id: Some("boto3-cors".to_owned()),
                        max_age_seconds: Some(600),
                    }],
                },
                origin: SampleOrigin {
                    source: "Source-(b) live boto3 client matrix capture".to_owned(),
                    producer: "boto3 1.40.21 against disposable RustFS; rustfs-cli raw export".to_owned(),
                    version: "botocore@1.40.76; rustfs-server@sha256:e294d7887fbea1992496146f98c32e3b517efc6dec9e53bb592fff9a04bb2ae9; rustfs-cli@c876df53f5097618b1817568a471cbb8b4f26ee8".to_owned(),
                    sha256: "be55a446cff4f490a1e978281abc85174eccab433bf7a0890d2ff198a474052a".to_owned(),
                },
                notes: "byte-exact CORS XML persisted after a structured boto3 PutBucketCors request".to_owned(),
            },
            &[CorpusVariant::Canonical],
        ),
        accepted(
            REPRESENTATIVE.to_vec(),
            "03e02728783595d08321ee1e224b29a1e006bc741b1d3a47ce5947d1eab339f1",
            representative_value(),
            "all behavior-bearing CORS fields",
            &[CorpusVariant::Canonical],
        ),
        accepted(
            UNKNOWN_TOP.to_vec(),
            "2cf2c8e727d1b27a3ba5086dc2d48288e85467636945993ba2a3a9f797812aad",
            minimal("GET", "*"),
            "old-readable unknown top-level element",
            &[CorpusVariant::UnknownTopLevel],
        ),
        accepted(
            UNKNOWN_ATTRIBUTES.to_vec(),
            "a3ce2be903f0059e260a7e5b5e779a98cf28c36a9b7b21f1e0fe81ff3e02736b",
            minimal("GET", "*"),
            "old-readable attributes at structural and scalar levels",
            &[CorpusVariant::UnknownAttribute],
        ),
        accepted(
            ALTERNATE_ORDER.to_vec(),
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
            &[CorpusVariant::AlternateOrder],
        ),
        accepted(
            large_xml.into_bytes(),
            "1432cdfad5109e34da045dd09eee473a75fc9cb6aa30d3ea3da7cbee0e98f2b5",
            minimal("GET", &large_origin),
            "persistence-sized origin is independent from HTTP header limits",
            &[CorpusVariant::LargeValue],
        ),
    ];
    cases.extend(crate::source_a_boundary::cors_cases());
    cases.extend(crate::source_a_new_writer::cors_cases());
    cases
}

fn rejected_cases() -> Vec<RejectedCorsCase> {
    vec![
        rejected(b"<CORSConfiguration><CORSRule><ID>a</ID><ID>b</ID></CORSRule></CORSConfiguration>", "b1125e5104486b5627f7df353ea19e6a8e90062f339e2b286638ec60fed5380e", "duplicate ID", &[CorpusVariant::DuplicateField]),
        rejected(b"<CORSConfiguration><CORSRule><MaxAgeSeconds>1</MaxAgeSeconds><MaxAgeSeconds>2</MaxAgeSeconds></CORSRule></CORSConfiguration>", "df206ae90549ee53761dd8e5c7aaf3b1b86fe922f2cb82af9b51f566e8aa71a8", "duplicate MaxAgeSeconds", &[CorpusVariant::DuplicateField]),
        rejected(EMPTY, "7f5354cf5478f637bb71cf452533e4195185d6899fcb84c81eabb3653c377c7e", "empty configuration", &[CorpusVariant::EmptyElement, CorpusVariant::MissingField]),
        rejected(EMPTY_RULE, "5535567aa7ed041583c8a7ce3c8d49851d8a9f54186df9edd836c42e8f9f98e6", "empty rule", &[CorpusVariant::EmptyElement, CorpusVariant::MissingField]),
        rejected(b"<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin></CORSRule></CORSConfiguration>", "05a9839e61114e41f4be6b5bd761808fc7ad851a2d1368a8c84683d8fc495c55", "missing method", &[CorpusVariant::MissingField]),
        rejected(b"<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>", "c3c8f934819878bf318b7857d612ec9be5db9a7bb2e48fb98f1e3cfc4a97a53e", "missing origin", &[CorpusVariant::MissingField]),
        rejected(UNKNOWN_NESTED, "14180bdeedd53c8f86d2379ed6c314938a05a8f9024e959906635f739c58233b", "unknown nested element", &[CorpusVariant::UnknownNested]),
        rejected(b"<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin><MaxAgeSeconds> 1 </MaxAgeSeconds></CORSRule></CORSConfiguration>", "148be55a075437919f16a0143c49d75f0282a6553b12eb755cd8b88de3488db9", "whitespace around max age", &[CorpusVariant::UnknownScalar]),
        rejected(b"<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin><MaxAgeSeconds>-2147483649</MaxAgeSeconds></CORSRule></CORSConfiguration>", "bcbc44e18f3915d3acab0a1383c3e3f544618563612fc712070ccb68f380bbe6", "max age below i32", &[CorpusVariant::UnknownScalar]),
        rejected(b"<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin><MaxAgeSeconds>2147483648</MaxAgeSeconds></CORSRule></CORSConfiguration>", "5212232714ae8a86e16b4452a3d5101ee8c132c4a5eb6db8e5d82285a43a95e8", "max age above i32", &[CorpusVariant::UnknownScalar]),
    ]
}

/// Builds CORS coverage from the same accepted and rejected cases used by the codec tests.
///
/// # Errors
///
/// Returns an error when a case has stale provenance or lacks a coverage classification.
pub(crate) fn corpus_evidence() -> Result<FamilyCorpusEvidence, CorpusCoverageError> {
    let mut cases = Vec::new();
    for (sample, variants) in accepted_cases() {
        cases.push(CorpusCaseEvidence::accepted(&sample, variants)?);
    }
    for (sample, variants) in rejected_cases() {
        cases.push(CorpusCaseEvidence::rejected(&sample, variants)?);
    }
    Ok(FamilyCorpusEvidence::new(
        ConfigKind::Cors,
        vec![
            CorpusVariant::Canonical,
            CorpusVariant::EmptyElement,
            CorpusVariant::MissingField,
            CorpusVariant::UnknownTopLevel,
            CorpusVariant::UnknownNested,
            CorpusVariant::UnknownAttribute,
            CorpusVariant::AlternateOrder,
            CorpusVariant::DuplicateField,
            CorpusVariant::UnknownScalar,
            CorpusVariant::LargeValue,
        ],
        cases,
    ))
}
const _: fn() -> Result<FamilyCorpusEvidence, CorpusCoverageError> = corpus_evidence;

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

pub(crate) fn run_cors_corpus_four_way() -> Result<usize, GoldenFailure> {
    let cases = accepted_cases();
    for (sample, _) in &cases {
        assert_cors_four_way(sample)?;
    }
    Ok(cases.len())
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
    use super::*;
    use crate::{Direction, build_corpus_report};

    fn sample() -> GoldenSample<PersistedCorsConfiguration> {
        accepted_cases()
            .into_iter()
            .find(|(_, variants)| variants.contains(&CorpusVariant::UnknownAttribute))
            .expect("CORS corpus has an unknown-attribute control")
            .0
    }

    #[test]
    fn cors_sample_matrix_passes_all_five_directions() {
        for (case, _) in accepted_cases() {
            assert_cors_four_way(&case).unwrap_or_else(|error| panic!("CORS {}: {error}", case.notes));
        }
    }

    #[test]
    fn source_b_boto3_cors_capture_is_registered() {
        let (sample, _) = accepted_cases()
            .into_iter()
            .find(|(sample, _)| sample.origin.producer.starts_with("boto3"))
            .expect("the live boto3 CORS capture is registered");
        assert_eq!(sample.origin.sha256, "be55a446cff4f490a1e978281abc85174eccab433bf7a0890d2ff198a474052a");
        assert_eq!(sample.bytes.len(), 447);
    }

    #[test]
    fn source_b_aws_cli_cors_capture_is_registered() {
        let (sample, _) = accepted_cases()
            .into_iter()
            .find(|(sample, _)| sample.origin.producer.starts_with("aws-cli"))
            .expect("the live aws-cli CORS capture is registered");
        assert_eq!(sample.origin.sha256, "47bacc6af5e2106e50ac20da793aede81416437e92df757f8a1682b315782da3");
        assert_eq!(sample.bytes.len(), 458);
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

        for (case, _) in rejected_cases()
            .into_iter()
            .filter(|(_, variants)| variants.contains(&CorpusVariant::DuplicateField))
        {
            assert!(CorsCodec.old_parse(&case.bytes).is_err(), "old parser accepted {}", case.notes);
            assert!(CorsCodec.new_parse(&case.bytes).is_err(), "new parser accepted {}", case.notes);
        }
    }

    #[test]
    fn exact_old_cors_serializer_order_is_pinned() {
        assert_eq!(
            CorsCodec
                .old_serialize(&representative_value())
                .expect("old serializer accepts full rule"),
            REPRESENTATIVE
        );
        assert_eq!(
            CorsCodec
                .new_serialize(&representative_value())
                .expect("new serializer is infallible"),
            REPRESENTATIVE
        );
    }

    #[test]
    fn missing_required_cors_lists_match_the_old_refusal_boundary() {
        for (case, _) in rejected_cases() {
            assert!(CorsCodec.old_parse(&case.bytes).is_err(), "old parser accepted {}", case.notes);
            assert!(CorsCodec.new_parse(&case.bytes).is_err(), "new parser accepted {}", case.notes);
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
            if self.d3 && bytes == CorsCodec.new_serialize(&sample().value)? {
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

    #[test]
    fn cors_report_is_derived_from_the_shared_concrete_cases() {
        let evidence = corpus_evidence().expect("CORS corpus evidence is traceable");
        let report =
            build_corpus_report(&[ConfigKind::Cors], &[evidence]).expect("CORS concrete cases satisfy the coverage contract");
        assert!(report.render().contains("cors: accepted=10 rejected=10"));
    }
}
