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

//! Bucket Website persistence compatibility evidence.
//!
//! Responsible for: exercising independent old and new Website persistence codecs through D1-D5.
//! NOT responsible for: serving website requests or HTTP validation. Upstream: pinned-s3s
//! observations and gateway persistence codecs. Downstream: migration gates.

use rustfs_gateway_types::compat::{S3sWebsiteObservation, parse_s3s_website, serialize_s3s_website};
use rustfs_gateway_types::persistence::{
    PersistedErrorDocument, PersistedIndexDocument, PersistedRedirect, PersistedRedirectAllRequestsTo, PersistedRoutingRule,
    PersistedRoutingRuleCondition, PersistedWebsiteConfiguration, parse_website, serialize_website,
};

use crate::{
    ConfigKind, CorpusCaseEvidence, CorpusCoverageError, CorpusVariant, FamilyCorpusEvidence, FourWayCodec, GoldenFailure,
    GoldenSample, RejectedGoldenSample, SampleOrigin, assert_four_way,
};

const EMPTY: &[u8] = b"<WebsiteConfiguration></WebsiteConfiguration>";
const ERROR: &[u8] = b"<WebsiteConfiguration><ErrorDocument><Key>error.html</Key></ErrorDocument></WebsiteConfiguration>";
const INDEX: &[u8] = b"<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument></WebsiteConfiguration>";
const REDIRECT_ALL: &[u8] = b"<WebsiteConfiguration><RedirectAllRequestsTo><HostName>example.test</HostName><Protocol>https</Protocol></RedirectAllRequestsTo></WebsiteConfiguration>";
const EMPTY_REDIRECT_RULE: &[u8] =
    b"<WebsiteConfiguration><RoutingRules><RoutingRule><Redirect></Redirect></RoutingRule></RoutingRules></WebsiteConfiguration>";
const FULL_RULE: &[u8] = b"<WebsiteConfiguration><RoutingRules><RoutingRule><Condition><HttpErrorCodeReturnedEquals>404</HttpErrorCodeReturnedEquals><KeyPrefixEquals>docs/</KeyPrefixEquals></Condition><Redirect><HostName>docs.example.test</HostName><HttpRedirectCode>302</HttpRedirectCode><Protocol>https</Protocol><ReplaceKeyPrefixWith>manual/</ReplaceKeyPrefixWith><ReplaceKeyWith>index.html</ReplaceKeyWith></Redirect></RoutingRule></RoutingRules></WebsiteConfiguration>";
const NAMESPACE: &[u8] = br#"<WebsiteConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><IndexDocument><Suffix>index.html</Suffix></IndexDocument></WebsiteConfiguration>"#;
const UNKNOWN_TOP: &[u8] = b"<WebsiteConfiguration><FutureTopLevel>future</FutureTopLevel><IndexDocument><Suffix>index.html</Suffix></IndexDocument></WebsiteConfiguration>";
const ALTERNATE_ORDER: &[u8] = b"<WebsiteConfiguration><RedirectAllRequestsTo><Protocol>http</Protocol><HostName>example.test</HostName></RedirectAllRequestsTo><IndexDocument><Suffix>home.html</Suffix></IndexDocument><ErrorDocument><Key>error.html</Key></ErrorDocument></WebsiteConfiguration>";
const EMPTY_ROUTING_RULES: &[u8] = b"<WebsiteConfiguration><RoutingRules></RoutingRules></WebsiteConfiguration>";

type AcceptedWebsiteCase = (GoldenSample<PersistedWebsiteConfiguration>, &'static [CorpusVariant]);
type RejectedWebsiteCase = (RejectedGoldenSample, &'static [CorpusVariant]);

fn full_rule() -> PersistedRoutingRule {
    PersistedRoutingRule {
        condition: Some(PersistedRoutingRuleCondition {
            http_error_code_returned_equals: Some("404".to_owned()),
            key_prefix_equals: Some("docs/".to_owned()),
        }),
        redirect: PersistedRedirect {
            host_name: Some("docs.example.test".to_owned()),
            http_redirect_code: Some("302".to_owned()),
            protocol: Some("https".to_owned()),
            replace_key_prefix_with: Some("manual/".to_owned()),
            replace_key_with: Some("index.html".to_owned()),
        },
    }
}

fn origin(sha256: &str) -> SampleOrigin {
    SampleOrigin {
        source: "P9 Website persistence matrix".to_owned(),
        producer: "pinned s3s XML behavior".to_owned(),
        version: "s3s@9c4690d8e73fc8d184031a19b2c4539ebc77d180".to_owned(),
        sha256: sha256.to_owned(),
    }
}

fn accepted(
    bytes: &[u8],
    sha256: &str,
    value: PersistedWebsiteConfiguration,
    notes: &str,
    variants: &'static [CorpusVariant],
) -> AcceptedWebsiteCase {
    (
        GoldenSample {
            kind: ConfigKind::Website,
            bytes: bytes.to_vec(),
            value,
            origin: origin(sha256),
            notes: notes.to_owned(),
        },
        variants,
    )
}

fn rejected(bytes: &[u8], sha256: &str, notes: &str, variants: &'static [CorpusVariant]) -> RejectedWebsiteCase {
    (
        RejectedGoldenSample {
            kind: ConfigKind::Website,
            bytes: bytes.to_vec(),
            origin: origin(sha256),
            notes: notes.to_owned(),
        },
        variants,
    )
}

fn index_value(suffix: &str) -> PersistedWebsiteConfiguration {
    PersistedWebsiteConfiguration {
        index_document: Some(PersistedIndexDocument {
            suffix: suffix.to_owned(),
        }),
        ..PersistedWebsiteConfiguration::default()
    }
}

fn namespace_case() -> AcceptedWebsiteCase {
    accepted(
        NAMESPACE,
        "740d79d00f8c04c133f6dcdbbe98cb43ad9430438a2a077981940da18bb8237f",
        index_value("index.html"),
        "old-readable default namespace",
        &[CorpusVariant::Namespace],
    )
}

fn accepted_cases() -> Vec<AcceptedWebsiteCase> {
    vec![
        accepted(
            EMPTY,
            "08b83bc276606aa2ce48152256014689d10181375cbdfaad0adb8aa2d3a02fc9",
            PersistedWebsiteConfiguration::default(),
            "empty configuration",
            &[CorpusVariant::EmptyElement],
        ),
        accepted(
            ERROR,
            "33a488308b39de725e2274042a5c4f152fc4e5b63b15f656e5005ead636d8ea5",
            PersistedWebsiteConfiguration {
                error_document: Some(PersistedErrorDocument {
                    key: "error.html".to_owned(),
                }),
                ..PersistedWebsiteConfiguration::default()
            },
            "error document",
            &[CorpusVariant::Canonical],
        ),
        accepted(
            INDEX,
            "c7283582d3321a1fa6eb591309d757db781f74f811fc7410f5ca1afde1497e86",
            index_value("index.html"),
            "index document",
            &[CorpusVariant::Canonical],
        ),
        accepted(
            REDIRECT_ALL,
            "c35649eb06d917f777d4babb36b21dab6c833be4480974e7a2d2800bfc4b215e",
            PersistedWebsiteConfiguration {
                redirect_all_requests_to: Some(PersistedRedirectAllRequestsTo {
                    host_name: "example.test".to_owned(),
                    protocol: Some("https".to_owned()),
                }),
                ..PersistedWebsiteConfiguration::default()
            },
            "unconditional redirect",
            &[CorpusVariant::Canonical],
        ),
        accepted(
            EMPTY_REDIRECT_RULE,
            "9456261036f998e1ef499dc7ea8f2a890ed67e01c25d579bb77dcb41e33f4eb5",
            PersistedWebsiteConfiguration {
                routing_rules: Some(vec![PersistedRoutingRule::default()]),
                ..PersistedWebsiteConfiguration::default()
            },
            "required empty Redirect wrapper",
            &[CorpusVariant::EmptyElement],
        ),
        accepted(
            FULL_RULE,
            "7b0ae91924784feb263c96490c5bdfb4003a8aed1ff19fecb77b063a2f29d303",
            PersistedWebsiteConfiguration {
                routing_rules: Some(vec![full_rule()]),
                ..PersistedWebsiteConfiguration::default()
            },
            "every routing decision",
            &[CorpusVariant::Canonical],
        ),
        namespace_case(),
        accepted(
            UNKNOWN_TOP,
            "af3912c6a2db65fe2cae9329966eb0290cbfc861481f43bd52c8eee8c06bdc62",
            index_value("index.html"),
            "unknown root child",
            &[CorpusVariant::UnknownTopLevel],
        ),
        accepted(
            ALTERNATE_ORDER,
            "26f0c125e38a83b520958c1452faa2e8b01e695ffc45ee669eadeee0b7b93dc6",
            PersistedWebsiteConfiguration {
                error_document: Some(PersistedErrorDocument {
                    key: "error.html".to_owned(),
                }),
                index_document: Some(PersistedIndexDocument {
                    suffix: "home.html".to_owned(),
                }),
                redirect_all_requests_to: Some(PersistedRedirectAllRequestsTo {
                    host_name: "example.test".to_owned(),
                    protocol: Some("http".to_owned()),
                }),
                routing_rules: None,
            },
            "noncanonical field order",
            &[CorpusVariant::AlternateOrder],
        ),
        accepted(
            EMPTY_ROUTING_RULES,
            "f5df1db8cad93376e44efee5d858550e4b737fbd1580e7bcd9760b4f4f0decfe",
            PersistedWebsiteConfiguration {
                routing_rules: Some(Vec::new()),
                ..PersistedWebsiteConfiguration::default()
            },
            "present empty routing list",
            &[CorpusVariant::EmptyElement],
        ),
    ]
}

fn rejected_cases() -> Vec<RejectedWebsiteCase> {
    vec![
        rejected(b"<WebsiteConfiguration><ErrorDocument></ErrorDocument></WebsiteConfiguration>", "89098f4fb5e6c644b905bc6af4f3489131cad7f356407228a46291ca518f7fea", "missing ErrorDocument.Key", &[CorpusVariant::MissingField]),
        rejected(b"<WebsiteConfiguration><IndexDocument></IndexDocument></WebsiteConfiguration>", "b8bdd390e9837d27cbcca32a88f649a7747dd91c7f512ea0a3be7db9c0c9f5a9", "missing IndexDocument.Suffix", &[CorpusVariant::MissingField]),
        rejected(b"<WebsiteConfiguration><RedirectAllRequestsTo></RedirectAllRequestsTo></WebsiteConfiguration>", "a2dbe5efae571a0d3df7e30c1831e33706a8f5c55cd591e672c06ac8d80e3662", "missing RedirectAllRequestsTo.HostName", &[CorpusVariant::MissingField]),
        rejected(b"<WebsiteConfiguration><RoutingRules><RoutingRule></RoutingRule></RoutingRules></WebsiteConfiguration>", "700264451d8eba58a599318a657a6bf6e16f5d307fc4e235b1a0872672776786", "missing RoutingRule.Redirect", &[CorpusVariant::MissingField]),
        rejected(b"<WebsiteConfiguration><ErrorDocument><Future>x</Future><Key>e</Key></ErrorDocument></WebsiteConfiguration>", "f7f879ead3c0b63c0c4adc12915d6291ca0edfd55f5e8d3e783fd5c70590c951", "unknown nested ErrorDocument child", &[CorpusVariant::UnknownNested]),
        rejected(b"<WebsiteConfiguration><IndexDocument><Future>x</Future><Suffix>i</Suffix></IndexDocument></WebsiteConfiguration>", "e02bb7fc7606f012c34f1909b9467c93693b5d10ef784d819b6773928b5dc480", "unknown nested IndexDocument child", &[CorpusVariant::UnknownNested]),
        rejected(b"<WebsiteConfiguration><RedirectAllRequestsTo><Future>x</Future><HostName>h</HostName></RedirectAllRequestsTo></WebsiteConfiguration>", "853acbde269580d177afe02109592fbf6c0c03882868fc9aebf57b2dea96c2c8", "unknown nested RedirectAllRequestsTo child", &[CorpusVariant::UnknownNested]),
        rejected(b"<WebsiteConfiguration><RoutingRules><RoutingRule><Future>x</Future><Redirect></Redirect></RoutingRule></RoutingRules></WebsiteConfiguration>", "a517f490c1bdc559dd5488e287de912596287d8ceb416d12df80d3a0f442839b", "unknown nested RoutingRule child", &[CorpusVariant::UnknownNested]),
        rejected(b"<WebsiteConfiguration><RoutingRules><RoutingRule><Condition><Future>x</Future></Condition><Redirect></Redirect></RoutingRule></RoutingRules></WebsiteConfiguration>", "c71910d565661424936b0154a5fb6033eca1e90dccb9a3a223a5f2376fa24bac", "unknown nested Condition child", &[CorpusVariant::UnknownNested]),
        rejected(b"<WebsiteConfiguration><RoutingRules><RoutingRule><Redirect><Future>x</Future></Redirect></RoutingRule></RoutingRules></WebsiteConfiguration>", "baa72824806b57af4b593d72ad70ec9349f7bcd9184bd4480772a4f3c9c1567c", "unknown nested Redirect child", &[CorpusVariant::UnknownNested]),
        rejected(b"<WebsiteConfiguration><ErrorDocument><Key>a</Key></ErrorDocument><ErrorDocument><Key>b</Key></ErrorDocument></WebsiteConfiguration>", "9e71a591a576f1063235ca339450adc3c9fdf6a884f7b110834fadf81947de92", "duplicate ErrorDocument", &[CorpusVariant::DuplicateField]),
        rejected(b"<WebsiteConfiguration><IndexDocument><Suffix>a</Suffix><Suffix>b</Suffix></IndexDocument></WebsiteConfiguration>", "3f1780fe7cf74662798bbe4ac4cfc195aa34d42f7f7d99008438227165aab1e2", "duplicate IndexDocument.Suffix", &[CorpusVariant::DuplicateField]),
        rejected(b"<WebsiteConfiguration><RedirectAllRequestsTo><HostName>a</HostName><HostName>b</HostName></RedirectAllRequestsTo></WebsiteConfiguration>", "e5d431ccfa185e3374cb3e26d0ddf7912e6bd2dbcad3220d09706ceb33b91afa", "duplicate RedirectAllRequestsTo.HostName", &[CorpusVariant::DuplicateField]),
        rejected(b"<WebsiteConfiguration><RoutingRules></RoutingRules><RoutingRules></RoutingRules></WebsiteConfiguration>", "7a01523d8a70307cf04259e25fdf20ba0a73f43bde727ca29150d20528e761fa", "duplicate RoutingRules", &[CorpusVariant::DuplicateField]),
        rejected(b"<WebsiteConfiguration><RoutingRules><RoutingRule><Redirect><Protocol>http</Protocol><Protocol>https</Protocol></Redirect></RoutingRule></RoutingRules></WebsiteConfiguration>", "a270079d5195822c5eb31ad466c074f6c87cb5fc5aa2ab5af819ab09d6e74d7e", "duplicate Redirect.Protocol", &[CorpusVariant::DuplicateField]),
        rejected(b"<WebsiteConfiguration><RoutingRules><RoutingRule><Redirect><ReplaceKeyWith>a</ReplaceKeyWith><ReplaceKeyWith>b</ReplaceKeyWith></Redirect></RoutingRule></RoutingRules></WebsiteConfiguration>", "8297d404f87564f67274bf2bf3b523dd4774d55b38fa708cd3b338df20439d30", "duplicate Redirect.ReplaceKeyWith", &[CorpusVariant::DuplicateField]),
        rejected(b"<BucketLoggingStatus></BucketLoggingStatus>", "793250b29f13f41065355f5dbacde7476e500a047882380079067dcc543dfde7", "wrong Website root", &[CorpusVariant::MissingField]),
    ]
}

/// Builds Website corpus coverage from the exact cases used by codec tests.
///
/// # Errors
///
/// Returns an error when provenance is stale or a concrete case lacks a variant.
pub(crate) fn website_corpus_evidence() -> Result<FamilyCorpusEvidence, CorpusCoverageError> {
    let mut cases = Vec::new();
    for (sample, variants) in accepted_cases() {
        cases.push(CorpusCaseEvidence::accepted(&sample, variants)?);
    }
    for (sample, variants) in rejected_cases() {
        cases.push(CorpusCaseEvidence::rejected(&sample, variants)?);
    }
    Ok(FamilyCorpusEvidence::new(
        ConfigKind::Website,
        vec![
            CorpusVariant::Canonical,
            CorpusVariant::EmptyElement,
            CorpusVariant::MissingField,
            CorpusVariant::UnknownTopLevel,
            CorpusVariant::UnknownNested,
            CorpusVariant::Namespace,
            CorpusVariant::AlternateOrder,
            CorpusVariant::DuplicateField,
        ],
        cases,
    ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WebsiteBehaviorProjection(PersistedWebsiteConfiguration);

/// Runs pinned-s3s versus gateway Website persistence evidence.
///
/// # Errors
///
/// Returns invalid-provenance or the first D1-D5 failure.
pub fn assert_website_four_way(sample: &GoldenSample<PersistedWebsiteConfiguration>) -> Result<(), GoldenFailure> {
    assert_four_way(&WebsiteCodec, sample)
}

#[derive(Clone, Copy, Debug)]
struct WebsiteCodec;

impl FourWayCodec for WebsiteCodec {
    const KIND: ConfigKind = ConfigKind::Website;
    type Value = PersistedWebsiteConfiguration;
    type OldParsed = S3sWebsiteObservation;
    type NewParsed = PersistedWebsiteConfiguration;
    type Structure = PersistedWebsiteConfiguration;
    type Behavior = WebsiteBehaviorProjection;

    fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
        parse_s3s_website(bytes).map_err(|e| e.to_string())
    }
    fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
        parse_website(bytes).map_err(|e| e.to_string())
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
        serialize_s3s_website(value).map_err(|e| e.to_string())
    }
    fn new_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
        Ok(serialize_website(value))
    }
    fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior {
        WebsiteBehaviorProjection(value.behavior.clone())
    }
    fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior {
        WebsiteBehaviorProjection(value.routing_behavior())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Direction;

    fn base_sample() -> GoldenSample<PersistedWebsiteConfiguration> {
        namespace_case().0
    }

    #[test]
    fn website_sample_matrix_passes_all_five_directions() {
        for (case, _) in accepted_cases() {
            if let Err(error) = assert_website_four_way(&case) {
                panic!("Website sample failed ({}): {error}", case.notes);
            }
        }
    }

    #[test]
    fn n_required_website_members_match_the_old_refusals() {
        for (case, _) in rejected_cases()
            .into_iter()
            .filter(|(case, variants)| variants.contains(&CorpusVariant::MissingField) && case.notes != "wrong Website root")
        {
            assert!(WebsiteCodec.old_parse(&case.bytes).is_err(), "old accepted {}", case.notes);
            assert!(WebsiteCodec.new_parse(&case.bytes).is_err(), "new accepted {}", case.notes);
        }
    }

    #[test]
    fn n_nested_unknown_website_content_matches_the_old_boundary() {
        for (case, _) in rejected_cases()
            .into_iter()
            .filter(|(_, variants)| variants.contains(&CorpusVariant::UnknownNested))
        {
            assert!(WebsiteCodec.old_parse(&case.bytes).is_err(), "old accepted {}", case.notes);
            assert!(WebsiteCodec.new_parse(&case.bytes).is_err(), "new accepted {}", case.notes);
        }
    }

    #[test]
    fn unknown_content_in_the_routing_list_wrapper_stays_old_readable() {
        let bytes = b"<WebsiteConfiguration><RoutingRules><Future>x</Future></RoutingRules></WebsiteConfiguration>";
        assert!(WebsiteCodec.old_parse(bytes).is_ok());
        assert!(WebsiteCodec.new_parse(bytes).is_ok());
    }

    #[test]
    fn n_duplicate_website_wrappers_and_scalars_are_rejected() {
        for (case, _) in rejected_cases()
            .into_iter()
            .filter(|(_, variants)| variants.contains(&CorpusVariant::DuplicateField))
        {
            assert!(WebsiteCodec.old_parse(&case.bytes).is_err());
            assert!(WebsiteCodec.new_parse(&case.bytes).is_err());
        }
    }

    #[test]
    fn n_wrong_website_root_is_rejected() {
        let (case, _) = rejected_cases()
            .into_iter()
            .find(|(case, _)| case.notes == "wrong Website root")
            .expect("the shared refusal corpus contains the wrong-root case");
        assert!(WebsiteCodec.old_parse(&case.bytes).is_err());
        assert!(WebsiteCodec.new_parse(&case.bytes).is_err());
    }

    struct Mutant {
        old_byte_drift: bool,
        reject_new_output_in_old: bool,
        reject_historical_in_new: bool,
        new_structure_drift: bool,
        new_behavior_drift: bool,
        panic_on_old_parse: bool,
    }

    impl FourWayCodec for Mutant {
        const KIND: ConfigKind = ConfigKind::Website;
        type Value = PersistedWebsiteConfiguration;
        type OldParsed = S3sWebsiteObservation;
        type NewParsed = PersistedWebsiteConfiguration;
        type Structure = PersistedWebsiteConfiguration;
        type Behavior = WebsiteBehaviorProjection;
        fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
            assert!(!self.panic_on_old_parse, "Website observation must not run");
            if self.reject_new_output_in_old && bytes == INDEX {
                return Err("mutation: rollback refusal".to_owned());
            }
            WebsiteCodec.old_parse(bytes)
        }
        fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
            if self.reject_historical_in_new && bytes == NAMESPACE {
                return Err("mutation: stricter parser".to_owned());
            }
            let mut parsed = WebsiteCodec.new_parse(bytes)?;
            if self.new_structure_drift {
                parsed.index_document = None;
            }
            Ok(parsed)
        }
        fn old_structure(&self, v: &Self::OldParsed) -> Self::Structure {
            WebsiteCodec.old_structure(v)
        }
        fn new_structure(&self, v: &Self::NewParsed) -> Self::Structure {
            WebsiteCodec.new_structure(v)
        }
        fn expected_structure(&self, v: &Self::Value) -> Self::Structure {
            WebsiteCodec.expected_structure(v)
        }
        fn old_serialize(&self, v: &Self::Value) -> Result<Vec<u8>, String> {
            let mut b = WebsiteCodec.old_serialize(v)?;
            if self.old_byte_drift {
                b.push(b' ');
            }
            Ok(b)
        }
        fn new_serialize(&self, v: &Self::Value) -> Result<Vec<u8>, String> {
            WebsiteCodec.new_serialize(v)
        }
        fn old_behavior(&self, v: &Self::OldParsed) -> Self::Behavior {
            WebsiteCodec.old_behavior(v)
        }
        fn new_behavior(&self, v: &Self::NewParsed) -> Self::Behavior {
            let mut b = WebsiteCodec.new_behavior(v);
            if self.new_behavior_drift {
                b.0.error_document = Some(PersistedErrorDocument {
                    key: "mutation".to_owned(),
                });
            }
            b
        }
    }

    fn mutant() -> Mutant {
        Mutant {
            old_byte_drift: false,
            reject_new_output_in_old: false,
            reject_historical_in_new: false,
            new_structure_drift: false,
            new_behavior_drift: false,
            panic_on_old_parse: false,
        }
    }

    #[test]
    fn n_each_d1_d5_website_mutant_is_killed() {
        let mut cases = Vec::new();
        let mut d1 = mutant();
        d1.new_structure_drift = true;
        cases.push(("D1", d1, Direction::D1CompatibleRead));
        let mut d2 = mutant();
        d2.old_byte_drift = true;
        cases.push(("D2", d2, Direction::D2ByteWrite));
        let mut d3 = mutant();
        d3.reject_new_output_in_old = true;
        cases.push(("D3", d3, Direction::D3RollbackRead));
        let mut d4 = mutant();
        d4.reject_historical_in_new = true;
        cases.push(("D4", d4, Direction::D4NotStricter));
        let mut d5 = mutant();
        d5.new_behavior_drift = true;
        cases.push(("D5", d5, Direction::D5Behavior));
        for (name, codec, expected) in cases {
            let failure = match assert_four_way(&codec, &base_sample()) {
                Err(failure) => failure,
                Ok(()) => panic!("{name} Website mutant must be killed"),
            };
            assert_eq!(failure.direction, expected);
        }
    }

    #[test]
    fn n_wrong_family_label_fails_before_website_observation() {
        let mut invalid = base_sample();
        invalid.kind = ConfigKind::Logging;
        let mut codec = mutant();
        codec.panic_on_old_parse = true;
        let failure = assert_four_way(&codec, &invalid).expect_err("mislabeled Website sample must fail closed");
        assert_eq!(failure.direction, Direction::Input);
    }

    #[test]
    fn website_provider_report_is_derived_from_shared_concrete_cases() {
        let evidence = website_corpus_evidence().expect("Website corpus evidence is traceable");
        let report = crate::build_corpus_report(&[ConfigKind::Website], &[evidence])
            .expect("Website concrete cases satisfy the coverage contract");
        assert!(report.render().contains("website: accepted=10 rejected=17"));
    }
}
