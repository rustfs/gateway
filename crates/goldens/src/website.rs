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
use rustfs_gateway_types::persistence::{PersistedWebsiteConfiguration, parse_website, serialize_website};

use crate::{ConfigKind, FourWayCodec, GoldenFailure, GoldenSample, assert_four_way};

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
    use crate::{Direction, SampleOrigin};
    use rustfs_gateway_types::persistence::{
        PersistedErrorDocument, PersistedIndexDocument, PersistedRedirect, PersistedRedirectAllRequestsTo, PersistedRoutingRule,
        PersistedRoutingRuleCondition,
    };
    use sha2::{Digest, Sha256};

    const EMPTY: &[u8] = b"<WebsiteConfiguration></WebsiteConfiguration>";
    const ERROR: &[u8] = b"<WebsiteConfiguration><ErrorDocument><Key>error.html</Key></ErrorDocument></WebsiteConfiguration>";
    const INDEX: &[u8] =
        b"<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument></WebsiteConfiguration>";
    const REDIRECT_ALL: &[u8] = b"<WebsiteConfiguration><RedirectAllRequestsTo><HostName>example.test</HostName><Protocol>https</Protocol></RedirectAllRequestsTo></WebsiteConfiguration>";
    const EMPTY_REDIRECT_RULE: &[u8] = b"<WebsiteConfiguration><RoutingRules><RoutingRule><Redirect></Redirect></RoutingRule></RoutingRules></WebsiteConfiguration>";
    const FULL_RULE: &[u8] = b"<WebsiteConfiguration><RoutingRules><RoutingRule><Condition><HttpErrorCodeReturnedEquals>404</HttpErrorCodeReturnedEquals><KeyPrefixEquals>docs/</KeyPrefixEquals></Condition><Redirect><HostName>docs.example.test</HostName><HttpRedirectCode>302</HttpRedirectCode><Protocol>https</Protocol><ReplaceKeyPrefixWith>manual/</ReplaceKeyPrefixWith><ReplaceKeyWith>index.html</ReplaceKeyWith></Redirect></RoutingRule></RoutingRules></WebsiteConfiguration>";
    const NAMESPACE: &[u8] = br#"<WebsiteConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><IndexDocument><Suffix>index.html</Suffix></IndexDocument></WebsiteConfiguration>"#;
    const UNKNOWN_TOP: &[u8] = b"<WebsiteConfiguration><FutureTopLevel>future</FutureTopLevel><IndexDocument><Suffix>index.html</Suffix></IndexDocument></WebsiteConfiguration>";
    const ALTERNATE_ORDER: &[u8] = b"<WebsiteConfiguration><RedirectAllRequestsTo><Protocol>http</Protocol><HostName>example.test</HostName></RedirectAllRequestsTo><IndexDocument><Suffix>home.html</Suffix></IndexDocument><ErrorDocument><Key>error.html</Key></ErrorDocument></WebsiteConfiguration>";
    const EMPTY_ROUTING_RULES: &[u8] = b"<WebsiteConfiguration><RoutingRules></RoutingRules></WebsiteConfiguration>";

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

    fn sample(
        bytes: &[u8],
        sha256: &str,
        value: PersistedWebsiteConfiguration,
        notes: &str,
    ) -> GoldenSample<PersistedWebsiteConfiguration> {
        assert_eq!(hex::encode(Sha256::digest(bytes)), sha256, "stale Website sample digest");
        GoldenSample {
            kind: ConfigKind::Website,
            bytes: bytes.to_vec(),
            value,
            origin: SampleOrigin {
                source: "P9 Website persistence matrix".to_owned(),
                producer: "pinned s3s XML behavior".to_owned(),
                version: "s3s@9c4690d8e73fc8d184031a19b2c4539ebc77d180".to_owned(),
                sha256: sha256.to_owned(),
            },
            notes: notes.to_owned(),
        }
    }

    fn index_value(suffix: &str) -> PersistedWebsiteConfiguration {
        PersistedWebsiteConfiguration {
            index_document: Some(PersistedIndexDocument {
                suffix: suffix.to_owned(),
            }),
            ..PersistedWebsiteConfiguration::default()
        }
    }

    fn base_sample() -> GoldenSample<PersistedWebsiteConfiguration> {
        sample(
            NAMESPACE,
            "740d79d00f8c04c133f6dcdbbe98cb43ad9430438a2a077981940da18bb8237f",
            index_value("index.html"),
            "old-readable default namespace",
        )
    }

    #[test]
    fn website_sample_matrix_passes_all_five_directions() {
        let cases = [
            sample(
                EMPTY,
                "08b83bc276606aa2ce48152256014689d10181375cbdfaad0adb8aa2d3a02fc9",
                PersistedWebsiteConfiguration::default(),
                "empty configuration",
            ),
            sample(
                ERROR,
                "33a488308b39de725e2274042a5c4f152fc4e5b63b15f656e5005ead636d8ea5",
                PersistedWebsiteConfiguration {
                    error_document: Some(PersistedErrorDocument {
                        key: "error.html".to_owned(),
                    }),
                    ..PersistedWebsiteConfiguration::default()
                },
                "error document",
            ),
            sample(
                INDEX,
                "c7283582d3321a1fa6eb591309d757db781f74f811fc7410f5ca1afde1497e86",
                index_value("index.html"),
                "index document",
            ),
            sample(
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
            ),
            sample(
                EMPTY_REDIRECT_RULE,
                "9456261036f998e1ef499dc7ea8f2a890ed67e01c25d579bb77dcb41e33f4eb5",
                PersistedWebsiteConfiguration {
                    routing_rules: Some(vec![PersistedRoutingRule::default()]),
                    ..PersistedWebsiteConfiguration::default()
                },
                "required empty Redirect wrapper",
            ),
            sample(
                FULL_RULE,
                "7b0ae91924784feb263c96490c5bdfb4003a8aed1ff19fecb77b063a2f29d303",
                PersistedWebsiteConfiguration {
                    routing_rules: Some(vec![full_rule()]),
                    ..PersistedWebsiteConfiguration::default()
                },
                "every routing decision",
            ),
            base_sample(),
            sample(
                UNKNOWN_TOP,
                "af3912c6a2db65fe2cae9329966eb0290cbfc861481f43bd52c8eee8c06bdc62",
                index_value("index.html"),
                "unknown root child",
            ),
            sample(
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
            ),
            sample(
                EMPTY_ROUTING_RULES,
                "f5df1db8cad93376e44efee5d858550e4b737fbd1580e7bcd9760b4f4f0decfe",
                PersistedWebsiteConfiguration {
                    routing_rules: Some(Vec::new()),
                    ..PersistedWebsiteConfiguration::default()
                },
                "present empty routing list",
            ),
        ];
        for case in cases {
            if let Err(error) = assert_website_four_way(&case) {
                panic!("Website sample failed ({}): {error}", case.notes);
            }
        }
    }

    #[test]
    fn n_required_website_members_match_the_old_refusals() {
        for (name, bytes) in [
            (
                "ErrorDocument.Key",
                b"<WebsiteConfiguration><ErrorDocument></ErrorDocument></WebsiteConfiguration>".as_slice(),
            ),
            (
                "IndexDocument.Suffix",
                b"<WebsiteConfiguration><IndexDocument></IndexDocument></WebsiteConfiguration>".as_slice(),
            ),
            (
                "RedirectAllRequestsTo.HostName",
                b"<WebsiteConfiguration><RedirectAllRequestsTo></RedirectAllRequestsTo></WebsiteConfiguration>".as_slice(),
            ),
            (
                "RoutingRule.Redirect",
                b"<WebsiteConfiguration><RoutingRules><RoutingRule></RoutingRule></RoutingRules></WebsiteConfiguration>"
                    .as_slice(),
            ),
        ] {
            assert!(WebsiteCodec.old_parse(bytes).is_err(), "old accepted missing {name}");
            assert!(WebsiteCodec.new_parse(bytes).is_err(), "new accepted missing {name}");
        }
    }

    #[test]
    fn n_nested_unknown_website_content_matches_the_old_boundary() {
        let cases = [
            ("error", b"<WebsiteConfiguration><ErrorDocument><Future>x</Future><Key>e</Key></ErrorDocument></WebsiteConfiguration>".as_slice()),
            ("index", b"<WebsiteConfiguration><IndexDocument><Future>x</Future><Suffix>i</Suffix></IndexDocument></WebsiteConfiguration>".as_slice()),
            ("redirect-all", b"<WebsiteConfiguration><RedirectAllRequestsTo><Future>x</Future><HostName>h</HostName></RedirectAllRequestsTo></WebsiteConfiguration>".as_slice()),
            ("rule", b"<WebsiteConfiguration><RoutingRules><RoutingRule><Future>x</Future><Redirect></Redirect></RoutingRule></RoutingRules></WebsiteConfiguration>".as_slice()),
            ("condition", b"<WebsiteConfiguration><RoutingRules><RoutingRule><Condition><Future>x</Future></Condition><Redirect></Redirect></RoutingRule></RoutingRules></WebsiteConfiguration>".as_slice()),
            ("redirect", b"<WebsiteConfiguration><RoutingRules><RoutingRule><Redirect><Future>x</Future></Redirect></RoutingRule></RoutingRules></WebsiteConfiguration>".as_slice()),
        ];
        for (name, bytes) in cases {
            assert!(WebsiteCodec.old_parse(bytes).is_err(), "old accepted nested unknown in {name}");
            assert!(WebsiteCodec.new_parse(bytes).is_err(), "new accepted nested unknown in {name}");
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
        let cases = [
            b"<WebsiteConfiguration><ErrorDocument><Key>a</Key></ErrorDocument><ErrorDocument><Key>b</Key></ErrorDocument></WebsiteConfiguration>".as_slice(),
            b"<WebsiteConfiguration><IndexDocument><Suffix>a</Suffix><Suffix>b</Suffix></IndexDocument></WebsiteConfiguration>".as_slice(),
            b"<WebsiteConfiguration><RedirectAllRequestsTo><HostName>a</HostName><HostName>b</HostName></RedirectAllRequestsTo></WebsiteConfiguration>".as_slice(),
            b"<WebsiteConfiguration><RoutingRules></RoutingRules><RoutingRules></RoutingRules></WebsiteConfiguration>".as_slice(),
            b"<WebsiteConfiguration><RoutingRules><RoutingRule><Redirect><Protocol>http</Protocol><Protocol>https</Protocol></Redirect></RoutingRule></RoutingRules></WebsiteConfiguration>".as_slice(),
            b"<WebsiteConfiguration><RoutingRules><RoutingRule><Redirect><ReplaceKeyWith>a</ReplaceKeyWith><ReplaceKeyWith>b</ReplaceKeyWith></Redirect></RoutingRule></RoutingRules></WebsiteConfiguration>".as_slice(),
        ];
        for bytes in cases {
            assert!(WebsiteCodec.old_parse(bytes).is_err());
            assert!(WebsiteCodec.new_parse(bytes).is_err());
        }
    }

    #[test]
    fn n_wrong_website_root_is_rejected() {
        let bytes = b"<BucketLoggingStatus></BucketLoggingStatus>";
        assert!(WebsiteCodec.old_parse(bytes).is_err());
        assert!(WebsiteCodec.new_parse(bytes).is_err());
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
}
