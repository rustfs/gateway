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

//! Real-reader comparison for the RustFS 5761 persistence contract.
//!
//! Responsible for: comparing legacy and Gateway persistence reader results on stored XML.
//! NOT responsible for: request-body policy or serialization compatibility.
//! Upstream: the pinned RustFS s3s oracle and Gateway readers. Downstream: persistence migration regressions.
#![cfg(feature = "compat-s3s-rustfs")]

use s3s_rustfs::xml::{Deserialize, Deserializer};

fn read_old(input: &[u8]) -> Result<Option<String>, String> {
    let mut reader = Deserializer::new(input);
    let value = s3s_rustfs::dto::AccelerateConfiguration::deserialize(&mut reader).map_err(|error| format!("{error:?}"))?;
    reader.expect_eof().map_err(|error| format!("{error:?}"))?;
    Ok(value.status.map(|status| status.as_str().to_owned()))
}

#[test]
fn acceleration_reader_matches_explicit_rustfs_5761_text_contract() {
    let inputs: [(&str, &[u8]); 6] = [
        (
            "CDATA_STATUS",
            b"<AccelerateConfiguration><Status><![CDATA[Enabled]]></Status></AccelerateConfiguration>",
        ),
        (
            "MIXED_CDATA_STATUS",
            b"<AccelerateConfiguration><Status>Before<![CDATA[Middle]]>After</Status></AccelerateConfiguration>",
        ),
        (
            "RAW_CRLF_STATUS",
            b"<AccelerateConfiguration><Status>Future\r\nStatus</Status></AccelerateConfiguration>",
        ),
        (
            "RAW_CR_STATUS",
            b"<AccelerateConfiguration><Status>Future\rStatus</Status></AccelerateConfiguration>",
        ),
        (
            "RAW_NUL_STATUS",
            b"<AccelerateConfiguration><Status>\0</Status></AccelerateConfiguration>",
        ),
        (
            "NORMAL_TEXT_STATUS",
            b"<AccelerateConfiguration><Status>Enabled</Status></AccelerateConfiguration>",
        ),
    ];
    let (expected_from_real_old_reader, observed_gateway): (Vec<_>, Vec<_>) = inputs
        .into_iter()
        .map(|(case, input)| {
            let old = read_old(input);
            let gateway = rustfs_gateway_types::persistence::parse_accelerate(input)
                .map(|value| value.status)
                .map_err(|error| format!("{error:?}"));
            eprintln!(
                "{case}: old={old:?}, gateway={gateway:?}; expected_source=real s3s_rustfs@5761ddfe4c509fcac87e3b99fd5bd9e176b442c0 Deserialize+expect_eof; gateway_reader=rustfs_gateway_types::persistence::parse_accelerate"
            );
            // Compare accepted raw values or rejection, not unrelated error strings.
            ((case, old.map_err(|_| ())), (case, gateway.map_err(|_| ())))
        })
        .unzip();
    assert_eq!(observed_gateway, expected_from_real_old_reader);
}

#[test]
fn public_access_block_reader_matches_explicit_rustfs_5761_nested_scalar_contract() {
    let inputs: [(&str, &[u8]); 3] = [
        (
            "NORMAL_FALSE",
            b"<PublicAccessBlockConfiguration><RestrictPublicBuckets>false</RestrictPublicBuckets></PublicAccessBlockConfiguration>",
        ),
        (
            "NESTED_EMPTY_ELEMENT",
            b"<PublicAccessBlockConfiguration><RestrictPublicBuckets>false<x/></RestrictPublicBuckets></PublicAccessBlockConfiguration>",
        ),
        (
            "NESTED_TEXT_ELEMENT",
            b"<PublicAccessBlockConfiguration><RestrictPublicBuckets>false<x>ignored</x></RestrictPublicBuckets></PublicAccessBlockConfiguration>",
        ),
    ];
    let (expected_from_real_old_reader, observed_gateway): (Vec<_>, Vec<_>) = inputs
        .into_iter()
        .map(|(case, input)| {
            let mut reader = Deserializer::new(input);
            let old = s3s_rustfs::dto::PublicAccessBlockConfiguration::deserialize(&mut reader).and_then(|value| {
                reader.expect_eof()?;
                Ok(value)
            });
            let gateway = rustfs_gateway_types::persistence::parse_public_access_block(input);
            eprintln!(
                "{case}: old={old:?}, gateway={gateway:?}; expected_source=real s3s_rustfs@5761ddfe4c509fcac87e3b99fd5bd9e176b442c0 Deserialize+expect_eof; gateway_reader=rustfs_gateway_types::persistence::parse_public_access_block"
            );
            let old: Result<[Option<bool>; 4], ()> = old
                .map(|value| {
                    [
                        value.block_public_acls,
                        value.ignore_public_acls,
                        value.block_public_policy,
                        value.restrict_public_buckets,
                    ]
                })
                .map_err(|_| ());
            let gateway: Result<[Option<bool>; 4], ()> = gateway
                .map(|value| {
                    [
                        value.block_public_acls,
                        value.ignore_public_acls,
                        value.block_public_policy,
                        value.restrict_public_buckets,
                    ]
                })
                .map_err(|_| ());
            ((case, old), (case, gateway))
        })
        .unzip();
    assert_eq!(observed_gateway, expected_from_real_old_reader);
}

#[test]
fn tagging_reader_matches_explicit_rustfs_5761_text_contract() {
    type TaggingResult = Result<Vec<(Option<String>, Option<String>)>, ()>;

    let inputs: [(&str, &[u8]); 8] = [
        (
            "PURE_CDATA_VALUE",
            b"<Tagging><TagSet><Tag><Key>k</Key><Value><![CDATA[v]]></Value></Tag></TagSet></Tagging>",
        ),
        (
            "MIXED_CDATA_VALUE",
            b"<Tagging><TagSet><Tag><Key>k</Key><Value>a<![CDATA[b]]>c</Value></Tag></TagSet></Tagging>",
        ),
        (
            "RAW_CRLF_VALUE",
            b"<Tagging><TagSet><Tag><Key>k</Key><Value>a\r\nb</Value></Tag></TagSet></Tagging>",
        ),
        (
            "RAW_CR_VALUE",
            b"<Tagging><TagSet><Tag><Key>k</Key><Value>a\rb</Value></Tag></TagSet></Tagging>",
        ),
        (
            "RAW_NUL_VALUE",
            b"<Tagging><TagSet><Tag><Key>k</Key><Value>\0</Value></Tag></TagSet></Tagging>",
        ),
        (
            "NORMAL_VALUE",
            b"<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>",
        ),
        (
            "NESTED_KEY",
            b"<Tagging><TagSet><Tag><Key>k<x/></Key><Value>v</Value></Tag></TagSet></Tagging>",
        ),
        (
            "NESTED_VALUE",
            b"<Tagging><TagSet><Tag><Key>k</Key><Value>v<x/></Value></Tag></TagSet></Tagging>",
        ),
    ];
    let (expected_from_real_old_reader, observed_gateway): (Vec<_>, Vec<_>) = inputs
        .into_iter()
        .map(|(case, input)| {
            let mut reader = Deserializer::new(input);
            let old = s3s_rustfs::dto::Tagging::deserialize(&mut reader).and_then(|value| {
                reader.expect_eof()?;
                Ok(value)
            });
            let gateway = rustfs_gateway_types::cors_tagging::parse_tagging(input);
            eprintln!(
                "{case}: old={old:?}, gateway={gateway:?}; expected_source=real s3s_rustfs@5761ddfe4c509fcac87e3b99fd5bd9e176b442c0 Deserialize+expect_eof; gateway_reader=rustfs_gateway_types::cors_tagging::parse_tagging"
            );
            let old: TaggingResult = old
                .map(|value| value.tag_set.into_iter().map(|tag| (tag.key, tag.value)).collect())
                .map_err(|_| ());
            let gateway: TaggingResult = gateway
                .map(|value| value.tag_set.into_iter().map(|tag| (tag.key, tag.value)).collect())
                .map_err(|_| ());
            ((case, old), (case, gateway))
        })
        .unzip();
    assert_eq!(observed_gateway, expected_from_real_old_reader);
}

#[test]
fn cors_reader_matches_explicit_rustfs_5761_max_age_contract() {
    type RuleFields = (
        Option<Vec<String>>,
        Vec<String>,
        Vec<String>,
        Option<Vec<String>>,
        Option<String>,
        Option<i32>,
    );
    let inputs: [(&str, &[u8]); 6] = [
        (
            "NORMAL_ONE",
            b"<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin><MaxAgeSeconds>1</MaxAgeSeconds></CORSRule></CORSConfiguration>",
        ),
        (
            "NEGATIVE_ONE",
            b"<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin><MaxAgeSeconds>-1</MaxAgeSeconds></CORSRule></CORSConfiguration>",
        ),
        (
            "TRAILING_TEXT",
            b"<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin><MaxAgeSeconds>1tail</MaxAgeSeconds></CORSRule></CORSConfiguration>",
        ),
        (
            "TRAILING_SPACE",
            b"<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin><MaxAgeSeconds>1 </MaxAgeSeconds></CORSRule></CORSConfiguration>",
        ),
        (
            "LEADING_SPACE",
            b"<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin><MaxAgeSeconds> 1</MaxAgeSeconds></CORSRule></CORSConfiguration>",
        ),
        (
            "I32_POSITIVE_OVERFLOW",
            b"<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin><MaxAgeSeconds>2147483648</MaxAgeSeconds></CORSRule></CORSConfiguration>",
        ),
    ];
    let (expected_from_real_old_reader, observed_gateway): (Vec<_>, Vec<_>) = inputs
        .into_iter()
        .map(|(case, input)| {
            let mut reader = Deserializer::new(input);
            let old = s3s_rustfs::dto::CORSConfiguration::deserialize(&mut reader).and_then(|value| {
                reader.expect_eof()?;
                Ok(value)
            });
            let gateway = rustfs_gateway_types::cors_tagging::parse_cors(input);
            eprintln!(
                "{case}: old={old:?}, gateway={gateway:?}; expected_source=real s3s_rustfs@5761ddfe4c509fcac87e3b99fd5bd9e176b442c0 Deserialize+expect_eof; gateway_reader=rustfs_gateway_types::cors_tagging::parse_cors"
            );
            let old: Result<Vec<RuleFields>, ()> = old
                .map(|value| {
                    value
                        .cors_rules
                        .into_iter()
                        .map(|rule| {
                            (
                                rule.allowed_headers,
                                rule.allowed_methods,
                                rule.allowed_origins,
                                rule.expose_headers,
                                rule.id,
                                rule.max_age_seconds,
                            )
                        })
                        .collect()
                })
                .map_err(|_| ());
            let gateway: Result<Vec<RuleFields>, ()> = gateway
                .map(|value| {
                    value
                        .cors_rules
                        .into_iter()
                        .map(|rule| {
                            (
                                rule.allowed_headers,
                                rule.allowed_methods,
                                rule.allowed_origins,
                                rule.expose_headers,
                                rule.id,
                                rule.max_age_seconds,
                            )
                        })
                        .collect()
                })
                .map_err(|_| ());
            ((case, old), (case, gateway))
        })
        .unzip();
    assert_eq!(observed_gateway, expected_from_real_old_reader);
}
