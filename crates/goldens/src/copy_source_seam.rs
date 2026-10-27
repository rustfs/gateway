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

//! Lossless decoded copy-source values across the three compatibility revisions.
//!
//! Responsible for: preserving source identity, decoded text and version presence before validation.
//! NOT responsible for: parsing new grammar, choosing name policy or granting source authorization.
//! Upstream: public parser measurements in rustfs/gateway#1470. Downstream: native migration gates.

// Public parser facts: https://github.com/rustfs/gateway/issues/1470#issuecomment-6404723770
// The legacy parser preserves these decoded fields, including values rejected by later policies.
const PARSED: &[(&str, &str)] = &[
    ("src/key", r##"{"bucket":"src","key":"key","kind":"bucket","version_id":null}"##),
    ("/src/key", r##"{"bucket":"src","key":"key","kind":"bucket","version_id":null}"##),
    ("sthree-x/key", r##"{"bucket":"sthree-x","key":"key","kind":"bucket","version_id":null}"##),
    (
        "abc-s3alias/key",
        r##"{"bucket":"abc-s3alias","key":"key","kind":"bucket","version_id":null}"##,
    ),
    ("src/", r##"{"bucket":"src","key":"","kind":"bucket","version_id":null}"##),
    ("src/a//b", r##"{"bucket":"src","key":"a//b","kind":"bucket","version_id":null}"##),
    ("src/a/../b", r##"{"bucket":"src","key":"a/../b","kind":"bucket","version_id":null}"##),
    ("src/a%252Fb", r##"{"bucket":"src","key":"a%2Fb","kind":"bucket","version_id":null}"##),
    ("src/a%255Cb", r##"{"bucket":"src","key":"a%5Cb","kind":"bucket","version_id":null}"##),
    ("src/a%00b", r##"{"bucket":"src","key":"a\u0000b","kind":"bucket","version_id":null}"##),
    ("src/a%01b", r##"{"bucket":"src","key":"a\u0001b","kind":"bucket","version_id":null}"##),
    ("src/a%5Cb", r##"{"bucket":"src","key":"a\\b","kind":"bucket","version_id":null}"##),
    (
        "src/a?other=1",
        r##"{"bucket":"src","key":"a?other=1","kind":"bucket","version_id":null}"##,
    ),
    (
        "src/a?b?versionId=v1",
        r##"{"bucket":"src","key":"a?b","kind":"bucket","version_id":"v1"}"##,
    ),
    ("src/a?versionId=", r##"{"bucket":"src","key":"a","kind":"bucket","version_id":""}"##),
    (
        "src/a?versionId=null",
        r##"{"bucket":"src","key":"a","kind":"bucket","version_id":"null"}"##,
    ),
    (
        "src/a?versionId=a%2Fb",
        r##"{"bucket":"src","key":"a","kind":"bucket","version_id":"a/b"}"##,
    ),
    (
        "src/a?versionId=v?x",
        r##"{"bucket":"src","key":"a","kind":"bucket","version_id":"v?x"}"##,
    ),
    (
        "src/a?versionId=v?versionId=w",
        r##"{"bucket":"src","key":"a","kind":"bucket","version_id":"v?versionId=w"}"##,
    ),
    (
        "src/a%3Fb?versionId=v%252F",
        r##"{"bucket":"src","key":"a?b","kind":"bucket","version_id":"v%2F"}"##,
    ),
    ("src/%", r##"{"bucket":"src","key":"%","kind":"bucket","version_id":null}"##),
    ("src/%2", r##"{"bucket":"src","key":"%2","kind":"bucket","version_id":null}"##),
    ("src/%GG", r##"{"bucket":"src","key":"%GG","kind":"bucket","version_id":null}"##),
    (
        "arn:aws:s3:us-west-2:123456789012:accesspoint/point/object/key",
        r##"{"access_point_name":"point","account_id":"123456789012","key":"key","kind":"access_point","partition":"aws","region":"us-west-2","version_id":null}"##,
    ),
    (
        "/arn:aws:s3:us-west-2:123456789012:accesspoint/point/object/key",
        r##"{"access_point_name":"point","account_id":"123456789012","key":"key","kind":"access_point","partition":"aws","region":"us-west-2","version_id":null}"##,
    ),
    (
        "arn:aws:s3-outposts:us-west-2:123456789012:outpost/op-123/accesspoint/point/object/key",
        r##"{"account_id":"123456789012","key":"key","kind":"outpost","outpost_id":"op-123/accesspoint/point","partition":"aws","region":"us-west-2","version_id":null}"##,
    ),
];

macro_rules! define_tests {
    ($name:ident, $revision:ident) => {
        mod $name {
            use rustfs_gateway_types::{CopySourceValue as Owned, compat::$revision as seam};
            use seam::s3s::dto::CopySource as Legacy;

            fn owned_view(value: Owned) -> serde_json::Value {
                match value {
                    Owned::Bucket { bucket, key, version_id } => {
                        serde_json::json!({"kind":"bucket", "bucket":bucket, "key":key, "version_id":version_id})
                    }
                    Owned::AccessPoint {
                        partition,
                        region,
                        account_id,
                        access_point_name,
                        key,
                        version_id,
                    } => {
                        serde_json::json!({"kind":"access_point", "partition":partition, "region":region, "account_id":account_id, "access_point_name":access_point_name, "key":key, "version_id":version_id})
                    }
                    Owned::Outpost {
                        partition,
                        region,
                        account_id,
                        outpost_id,
                        key,
                        version_id,
                    } => {
                        serde_json::json!({"kind":"outpost", "partition":partition, "region":region, "account_id":account_id, "outpost_id":outpost_id, "key":key, "version_id":version_id})
                    }
                }
            }
            fn legacy_view(value: Legacy) -> serde_json::Value {
                match value {
                    Legacy::Bucket { bucket, key, version_id } => {
                        serde_json::json!({"kind":"bucket", "bucket":bucket, "key":key, "version_id":version_id})
                    }
                    Legacy::AccessPoint {
                        partition,
                        region,
                        account_id,
                        access_point_name,
                        key,
                        version_id,
                    } => {
                        serde_json::json!({"kind":"access_point", "partition":partition, "region":region, "account_id":account_id, "access_point_name":access_point_name, "key":key, "version_id":version_id})
                    }
                    Legacy::Outpost {
                        partition,
                        region,
                        account_id,
                        outpost_id,
                        key,
                        version_id,
                    } => {
                        serde_json::json!({"kind":"outpost", "partition":partition, "region":region, "account_id":account_id, "outpost_id":outpost_id, "key":key, "version_id":version_id})
                    }
                }
            }

            pub(super) fn direct_pairs() -> Vec<(Owned, Legacy)> {
                let normal = ["bucket", "object/key", "aws", "us-west-2", "123456789012", "container"].map(str::to_owned);
                let mut fields = vec![normal.clone()];
                for replacement in ["", "\0", "a//b", "../x", "%2F", "Legacy_Bucket", "a?versionId=x"] {
                    for position in 0..normal.len() {
                        let mut changed = normal.clone();
                        for (index, field) in changed.iter_mut().enumerate() {
                            if index == position {
                                *field = replacement.to_owned();
                            }
                        }
                        fields.push(changed);
                    }
                }
                let mut pairs = Vec::new();
                for values in fields {
                    for version in [None, Some(""), Some("v%2F?x")] {
                        let [bucket, key, partition, region, account_id, container] = values.clone();
                        let version_id = version.map(str::to_owned);
                        pairs.push((
                            Owned::Bucket {
                                bucket: bucket.clone(),
                                key: key.clone(),
                                version_id: version_id.clone(),
                            },
                            Legacy::Bucket {
                                bucket: bucket.into_boxed_str(),
                                key: key.clone().into_boxed_str(),
                                version_id: version_id.clone().map(String::into_boxed_str),
                            },
                        ));
                        pairs.push((
                            Owned::AccessPoint {
                                partition: partition.clone(),
                                region: region.clone(),
                                account_id: account_id.clone(),
                                access_point_name: container.clone(),
                                key: key.clone(),
                                version_id: version_id.clone(),
                            },
                            Legacy::AccessPoint {
                                partition: partition.clone().into_boxed_str(),
                                region: region.clone().into_boxed_str(),
                                account_id: account_id.clone().into_boxed_str(),
                                access_point_name: container.clone().into_boxed_str(),
                                key: key.clone().into_boxed_str(),
                                version_id: version_id.clone().map(String::into_boxed_str),
                            },
                        ));
                        pairs.push((
                            Owned::Outpost {
                                partition: partition.clone(),
                                region: region.clone(),
                                account_id: account_id.clone(),
                                outpost_id: container.clone(),
                                key: key.clone(),
                                version_id: version_id.clone(),
                            },
                            Legacy::Outpost {
                                partition: partition.into_boxed_str(),
                                region: region.into_boxed_str(),
                                account_id: account_id.into_boxed_str(),
                                outpost_id: container.into_boxed_str(),
                                key: key.into_boxed_str(),
                                version_id: version_id.map(String::into_boxed_str),
                            },
                        ));
                    }
                }
                pairs
            }

            /// Positive and negative controls — independent parser facts retain their full decoded shape.
            #[test]
            fn parsed_sources_keep_the_observed_fields() -> Result<(), String> {
                for (raw, expected) in super::PARSED {
                    let input = Legacy::parse(raw).map_err(|error| format!("fixture parse: {error:?}"))?;
                    let expected: serde_json::Value = serde_json::from_str(expected).map_err(|error| error.to_string())?;
                    assert_eq!(owned_view(seam::copy_source::from_s3s(input)), expected);
                }
                Ok(())
            }

            /// Negative — conversion must not reject, normalize or authorize directly constructed fields.
            #[test]
            fn legacy_dto_fields_cross_before_validation() {
                for (expected, input) in direct_pairs() {
                    assert_eq!(seam::copy_source::from_s3s(input), expected);
                }
            }

            /// Negative — the reverse path must preserve explicit empty versions and each ARN identity field.
            #[test]
            fn owned_fields_cross_before_validation() {
                for (input, expected) in direct_pairs() {
                    assert_eq!(legacy_view(seam::copy_source::to_s3s(input)), legacy_view(expected));
                }
            }
        }
    };
}

define_tests!(release, s3s_0_17_0);
define_tests!(rustfs, s3s_5761ddfe);
define_tests!(baseline, s3s_9c4690d8);

// Only the release and RustFS revision expose the full generated operation seam.
// Baseline evidence continues through the three carrier tests above.
macro_rules! operation_input_test {
    ($test:ident, $name:ident, $revision:ident) => {
        #[test]
        fn $test() {
            use rustfs_gateway_types::compat::$revision as seam;
            for (expected, source) in $name::direct_pairs() {
                let copy = seam::s3s::dto::CopyObjectInput::builder()
                    .bucket("target".to_owned())
                    .key("key".to_owned())
                    .copy_source(source.clone())
                    .build()
                    .expect("copy input");
                let (copy, _) = seam::generated::ops::copy_object::input_from_s3s(copy).expect("decoded copy conversion");
                let part = seam::s3s::dto::UploadPartCopyInput::builder()
                    .bucket("target".to_owned())
                    .key("key".to_owned())
                    .part_number(1)
                    .upload_id("upload".to_owned())
                    .copy_source(source)
                    .build()
                    .expect("part copy input");
                let part = seam::generated::ops::upload_part_copy::input_from_s3s(part).expect("decoded part conversion");
                assert_eq!((copy.copy_source, part.copy_source), (expected.clone(), expected));
            }
        }
    };
}
operation_input_test!(release_operation_inputs_keep_direct_sources, release, s3s_0_17_0);
operation_input_test!(rustfs_operation_inputs_keep_direct_sources, rustfs, s3s_5761ddfe);
