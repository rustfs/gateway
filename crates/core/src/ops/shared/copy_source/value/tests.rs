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

//! Decoded Copy source preservation and erasure regressions.
//!
//! Responsible for: full resource identity, error order, literal decoded text and all source seals.
//! NOT responsible for: ordinary header binding or backend storage behavior.
//! Upstream: the existing wire parser and owned carrier. Downstream: typed Copy input integration.

use std::sync::Arc;

use rustfs_gateway_types::{LegacyRustfsNameValidator, SlashPolicy};

use super::*;

fn rustfs() -> NamePolicy {
    NamePolicy::default()
        .with_slash_policy(SlashPolicy::RustfsLegacy)
        .with_legacy_rustfs_key_floor()
        .with_legacy_rustfs_path_split()
        .with_validator(Arc::new(LegacyRustfsNameValidator))
}

#[test]
fn decoded_value_keeps_the_wire_source_identity_and_errors() {
    let cases = [
        "src/key",
        "/src/a%252Fb?versionId=v%2525",
        "src%2Fkey?versionId=v1",
        "old_src/key",
        "arn:aws:s3:us-east-1:123456789012:accesspoint/ap-name/object/key",
        "arn:aws:s3:us-east-1:123456789012:accesspoint/ap-name/object/a%252Fb?versionId=v1",
        "arn:aws:s3-outposts:us-west-2:123456789012:outpost/op-1/bucket/src/object/key",
        "arn:aws:s3-outposts:us-west-2:123456789012:outpost/op-1/object/key?versionId=v1",
        "",
        "src",
        "/",
        "src/",
        "src/%00",
        "src/%FF",
        "src/key?versionId=",
        "src/key?versionId=%FF",
        "src/key?other=value",
        "bad!/key",
        "arn:bad",
        "arn:aws:other:us-east-1:123456789012:accesspoint/ap-name/object/key",
        "arn:aws:s3:us-east-1:123:accesspoint/ap-name/object/key",
        "arn:aws:s3:us-east-1:12345678901x:accesspoint/ap-name/object/key",
        "arn::s3:us-east-1:123456789012:accesspoint/ap-name/object/key",
        "arn:aws:s3::123456789012:accesspoint/ap-name/object/key",
        "arn:aws:s3:us-east-1:123456789012:accesspoint//object/key",
        "arn:aws:s3:us-east-1:123456789012:accesspoint/ap-name/object/",
        "arn:aws:s3-outposts:us-west-2:123456789012:outpost//object/key",
        "arn:aws:s3-outposts:us-west-2:123456789012:outpost/op-1/bucket/bad!/object/key",
        "arn::s3-outposts:us-west-2:123456789012:outpost/op-1/bucket/bad!/object/key",
        "arn:aws:s3-outposts:us-west-2:123456789012:outpost/op-1/other/key",
        "arn:aws:s3-outposts:us-west-2:123456789012:outpost/op-1/object/%00",
        "arn:aws:s3-outposts:us-west-2:123456789012:outpost/op-1/bucket/src/object/%FF",
    ];
    for names in [NamePolicy::default(), rustfs()] {
        for raw in cases {
            let expected = CopySource::parse_under(raw, &names)
                .map(|source| source.resource)
                .map_err(|error| (error.code().clone(), error.reason(), None));
            let observed = decode_value(raw, &names)
                .and_then(|value| {
                    bind_value(&value, &names).map_err(|error| CodecError::new(error.code().clone(), error.reason()))
                })
                .map(|source| source.resource)
                .map_err(|error| (error.code().clone(), error.message(), error.member()));
            assert_eq!(observed, expected, "raw={raw:?}, split={:?}", names.path_split());
        }
    }
}

#[test]
fn decoded_value_binding_does_not_reinterpret_escapes() -> Result<(), CopySourceRejection> {
    let value = CopySourceValue::Bucket {
        bucket: "src".to_owned(),
        key: "a%2Fb?versionId=literal".to_owned(),
        version_id: Some("v%2F".to_owned()),
    };
    for names in [NamePolicy::default(), rustfs()] {
        let expected = CopySource::parse_under("src/a%252Fb%3FversionId%3Dliteral?versionId=v%252F", &names)?.resource;
        let observed = bind_value(&value, &names).map(|source| source.resource);
        let literal = observed
            .as_ref()
            .ok()
            .map(|source| (source.key.as_str(), source.version_id.as_deref()));
        assert_eq!(
            (observed.clone(), literal),
            (Ok(expected), Some(("a%2Fb?versionId=literal", Some("v%2F")))),
            "decoded fields are not a second wire header"
        );
    }
    Ok(())
}

#[test]
fn decoded_value_sealing_erases_every_identity_component() {
    let cases = [
        (
            CopySourceValue::Bucket {
                bucket: "src".to_owned(),
                key: "secret".to_owned(),
                version_id: Some("v1".to_owned()),
            },
            CopySourceValue::Bucket {
                bucket: String::new(),
                key: String::new(),
                version_id: None,
            },
        ),
        (
            CopySourceValue::AccessPoint {
                partition: "aws".to_owned(),
                region: "us-east-1".to_owned(),
                account_id: "123456789012".to_owned(),
                access_point_name: "ap-name".to_owned(),
                key: "secret".to_owned(),
                version_id: Some(String::new()),
            },
            CopySourceValue::AccessPoint {
                partition: String::new(),
                region: String::new(),
                account_id: String::new(),
                access_point_name: String::new(),
                key: String::new(),
                version_id: None,
            },
        ),
        (
            CopySourceValue::Outpost {
                partition: "aws".to_owned(),
                region: "us-west-2".to_owned(),
                account_id: "123456789012".to_owned(),
                outpost_id: "op-1/bucket/src".to_owned(),
                key: "secret".to_owned(),
                version_id: Some("v2".to_owned()),
            },
            CopySourceValue::Outpost {
                partition: String::new(),
                region: String::new(),
                account_id: String::new(),
                outpost_id: String::new(),
                key: String::new(),
                version_id: None,
            },
        ),
    ];
    for (mut value, expected) in cases {
        seal_value(&mut value);
        assert_eq!(value, expected, "no source identity or version presence survives the seal");
    }
}

#[test]
fn decoded_value_binding_validates_direct_carriers_under_the_request_policy() {
    let mut cases = Vec::new();
    for (bucket, key, version, default_ok, legacy_ok) in [
        ("src", "key", None, true, true),
        ("src", "key", Some("v1"), true, true),
        ("old_src", "key", None, false, false),
        ("sthree-x", "key", None, false, true),
        ("bad!", "key", None, false, false),
        ("", "key", None, false, false),
        ("src", "", None, false, false),
        ("src", "../key", None, false, true),
        ("src", "\0", None, false, false),
        ("src", "key", Some(""), false, true),
    ] {
        let raw = format!("/{bucket}/{key}{}", version.map(|v| format!("?versionId={v}")).unwrap_or_default());
        cases.push((
            CopySourceValue::Bucket {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                version_id: version.map(str::to_owned),
            },
            raw,
            default_ok,
            legacy_ok,
        ));
    }
    for (partition, region, account, component, ap_ok, outpost_ok) in [
        ("aws", "us-east-1", "123456789012", "ap-name", true, true),
        ("aws:s3", "us-east-1", "123456789012", "ap-name", false, false),
        ("aws", "us:east-1", "123456789012", "ap-name", false, false),
        ("", "us-east-1", "123456789012", "ap-name", false, false),
        ("aws", "", "123456789012", "ap-name", false, false),
        ("aws", "us-east-1", "123", "ap-name", false, false),
        ("aws", "us-east-1", "12345678901x", "ap-name", false, false),
        ("aws", "us-east-1", "123456789012", "", false, false),
        ("aws", "us-east-1", "123456789012", "bad!", false, true),
    ] {
        cases.push((
            CopySourceValue::AccessPoint {
                partition: partition.to_owned(),
                region: region.to_owned(),
                account_id: account.to_owned(),
                access_point_name: component.to_owned(),
                key: "key".to_owned(),
                version_id: None,
            },
            format!("arn:{partition}:s3:{region}:{account}:accesspoint/{component}/object/key"),
            ap_ok,
            ap_ok,
        ));
        for suffix in ["", "/bucket/bad!"] {
            let outpost = format!("{component}{suffix}");
            cases.push((
                CopySourceValue::Outpost {
                    partition: partition.to_owned(),
                    region: region.to_owned(),
                    account_id: account.to_owned(),
                    outpost_id: outpost.clone(),
                    key: "key".to_owned(),
                    version_id: None,
                },
                format!("arn:{partition}:s3-outposts:{region}:{account}:outpost/{outpost}/object/key"),
                outpost_ok && suffix.is_empty(),
                outpost_ok && suffix.is_empty(),
            ));
        }
    }
    for names in [NamePolicy::default(), rustfs()] {
        for (value, raw, default_ok, legacy_ok) in &cases {
            let expected = CopySource::parse_under(raw, &names).map(|source| source.resource);
            let observed = bind_value(value, &names).map(|source| source.resource);
            let accepted = if names.path_split() == rustfs_gateway_types::PathSplit::RustfsLegacy {
                *legacy_ok
            } else {
                *default_ok
            };
            assert_eq!(
                (observed.is_ok(), observed),
                (accepted, expected),
                "direct carrier {value:?}, split={:?}",
                names.path_split()
            );
        }
    }
}
