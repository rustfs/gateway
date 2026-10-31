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

//! Canonical Copy input decoding through the real request codecs.
//!
//! Responsible for: deferred source parsing, decoded field identity and deployment policy.
//! NOT responsible for: backend storage or authorization decisions.
//! Upstream: accepted HTTP requests. Downstream: both generated Copy inputs.

#![allow(clippy::expect_used)]

use std::sync::Arc;

use rustfs_gateway_core::CodecError;
use rustfs_gateway_core::codec::{MetaView, OperationCodec, RequestBody};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::{CopySourceValue, ErrorCode, LegacyRustfsNameValidator, NamePolicy, SlashPolicy, dto};

type Refusal = (ErrorCode, &'static str, Option<&'static str>);

fn rustfs() -> NamePolicy {
    NamePolicy::default()
        .with_slash_policy(SlashPolicy::RustfsLegacy)
        .with_legacy_rustfs_key_floor()
        .with_legacy_rustfs_path_split()
        .with_validator(Arc::new(LegacyRustfsNameValidator))
}

fn refusal(error: CodecError) -> Refusal {
    (error.code().clone(), error.message(), error.member())
}

fn decode(
    part: bool,
    source: &str,
    query: &str,
    headers: &[(&str, &str)],
    names: &NamePolicy,
) -> Result<CopySourceValue, Refusal> {
    let mut request = http::Request::builder()
        .method("PUT")
        .uri(format!("http://host.invalid/target/key{query}"))
        .header("host", "host.invalid")
        .header("x-amz-copy-source", source);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let request = WireRequest::accept(request.body(()).expect("request"), &Limits::default()).expect("accepted request");
    let view = MetaView::of_with(&request, TargetKind::Object, names).map_err(refusal)?;
    if part {
        dto::UploadPartCopy::decode(&view, RequestBody::None)
            .map(|input| input.copy_source)
            .map_err(refusal)
    } else {
        dto::CopyObject::decode(&view, RequestBody::None)
            .map(|input| input.copy_source)
            .map_err(refusal)
    }
}

#[test]
fn later_bindings_keep_their_error_ahead_of_invalid_copy_sources() {
    for names in [NamePolicy::default(), rustfs()] {
        for (part, query, headers, member) in [
            (
                false,
                "",
                vec![("x-amz-object-lock-retain-until-date", "invalid")],
                "ObjectLockRetainUntilDate",
            ),
            (true, "?partNumber=invalid&uploadId=upload", vec![], "PartNumber"),
            (true, "?partNumber=999999999999999999999&uploadId=upload", vec![], "PartNumber"),
            (true, "?uploadId=upload", vec![], "PartNumber"),
            (true, "?partNumber=1", vec![], "UploadId"),
        ] {
            let expected = decode(part, "src/key", query, &headers, &names).expect_err("ordinary binding refuses");
            assert_eq!(expected.2, Some(member));
            for source in [
                "",
                "src",
                "bad!/key",
                "src/%FF",
                "arn:bad",
                "arn:aws:s3:us-east-1:123:accesspoint/ap/object/key",
            ] {
                assert_eq!(
                    decode(part, source, query, &headers, &names),
                    Err(expected.clone()),
                    "{part}/{member}/{source}"
                );
            }
        }
    }
}

#[test]
fn both_copy_inputs_hold_decoded_values_and_preserve_empty_version_policy() {
    for names in [NamePolicy::default(), rustfs()] {
        for (part, query) in [(false, ""), (true, "?partNumber=1&uploadId=upload")] {
            let value = decode(part, "src/a%252Fb%3FversionId%3Dliteral?versionId=v%252F", query, &[], &names);
            assert_eq!(
                value,
                Ok(CopySourceValue::Bucket {
                    bucket: "src".to_owned(),
                    key: "a%2Fb?versionId=literal".to_owned(),
                    version_id: Some("v%2F".to_owned()),
                })
            );
            let empty = decode(part, "src/key?versionId=", query, &[], &names);
            let expected = if names.path_split() == rustfs_gateway_types::PathSplit::RustfsLegacy {
                Ok(CopySourceValue::Bucket {
                    bucket: "src".to_owned(),
                    key: "key".to_owned(),
                    version_id: Some(String::new()),
                })
            } else {
                Err((ErrorCode::INVALID_ARGUMENT, "the versionId of x-amz-copy-source must not be empty", None))
            };
            assert_eq!(empty, expected);
        }
    }
}

#[test]
fn outposts_access_point_is_preserved_by_both_copy_codecs_but_not_bound() {
    use rustfs_gateway_core::Operation;

    let source = "arn:aws:s3-outposts:us-east-1:123456789012:outpost/op-1/accesspoint/ap-1/object/key?versionId=v1";
    for names in [NamePolicy::default(), rustfs()] {
        for (part, query) in [(false, ""), (true, "?partNumber=1&uploadId=upload")] {
            let value = decode(part, source, query, &[], &names).expect("source grammar");
            assert_eq!(
                value,
                CopySourceValue::Outpost {
                    partition: "aws".into(),
                    region: "us-east-1".into(),
                    account_id: "123456789012".into(),
                    outpost_id: "op-1/accesspoint/ap-1".into(),
                    key: "key".into(),
                    version_id: Some("v1".into()),
                }
            );
            let error = if part {
                dto::UploadPartCopy::derive_resources_under(&dto::UploadPartCopyInput::builder(value).build(), &names).err()
            } else {
                dto::CopyObject::derive_resources_under(&dto::CopyObjectInput::builder(value).build(), &names).err()
            }
            .expect("unsupported identity must not bind");
            assert_eq!(error.code(), &ErrorCode::INVALID_ARGUMENT);
            assert_eq!(
                error.message(),
                "x-amz-copy-source accepts an access point or Outposts ARN, or a bucket and key"
            );
        }
    }
}

#[test]
fn erased_dispatch_still_refuses_outposts_access_point_sources() {
    use rustfs_gateway_core::ErasedCodec;

    for (part, query) in [(false, ""), (true, "?partNumber=1&uploadId=upload")] {
        let request = http::Request::builder()
            .method("PUT")
            .uri(format!("http://host.invalid/target/key{query}"))
            .header("host", "host.invalid")
            .header(
                "x-amz-copy-source",
                "arn:aws:s3-outposts:us-east-1:123456789012:outpost/op/accesspoint/ap/object/key",
            )
            .body(())
            .expect("request");
        let wire = WireRequest::accept(request, &Limits::default()).expect("accepted request");
        let view = MetaView::of_with(&wire, TargetKind::Object, &rustfs()).expect("request metadata");
        let codec = if part {
            ErasedCodec::for_operation::<dto::UploadPartCopy>()
        } else {
            ErasedCodec::for_operation::<dto::CopyObject>()
        };
        let error = match codec.decode(&view, RequestBody::None) {
            Err(error) => error,
            Ok(_) => panic!("unbound source"),
        };
        assert_eq!(error.code(), &ErrorCode::INVALID_ARGUMENT);
        assert_eq!(
            error.message(),
            "x-amz-copy-source accepts an access point or Outposts ARN, or a bucket and key"
        );
    }
}

#[test]
fn source_deployment_validation_runs_once_at_resource_derivation() {
    use rustfs_gateway_core::Operation;
    use rustfs_gateway_types::{NameValidator, Stricter};
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct CountSource(Arc<AtomicUsize>);
    impl NameValidator for CountSource {
        fn check_bucket(&self, _name: &str) -> Stricter {
            Stricter::NoOpinion
        }
        fn check_key(&self, key: &str) -> Stricter {
            if key == "source-key" {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
            Stricter::NoOpinion
        }
    }
    for part in [false, true] {
        let calls = Arc::new(AtomicUsize::new(0));
        let names = NamePolicy::default().with_validator(Arc::new(CountSource(calls.clone())));
        let source = decode(part, "src/source-key", "?partNumber=1&uploadId=upload", &[], &names).expect("source syntax");
        let after_decode = calls.load(Ordering::SeqCst);
        if part {
            let input = dto::UploadPartCopyInput::builder(source).build();
            dto::UploadPartCopy::derive_resources_under(&input, &names).expect("source binding");
        } else {
            let input = dto::CopyObjectInput::builder(source).build();
            dto::CopyObject::derive_resources_under(&input, &names).expect("source binding");
        }
        assert_eq!(
            (after_decode, calls.load(Ordering::SeqCst)),
            (0, 1),
            "source validation belongs to derivation: part={part}"
        );
    }
}
