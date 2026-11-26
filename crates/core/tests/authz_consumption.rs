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

//! Public authorization outcomes fail closed without exposing the proof constructor.
//!
//! Responsible for: the stable public three-state outcome semantics.
//! NOT responsible for: constructing authorization proofs, which is crate-private and unit-tested.
//! Upstream: `rustfs_gateway_core::authz`. Downstream: facade authorizers.

use bytes::Bytes;
use http::Request;
use rustfs_gateway_core::{Decision, ErasedCodec, MetaView, Operation, RequestBody, TargetKind};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_sig::SigService;
use rustfs_gateway_types::dto::{DeleteObjects, RenameObject};

#[test]
fn allow_is_the_only_continuation() {
    assert!(Decision::Allow.settle().is_ok());
}

#[test]
fn deny_is_a_refusal() {
    assert_eq!(Decision::Deny.settle().expect_err("deny refuses").decision(), Decision::Deny);
}

#[test]
fn indeterminate_is_a_refusal() {
    assert_eq!(
        Decision::Indeterminate
            .settle()
            .expect_err("indeterminate refuses")
            .decision(),
        Decision::Indeterminate
    );
}

#[test]
fn delete_objects_derives_every_key_and_version_action() {
    let request = Request::builder()
        .method("POST")
        .uri("http://host.invalid/bucket?delete")
        .header("host", "host.invalid")
        // The true digest of the body below: `Content-MD5` is verified against the bytes now, so a
        // placeholder would refuse this request with `BadDigest` before any action was derived.
        .header("content-md5", "iunWEGrmj9rjGeTZYc+R5w==")
        .body(())
        .expect("valid request");
    let wire = WireRequest::accept(request, &Limits::default()).expect("accepted request");
    let meta = MetaView::of(&wire, TargetKind::Bucket).expect("bucket target");
    let body = Bytes::from_static(
        b"<Delete><Object><Key>one</Key></Object><Object><Key>two</Key><VersionId>v1</VersionId></Object><Object><Key>three</Key></Object></Delete>",
    );
    let codec = ErasedCodec::for_operation::<DeleteObjects>();
    let decoded = codec.decode(&meta, RequestBody::Buffered(body)).expect("decoded");
    let resources = codec.derived_resources(&decoded).expect("derived resources");

    let observed: Vec<(&str, &str, Option<&str>)> = resources
        .iter()
        .map(|resource| {
            (
                resource.action(),
                resource.key().expect("an object resource").as_str(),
                resource.version_id(),
            )
        })
        .collect();
    assert_eq!(
        observed,
        [
            ("s3:DeleteObject", "one", None),
            ("s3:DeleteObjectVersion", "two", Some("v1")),
            ("s3:DeleteObject", "three", None),
        ]
    );
}

fn decode_rename(
    source: &str,
    names: &rustfs_gateway_types::NamePolicy,
) -> Result<Vec<rustfs_gateway_core::OwnedResource>, rustfs_gateway_core::CodecError> {
    let request = Request::builder()
        .method("PUT")
        .uri("http://host.invalid/bucket/dest/key?renameObject")
        .header("host", "host.invalid")
        .header("x-amz-rename-source", source)
        .body(())
        .expect("valid rename request");
    let wire = WireRequest::accept(request, &Limits::default()).expect("accepted request");
    let meta = MetaView::of_with(&wire, TargetKind::Object, names).expect("object target");
    let codec = ErasedCodec::for_operation::<RenameObject>();
    let decoded = codec.decode(&meta, RequestBody::None)?;
    codec.derived_resources(&decoded)
}

#[test]
fn rename_object_derives_normalized_source_object_resource() {
    let resources = decode_rename("dir/old%20file.txt", &rustfs_gateway_types::NamePolicy::default())
        .expect("valid rename source derives its resource");
    let observed: Vec<(&str, Option<&str>, Option<&str>)> = resources
        .iter()
        .map(|resource| {
            (
                resource.action(),
                resource.bucket().map(rustfs_gateway_types::BucketName::as_str),
                resource.key().map(rustfs_gateway_types::ObjectKey::as_str),
            )
        })
        .collect();
    assert_eq!(observed, [("s3express:CreateSession", Some("bucket"), Some("dir/old file.txt"))]);
}

#[test]
fn n_rename_object_rejects_unsafe_source_keys_before_authorization() {
    let names = rustfs_gateway_types::NamePolicy::default();
    let too_long = "a".repeat(1025);
    for (raw, expected_code) in [
        ("", rustfs_gateway_types::ErrorCode::INVALID_ARGUMENT),
        ("..", rustfs_gateway_types::ErrorCode::INVALID_ARGUMENT),
        ("../secret", rustfs_gateway_types::ErrorCode::INVALID_ARGUMENT),
        ("a/../../etc/passwd", rustfs_gateway_types::ErrorCode::INVALID_ARGUMENT),
        ("a\\..\\secret", rustfs_gateway_types::ErrorCode::INVALID_ARGUMENT),
        ("%2e%2e/secret", rustfs_gateway_types::ErrorCode::INVALID_ARGUMENT),
        ("a%2F..%2Fb", rustfs_gateway_types::ErrorCode::INVALID_ARGUMENT),
        ("%252e%252e/secret", rustfs_gateway_types::ErrorCode::INVALID_ARGUMENT),
        ("%252e%252e%252fsecret", rustfs_gateway_types::ErrorCode::INVALID_ARGUMENT),
        ("a%252Fb", rustfs_gateway_types::ErrorCode::INVALID_ARGUMENT),
        ("a%255cb", rustfs_gateway_types::ErrorCode::INVALID_ARGUMENT),
        ("%255c%255cshare", rustfs_gateway_types::ErrorCode::INVALID_ARGUMENT),
        ("a%00b", rustfs_gateway_types::ErrorCode::INVALID_ARGUMENT),
        ("a%01b", rustfs_gateway_types::ErrorCode::INVALID_ARGUMENT),
        ("a%7Fb", rustfs_gateway_types::ErrorCode::INVALID_ARGUMENT),
        ("%FF%FE", rustfs_gateway_types::ErrorCode::INVALID_ARGUMENT),
        ("//server/share", rustfs_gateway_types::ErrorCode::INVALID_ARGUMENT),
        ("\\server\\share", rustfs_gateway_types::ErrorCode::INVALID_ARGUMENT),
        ("C:/Windows/win.ini", rustfs_gateway_types::ErrorCode::INVALID_ARGUMENT),
        (too_long.as_str(), rustfs_gateway_types::ErrorCode::KEY_TOO_LONG),
    ] {
        let Err(error) = decode_rename(raw, &names) else {
            panic!("disallowed source {raw:?} must be refused");
        };
        assert_eq!(error.code(), &expected_code, "raw={raw:?}");
    }
}

#[test]
fn n_rename_object_uses_s3express_signing_floor() {
    assert_eq!(RenameObject::floor().service(), SigService::S3Express);
}
