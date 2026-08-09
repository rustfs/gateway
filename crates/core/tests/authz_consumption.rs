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
use rustfs_gateway_core::{Decision, ErasedCodec, MetaView, RequestBody, TargetKind};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::dto::DeleteObjects;

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
        .header("content-md5", "present")
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
