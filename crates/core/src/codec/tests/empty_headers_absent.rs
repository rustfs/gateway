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

//! The empty-header reading a view applies for the RustFS profile (rustfs/gateway#1087), seen
//! through the generated decoders.
//!
//! Responsible for: a header whose one line is empty decoding as absent under the reading — a
//! string, a timestamp, an enumeration, a boolean — and everything else decoding exactly as it did:
//! a value, a repeated line, the metadata prefix, and every empty line without the reading.
//! NOT responsible for: when an assembly applies the reading (`rustfs-gateway`'s view policy), or
//! the integrity claims, which `rustfs-gateway-http`'s arbitration reads.
//! Upstream: `crate::codec::view::MetaView::with_empty_headers_absent`. Downstream: nothing.

use super::*;

fn put(headers: &[(&str, &str)], absent: bool) -> Result<dto::PutObjectInput, crate::codec::CodecError> {
    let request = accepted("PUT", "/photos/key", &[&[("content-length", "0")], headers].concat());
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let view = if absent { view.with_empty_headers_absent() } else { view };
    dto::PutObject::decode(&view, RequestBody::None)
}

fn delete(headers: &[(&str, &str)], absent: bool) -> Result<dto::DeleteObjectInput, crate::codec::CodecError> {
    let request = accepted("DELETE", "/photos/key", headers);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let view = if absent { view.with_empty_headers_absent() } else { view };
    dto::DeleteObject::decode(&view, RequestBody::None)
}

#[test]
fn an_empty_header_decodes_as_absent_under_the_reading() {
    let input = put(
        &[
            ("content-type", ""),
            ("x-amz-tagging", ""),
            ("x-amz-object-lock-mode", ""),
            ("x-amz-object-lock-retain-until-date", ""),
            ("x-amz-expected-bucket-owner", ""),
        ],
        true,
    )
    .expect("decodes");
    assert_eq!(input.content_type, None);
    assert_eq!(input.tagging, None);
    assert_eq!(input.object_lock_mode, None);
    assert_eq!(input.object_lock_retain_until_date, None);
    assert_eq!(input.expected_bucket_owner, None);
    let input = delete(&[("x-amz-bypass-governance-retention", "")], true).expect("decodes");
    assert_eq!(input.bypass_governance_retention, None);
}

#[test]
fn n_without_the_reading_an_empty_header_is_a_value_or_a_refusal() {
    let input = put(&[("content-type", ""), ("x-amz-tagging", ""), ("x-amz-object-lock-mode", "")], false).expect("decodes");
    assert_eq!(input.content_type.as_deref(), Some(""));
    assert_eq!(input.tagging.as_deref(), Some(""));
    assert_eq!(input.object_lock_mode.as_ref().map(|mode| mode.as_str()), Some(""));
    let error = put(&[("x-amz-object-lock-retain-until-date", "")], false).expect_err("not a timestamp");
    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    assert_eq!(error.member(), Some("ObjectLockRetainUntilDate"));
    delete(&[("x-amz-bypass-governance-retention", "")], false).expect_err("not a boolean");
}

#[test]
fn n_a_value_a_repeated_line_and_the_metadata_prefix_read_as_before() {
    let input = put(&[("content-type", "text/plain"), ("x-amz-meta-note", "")], true).expect("decodes");
    assert_eq!(input.content_type.as_deref(), Some("text/plain"));
    assert_eq!(
        input.metadata.get("note").map(String::as_str),
        Some(""),
        "an empty metadata value is kept"
    );
    let request = accepted("PUT", "/photos/key", &[("cache-control", ""), ("cache-control", "no-cache")]);
    let view = MetaView::of(&request, TargetKind::Object)
        .expect("view")
        .with_empty_headers_absent();
    assert_eq!(
        view.header("cache-control").as_deref(),
        Some(", no-cache"),
        "two lines are not one empty line"
    );
    assert!(view.has_header("cache-control"));
}

#[test]
fn presence_follows_the_reading() {
    let request = accepted(
        "GET",
        "/photos/key",
        &[("x-amz-expected-bucket-owner", ""), ("x-amz-request-payer", "requester")],
    );
    let plain = MetaView::of(&request, TargetKind::Object).expect("view");
    assert!(plain.has_header("x-amz-expected-bucket-owner"));
    assert_eq!(plain.header("x-amz-expected-bucket-owner").as_deref(), Some(""));
    assert!(!plain.empty_headers_absent());
    let absent = MetaView::of(&request, TargetKind::Object)
        .expect("view")
        .with_empty_headers_absent();
    assert!(absent.empty_headers_absent());
    assert!(!absent.has_header("x-amz-expected-bucket-owner"));
    assert_eq!(absent.header("x-amz-expected-bucket-owner"), None);
    assert!(absent.has_header("x-amz-request-payer"));
    assert!(!absent.has_header("x-amz-not-sent"));
    assert!(!absent.has_header("not a header name"));
}
