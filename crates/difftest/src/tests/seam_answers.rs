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

//! Judges how a RustFS answer's own response headers reach the wire through the seam
//! (rustfs/gateway#1076, item 2).
//!
//! Responsible for: every kind of header a RustFS app body sets beside its output
//! (rustfs/rustfs `1e7065101d`: `Accept-Ranges` on every GetObject, bucket CORS on GetObject and
//! HeadObject, additional checksums, restore, tagging count, Object Lock and replication status on
//! HeadObject, SSE-C on CompleteMultipartUpload, the on-demand-migration markers), each written by
//! both stacks as the same header lines, the one replacing an output member's header included.
//! NOT responsible for: how either stack encodes the output members themselves (the encode diff).
//! Upstream: `crate::seam`. Downstream: none.

use http::{HeaderMap, HeaderName, HeaderValue};

use crate::encode::{PLACEHOLDER_LENGTH, WireAnswer, placeholder_body};
use crate::request::RawRequest;
use crate::s3s::dto as legacy;
use crate::seam::SeamDiffer;

fn headers(lines: &[(&'static str, &'static str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in lines {
        map.append(HeaderName::from_static(name), HeaderValue::from_static(value));
    }
    map
}

fn lines(answer: &WireAnswer, name: &str) -> Vec<Vec<u8>> {
    answer
        .headers
        .iter()
        .filter(|(present, _)| present == name)
        .map(|(_, value)| value.clone())
        .collect()
}

/// Both stacks answer `request` with the same RustFS answer; every header the body set is written
/// as the same lines, with the same status.
fn same_lines<T: Send + 'static>(request: &RawRequest, extra: &[(&'static str, &'static str)], build: impl Fn() -> T) {
    let differ = SeamDiffer::new().expect("both stacks assemble");
    let (gateway, legacy) = differ
        .answer(request, || (build(), headers(extra)))
        .expect("both stacks answer");
    assert_eq!(gateway.status, legacy.status, "gateway {gateway:#?}\nlegacy {legacy:#?}");
    for (name, _) in extra {
        assert_eq!(
            lines(&gateway, name),
            lines(&legacy, name),
            "{name}: gateway {gateway:#?}\nlegacy {legacy:#?}"
        );
        assert!(!lines(&gateway, name).is_empty(), "{name} was not written");
    }
}

fn got() -> legacy::GetObjectOutput {
    legacy::GetObjectOutput {
        accept_ranges: Some("bytes".to_owned()),
        body: Some(placeholder_body()),
        content_length: Some(PLACEHOLDER_LENGTH),
        e_tag: Some(legacy::ETag::Strong("abc".to_owned())),
        ..Default::default()
    }
}

#[test]
fn every_get_objects_accept_ranges_crosses_once_as_rustfs_writes_it() {
    same_lines(&RawRequest::get("/bucket/k"), &[("accept-ranges", "bytes")], got);
}

#[test]
fn bucket_cors_additional_checksums_and_the_migration_marker_cross_on_a_get() {
    same_lines(
        &RawRequest::get("/bucket/k").header("origin", "https://a.example"),
        &[
            ("accept-ranges", "bytes"),
            ("access-control-allow-origin", "https://a.example"),
            ("vary", "Origin"),
            ("vary", "Access-Control-Request-Method"),
            ("access-control-allow-credentials", "true"),
            ("access-control-expose-headers", "ETag"),
            ("x-amz-checksum-xxhash64", "AAAAAAAAAAA="),
            ("x-rustfs-on-demand-migration", "source"),
        ],
        got,
    );
}

#[test]
fn a_header_the_body_sets_replaces_the_output_members_value_as_on_the_legacy_wire() {
    same_lines(&RawRequest::get("/bucket/k"), &[("accept-ranges", "none")], got);
    same_lines(&RawRequest::get("/bucket/k"), &[("x-amz-meta-color", "red")], || {
        legacy::GetObjectOutput {
            metadata: Some(
                [("color".to_owned(), "blue".to_owned()), ("size".to_owned(), "big".to_owned())]
                    .into_iter()
                    .collect(),
            ),
            ..got()
        }
    });
}

#[test]
fn restore_tagging_object_lock_and_replication_status_cross_on_a_head() {
    let restore = "ongoing-request=\"false\", expiry-date=\"Fri, 02 Jan 2026 00:00:00 GMT\"";
    same_lines(
        &RawRequest::head("/bucket/k"),
        &[
            (
                "x-amz-restore",
                "ongoing-request=\"false\", expiry-date=\"Fri, 02 Jan 2026 00:00:00 GMT\"",
            ),
            ("x-amz-restore-request-date", "Thu, 01 Jan 2026 00:00:00 GMT"),
            ("x-amz-restore-expiry-days", "1"),
            ("x-amz-tagging-count", "2"),
            ("x-amz-object-lock-mode", "GOVERNANCE"),
            ("x-amz-object-lock-retain-until-date", "2030-01-01T00:00:00Z"),
            ("x-amz-object-lock-legal-hold", "ON"),
            ("x-amz-replication-status", "COMPLETED"),
        ],
        || legacy::HeadObjectOutput {
            content_length: Some(5),
            e_tag: Some(legacy::ETag::Strong("abc".to_owned())),
            restore: Some(restore.to_owned()),
            ..Default::default()
        },
    );
}

#[test]
fn an_additional_checksum_crosses_on_a_put_and_a_part() {
    same_lines(
        &RawRequest::put("/bucket/k", b"hello"),
        &[("x-amz-checksum-xxhash3", "AAAAAAAAAAA="), ("x-amz-checksum-sha512", "AAAA")],
        || legacy::PutObjectOutput {
            e_tag: Some(legacy::ETag::Strong("abc".to_owned())),
            ..Default::default()
        },
    );
    same_lines(
        &RawRequest::put(&format!("/bucket/k?partNumber=1&uploadId={}", crate::samples::UPLOAD_ID), b"hello"),
        &[("x-amz-checksum-xxhash64", "AAAAAAAAAAA=")],
        || legacy::UploadPartOutput {
            e_tag: Some(legacy::ETag::Strong("abc".to_owned())),
            ..Default::default()
        },
    );
}

#[test]
fn a_completed_uploads_customer_key_headers_cross() {
    let body = b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"e1\"</ETag></Part></CompleteMultipartUpload>";
    same_lines(
        &RawRequest::post(&format!("/bucket/k?uploadId={}", crate::samples::UPLOAD_ID), body),
        &[
            ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            ("x-amz-server-side-encryption-customer-key-md5", "hRasmdxgYDKV3nvbahU1MA=="),
        ],
        || legacy::CompleteMultipartUploadOutput {
            bucket: Some("bucket".to_owned()),
            key: Some("k".to_owned()),
            e_tag: Some(legacy::ETag::Strong("abc-1".to_owned())),
            ..Default::default()
        },
    );
}

#[test]
fn a_listings_migration_marker_crosses() {
    same_lines(
        &RawRequest::get("/bucket?list-type=2"),
        &[("x-rustfs-on-demand-migration-list", "local_only")],
        || legacy::ListObjectsV2Output {
            name: Some("bucket".to_owned()),
            prefix: Some(String::new()),
            max_keys: Some(1000),
            key_count: Some(0),
            is_truncated: Some(false),
            ..Default::default()
        },
    );
}

#[test]
fn n_an_answer_without_its_own_headers_crosses_unchanged() {
    same_lines(&RawRequest::get("/bucket/k"), &[], got);
    let differ = SeamDiffer::new().expect("both stacks assemble");
    let (gateway, _) = differ
        .answer(&RawRequest::get("/bucket/k"), || (got(), HeaderMap::new()))
        .expect("answers");
    assert_eq!(
        lines(&gateway, "accept-ranges"),
        [b"bytes".to_vec()],
        "the output member still writes its header"
    );
}

#[test]
fn n_a_header_the_gateway_owns_is_refused_not_written() {
    let differ = SeamDiffer::new().expect("both stacks assemble");
    let (gateway, legacy) = differ
        .answer(&RawRequest::get("/bucket/k"), || (got(), headers(&[("x-amz-request-id", "FORGED")])))
        .expect("answers");
    assert_eq!(gateway.status, 500, "{gateway:#?}");
    assert!(!lines(&gateway, "x-amz-request-id").contains(&b"FORGED".to_vec()), "{gateway:#?}");
    assert_eq!(legacy.status, 200);
}

#[test]
fn n_a_body_header_naming_no_member_leaves_every_member_header_written() {
    let differ = SeamDiffer::new().expect("both stacks assemble");
    let (gateway, legacy) = differ
        .answer(&RawRequest::get("/bucket/k"), || {
            (got(), headers(&[("x-rustfs-on-demand-migration", "source")]))
        })
        .expect("answers");
    for name in ["accept-ranges", "etag", "x-rustfs-on-demand-migration"] {
        assert_eq!(lines(&gateway, name), lines(&legacy, name), "{name}");
        assert_eq!(lines(&gateway, name).len(), 1, "{name}: {gateway:#?}");
    }
}
