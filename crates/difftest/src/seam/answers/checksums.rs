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

//! Seam answer rows for the nested checksum members, one row per algorithm, and the few nested
//! members the encode matrix leaves unset.
//!
//! Responsible for: every algorithm's member of the object attributes' checksum and parts, a
//! listed part and a copied part, the customer-key headers of a part copy, and a listed version's
//! restore expiry.
//! NOT responsible for: judging (`tests/seam_outputs.rs`). Upstream: none. Downstream: `super`.

use http::Method;

use crate::request::RawRequest;
use crate::s3s::dto as legacy;
use crate::samples::{CHECKSUMS, UPLOAD_ID};

use super::{AnswerRow, VERSION_ID, XML, XML_ETAG, answer, differs, named};

/// `target` with its member named after `algorithm` (`checksum_<algorithm>`) set to `value`.
macro_rules! with_checksum {
    ($target:expr, $algorithm:expr, $value:expr) => {{
        let mut target = $target;
        let value = Some($value.to_owned());
        match $algorithm {
            "crc32" => target.checksum_crc32 = value,
            "crc32c" => target.checksum_crc32c = value,
            "crc64nvme" => target.checksum_crc64nvme = value,
            "md5" => target.checksum_md5 = value,
            "sha1" => target.checksum_sha1 = value,
            "sha256" => target.checksum_sha256 = value,
            "sha512" => target.checksum_sha512 = value,
            "xxhash128" => target.checksum_xxhash128 = value,
            "xxhash3" => target.checksum_xxhash3 = value,
            "xxhash64" => target.checksum_xxhash64 = value,
            other => unreachable!("no checksum member for {other}"),
        }
        target
    }};
}

fn at(secs: i64) -> legacy::Timestamp {
    legacy::Timestamp::from(time::OffsetDateTime::from_unix_timestamp(secs).unwrap_or_else(|_| unreachable!("in range")))
}

fn etag(tag: &str) -> Option<legacy::ETag> {
    Some(legacy::ETag::Strong(tag.to_owned()))
}

fn attributes(algorithm: &'static str, value: &'static str) -> legacy::GetObjectAttributesOutput {
    legacy::GetObjectAttributesOutput {
        checksum: Some(with_checksum!(legacy::Checksum::default(), algorithm, value)),
        e_tag: etag("5d41402abc4b2a76b9719d911017c592"),
        object_parts: Some(legacy::GetObjectAttributesParts {
            is_truncated: Some(false),
            max_parts: Some(1000),
            next_part_number_marker: Some(1),
            part_number_marker: Some(0),
            parts: Some(vec![with_checksum!(
                legacy::ObjectPart {
                    part_number: Some(1),
                    size: Some(5),
                    ..Default::default()
                },
                algorithm,
                value
            )]),
            total_parts_count: Some(1),
        }),
        object_size: Some(5),
        ..Default::default()
    }
}

fn listed_parts(algorithm: &'static str, value: &'static str) -> legacy::ListPartsOutput {
    legacy::ListPartsOutput {
        bucket: Some("bucket".to_owned()),
        key: Some("k".to_owned()),
        upload_id: Some(UPLOAD_ID.to_owned()),
        max_parts: Some(1000),
        is_truncated: Some(false),
        part_number_marker: Some(0),
        parts: Some(vec![with_checksum!(
            legacy::Part {
                e_tag: etag("7ac66c0f148de9519b8bd264312c4d64"),
                last_modified: Some(at(1_767_225_600)),
                part_number: Some(1),
                size: Some(5_242_880),
                ..Default::default()
            },
            algorithm,
            value
        )]),
        ..Default::default()
    }
}

fn copied_part(algorithm: &'static str, value: &'static str) -> legacy::UploadPartCopyOutput {
    legacy::UploadPartCopyOutput {
        copy_part_result: Some(with_checksum!(
            legacy::CopyPartResult {
                e_tag: etag("5d41402abc4b2a76b9719d911017c592"),
                last_modified: Some(at(1_767_225_600)),
                ..Default::default()
            },
            algorithm,
            value
        )),
        ..Default::default()
    }
}

fn part_copy() -> RawRequest {
    RawRequest::new(Method::PUT, &format!("/bucket/k?partNumber=1&uploadId={UPLOAD_ID}")).header("x-amz-copy-source", "src/k")
}

/// [`XML_ETAG`], the listing's child order (`kd-encode-0029`) and a CRC32 part's (`kd-encode-0032`).
const LISTED: &[&str] = &[
    "kd-encode-0001",
    "kd-encode-0002",
    "kd-encode-0003",
    "kd-encode-0004",
    "kd-encode-0005",
    "kd-encode-0006",
    "kd-encode-0029",
    "kd-encode-0032",
];

/// [`LISTED`] without the CRC32 part's order.
const LISTED_ELSEWHERE: &[&str] = &[
    "kd-encode-0001",
    "kd-encode-0002",
    "kd-encode-0003",
    "kd-encode-0004",
    "kd-encode-0005",
    "kd-encode-0006",
    "kd-encode-0029",
];

/// [`XML_ETAG`] and a version listing's child orders (`kd-encode-0018`, `kd-encode-0021`).
const VERSIONS: &[&str] = &[
    "kd-encode-0001",
    "kd-encode-0002",
    "kd-encode-0003",
    "kd-encode-0004",
    "kd-encode-0005",
    "kd-encode-0006",
    "kd-encode-0018",
    "kd-encode-0021",
];

fn per_algorithm() -> Vec<AnswerRow> {
    let mut rows = Vec::new();
    for (algorithm, value) in CHECKSUMS {
        rows.push(answer(
            format!("get-object-attributes-checksum-{algorithm}"),
            RawRequest::get("/bucket/k?attributes").header("x-amz-object-attributes", "ETag,Checksum,ObjectParts,ObjectSize"),
            move || attributes(algorithm, value),
            differs(XML, &["sa-0009"], &[]),
        ));
        // The register pins a part's child order with a CRC32 member (`kd-encode-0032`); a part
        // with another algorithm's member is the same reorder, named by its path here.
        let listed = if algorithm == "crc32" {
            differs(LISTED, &[], &[])
        } else {
            differs(LISTED_ELSEWHERE, &[], &["ListPartsResult/Part"])
        };
        rows.push(answer(
            format!("list-parts-checksum-{algorithm}"),
            RawRequest::get(&format!("/bucket/k?uploadId={UPLOAD_ID}")),
            move || listed_parts(algorithm, value),
            listed,
        ));
        rows.push(answer(
            format!("upload-part-copy-checksum-{algorithm}"),
            part_copy(),
            move || copied_part(algorithm, value),
            differs(XML_ETAG, &["sa-0008"], &["CopyPartResult"]),
        ));
    }
    rows
}

fn others() -> Vec<AnswerRow> {
    vec![
        answer(
            "upload-part-copy-customer-key",
            crate::samples::sse(part_copy()),
            || legacy::UploadPartCopyOutput {
                copy_part_result: Some(legacy::CopyPartResult {
                    e_tag: etag("5d41402abc4b2a76b9719d911017c592"),
                    last_modified: Some(at(1_767_225_600)),
                    ..Default::default()
                }),
                sse_customer_algorithm: Some("AES256".to_owned()),
                sse_customer_key_md5: Some("hRasmdxgYDKV3nvbahU1MA==".to_owned()),
                ..Default::default()
            },
            differs(XML_ETAG, &["sa-0008"], &[]),
        ),
        answer(
            "list-object-versions-restore-expiry",
            RawRequest::get("/bucket?versions"),
            || legacy::ListObjectVersionsOutput {
                name: Some("bucket".to_owned()),
                prefix: Some(String::new()),
                key_marker: Some(String::new()),
                version_id_marker: Some(String::new()),
                max_keys: Some(1000),
                is_truncated: Some(false),
                versions: Some(vec![legacy::ObjectVersion {
                    e_tag: etag("abc"),
                    is_latest: Some(true),
                    key: Some("k".to_owned()),
                    last_modified: Some(at(1_767_225_600)),
                    restore_status: Some(legacy::RestoreStatus {
                        is_restore_in_progress: Some(false),
                        restore_expiry_date: Some(at(1_767_312_000)),
                    }),
                    size: Some(3),
                    storage_class: Some(named("STANDARD")),
                    version_id: Some(VERSION_ID.to_owned()),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            differs(VERSIONS, &[], &[]),
        ),
    ]
}

pub(super) fn rows() -> Vec<AnswerRow> {
    let mut rows = per_algorithm();
    rows.extend(others());
    rows
}
