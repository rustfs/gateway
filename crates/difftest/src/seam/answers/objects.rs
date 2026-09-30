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

//! Seam answer rows for the object sub-resources, restores and part copies.
//!
//! Responsible for: rows that set every member of those operations' legacy outputs between them.
//! NOT responsible for: judging (`tests/seam_outputs.rs`). Upstream: none. Downstream: `super`.

use http::Method;

use crate::encode::placeholder_body;
use crate::request::RawRequest;
use crate::s3s::dto as legacy;

use super::super::samples::configs::{BUCKET_ACL, config};
use super::super::samples_document as document;
use super::{AnswerRow, BARE, VERSION_ID, XML, answer, legacy_document, named, same};

/// An instant with milliseconds, as the legacy DTO holds one.
fn at(secs: i64, millis: i64) -> legacy::Timestamp {
    let nanos = i128::from(secs) * 1_000_000_000 + i128::from(millis) * 1_000_000;
    legacy::Timestamp::from(
        time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
            .unwrap_or_else(|_| unreachable!("every fixture instant is in range")),
    )
}

fn etag(tag: &str) -> Option<legacy::ETag> {
    Some(legacy::ETag::Strong(tag.to_owned()))
}

fn text(value: &str) -> Option<String> {
    Some(value.to_owned())
}

const UPLOAD_ID: &str = crate::samples::UPLOAD_ID;

fn tag_set() -> Vec<legacy::Tag> {
    vec![legacy::Tag {
        key: Some("project".to_owned()),
        value: Some("gateway".to_owned()),
    }]
}

fn part_copy() -> RawRequest {
    RawRequest::new(Method::PUT, &format!("/bucket/k?partNumber=1&uploadId={UPLOAD_ID}")).header("x-amz-copy-source", "src/k")
}

fn sub_resources() -> Vec<AnswerRow> {
    vec![
        answer(
            "get-object-acl-every-member",
            RawRequest::get("/bucket/k?acl"),
            || {
                let policy: legacy::AccessControlPolicy = legacy_document(BUCKET_ACL);
                legacy::GetObjectAclOutput {
                    grants: policy.grants,
                    owner: policy.owner,
                    request_charged: Some(named("requester")),
                }
            },
            same(XML),
        ),
        answer(
            "get-object-attributes-every-member",
            RawRequest::get("/bucket/k?attributes")
                .header("x-amz-object-attributes", "ETag,Checksum,ObjectParts,StorageClass,ObjectSize"),
            || legacy::GetObjectAttributesOutput {
                checksum: Some(legacy::Checksum {
                    checksum_crc32: text("DUoRhQ=="),
                    checksum_type: Some(named("FULL_OBJECT")),
                    ..Default::default()
                }),
                delete_marker: Some(false),
                e_tag: etag("5d41402abc4b2a76b9719d911017c592"),
                last_modified: Some(at(1_767_225_600, 0)),
                object_parts: Some(legacy::GetObjectAttributesParts {
                    is_truncated: Some(true),
                    max_parts: Some(1),
                    next_part_number_marker: Some(2),
                    part_number_marker: Some(1),
                    parts: Some(vec![legacy::ObjectPart {
                        checksum_crc32: text("DUoRhQ=="),
                        part_number: Some(2),
                        size: Some(5),
                        ..Default::default()
                    }]),
                    total_parts_count: Some(3),
                }),
                object_size: Some(15),
                request_charged: Some(named("requester")),
                storage_class: Some(named("STANDARD")),
                version_id: text(VERSION_ID),
            },
            same(XML),
        ),
        answer(
            "get-object-legal-hold-every-member",
            RawRequest::get("/bucket/k?legal-hold"),
            || legacy::GetObjectLegalHoldOutput {
                legal_hold: Some(legacy::ObjectLockLegalHold {
                    status: Some(named("ON")),
                }),
            },
            same(XML),
        ),
        answer(
            "get-object-retention-every-member",
            RawRequest::get("/bucket/k?retention"),
            || legacy::GetObjectRetentionOutput {
                retention: Some(legacy::ObjectLockRetention {
                    mode: Some(named("GOVERNANCE")),
                    retain_until_date: Some(at(1_893_456_000, 0)),
                }),
            },
            same(XML),
        ),
        answer(
            "get-object-tagging-every-member",
            RawRequest::get("/bucket/k?tagging"),
            || legacy::GetObjectTaggingOutput {
                tag_set: tag_set(),
                version_id: text(VERSION_ID),
            },
            same(XML),
        ),
        answer(
            "get-object-torrent-every-member",
            RawRequest::get("/bucket/k?torrent"),
            || legacy::GetObjectTorrentOutput {
                body: Some(placeholder_body()),
                request_charged: Some(named("requester")),
            },
            same(BARE),
        ),
        answer(
            "put-object-acl-every-member",
            config("/bucket/k?acl", BUCKET_ACL),
            || legacy::PutObjectAclOutput {
                request_charged: Some(named("requester")),
            },
            same(BARE),
        ),
        answer(
            "put-object-legal-hold-every-member",
            config("/bucket/k?legal-hold", "<LegalHold><Status>ON</Status></LegalHold>"),
            || legacy::PutObjectLegalHoldOutput {
                request_charged: Some(named("requester")),
            },
            same(BARE),
        ),
        answer(
            "put-object-retention-every-member",
            config(
                "/bucket/k?retention",
                "<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2030-01-01T00:00:00.000Z</RetainUntilDate></Retention>",
            ),
            || legacy::PutObjectRetentionOutput {
                request_charged: Some(named("requester")),
            },
            same(BARE),
        ),
        answer(
            "put-object-tagging-every-member",
            config(
                "/bucket/k?tagging",
                "<Tagging><TagSet><Tag><Key>a</Key><Value>1</Value></Tag></TagSet></Tagging>",
            ),
            || legacy::PutObjectTaggingOutput {
                version_id: text(VERSION_ID),
            },
            same(BARE),
        ),
        answer(
            "delete-object-tagging-every-member",
            RawRequest::delete("/bucket/k?tagging"),
            || legacy::DeleteObjectTaggingOutput {
                version_id: text(VERSION_ID),
            },
            same(BARE),
        ),
    ]
}

fn restores_and_copies() -> Vec<AnswerRow> {
    vec![
        answer(
            "restore-object-every-member",
            document(
                Method::POST,
                "/bucket/k?restore",
                "<RestoreRequest><Days>2</Days><GlacierJobParameters><Tier>Bulk</Tier></GlacierJobParameters></RestoreRequest>",
            ),
            || legacy::RestoreObjectOutput {
                request_charged: Some(named("requester")),
                restore_output_path: text("out/p/"),
            },
            same(BARE),
        ),
        answer(
            "upload-part-copy-every-member",
            part_copy(),
            || legacy::UploadPartCopyOutput {
                bucket_key_enabled: Some(true),
                copy_part_result: Some(legacy::CopyPartResult {
                    checksum_crc32: text("DUoRhQ=="),
                    e_tag: etag("5d41402abc4b2a76b9719d911017c592"),
                    last_modified: Some(at(1_767_225_600, 0)),
                    ..Default::default()
                }),
                copy_source_version_id: text(VERSION_ID),
                request_charged: Some(named("requester")),
                sse_customer_algorithm: None,
                sse_customer_key_md5: None,
                ssekms_key_id: text("key-1"),
                server_side_encryption: Some(named("aws:kms")),
            },
            same(XML),
        ),
    ]
}

pub(super) fn rows() -> Vec<AnswerRow> {
    let mut rows = sub_resources();
    rows.extend(restores_and_copies());
    rows
}
