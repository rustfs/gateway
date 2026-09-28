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

//! The output matrix, object operations: s3s outputs a RustFS handler could return, the request
//! each answers, and exactly which registered differences each encoding must produce.
//!
//! Responsible for: the object samples (GetObject, HeadObject, PutObject, DeleteObject,
//! DeleteObjects, CopyObject) — every member set somewhere, a streaming body always the
//! deterministic placeholder — and the fixtures the other sample file shares.
//! NOT responsible for: listing, multipart and bucket samples (`outputs_more.rs`), or judging
//! (`tests/encoding.rs`).
//! Upstream: the library's sample type. Downstream: tests, the `encode-diff` runner, fuzzing.

use std::sync::Arc;

use http::Method;

use crate::s3s::dto as oracle;
use crate::{OracleOutput, OutputSample, PLACEHOLDER_LENGTH, RawRequest, placeholder_body};

/// A version id in the shape RustFS mints: a lowercase UUID.
pub const VERSION_ID: &str = "0f1e2d3c-4b5a-4978-8796-a5b4c3d2e1f0";
/// An upload id in the shape RustFS mints: unpadded base64url of `<deployment>.<UUID>`.
pub const UPLOAD_ID: &str = "ZjNhMWMyZDQtNWU2Zi00YTdiLThjOWQtMGUxZjJhM2I0YzVkLjdjMmU5ZjEwLTNiNGEtNGQ1ZS05ZjYwLTcxODI5M2E0YjVjNg";
/// A canonical owner id.
pub(crate) const OWNER_ID: &str = "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a";

/// The four headers the gateway stamps on every answer (`kd-encode-0001`..`0004`), followed by a
/// sample's own register ids.
macro_rules! stamped {
    ($($id:literal),* $(,)?) => {
        &["kd-encode-0001", "kd-encode-0002", "kd-encode-0003", "kd-encode-0004", $($id),*]
    };
}
pub(crate) use stamped;

/// One output sample and the register ids its findings must match, no more and no fewer.
#[derive(Clone, Debug)]
pub struct OutputRow {
    /// The output and the request it answers.
    pub sample: OutputSample,
    /// The register ids its encode diff produces.
    pub expect: &'static [&'static str],
}

pub(crate) fn row(
    name: &str,
    request: RawRequest,
    output: impl Fn() -> OracleOutput + Send + Sync + 'static,
    expect: &'static [&'static str],
) -> OutputRow {
    OutputRow {
        sample: OutputSample {
            name: name.to_owned(),
            request,
            output: Arc::new(output),
        },
        expect,
    }
}

/// An instant with milliseconds.
pub(crate) fn at(secs: i64, millis: i64) -> oracle::Timestamp {
    let nanos = i128::from(secs) * 1_000_000_000 + i128::from(millis) * 1_000_000;
    oracle::Timestamp::from(
        time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
            .unwrap_or_else(|_| unreachable!("every fixture instant is in range")),
    )
}

pub(crate) fn etag(tag: &str) -> Option<oracle::ETag> {
    Some(oracle::ETag::Strong(tag.to_owned()))
}

pub(crate) fn owner() -> Option<oracle::Owner> {
    Some(oracle::Owner {
        display_name: Some("owner".to_owned()),
        id: Some(OWNER_ID.to_owned()),
    })
}

pub(crate) fn text<T: From<String>>(value: &str) -> Option<T> {
    Some(T::from(value.to_owned()))
}

/// A value of the right width for every checksum algorithm, by s3s member suffix. The ones the
/// standard library computes are the digests of `hello world`.
pub(crate) const CHECKSUMS: [(&str, &str); 10] = [
    ("crc32", "DUoRhQ=="),
    ("crc32c", "AAECAw=="),
    ("crc64nvme", "AAECAwQFBgc="),
    ("md5", "XrY7u+Ae7tCTyyK7j1rNww=="),
    ("sha1", "Kq5sNclPz7QV2+lfQIuc6R7oRu0="),
    ("sha256", "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="),
    (
        "sha512",
        "MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxf9JlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw==",
    ),
    ("xxhash128", "AAECAwQFBgcICQoLDA0ODw=="),
    ("xxhash3", "AAECAwQFBgc="),
    ("xxhash64", "AAECAwQFBgc="),
];

fn get_object_full() -> oracle::GetObjectOutput {
    oracle::GetObjectOutput {
        accept_ranges: Some("bytes".to_owned()),
        body: Some(placeholder_body()),
        bucket_key_enabled: Some(true),
        cache_control: Some("no-cache".to_owned()),
        checksum_crc32: Some("DUoRhQ==".to_owned()),
        checksum_crc32c: Some("AAECAw==".to_owned()),
        checksum_crc64nvme: Some("AAECAwQFBgc=".to_owned()),
        checksum_md5: Some("XrY7u+Ae7tCTyyK7j1rNww==".to_owned()),
        checksum_sha1: Some("Kq5sNclPz7QV2+lfQIuc6R7oRu0=".to_owned()),
        checksum_sha256: Some("uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=".to_owned()),
        checksum_sha512: Some(
            "MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxf9JlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw==".to_owned(),
        ),
        checksum_type: text("FULL_OBJECT"),
        checksum_xxhash128: Some("AAECAwQFBgcICQoLDA0ODw==".to_owned()),
        checksum_xxhash3: Some("AAECAwQFBgc=".to_owned()),
        checksum_xxhash64: Some("AAECAwQFBgc=".to_owned()),
        content_disposition: Some("attachment".to_owned()),
        content_encoding: Some("identity".to_owned()),
        content_language: Some("en".to_owned()),
        content_length: Some(PLACEHOLDER_LENGTH),
        content_range: None,
        content_type: Some("text/plain".to_owned()),
        delete_marker: Some(false),
        e_tag: etag("5d41402abc4b2a76b9719d911017c592"),
        expiration: Some("expiry-date=\"Fri, 01 Jan 2027 00:00:00 GMT\", rule-id=\"r1\"".to_owned()),
        expires: Some("Thu, 01 Jan 2037 00:00:00 GMT".to_owned()),
        last_modified: Some(at(1_767_225_600, 0)),
        metadata: Some([("color".to_owned(), "blue".to_owned())].into_iter().collect()),
        missing_meta: Some(1),
        object_lock_legal_hold_status: text("ON"),
        object_lock_mode: text("GOVERNANCE"),
        object_lock_retain_until_date: Some(at(1_893_456_000, 0)),
        parts_count: Some(3),
        replication_status: text("COMPLETED"),
        request_charged: text("requester"),
        restore: Some("ongoing-request=\"false\"".to_owned()),
        sse_customer_algorithm: None,
        sse_customer_key_md5: None,
        ssekms_key_id: Some("key-1".to_owned()),
        server_side_encryption: text("aws:kms"),
        storage_class: text("STANDARD_IA"),
        tag_count: Some(2),
        version_id: Some(VERSION_ID.to_owned()),
        website_redirect_location: Some("/other".to_owned()),
    }
}

fn head_object_full() -> oracle::HeadObjectOutput {
    let oracle::GetObjectOutput {
        accept_ranges,
        body: _,
        bucket_key_enabled,
        cache_control,
        checksum_crc32,
        checksum_crc32c,
        checksum_crc64nvme,
        checksum_md5,
        checksum_sha1,
        checksum_sha256,
        checksum_sha512,
        checksum_type,
        checksum_xxhash128,
        checksum_xxhash3,
        checksum_xxhash64,
        content_disposition,
        content_encoding,
        content_language,
        content_length: _,
        content_range,
        content_type,
        delete_marker,
        e_tag,
        expiration,
        expires,
        last_modified,
        metadata,
        missing_meta,
        object_lock_legal_hold_status,
        object_lock_mode,
        object_lock_retain_until_date,
        parts_count,
        replication_status,
        request_charged,
        restore,
        sse_customer_algorithm,
        sse_customer_key_md5,
        ssekms_key_id,
        server_side_encryption,
        storage_class,
        tag_count,
        version_id,
        website_redirect_location,
    } = get_object_full();
    oracle::HeadObjectOutput {
        accept_ranges,
        archive_status: text("ARCHIVE_ACCESS"),
        bucket_key_enabled,
        cache_control,
        checksum_crc32,
        checksum_crc32c,
        checksum_crc64nvme,
        checksum_md5,
        checksum_sha1,
        checksum_sha256,
        checksum_sha512,
        checksum_type,
        checksum_xxhash128,
        checksum_xxhash3,
        checksum_xxhash64,
        content_disposition,
        content_encoding,
        content_language,
        content_length: Some(1024),
        content_range: content_range.or_else(|| Some("bytes 0-1023/2048".to_owned())),
        content_type,
        delete_marker,
        e_tag,
        expiration,
        expires,
        last_modified,
        metadata,
        missing_meta,
        object_lock_legal_hold_status,
        object_lock_mode,
        object_lock_retain_until_date,
        parts_count,
        replication_status,
        request_charged,
        restore,
        sse_customer_algorithm,
        sse_customer_key_md5,
        ssekms_key_id,
        server_side_encryption,
        storage_class,
        tag_count,
        version_id,
        website_redirect_location,
    }
}

pub(crate) fn sse_c() -> (Option<String>, Option<String>) {
    (Some("AES256".to_owned()), Some("hRasmdxgYDKV3nvbahU1MA==".to_owned()))
}

fn put_object(checksum: Option<(&'static str, &'static str)>) -> OracleOutput {
    let mut output = oracle::PutObjectOutput {
        bucket_key_enabled: Some(true),
        checksum_type: text("FULL_OBJECT"),
        e_tag: etag("5d41402abc4b2a76b9719d911017c592"),
        expiration: Some("expiry-date=\"Fri, 01 Jan 2027 00:00:00 GMT\", rule-id=\"r1\"".to_owned()),
        request_charged: text("requester"),
        ssekms_encryption_context: Some("e30=".to_owned()),
        ssekms_key_id: Some("key-1".to_owned()),
        server_side_encryption: text("aws:kms"),
        size: Some(11),
        version_id: Some(VERSION_ID.to_owned()),
        ..Default::default()
    };
    if let Some((algorithm, value)) = checksum {
        let slot = match algorithm {
            "crc32" => &mut output.checksum_crc32,
            "crc32c" => &mut output.checksum_crc32c,
            "crc64nvme" => &mut output.checksum_crc64nvme,
            "md5" => &mut output.checksum_md5,
            "sha1" => &mut output.checksum_sha1,
            "sha256" => &mut output.checksum_sha256,
            "sha512" => &mut output.checksum_sha512,
            "xxhash128" => &mut output.checksum_xxhash128,
            "xxhash3" => &mut output.checksum_xxhash3,
            _ => &mut output.checksum_xxhash64,
        };
        *slot = Some(value.to_owned());
    }
    OracleOutput::PutObject(output)
}

const DELETE_BODY: &[u8] = b"<Delete><Object><Key>a</Key></Object><Object><Key>b</Key></Object></Delete>";

fn copy(result: oracle::CopyObjectResult) -> OracleOutput {
    let (sse_customer_algorithm, sse_customer_key_md5) = sse_c();
    OracleOutput::CopyObject(oracle::CopyObjectOutput {
        bucket_key_enabled: Some(false),
        copy_object_result: Some(result),
        copy_source_version_id: Some(VERSION_ID.to_owned()),
        expiration: Some("expiry-date=\"Fri, 01 Jan 2027 00:00:00 GMT\", rule-id=\"r1\"".to_owned()),
        request_charged: text("requester"),
        sse_customer_algorithm,
        sse_customer_key_md5,
        ssekms_encryption_context: Some("e30=".to_owned()),
        ssekms_key_id: Some("key-1".to_owned()),
        server_side_encryption: text("AES256"),
        version_id: Some(VERSION_ID.to_owned()),
    })
}

fn copy_result() -> oracle::CopyObjectResult {
    oracle::CopyObjectResult {
        e_tag: etag("5d41402abc4b2a76b9719d911017c592"),
        last_modified: Some(at(1_767_225_600, 0)),
        ..Default::default()
    }
}

fn copy_request() -> RawRequest {
    RawRequest::new(Method::PUT, "/bkt/dst").header("x-amz-copy-source", "src/k")
}

/// The object rows.
#[allow(clippy::too_many_lines, reason = "one table, read row by row")]
pub(crate) fn rows() -> Vec<OutputRow> {
    let mut rows = vec![
        row(
            "get-object-full",
            RawRequest::get("/bkt/k"),
            || OracleOutput::GetObject(get_object_full()),
            stamped!(),
        ),
        row(
            "get-object-sse-c",
            super::sse(RawRequest::get("/bkt/k")),
            || {
                let (sse_customer_algorithm, sse_customer_key_md5) = sse_c();
                OracleOutput::GetObject(oracle::GetObjectOutput {
                    body: Some(placeholder_body()),
                    content_length: Some(PLACEHOLDER_LENGTH),
                    e_tag: etag("abc"),
                    sse_customer_algorithm,
                    sse_customer_key_md5,
                    ..Default::default()
                })
            },
            stamped!("kd-encode-0034"),
        ),
        row(
            "get-object-ranged",
            RawRequest::get("/bkt/k").header("range", "bytes=0-34"),
            || {
                OracleOutput::GetObject(oracle::GetObjectOutput {
                    body: Some(placeholder_body()),
                    content_length: Some(PLACEHOLDER_LENGTH),
                    content_range: Some(format!("bytes 0-{}/100", PLACEHOLDER_LENGTH - 1)),
                    e_tag: etag("abc"),
                    accept_ranges: Some("bytes".to_owned()),
                    ..Default::default()
                })
            },
            stamped!("kd-encode-0034", "kd-encode-0036"),
        ),
        row(
            "get-object-response-overrides",
            RawRequest::get("/bkt/k?response-content-type=application%2Fjson&response-cache-control=max-age%3D1"),
            || OracleOutput::GetObject(get_object_full()),
            stamped!(),
        ),
        row(
            "head-object-full",
            RawRequest::head("/bkt/k"),
            || OracleOutput::HeadObject(head_object_full()),
            stamped!(),
        ),
        row(
            "head-object-c1-metadata",
            RawRequest::head("/bkt/k"),
            || {
                OracleOutput::HeadObject(oracle::HeadObjectOutput {
                    content_length: Some(5),
                    e_tag: etag("abc"),
                    metadata: Some([("a".to_owned(), "\u{83}x".to_owned())].into_iter().collect()),
                    ..Default::default()
                })
            },
            stamped!("kd-encode-0035"),
        ),
        row(
            "head-object-encoded-word-lookalike-metadata",
            RawRequest::head("/bkt/k"),
            || {
                OracleOutput::HeadObject(oracle::HeadObjectOutput {
                    content_length: Some(5),
                    e_tag: etag("abc"),
                    metadata: Some([("w".to_owned(), "a=?b".to_owned())].into_iter().collect()),
                    ..Default::default()
                })
            },
            stamped!("kd-encode-0035", "kd-encode-0060"),
        ),
        row(
            "head-object-tab-metadata",
            RawRequest::head("/bkt/k"),
            || {
                OracleOutput::HeadObject(oracle::HeadObjectOutput {
                    content_length: Some(5),
                    e_tag: etag("abc"),
                    metadata: Some([("t".to_owned(), "a\tb".to_owned())].into_iter().collect()),
                    ..Default::default()
                })
            },
            stamped!("kd-encode-0035"),
        ),
        row(
            "head-object-long-utf8-metadata",
            RawRequest::head("/bkt/k"),
            || {
                OracleOutput::HeadObject(oracle::HeadObjectOutput {
                    content_length: Some(5),
                    e_tag: etag("abc"),
                    metadata: Some(
                        [("note".to_owned(), format!("{}91", "\u{fffd}".repeat(15)))]
                            .into_iter()
                            .collect(),
                    ),
                    ..Default::default()
                })
            },
            stamped!("kd-encode-0035", "kd-encode-0058"),
        ),
        row(
            "head-object-sse-c",
            super::sse(RawRequest::head("/bkt/k")),
            || {
                let (sse_customer_algorithm, sse_customer_key_md5) = sse_c();
                OracleOutput::HeadObject(oracle::HeadObjectOutput {
                    content_length: Some(5),
                    e_tag: etag("abc"),
                    sse_customer_algorithm,
                    sse_customer_key_md5,
                    ..Default::default()
                })
            },
            stamped!("kd-encode-0035"),
        ),
        row("put-object", RawRequest::put("/bkt/k", b"hello world"), || put_object(None), stamped!()),
        row(
            "put-object-sse-c",
            super::sse(RawRequest::put("/bkt/k", b"hello world")),
            || {
                let (sse_customer_algorithm, sse_customer_key_md5) = sse_c();
                OracleOutput::PutObject(oracle::PutObjectOutput {
                    e_tag: etag("abc"),
                    sse_customer_algorithm,
                    sse_customer_key_md5,
                    ..Default::default()
                })
            },
            stamped!(),
        ),
        row(
            "delete-object",
            RawRequest::delete("/bkt/k"),
            || {
                OracleOutput::DeleteObject(oracle::DeleteObjectOutput {
                    delete_marker: Some(true),
                    version_id: Some(VERSION_ID.to_owned()),
                    request_charged: text("requester"),
                })
            },
            stamped!(),
        ),
        row(
            "delete-objects",
            RawRequest::post("/bkt?delete", DELETE_BODY).header("content-md5", "gnFQWv8HmHVEQ7mTrck6JQ=="),
            || {
                OracleOutput::DeleteObjects(oracle::DeleteObjectsOutput {
                    deleted: Some(vec![oracle::DeletedObject {
                        delete_marker: Some(true),
                        delete_marker_version_id: Some(VERSION_ID.to_owned()),
                        key: Some("a".to_owned()),
                        version_id: Some(VERSION_ID.to_owned()),
                    }]),
                    errors: Some(vec![oracle::Error {
                        code: Some("AccessDenied".to_owned()),
                        key: Some("b".to_owned()),
                        message: Some("Access Denied".to_owned()),
                        version_id: Some(VERSION_ID.to_owned()),
                    }]),
                    request_charged: text("requester"),
                })
            },
            stamped!("kd-encode-0005", "kd-encode-0008", "kd-encode-0009"),
        ),
        row(
            "copy-object",
            copy_request(),
            || copy(copy_result()),
            stamped!("kd-encode-0005", "kd-encode-0006", "kd-encode-0033"),
        ),
        row(
            "copy-object-with-checksum",
            copy_request(),
            || {
                copy(oracle::CopyObjectResult {
                    checksum_crc32: Some("DUoRhQ==".to_owned()),
                    ..copy_result()
                })
            },
            &["kd-encode-0042"],
        ),
        row(
            "copy-object-with-checksum-type",
            copy_request(),
            || {
                copy(oracle::CopyObjectResult {
                    checksum_type: text("FULL_OBJECT"),
                    ..copy_result()
                })
            },
            &["kd-encode-0047"],
        ),
    ];
    for (algorithm, value) in CHECKSUMS {
        rows.push(row(
            &format!("put-object-checksum-{algorithm}"),
            RawRequest::put("/bkt/k", b"hello world"),
            move || put_object(Some((algorithm, value))),
            stamped!(),
        ));
    }
    rows
}
