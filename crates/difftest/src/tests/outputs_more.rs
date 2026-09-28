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

//! The output matrix, listing, multipart and bucket operations.
//!
//! Responsible for: the samples of ListObjects, ListObjectsV2, ListObjectVersions,
//! ListMultipartUploads, ListBuckets, the multipart family and the bucket operations — every
//! member set somewhere, lists full and empty, `encoding-type=url` with a key that needs it.
//! NOT responsible for: object samples (`outputs.rs`), or judging (`encoding.rs`).
//! Upstream: the fixtures in `outputs.rs`. Downstream: `encoding.rs`.

use http::Method;

use super::outputs::{CHECKSUMS, OutputRow, UPLOAD_ID, VERSION_ID, at, etag, owner, row, sse_c, stamped, text};
use crate::s3s::dto as oracle;
use crate::{OracleOutput, RawRequest};

fn object(key: &str) -> oracle::Object {
    oracle::Object {
        checksum_algorithm: Some(vec![oracle::ChecksumAlgorithm::from("CRC32".to_owned())]),
        checksum_type: text("FULL_OBJECT"),
        e_tag: etag("5d41402abc4b2a76b9719d911017c592"),
        key: Some(key.to_owned()),
        last_modified: Some(at(1_767_225_600, 123)),
        owner: owner(),
        restore_status: Some(oracle::RestoreStatus {
            is_restore_in_progress: Some(false),
            restore_expiry_date: Some(at(1_767_312_000, 0)),
        }),
        size: Some(5),
        storage_class: text("STANDARD"),
    }
}

fn prefix(value: &str) -> oracle::CommonPrefix {
    oracle::CommonPrefix {
        prefix: Some(value.to_owned()),
    }
}

fn list_v2(key: &str) -> OracleOutput {
    OracleOutput::ListObjectsV2(oracle::ListObjectsV2Output {
        name: Some("bkt".to_owned()),
        prefix: Some("p/".to_owned()),
        max_keys: Some(2),
        key_count: Some(2),
        continuation_token: Some("tok".to_owned()),
        is_truncated: Some(true),
        next_continuation_token: Some("next".to_owned()),
        contents: Some(vec![object(key), object("p/b")]),
        common_prefixes: Some(vec![prefix("p/c/")]),
        delimiter: Some("/".to_owned()),
        encoding_type: None,
        start_after: Some("p/0".to_owned()),
        request_charged: text("requester"),
    })
}

/// A listing with `encoding` set holds what RustFS writes for it: a delimiter it already encoded.
fn delimiter(encoding: Option<&str>) -> Option<String> {
    Some(if encoding.is_some() { "%2F" } else { "/" }.to_owned())
}

fn list_v1(encoding: Option<&str>) -> OracleOutput {
    OracleOutput::ListObjects(oracle::ListObjectsOutput {
        name: Some("bkt".to_owned()),
        prefix: Some(String::new()),
        marker: Some(String::new()),
        next_marker: Some("b".to_owned()),
        max_keys: Some(1),
        is_truncated: Some(true),
        contents: Some(vec![object("a")]),
        common_prefixes: encoding.is_none().then(|| vec![prefix("c/")]),
        delimiter: delimiter(encoding),
        encoding_type: encoding.and_then(text),
        request_charged: text("requester"),
    })
}

fn list_versions(encoding: Option<&str>) -> OracleOutput {
    OracleOutput::ListObjectVersions(oracle::ListObjectVersionsOutput {
        name: Some("bkt".to_owned()),
        prefix: Some(String::new()),
        key_marker: Some(String::new()),
        version_id_marker: Some(String::new()),
        next_key_marker: Some("k".to_owned()),
        next_version_id_marker: Some(VERSION_ID.to_owned()),
        max_keys: Some(1000),
        is_truncated: Some(false),
        delimiter: delimiter(encoding),
        encoding_type: encoding.and_then(text),
        common_prefixes: encoding.is_none().then(|| vec![prefix("d/")]),
        request_charged: text("requester"),
        versions: Some(vec![oracle::ObjectVersion {
            checksum_algorithm: Some(vec![oracle::ChecksumAlgorithm::from("CRC32".to_owned())]),
            checksum_type: text("FULL_OBJECT"),
            e_tag: etag("abc"),
            is_latest: Some(true),
            key: Some("k".to_owned()),
            last_modified: Some(at(1_767_225_600, 0)),
            owner: owner(),
            restore_status: Some(oracle::RestoreStatus {
                is_restore_in_progress: Some(true),
                restore_expiry_date: None,
            }),
            size: Some(3),
            storage_class: text("STANDARD"),
            version_id: Some(VERSION_ID.to_owned()),
        }]),
        delete_markers: Some(vec![oracle::DeleteMarkerEntry {
            is_latest: Some(false),
            key: Some("k".to_owned()),
            last_modified: Some(at(1_767_225_500, 0)),
            owner: owner(),
            version_id: Some("null".to_owned()),
        }]),
    })
}

fn list_uploads(encoding: Option<&str>) -> OracleOutput {
    OracleOutput::ListMultipartUploads(oracle::ListMultipartUploadsOutput {
        bucket: Some("bkt".to_owned()),
        key_marker: Some(String::new()),
        upload_id_marker: Some(String::new()),
        next_key_marker: Some("k".to_owned()),
        next_upload_id_marker: Some(UPLOAD_ID.to_owned()),
        prefix: Some(String::new()),
        delimiter: delimiter(encoding),
        encoding_type: encoding.and_then(text),
        max_uploads: Some(1000),
        is_truncated: Some(false),
        common_prefixes: encoding.is_none().then(|| vec![prefix("u/")]),
        request_charged: text("requester"),
        uploads: Some(vec![oracle::MultipartUpload {
            checksum_algorithm: text("CRC32"),
            checksum_type: text("COMPOSITE"),
            initiated: Some(at(1_767_225_600, 0)),
            initiator: Some(oracle::Initiator {
                display_name: Some("owner".to_owned()),
                id: Some("id".to_owned()),
            }),
            key: Some("k".to_owned()),
            owner: owner(),
            storage_class: text("STANDARD"),
            upload_id: Some(UPLOAD_ID.to_owned()),
        }]),
    })
}

fn create_mpu() -> OracleOutput {
    let (sse_customer_algorithm, sse_customer_key_md5) = sse_c();
    OracleOutput::CreateMultipartUpload(oracle::CreateMultipartUploadOutput {
        abort_date: Some(at(1_767_312_000, 0)),
        abort_rule_id: Some("abort-rule".to_owned()),
        bucket: Some("bkt".to_owned()),
        bucket_key_enabled: Some(true),
        checksum_algorithm: text("CRC32C"),
        checksum_type: text("COMPOSITE"),
        key: Some("k".to_owned()),
        request_charged: text("requester"),
        sse_customer_algorithm,
        sse_customer_key_md5,
        ssekms_encryption_context: Some("e30=".to_owned()),
        ssekms_key_id: Some("key-1".to_owned()),
        server_side_encryption: text("aws:kms"),
        upload_id: Some(UPLOAD_ID.to_owned()),
    })
}

fn upload_part(checksum: Option<(&'static str, &'static str)>) -> OracleOutput {
    let (sse_customer_algorithm, sse_customer_key_md5) = sse_c();
    let mut output = oracle::UploadPartOutput {
        bucket_key_enabled: Some(true),
        e_tag: etag("7ac66c0f148de9519b8bd264312c4d64"),
        request_charged: text("requester"),
        sse_customer_algorithm,
        sse_customer_key_md5,
        ssekms_key_id: Some("key-1".to_owned()),
        server_side_encryption: text("aws:kms"),
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
    OracleOutput::UploadPart(output)
}

fn complete() -> oracle::CompleteMultipartUploadOutput {
    oracle::CompleteMultipartUploadOutput {
        bucket: Some("bkt".to_owned()),
        bucket_key_enabled: Some(true),
        checksum_crc32: Some("DUoRhQ==-2".to_owned()),
        checksum_crc32c: Some("AAECAw==-2".to_owned()),
        checksum_crc64nvme: Some("AAECAwQFBgc=".to_owned()),
        checksum_md5: Some("XrY7u+Ae7tCTyyK7j1rNww==-2".to_owned()),
        checksum_sha1: Some("Kq5sNclPz7QV2+lfQIuc6R7oRu0=-2".to_owned()),
        checksum_sha256: Some("uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=-2".to_owned()),
        checksum_sha512: Some("AAECAw==-2".to_owned()),
        checksum_type: text("COMPOSITE"),
        checksum_xxhash128: Some("AAECAwQFBgcICQoLDA0ODw==-2".to_owned()),
        checksum_xxhash3: Some("AAECAwQFBgc=-2".to_owned()),
        checksum_xxhash64: Some("AAECAwQFBgc=-2".to_owned()),
        e_tag: etag("3858f62230ac3c915f300c664312c11f-2"),
        expiration: Some("expiry-date=\"Fri, 01 Jan 2027 00:00:00 GMT\", rule-id=\"r1\"".to_owned()),
        key: Some("k".to_owned()),
        location: Some("http://difftest.invalid/bkt/k".to_owned()),
        request_charged: text("requester"),
        ssekms_key_id: Some("key-1".to_owned()),
        server_side_encryption: text("aws:kms"),
        version_id: Some(VERSION_ID.to_owned()),
        future: None,
    }
}

fn list_parts() -> OracleOutput {
    OracleOutput::ListParts(oracle::ListPartsOutput {
        abort_date: Some(at(1_767_312_000, 0)),
        abort_rule_id: Some("abort-rule".to_owned()),
        bucket: Some("bkt".to_owned()),
        checksum_algorithm: text("CRC32"),
        checksum_type: text("COMPOSITE"),
        key: Some("k".to_owned()),
        upload_id: Some(UPLOAD_ID.to_owned()),
        max_parts: Some(1000),
        is_truncated: Some(false),
        part_number_marker: Some(0),
        next_part_number_marker: Some(1),
        parts: Some(vec![oracle::Part {
            checksum_crc32: Some("DUoRhQ==".to_owned()),
            e_tag: etag("7ac66c0f148de9519b8bd264312c4d64"),
            last_modified: Some(at(1_767_225_600, 0)),
            part_number: Some(1),
            size: Some(5_242_880),
            ..Default::default()
        }]),
        storage_class: text("STANDARD"),
        initiator: Some(oracle::Initiator {
            display_name: Some("owner".to_owned()),
            id: Some("id".to_owned()),
        }),
        owner: owner(),
        request_charged: text("requester"),
    })
}

/// A HeadBucket output with its region and one more member set by `set`.
fn head_bucket(set: impl FnOnce(&mut oracle::HeadBucketOutput)) -> OracleOutput {
    let mut output = oracle::HeadBucketOutput {
        bucket_region: Some("us-east-1".to_owned()),
        ..Default::default()
    };
    set(&mut output);
    OracleOutput::HeadBucket(output)
}

const COMPLETE_BODY: &[u8] =
    b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"e1\"</ETag></Part></CompleteMultipartUpload>";

/// The listing, multipart and bucket rows.
#[allow(clippy::too_many_lines, reason = "one table, read row by row")]
pub(crate) fn rows() -> Vec<OutputRow> {
    let mut rows = vec![
        row(
            "list-objects-v2-full",
            RawRequest::get("/bkt?list-type=2"),
            || list_v2("p/a"),
            stamped!("kd-encode-0005", "kd-encode-0006", "kd-encode-0026", "kd-encode-0027", "kd-encode-0028"),
        ),
        row(
            "list-objects-v2-url",
            RawRequest::get("/bkt?list-type=2&encoding-type=url"),
            || {
                // What RustFS returns: it URL-encodes listing values itself when asked to.
                OracleOutput::ListObjectsV2(oracle::ListObjectsV2Output {
                    name: Some("bkt".to_owned()),
                    prefix: Some(String::new()),
                    max_keys: Some(1000),
                    key_count: Some(1),
                    is_truncated: Some(false),
                    contents: Some(vec![object("a%20b")]),
                    delimiter: Some("%2F".to_owned()),
                    encoding_type: text("url"),
                    ..Default::default()
                })
            },
            stamped!(
                "kd-encode-0005",
                "kd-encode-0006",
                "kd-encode-0026",
                "kd-encode-0027",
                "kd-encode-0028",
                "kd-encode-0037",
                "kd-encode-0038"
            ),
        ),
        row(
            "list-objects-v2-empty",
            RawRequest::get("/bkt?list-type=2"),
            || {
                OracleOutput::ListObjectsV2(oracle::ListObjectsV2Output {
                    name: Some("bkt".to_owned()),
                    prefix: Some(String::new()),
                    max_keys: Some(1000),
                    key_count: Some(0),
                    is_truncated: Some(false),
                    ..Default::default()
                })
            },
            stamped!("kd-encode-0005", "kd-encode-0026"),
        ),
        row(
            "list-objects-full",
            RawRequest::get("/bkt"),
            || list_v1(None),
            stamped!("kd-encode-0005", "kd-encode-0006", "kd-encode-0023", "kd-encode-0024", "kd-encode-0025"),
        ),
        row(
            "list-objects-url",
            RawRequest::get("/bkt?encoding-type=url"),
            || list_v1(Some("url")),
            stamped!(
                "kd-encode-0005",
                "kd-encode-0006",
                "kd-encode-0023",
                "kd-encode-0024",
                "kd-encode-0025",
                "kd-encode-0039"
            ),
        ),
        row(
            "list-object-versions-full",
            RawRequest::get("/bkt?versions"),
            || list_versions(None),
            stamped!(
                "kd-encode-0005",
                "kd-encode-0006",
                "kd-encode-0018",
                "kd-encode-0019",
                "kd-encode-0020",
                "kd-encode-0021",
                "kd-encode-0022"
            ),
        ),
        row(
            "list-object-versions-url",
            RawRequest::get("/bkt?versions&encoding-type=url"),
            || list_versions(Some("url")),
            stamped!(
                "kd-encode-0005",
                "kd-encode-0006",
                "kd-encode-0018",
                "kd-encode-0019",
                "kd-encode-0020",
                "kd-encode-0021",
                "kd-encode-0022",
                "kd-encode-0040"
            ),
        ),
        row(
            "list-multipart-uploads-full",
            RawRequest::get("/bkt?uploads"),
            || list_uploads(None),
            stamped!("kd-encode-0005", "kd-encode-0014", "kd-encode-0015", "kd-encode-0016", "kd-encode-0017"),
        ),
        row(
            "list-multipart-uploads-url",
            RawRequest::get("/bkt?uploads&encoding-type=url"),
            || list_uploads(Some("url")),
            stamped!(
                "kd-encode-0005",
                "kd-encode-0014",
                "kd-encode-0015",
                "kd-encode-0016",
                "kd-encode-0017",
                "kd-encode-0041"
            ),
        ),
        row(
            "list-buckets-full",
            RawRequest::get("/"),
            || {
                OracleOutput::ListBuckets(oracle::ListBucketsOutput {
                    buckets: Some(vec![oracle::Bucket {
                        bucket_arn: Some("arn:aws:s3:::bkt".to_owned()),
                        bucket_region: Some("us-east-1".to_owned()),
                        creation_date: Some(at(1_767_225_600, 0)),
                        name: Some("bkt".to_owned()),
                    }]),
                    owner: owner(),
                    continuation_token: Some("next".to_owned()),
                    prefix: Some("b".to_owned()),
                })
            },
            stamped!("kd-encode-0005", "kd-encode-0011", "kd-encode-0012", "kd-encode-0013"),
        ),
        row(
            "create-multipart-upload",
            RawRequest::new(Method::POST, "/bkt/k?uploads"),
            create_mpu,
            stamped!("kd-encode-0005"),
        ),
        row(
            "upload-part",
            RawRequest::put("/bkt/k?partNumber=1&uploadId=u", b"hello world"),
            || upload_part(None),
            stamped!(),
        ),
        row(
            "upload-part-two-checksums",
            RawRequest::put("/bkt/k?partNumber=1&uploadId=u", b"hello world"),
            || {
                let OracleOutput::UploadPart(mut output) = upload_part(Some(("crc32", "DUoRhQ=="))) else {
                    unreachable!("upload_part builds an UploadPart output");
                };
                output.checksum_sha1 = Some("Kq5sNclPz7QV2+lfQIuc6R7oRu0=".to_owned());
                OracleOutput::UploadPart(output)
            },
            &["kd-encode-0043"],
        ),
        row(
            "complete-multipart-upload",
            RawRequest::post("/bkt/k?uploadId=u", COMPLETE_BODY),
            || OracleOutput::CompleteMultipartUpload(complete()),
            stamped!("kd-encode-0005", "kd-encode-0006", "kd-encode-0007"),
        ),
        row(
            "complete-multipart-upload-deferred",
            RawRequest::post("/bkt/k?uploadId=u", COMPLETE_BODY),
            || {
                OracleOutput::CompleteMultipartUpload(oracle::CompleteMultipartUploadOutput {
                    future: Some(Box::pin(async { Ok(complete()) })),
                    ..complete()
                })
            },
            &["kd-encode-0044"],
        ),
        row(
            "abort-multipart-upload",
            RawRequest::delete("/bkt/k?uploadId=u"),
            || {
                OracleOutput::AbortMultipartUpload(oracle::AbortMultipartUploadOutput {
                    request_charged: text("requester"),
                })
            },
            stamped!(),
        ),
        row(
            "list-parts",
            RawRequest::get("/bkt/k?uploadId=u"),
            list_parts,
            stamped!(
                "kd-encode-0005",
                "kd-encode-0006",
                "kd-encode-0029",
                "kd-encode-0030",
                "kd-encode-0031",
                "kd-encode-0032"
            ),
        ),
        row(
            "create-bucket",
            RawRequest::new(Method::PUT, "/newbkt"),
            || {
                OracleOutput::CreateBucket(oracle::CreateBucketOutput {
                    location: Some("/newbkt".to_owned()),
                    bucket_arn: None,
                })
            },
            stamped!(),
        ),
        row(
            "create-bucket-arn",
            RawRequest::new(Method::PUT, "/newbkt"),
            || {
                OracleOutput::CreateBucket(oracle::CreateBucketOutput {
                    location: Some("/newbkt".to_owned()),
                    bucket_arn: Some("arn:aws:s3:::newbkt".to_owned()),
                })
            },
            &["kd-encode-0045"],
        ),
        row(
            "delete-bucket",
            RawRequest::delete("/bkt"),
            || OracleOutput::DeleteBucket(oracle::DeleteBucketOutput {}),
            stamped!(),
        ),
        row(
            "head-bucket",
            RawRequest::head("/bkt"),
            || {
                OracleOutput::HeadBucket(oracle::HeadBucketOutput {
                    bucket_region: Some("us-east-1".to_owned()),
                    ..Default::default()
                })
            },
            stamped!(),
        ),
        row(
            "head-bucket-access-point-alias",
            RawRequest::head("/bkt"),
            || head_bucket(|output| output.access_point_alias = Some(false)),
            &["kd-encode-0046"],
        ),
        row(
            "head-bucket-arn",
            RawRequest::head("/bkt"),
            || head_bucket(|output| output.bucket_arn = Some("arn:aws:s3:::bkt".to_owned())),
            &["kd-encode-0048"],
        ),
        row(
            "head-bucket-location-name",
            RawRequest::head("/bkt"),
            || head_bucket(|output| output.bucket_location_name = Some("usw2-az1".to_owned())),
            &["kd-encode-0049"],
        ),
        row(
            "head-bucket-location-type",
            RawRequest::head("/bkt"),
            || head_bucket(|output| output.bucket_location_type = text("AvailabilityZone")),
            &["kd-encode-0050"],
        ),
        row(
            "get-bucket-location",
            RawRequest::get("/bkt?location"),
            || {
                OracleOutput::GetBucketLocation(oracle::GetBucketLocationOutput {
                    location_constraint: text("eu-west-1"),
                })
            },
            stamped!("kd-encode-0005"),
        ),
        row(
            "get-bucket-location-default",
            RawRequest::get("/bkt?location"),
            || {
                OracleOutput::GetBucketLocation(oracle::GetBucketLocationOutput {
                    location_constraint: None,
                })
            },
            stamped!("kd-encode-0005"),
        ),
        row(
            "get-bucket-versioning",
            RawRequest::get("/bkt?versioning"),
            || {
                OracleOutput::GetBucketVersioning(oracle::GetBucketVersioningOutput {
                    mfa_delete: text("Disabled"),
                    status: text("Enabled"),
                })
            },
            stamped!("kd-encode-0005", "kd-encode-0010"),
        ),
        row(
            "get-bucket-versioning-never",
            RawRequest::get("/bkt?versioning"),
            || OracleOutput::GetBucketVersioning(oracle::GetBucketVersioningOutput::default()),
            stamped!("kd-encode-0005"),
        ),
        row(
            "put-bucket-versioning",
            RawRequest::put(
                "/bkt?versioning",
                b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
            )
            .header("content-md5", "8qj8HSeDu3APPMQZVG06WQ=="),
            || OracleOutput::PutBucketVersioning(oracle::PutBucketVersioningOutput {}),
            stamped!(),
        ),
    ];
    for (algorithm, value) in CHECKSUMS {
        rows.push(row(
            &format!("upload-part-checksum-{algorithm}"),
            RawRequest::put("/bkt/k?partNumber=1&uploadId=u", b"hello world"),
            move || upload_part(Some((algorithm, value))),
            stamped!(),
        ));
    }
    rows
}
