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

//! CopyObject and UploadPartCopy result checksums: what a RustFS copy reports in its result
//! element, carried through the generated seam and written by the gateway codec.
//!
//! Responsible for: proving that every checksum member (and CopyObject's checksum type) an s3s copy
//! output holds reaches the gateway's encoded result document with the same value, in the S3
//! model's element order, and that a result without checksums writes none. The test carries its
//! ruling id; the register's guard refuses one without.
//! NOT responsible for: the two-stack wire comparison, which `rustfs-gateway-difftest`'s encode
//! rows `copy-object-with-*` make against the s3s service itself.
//! Upstream: the generated `s3s_0_17_0` seam. Downstream: the request-divergence register.

use rustfs_gateway_core::codec::{MetaView, OperationCodec, ResponseBody};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::dto;

use super::seam::generated::ops::{copy_object, upload_part_copy};
use super::{HOST, oracle};

/// The ten algorithms, in the S3 model's element order, with a value of each one's width.
const CHECKSUMS: [(&str, &str); 10] = [
    ("ChecksumCRC32", "DUoRhQ=="),
    ("ChecksumCRC32C", "yZRlqg=="),
    ("ChecksumCRC64NVME", "jSnVw/bqjr4="),
    ("ChecksumSHA1", "Kq5sNclPz7QV2+lfQIuc6R7oRu0="),
    ("ChecksumSHA256", "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="),
    (
        "ChecksumSHA512",
        "MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxf9JlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw==",
    ),
    ("ChecksumMD5", "XrY7u+Ae7tCTyyK7j1rNww=="),
    ("ChecksumXXHASH64", "RQUY/mbA3bQ="),
    ("ChecksumXXHASH3", "0vGmIJHyGyA="),
    ("ChecksumXXHASH128", "32WdXnMWYnm/8YO6JpWpCg=="),
];

fn value(name: &str) -> Option<String> {
    CHECKSUMS
        .iter()
        .find(|(element, _)| *element == name)
        .map(|(_, value)| (*value).to_owned())
}

fn etag() -> Option<oracle::ETag> {
    Some(oracle::ETag::Strong("5d41402abc4b2a76b9719d911017c592".to_owned()))
}

fn modified() -> Option<oracle::Timestamp> {
    Some(oracle::Timestamp::from(
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_767_225_600),
    ))
}

fn view_of(target: &str) -> WireRequest<()> {
    let head = http::Request::builder()
        .method("PUT")
        .uri(format!("http://{HOST}{target}"))
        .header("host", HOST)
        .header("x-amz-copy-source", "src/k")
        .body(())
        .expect("a fixture head");
    WireRequest::accept(head, &Limits::default()).expect("an accepted fixture head")
}

fn body(encoded: rustfs_gateway_core::codec::EncodedResponse) -> String {
    match encoded.body {
        ResponseBody::Complete(bytes) => String::from_utf8(bytes).expect("a UTF-8 document"),
        other => panic!("a copy result is a complete document, not {other:?}"),
    }
}

fn copy_document(result: oracle::CopyObjectResult) -> String {
    let output = copy_object::output_from_s3s(oracle::CopyObjectOutput {
        copy_object_result: Some(result),
        ..Default::default()
    })
    .expect("the seam carries the copy result");
    let wire = view_of("/bkt/dst");
    let view = MetaView::of(&wire, TargetKind::Object).expect("object metadata");
    body(dto::CopyObject::encode(output, &view, 200).expect("the gateway encodes the copy result"))
}

fn part_document(result: oracle::CopyPartResult) -> String {
    let output = upload_part_copy::output_from_s3s(oracle::UploadPartCopyOutput {
        copy_part_result: Some(result),
        ..Default::default()
    })
    .expect("the seam carries the part result");
    let wire = view_of("/bkt/dst?partNumber=1&uploadId=u");
    let view = MetaView::of(&wire, TargetKind::Object).expect("object metadata");
    body(dto::UploadPartCopy::encode(output, &view, 200).expect("the gateway encodes the part result"))
}

/// The children of the result element, in order, each with its text.
fn children(document: &str) -> Vec<(String, String)> {
    let mut rest = document;
    let mut out = Vec::new();
    for root in ["<CopyObjectResult", "<CopyPartResult"] {
        if let Some(start) = rest.find(root) {
            rest = &rest[start..];
            rest = &rest[rest.find('>').expect("an open root") + 1..];
        }
    }
    while let Some(open) = rest.find('<') {
        let after = &rest[open + 1..];
        if after.starts_with('/') {
            break;
        }
        let name_end = after.find('>').expect("a closed tag");
        let name = &after[..name_end];
        let close = format!("</{name}>");
        let text_end = after.find(&close).expect("a matching close");
        out.push((name.to_owned(), after[name_end + 1..text_end].to_owned()));
        rest = &after[text_end + close.len()..];
    }
    out
}

// ── controls ──────────────────────────────────────────────────────────────────────────────────

/// Each algorithm alone is written alone: no member stands in for another.
#[test]
fn n_one_checksum_writes_only_its_own_element() {
    for (name, value) in CHECKSUMS {
        let mut result = oracle::CopyPartResult {
            e_tag: etag(),
            last_modified: modified(),
            ..Default::default()
        };
        let slot = match name {
            "ChecksumCRC32" => &mut result.checksum_crc32,
            "ChecksumCRC32C" => &mut result.checksum_crc32c,
            "ChecksumCRC64NVME" => &mut result.checksum_crc64nvme,
            "ChecksumSHA1" => &mut result.checksum_sha1,
            "ChecksumSHA256" => &mut result.checksum_sha256,
            "ChecksumSHA512" => &mut result.checksum_sha512,
            "ChecksumMD5" => &mut result.checksum_md5,
            "ChecksumXXHASH64" => &mut result.checksum_xxhash64,
            "ChecksumXXHASH3" => &mut result.checksum_xxhash3,
            "ChecksumXXHASH128" => &mut result.checksum_xxhash128,
            other => panic!("{other} is not an algorithm"),
        };
        *slot = Some(value.to_owned());
        let document = part_document(result);
        let written = children(&document);
        assert_eq!(written.get(2..), Some(&[(name.to_owned(), value.to_owned())][..]), "{document}");
    }
}

/// The control: a result without checksums writes the two members it always had, and nothing else.
#[test]
fn n_a_result_without_checksums_writes_none() {
    let document = copy_document(oracle::CopyObjectResult {
        e_tag: etag(),
        last_modified: modified(),
        ..Default::default()
    });
    let names: Vec<_> = children(&document).into_iter().map(|(name, _)| name).collect();
    assert_eq!(names, ["ETag", "LastModified"], "{document}");
    assert!(!document.contains("Checksum"), "{document}");
}

// ── the named divergence (rd-copy) ────────────────────────────────────────────────────────────

/// RustFS reports a copy's checksums in the result element and s3s writes every one it is handed;
/// the gateway result carried none of them. Each now crosses the seam with its value and is written
/// in the model's order, CopyObject's checksum type included.
///
/// Ruling: `rd-copy-0001`
#[test]
fn every_copy_result_checksum_crosses_the_seam_with_its_value() {
    let document = copy_document(oracle::CopyObjectResult {
        e_tag: etag(),
        last_modified: modified(),
        checksum_type: Some("COMPOSITE".to_owned().into()),
        checksum_crc32: value("ChecksumCRC32"),
        checksum_crc32c: value("ChecksumCRC32C"),
        checksum_crc64nvme: value("ChecksumCRC64NVME"),
        checksum_sha1: value("ChecksumSHA1"),
        checksum_sha256: value("ChecksumSHA256"),
        checksum_sha512: value("ChecksumSHA512"),
        checksum_md5: value("ChecksumMD5"),
        checksum_xxhash64: value("ChecksumXXHASH64"),
        checksum_xxhash3: value("ChecksumXXHASH3"),
        checksum_xxhash128: value("ChecksumXXHASH128"),
    });
    let mut expected = vec![("ChecksumType".to_owned(), "COMPOSITE".to_owned())];
    expected.extend(
        CHECKSUMS
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    );
    let written = children(&document);
    assert_eq!(written.get(2..), Some(&expected[..]), "{document}");

    let document = part_document(oracle::CopyPartResult {
        e_tag: etag(),
        last_modified: modified(),
        checksum_crc32: value("ChecksumCRC32"),
        checksum_crc32c: value("ChecksumCRC32C"),
        checksum_crc64nvme: value("ChecksumCRC64NVME"),
        checksum_sha1: value("ChecksumSHA1"),
        checksum_sha256: value("ChecksumSHA256"),
        checksum_sha512: value("ChecksumSHA512"),
        checksum_md5: value("ChecksumMD5"),
        checksum_xxhash64: value("ChecksumXXHASH64"),
        checksum_xxhash3: value("ChecksumXXHASH3"),
        checksum_xxhash128: value("ChecksumXXHASH128"),
    });
    let expected: Vec<_> = CHECKSUMS
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    assert_eq!(children(&document).get(2..), Some(&expected[..]), "{document}");
}
