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

//! CRC32C fixture negotiation, independently computed bytes, and completion field selection.
//!
//! Responsible for: distinguishing Castagnoli from IEEE and exercising the actual committed
//! completion output. NOT responsible for: validating client checksum claims, owned by the
//! framework. Upstream: the fixture producer. Downstream: regression and mutation controls.

use super::*;

fn part_checksum(algorithm: ChecksumAlgorithm, bytes: &[u8]) -> String {
    checksum_of(
        &UploadChecksum {
            algorithm,
            kind: dto::ChecksumType::COMPOSITE,
        },
        bytes,
    )
    .expect("the fixture computes a valid checksum from owned bytes")
    .render_base64()
    .to_owned()
}

fn completed(algorithm: ChecksumAlgorithm) -> dto::CompleteMultipartUploadOutput {
    let mut fixture = Fixture::at(0);
    fixture.declare_bucket("conf-crc", false);
    let mut upload = StoredUpload::bare("conf-crc", "key");
    upload.checksum = Some(UploadChecksum {
        algorithm,
        kind: dto::ChecksumType::COMPOSITE,
    });
    let upload_id = fixture.begin_upload(upload);
    let tag = fixture.put_part(&upload_id, 1, b"testcontent\n".to_vec());
    let input = dto::CompleteMultipartUploadInput {
        bucket: BucketName::new("conf-crc").expect("an owned bucket name"),
        key: ObjectKey::new("key").expect("an owned key"),
        upload_id: UploadIdClaim::from_wire(upload_id),
        multipart_upload: dto::CompletedMultipartUpload {
            parts: vec![dto::CompletedPart {
                part_number: 1,
                e_tag: Some(ETag::new(format!("\"{tag}\"")).expect("a computed entity tag")),
                ..dto::CompletedPart::default()
            }],
        },
        ..dto::CompleteMultipartUploadInput::default()
    };
    let stub = Stub::new(Arc::new(Mutex::new(fixture)));
    let response = stub.complete_multipart_upload(&input).expect("the owned part is complete");
    let rustfs_gateway::Answer::Committed(committed) = response.into_parts().0 else {
        panic!("the fixture completion must retain its committed continuation");
    };
    crate::exec::block_on(committed.into_parts().1).expect("the actual assembly succeeds")
}

/// CRC RevEng's check value and RFC 3720 B.4's zero/one vectors, in S3 byte order.
/// https://reveng.sourceforge.io/crc-catalogue/17plus.htm#crc.cat.crc-32-iscsi
/// https://www.rfc-editor.org/rfc/rfc3720.html#appendix-B.4
#[test]
fn crc32c_vectors_use_castagnoli_and_big_endian_bytes() {
    let actual =
        [b"".as_slice(), b"123456789", &[0; 32], &[255; 32]].map(|bytes| part_checksum(ChecksumAlgorithm::Crc32c, bytes));
    assert_eq!(actual, ["AAAAAA==", "4waSgw==", "ipE2qg==", "YqirQw=="]);
}

#[test]
fn crc32c_negotiation_is_recorded_as_composite() {
    assert!(matches!(
        upload_checksum(Some(&dto::ChecksumAlgorithm::CRC32C), None),
        Ok(Some(UploadChecksum { algorithm: ChecksumAlgorithm::Crc32c, kind }))
            if kind == dto::ChecksumType::COMPOSITE
    ));
}

#[test]
fn crc32c_does_not_use_the_ieee_digest() {
    assert_ne!(part_checksum(ChecksumAlgorithm::Crc32c, b"123456789"), "y/Q5Jg==");
}

#[test]
fn crc32_does_not_use_the_castagnoli_digest() {
    assert_ne!(part_checksum(ChecksumAlgorithm::Crc32, b"123456789"), "4waSgw==");
}

#[test]
fn crc32c_does_not_ignore_changed_bytes() {
    assert_ne!(part_checksum(ChecksumAlgorithm::Crc32c, b"12345678X"), "4waSgw==");
}

#[test]
fn crc32c_support_does_not_admit_other_known_algorithms() {
    for name in ["SHA1", "SHA256", "CRC64NVME"] {
        assert!(matches!(
            upload_checksum(Some(&dto::ChecksumAlgorithm::custom(name)), None),
            Err(error) if error.code() == &ErrorCode::NOT_IMPLEMENTED
        ));
    }
}

#[test]
fn crc32c_support_does_not_admit_unknown_algorithms() {
    assert!(matches!(
        upload_checksum(Some(&dto::ChecksumAlgorithm::custom("not-an-algorithm")), None),
        Err(error) if error.code() == &ErrorCode::INVALID_REQUEST
    ));
}

#[test]
fn crc32c_completion_omits_the_crc32_element() {
    assert!(completed(ChecksumAlgorithm::Crc32c).checksum_crc32.is_none());
}

#[test]
fn crc32_completion_omits_the_crc32c_element() {
    assert!(completed(ChecksumAlgorithm::Crc32).checksum_crc32c.is_none());
}

#[test]
fn crc32c_completion_reports_the_actual_composite() {
    assert_eq!(completed(ChecksumAlgorithm::Crc32c).checksum_crc32c.as_deref(), Some("3+pJYA==-1"));
}
