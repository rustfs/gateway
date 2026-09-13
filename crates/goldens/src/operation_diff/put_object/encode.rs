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

//! PutObject encode diff: one s3s output, written by the s3s service and by the gateway codec.
//!
//! Responsible for: proving that an s3s `PutObjectOutput` the gateway can carry converts and encodes
//! to the same status, header lines and body the s3s service writes, and that every output the
//! gateway cannot carry is refused by name rather than trimmed.
//! NOT responsible for: the decode half, which is the parent module, or error documents.
//! Upstream: the harness two levels up and the fixtures in `super`. Downstream: nothing.

use std::sync::Arc;

use proptest::prelude::*;
use rustfs_gateway_types::ChecksumAlgorithm;
use rustfs_gateway_types::compat::ConversionError;

use super::super::seam::put_object::output_from_s3s;
use super::super::{BodyProbe, RawRequest, WireAnswer, gateway_encode, oracle, s3s_exchange};
use super::{accepted_output, checksum, md5_base64, pick, s3s_etag};

// ── encode ────────────────────────────────────────────────────────────────────────────────────

/// One s3s output, written by the s3s service and, through the conversion, by the gateway codec.
fn run_encode(output: oracle::PutObjectOutput) -> Result<(WireAnswer, WireAnswer), String> {
    let request = RawRequest::put("/photos/key", b"", 1);
    let probe = Arc::new(BodyProbe::default());
    let exchange = s3s_exchange(&request, &probe, output.clone())?;
    let converted = output_from_s3s(output).map_err(|error| error.to_string())?;
    let gateway = gateway_encode(&request, converted)?;
    Ok((exchange.answer, gateway))
}

fn full_output() -> oracle::PutObjectOutput {
    oracle::PutObjectOutput {
        bucket_key_enabled: Some(true),
        checksum_crc64nvme: Some("AAAAAAAAAAA=".to_owned()),
        checksum_type: Some("FULL_OBJECT".to_owned().into()),
        e_tag: Some(s3s_etag("5d41402abc4b2a76b9719d911017c592")),
        expiration: Some("expiry-date=\"Wed, 21 Oct 2037 00:00:00 GMT\", rule-id=\"r1\"".to_owned()),
        request_charged: Some("requester".to_owned().into()),
        sse_customer_algorithm: Some("AES256".to_owned()),
        sse_customer_key_md5: Some(md5_base64(&[7u8; 32])),
        ssekms_encryption_context: Some("eyJhIjoiYiJ9".to_owned()),
        ssekms_key_id: Some("arn:aws:kms:us-east-1:123456789012:key/k1".to_owned()),
        server_side_encryption: Some("aws:kms".to_owned().into()),
        size: Some(5),
        version_id: Some("3sL4kqtJlcpXroDTDmJ+rmSpXd3dIbrHY".to_owned()),
        ..Default::default()
    }
}

#[test]
fn every_member_of_a_full_output_encodes_to_the_same_answer() {
    let (oracle_answer, gateway_answer) = run_encode(full_output()).unwrap();
    assert_eq!(gateway_answer, oracle_answer);
}

#[test]
fn an_output_the_s3s_handler_left_without_an_etag_is_refused() {
    let output = oracle::PutObjectOutput {
        e_tag: None,
        ..full_output()
    };
    assert_eq!(output_from_s3s(output).map(|_| ()).unwrap_err().field, "e_tag");
}

#[test]
fn a_checksum_algorithm_the_gateway_cannot_write_is_refused() {
    for (field, output) in [
        (
            "checksum_md5",
            oracle::PutObjectOutput {
                checksum_md5: Some("AAAA".to_owned()),
                ..accepted_output()
            },
        ),
        (
            "checksum_sha512",
            oracle::PutObjectOutput {
                checksum_sha512: Some("AAAA".to_owned()),
                ..accepted_output()
            },
        ),
        (
            "checksum_xxhash128",
            oracle::PutObjectOutput {
                checksum_xxhash128: Some("AAAA".to_owned()),
                ..accepted_output()
            },
        ),
        (
            "checksum_xxhash3",
            oracle::PutObjectOutput {
                checksum_xxhash3: Some("AAAA".to_owned()),
                ..accepted_output()
            },
        ),
        (
            "checksum_xxhash64",
            oracle::PutObjectOutput {
                checksum_xxhash64: Some("AAAA".to_owned()),
                ..accepted_output()
            },
        ),
    ] {
        assert_eq!(output_from_s3s(output).map(|_| ()).unwrap_err().field, field);
    }
}

#[test]
fn two_checksums_on_one_output_are_refused_rather_than_one_dropped() {
    let output = oracle::PutObjectOutput {
        checksum_crc32: Some("NhCmhg==".to_owned()),
        checksum_sha256: Some("LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=".to_owned()),
        ..accepted_output()
    };
    let error: ConversionError = output_from_s3s(output).map(|_| ()).unwrap_err();
    assert_eq!(error.field, "checksum_spec");
}

#[test]
fn a_checksum_value_of_the_wrong_width_is_refused() {
    let output = oracle::PutObjectOutput {
        checksum_crc32: Some("AAAA".to_owned()),
        ..accepted_output()
    };
    assert_eq!(output_from_s3s(output).map(|_| ()).unwrap_err().field, "checksum_crc32");
}

fn outputs() -> impl Strategy<Value = oracle::PutObjectOutput> {
    (
        ("[0-9a-f]{32}", proptest::option::of(1u32..=10_000)),
        proptest::option::of(checksum()),
        proptest::option::of(pick(&["FULL_OBJECT", "COMPOSITE"])),
        proptest::option::of("expiry-date=\"Wed, 21 Oct 2037 00:00:00 GMT\", rule-id=\"[a-z0-9]{1,8}\""),
        proptest::option::of(pick(&["AES256", "aws:kms"])),
        proptest::option::of("[A-Za-z0-9._-]{1,32}"),
        proptest::option::of(("[a-z0-9:/-]{1,24}", pick(&["e30=", "eyJhIjoiYiJ9"]))),
        proptest::option::of(any::<bool>()),
        proptest::option::of(0i64..1 << 40),
        any::<bool>(),
    )
        .prop_map(
            |((etag, parts), checksum, kind, expiration, sse, version, kms, bucket_key, size, charged)| {
                let e_tag = match parts {
                    Some(parts) => format!("{etag}-{parts}"),
                    None => etag,
                };
                let mut output = oracle::PutObjectOutput {
                    e_tag: Some(s3s_etag(&e_tag)),
                    checksum_type: kind.map(Into::into),
                    expiration,
                    server_side_encryption: sse.map(Into::into),
                    version_id: version,
                    ssekms_key_id: kms.as_ref().map(|(id, _)| id.clone()),
                    ssekms_encryption_context: kms.map(|(_, context)| context),
                    bucket_key_enabled: bucket_key,
                    size,
                    request_charged: charged.then(|| "requester".to_owned().into()),
                    ..Default::default()
                };
                if let Some((algo, value)) = checksum {
                    let slot = match algo {
                        ChecksumAlgorithm::Crc32 => &mut output.checksum_crc32,
                        ChecksumAlgorithm::Crc32c => &mut output.checksum_crc32c,
                        ChecksumAlgorithm::Crc64Nvme => &mut output.checksum_crc64nvme,
                        ChecksumAlgorithm::Sha1 => &mut output.checksum_sha1,
                        ChecksumAlgorithm::Sha256 => &mut output.checksum_sha256,
                        // `ALL` is the generator's domain; a sixth algorithm must get its own slot.
                        other => panic!("no oracle output slot for {other:?}"),
                    };
                    *slot = Some(value);
                }
                output
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    /// Any output the gateway can carry is written with the same status, header lines and body by
    /// the s3s service and, through the conversion, by the gateway codec.
    #[test]
    fn a_generated_output_encodes_to_the_same_answer(output in outputs()) {
        let (oracle_answer, gateway_answer) = run_encode(output).map_err(TestCaseError::fail)?;
        prop_assert_eq!(gateway_answer, oracle_answer);
    }
}
