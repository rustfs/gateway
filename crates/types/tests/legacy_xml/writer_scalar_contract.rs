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

//! Stored scalar writer regression tests.
//!
//! Responsible for: preserving NUL values, exact XML bytes, and complete readback values for
//! Payer, AllowedOrigin, and KMSMasterKeyID. NOT responsible for: other fields or wire XML.
//! Upstream: persistence readers and writers. Downstream: stored XML compatibility.

use rustfs_gateway_types::{cors_tagging, persistence};

#[test]
fn request_payment_preserves_nul_bytes_and_readback() {
    const INPUT: &[u8] = b"<RequestPaymentConfiguration><Payer>\0</Payer></RequestPaymentConfiguration>";
    const OLD_BYTES: &[u8] = b"<RequestPaymentConfiguration><Payer>\0</Payer></RequestPaymentConfiguration>";
    let expected = persistence::PersistedRequestPaymentConfiguration {
        payer: String::from("\0"),
    };
    let input = persistence::parse_request_payment(INPUT).expect("original Payer input is readable");
    let written = persistence::serialize_request_payment(&input);
    let readback = persistence::parse_request_payment(&written);
    assert_eq!((input, written, readback), (expected.clone(), OLD_BYTES.to_vec(), Ok(expected)),);
}

#[test]
fn cors_origin_preserves_nul_bytes_and_readback() {
    const INPUT: &[u8] = b"<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>\0</AllowedOrigin></CORSRule></CORSConfiguration>";
    const OLD_BYTES: &[u8] = b"<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>\0</AllowedOrigin></CORSRule></CORSConfiguration>";
    let expected = cors_tagging::PersistedCorsConfiguration {
        cors_rules: vec![cors_tagging::PersistedCorsRule {
            allowed_headers: None,
            allowed_methods: vec![String::from("GET")],
            allowed_origins: vec![String::from("\0")],
            expose_headers: None,
            id: None,
            max_age_seconds: None,
        }],
    };
    let input = cors_tagging::parse_cors(INPUT).expect("original AllowedOrigin input is readable");
    let written = cors_tagging::serialize_cors(&input);
    let readback = cors_tagging::parse_cors(&written);
    assert_eq!((input, written, readback), (expected.clone(), OLD_BYTES.to_vec(), Ok(expected)),);
}

#[test]
fn kms_key_id_preserves_nul_bytes_and_readback() {
    const INPUT: &[u8] = b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm><KMSMasterKeyID>a\0b</KMSMasterKeyID></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";
    const OLD_BYTES: &[u8] = b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><KMSMasterKeyID>a\0b</KMSMasterKeyID><SSEAlgorithm>aws:kms</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";
    let expected = vec![(Some(String::from("aws:kms")), Some(String::from("a\0b")), None, None)];
    let input = persistence::parse_bucket_encryption(INPUT).expect("original KMS key input is readable");
    let written = persistence::serialize_bucket_encryption(&input);
    let readback = persistence::parse_bucket_encryption(&written).map(|value| value.encryption_behavior());
    assert_eq!(
        (input.encryption_behavior(), written, readback),
        (expected.clone(), OLD_BYTES.to_vec(), Ok(expected)),
    );
}
