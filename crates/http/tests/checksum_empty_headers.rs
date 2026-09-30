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

//! An integrity header whose one line is empty, read as a value by default and as no header under
//! [`EmptyIntegrityHeaders::Absent`] (legacy RustFS's reading, rustfs/gateway#1087).
//!
//! Responsible for: the default refusing every empty integrity header as before; the absent
//! reading claiming nothing for each of them while every claim beside it is still arbitrated and
//! verified; and a value, or a repeated line, arbitrated as before under either reading.
//! NOT responsible for: the rest of the arbitration (`checksum_arbitration.rs`), or which
//! assemblies read so (the facade's RustFS profile).
//! Upstream: `rustfs-gateway-http`. Downstream: nothing.

use http::{HeaderMap, HeaderName, HeaderValue};
use rustfs_gateway_http::{
    BodyIntegrity, ChecksumReject, ChecksumSubject, EmptyIntegrityHeaders, HeaderView, UnknownChecksumAlgorithms,
};

/// The body every case digests.
const BODY: &[u8] = b"hello world";
/// base64(CRC32(BODY)).
const CRC32: &str = "DUoRhQ==";
/// A well-formed CRC32 that is not the digest of [`BODY`].
const OTHER_CRC32: &str = "AAAAAA==";

/// Every integrity header the arbitration reads.
const INTEGRITY_HEADERS: [&str; 5] = [
    "content-md5",
    "x-amz-checksum-crc32",
    "x-amz-sdk-checksum-algorithm",
    "x-amz-checksum-type",
    "x-amz-trailer",
];

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        let name = HeaderName::from_bytes(name.as_bytes()).expect("a test header name");
        let value = HeaderValue::from_str(value).expect("a test header value");
        map.append(name, value);
    }
    map
}

fn resolve(pairs: &[(&str, &str)], empty: EmptyIntegrityHeaders) -> Result<BodyIntegrity, ChecksumReject> {
    let map = headers(pairs);
    BodyIntegrity::resolve_reading(
        &HeaderView::new(&map),
        ChecksumSubject::RequestBody,
        UnknownChecksumAlgorithms::Refused,
        empty,
    )
}

/// Digests [`BODY`] under `integrity` and closes.
fn verify(integrity: BodyIntegrity) -> Result<(), ChecksumReject> {
    let mut digests = integrity.begin();
    digests.update(BODY);
    digests.verify().map(|_| ())
}

/// Under the absent reading, each empty integrity header claims nothing.
#[test]
fn an_empty_integrity_header_claims_nothing_under_the_absent_reading() {
    for name in INTEGRITY_HEADERS {
        let integrity =
            resolve(&[(name, "")], EmptyIntegrityHeaders::Absent).unwrap_or_else(|reject| panic!("{name}: {reject:?}"));
        assert!(integrity.is_empty(), "{name}");
    }
}

/// Negative — by default an empty `Content-MD5`, `x-amz-checksum-*`, SDK algorithm or trailer
/// declaration is refused as before, through `resolve_with` and `resolve_reading` alike.
#[test]
fn n_by_default_an_empty_integrity_claim_is_refused() {
    assert_eq!(EmptyIntegrityHeaders::default(), EmptyIntegrityHeaders::Read);
    for name in [
        "content-md5",
        "x-amz-checksum-crc32",
        "x-amz-sdk-checksum-algorithm",
        "x-amz-trailer",
    ] {
        assert!(resolve(&[(name, "")], EmptyIntegrityHeaders::Read).is_err(), "{name}");
        let map = headers(&[(name, "")]);
        let through_resolve_with =
            BodyIntegrity::resolve_with(&HeaderView::new(&map), ChecksumSubject::RequestBody, UnknownChecksumAlgorithms::Refused);
        assert!(through_resolve_with.is_err(), "{name}");
    }
}

/// Negative — beside an empty header read as absent, every other claim is still arbitrated and
/// verified: a matching checksum passes, a mismatch is still refused.
#[test]
fn n_a_claim_beside_an_empty_header_is_still_verified() {
    for empty in [
        "content-md5",
        "x-amz-sdk-checksum-algorithm",
        "x-amz-checksum-type",
        "x-amz-trailer",
    ] {
        let matching = resolve(&[(empty, ""), ("x-amz-checksum-crc32", CRC32)], EmptyIntegrityHeaders::Absent)
            .unwrap_or_else(|reject| panic!("{empty}: {reject:?}"));
        assert!(!matching.is_empty(), "{empty}");
        assert_eq!(verify(matching), Ok(()), "{empty}");
        let mismatched = resolve(&[(empty, ""), ("x-amz-checksum-crc32", OTHER_CRC32)], EmptyIntegrityHeaders::Absent)
            .unwrap_or_else(|reject| panic!("{empty}: {reject:?}"));
        assert!(verify(mismatched).is_err(), "{empty}");
    }
}

/// Negative — only one empty line is absent: a repeated line, or a value, is read as before.
#[test]
fn n_a_repeated_line_or_a_value_is_read_as_before() {
    let repeated = [("x-amz-sdk-checksum-algorithm", ""), ("x-amz-sdk-checksum-algorithm", "")];
    assert_eq!(
        resolve(&repeated, EmptyIntegrityHeaders::Absent).is_err(),
        resolve(&repeated, EmptyIntegrityHeaders::Read).is_err()
    );
    assert!(resolve(&[("content-md5", "not base64")], EmptyIntegrityHeaders::Absent).is_err());
    assert!(resolve(&[("x-amz-sdk-checksum-algorithm", "CRC32")], EmptyIntegrityHeaders::Absent).is_err());
}
