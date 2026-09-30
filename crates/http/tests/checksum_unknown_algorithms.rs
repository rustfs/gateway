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

//! A checksum header naming an algorithm this build does not implement, refused by default and
//! ignored under [`UnknownChecksumAlgorithms::Ignored`] (legacy RustFS's reading,
//! rustfs/backlog#1677).
//!
//! Responsible for: the default refusing both forms of an unknown algorithm; the ignored policy
//! leaving out exactly those headers — an unknown `x-amz-checksum-<name>` and an
//! `x-amz-sdk-checksum-algorithm` naming none — while every other claim beside them is still
//! arbitrated and verified; and a declared trailer of an unknown algorithm still being refused.
//! NOT responsible for: the rest of the arbitration (`checksum_arbitration.rs`), or which
//! assemblies ignore (the facade's RustFS profile).
//! Upstream: `rustfs-gateway-http`. Downstream: nothing.

use http::{HeaderMap, HeaderName, HeaderValue};
use rustfs_gateway_http::{BodyIntegrity, ChecksumReject, ChecksumSubject, HeaderView, UnknownChecksumAlgorithms};
use rustfs_gateway_stream::TrailingHeaders;

/// The body every case digests.
const BODY: &[u8] = b"hello world";
/// base64(CRC32(BODY)).
const CRC32: &str = "DUoRhQ==";
/// A well-formed CRC32 that is not the digest of [`BODY`].
const OTHER_CRC32: &str = "AAAAAA==";
/// base64(MD5(BODY)).
const MD5: &str = "XrY7u+Ae7tCTyyK7j1rNww==";
/// A well-formed MD5 that is not the digest of [`BODY`].
const OTHER_MD5: &str = "AAAAAAAAAAAAAAAAAAAAAA==";

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        let name = HeaderName::from_bytes(name.as_bytes()).expect("a test header name");
        let value = HeaderValue::from_str(value).expect("a test header value");
        map.append(name, value);
    }
    map
}

fn resolve(pairs: &[(&str, &str)], unknown: UnknownChecksumAlgorithms) -> Result<BodyIntegrity, ChecksumReject> {
    let map = headers(pairs);
    BodyIntegrity::resolve_with(&HeaderView::new(&map), ChecksumSubject::RequestBody, unknown)
}

fn ignoring(pairs: &[(&str, &str)]) -> Result<BodyIntegrity, ChecksumReject> {
    resolve(pairs, UnknownChecksumAlgorithms::Ignored)
}

/// Digests [`BODY`] under `integrity` and closes.
fn verify(integrity: BodyIntegrity) -> Result<(), ChecksumReject> {
    let mut digests = integrity.begin();
    digests.update(BODY);
    digests.verify().map(|_| ())
}

/// The two forms of an unknown algorithm.
const UNKNOWN: [(&str, &str); 2] = [("x-amz-checksum-blake3", CRC32), ("x-amz-sdk-checksum-algorithm", "BLAKE3")];

/// Negative — the default refuses both forms, through `resolve` and through `resolve_with`.
#[test]
fn n_by_default_an_unknown_algorithm_is_refused() {
    assert_eq!(UnknownChecksumAlgorithms::default(), UnknownChecksumAlgorithms::Refused);
    for pair in UNKNOWN {
        assert_eq!(
            resolve(&[pair], UnknownChecksumAlgorithms::Refused),
            Err(ChecksumReject::UnknownAlgorithm),
            "{pair:?}"
        );
        let map = headers(&[pair]);
        assert_eq!(
            BodyIntegrity::resolve(&HeaderView::new(&map), ChecksumSubject::RequestBody),
            Err(ChecksumReject::UnknownAlgorithm),
            "{pair:?}"
        );
    }
}

/// Positive — ignored, an unknown algorithm alone claims nothing: the body owes no comparison.
#[test]
fn an_ignored_unknown_algorithm_alone_claims_nothing() {
    for pair in UNKNOWN {
        let integrity = ignoring(&[pair]).expect("ignored");
        assert!(integrity.is_empty(), "{pair:?}: {integrity:?}");
        assert!(integrity.declared_checksum().is_none(), "{pair:?}");
        assert_eq!(verify(integrity), Ok(()), "{pair:?}");
    }
}

/// Negative — ignored, the claims beside an unknown algorithm are still verified: a known
/// checksum and a `Content-MD5` that do not match the body are refused, and ones that do pass.
#[test]
fn n_an_ignored_unknown_algorithm_still_verifies_every_claim_beside_it() {
    for pair in UNKNOWN {
        let known = ignoring(&[pair, ("x-amz-checksum-crc32", CRC32)]).expect("one known claim");
        assert_eq!(known.declared_checksum().map(|checksum| checksum.render_base64()), Some(CRC32));
        assert_eq!(verify(known), Ok(()), "{pair:?}");
        let wrong = ignoring(&[pair, ("x-amz-checksum-crc32", OTHER_CRC32)]).expect("one known claim");
        assert_eq!(verify(wrong), Err(ChecksumReject::ChecksumMismatch), "{pair:?}");
        assert_eq!(verify(ignoring(&[pair, ("content-md5", MD5)]).expect("an MD5")), Ok(()));
        let bad_md5 = ignoring(&[pair, ("content-md5", OTHER_MD5)]).expect("an MD5");
        assert_eq!(verify(bad_md5), Err(ChecksumReject::BadDigest), "{pair:?}");
    }
}

/// Negative — ignoring unknown algorithms relaxes nothing else: two known checksums, a known
/// value that is not base64 of its width, an unreadable `Content-MD5`, an SDK algorithm naming a
/// known algorithm no value header carried, and an empty SDK algorithm are refused exactly as by
/// default.
#[test]
fn n_ignoring_unknown_algorithms_relaxes_no_other_refusal() {
    let rows: [(&[(&str, &str)], ChecksumReject); 4] = [
        (
            &[
                ("x-amz-checksum-crc32", CRC32),
                ("x-amz-checksum-sha1", "Kq5sNclPz7QV2+lfQIuc6R7oRu0="),
            ],
            ChecksumReject::MultipleChecksumHeaders,
        ),
        (&[("x-amz-checksum-crc32", "not base64!")], ChecksumReject::InvalidChecksumValue),
        (&[("content-md5", "not base64!")], ChecksumReject::InvalidDigest),
        (&[("x-amz-sdk-checksum-algorithm", "SHA256")], ChecksumReject::SdkAlgorithmMismatch),
    ];
    for (pairs, refusal) in rows {
        assert_eq!(ignoring(pairs), Err(refusal), "{pairs:?}");
        assert_eq!(resolve(pairs, UnknownChecksumAlgorithms::Refused), Err(refusal), "{pairs:?}");
    }
    // An empty SDK algorithm names no algorithm rather than an unknown one: still refused.
    let empty = [("x-amz-sdk-checksum-algorithm", "")];
    assert_eq!(ignoring(&empty), Err(ChecksumReject::UnknownAlgorithm));
}

/// Positive and negative — on a trailer upload, an SDK algorithm naming no algorithm is ignored
/// and the declared trailer is still verified; a trailer declared under an unknown algorithm is
/// still refused, because its value would arrive in the body with nothing to compare it to.
#[test]
fn a_trailer_upload_ignores_only_the_unknown_sdk_algorithm() {
    let integrity = ignoring(&[
        ("x-amz-trailer", "x-amz-checksum-crc32"),
        ("x-amz-sdk-checksum-algorithm", "BLAKE3"),
    ])
    .expect("the unknown SDK algorithm is ignored");
    let mut digests = integrity.begin();
    digests.update(BODY);
    let trailer = TrailingHeaders::from_header_map(headers(&[("x-amz-checksum-crc32", OTHER_CRC32)]));
    assert_eq!(digests.verify_with_trailers(&trailer), Err(ChecksumReject::ChecksumMismatch));
    assert_eq!(
        ignoring(&[("x-amz-trailer", "x-amz-checksum-blake3")]),
        Err(ChecksumReject::UnknownAlgorithm)
    );
}
