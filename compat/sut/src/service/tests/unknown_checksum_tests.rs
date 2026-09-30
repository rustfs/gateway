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

//! A checksum header naming an algorithm nobody implements, as the RustFS-profile launcher serves
//! it (rustfs/backlog#1677): ignored, as legacy RustFS ignores it.
//!
//! Responsible for: an upload and a buffered write carrying `x-amz-checksum-blake3`, or an
//! `x-amz-sdk-checksum-algorithm` naming no algorithm, being served and stored exactly as sent;
//! and a known checksum beside the unknown header still being compared, a mismatch storing
//! nothing, as legacy RustFS refuses it.
//! NOT responsible for: the default refusal (`rustfs-gateway`'s `tests/unknown_checksum_algorithms.rs`)
//! or the arbitration (`rustfs-gateway-http`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy behaviour, observed on a legacy RustFS build (rustfs/rustfs `e870a6d25b`,
//! `RUSTFS_S3_STACK=legacy`): a PutObject or PutObjectTagging with `x-amz-checksum-blake3` alone,
//! or with `x-amz-sdk-checksum-algorithm: FOO`, is `200` and stored; beside a wrong
//! `x-amz-checksum-crc32` it is `400 BadDigest` and nothing is stored; beside a right one, `200`.

use super::*;

/// The CRC-32 of `hello`, base64.
const HELLO_CRC32: &str = "NhCmhg==";
/// A well-formed CRC-32 that is not the digest of `hello`.
const OTHER_CRC32: &str = "AAAAAA==";

/// The two forms of an unknown algorithm.
const UNKNOWN: [(&str, &str); 2] = [
    ("x-amz-checksum-blake3", HELLO_CRC32),
    ("x-amz-sdk-checksum-algorithm", "BLAKE3"),
];

async fn with_bucket(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/unknown", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    service
}

async fn put(service: &S3Service, target: &str, body: &'static [u8], extra: &[(&str, &str)]) -> WireResponse {
    let request = signed(MAIN_KEY, MAIN_SECRET, http::Method::PUT, target, Bytes::from_static(body), extra);
    exchange(service, request).await
}

async fn get(service: &S3Service, target: &str) -> WireResponse {
    exchange(service, as_main(http::Method::GET, target, Bytes::new())).await
}

/// Positive — an upload carrying either form is stored exactly as sent.
#[tokio::test]
async fn an_upload_with_an_unknown_checksum_algorithm_is_stored() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    for (index, pair) in UNKNOWN.into_iter().enumerate() {
        let target = format!("/unknown/object-{index}");
        let stored = put(&service, &target, b"hello", &[pair]).await;
        assert_eq!(stored.status(), 200, "{pair:?}: {}", body_of(&stored));
        assert_eq!(get(&service, &target).await.body().as_ref(), b"hello", "{pair:?}");
    }
}

/// Positive — a buffered write carrying either form is applied.
#[tokio::test]
async fn a_buffered_write_with_an_unknown_checksum_algorithm_is_applied() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    assert_eq!(put(&service, "/unknown/tagged", b"hello", &[]).await.status(), 200);
    for (index, pair) in UNKNOWN.into_iter().enumerate() {
        let tagging = if index == 0 {
            "<Tagging><TagSet><Tag><Key>first</Key><Value>1</Value></Tag></TagSet></Tagging>"
        } else {
            "<Tagging><TagSet><Tag><Key>second</Key><Value>2</Value></Tag></TagSet></Tagging>"
        };
        let request = signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::PUT,
            "/unknown/tagged?tagging",
            Bytes::from_static(tagging.as_bytes()),
            &[pair],
        );
        let applied = exchange(&service, request).await;
        assert_eq!(applied.status(), 200, "{pair:?}: {}", body_of(&applied));
        let read = body_of(&get(&service, "/unknown/tagged?tagging").await);
        let key = if index == 0 { "first" } else { "second" };
        assert!(read.contains(&format!("<Key>{key}</Key>")), "{pair:?}: {read}");
    }
}

/// Negative — a known checksum beside the unknown header is still compared: a mismatch is
/// `400 BadDigest` and stores nothing, as legacy RustFS refuses it; a match is stored.
#[tokio::test]
async fn n_a_known_checksum_beside_an_unknown_one_is_still_compared() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    for (index, pair) in UNKNOWN.into_iter().enumerate() {
        let refused_target = format!("/unknown/refused-{index}");
        let refused = put(&service, &refused_target, b"hello", &[pair, ("x-amz-checksum-crc32", OTHER_CRC32)]).await;
        assert_eq!(refused.status(), 400, "{pair:?}: {}", body_of(&refused));
        assert!(body_of(&refused).contains("<Code>BadDigest</Code>"), "{pair:?}: {}", body_of(&refused));
        assert_eq!(get(&service, &refused_target).await.status(), 404, "{pair:?}");

        let stored_target = format!("/unknown/stored-{index}");
        let stored = put(&service, &stored_target, b"hello", &[pair, ("x-amz-checksum-crc32", HELLO_CRC32)]).await;
        assert_eq!(stored.status(), 200, "{pair:?}: {}", body_of(&stored));
        assert_eq!(get(&service, &stored_target).await.body().as_ref(), b"hello", "{pair:?}");
    }
}
