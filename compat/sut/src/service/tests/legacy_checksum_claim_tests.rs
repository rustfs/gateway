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

//! Checksum declarations as the RustFS-profile launcher reads them (rustfs/gateway#1349).
//!
//! Responsible for: the declarations legacy RustFS ignores being served — an
//! `x-amz-sdk-checksum-algorithm` it never reads, an `x-amz-checksum-type` it ignores — and the
//! ones it refuses being refused with its `BadDigest`, nothing stored; the value header present
//! being compared whatever the declarations say; and two value headers staying refused.
//! NOT responsible for: the rule (`rustfs-gateway-types`' `legacy_rustfs_request_checksum`), a
//! repeated `x-amz-checksum-algorithm` (`checksum_declaration_tests`), or `Content-MD5`
//! (`bad_digest_tests`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy behaviour, measured on a native build of rustfs/rustfs `95268a3b9` with signed raw
//! requests (`hello` uploaded each time): `x-amz-sdk-checksum-algorithm: CRC32` alone `200`, beside
//! a right SHA-256 `200`, beside a wrong one `400 BadDigest`; `x-amz-checksum-type: FOO` alone or
//! beside a right CRC-32 `200`, beside `x-amz-checksum-algorithm: CRC32` `400 BadDigest`;
//! `COMPOSITE` beside a plain CRC-32 `200`; `FULL_OBJECT` beside SHA-256 `400 BadDigest`;
//! `x-amz-checksum-algorithm: FOO` `400 BadDigest`; `x-amz-checksum-algorithm: CRC32` beside a
//! wrong SHA-256 `200` (stored unchecked); PutObjectTagging `200` whatever its checksum headers say;
//! CRC-32 and SHA-256 both right `200`.

use super::*;

const CRC32: (&str, &str) = ("x-amz-checksum-crc32", "NhCmhg==");
const SHA256: (&str, &str) = ("x-amz-checksum-sha256", "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=");
const WRONG_SHA256: (&str, &str) = ("x-amz-checksum-sha256", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
const SDK_CRC32: (&str, &str) = ("x-amz-sdk-checksum-algorithm", "CRC32");
const ALGORITHM_CRC32: (&str, &str) = ("x-amz-checksum-algorithm", "CRC32");
const TAGGING: &[u8] = b"<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>";

fn element<'a>(body: &'a str, name: &str) -> Option<&'a str> {
    body.split_once(&format!("<{name}>"))
        .and_then(|(_, rest)| rest.split_once(&format!("</{name}>")))
        .map(|(value, _)| value)
}

async fn with_bucket(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/claims", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    service
}

async fn put(service: &S3Service, key: &str, extra: &[(&str, &str)]) -> WireResponse {
    let target = format!("/claims/{key}");
    exchange(
        service,
        signed(MAIN_KEY, MAIN_SECRET, http::Method::PUT, &target, Bytes::from_static(b"hello"), extra),
    )
    .await
}

async fn assert_stored(service: &S3Service, key: &str) {
    let read = exchange(service, as_main(http::Method::GET, &format!("/claims/{key}"), Bytes::new())).await;
    assert_eq!(
        (read.status().as_u16(), read.body().as_ref()),
        (200, &b"hello"[..]),
        "{key}: {}",
        body_of(&read)
    );
}

async fn assert_absent(service: &S3Service, key: &str) {
    let read = exchange(service, as_main(http::Method::GET, &format!("/claims/{key}"), Bytes::new())).await;
    assert_eq!(read.status(), 404, "{key}: {}", body_of(&read));
}

fn assert_refused(response: &WireResponse, code: &str, what: &str) {
    let body = body_of(response);
    assert_eq!(response.status(), 400, "{what}: {body}");
    assert_eq!(element(&body, "Code"), Some(code), "{what}: {body}");
}

/// Positive — `x-amz-sdk-checksum-algorithm` is not read: alone it is served, and beside another
/// algorithm's right value it is served.
#[tokio::test]
async fn the_sdk_algorithm_header_is_not_read() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    for (key, extra) in [("sdk-alone", &[SDK_CRC32][..]), ("sdk-beside", &[SDK_CRC32, SHA256][..])] {
        let stored = put(&service, key, extra).await;
        assert_eq!(stored.status(), 200, "{key}: {}", body_of(&stored));
        assert_stored(&service, key).await;
    }
}

/// Positive — a checksum type legacy ignores is served: an unknown one alone or beside a right
/// value, and `COMPOSITE` beside a plain CRC-32.
#[tokio::test]
async fn a_checksum_type_legacy_ignores_is_served() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    for (key, extra) in [
        ("type-alone", &[("x-amz-checksum-type", "FOO")][..]),
        ("type-beside", &[("x-amz-checksum-type", "FOO"), CRC32][..]),
        ("composite-plain", &[("x-amz-checksum-type", "COMPOSITE"), CRC32][..]),
    ] {
        let stored = put(&service, key, extra).await;
        assert_eq!(stored.status(), 200, "{key}: {}", body_of(&stored));
        assert_stored(&service, key).await;
    }
}

/// Negative — the declarations legacy RustFS refuses on an upload are `400 BadDigest` and store
/// nothing: an algorithm it does not know, a type beside an algorithm it cannot read, and a
/// full-object type on an algorithm that cannot be combined.
#[tokio::test]
async fn n_declarations_legacy_refuses_store_nothing() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    for (key, extra) in [
        ("algorithm-unknown", &[("x-amz-checksum-algorithm", "FOO")][..]),
        ("algorithm-type", &[ALGORITHM_CRC32, ("x-amz-checksum-type", "FOO")][..]),
        ("full-sha256", &[("x-amz-checksum-type", "FULL_OBJECT"), SHA256][..]),
    ] {
        assert_refused(&put(&service, key, extra).await, "BadDigest", key);
        assert_absent(&service, key).await;
    }
}

/// Negative — the value header present is compared whatever the declarations beside it say: a
/// wrong SHA-256 beside an SDK algorithm, an ignored type, or an upload algorithm naming CRC-32
/// (which legacy RustFS would store unchecked) stores nothing.
#[tokio::test]
async fn n_a_wrong_value_is_compared_whatever_the_declarations_say() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    for (key, extra) in [
        ("sdk-wrong", &[SDK_CRC32, WRONG_SHA256][..]),
        ("type-wrong", &[("x-amz-checksum-type", "FOO"), WRONG_SHA256][..]),
        ("algorithm-wrong", &[ALGORITHM_CRC32, WRONG_SHA256][..]),
    ] {
        assert_refused(&put(&service, key, extra).await, "BadDigest", key);
        assert_absent(&service, key).await;
    }
    let right = put(&service, "algorithm-other", &[ALGORITHM_CRC32, SHA256]).await;
    assert_eq!(right.status(), 200, "{}", body_of(&right));
    assert_stored(&service, "algorithm-other").await;
}

/// Negative — two value headers that both match stay refused before the body is read, and store
/// nothing: legacy RustFS stores the body, but the operation's input carries one claim and legacy
/// RustFS hands its handler both and echoes both on its answer, so serving the pair would drop one
/// on the way to RustFS (rustfs/gateway#1349 records this as open).
#[tokio::test]
async fn n_two_matching_value_headers_stay_refused() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    assert_refused(&put(&service, "both", &[CRC32, SHA256]).await, "InvalidRequest", "both");
    assert_absent(&service, "both").await;
}

/// Positive — off an upload `x-amz-checksum-algorithm` is not read, so a name legacy refuses on an
/// upload is applied on a tagging write, as legacy RustFS applies it.
#[tokio::test]
async fn a_tagging_write_does_not_read_the_algorithm_header() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    assert_eq!(put(&service, "tagged", &[]).await.status(), 200);
    let tagging = exchange(
        &service,
        signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::PUT,
            "/claims/tagged?tagging",
            Bytes::from_static(TAGGING),
            &[("x-amz-checksum-algorithm", "FOO"), ("x-amz-sdk-checksum-algorithm", "CRC32")],
        ),
    )
    .await;
    assert_eq!(tagging.status(), 200, "{}", body_of(&tagging));
    let tags = exchange(&service, as_main(http::Method::GET, "/claims/tagged?tagging", Bytes::new())).await;
    assert!(body_of(&tags).contains("<Key>k</Key>"), "{}", body_of(&tags));
}
