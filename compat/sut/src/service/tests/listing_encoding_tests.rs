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

//! Listings under `encoding-type=url` as the RustFS-profile launcher renders them
//! (rustfs/gateway#1059).
//!
//! Responsible for: each listing encoding exactly the members legacy RustFS encodes, `/` literal,
//! only for exactly `url`, with legacy's echo — and every cursor it hands out working when a client
//! sends it back without decoding it, which is what the AWS SDKs do with continuation tokens.
//! NOT responsible for: the default encoding, which the core's codec suite and the conformance
//! corpus pin, or how the backend pages (`rustfs_gateway_fs::listing`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

async fn with_objects(root: &TestRoot, keys: &[&str]) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/encoded", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    for key in keys {
        let target = format!("/encoded/{}", key.replace(' ', "%20"));
        let stored = exchange(&service, as_main(http::Method::PUT, &target, Bytes::from_static(b"x"))).await;
        assert_eq!(stored.status(), 200, "{key}: {}", body_of(&stored));
    }
    service
}

async fn list(service: &S3Service, target: &str) -> String {
    let listed = exchange(service, as_main(http::Method::GET, target, Bytes::new())).await;
    let body = body_of(&listed);
    assert_eq!(listed.status(), 200, "{target}: {body}");
    body
}

fn element<'a>(body: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find('<')? + start;
    Some(&body[start..end])
}

/// Every byte a query value must not carry raw, percent-encoded the way an SDK sends it back.
fn query_value(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

/// Positive — ListObjectsV2 encodes each key and each rolled-up prefix with `/` literal, leaves
/// `Prefix` and `Delimiter` as sent, and echoes `url`.
#[tokio::test]
async fn list_objects_v2_encodes_keys_and_prefixes_with_slashes_literal() {
    let root = TestRoot::new();
    let service = with_objects(&root, &["dir/with space.txt", "dir/sub dir/x"]).await;
    let body = list(&service, "/encoded?list-type=2&prefix=dir%2F&delimiter=%2F&encoding-type=url").await;
    for expected in [
        "<Key>dir/with%20space.txt</Key>",
        "<Prefix>dir/sub%20dir/</Prefix>",
        "<Prefix>dir/</Prefix>",
        "<Delimiter>/</Delimiter>",
        "<EncodingType>url</EncodingType>",
    ] {
        assert!(body.contains(expected), "missing {expected}: {body}");
    }
    assert!(!body.contains("%2F"), "{body}");
}

/// Negative — a continuation token comes back as the backend minted it, so a client that returns
/// it without decoding it (the AWS SDKs do) reaches the next page instead of an unusable cursor.
#[tokio::test]
async fn n_a_continuation_token_is_never_encoded_and_round_trips() {
    let root = TestRoot::new();
    let service = with_objects(&root, &["a b/1", "a b/2"]).await;
    let first = list(&service, "/encoded?list-type=2&max-keys=1&encoding-type=url").await;
    assert!(first.contains("<Key>a%20b/1</Key>"), "{first}");
    let token = element(&first, "NextContinuationToken")
        .expect("a truncated page has a cursor")
        .to_owned();
    let second = list(
        &service,
        &format!(
            "/encoded?list-type=2&max-keys=1&encoding-type=url&continuation-token={}",
            query_value(&token)
        ),
    )
    .await;
    assert!(second.contains("<Key>a%20b/2</Key>"), "{second}");
    assert!(second.contains(&format!("<ContinuationToken>{token}</ContinuationToken>")), "{second}");
}

/// Negative — ListObjects encodes its keys and `NextMarker`, and echoes `Marker`, `Prefix` and
/// `Delimiter` as sent; the next page starts after the decoded marker.
#[tokio::test]
async fn n_list_objects_leaves_marker_prefix_and_delimiter_raw() {
    let root = TestRoot::new();
    let service = with_objects(&root, &["a b/1", "a b/2", "a b/3"]).await;
    let first = list(&service, "/encoded?max-keys=1&prefix=a%20b%2F&marker=a%20b%2F0&encoding-type=url").await;
    for expected in [
        "<Key>a%20b/1</Key>",
        "<NextMarker>a%20b/1</NextMarker>",
        "<Marker>a b/0</Marker>",
        "<Prefix>a b/</Prefix>",
        "<EncodingType>url</EncodingType>",
    ] {
        assert!(first.contains(expected), "missing {expected}: {first}");
    }
}

/// Negative — ListObjectVersions encodes every key-shaped member, `/` literal.
#[tokio::test]
async fn n_list_object_versions_encodes_every_key_shaped_member_with_slashes_literal() {
    let root = TestRoot::new();
    let service = with_objects(&root, &["d r/one x", "d r/two x"]).await;
    let body = list(
        &service,
        "/encoded?versions&prefix=d%20r%2F&delimiter=%2F&key-marker=d%20r%2Fa&max-keys=1&encoding-type=url",
    )
    .await;
    for expected in [
        "<Prefix>d%20r/</Prefix>",
        "<Delimiter>/</Delimiter>",
        "<KeyMarker>d%20r/a</KeyMarker>",
        "<Key>d%20r/one%20x</Key>",
        "<NextKeyMarker>d%20r/one%20x</NextKeyMarker>",
        "<EncodingType>url</EncodingType>",
    ] {
        assert!(body.contains(expected), "missing {expected}: {body}");
    }
}

/// Negative — the multipart listings are never encoded and never echo, as legacy RustFS writes
/// them.
#[tokio::test]
async fn n_multipart_listings_are_written_raw_without_an_echo() {
    let root = TestRoot::new();
    let service = with_objects(&root, &[]).await;
    let created = exchange(
        &service,
        as_main(http::Method::POST, "/encoded/dir/with%20space.txt?uploads", Bytes::new()),
    )
    .await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let upload_id = element(&body_of(&created), "UploadId").expect("an upload id").to_owned();

    let uploads = list(&service, "/encoded?uploads&prefix=dir%2F&encoding-type=url").await;
    assert!(uploads.contains("<Key>dir/with space.txt</Key>"), "{uploads}");
    assert!(uploads.contains("<Prefix>dir/</Prefix>"), "{uploads}");
    assert!(!uploads.contains("<EncodingType>"), "{uploads}");
    let parts = list(&service, &format!("/encoded/dir/with%20space.txt?uploadId={upload_id}&encoding-type=url")).await;
    assert!(parts.contains("<Key>dir/with space.txt</Key>"), "{parts}");
}

/// Negative — a spelling other than exactly `url` encodes nothing and is echoed as sent.
#[tokio::test]
async fn n_a_spelling_other_than_exactly_url_encodes_nothing() {
    let root = TestRoot::new();
    let service = with_objects(&root, &["dir/with space.txt"]).await;
    let body = list(&service, "/encoded?list-type=2&encoding-type=URL").await;
    assert!(body.contains("<Key>dir/with space.txt</Key>"), "{body}");
    assert!(body.contains("<EncodingType>URL</EncodingType>"), "{body}");
}
