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

//! The legacy RustFS key floor as the launcher serves it (rustfs/gateway#1107).
//!
//! Responsible for: every key legacy RustFS stores round-tripping through the RustFS-profile
//! assembly onto a real backend and back — written, read, listed under the same bytes, copied from
//! and batch-deleted — and the keys no `ObjectKey` can hold still storing nothing.
//! NOT responsible for: the rule (`rustfs-gateway-types`' `rustfs_key_floor_tests`), or equality
//! with the key legacy RustFS hands its storage (the difftest RustFS-profile rows). A key legacy
//! RustFS's storage refuses (`a/../b`) is refused in front of this backend as RustFS refuses it
//! (`legacy_storage_names_tests`); CR and LF, which RustFS's object handlers refuse, are not
//! written here: that refusal is RustFS's, behind the gateway, and this backend is not RustFS.
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

/// Keys legacy RustFS stored and served, as the label after `/keys/` and the stored bytes.
///
/// `a%zzb` (a `%` no hex follows, which legacy RustFS also stores) is not here: this harness signs
/// with the gateway's own signer, which refuses a malformed escape in the path it canonicalises.
/// Its naming is pinned unsigned by the difftest row `rustfs-key-invalid-escape`.
const STORED_BY_LEGACY: [(&str, &str); 12] = [
    ("a%01b", "a\u{1}b"),
    ("a%09b", "a\tb"),
    ("a%0Bb", "a\u{b}b"),
    ("a%7Fb", "a\u{7f}b"),
    ("a%C2%85b", "a\u{85}b"),
    ("a%252Fb", "a%2Fb"),
    ("a%255Cb", "a%5Cb"),
    ("a%252e%252e", "a%2e%2e"),
    ("%5Cx", "\\x"),
    ("%5C%5Cserver%5Cshare", "\\\\server\\share"),
    ("C:%5Cx", "C:\\x"),
    ("c:/x", "c:/x"),
];

async fn keys_bucket(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/keys", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    service
}

/// Percent-decodes one listed key. The listing is url-encoded: several of these keys hold bytes an
/// XML document cannot carry.
fn unescape(encoded: &str) -> String {
    let bytes = encoded.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() + 1 {
            let hex = std::str::from_utf8(&bytes[index + 1..(index + 3).min(bytes.len())]).unwrap_or("");
            if let Ok(byte) = u8::from_str_radix(hex, 16)
                && hex.len() == 2
            {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(out).expect("a listed key is UTF-8")
}

async fn listed(service: &S3Service) -> Vec<String> {
    let listing = exchange(service, as_main(http::Method::GET, "/keys?list-type=2&encoding-type=url", Bytes::new())).await;
    assert_eq!(listing.status(), 200, "{}", body_of(&listing));
    let body = body_of(&listing);
    body.split("<Key>")
        .skip(1)
        .filter_map(|rest| rest.split_once("</Key>").map(|(key, _)| unescape(key)))
        .collect()
}

/// Positive — every key legacy RustFS stores is written, read back and listed as the same bytes.
#[tokio::test]
async fn every_key_legacy_rustfs_stores_round_trips() {
    let root = TestRoot::new();
    let service = keys_bucket(&root).await;
    for (label, stored) in STORED_BY_LEGACY {
        let target = format!("/keys/{label}");
        let written = exchange(&service, as_main(http::Method::PUT, &target, Bytes::from(stored.to_owned()))).await;
        assert_eq!(written.status(), 200, "{target}: {}", body_of(&written));
        let read = exchange(&service, as_main(http::Method::GET, &target, Bytes::new())).await;
        assert_eq!(read.status(), 200, "{target}: {}", body_of(&read));
        assert_eq!(read.body().as_ref(), stored.as_bytes(), "{target}");
    }
    let mut expected: Vec<String> = STORED_BY_LEGACY.iter().map(|(_, stored)| (*stored).to_owned()).collect();
    expected.sort();
    let mut keys = listed(&service).await;
    keys.sort();
    assert_eq!(keys, expected);
}

/// Positive — such a key can be copied from, and a batch delete naming it deletes it.
#[tokio::test]
async fn a_legacy_key_can_be_copied_from_and_deleted_in_a_batch() {
    let root = TestRoot::new();
    let service = keys_bucket(&root).await;
    for label in ["a%01b", "C:%5Cx"] {
        let written = exchange(
            &service,
            as_main(http::Method::PUT, &format!("/keys/{label}"), Bytes::from_static(b"source")),
        )
        .await;
        assert_eq!(written.status(), 200, "{}", body_of(&written));
    }
    let copied = exchange(
        &service,
        signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::PUT,
            "/keys/copy",
            Bytes::new(),
            &[("x-amz-copy-source", "keys/a%01b")],
        ),
    )
    .await;
    assert_eq!(copied.status(), 200, "{}", body_of(&copied));
    let read = exchange(&service, as_main(http::Method::GET, "/keys/copy", Bytes::new())).await;
    assert_eq!(read.body().as_ref(), b"source");

    let delete = b"<Delete><Object><Key>C:\\x</Key></Object></Delete>";
    let deleted = exchange(
        &service,
        signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::POST,
            "/keys?delete",
            Bytes::from_static(delete),
            &[("content-md5", "EWJmvNBVFSZBJrSNvuGplQ==")],
        ),
    )
    .await;
    assert_eq!(deleted.status(), 200, "{}", body_of(&deleted));
    assert!(body_of(&deleted).contains("<Deleted>"), "{}", body_of(&deleted));
    assert!(!listed(&service).await.contains(&"C:\\x".to_owned()));
}

/// Negative — a literal `%2F` stays literal: it is not a separator, so `a/b` names another object.
#[tokio::test]
async fn n_a_literal_escape_is_not_a_separator() {
    let root = TestRoot::new();
    let service = keys_bucket(&root).await;
    let written = exchange(&service, as_main(http::Method::PUT, "/keys/a%252Fb", Bytes::from_static(b"literal"))).await;
    assert_eq!(written.status(), 200, "{}", body_of(&written));
    let other = exchange(&service, as_main(http::Method::GET, "/keys/a/b", Bytes::new())).await;
    assert_eq!(other.status(), 404, "a%2Fb must not be reachable as a/b");
    assert_eq!(listed(&service).await, vec!["a%2Fb".to_owned()]);
}

/// Negative — a NUL still stores nothing: an `ObjectKey` cannot hold one, and legacy RustFS refuses
/// it too, with the same code.
#[tokio::test]
async fn n_a_nul_key_stores_nothing() {
    let root = TestRoot::new();
    let service = keys_bucket(&root).await;
    let refused = exchange(&service, as_main(http::Method::PUT, "/keys/a%00b", Bytes::from_static(b"nul"))).await;
    assert_eq!(refused.status(), 400, "{}", body_of(&refused));
    assert!(body_of(&refused).contains("<Code>InvalidArgument</Code>"), "{}", body_of(&refused));
    assert!(listed(&service).await.is_empty());
}

/// Negative — a key over 1024 bytes stores nothing and is answered `KeyTooLongError`, as legacy
/// RustFS answers it.
#[tokio::test]
async fn n_an_overlong_key_stores_nothing() {
    let root = TestRoot::new();
    let service = keys_bucket(&root).await;
    let target = format!("/keys/{}", "k".repeat(1025));
    let refused = exchange(&service, as_main(http::Method::PUT, &target, Bytes::from_static(b"long"))).await;
    assert_eq!(refused.status(), 400, "{}", body_of(&refused));
    assert!(body_of(&refused).contains("<Code>KeyTooLongError</Code>"), "{}", body_of(&refused));
    assert!(listed(&service).await.is_empty());
}
