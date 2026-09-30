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

//! The keys legacy RustFS's object handlers and disk refuse beyond its storage's name rule, as
//! the launcher serves them (rustfs/gateway#1153).
//!
//! Responsible for: a key holding a NUL, CR or LF refused with legacy RustFS's own sentence on
//! exactly the operations whose handlers check it (PutObject, GetObject, HeadObject, DeleteObject
//! and CopyObject's two keys), in legacy RustFS's order around the bucket lookup, and stored by a
//! multipart upload as legacy RustFS stores it; a key with a `/`-separated segment
//! its disk cannot name refused `400 InvalidArgument` "Invalid argument" with nothing stored; and
//! the keys both rules keep. Every expectation is legacy RustFS's answer on a legacy build, except
//! the `400` for a segment on the operations whose legacy answer depends on its disk (module
//! documentation of `crate::storage_names`).
//! NOT responsible for: the rules themselves (`crate::storage_names`' tests), or the `.`, `..`,
//! `//` and NUL rule of RustFS's storage (`legacy_storage_names_tests`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::legacy_storage_names_tests::posted;
use super::*;

/// Path spellings of keys legacy RustFS's handlers refuse, with the key each decodes to. A NUL is
/// refused by the RustFS profile's key floor before any layer runs (`crate::storage_names`).
const CONTROLLED: [(&str, &str); 2] = [("a%0Ab", "a\nb"), ("a%0Db", "a\rb")];

/// A tagging document.
const TAGS: &[u8] = b"<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>";

/// Keys with a segment RustFS's disk cannot name, as path spellings: a flat key, one under a
/// parent nothing is stored under, one whose long segment is a directory, a directory key whose
/// last segment is one byte over the budget its `__XLDIR__` suffix leaves, and a key of two-byte
/// characters counted in bytes.
fn too_long() -> Vec<String> {
    vec![
        "x".repeat(256),
        format!("q/{}", "x".repeat(256)),
        format!("{}/a", "x".repeat(256)),
        format!("d/{}/", "z".repeat(247)),
        "%C3%A9".repeat(129),
    ]
}

async fn keys_bucket(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/keys", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let written = exchange(&service, as_main(http::Method::PUT, "/keys/ok", Bytes::from_static(b"ok"))).await;
    assert_eq!(written.status(), 200, "{}", body_of(&written));
    service
}

fn as_main_with(method: http::Method, target: &str, body: Bytes, headers: &[(&str, &str)]) -> http::Request<Bytes> {
    signed(MAIN_KEY, MAIN_SECRET, method, target, body, headers)
}

/// Fails unless `response` is legacy RustFS's refusal of a control character in `key`: its code,
/// and its sentence naming the key as Rust's `Debug` renders it, compared as XML text.
fn assert_control_refused(response: &WireResponse, key: &str, label: &str) {
    let body = body_of(response);
    assert_eq!(response.status(), 400, "{label}: {body}");
    assert!(body.contains("<Code>InvalidArgument</Code>"), "{label}: {body}");
    let text = body.replace("&quot;", "\"").replace("&apos;", "'");
    let sentence = format!("<Message>Object key contains invalid control characters: {key:?}</Message>");
    assert!(text.contains(&sentence), "{label}: expected {sentence} in {body}");
}

/// Fails unless `response` is the refusal of a name RustFS cannot hold.
fn assert_refused(response: &WireResponse, label: &str) {
    let body = body_of(response);
    assert_eq!(response.status(), 400, "{label}: {body}");
    assert!(body.contains("<Code>InvalidArgument</Code>"), "{label}: {body}");
    assert!(body.contains("<Message>Invalid argument</Message>"), "{label}: {body}");
}

/// Fails unless `response` is the missing-bucket answer.
fn assert_no_bucket(response: &WireResponse, label: &str) {
    let body = body_of(response);
    assert_eq!(response.status(), 404, "{label}: {body}");
    assert!(body.contains("<Code>NoSuchBucket</Code>"), "{label}: {body}");
}

async fn listed_keys(service: &S3Service, target: &str) -> usize {
    let listing = exchange(service, as_main(http::Method::GET, target, Bytes::new())).await;
    assert_eq!(listing.status(), 200, "{target}: {}", body_of(&listing));
    body_of(&listing).matches("<Key>").count()
}

/// Negative — a NUL, CR or LF in a key is refused with legacy RustFS's sentence by each of the
/// operations whose handlers check it (a `HEAD` without a body), and nothing is stored. A browser
/// form naming such a key is refused before any handler by the gateway's form reader, a difference
/// of the RustFS profile's POST forms recorded in `crate::storage_names`, so it is not asserted here.
#[tokio::test]
async fn n_a_control_character_is_refused_by_the_handlers_that_check_it() {
    let root = TestRoot::new();
    let service = keys_bucket(&root).await;
    for (spelled, key) in CONTROLLED {
        let target = format!("/keys/{spelled}");
        for (method, body) in [
            (http::Method::PUT, Bytes::from_static(b"bytes")),
            (http::Method::GET, Bytes::new()),
            (http::Method::DELETE, Bytes::new()),
        ] {
            let label = format!("{method} {target}");
            assert_control_refused(&exchange(&service, as_main(method, &target, body)).await, key, &label);
        }
        let head = exchange(&service, as_main(http::Method::HEAD, &target, Bytes::new())).await;
        assert_eq!(head.status(), 400, "HEAD {target}");
        assert!(head.body().is_empty(), "HEAD {target}");
        let copied_to = exchange(
            &service,
            as_main_with(http::Method::PUT, &target, Bytes::new(), &[("x-amz-copy-source", "keys/ok")]),
        )
        .await;
        assert_control_refused(&copied_to, key, &format!("a copy to {target}"));
        let source = format!("keys/{spelled}");
        let copied_from = exchange(
            &service,
            as_main_with(http::Method::PUT, "/keys/copy", Bytes::new(), &[("x-amz-copy-source", &source)]),
        )
        .await;
        assert_control_refused(&copied_from, key, &format!("a copy from {source}"));
    }
    assert_eq!(listed_keys(&service, "/keys?list-type=2").await, 1, "only `ok` is stored");
}

/// Negative — GetObject and HeadObject judge the key before the bucket; every other checking
/// handler, and a copy for both of its buckets, looks the bucket up first; a copy naming two
/// refused keys is answered for its source.
#[tokio::test]
async fn n_a_control_character_is_judged_in_legacy_rustfs_s_order() {
    let root = TestRoot::new();
    let service = keys_bucket(&root).await;
    let refused = exchange(&service, as_main(http::Method::GET, "/absent/a%0Ab", Bytes::new())).await;
    assert_control_refused(&refused, "a\nb", "GET on a missing bucket");
    let head = exchange(&service, as_main(http::Method::HEAD, "/absent/a%0Db", Bytes::new())).await;
    assert_eq!(head.status(), 400, "HEAD on a missing bucket");
    for (method, body) in [
        (http::Method::PUT, Bytes::from_static(b"bytes")),
        (http::Method::DELETE, Bytes::new()),
    ] {
        let label = format!("{method} on a missing bucket");
        assert_no_bucket(&exchange(&service, as_main(method, "/absent/a%0Ab", body)).await, &label);
    }
    for (target, source) in [
        ("/absent/a%0Ab", "keys/ok"),
        ("/keys/a%0Ab", "absent/ok"),
        ("/keys/copy", "absent/a%0Ab"),
    ] {
        let copied = exchange(
            &service,
            as_main_with(http::Method::PUT, target, Bytes::new(), &[("x-amz-copy-source", source)]),
        )
        .await;
        assert_no_bucket(&copied, &format!("{target} from {source}"));
    }
    let both = exchange(
        &service,
        as_main_with(http::Method::PUT, "/keys/a%0Db", Bytes::new(), &[("x-amz-copy-source", "keys/c%0Ad")]),
    )
    .await;
    assert_control_refused(&both, "c\nd", "a copy naming two refused keys");
}

/// Negative — a segment RustFS's disk cannot name is refused on every operation that reaches it
/// (a `HEAD` without a body), nothing is stored and no upload starts; an operation on an upload
/// under that key answers `404 NoSuchUpload`, as legacy RustFS's upload lookup does.
#[tokio::test]
async fn n_a_segment_too_long_for_rustfs_s_disk_is_refused_and_nothing_is_stored() {
    let root = TestRoot::new();
    let service = keys_bucket(&root).await;
    for key in too_long() {
        let target = format!("/keys/{key}");
        let requests = [
            (http::Method::PUT, target.clone(), Bytes::from_static(b"bytes")),
            (http::Method::GET, target.clone(), Bytes::new()),
            (http::Method::DELETE, target.clone(), Bytes::new()),
            (http::Method::POST, format!("{target}?uploads"), Bytes::new()),
            (http::Method::GET, format!("{target}?tagging"), Bytes::new()),
            (http::Method::PUT, format!("{target}?tagging"), Bytes::from_static(TAGS)),
            (http::Method::DELETE, format!("{target}?tagging"), Bytes::new()),
            (http::Method::GET, format!("{target}?acl"), Bytes::new()),
        ];
        for (method, target, body) in requests {
            let label = format!("{method} {}", &target[..target.len().min(40)]);
            assert_refused(&exchange(&service, as_main(method, &target, body)).await, &label);
        }
        let acl = as_main_with(http::Method::PUT, &format!("{target}?acl"), Bytes::new(), &[("x-amz-acl", "private")]);
        assert_refused(&exchange(&service, acl).await, "PUT ?acl");
        let head = exchange(&service, as_main(http::Method::HEAD, &target, Bytes::new())).await;
        assert_eq!(head.status(), 400, "HEAD");
        assert!(head.body().is_empty(), "HEAD");
        let copied_to = exchange(
            &service,
            as_main_with(http::Method::PUT, &target, Bytes::new(), &[("x-amz-copy-source", "keys/ok")]),
        )
        .await;
        assert_refused(&copied_to, "a copy to a long key");
        let source = format!("keys/{key}");
        let copied_from = exchange(
            &service,
            as_main_with(http::Method::PUT, "/keys/copy", Bytes::new(), &[("x-amz-copy-source", &source)]),
        )
        .await;
        assert_refused(&copied_from, "a copy from a long key");
        for (method, target) in [
            (http::Method::PUT, format!("{target}?partNumber=1&uploadId=bm9uZQ")),
            (http::Method::GET, format!("{target}?uploadId=bm9uZQ")),
            (http::Method::DELETE, format!("{target}?uploadId=bm9uZQ")),
        ] {
            let answered = exchange(&service, as_main(method.clone(), &target, Bytes::from_static(b"p"))).await;
            let body = body_of(&answered);
            assert_eq!(answered.status(), 404, "{method} on an upload: {body}");
            assert!(body.contains("<Code>NoSuchUpload</Code>"), "{method} on an upload: {body}");
        }
    }
    let form_key = "x".repeat(256);
    assert_refused(&exchange(&service, posted("keys", &form_key)).await, "a form under a long key");
    assert_eq!(listed_keys(&service, "/keys?list-type=2").await, 1, "only `ok` is stored");
    assert_eq!(listed_keys(&service, "/keys?uploads").await, 0, "no upload started");
}

/// Negative — on a bucket that does not exist the bucket is answered first, except on the tagging
/// and ACL operations, which judge the name first, as legacy RustFS does.
#[tokio::test]
async fn n_a_long_segment_on_a_missing_bucket_is_answered_in_legacy_rustfs_s_order() {
    let root = TestRoot::new();
    let service = keys_bucket(&root).await;
    let target = format!("/absent/{}", "x".repeat(256));
    for (method, target) in [
        (http::Method::PUT, target.clone()),
        (http::Method::GET, target.clone()),
        (http::Method::DELETE, target.clone()),
        (http::Method::POST, format!("{target}?uploads")),
    ] {
        let label = format!("{method} on a missing bucket");
        assert_no_bucket(&exchange(&service, as_main(method, &target, Bytes::new())).await, &label);
    }
    for (method, target) in [
        (http::Method::GET, format!("{target}?tagging")),
        (http::Method::DELETE, format!("{target}?tagging")),
        (http::Method::GET, format!("{target}?acl")),
    ] {
        let label = format!("{method} ?subresource on a missing bucket");
        assert_refused(&exchange(&service, as_main(method, &target, Bytes::new())).await, &label);
    }
}

/// Negative — a part copied from a source with a segment RustFS's disk cannot name is refused under
/// an upload that exists, and a batch delete answers each such key with its own `InvalidArgument`
/// entry and deletes the rest.
#[tokio::test]
async fn n_a_long_segment_is_refused_as_a_part_copy_source_and_in_a_batch_delete() {
    let root = TestRoot::new();
    let service = keys_bucket(&root).await;
    let started = exchange(&service, as_main(http::Method::POST, "/keys/up?uploads", Bytes::new())).await;
    let started = body_of(&started);
    let upload = started
        .split_once("<UploadId>")
        .and_then(|(_, rest)| rest.split_once("</UploadId>"))
        .map(|(id, _)| id.to_owned())
        .expect("an upload id");
    let source = format!("keys/{}", "x".repeat(256));
    let part = exchange(
        &service,
        as_main_with(
            http::Method::PUT,
            &format!("/keys/up?partNumber=1&uploadId={upload}"),
            Bytes::new(),
            &[("x-amz-copy-source", &source)],
        ),
    )
    .await;
    assert_refused(&part, "a part copied from a long key");
    let batch = format!(
        "<Delete><Object><Key>{}</Key></Object><Object><Key>ok</Key></Object><Object><Key>q/{}</Key></Object></Delete>",
        "x".repeat(256),
        "x".repeat(256)
    );
    let deleted = exchange(&service, as_main(http::Method::POST, "/keys?delete", Bytes::from(batch))).await;
    let body = body_of(&deleted);
    assert_eq!(deleted.status(), 200, "{body}");
    assert_eq!(body.matches("<Deleted>").count(), 1, "{body}");
    assert!(body.contains("<Key>ok</Key>"), "{body}");
    assert_eq!(body.matches("<Code>InvalidArgument</Code>").count(), 2, "{body}");
    assert_eq!(listed_keys(&service, "/keys?list-type=2").await, 0);
}

/// Positive — the keys both rules keep are stored and read back: a 255-byte segment, a directory
/// key whose last segment fits its suffix's budget, and a control character written by a multipart
/// upload, which legacy RustFS stores (and then refuses to read); a listing under a long prefix
/// answers as usual.
#[tokio::test]
async fn the_keys_legacy_rustfs_keeps_are_stored() {
    let root = TestRoot::new();
    let service = keys_bucket(&root).await;
    for key in ["w".repeat(255), format!("d/{}/", "z".repeat(246))] {
        let target = format!("/keys/{key}");
        let written = exchange(&service, as_main(http::Method::PUT, &target, Bytes::from_static(b"kept"))).await;
        assert_eq!(written.status(), 200, "{}", body_of(&written));
        let read = exchange(&service, as_main(http::Method::GET, &target, Bytes::new())).await;
        assert_eq!(read.status(), 200, "{}", body_of(&read));
    }
    let started = exchange(&service, as_main(http::Method::POST, "/keys/c%0Ad?uploads", Bytes::new())).await;
    let started = body_of(&started);
    let upload = started
        .split_once("<UploadId>")
        .and_then(|(_, rest)| rest.split_once("</UploadId>"))
        .map(|(id, _)| id.to_owned())
        .expect("an upload id");
    let part = exchange(
        &service,
        as_main(
            http::Method::PUT,
            &format!("/keys/c%0Ad?partNumber=1&uploadId={upload}"),
            Bytes::from_static(b"part"),
        ),
    )
    .await;
    assert_eq!(part.status(), 200, "{}", body_of(&part));
    let etag = part.header("etag").expect("a part ETag").to_owned();
    let completion =
        format!("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part></CompleteMultipartUpload>");
    let completed = exchange(
        &service,
        as_main(http::Method::POST, &format!("/keys/c%0Ad?uploadId={upload}"), Bytes::from(completion)),
    )
    .await;
    assert_eq!(completed.status(), 200, "{}", body_of(&completed));
    assert_eq!(listed_keys(&service, "/keys?list-type=2").await, 4);
    let read = exchange(&service, as_main(http::Method::GET, "/keys/c%0Ad", Bytes::new())).await;
    assert_control_refused(&read, "c\nd", "reading the multipart object back");
    let long_prefix = format!("/keys?list-type=2&prefix={}", "x".repeat(256));
    assert_eq!(listed_keys(&service, &long_prefix).await, 0);
}
