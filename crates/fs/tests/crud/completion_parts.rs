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

//! A completion's part list normalized as legacy RustFS normalizes it, once
//! `FsBackend::normalizing_completed_parts` is on (rustfs/gateway#1002).
//!
//! Responsible for: the last entry naming a part number kept and the earlier ones dropped unread —
//! s3-tests `test_multipart_resend_first_finishes_last` — then the kept list required to be
//! strictly increasing and within 1 to 10000, judged before the upload is looked up but after the
//! bucket; a kept entry still matched against its part's tag and checksum; and a retried
//! completion normalized the same way before it is compared with what was completed.
//! NOT responsible for: the default refusals, which `crud.rs` pins
//! (`completion_refuses_a_duplicate_part`, `completion_refuses_descending_parts`), or checksum
//! negotiation (`multipart_checksums.rs`).
//! Upstream: the assembled service over the fs backend (`super`). Downstream: nothing.

use super::multipart_sizing::{MIN_PART_SIZE, upload_owned};
use super::*;

/// The fixture service over a backend that normalizes a completion's part list.
fn normalizing(root: &TestRoot) -> S3Service {
    let backend = FsBackend::open_with_clock(&root.0, Arc::new(FixedClock::at_unix_seconds(SIGNED_AT_SECONDS)))
        .expect("a usable test root")
        .normalizing_completed_parts();
    service_with_backend(Arc::new(backend)).1
}

fn text(response: &rustfs_gateway::WireResponse) -> String {
    String::from_utf8_lossy(response.body()).into_owned()
}

/// One uploaded part: its entity tag and, for a checksum upload, its CRC32.
struct Uploaded {
    e_tag: String,
    crc32: Option<String>,
}

async fn upload(service: &S3Service, target: &str, upload_id: &str, number: i32, body: Bytes, crc32: bool) -> Uploaded {
    let mut headers = http::HeaderMap::new();
    if crc32 {
        headers.insert("x-amz-checksum-crc32", http::HeaderValue::from_str(&crc32_of(&body)).expect("base64"));
    }
    let response = exchange(
        service,
        signed_with_headers(
            http::Method::PUT,
            &format!("{target}?partNumber={number}&uploadId={upload_id}"),
            body,
            headers,
        ),
    )
    .await;
    assert_eq!(response.status(), 200, "{}", text(&response));
    Uploaded {
        e_tag: header(&response, "etag")
            .expect("a part tag")
            .to_str()
            .expect("ASCII")
            .to_owned(),
        crc32: header(&response, "x-amz-checksum-crc32").map(|value| value.to_str().expect("ASCII").to_owned()),
    }
}

/// Part 1 of `/{bucket}/key` at the minimum size a part that is not the last may have, sent in
/// frames as a large body arrives.
async fn full_size(service: &S3Service, bucket: &str, upload_id: &str) -> Uploaded {
    let e_tag = upload_owned(service, bucket, "key", upload_id, 1, Bytes::from(vec![b'x'; MIN_PART_SIZE])).await;
    Uploaded { e_tag, crc32: None }
}

/// The base64 CRC32 (IEEE) of `bytes`, as `x-amz-checksum-crc32` carries it.
fn crc32_of(bytes: &[u8]) -> String {
    let mut crc = 0xffff_ffff_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    let digest = (!crc).to_be_bytes();
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let triple = (u32::from(digest[0]) << 16) | (u32::from(digest[1]) << 8) | u32::from(digest[2]);
    let last = u32::from(digest[3]) << 16;
    [
        ALPHABET[(triple >> 18) as usize & 63],
        ALPHABET[(triple >> 12) as usize & 63],
        ALPHABET[(triple >> 6) as usize & 63],
        ALPHABET[triple as usize & 63],
        ALPHABET[(last >> 18) as usize & 63],
        ALPHABET[(last >> 12) as usize & 63],
        b'=',
        b'=',
    ]
    .iter()
    .map(|byte| char::from(*byte))
    .collect()
}

/// A completion document naming `(part number, tag, CRC32)` entries in the order given.
fn document(entries: &[(i32, &str, Option<&str>)]) -> Bytes {
    let mut body = String::from("<CompleteMultipartUpload>");
    for (number, e_tag, crc32) in entries {
        body.push_str(&format!("<Part><PartNumber>{number}</PartNumber><ETag>{e_tag}</ETag>"));
        if let Some(crc32) = crc32 {
            body.push_str(&format!("<ChecksumCRC32>{crc32}</ChecksumCRC32>"));
        }
        body.push_str("</Part>");
    }
    body.push_str("</CompleteMultipartUpload>");
    Bytes::from(body)
}

async fn finish(
    service: &S3Service,
    target: &str,
    upload_id: &str,
    entries: &[(i32, &str, Option<&str>)],
) -> rustfs_gateway::WireResponse {
    exchange(
        service,
        signed(http::Method::POST, &format!("{target}?uploadId={upload_id}"), document(entries)),
    )
    .await
}

async fn start(service: &S3Service, target: &str, crc32: bool) -> String {
    let mut headers = http::HeaderMap::new();
    if crc32 {
        headers.insert("x-amz-checksum-algorithm", http::HeaderValue::from_static("CRC32"));
    }
    let response = exchange(
        service,
        signed_with_headers(http::Method::POST, &format!("{target}?uploads"), Bytes::new(), headers),
    )
    .await;
    assert_eq!(response.status(), 200, "{}", text(&response));
    element(response.body(), "UploadId").expect("an upload id")
}

async fn read(service: &S3Service, target: &str) -> rustfs_gateway::WireResponse {
    exchange(service, signed(http::Method::GET, target, Bytes::new())).await
}

/// Asserts a refusal and that the upload is still there to be completed.
async fn assert_refused_keeping_the_upload(
    service: &S3Service,
    target: &str,
    upload_id: &str,
    response: &rustfs_gateway::WireResponse,
    code: &str,
    message: &str,
) {
    assert_eq!(response.status(), 400, "{}", text(response));
    assert_eq!(element(response.body(), "Code").as_deref(), Some(code), "{}", text(response));
    assert_eq!(element(response.body(), "Message").as_deref(), Some(message), "{}", text(response));
    assert_eq!(read(service, target).await.status(), 404, "nothing was published");
    let parts = read(service, &format!("{target}?uploadId={upload_id}")).await;
    assert_eq!(parts.status(), 200, "the upload stays: {}", text(&parts));
}

/// Positive — s3-tests `test_multipart_resend_first_finishes_last`: part 1 uploaded twice and named
/// twice, stale tag first; the last entry is kept, the first is never compared, and the object is
/// the part's last upload.
#[tokio::test]
async fn a_resent_part_completes_with_its_last_entry() {
    let root = TestRoot::new();
    let service = normalizing(&root);
    create_bucket(&service, "resent").await;
    let upload_id = start(&service, "/resent/key", false).await;
    let first = upload(&service, "/resent/key", &upload_id, 1, Bytes::from_static(b"B-first"), false).await;
    let second = upload(&service, "/resent/key", &upload_id, 1, Bytes::from_static(b"A-second"), false).await;

    let completed = finish(&service, "/resent/key", &upload_id, &[(1, &first.e_tag, None), (1, &second.e_tag, None)]).await;
    assert_eq!(completed.status(), 200, "{}", text(&completed));
    assert_eq!(read(&service, "/resent/key").await.body().as_ref(), b"A-second");
}

/// Positive — an entry repeated verbatim completes once: the part is not concatenated twice.
#[tokio::test]
async fn a_repeated_entry_completes_once() {
    let root = TestRoot::new();
    let service = normalizing(&root);
    create_bucket(&service, "repeated").await;
    let upload_id = start(&service, "/repeated/key", false).await;
    let part = upload(&service, "/repeated/key", &upload_id, 1, Bytes::from_static(b"once"), false).await;
    let completed = finish(&service, "/repeated/key", &upload_id, &[(1, &part.e_tag, None), (1, &part.e_tag, None)]).await;
    assert_eq!(completed.status(), 200, "{}", text(&completed));
    let e_tag = element(completed.body(), "ETag")
        .expect("a completed tag")
        .replace("&quot;", "")
        .replace('"', "");
    assert!(e_tag.ends_with("-1"), "one part, not two: {e_tag}");
    assert_eq!(read(&service, "/repeated/key").await.body().as_ref(), b"once");
}

/// Positive — the entries kept stay where their last occurrence was: `[2, 1, 2]` keeps `[1, 2]`.
#[tokio::test]
async fn a_repeat_behind_a_lower_part_keeps_the_order_of_last_occurrences() {
    let root = TestRoot::new();
    let service = normalizing(&root);
    create_bucket(&service, "reordered").await;
    let upload_id = start(&service, "/reordered/key", false).await;
    let one = full_size(&service, "reordered", &upload_id).await;
    let two = upload(&service, "/reordered/key", &upload_id, 2, Bytes::from_static(b"tail"), false).await;
    let entries = [
        (2, two.e_tag.as_str(), None),
        (1, one.e_tag.as_str(), None),
        (2, two.e_tag.as_str(), None),
    ];
    let completed = finish(&service, "/reordered/key", &upload_id, &entries).await;
    assert_eq!(completed.status(), 200, "{}", text(&completed));
    let body = read(&service, "/reordered/key").await;
    assert_eq!(body.body().len(), MIN_PART_SIZE + 4);
    assert!(body.body().ends_with(b"tail"));
}

/// Positive — a checksum upload is normalized alike: the dropped entry's checksum is never
/// compared, and the kept entry's is, with the object's checksum built from the kept part.
#[tokio::test]
async fn a_checksum_upload_keeps_the_last_entry_and_its_checksum() {
    let root = TestRoot::new();
    let service = normalizing(&root);
    create_bucket(&service, "checksummed").await;
    let upload_id = start(&service, "/checksummed/key", true).await;
    let first = upload(&service, "/checksummed/key", &upload_id, 1, Bytes::from_static(b"B-first"), true).await;
    let second = upload(&service, "/checksummed/key", &upload_id, 1, Bytes::from_static(b"A-second"), true).await;
    let entries = [
        (1, second.e_tag.as_str(), first.crc32.as_deref()),
        (1, second.e_tag.as_str(), second.crc32.as_deref()),
    ];
    let completed = finish(&service, "/checksummed/key", &upload_id, &entries).await;
    assert_eq!(completed.status(), 200, "{}", text(&completed));
    assert_eq!(element(completed.body(), "ChecksumType").as_deref(), Some("COMPOSITE"));
    assert_eq!(read(&service, "/checksummed/key").await.body().as_ref(), b"A-second");
}

/// Positive — a retry of a completion that named duplicates is normalized the same way, so it
/// replays the committed object, as does the retry naming the kept entry alone.
#[tokio::test]
async fn a_retried_completion_naming_duplicates_replays() {
    let root = TestRoot::new();
    let service = normalizing(&root);
    create_bucket(&service, "retried").await;
    let upload_id = start(&service, "/retried/key", false).await;
    let first = upload(&service, "/retried/key", &upload_id, 1, Bytes::from_static(b"B-first"), false).await;
    let second = upload(&service, "/retried/key", &upload_id, 1, Bytes::from_static(b"A-second"), false).await;
    let entries = [(1, first.e_tag.as_str(), None), (1, second.e_tag.as_str(), None)];
    let completed = finish(&service, "/retried/key", &upload_id, &entries).await;
    assert_eq!(completed.status(), 200, "{}", text(&completed));
    let e_tag = element(completed.body(), "ETag").expect("a completed tag");

    for retry in [&entries[..], &entries[1..]] {
        let again = finish(&service, "/retried/key", &upload_id, retry).await;
        assert_eq!(again.status(), 200, "{}", text(&again));
        assert_eq!(element(again.body(), "ETag").as_deref(), Some(e_tag.as_str()));
    }
}

/// Negative — a repeat that ends up out of order is refused: `[1, 2, 1]` keeps `[2, 1]`.
#[tokio::test]
async fn n_a_repeat_left_out_of_order_is_refused() {
    let root = TestRoot::new();
    let service = normalizing(&root);
    create_bucket(&service, "unordered").await;
    let upload_id = start(&service, "/unordered/key", false).await;
    let one = full_size(&service, "unordered", &upload_id).await;
    let two = upload(&service, "/unordered/key", &upload_id, 2, Bytes::from_static(b"tail"), false).await;
    let entries = [
        (1, one.e_tag.as_str(), None),
        (2, two.e_tag.as_str(), None),
        (1, one.e_tag.as_str(), None),
    ];
    let refused = finish(&service, "/unordered/key", &upload_id, &entries).await;
    let sentence = "Part numbers must be strictly increasing";
    assert_refused_keeping_the_upload(&service, "/unordered/key", &upload_id, &refused, "InvalidPartOrder", sentence).await;

    let entries = [(2, two.e_tag.as_str(), None), (1, one.e_tag.as_str(), None)];
    let refused = finish(&service, "/unordered/key", &upload_id, &entries).await;
    assert_refused_keeping_the_upload(&service, "/unordered/key", &upload_id, &refused, "InvalidPartOrder", sentence).await;
}

/// Negative — the kept entry is still matched against its part: a stale tag named last is
/// `InvalidPart`, however right the dropped entry was.
#[tokio::test]
async fn n_a_stale_last_entry_is_invalid_part() {
    let root = TestRoot::new();
    let service = normalizing(&root);
    create_bucket(&service, "stale").await;
    for (key, crc32) in [("plain", false), ("checksummed", true)] {
        let target = format!("/stale/{key}");
        let upload_id = start(&service, &target, crc32).await;
        let first = upload(&service, &target, &upload_id, 1, Bytes::from_static(b"B-first"), crc32).await;
        let second = upload(&service, &target, &upload_id, 1, Bytes::from_static(b"A-second"), crc32).await;
        let entries = [
            (1, second.e_tag.as_str(), second.crc32.as_deref()),
            (1, first.e_tag.as_str(), first.crc32.as_deref()),
        ];
        let refused = finish(&service, &target, &upload_id, &entries).await;
        assert_eq!(refused.status(), 400, "{key}: {}", text(&refused));
        assert_eq!(element(refused.body(), "Code").as_deref(), Some("InvalidPart"), "{key}");
        assert_eq!(read(&service, &target).await.status(), 404, "{key}");
    }
}

/// Negative — a kept part number outside 1 to 10000 is `InvalidPart`, as legacy RustFS words it.
#[tokio::test]
async fn n_a_part_number_outside_the_range_is_invalid_part() {
    let root = TestRoot::new();
    let service = normalizing(&root);
    create_bucket(&service, "ranged").await;
    let upload_id = start(&service, "/ranged/key", false).await;
    let part = upload(&service, "/ranged/key", &upload_id, 1, Bytes::from_static(b"part"), false).await;
    for (entries, number) in [
        (vec![(0, part.e_tag.as_str(), None)], 0),
        (vec![(1, part.e_tag.as_str(), None), (0, part.e_tag.as_str(), None)], 0),
        (vec![(10_001, part.e_tag.as_str(), None)], 10_001),
    ] {
        let refused = finish(&service, "/ranged/key", &upload_id, &entries).await;
        let sentence = format!("Part number {number} must be between 1 and 10000");
        assert_refused_keeping_the_upload(&service, "/ranged/key", &upload_id, &refused, "InvalidPart", &sentence).await;
    }
}

/// Negative — the list is judged before the upload is looked up, and after the bucket: an upload
/// that does not exist is `InvalidPartOrder` for `[2, 1]` but `NoSuchUpload` for `[1, 1]`, and a
/// missing bucket is `NoSuchBucket` whatever the list.
#[tokio::test]
async fn n_the_list_is_judged_between_the_bucket_and_the_upload() {
    let root = TestRoot::new();
    let service = normalizing(&root);
    create_bucket(&service, "judged").await;
    let upload_id = start(&service, "/judged/key", false).await;
    let part = upload(&service, "/judged/key", &upload_id, 1, Bytes::from_static(b"part"), false).await;
    let tag = part.e_tag.as_str();
    let unknown = start(&service, "/judged/key", false).await;
    let aborted = exchange(
        &service,
        signed(http::Method::DELETE, &format!("/judged/key?uploadId={unknown}"), Bytes::new()),
    )
    .await;
    assert_eq!(aborted.status(), 204, "{}", text(&aborted));
    let unknown = unknown.as_str();

    let descending = finish(&service, "/judged/key", unknown, &[(2, tag, None), (1, tag, None)]).await;
    assert_eq!(
        element(descending.body(), "Code").as_deref(),
        Some("InvalidPartOrder"),
        "{}",
        text(&descending)
    );
    let repeated = finish(&service, "/judged/key", unknown, &[(1, tag, None), (1, tag, None)]).await;
    assert_eq!(element(repeated.body(), "Code").as_deref(), Some("NoSuchUpload"), "{}", text(&repeated));
    let bucketless = finish(
        &service,
        "/no-such-bucket/key",
        &upload_id,
        &[(1, tag, None), (2, tag, None), (1, tag, None)],
    )
    .await;
    assert_eq!(
        element(bucketless.body(), "Code").as_deref(),
        Some("NoSuchBucket"),
        "{}",
        text(&bucketless)
    );
}

/// Negative — a retry whose last entry names another upload of the part is not the completion
/// that was made: `InvalidPart`, and the committed object stays.
#[tokio::test]
async fn n_a_retry_whose_kept_entry_differs_is_invalid_part() {
    let root = TestRoot::new();
    let service = normalizing(&root);
    create_bucket(&service, "diverged").await;
    let upload_id = start(&service, "/diverged/key", false).await;
    let first = upload(&service, "/diverged/key", &upload_id, 1, Bytes::from_static(b"B-first"), false).await;
    let second = upload(&service, "/diverged/key", &upload_id, 1, Bytes::from_static(b"A-second"), false).await;
    let entries = [(1, first.e_tag.as_str(), None), (1, second.e_tag.as_str(), None)];
    assert_eq!(finish(&service, "/diverged/key", &upload_id, &entries).await.status(), 200);

    let swapped = [(1, second.e_tag.as_str(), None), (1, first.e_tag.as_str(), None)];
    let refused = finish(&service, "/diverged/key", &upload_id, &swapped).await;
    assert_eq!(refused.status(), 400, "{}", text(&refused));
    assert_eq!(element(refused.body(), "Code").as_deref(), Some("InvalidPart"));
    assert_eq!(read(&service, "/diverged/key").await.body().as_ref(), b"A-second");
}

/// Negative — keeping the last entry does not relax the size rule: a small part kept before
/// another is `EntityTooSmall`, as on legacy RustFS.
#[tokio::test]
async fn n_a_small_kept_part_before_another_is_entity_too_small() {
    let root = TestRoot::new();
    let service = normalizing(&root);
    create_bucket(&service, "small").await;
    let upload_id = start(&service, "/small/key", false).await;
    let one = upload(&service, "/small/key", &upload_id, 1, Bytes::from_static(b"tiny"), false).await;
    let two = upload(&service, "/small/key", &upload_id, 2, Bytes::from_static(b"tail"), false).await;
    let entries = [
        (1, one.e_tag.as_str(), None),
        (1, one.e_tag.as_str(), None),
        (2, two.e_tag.as_str(), None),
    ];
    let refused = finish(&service, "/small/key", &upload_id, &entries).await;
    assert_eq!(refused.status(), 400, "{}", text(&refused));
    assert_eq!(element(refused.body(), "Code").as_deref(), Some("EntityTooSmall"));
    assert_eq!(read(&service, "/small/key").await.status(), 404);
}

/// Negative — naming a part twice does not make it exist: a part never uploaded is `InvalidPart`.
#[tokio::test]
async fn n_a_repeated_part_never_uploaded_is_invalid_part() {
    let root = TestRoot::new();
    let service = normalizing(&root);
    create_bucket(&service, "never").await;
    let upload_id = start(&service, "/never/key", false).await;
    let one = full_size(&service, "never", &upload_id).await;
    let bogus = "\"0123456789abcdef0123456789abcdef\"";
    let entries = [(1, one.e_tag.as_str(), None), (2, bogus, None), (2, bogus, None)];
    let refused = finish(&service, "/never/key", &upload_id, &entries).await;
    assert_eq!(refused.status(), 400, "{}", text(&refused));
    assert_eq!(element(refused.body(), "Code").as_deref(), Some("InvalidPart"));
    assert_eq!(read(&service, "/never/key").await.status(), 404);
}

/// Negative — a retry is judged before it is compared: `[1, 2, 1]` against a completed upload is
/// `InvalidPartOrder`, not a replay and not `NoSuchUpload`, and the object stays.
#[tokio::test]
async fn n_a_retry_left_out_of_order_is_refused() {
    let root = TestRoot::new();
    let service = normalizing(&root);
    create_bucket(&service, "retry-order").await;
    let upload_id = start(&service, "/retry-order/key", false).await;
    let one = upload(&service, "/retry-order/key", &upload_id, 1, Bytes::from_static(b"one"), false).await;
    let completed = finish(&service, "/retry-order/key", &upload_id, &[(1, one.e_tag.as_str(), None)]).await;
    assert_eq!(completed.status(), 200, "{}", text(&completed));

    let bogus = "\"0123456789abcdef0123456789abcdef\"";
    let entries = [(1, one.e_tag.as_str(), None), (2, bogus, None), (1, one.e_tag.as_str(), None)];
    let refused = finish(&service, "/retry-order/key", &upload_id, &entries).await;
    assert_eq!(refused.status(), 400, "{}", text(&refused));
    assert_eq!(element(refused.body(), "Code").as_deref(), Some("InvalidPartOrder"));
    assert_eq!(read(&service, "/retry-order/key").await.body().as_ref(), b"one");
}
