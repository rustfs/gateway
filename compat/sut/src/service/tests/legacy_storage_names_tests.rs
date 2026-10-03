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

//! The object names RustFS's storage refuses, as the launcher serves them (rustfs/gateway#1145).
//!
//! Responsible for: a key, a copy source, a browser form's key and a listing prefix with a `.` or
//! `..` segment, `//` or a NUL answered `400 InvalidArgument` "Invalid argument" with nothing
//! stored or listed; RustFS's order around it — `404 NoSuchBucket` first on a missing bucket
//! except on the tagging and ACL operations, and authentication, authorization and a request
//! document's decode before it; a batch delete answering each refused key and deleting the rest;
//! and the names RustFS's storage keeps stored as before. Every expectation is legacy RustFS's
//! answer on a legacy build.
//! NOT responsible for: the rule itself (`crate::storage_names`' tests), or the key the gateway
//! hands the backend (the difftest RustFS-profile key rows).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use hmac::{Hmac, KeyInit, Mac};

use super::*;

/// Key shapes RustFS's storage refuses, as path spellings under `/names/`.
const REFUSED: [&str; 11] = [
    "a/./b=",
    "a/../b",
    "./b",
    "a/.",
    "..",
    "a//b",
    "a/b//",
    "a%5C..%5Cb",
    "a/%20../b",
    "a/.%2Fb",
    "a%2F%2Fb",
];

/// A tagging document.
const TAGS: &[u8] = b"<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>";

/// A completion naming one part.
const COMPLETE: &[u8] =
    b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"e\"</ETag></Part></CompleteMultipartUpload>";

/// Key shapes RustFS's storage keeps.
const KEPT: [&str; 5] = ["a/b=", "a/.b", "a/..b", "a/b.", "a/b/"];

async fn names_bucket(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/names", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    service
}

fn as_main_with(method: http::Method, target: &str, body: Bytes, headers: &[(&str, &str)]) -> http::Request<Bytes> {
    signed(MAIN_KEY, MAIN_SECRET, method, target, body, headers)
}

/// Fails unless `response` is RustFS's refusal of a name its storage cannot hold.
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

/// Negative — every operation on a refused key is `400 InvalidArgument` (a `HEAD` without a body),
/// and nothing is stored, listed or left as an upload.
#[tokio::test]
async fn n_a_refused_key_is_refused_on_every_operation_and_nothing_is_stored() {
    let root = TestRoot::new();
    let service = names_bucket(&root).await;
    for key in REFUSED {
        let target = format!("/names/{key}");
        let requests = [
            (http::Method::PUT, target.clone(), Bytes::from_static(b"bytes")),
            (http::Method::GET, target.clone(), Bytes::new()),
            (http::Method::DELETE, target.clone(), Bytes::new()),
            (http::Method::POST, format!("{target}?uploads"), Bytes::new()),
            (http::Method::GET, format!("{target}?tagging"), Bytes::new()),
            (http::Method::GET, format!("{target}?acl"), Bytes::new()),
            (
                http::Method::PUT,
                format!("{target}?partNumber=1&uploadId=bm9uZQ"),
                Bytes::from_static(b"part"),
            ),
            (http::Method::GET, format!("{target}?uploadId=bm9uZQ"), Bytes::new()),
            (http::Method::DELETE, format!("{target}?uploadId=bm9uZQ"), Bytes::new()),
            (http::Method::POST, format!("{target}?uploadId=bm9uZQ"), Bytes::from_static(COMPLETE)),
            (http::Method::PUT, format!("{target}?tagging"), Bytes::from_static(TAGS)),
            (http::Method::DELETE, format!("{target}?tagging"), Bytes::new()),
        ];
        for (method, target, body) in requests {
            let label = format!("{method} {target}");
            assert_refused(&exchange(&service, as_main(method, &target, body)).await, &label);
        }
        for (target, header) in [
            (format!("{target}?acl"), ("x-amz-acl", "private")),
            (format!("{target}?partNumber=1&uploadId=bm9uZQ"), ("x-amz-copy-source", "names/ok")),
        ] {
            let request = as_main_with(http::Method::PUT, &target, Bytes::new(), &[header]);
            assert_refused(&exchange(&service, request).await, &format!("PUT {target}"));
        }
        let head = exchange(&service, as_main(http::Method::HEAD, &target, Bytes::new())).await;
        assert_eq!(head.status(), 400, "HEAD {target}");
        assert!(head.body().is_empty(), "HEAD {target}");
    }
    assert_eq!(listed_keys(&service, "/names?list-type=2").await, 0);
    assert_eq!(listed_keys(&service, "/names?uploads").await, 0);
}

/// Negative — a refused copy source or destination and a refused listing prefix are refused, and
/// nothing new is stored.
#[tokio::test]
async fn n_a_refused_copy_source_or_prefix_is_refused() {
    let root = TestRoot::new();
    let service = names_bucket(&root).await;
    let written = exchange(&service, as_main(http::Method::PUT, "/names/ok", Bytes::from_static(b"ok"))).await;
    assert_eq!(written.status(), 200, "{}", body_of(&written));
    for source in ["names/a/./b", "/names/a//b", "names/a%2F..%2Fb?versionId=null"] {
        let copied = exchange(
            &service,
            as_main_with(http::Method::PUT, "/names/copy", Bytes::new(), &[("x-amz-copy-source", source)]),
        )
        .await;
        assert_refused(&copied, source);
    }
    let copied = exchange(
        &service,
        as_main_with(http::Method::PUT, "/names/a/./b", Bytes::new(), &[("x-amz-copy-source", "names/ok")]),
    )
    .await;
    assert_refused(&copied, "a copy to a refused key");
    let started = exchange(&service, as_main(http::Method::POST, "/names/up?uploads", Bytes::new())).await;
    let started = body_of(&started);
    let upload = started
        .split_once("<UploadId>")
        .and_then(|(_, rest)| rest.split_once("</UploadId>"))
        .map(|(id, _)| id.to_owned())
        .expect("an upload id");
    let part = exchange(
        &service,
        as_main_with(
            http::Method::PUT,
            &format!("/names/up?partNumber=1&uploadId={upload}"),
            Bytes::new(),
            &[("x-amz-copy-source", "names/a/./b")],
        ),
    )
    .await;
    assert_refused(&part, "a part copied from a refused source");
    assert_eq!(listed_keys(&service, "/names?list-type=2").await, 1);
    for listing in [
        "/names?list-type=2&prefix=",
        "/names?prefix=",
        "/names?versions&prefix=",
        "/names?uploads&prefix=",
    ] {
        for prefix in ["a/./b", "a//b", "./", "a/..", "a%00b"] {
            let target = format!("{listing}{}", prefix.replace('/', "%2F"));
            assert_refused(&exchange(&service, as_main(http::Method::GET, &target, Bytes::new())).await, &target);
        }
    }
}

/// Negative — on a bucket that does not exist the bucket is answered first, except on the tagging
/// and ACL operations, which judge the name first; a copy looks both buckets up first.
#[tokio::test]
async fn n_a_missing_bucket_is_answered_before_the_name_but_on_tagging_and_acls() {
    let root = TestRoot::new();
    let service = names_bucket(&root).await;
    for (method, target) in [
        (http::Method::GET, "/absent/a/./b"),
        (http::Method::PUT, "/absent/a/./b"),
        (http::Method::DELETE, "/absent/a/./b"),
        (http::Method::POST, "/absent/a/./b?uploads"),
        (http::Method::GET, "/absent?list-type=2&prefix=a%2F.%2Fb"),
    ] {
        let label = format!("{method} {target}");
        assert_no_bucket(&exchange(&service, as_main(method, target, Bytes::new())).await, &label);
    }
    for (method, target) in [
        (http::Method::GET, "/absent/a/./b?tagging"),
        (http::Method::DELETE, "/absent/a/./b?tagging"),
        (http::Method::GET, "/absent/a/./b?acl"),
    ] {
        let label = format!("{method} {target}");
        assert_refused(&exchange(&service, as_main(method, target, Bytes::new())).await, &label);
    }
    for (target, source) in [("/absent/copy", "names/a/./b"), ("/names/a/./b", "absent/src")] {
        let copied = exchange(
            &service,
            as_main_with(http::Method::PUT, target, Bytes::new(), &[("x-amz-copy-source", source)]),
        )
        .await;
        assert_no_bucket(&copied, &format!("{target} from {source}"));
    }
}

/// Negative — the name is judged after the caller: an anonymous request and another identity are
/// refused access, and a malformed tagging document is `MalformedXML`, as on RustFS.
#[tokio::test]
async fn n_a_refused_name_is_judged_after_authorization_and_the_document() {
    let root = TestRoot::new();
    let service = names_bucket(&root).await;
    let anonymous = http::Request::builder()
        .method(http::Method::GET)
        .uri("/names/a/./b")
        .header(http::header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("a valid request");
    let refused = exchange(&service, anonymous).await;
    assert_eq!(refused.status(), 403, "{}", body_of(&refused));
    let foreign = exchange(&service, as_alt(http::Method::GET, "/names/a/./b", Bytes::new())).await;
    assert_eq!(foreign.status(), 403, "{}", body_of(&foreign));
    let malformed = exchange(
        &service,
        as_main(http::Method::PUT, "/names/a/./b?tagging", Bytes::from_static(b"<Tagging><TagSet><Tag>")),
    )
    .await;
    assert_eq!(malformed.status(), 400, "{}", body_of(&malformed));
    assert!(body_of(&malformed).contains("<Code>MalformedXML</Code>"), "{}", body_of(&malformed));
}

/// A bucket named `bucket` under `versioning` (`None` for never configured) holding `a/b` and `ok`.
async fn batch_bucket(service: &S3Service, bucket: &str, versioning: Option<&str>) {
    let created = exchange(service, as_main(http::Method::PUT, &format!("/{bucket}"), Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    if let Some(status) = versioning {
        let document = format!("<VersioningConfiguration><Status>{status}</Status></VersioningConfiguration>");
        let set = exchange(
            service,
            as_main(http::Method::PUT, &format!("/{bucket}?versioning"), Bytes::from(document)),
        )
        .await;
        assert_eq!(set.status(), 200, "{}", body_of(&set));
    }
    for key in ["a/b", "ok"] {
        let written = exchange(service, as_main(http::Method::PUT, &format!("/{bucket}/{key}"), Bytes::from(key))).await;
        assert_eq!(written.status(), 200, "{}", body_of(&written));
    }
}

/// Deletes `a/./b`, `ok` and `a//b` from `bucket` in one batch, and returns the answer.
async fn batch_delete(service: &S3Service, bucket: &str) -> String {
    let batch = Bytes::from_static(
        b"<Delete><Object><Key>a/./b</Key></Object><Object><Key>ok</Key></Object><Object><Key>a//b</Key></Object></Delete>",
    );
    let deleted = exchange(service, as_main(http::Method::POST, &format!("/{bucket}?delete"), batch)).await;
    let body = body_of(&deleted);
    assert_eq!(deleted.status(), 200, "{body}");
    body
}

/// Negative — a batch delete answers each refused key with its own `InvalidArgument` entry and
/// deletes the others, on a bucket never versioned and on a suspended one, as legacy RustFS does;
/// the object the refused keys resolve to on a disk (`a/b`) is untouched.
#[tokio::test]
async fn n_a_batch_delete_answers_each_refused_key_and_deletes_the_rest() {
    let root = TestRoot::new();
    let service = names_bucket(&root).await;
    for (bucket, versioning) in [("batch-plain", None), ("batch-suspended", Some("Suspended"))] {
        batch_bucket(&service, bucket, versioning).await;
        let body = batch_delete(&service, bucket).await;
        assert_eq!(body.matches("<Deleted>").count(), 1, "{bucket}: {body}");
        assert!(body.contains("<Key>ok</Key>"), "{bucket}: {body}");
        assert_eq!(body.matches("<Error>").count(), 2, "{bucket}: {body}");
        assert_eq!(body.matches("<Code>InvalidArgument</Code>").count(), 2, "{bucket}: {body}");
        assert_eq!(body.matches("<Message>Invalid argument</Message>").count(), 2, "{bucket}: {body}");
        let read = exchange(&service, as_main(http::Method::GET, &format!("/{bucket}/a/b"), Bytes::new())).await;
        assert_eq!(read.status(), 200, "{bucket}: {}", body_of(&read));
        let gone = exchange(&service, as_main(http::Method::GET, &format!("/{bucket}/ok"), Bytes::new())).await;
        assert_eq!(gone.status(), 404, "{bucket}: {}", body_of(&gone));
    }
}

/// Negative — on a bucket with versioning enabled the refused keys are answered the same way and
/// no delete marker is recorded for them or for the object they resolve to on a disk. Legacy
/// RustFS answers them as deleted there and records its marker under the path its disk resolves
/// them to, hiding `a/b`: a defect of its storage, reported to the maintainers, that the launcher
/// does not reproduce.
#[tokio::test]
async fn n_a_batch_delete_on_an_enabled_bucket_hides_no_other_object() {
    let root = TestRoot::new();
    let service = names_bucket(&root).await;
    batch_bucket(&service, "batch-enabled", Some("Enabled")).await;
    let body = batch_delete(&service, "batch-enabled").await;
    assert_eq!(body.matches("<Code>InvalidArgument</Code>").count(), 2, "{body}");
    let read = exchange(&service, as_main(http::Method::GET, "/batch-enabled/a/b", Bytes::new())).await;
    assert_eq!(read.status(), 200, "{}", body_of(&read));
    let versions = exchange(&service, as_main(http::Method::GET, "/batch-enabled?versions", Bytes::new())).await;
    let listed = body_of(&versions);
    assert_eq!(versions.status(), 200, "{listed}");
    assert_eq!(listed.matches("<DeleteMarker>").count(), 1, "only `ok` gained a marker: {listed}");
}

/// Negative — a browser form naming a refused key is refused and stores nothing; on a bucket that
/// does not exist the bucket is answered first.
#[tokio::test]
async fn n_a_form_upload_under_a_refused_key_stores_nothing() {
    let root = TestRoot::new();
    let service = names_bucket(&root).await;
    let refused = exchange(&service, posted("names", "a/./b")).await;
    assert_refused(&refused, "a form under a/./b");
    assert_eq!(listed_keys(&service, "/names?list-type=2").await, 0);
    let stored = exchange(&service, posted("names", "a/.b")).await;
    assert_eq!(stored.status(), 204, "{}", body_of(&stored));
    assert_no_bucket(&exchange(&service, posted("absent", "a/./b")).await, "a form to a missing bucket");
}

/// Positive — the names RustFS's storage keeps are stored, read back, listed and copied as before.
#[tokio::test]
async fn the_names_rustfs_s_storage_keeps_are_stored() {
    let root = TestRoot::new();
    let service = names_bucket(&root).await;
    for key in KEPT {
        let target = format!("/names/{key}");
        let written = exchange(&service, as_main(http::Method::PUT, &target, Bytes::from(key))).await;
        assert_eq!(written.status(), 200, "{target}: {}", body_of(&written));
        let read = exchange(&service, as_main(http::Method::GET, &target, Bytes::new())).await;
        assert_eq!(read.status(), 200, "{target}: {}", body_of(&read));
        assert_eq!(read.body().as_ref(), key.as_bytes(), "{target}");
    }
    assert_eq!(listed_keys(&service, "/names?list-type=2&prefix=a%2F").await, KEPT.len());
    let copied = exchange(
        &service,
        as_main_with(http::Method::PUT, "/names/c/..d", Bytes::new(), &[("x-amz-copy-source", "names/a/.b")]),
    )
    .await;
    assert_eq!(copied.status(), 200, "{}", body_of(&copied));
}

/// A browser `POST` of one file to `bucket` under `key`, its policy signed now for the main
/// identity. The key is written into the policy as a JSON string, so a control character in it
/// stays a valid document (`legacy_key_rule_tests` sends them).
pub(super) fn posted(bucket: &str, key: &str) -> http::Request<Bytes> {
    const BOUNDARY: &str = "----RustFSStorageNames";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs();
    let now = i64::try_from(now).expect("a representable clock");
    let stamp = Timestamp::from_secs(now)
        .render(TimestampFormat::Iso8601Basic)
        .expect("a representable signing stamp");
    let expires = Timestamp::from_secs(now + 3600)
        .render(TimestampFormat::Iso8601)
        .expect("a representable expiration");
    let day = &stamp[..8];
    let credential = format!("{MAIN_KEY}/{day}/us-east-1/s3/aws4_request");
    let json_key = json_escaped(key);
    let document = format!(
        "{{\"expiration\":\"{expires}\",\"conditions\":[{{\"bucket\":\"{bucket}\"}},[\"eq\",\"$key\",\"{json_key}\"],\
         {{\"x-amz-algorithm\":\"AWS4-HMAC-SHA256\"}},{{\"x-amz-credential\":\"{credential}\"}},{{\"x-amz-date\":\"{stamp}\"}}]}}"
    );
    let policy = base64(document.as_bytes());
    let mut signing_key = hmac_sha256(format!("AWS4{MAIN_SECRET}").as_bytes(), day.as_bytes());
    for part in [&b"us-east-1"[..], b"s3", b"aws4_request"] {
        signing_key = hmac_sha256(&signing_key, part);
    }
    let signature: String = hmac_sha256(&signing_key, policy.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let mut body = String::new();
    for (name, value) in [
        ("key", key),
        ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
        ("x-amz-credential", credential.as_str()),
        ("x-amz-date", stamp.as_str()),
        ("policy", policy.as_str()),
        ("x-amz-signature", signature.as_str()),
    ] {
        body.push_str(&format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        ));
    }
    body.push_str(&format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f.txt\"\r\n\
         Content-Type: text/plain\r\n\r\nform\r\n--{BOUNDARY}--\r\n"
    ));
    http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("/{bucket}"))
        .header(http::header::HOST, "s3.example.com")
        .header(http::header::CONTENT_TYPE, format!("multipart/form-data; boundary={BOUNDARY}"))
        .header(http::header::CONTENT_LENGTH, body.len())
        .body(Bytes::from(body))
        .expect("a valid form request")
}

/// `text` as the body of a JSON string: quotes, backslashes and control characters escaped.
fn json_escaped(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            control if u32::from(control) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(control))),
            other => out.push(other),
        }
    }
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// `bytes` in standard base64, for a POST policy document.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let word = chunk
            .iter()
            .enumerate()
            .fold(0u32, |word, (index, byte)| word | u32::from(*byte) << (16 - 8 * index));
        for index in 0..4 {
            if index <= chunk.len() {
                out.push(char::from(ALPHABET[(word >> (18 - 6 * index) & 0x3f) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}
