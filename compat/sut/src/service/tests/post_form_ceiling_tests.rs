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

//! A browser form read under legacy RustFS's ceilings by the RustFS-profile launcher
//! (rustfs/gateway#1173), read back from the object.
//!
//! Responsible for: a form past the gateway's own ceilings — more than 64 fields, a field past
//! 8 KiB — stored exactly as sent, and one past legacy RustFS's — a field past 1 MiB, a thousandth
//! field — refused with legacy RustFS's `400 MalformedPOSTRequest` and nothing stored.
//! NOT responsible for: the ceilings at their byte edges (`rustfs-gateway-http`'s
//! `form_legacy_limits.rs`) or the members a form sets (`post_object_field_tests.rs`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Evidence: RustFS leaves its legacy stack's form limits at their defaults
//! (`rustfs/src/server/http.rs:166-173` at rustfs/rustfs@95268a3b9) — 1 MiB per field, 20 MiB of
//! field values, 1000 parts — and that stack answers every form it cannot read
//! `400 MalformedPOSTRequest`.

use super::*;

const BUCKET: &str = "ceilings";
const PUBLIC_WRITE: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::ceilings/*"}]}"#;
const BOUNDARY: &str = "----RustFSFormCeilings";
const MIB: usize = 1024 * 1024;

async fn public_bucket() -> (TestRoot, S3Service) {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);
    let created = exchange(&service, as_main(http::Method::PUT, &format!("/{BUCKET}"), Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let policy = exchange(
        &service,
        as_main(
            http::Method::PUT,
            &format!("/{BUCKET}?policy"),
            Bytes::from_static(PUBLIC_WRITE.as_bytes()),
        ),
    )
    .await;
    assert!(policy.status().is_success(), "{}", body_of(&policy));
    (root, service)
}

/// An anonymous form storing a small file under `key`, with `fields` before the file.
async fn post_form(service: &S3Service, key: &str, fields: &[(String, String)]) -> WireResponse {
    let mut body = format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\n{key}\r\n");
    for (name, value) in fields {
        body.push_str(&format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        ));
    }
    body.push_str(&format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f\"\r\n\r\nthe file\r\n--{BOUNDARY}--\r\n"
    ));
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("/{BUCKET}"))
        .header(http::header::HOST, "s3.example.com")
        .header(http::header::CONTENT_TYPE, format!("multipart/form-data; boundary={BOUNDARY}"))
        .header(http::header::CONTENT_LENGTH, body.len())
        .body(Bytes::from(body))
        .expect("a valid form request");
    exchange(service, request).await
}

async fn head(service: &S3Service, key: &str) -> WireResponse {
    exchange(service, as_main(http::Method::HEAD, &format!("/{BUCKET}/{key}"), Bytes::new())).await
}

fn header<'a>(response: &'a WireResponse, name: &str) -> Option<&'a [u8]> {
    response
        .headers()
        .iter()
        .find_map(|(header, value)| (header.as_str() == name).then(|| value.as_bytes()))
}

/// `count` metadata fields `x-amz-meta-m<index>` holding their index.
fn metadata(count: usize) -> Vec<(String, String)> {
    (0..count)
        .map(|index| (format!("x-amz-meta-m{index}"), index.to_string()))
        .collect()
}

/// Asserts the form was refused with legacy RustFS's `400 MalformedPOSTRequest` and stored nothing.
async fn refused(service: &S3Service, key: &str, fields: &[(String, String)]) {
    let posted = post_form(service, key, fields).await;
    let body = body_of(&posted);
    assert_eq!(posted.status(), 400, "{body}");
    assert!(body.contains("<Code>MalformedPOSTRequest</Code>"), "{body}");
    assert_eq!(head(service, key).await.status(), 404, "a refused form stored an object");
}

/// Positive — seventy metadata fields, past the gateway's own 64, are all stored.
#[tokio::test]
async fn a_form_past_sixty_four_fields_is_stored_whole() {
    let (_root, service) = public_bucket().await;
    let posted = post_form(&service, "many", &metadata(70)).await;
    assert_eq!(posted.status(), 204, "{}", body_of(&posted));
    let head = head(&service, "many").await;
    assert_eq!(head.status(), 200);
    for index in [0, 63, 64, 69] {
        assert_eq!(
            header(&head, &format!("x-amz-meta-m{index}")),
            Some(index.to_string().as_bytes()),
            "x-amz-meta-m{index}"
        );
    }
}

/// Positive — a 16 KiB `Cache-Control` field, past the gateway's own 8 KiB, is stored as sent.
#[tokio::test]
async fn a_field_past_eight_kibibytes_is_stored_as_sent() {
    let (_root, service) = public_bucket().await;
    let value = format!("max-age=60, x={}", "a".repeat(16 * 1024));
    let posted = post_form(&service, "wide", &[("Cache-Control".to_owned(), value.clone())]).await;
    assert_eq!(posted.status(), 204, "{}", body_of(&posted));
    let head = head(&service, "wide").await;
    assert_eq!(header(&head, "cache-control"), Some(value.as_bytes()));
}

/// Negative — a field past 1 MiB is refused and stores nothing.
#[tokio::test]
async fn n_a_field_past_one_mebibyte_is_refused() {
    let (_root, service) = public_bucket().await;
    refused(&service, "huge", &[("Cache-Control".to_owned(), "a".repeat(MIB + 1))]).await;
}

/// Negative — a thousandth field, the form's 1001st part with the key and the file, is refused and
/// stores nothing; 998 metadata fields beside the key are the most a form may carry.
#[tokio::test]
async fn n_a_thousandth_field_is_refused() {
    let (_root, service) = public_bucket().await;
    refused(&service, "crowded", &metadata(999)).await;
}

/// Negative — the gateway's own ceilings no longer refuse, but a form past legacy RustFS's field
/// values together is still refused: twenty-one fields of 1 MiB.
#[tokio::test]
async fn n_field_values_past_twenty_mebibytes_are_refused() {
    let (_root, service) = public_bucket().await;
    let fields: Vec<(String, String)> = (0..21).map(|index| (format!("x-pad-{index}"), "a".repeat(MIB))).collect();
    refused(&service, "heavy", &fields).await;
}
