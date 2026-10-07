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

//! What the RustFS-profile launcher stores from a browser form's file and request head
//! (rustfs/gateway#1167), read back from the bucket.
//!
//! Responsible for: an empty file refused as legacy RustFS refuses it, with nothing stored and an
//! object already under the key untouched; and the two legacy behaviours the #1167 ruling keeps out
//! of the product, each proven unable to change stored data: a `?versionId=` on the request never
//! overwrites the version it names, and the request's own headers never override or add to what
//! the form stores; and the `redirect` field read as the success redirect, as legacy RustFS's POST
//! decoding reads it when the form carries no `success_action_redirect`.
//! NOT responsible for: the form members' effects (`post_object_field_tests.rs`) or the form's
//! ceilings (`post_form_ceiling_tests.rs`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Evidence: legacy RustFS sizes a form upload from the file's length and hands its upload path no
//! length for an empty file, which that path refuses `400 UnexpectedContent` before storing
//! anything (`rustfs/src/app/object/put.rs:91-116` at rustfs/rustfs@95268a3b9; confirmed on the
//! legacy stack in rustfs/gateway#1167). The same issue's ruling (2026-10-03) keeps the legacy
//! version overwrite and header-over-form precedence out of the product.

use super::*;

const BUCKET: &str = "uploads";
const PUBLIC_WRITE: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::uploads/*"}]}"#;
const BOUNDARY: &str = "----RustFSFormFile";
const UNEXPECTED_CONTENT: &str = "This request does not support content.";

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

/// The body of an anonymous form storing `content` under `key`, with `fields` before the file.
fn form(key: &str, fields: &[(&str, &str)], content: &str) -> String {
    let mut body = String::new();
    for (name, value) in [("key", key)].iter().chain(fields) {
        body.push_str(&format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        ));
    }
    body.push_str(&format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f\"\r\n\r\n{content}\r\n--{BOUNDARY}--\r\n"
    ));
    body
}

/// Posts `body` to `target`, with `Content-Length` when `declared`, and `headers` besides.
async fn post(service: &S3Service, target: &str, body: String, declared: bool, headers: &[(&str, &str)]) -> WireResponse {
    let mut request = http::Request::builder()
        .method(http::Method::POST)
        .uri(target)
        .header(http::header::HOST, "s3.example.com")
        .header(http::header::CONTENT_TYPE, format!("multipart/form-data; boundary={BOUNDARY}"));
    if declared {
        request = request.header(http::header::CONTENT_LENGTH, body.len());
    }
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    exchange(service, request.body(Bytes::from(body)).expect("a valid form request")).await
}

async fn get(service: &S3Service, target: &str) -> WireResponse {
    exchange(service, as_main(http::Method::GET, target, Bytes::new())).await
}

fn header<'a>(response: &'a WireResponse, name: &str) -> Option<&'a str> {
    response
        .headers()
        .iter()
        .find_map(|(header, value)| (header.as_str() == name).then(|| value.to_str().ok()).flatten())
}

// ── an empty file ────────────────────────────────────────────────────────────────────────────

/// Negative — an empty file is legacy RustFS's `400 UnexpectedContent`, with or without a declared
/// length, and nothing is stored.
#[tokio::test]
async fn n_an_empty_file_is_refused_as_legacy_rustfs_refuses_it() {
    let (_root, service) = public_bucket().await;
    for declared in [true, false] {
        let posted = post(&service, &format!("/{BUCKET}"), form("empty", &[], ""), declared, &[]).await;
        let body = body_of(&posted);
        assert_eq!(posted.status(), 400, "declared {declared}: {body}");
        assert!(body.contains("<Code>UnexpectedContent</Code>"), "declared {declared}: {body}");
        assert!(body.contains(UNEXPECTED_CONTENT), "declared {declared}: {body}");
        assert_eq!(get(&service, &format!("/{BUCKET}/empty")).await.status(), 404, "declared {declared}");
    }
}

/// Negative — the refusal leaves an object already stored under the key exactly as it was.
#[tokio::test]
async fn n_an_empty_file_leaves_the_stored_object_untouched() {
    let (_root, service) = public_bucket().await;
    let first = post(&service, &format!("/{BUCKET}"), form("kept", &[], "original"), true, &[]).await;
    assert_eq!(first.status(), 204, "{}", body_of(&first));
    let refused = post(&service, &format!("/{BUCKET}"), form("kept", &[], ""), true, &[]).await;
    assert_eq!(refused.status(), 400, "{}", body_of(&refused));
    let read = get(&service, &format!("/{BUCKET}/kept")).await;
    assert_eq!(read.status(), 200);
    assert_eq!(read.body().as_ref(), b"original");
}

/// Positive — the control: a one-byte file is stored.
#[tokio::test]
async fn a_one_byte_file_is_stored() {
    let (_root, service) = public_bucket().await;
    let posted = post(&service, &format!("/{BUCKET}"), form("one", &[], "x"), true, &[]).await;
    assert_eq!(posted.status(), 204, "{}", body_of(&posted));
    assert_eq!(get(&service, &format!("/{BUCKET}/one")).await.body().as_ref(), b"x");
}

// ── what the request itself cannot change ────────────────────────────────────────────────────

/// Negative — `?versionId=` naming a stored version never overwrites it: the form is stored as a
/// new version and the named one still holds its bytes.
#[tokio::test]
async fn n_a_version_id_on_the_request_never_overwrites_that_version() {
    let (_root, service) = public_bucket().await;
    let versioning = exchange(
        &service,
        as_main(
            http::Method::PUT,
            &format!("/{BUCKET}?versioning"),
            Bytes::from_static(b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"),
        ),
    )
    .await;
    assert_eq!(versioning.status(), 200, "{}", body_of(&versioning));
    let first = post(&service, &format!("/{BUCKET}"), form("doc", &[], "first"), true, &[]).await;
    assert_eq!(first.status(), 204, "{}", body_of(&first));
    let listed = versions(&service).await;
    let [named] = listed.as_slice() else {
        panic!("one version after one upload: {listed:?}");
    };
    let named = named.clone();

    let second = post(&service, &format!("/{BUCKET}?versionId={named}"), form("doc", &[], "second"), true, &[]).await;
    assert_eq!(second.status(), 204, "{}", body_of(&second));
    let listed = versions(&service).await;
    assert_eq!(listed.len(), 2, "the upload replaced a version instead of adding one: {listed:?}");
    assert!(listed.contains(&named), "the named version is gone: {listed:?}");

    let kept = get(&service, &format!("/{BUCKET}/doc?versionId={named}")).await;
    assert_eq!(kept.status(), 200);
    assert_eq!(kept.body().as_ref(), b"first", "the named version was overwritten");
    assert_eq!(get(&service, &format!("/{BUCKET}/doc")).await.body().as_ref(), b"second");
}

/// Every version id stored under `doc`, as `ListObjectVersions` reports them.
async fn versions(service: &S3Service) -> Vec<String> {
    let listed = get(service, &format!("/{BUCKET}?versions&prefix=doc")).await;
    assert_eq!(listed.status(), 200, "{}", body_of(&listed));
    body_of(&listed)
        .split("<VersionId>")
        .skip(1)
        .filter_map(|rest| rest.split_once("</VersionId>").map(|(id, _)| id.to_owned()))
        .collect()
}

/// Negative — the request's own headers neither override a form field nor add a member the form
/// did not set: the stored object carries the form's `Cache-Control`, no header metadata, no
/// header tags and no header storage class.
#[tokio::test]
async fn n_the_requests_own_headers_never_change_what_the_form_stores() {
    let (_root, service) = public_bucket().await;
    let posted = post(
        &service,
        &format!("/{BUCKET}"),
        form("page", &[("Cache-Control", "max-age=60")], "body"),
        true,
        &[
            ("cache-control", "no-cache"),
            ("x-amz-meta-from-header", "1"),
            ("x-amz-tagging", "from=header"),
            ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
        ],
    )
    .await;
    assert_eq!(posted.status(), 204, "{}", body_of(&posted));
    let read = get(&service, &format!("/{BUCKET}/page")).await;
    assert_eq!(read.status(), 200);
    assert_eq!(header(&read, "cache-control"), Some("max-age=60"));
    assert_eq!(header(&read, "x-amz-meta-from-header"), None);
    assert_eq!(header(&read, "x-amz-storage-class"), None);
    let tagging = get(&service, &format!("/{BUCKET}/page?tagging")).await;
    assert_eq!(tagging.status(), 200, "{}", body_of(&tagging));
    assert!(!body_of(&tagging).contains("<Key>from</Key>"), "{}", body_of(&tagging));
}

// ── the `redirect` field ─────────────────────────────────────────────────────────────────────

/// Positive — without `success_action_redirect`, the `redirect` field redirects to the stored
/// object as legacy RustFS's POST decoding reads it, and the object is stored.
#[tokio::test]
async fn a_redirect_field_redirects_to_the_stored_object() {
    let (_root, service) = public_bucket().await;
    let posted = post(
        &service,
        &format!("/{BUCKET}"),
        form("routed", &[("redirect", "https://client.example/done")], "routed body"),
        true,
        &[],
    )
    .await;
    assert_eq!(posted.status(), 303, "{}", body_of(&posted));
    let location = header(&posted, "location").expect("a Location");
    assert!(
        location.starts_with("https://client.example/done?bucket=uploads&key=routed&etag="),
        "{location}"
    );
    assert_eq!(get(&service, &format!("/{BUCKET}/routed")).await.body().as_ref(), b"routed body");
}

/// Negative — a `redirect` that is not an absolute URL is refused before storage.
#[tokio::test]
async fn n_an_unparseable_redirect_field_stores_nothing() {
    let (_root, service) = public_bucket().await;
    let posted = post(
        &service,
        &format!("/{BUCKET}"),
        form("unrouted", &[("redirect", "://nowhere")], "x"),
        true,
        &[],
    )
    .await;
    assert_eq!(posted.status(), 400, "{}", body_of(&posted));
    assert!(body_of(&posted).contains("<Code>MalformedPOSTRequest</Code>"), "{}", body_of(&posted));
    assert_eq!(get(&service, &format!("/{BUCKET}/unrouted")).await.status(), 404);
}
