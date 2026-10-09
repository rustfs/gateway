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

//! What the RustFS profile stores from each `PutObject` member a browser form sets
//! (rustfs/gateway#1129), read back from the object: exactly what legacy RustFS stores from the same
//! form, or a refusal that stores nothing.
//!
//! Evidence, rustfs/rustfs `e870a6d25b`: legacy RustFS decodes the form into a `PutObject` and
//! stores it through `put_object`. It keeps `Cache-Control`, `Content-Disposition`,
//! `Content-Language` and `Content-Type` as sent, and `Content-Encoding` with `aws-chunked` and
//! empty codings dropped (`rustfs/src/app/object/shared.rs:740-771`,
//! `rustfs/src/storage/options.rs:664-683`); keeps the tag set and a `REDUCED_REDUNDANCY` class,
//! refusing any class but it and `STANDARD` (`rustfs/src/app/object/put.rs:866-871`, `:1202-1206`);
//! encrypts under the form's algorithm, else the request's own header, refusing SSE-KMS for a form
//! upload and any algorithm but `AES256` (`put.rs:898-913`, `:1198-1201`, `:1265`,
//! `rustfs/src/storage/sse.rs:617-623`); and reads, then never uses, the ACL and grant fields, the
//! expected owner, the request payer, the bucket-key flag, the checksum fields, the KMS context, the
//! write offset and the two condition fields (`put.rs:1236-1257` destructures none of them; the
//! conditional write reads the request's own headers, `rustfs/src/storage/options.rs:316-345`).

use super::*;

const BUCKET: &str = "forms";
const PUBLIC_WRITE: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::forms/*"}]}"#;
const BOUNDARY: &str = "----RustFSFormFields";

/// [`PUBLIC_WRITE`] with the two Object Lock actions a form's lock fields ask granted too.
const PUBLIC_WRITE_WITH_LOCK: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":["s3:PutObject","s3:PutObjectRetention","s3:PutObjectLegalHold"],"Resource":"arn:aws:s3:::forms/*"}]}"#;

/// A bucket anyone may write to, as a browser upload page's bucket is.
async fn public_bucket() -> (TestRoot, S3Service) {
    bucket_with_policy(PUBLIC_WRITE).await
}

/// A bucket whose policy is `policy`.
async fn bucket_with_policy(policy: &'static str) -> (TestRoot, S3Service) {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);
    let created = exchange(&service, as_main(http::Method::PUT, &format!("/{BUCKET}"), Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let policy = exchange(
        &service,
        as_main(http::Method::PUT, &format!("/{BUCKET}?policy"), Bytes::from_static(policy.as_bytes())),
    )
    .await;
    assert!(policy.status().is_success(), "{}", body_of(&policy));
    (root, service)
}

/// An anonymous form storing `content` under `key`, with `fields` before the file.
async fn post_form(service: &S3Service, key: &str, fields: &[(&str, &str)], content: &str) -> WireResponse {
    post_form_with_header(service, key, fields, content, None).await
}

async fn post_form_with_header(
    service: &S3Service,
    key: &str,
    fields: &[(&str, &str)],
    content: &str,
    header: Option<(&str, &str)>,
) -> WireResponse {
    let mut body = String::new();
    for (name, value) in [("key", key)].iter().chain(fields) {
        body.push_str(&format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        ));
    }
    body.push_str(&format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f\"\r\n\r\n{content}\r\n--{BOUNDARY}--\r\n"
    ));
    let mut request = http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("/{BUCKET}"))
        .header(http::header::HOST, "s3.example.com")
        .header(http::header::CONTENT_TYPE, format!("multipart/form-data; boundary={BOUNDARY}"))
        .header(http::header::CONTENT_LENGTH, body.len());
    if let Some((name, value)) = header {
        request = request.header(name, value);
    }
    exchange(service, request.body(Bytes::from(body)).expect("a valid form request")).await
}

async fn head(service: &S3Service, key: &str) -> WireResponse {
    exchange(service, as_main(http::Method::HEAD, &format!("/{BUCKET}/{key}"), Bytes::new())).await
}

async fn stored(service: &S3Service, key: &str, fields: &[(&str, &str)]) -> Vec<(http::HeaderName, http::HeaderValue)> {
    let posted = post_form(service, key, fields, "the file").await;
    assert_eq!(posted.status(), 204, "{fields:?}: {}", body_of(&posted));
    let head = head(service, key).await;
    assert_eq!(head.status(), 200, "{fields:?}");
    head.headers().to_vec()
}

fn header<'a>(headers: &'a [(http::HeaderName, http::HeaderValue)], name: &str) -> Option<&'a [u8]> {
    headers
        .iter()
        .find_map(|(header, value)| (header.as_str() == name).then(|| value.as_bytes()))
}

/// Asserts the form was refused with `status` and `code`, and that nothing was stored under `key`.
async fn refused(service: &S3Service, key: &str, fields: &[(&str, &str)], status: u16, code: &str) -> String {
    let posted = post_form(service, key, fields, "must not land").await;
    let body = body_of(&posted);
    assert_eq!(posted.status(), status, "{fields:?}: {body}");
    assert!(body.contains(&format!("<Code>{code}</Code>")), "{fields:?}: {body}");
    assert_eq!(head(service, key).await.status(), 404, "{fields:?} stored an object");
    body
}

/// Positive — the representation fields are stored as RustFS stores them: as sent, an empty value
/// and a character outside ASCII included, and `Content-Encoding` with its `aws-chunked` and empty
/// codings dropped and the rest joined by `", "`.
#[tokio::test]
async fn a_forms_representation_fields_are_stored_as_rustfs_stores_them() {
    let (_root, service) = public_bucket().await;
    let headers = stored(
        &service,
        "report.md",
        &[
            ("Content-Type", "text/markdown"),
            ("Cache-Control", "max-age=60"),
            ("Content-Disposition", "attachment; filename=\"r\u{e9}sum\u{e9}.md\""),
            ("Content-Language", ""),
            ("Content-Encoding", " gzip,aws-chunked,, br "),
        ],
    )
    .await;
    assert_eq!(header(&headers, "content-type"), Some(b"text/markdown".as_slice()));
    assert_eq!(header(&headers, "cache-control"), Some(b"max-age=60".as_slice()));
    assert_eq!(
        header(&headers, "content-disposition"),
        Some("attachment; filename=\"r\u{e9}sum\u{e9}.md\"".as_bytes())
    );
    assert_eq!(header(&headers, "content-language"), Some(b"".as_slice()));
    assert_eq!(header(&headers, "content-encoding"), Some(b"gzip, br".as_slice()));

    let headers = stored(&service, "chunked", &[("Content-Encoding", "AWS-Chunked")]).await;
    assert_eq!(header(&headers, "content-encoding"), None, "a lone aws-chunked stores no coding");
}

/// Positive and negative — `REDUCED_REDUNDANCY` is kept with the object; any class but it and
/// `STANDARD`, the model's other classes and a lowercase spelling included, stores nothing.
#[tokio::test]
async fn a_forms_storage_class_is_kept_or_refused_as_rustfs_does() {
    let (_root, service) = public_bucket().await;
    let headers = stored(&service, "rrs", &[("x-amz-storage-class", "REDUCED_REDUNDANCY")]).await;
    assert_eq!(header(&headers, "x-amz-storage-class"), Some(b"REDUCED_REDUNDANCY".as_slice()));
    let headers = stored(&service, "standard", &[("x-amz-storage-class", "STANDARD")]).await;
    assert_eq!(header(&headers, "x-amz-storage-class"), None, "STANDARD is not reported");
    for class in ["STANDARD_IA", "GLACIER", "standard", ""] {
        refused(&service, "classed", &[("x-amz-storage-class", class)], 400, "InvalidStorageClass").await;
    }
}

/// Positive — the tag set is kept with the object and read back, its values URL-decoded.
#[tokio::test]
async fn a_forms_tag_set_is_kept_with_the_object() {
    let (_root, service) = public_bucket().await;
    let headers = stored(&service, "tagged", &[("x-amz-tagging", "team=web&stage=a%20b")]).await;
    assert_eq!(header(&headers, "x-amz-tagging-count"), Some(b"2".as_slice()));
    let tags = exchange(&service, as_main(http::Method::GET, &format!("/{BUCKET}/tagged?tagging"), Bytes::new())).await;
    let tags = body_of(&tags);
    for tag in [
        "<Tag><Key>team</Key><Value>web</Value></Tag>",
        "<Tag><Key>stage</Key><Value>a b</Value></Tag>",
    ] {
        assert!(tags.contains(tag), "{tag} in {tags}");
    }
}

/// Positive and negative — `AES256` from the form, or from the request's own header when the form
/// names none, is recorded; SSE-KMS asked for any way is refused, and any other algorithm too.
#[tokio::test]
async fn a_forms_encryption_is_recorded_or_refused_as_rustfs_does() {
    let (_root, service) = public_bucket().await;
    let headers = stored(&service, "sealed", &[("x-amz-server-side-encryption", "AES256")]).await;
    assert_eq!(header(&headers, "x-amz-server-side-encryption"), Some(b"AES256".as_slice()));

    let posted = post_form_with_header(
        &service,
        "sealed-by-header",
        &[],
        "the file",
        Some(("x-amz-server-side-encryption", "AES256")),
    )
    .await;
    assert_eq!(posted.status(), 204, "{}", body_of(&posted));
    let headers = head(&service, "sealed-by-header").await;
    assert_eq!(header(headers.headers(), "x-amz-server-side-encryption"), Some(b"AES256".as_slice()));

    for fields in [
        &[("x-amz-server-side-encryption", "aws:kms")][..],
        &[("x-amz-server-side-encryption", "AWS:KMS")],
        &[("x-amz-server-side-encryption-aws-kms-key-id", "")],
        &[
            ("x-amz-server-side-encryption", "AES256"),
            ("x-amz-server-side-encryption-aws-kms-key-id", "k"),
        ],
    ] {
        let body = refused(&service, "kms", fields, 501, "NotImplemented").await;
        assert!(body.contains("SSE-KMS is not supported for POST object uploads"), "{body}");
    }
    let posted = post_form_with_header(
        &service,
        "kms",
        &[("x-amz-server-side-encryption", "AES256")],
        "must not land",
        Some(("x-amz-server-side-encryption", "aws:kms")),
    )
    .await;
    assert_eq!(posted.status(), 501, "{}", body_of(&posted));
    assert_eq!(head(&service, "kms").await.status(), 404);

    for algorithm in ["aes256", "", "aws:kms:dsse"] {
        let body = refused(
            &service,
            "unknown",
            &[("x-amz-server-side-encryption", algorithm)],
            400,
            "InvalidArgument",
        )
        .await;
        assert!(
            body.contains("The SSE algorithm specified is not supported. The valid values are AES256 or aws:kms."),
            "{algorithm:?}: {body}"
        );
    }
}

/// Negative — an opaque algorithm stays the host's input. RustFS refuses an effective KMS
/// request before validating that algorithm, including a key-id sent empty or a request header.
#[tokio::test]
async fn n_opaque_form_algorithms_keep_the_legacy_kms_refusal_order() {
    let (_root, service) = public_bucket().await;
    for algorithm in ["", "opaque"] {
        let fields = [("x-amz-server-side-encryption", algorithm)];
        let body = refused(&service, "opaque", &fields, 400, "InvalidArgument").await;
        assert!(body.contains("The SSE algorithm specified is not supported."), "{algorithm:?}: {body}");
        let with_key = [
            ("x-amz-server-side-encryption", algorithm),
            ("x-amz-server-side-encryption-aws-kms-key-id", ""),
        ];
        let body = refused(&service, "opaque-kms", &with_key, 501, "NotImplemented").await;
        assert!(body.contains("SSE-KMS is not supported for POST object uploads"), "{algorithm:?}: {body}");
        let posted = post_form_with_header(
            &service,
            "opaque-header",
            &fields,
            "must not land",
            Some(("x-amz-server-side-encryption", "aws:kms")),
        )
        .await;
        let body = body_of(&posted);
        assert_eq!(posted.status(), 501, "{algorithm:?}: {body}");
        assert!(body.contains("<Code>NotImplemented</Code>"), "{algorithm:?}: {body}");
        assert!(body.contains("SSE-KMS is not supported for POST object uploads"), "{algorithm:?}: {body}");
        assert_eq!(head(&service, "opaque-header").await.status(), 404, "{algorithm:?} stored an object");
    }
}

/// Positive — the members RustFS reads and never uses change nothing: with every one set, a wrong
/// checksum, a foreign expected owner and conditions that would fail included, the form overwrites
/// the object exactly as a form without them does.
#[tokio::test]
async fn the_members_rustfs_ignores_change_nothing() {
    let (_root, service) = public_bucket().await;
    let first = post_form(&service, "ignored", &[], "first").await;
    assert_eq!(first.status(), 204, "{}", body_of(&first));
    let ignored = [
        ("x-amz-acl", "public-read"),
        ("x-amz-grant-read", "id=\"someone\""),
        ("x-amz-expected-bucket-owner", "999999999999"),
        ("x-amz-request-payer", "requester"),
        ("x-amz-server-side-encryption-bucket-key-enabled", "true"),
        ("x-amz-sdk-checksum-algorithm", "CRC32"),
        ("x-amz-checksum-crc32", "AAAAAA=="),
        ("x-amz-server-side-encryption-context", "e30="),
        ("x-amz-write-offset-bytes", "5"),
        ("If-Match", "\"not-the-current-tag\""),
        ("If-None-Match", "*"),
    ];
    let second = post_form(&service, "ignored", &ignored, "second").await;
    assert_eq!(second.status(), 204, "{}", body_of(&second));
    let read = exchange(&service, as_main(http::Method::GET, &format!("/{BUCKET}/ignored"), Bytes::new())).await;
    assert_eq!(read.status(), 200);
    assert_eq!(read.body().as_ref(), b"second");
    assert_eq!(header(read.headers(), "x-amz-server-side-encryption"), None);
    assert_eq!(header(read.headers(), "x-amz-storage-class"), None);
}

/// Negative — a value RustFS cannot read, a member this backend cannot store as RustFS does, and a
/// customer key on this cleartext service each store nothing.
#[tokio::test]
async fn a_form_member_that_cannot_be_stored_as_rustfs_stores_it_stores_nothing() {
    let (_root, service) = public_bucket().await;
    for (name, value) in [
        ("x-amz-server-side-encryption-bucket-key-enabled", "yes"),
        ("If-None-Match", "no quotes"),
        ("x-amz-write-offset-bytes", "-"),
        ("x-amz-object-lock-retain-until-date", "Tue, 01 Jan 2030 00:00:00 GMT"),
    ] {
        refused(&service, "unreadable", &[(name, value)], 400, "InvalidArgument").await;
    }
    for (name, value) in [
        ("x-amz-website-redirect-location", "/elsewhere"),
        ("Expires", "Tue, 01 Jan 2030 00:00:00 GMT"),
        ("Content-MD5", "1B2M2Y8AsgTpgAmY7PhCfg=="),
    ] {
        refused(&service, "unstored", &[(name, value)], 501, "NotImplemented").await;
    }
    // A customer key, or a fragment of its trio, is the gate's refusal on this cleartext service,
    // as it is for a header (rustfs/gateway#1167); it never reaches the backend's own refusal.
    refused(
        &service,
        "cleartext-key",
        &[("x-amz-server-side-encryption-customer-algorithm", "AES256")],
        400,
        "InvalidRequest",
    )
    .await;
    // A refusal RustFS answers itself comes first: it never reaches the member this backend
    // cannot store.
    for (name, value) in [
        ("Content-MD5", "x"),
        ("x-amz-website-redirect-location", "/elsewhere"),
        ("Expires", "Tue, 01 Jan 2030 00:00:00 GMT"),
    ] {
        refused(
            &service,
            "ordered",
            &[(name, value), ("x-amz-storage-class", "GLACIER")],
            400,
            "InvalidStorageClass",
        )
        .await;
    }
}

/// Negative — an Object Lock field asks the action legacy RustFS's `put_object` access hook asks
/// for it, an empty value included (rustfs/gateway#1167): under a policy granting anonymous
/// writers `s3:PutObject` alone the form is refused `403 AccessDenied`; under one granting the
/// lock actions too it is authorized, and this backend, which keeps no Object Lock state, refuses
/// it `501`. Nothing is stored either way.
#[tokio::test]
async fn n_an_object_lock_field_asks_its_action_and_stores_nothing_here() {
    let fields: [(&str, &str); 5] = [
        ("x-amz-object-lock-mode", "GOVERNANCE"),
        ("x-amz-object-lock-mode", ""),
        ("x-amz-object-lock-retain-until-date", "2030-01-01T00:00:00Z"),
        ("x-amz-object-lock-legal-hold", "ON"),
        ("x-amz-object-lock-legal-hold", ""),
    ];
    let (_root, service) = public_bucket().await;
    for field in fields {
        refused(&service, "locked", &[field], 403, "AccessDenied").await;
    }
    let (_root, service) = bucket_with_policy(PUBLIC_WRITE_WITH_LOCK).await;
    for field in fields {
        refused(&service, "locked", &[field], 501, "NotImplemented").await;
    }
}
