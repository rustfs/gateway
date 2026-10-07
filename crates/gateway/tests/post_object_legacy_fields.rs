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

//! What a POST Object handler is handed under the RustFS profile for the `PutObject` members a form
//! sets besides its key, content type and metadata (rustfs/gateway#1129): every one legacy RustFS
//! reads, as it reads it, or the refusal it answers before anything is stored.
//!
//! Responsible for: the handler's `PostObjectInput::fields` for each member, the refusal of a value
//! legacy RustFS cannot read (before authorization, as legacy RustFS decodes the form before its
//! access hook runs), and a member that stays uncarried still reaching no handler.
//! NOT responsible for: what a backend stores from a member (`compat-sut`'s
//! `post_object_field_tests.rs`), the form grammar (`post_object_legacy_form.rs`), or signed
//! policies.
//! Upstream: the facade's public API. Downstream: nothing.
//!
//! Evidence: legacy RustFS (rustfs/rustfs `e870a6d25b`, the S3 stack its `Cargo.toml:318` pins)
//! decodes a POST form by running the `PutObject` decoder over the form's fields — each member with
//! its own text parser, errors answered `InvalidArgument` — before `S3Access::put_object`
//! (`rustfs/src/storage/access.rs:3157`) and its `put_object` store path run.

#![allow(clippy::expect_used)]

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use rustfs_gateway::dto::{PostObject, PostObjectFields, PostObjectOutput};
use rustfs_gateway::{Credentials, ETag, Handler, HandlerResult, Req, Resp, S3Service, ServiceBuilder, StaticCredentials};

const BOUNDARY: &str = "----RustFSLegacyFields";

/// Records the members each handled form was handed.
#[derive(Default)]
struct Backend {
    handed: Mutex<Option<PostObjectFields>>,
}

impl Handler<PostObject> for Backend {
    async fn call(&self, request: Req<PostObject>) -> HandlerResult<PostObject> {
        let input = request.into_input();
        let _ = input.body.into_body().collect().await;
        *self.handed.lock().expect("observation lock") = Some(input.fields);
        Ok(Resp::new(PostObjectOutput {
            e_tag: Some(ETag::new("storage-etag").expect("the fixture entity tag is valid")),
            version_id: None,
        }))
    }
}

/// The service, its authorizer deciding each route-stage action by `allow`.
fn service_deciding(backend: Arc<Backend>, allow: impl Fn(&str) -> bool + Send + Sync + 'static) -> S3Service {
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials")));
    ServiceBuilder::new()
        .register::<PostObject, _>(backend)
        .authenticator(rustfs_gateway::SigV4Authenticator::new(
            credentials,
            rustfs_gateway::RegionSet::new(["us-east-1"]).expect("non-empty region set"),
        ))
        .authorizer(rustfs_gateway::allow_when(move |request| allow(request.action)))
        .legacy_rustfs_post_forms()
        .build()
        .expect("complete POST Object service")
}

/// A form with the key `k`, then `fields` in order, then a one-byte file.
fn form(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut body = String::new();
    for (name, value) in [("key", "k")].iter().chain(fields) {
        body.push_str(&format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        ));
    }
    body.push_str(&format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f\"\r\n\r\nc\r\n--{BOUNDARY}--\r\n"
    ));
    body.into_bytes()
}

/// Posts the form through a service whose authorizer allows everything or nothing; the answer's
/// status and body, and what the handler was handed.
async fn post(fields: &[(&str, &str)], allow: bool) -> (StatusCode, String, Option<PostObjectFields>) {
    post_deciding(fields, move |_| allow).await
}

/// [`post`], the authorizer deciding each action by `allow`.
async fn post_deciding(
    fields: &[(&str, &str)],
    allow: impl Fn(&str) -> bool + Send + Sync + 'static,
) -> (StatusCode, String, Option<PostObjectFields>) {
    let backend = Arc::new(Backend::default());
    let body = form(fields);
    let request = Request::builder()
        .method("POST")
        .uri("http://host.invalid/example-bucket")
        .header("host", "host.invalid")
        .header("content-type", format!("multipart/form-data; boundary={BOUNDARY}"))
        .header("content-length", body.len())
        .body(Bytes::from(body))
        .expect("valid request");
    let response = service_deciding(Arc::clone(&backend), allow).call_bytes(request).await;
    let status = response.status();
    let answer = response.into_body().collect().await.expect("the answer body").to_bytes();
    let handed = backend.handed.lock().expect("observation lock").clone();
    (status, String::from_utf8_lossy(&answer).into_owned(), handed)
}

async fn handed(fields: &[(&str, &str)]) -> PostObjectFields {
    let (status, answer, handed) = post(fields, true).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{answer}");
    handed.expect("the handler ran")
}

/// Positive — every text and enumeration member legacy RustFS reads reaches the handler as the form
/// spelled it: the field name read without regard to case, the value unchanged — spaces, a
/// character outside ASCII and an empty value included.
#[tokio::test]
async fn every_text_member_reaches_the_handler_as_sent() {
    let fields = handed(&[
        ("X-Amz-Acl", "public-read"),
        ("Cache-Control", " max-age=60 "),
        ("x-amz-sdk-checksum-algorithm", "crc32"),
        ("x-amz-checksum-crc32", "AAAAAA=="),
        ("x-amz-checksum-crc32c", "c32c"),
        ("x-amz-checksum-crc64nvme", "c64"),
        ("x-amz-checksum-md5", "md5"),
        ("x-amz-checksum-sha1", "sha1"),
        ("x-amz-checksum-sha256", "sha256"),
        ("x-amz-checksum-sha512", "sha512"),
        ("x-amz-checksum-xxhash128", "xx128"),
        ("x-amz-checksum-xxhash3", "xx3"),
        ("x-amz-checksum-xxhash64", "xx64"),
        ("Content-Disposition", "attachment; filename=\"r\u{e9}sum\u{e9}.pdf\""),
        ("Content-Encoding", "gzip,aws-chunked"),
        ("Content-Language", ""),
        ("Content-MD5", "1B2M2Y8AsgTpgAmY7PhCfg=="),
        ("x-amz-expected-bucket-owner", "123456789012"),
        ("Expires", "Thu, 01 Jan 2030 00:00:00 GMT"),
        ("x-amz-grant-full-control", "id=\"a\""),
        ("x-amz-grant-read", "id=\"b\""),
        ("x-amz-grant-read-acp", "id=\"c\""),
        ("x-amz-grant-write-acp", "id=\"d\""),
        ("If-Match", "\"etag\""),
        ("If-None-Match", "*"),
        ("x-amz-request-payer", "requester"),
        ("x-amz-server-side-encryption", "AES256"),
        ("x-amz-server-side-encryption-context", "e30="),
        ("x-amz-server-side-encryption-aws-kms-key-id", "key-1"),
        ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
        ("x-amz-tagging", "a=b&c=d"),
        ("x-amz-website-redirect-location", "/elsewhere"),
    ])
    .await;
    let text = |value: &str| Some(value.to_owned());
    assert_eq!(fields.acl.as_ref().map(|acl| acl.as_str()), Some("public-read"));
    assert_eq!(fields.cache_control, text(" max-age=60 "));
    assert_eq!(fields.checksum_algorithm.as_ref().map(|algorithm| algorithm.as_str()), Some("crc32"));
    assert_eq!(
        [
            &fields.checksum_crc32,
            &fields.checksum_crc32c,
            &fields.checksum_crc64nvme,
            &fields.checksum_md5,
            &fields.checksum_sha1,
            &fields.checksum_sha256,
            &fields.checksum_sha512,
            &fields.checksum_xxhash128,
            &fields.checksum_xxhash3,
            &fields.checksum_xxhash64,
        ],
        [
            &text("AAAAAA=="),
            &text("c32c"),
            &text("c64"),
            &text("md5"),
            &text("sha1"),
            &text("sha256"),
            &text("sha512"),
            &text("xx128"),
            &text("xx3"),
            &text("xx64"),
        ]
    );
    assert_eq!(fields.content_disposition, text("attachment; filename=\"r\u{e9}sum\u{e9}.pdf\""));
    assert_eq!(fields.content_encoding, text("gzip,aws-chunked"));
    assert_eq!(fields.content_language, text(""));
    assert_eq!(fields.content_md5, text("1B2M2Y8AsgTpgAmY7PhCfg=="));
    assert_eq!(fields.expected_bucket_owner, text("123456789012"));
    assert_eq!(
        fields.expires.as_ref().map(|expires| expires.as_str()),
        Some("Thu, 01 Jan 2030 00:00:00 GMT")
    );
    assert_eq!(
        [
            &fields.grant_full_control,
            &fields.grant_read,
            &fields.grant_read_acp,
            &fields.grant_write_acp
        ],
        [&text("id=\"a\""), &text("id=\"b\""), &text("id=\"c\""), &text("id=\"d\"")]
    );
    assert_eq!((fields.if_match, fields.if_none_match), (text("\"etag\""), text("*")));
    assert_eq!(fields.request_payer.as_ref().map(|payer| payer.as_str()), Some("requester"));
    assert_eq!(fields.server_side_encryption.as_ref().map(|algorithm| algorithm.as_str()), Some("AES256"));
    assert_eq!(fields.ssekms_encryption_context, text("e30="));
    assert_eq!(fields.ssekms_key_id, text("key-1"));
    assert_eq!(fields.storage_class.as_ref().map(|class| class.as_str()), Some("REDUCED_REDUNDANCY"));
    assert_eq!(fields.tagging, text("a=b&c=d"));
    assert_eq!(fields.website_redirect_location, text("/elsewhere"));
    assert_eq!((fields.bucket_key_enabled, fields.write_offset_bytes), (None, None));
}

/// Positive — the flag and the offset reach the handler as Rust reads them, as legacy RustFS reads
/// them; a form that sets no member hands none.
#[tokio::test]
async fn a_numeric_member_reaches_the_handler_parsed_and_an_absent_one_is_none() {
    let fields = handed(&[
        ("x-amz-server-side-encryption-bucket-key-enabled", "false"),
        ("x-amz-write-offset-bytes", "+42"),
    ])
    .await;
    assert_eq!((fields.bucket_key_enabled, fields.write_offset_bytes), (Some(false), Some(42)));

    assert!(handed(&[("x-amz-meta-note", "kept")]).await.is_empty());
}

/// Negative — a value legacy RustFS cannot read is refused with its `400 InvalidArgument`, naming the
/// field and the value, before authorization (a caller who may not write learns the same answer
/// legacy RustFS gives it) and before the handler.
#[tokio::test]
async fn an_unreadable_member_is_refused_before_authorization() {
    for (name, value, message) in [
        (
            "x-amz-server-side-encryption-bucket-key-enabled",
            "TRUE",
            "invalid field value: x-amz-server-side-encryption-bucket-key-enabled: &quot;TRUE&quot;",
        ),
        ("If-Match", "etag one", "invalid field value: if-match: &quot;etag one&quot;"),
        ("If-None-Match", "", "invalid field value: if-none-match: &quot;&quot;"),
        (
            "x-amz-object-lock-retain-until-date",
            "tomorrow",
            "invalid field value: x-amz-object-lock-retain-until-date: &quot;tomorrow&quot;",
        ),
        (
            "x-amz-write-offset-bytes",
            "1.5",
            "invalid field value: x-amz-write-offset-bytes: &quot;1.5&quot;",
        ),
    ] {
        for allow in [true, false] {
            let (status, answer, handed) = post(&[(name, value)], allow).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{name}: {answer}");
            assert!(answer.contains("<Code>InvalidArgument</Code>"), "{name}: {answer}");
            assert!(answer.contains(&format!("<Message>{message}</Message>")), "{name}: {answer}");
            assert!(handed.is_none(), "{name}");
        }
    }
}

/// Negative — an SSE-C field still reaches no handler: `501` once authorized, the authorizer's
/// answer first.
#[tokio::test]
async fn an_uncarried_member_still_reaches_no_handler() {
    for (name, value) in [
        ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
        ("x-amz-server-side-encryption-customer-key-md5", "md5"),
    ] {
        let (status, answer, handed) = post(&[(name, value)], true).await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{name}: {answer}");
        assert!(handed.is_none(), "{name}");
        let (status, _, handed) = post(&[(name, value)], false).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{name}");
        assert!(handed.is_none(), "{name}");
    }
}

/// The actions a form's route stage asked, in order, and the handed members, with every action
/// allowed.
async fn ask(fields: &[(&str, &str)]) -> (Vec<String>, Option<PostObjectFields>) {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&asked);
    let (status, answer, handed) = post_deciding(fields, move |action| {
        record.lock().expect("observation lock").push(action.to_owned());
        true
    })
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{answer}");
    let asked = asked.lock().expect("observation lock").clone();
    (asked, handed)
}

/// Positive — the Object Lock fields reach the handler as legacy RustFS reads them, and each asks
/// the action legacy RustFS's `put_object` access hook asks for it, after the base action: a legal
/// hold `s3:PutObjectLegalHold`, a mode or a retain-until date `s3:PutObjectRetention`, the legal
/// hold first. A field sent empty still asks, as legacy RustFS reads it as set; `OFF` asks too.
#[tokio::test]
async fn object_lock_fields_reach_the_handler_and_ask_their_actions() {
    const HOLD: &str = "s3:PutObjectLegalHold";
    const RETENTION: &str = "s3:PutObjectRetention";
    let (asked, handed) = ask(&[
        ("x-amz-object-lock-mode", "GOVERNANCE"),
        ("x-amz-object-lock-retain-until-date", "2030-01-02T03:04:05.678Z"),
        ("x-amz-object-lock-legal-hold", "ON"),
    ])
    .await;
    let handed = handed.expect("the handler ran");
    assert_eq!(handed.object_lock_mode.as_ref().map(|mode| mode.as_str()), Some("GOVERNANCE"));
    assert_eq!(handed.object_lock_legal_hold_status.as_ref().map(|status| status.as_str()), Some("ON"));
    let date = handed.object_lock_retain_until_date.expect("a retain-until date");
    assert_eq!(
        date.render(rustfs_gateway::TimestampFormat::Iso8601).expect("renders"),
        "2030-01-02T03:04:05.678Z"
    );
    let extra: Vec<&str> = asked
        .iter()
        .map(String::as_str)
        .filter(|action| [HOLD, RETENTION].contains(action))
        .collect();
    assert_eq!(extra, [HOLD, RETENTION], "{asked:?}");
    assert_eq!(asked.first().map(String::as_str), Some("s3:PutObject"), "{asked:?}");
    for (field, value, action) in [
        ("x-amz-object-lock-mode", "", RETENTION),
        ("x-amz-object-lock-mode", "COMPLIANCE", RETENTION),
        ("x-amz-object-lock-retain-until-date", "2030-01-01T00:00:00Z", RETENTION),
        ("x-amz-object-lock-legal-hold", "OFF", HOLD),
        ("x-amz-object-lock-legal-hold", "", HOLD),
    ] {
        let (asked, handed) = ask(&[(field, value)]).await;
        let extra: Vec<&str> = asked
            .iter()
            .map(String::as_str)
            .filter(|action| [HOLD, RETENTION].contains(action))
            .collect();
        assert_eq!(extra, [action], "{field}={value:?}: {asked:?}");
        assert!(handed.is_some(), "{field}");
    }
    let (asked, _) = ask(&[("x-amz-meta-color", "red")]).await;
    assert!(!asked.iter().any(|action| action == HOLD || action == RETENTION), "{asked:?}");
}

/// Negative — when the authorizer denies the action an Object Lock field asks, the form is refused
/// `403 AccessDenied` and nothing reaches the handler.
#[tokio::test]
async fn n_a_denied_object_lock_action_stores_nothing() {
    for (field, value, denied) in [
        ("x-amz-object-lock-legal-hold", "ON", "s3:PutObjectLegalHold"),
        ("x-amz-object-lock-mode", "GOVERNANCE", "s3:PutObjectRetention"),
        ("x-amz-object-lock-retain-until-date", "2030-01-01T00:00:00Z", "s3:PutObjectRetention"),
        ("X-Amz-Object-Lock-Retain-Until-Date", "2030-01-01T00:00:00Z", "s3:PutObjectRetention"),
        ("X-AMZ-OBJECT-LOCK-LEGAL-HOLD", "ON", "s3:PutObjectLegalHold"),
    ] {
        let (status, answer, handed) = post_deciding(&[(field, value)], move |action| action != denied).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{field}: {answer}");
        assert!(answer.contains("<Code>AccessDenied</Code>"), "{field}: {answer}");
        assert!(handed.is_none(), "{field}");
    }
}
