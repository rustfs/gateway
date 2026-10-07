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

//! What a POST Object stores under the RustFS profile's legacy form grammar
//! (`ServiceBuilder::legacy_rustfs_post_forms`): for every form shape the legacy grammar adds, the
//! key, content type, metadata and bytes legacy RustFS stores from the same request — and, for every
//! shape legacy RustFS refuses, that nothing is stored.
//!
//! Responsible for: one stored-object assertion per accepted shape, and for each refused shape
//! either a refusal before the handler runs or a file stream that ends in an error instead of a
//! clean end (a store aborts on it, as legacy RustFS's does when its own file stream fails at the
//! same point). NOT responsible for: the grammar byte by byte (`rustfs-gateway-http`'s
//! `form_grammar.rs`), the gateway grammar's own behaviour (`post_object_runtime.rs` and
//! `post_object_streaming.rs`, which run without the option), or signed policies.
//! Upstream: the facade's public API. Downstream: nothing.
//!
//! Evidence: every expected value is what legacy RustFS stores for the same bytes — RustFS main
//! (rustfs/rustfs `1e7065101d`) serves POST Object through the S3 stack its `Cargo.toml:318` pins,
//! and `rustfs/src/storage/access.rs` has no `post_object` override, so the form reaches its
//! `put_object` store path — confirmed by running that stack on each form.

#![allow(clippy::expect_used)]

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use rustfs_gateway::dto::{PostObject, PostObjectOutput};
use rustfs_gateway::{
    Credentials, ETag, Handler, HandlerError, HandlerResult, Req, Resp, S3Service, ServiceBuilder, StaticCredentials,
};

const BOUNDARY: &str = "----WebKitFormBoundary7MA4YWxkTrZu0gW";

/// What the handler was handed, and how its file stream ended.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Stored {
    key: String,
    content_type: Option<String>,
    metadata: Vec<(String, String)>,
    bytes: Vec<u8>,
    /// `true` for a clean end of the file stream; `false` when it ended in an error, which a store
    /// aborts on.
    clean_end: bool,
}

#[derive(Default)]
struct Backend {
    stored: Mutex<Option<Stored>>,
}

impl Handler<PostObject> for Backend {
    async fn call(&self, request: Req<PostObject>) -> HandlerResult<PostObject> {
        let input = request.into_input();
        let mut stored = Stored {
            key: input.key.as_str().to_owned(),
            content_type: input.content_type,
            metadata: input.metadata,
            bytes: Vec::new(),
            clean_end: true,
        };
        let mut body = input.body.into_body();
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(frame) => {
                    if let Ok(data) = frame.into_data() {
                        stored.bytes.extend_from_slice(&data);
                    }
                }
                Err(_) => {
                    stored.clean_end = false;
                    break;
                }
            }
        }
        let clean_end = stored.clean_end;
        *self
            .stored
            .lock()
            .map_err(|_| HandlerError::internal_error("the observation lock failed"))? = Some(stored);
        if !clean_end {
            return Err(HandlerError::internal_error("the POST file stream failed"));
        }
        Ok(Resp::new(PostObjectOutput {
            e_tag: Some(ETag::new("storage-etag").expect("the fixture entity tag is valid")),
            version_id: None,
        }))
    }
}

/// The service, with an authorizer that allows every request or refuses every request.
fn service_authorizing(backend: Arc<Backend>, allow: bool) -> S3Service {
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials")));
    ServiceBuilder::new()
        .register::<PostObject, _>(backend)
        .authenticator(rustfs_gateway::SigV4Authenticator::new(
            credentials,
            rustfs_gateway::RegionSet::new(["us-east-1"]).expect("non-empty region set"),
        ))
        .authorizer(rustfs_gateway::allow_when(move |_| allow))
        .legacy_rustfs_post_forms()
        .build()
        .expect("complete POST Object service")
}

/// Posts `body` under `content_type`, with a `Content-Length` unless `chunked`.
async fn post(content_type: &str, body: Vec<u8>, chunked: bool) -> (StatusCode, Option<Stored>) {
    post_authorizing(content_type, body, chunked, true).await
}

/// As [`post`], through a service whose authorizer allows everything or nothing.
async fn post_authorizing(content_type: &str, body: Vec<u8>, chunked: bool, allow: bool) -> (StatusCode, Option<Stored>) {
    let backend = Arc::new(Backend::default());
    let mut request = Request::builder()
        .method("POST")
        .uri("http://host.invalid/example-bucket")
        .header("host", "host.invalid")
        .header("content-type", content_type);
    if !chunked {
        request = request.header("content-length", body.len());
    }
    let request = request.body(Bytes::from(body)).expect("valid request");
    let response = service_authorizing(Arc::clone(&backend), allow).call_bytes(request).await;
    let status = response.status();
    let _ = response.into_body().collect().await;
    let stored = backend.stored.lock().expect("observation lock").clone();
    (status, stored)
}

fn content_type() -> String {
    format!("multipart/form-data; boundary={BOUNDARY}")
}

fn part(headers: &str, content: &str) -> Vec<u8> {
    format!("--{BOUNDARY}\r\n{headers}\r\n\r\n{content}\r\n").into_bytes()
}

fn field(name: &str, value: &str) -> Vec<u8> {
    part(&format!("Content-Disposition: form-data; name=\"{name}\""), value)
}

fn form(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut body = parts.concat();
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    body
}

/// A form with the key `uploads/${filename}` and a file part whose disposition is `disposition`.
fn with_file_disposition(disposition: &str) -> Vec<u8> {
    form(&[
        field("key", "uploads/${filename}"),
        part(&format!("Content-Disposition: {disposition}"), "the object content"),
    ])
}

/// The object stored from `uploads/${filename}` with `name` as the file name, and no metadata.
fn stored_as(name: &str) -> Stored {
    Stored {
        key: format!("uploads/{name}"),
        content_type: None,
        metadata: Vec::new(),
        bytes: b"the object content".to_vec(),
        clean_end: true,
    }
}

async fn accepted(content_type: &str, body: Vec<u8>) -> Stored {
    let (status, stored) = post(content_type, body, false).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "stored={stored:?}");
    stored.expect("the handler stored the object")
}

async fn refused_before_the_handler(content_type: &str, body: Vec<u8>) -> StatusCode {
    let (status, stored) = post(content_type, body, false).await;
    assert!(!status.is_success(), "{status}");
    assert_eq!(stored, None, "the handler ran for a refused form");
    status
}

// ── positive ──────────────────────────────────────────────────────────────────────────────────

/// A browser upload: the key names the file, and the `Content-Type` field and every
/// `x-amz-meta-*` field are stored as legacy RustFS stores them.
#[tokio::test]
async fn a_browser_form_stores_its_key_content_type_metadata_and_bytes() {
    let body = form(&[
        field("key", "uploads/${filename}"),
        field("Content-Type", "application/pdf"),
        field("X-Amz-Meta-Origin", "browser form"),
        field("acl", "private"),
        field("success_action_status", "204"),
        part(
            "Content-Disposition: form-data; name=\"file\"; filename=\"report.pdf\"\r\nContent-Type: text/plain",
            "%PDF-1.7 the object content",
        ),
    ]);
    let stored = accepted(&content_type(), body).await;
    assert_eq!(
        stored,
        Stored {
            key: "uploads/report.pdf".to_owned(),
            content_type: Some("application/pdf".to_owned()),
            metadata: vec![("origin".to_owned(), "browser form".to_owned())],
            bytes: b"%PDF-1.7 the object content".to_vec(),
            clean_end: true,
        }
    );
}

/// R8: a `;` inside a quoted filename is part of the name.
#[tokio::test]
async fn a_semicolon_inside_a_quoted_filename_is_stored_in_the_key() {
    let stored = accepted(&content_type(), with_file_disposition("form-data; name=\"file\"; filename=\"a;b.txt\"")).await;
    assert_eq!(stored, stored_as("a;b.txt"));
}

/// R8: `filename*` is ignored; without a `filename` the file is named after its part, as sent.
#[tokio::test]
async fn an_extended_filename_is_ignored_and_the_part_names_the_file() {
    for (disposition, name) in [
        ("form-data; name=\"file\"; filename*=UTF-8''%E2%82%AC.txt", "file"),
        ("form-data; name=\"File\"; filename*=UTF-8''%E2%82%AC.txt", "File"),
        ("form-data; name=\"file\"", "file"),
        (
            "form-data; name=\"file\"; filename*=UTF-8''%E2%82%AC.txt; filename=\"eur.txt\"",
            "eur.txt",
        ),
    ] {
        let stored = accepted(&content_type(), with_file_disposition(disposition)).await;
        assert_eq!(stored, stored_as(name), "{disposition}");
    }
}

/// R8: bare parameter values.
#[tokio::test]
async fn bare_parameter_values_are_stored_as_quoted_ones() {
    let body = form(&[
        part("Content-Disposition: form-data; name=key", "uploads/${filename}"),
        part("Content-Disposition: form-data; name = x-amz-meta-note ;", "bare"),
        part("Content-Disposition: form-data; name=file; filename=my report.txt", "the object content"),
    ]);
    let stored = accepted(&content_type(), body).await;
    assert_eq!(
        stored,
        Stored {
            metadata: vec![("note".to_owned(), "bare".to_owned())],
            ..stored_as("my report.txt")
        }
    );
}

/// R8: a preamble before the first boundary is discarded, and so is transport padding after a
/// boundary line.
#[tokio::test]
async fn a_preamble_and_transport_padding_store_the_same_object() {
    let canonical = with_file_disposition("form-data; name=\"file\"; filename=\"a.txt\"");
    let preamble = [b"This is a multi-part message in MIME format.\r\n".as_slice(), &canonical].concat();
    let padded = [
        format!("--{BOUNDARY} \t\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nuploads/${{filename}}\r\n").as_bytes(),
        format!("--{BOUNDARY}\t\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\r\n").as_bytes(),
        b"the object content\r\n",
        format!("--{BOUNDARY}--\r\n").as_bytes(),
    ]
    .concat();
    for body in [preamble, padded] {
        assert_eq!(accepted(&content_type(), body).await, stored_as("a.txt"));
    }
}

/// A quoted filename keeps its backslash escapes, and the first of two `filename`s names the file.
#[tokio::test]
async fn escapes_and_the_first_filename_are_stored_as_legacy_rustfs_stores_them() {
    let stored = accepted(
        &content_type(),
        with_file_disposition(r#"form-data; name="file"; filename="a \"b\".txt""#),
    )
    .await;
    assert_eq!(stored, stored_as(r#"a \"b\".txt"#));
    let stored = accepted(
        &content_type(),
        with_file_disposition("form-data; name=\"file\"; filename=\"one.txt\"; filename=\"two.txt\""),
    )
    .await;
    assert_eq!(stored, stored_as("one.txt"));
}

/// A metadata field with no name after its prefix is accepted and not stored; the last of two
/// dispositions names a part.
#[tokio::test]
async fn nameless_metadata_is_dropped_and_the_last_disposition_names_the_part() {
    let body = form(&[
        field("key", "uploads/${filename}"),
        field("x-amz-meta-", "nameless"),
        part(
            "Content-Disposition: form-data; name=\"x-amz-meta-first\"\r\nContent-Disposition: form-data; name=\"x-amz-meta-last\"",
            "kept",
        ),
        part("Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"", "the object content"),
    ]);
    let stored = accepted(&content_type(), body).await;
    assert_eq!(
        stored,
        Stored {
            metadata: vec![("last".to_owned(), "kept".to_owned())],
            ..stored_as("a.txt")
        }
    );
}

/// Without a `Content-Length`, padding may precede the closing delimiter's CRLF.
#[tokio::test]
async fn a_chunked_form_may_pad_its_closing_delimiter() {
    let mut body = with_file_disposition("form-data; name=\"file\"; filename=\"a.txt\"");
    body.truncate(body.len() - 2);
    body.extend_from_slice(b" \t\r\n");
    let (status, stored) = post(&content_type(), body, true).await;
    assert_eq!((status, stored), (StatusCode::NO_CONTENT, Some(stored_as("a.txt"))));
}

// ── negative ──────────────────────────────────────────────────────────────────────────────────

/// Whatever follows the closing delimiter but its CRLF: the file stream ends in an error, never a
/// clean end, so nothing is committed — as legacy RustFS's own file stream fails at that point.
#[tokio::test]
async fn bytes_after_the_closing_delimiter_never_complete_the_upload() {
    let canonical = with_file_disposition("form-data; name=\"file\"; filename=\"a.txt\"");
    let close = canonical.len() - 2;
    for tail in [&b"\r\nan epilogue"[..], b"\r\n\r\n", b" \r\n", b"", b"x"] {
        let body = [&canonical[..close], tail].concat();
        let (status, stored) = post(&content_type(), body, false).await;
        assert!(!status.is_success(), "{tail:?}: {status}");
        let stored = stored.expect("the handler was reached with the file");
        assert!(!stored.clean_end, "{tail:?}: the upload completed");
    }
}

/// A boundary outside RFC 2046's characters, and a `Content-Type` the legacy header reader cannot
/// read, are refused before the handler.
#[tokio::test]
async fn an_unreadable_boundary_or_content_type_is_refused_before_the_handler() {
    let body = |boundary: &str| {
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nk\r\n--{boundary}\r\n\
             Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\r\nc\r\n--{boundary}--\r\n"
        )
        .into_bytes()
    };
    for (content_type, boundary) in [
        ("multipart/form-data; boundary=\"a@b\"", "a@b"),
        ("multipart/form-data; boundary=\"trailing \"", "trailing "),
        ("multipart/form-data ; boundary=abc", "abc"),
        ("multipart/form-data;\tboundary=abc", "abc"),
    ] {
        let status = refused_before_the_handler(content_type, body(boundary)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{content_type}");
    }
}

/// Header blocks legacy RustFS refuses: empty, a disposition in fourth place, a bare word before
/// `name`, an unterminated quote, a folded line.
#[tokio::test]
async fn an_unnamed_or_malformed_part_is_refused_before_the_handler() {
    for headers in [
        "X-1: 1\r\nX-2: 2\r\nX-3: 3\r\nContent-Disposition: form-data; name=\"x-amz-meta-m\"",
        "Content-Disposition: form-data; junk; name=\"x-amz-meta-m\"",
        "Content-Disposition: form-data; name=\"x-amz-meta-m",
        "Content-Disposition: form-data;\r\n name=\"x-amz-meta-m\"",
    ] {
        let body = form(&[
            field("key", "k"),
            part(headers, "v"),
            part("Content-Disposition: form-data; name=\"file\"", "c"),
        ]);
        assert_eq!(
            refused_before_the_handler(&content_type(), body).await,
            StatusCode::BAD_REQUEST,
            "{headers}"
        );
    }
    let mut empty = format!("--{BOUNDARY}\r\n\r\n").into_bytes();
    empty.extend_from_slice(&with_file_disposition("form-data; name=\"file\""));
    assert_eq!(refused_before_the_handler(&content_type(), empty).await, StatusCode::BAD_REQUEST);
}

/// A field legacy RustFS applies to the stored object and this profile cannot carry yet is refused
/// before the handler, rather than stored without it. (The Object Lock fields are carried since
/// rustfs/gateway#1167: `post_object_legacy_fields.rs`.)
#[tokio::test]
async fn a_field_the_profile_cannot_carry_is_refused_before_the_handler() {
    for name in [
        "x-amz-server-side-encryption-customer-key",
        "X-Amz-Server-Side-Encryption-Customer-Algorithm",
    ] {
        let body = form(&[
            field("key", "k"),
            field(name, "value"),
            part("Content-Disposition: form-data; name=\"file\"", "c"),
        ]);
        assert_eq!(
            refused_before_the_handler(&content_type(), body).await,
            StatusCode::NOT_IMPLEMENTED,
            "{name}"
        );
    }
}

/// The field rules both grammars keep: a repeated field, and a control byte in a value.
#[tokio::test]
async fn a_repeated_field_or_a_control_byte_is_still_refused_before_the_handler() {
    for parts in [
        vec![field("key", "one"), field("KEY", "two")],
        vec![field("key", "k"), field("x-amz-meta-note", "line one\r\nline two")],
    ] {
        let mut parts = parts;
        parts.push(part("Content-Disposition: form-data; name=\"file\"", "c"));
        assert_eq!(refused_before_the_handler(&content_type(), form(&parts)).await, StatusCode::BAD_REQUEST);
    }
}

/// A form carrying a field the profile cannot carry is refused with 501 only where legacy RustFS
/// would have stored it. A refusal legacy RustFS answers before it stores — authorization, an
/// invalid `success_action_status` (its access hook, `rustfs/src/storage/access.rs:2024-2029`) —
/// is answered the same way here, not with 501.
#[tokio::test]
async fn an_earlier_refusal_wins_over_the_uncarried_field_refusal() {
    let file = part("Content-Disposition: form-data; name=\"file\"", "c");
    let body = form(&[field("key", "k"), field("Cache-Control", "no-cache"), file.clone()]);
    let (status, stored) = post_authorizing(&content_type(), body, false, false).await;
    assert_eq!((status, stored), (StatusCode::FORBIDDEN, None), "authorization answers first");

    let body = form(&[
        field("key", "k"),
        field("Cache-Control", "no-cache"),
        field("success_action_status", "999"),
        file,
    ]);
    assert_eq!(refused_before_the_handler(&content_type(), body).await, StatusCode::BAD_REQUEST);
}
