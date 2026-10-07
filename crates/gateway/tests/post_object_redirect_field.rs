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

//! A POST form's `redirect` field under the RustFS profile (rustfs/gateway#1167).
//!
//! Responsible for: `redirect` read as the success redirect when the form carries no
//! `success_action_redirect`, with every answer legacy RustFS gives a redirect — a `303` to it with
//! the stored object named, a malformed one refused before storage, an empty one refused after it,
//! authorization first — and the generic profile still ignoring the field.
//! NOT responsible for: `success_action_redirect` itself (`post_object_runtime.rs`) or the form
//! members a handler stores (`post_object_legacy_fields.rs`).
//! Upstream: the facade's public API. Downstream: nothing.
//!
//! Evidence: legacy RustFS's POST decoding reads `success_action_redirect`, and the `redirect`
//! field only when that one is absent, into the same success redirect; its access hook refuses one
//! that is not an absolute URL before storage (`rustfs/src/storage/access.rs:2060-2075` at
//! rustfs/rustfs@95268a3b9), and its answer refuses an empty one after storage, as it does for
//! `success_action_redirect`.

#![allow(clippy::expect_used)]

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use rustfs_gateway::dto::{PostObject, PostObjectOutput};
use rustfs_gateway::{Credentials, ETag, Handler, HandlerResult, Req, Resp, S3Service, ServiceBuilder, StaticCredentials};

const BOUNDARY: &str = "----RustFSRedirectField";

/// Records what each handled form stored.
#[derive(Default)]
struct Backend {
    stored: Mutex<Option<(String, Vec<u8>)>>,
}

impl Handler<PostObject> for Backend {
    async fn call(&self, request: Req<PostObject>) -> HandlerResult<PostObject> {
        let input = request.into_input();
        let key = input.key.as_str().to_owned();
        let bytes = input
            .body
            .into_body()
            .collect()
            .await
            .map(|body| body.to_bytes().to_vec())
            .unwrap_or_default();
        *self.stored.lock().expect("observation lock") = Some((key, bytes));
        Ok(Resp::new(PostObjectOutput {
            e_tag: Some(ETag::new("storage-etag").expect("the fixture entity tag is valid")),
            version_id: None,
        }))
    }
}

fn service(backend: Arc<Backend>, legacy: bool, allow: bool) -> S3Service {
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials")));
    let builder = ServiceBuilder::new()
        .register::<PostObject, _>(backend)
        .authenticator(rustfs_gateway::SigV4Authenticator::new(
            credentials,
            rustfs_gateway::RegionSet::new(["us-east-1"]).expect("non-empty region set"),
        ))
        .authorizer(rustfs_gateway::allow_when(move |_| allow));
    let builder = if legacy { builder.legacy_rustfs_post_forms() } else { builder };
    builder.build().expect("complete POST Object service")
}

/// Posts an anonymous form storing `uploads/report.txt` with `fields`; the status, the
/// `Location`, the answer and what was stored.
async fn post(
    legacy: bool,
    allow: bool,
    fields: &[(&str, &str)],
) -> (StatusCode, Option<String>, String, Option<(String, Vec<u8>)>) {
    let mut body = format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nuploads/report.txt\r\n");
    for (name, value) in fields {
        body.push_str(&format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        ));
    }
    body.push_str(&format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"report.txt\"\r\n\r\nhello\r\n--{BOUNDARY}--\r\n"
    ));
    let request = Request::builder()
        .method("POST")
        .uri("http://host.invalid/example-bucket")
        .header("host", "host.invalid")
        .header("content-type", format!("multipart/form-data; boundary={BOUNDARY}"))
        .header("content-length", body.len())
        .body(Bytes::from(body))
        .expect("valid request");
    let backend = Arc::new(Backend::default());
    let response = service(Arc::clone(&backend), legacy, allow).call_bytes(request).await;
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .map(|value| value.to_str().expect("location").to_owned());
    let answer = response.into_body().collect().await.expect("response body").to_bytes();
    let stored = backend.stored.lock().expect("observation lock").clone();
    (status, location, String::from_utf8_lossy(&answer).into_owned(), stored)
}

fn stored() -> Option<(String, Vec<u8>)> {
    Some(("uploads/report.txt".to_owned(), b"hello".to_vec()))
}

// ── positive ─────────────────────────────────────────────────────────────────────────────────

/// Positive — without `success_action_redirect`, the `redirect` field is the success redirect: a
/// `303` to it naming the stored object.
#[tokio::test]
async fn the_redirect_field_is_the_success_redirect() {
    let (status, location, answer, stored_object) = post(true, true, &[("redirect", "https://client.example/done")]).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{answer}");
    assert_eq!(
        location.as_deref(),
        Some("https://client.example/done?bucket=example-bucket&key=uploads%2Freport.txt&etag=storage-etag")
    );
    assert_eq!(stored_object, stored());
}

// ── negative ─────────────────────────────────────────────────────────────────────────────────

/// Negative — `success_action_redirect` wins over the `redirect` field.
#[tokio::test]
async fn n_success_action_redirect_wins_over_the_redirect_field() {
    let (status, location, answer, _) = post(
        true,
        true,
        &[
            ("redirect", "https://client.example/ignored"),
            ("success_action_redirect", "https://client.example/chosen"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{answer}");
    assert!(
        location
            .as_deref()
            .is_some_and(|location| location.starts_with("https://client.example/chosen?")),
        "{location:?}"
    );
}

/// Negative — a `redirect` that is not an absolute URL is legacy RustFS's
/// `400 MalformedPOSTRequest`, and nothing is stored.
#[tokio::test]
async fn n_an_unparseable_redirect_field_is_refused_before_storage() {
    let (status, _, answer, stored_object) = post(true, true, &[("redirect", "://not-a-url")]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert!(answer.contains("<Code>MalformedPOSTRequest</Code>"), "{answer}");
    assert_eq!(stored_object, None);
}

/// Negative — an empty `redirect` is refused `400 InvalidArgument` only after the file is stored,
/// as legacy RustFS refuses an empty `success_action_redirect`.
#[tokio::test]
async fn n_an_empty_redirect_field_is_refused_after_storage() {
    let (status, _, answer, stored_object) = post(true, true, &[("redirect", "")]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert!(answer.contains("<Code>InvalidArgument</Code>"), "{answer}");
    assert_eq!(stored_object, stored());
}

/// Negative — authorization comes first: a denied form with a `redirect` is `403` and stores
/// nothing.
#[tokio::test]
async fn n_a_redirect_field_cannot_bypass_authorization() {
    for redirect in ["https://client.example/done", "://not-a-url", ""] {
        let (status, _, answer, stored_object) = post(true, false, &[("redirect", redirect)]).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{redirect:?}: {answer}");
        assert_eq!(stored_object, None, "{redirect:?}");
    }
}

/// Negative — the generic profile does not read the field: the upload gets its default `204`.
#[tokio::test]
async fn n_the_generic_profile_ignores_the_redirect_field() {
    let (status, location, answer, stored_object) = post(false, true, &[("redirect", "https://client.example/done")]).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{answer}");
    assert_eq!(location, None);
    assert_eq!(stored_object, stored());
}
