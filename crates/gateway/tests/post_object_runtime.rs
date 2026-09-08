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

//! Production POST Object form routing, bounded prelude parsing and live handler dispatch.
//!
//! Responsible for: proving that an actual `S3Service` turns an anonymous multipart form into the
//! typed PostObject handler input, including its resolved key, file bytes, and success-action
//! response selected from the real storage result.
//! NOT responsible for: signed-policy vectors or browser execution of returned redirects.
//! Upstream: the facade public API. Downstream: the POST Object conformance family.

#![allow(clippy::expect_used)]

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use rustfs_gateway::dto::{PostObject, PostObjectOutput};
use rustfs_gateway::{
    Credentials, ETag, Handler, HandlerError, HandlerResult, Req, Resp, S3Service, ServiceBuilder, StaticCredentials,
};

const BOUNDARY: &str = "----RustFSPostRuntime";

#[derive(Default)]
struct Backend {
    observed: Mutex<Option<(String, Vec<u8>)>>,
}

impl Handler<PostObject> for Backend {
    async fn call(&self, request: Req<PostObject>) -> HandlerResult<PostObject> {
        let input = request.into_input();
        let key = input.key.as_str().to_owned();
        let mut body = input.body.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = match frame {
                Ok(frame) => frame,
                Err(error) => {
                    *self
                        .observed
                        .lock()
                        .map_err(|_| HandlerError::internal_error("the observation lock failed"))? =
                        Some((format!("stream-error:{error}"), bytes));
                    return Err(HandlerError::internal_error("the POST file stream failed"));
                }
            };
            if let Ok(data) = frame.into_data() {
                bytes.extend_from_slice(&data);
            }
        }
        *self
            .observed
            .lock()
            .map_err(|_| HandlerError::internal_error("the observation lock failed"))? = Some((key, bytes));
        Ok(Resp::new(PostObjectOutput {
            e_tag: Some(ETag::new("storage-etag").expect("the fixture entity tag is valid")),
            version_id: Some("stored-version".to_owned()),
        }))
    }
}

fn form() -> Bytes {
    form_with_fields(&[])
}

fn form_with_fields(fields: &[(&str, &str)]) -> Bytes {
    form_with_filename_and_fields("report.txt", fields)
}

fn form_with_filename_and_fields(filename: &str, fields: &[(&str, &str)]) -> Bytes {
    let mut extra = String::new();
    for (name, value) in fields {
        extra.push_str(&format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        ));
    }
    Bytes::from(format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nuploads/${{filename}}\r\n\
         {extra}\
         --{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n\
         Content-Type: text/plain\r\n\r\nhello from a browser\r\n--{BOUNDARY}--\r\n"
    ))
}

fn file_only_form() -> Bytes {
    Bytes::from(format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"report.txt\"\r\n\r\n\
         unaddressed\r\n--{BOUNDARY}--\r\n"
    ))
}

fn service(backend: Arc<Backend>) -> S3Service {
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials")));
    ServiceBuilder::new()
        .register::<PostObject, _>(backend)
        .authenticator(rustfs_gateway::SigV4Authenticator::new(
            credentials,
            rustfs_gateway::RegionSet::new(["us-east-1"]).expect("non-empty region set"),
        ))
        .authorizer(rustfs_gateway::allow_when(|_| true))
        .build()
        .expect("complete POST Object service")
}

fn request(body: Bytes) -> Request<Bytes> {
    Request::builder()
        .method("POST")
        .uri("http://host.invalid/example-bucket")
        .header("host", "host.invalid")
        .header("content-type", format!("multipart/form-data; boundary={BOUNDARY}"))
        .body(body)
        .expect("valid request")
}

#[tokio::test]
async fn an_anonymous_form_reaches_the_real_post_object_handler() {
    let backend = Arc::new(Backend::default());
    let service = service(Arc::clone(&backend));

    let response = service.call_bytes(request(form())).await;
    let status = response.status();
    let refusal = response.into_body().collect().await.expect("response body").to_bytes();
    let observed = backend.observed.lock().expect("observation lock").clone();

    assert_eq!((status, refusal), (StatusCode::NO_CONTENT, Bytes::new()), "observed={observed:?}");
    assert_eq!(
        observed.as_ref(),
        Some(&("uploads/report.txt".to_owned(), b"hello from a browser".to_vec()))
    );
}

#[tokio::test]
async fn success_action_status_204_returns_an_empty_204_response() {
    let backend = Arc::new(Backend::default());
    let response = service(Arc::clone(&backend))
        .call_bytes(request(form_with_fields(&[("success_action_status", "204")])))
        .await;

    let status = response.status();
    let body = response.into_body().collect().await.expect("response body").to_bytes();
    assert_eq!((status, body), (StatusCode::NO_CONTENT, Bytes::new()));
}

#[tokio::test]
async fn success_action_status_200_returns_an_empty_200_response() {
    let backend = Arc::new(Backend::default());
    let response = service(Arc::clone(&backend))
        .call_bytes(request(form_with_fields(&[("success_action_status", "200")])))
        .await;

    let status = response.status();
    let body = response.into_body().collect().await.expect("response body").to_bytes();
    assert_eq!((status, body), (StatusCode::OK, Bytes::new()));
}

#[tokio::test]
async fn success_action_status_201_returns_the_real_object_result() {
    let backend = Arc::new(Backend::default());
    let response = service(Arc::clone(&backend))
        .call_bytes(request(form_with_filename_and_fields(
            "report & 1.txt",
            &[("success_action_status", "201")],
        )))
        .await;

    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = response.into_body().collect().await.expect("response body").to_bytes();
    assert_eq!(
        (status, content_type, body),
        (
            StatusCode::CREATED,
            Some("application/xml".to_owned()),
            Bytes::from_static(
                b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<PostResponse xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Location>http://host.invalid/example-bucket/uploads/report%20%26%201.txt</Location><Bucket>example-bucket</Bucket><Key>uploads/report &amp; 1.txt</Key><ETag>&quot;storage-etag&quot;</ETag></PostResponse>"
            )
        )
    );
}

#[tokio::test]
async fn success_action_redirect_returns_a_validated_303_location() {
    let backend = Arc::new(Backend::default());
    let response = service(Arc::clone(&backend))
        .call_bytes(request(form_with_fields(&[(
            "success_action_redirect",
            "https://client.example/finished?upload=1#receipt",
        )])))
        .await;

    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = response.into_body().collect().await.expect("response body").to_bytes();
    assert_eq!(
        (status, location, body),
        (
            StatusCode::SEE_OTHER,
            Some("https://client.example/finished?upload=1&bucket=example-bucket&key=uploads%2Freport.txt&etag=%22storage-etag%22#receipt".to_owned()),
            Bytes::new()
        )
    );
}

async fn assert_success_action_is_refused(fields: &[(&str, &str)]) {
    let backend = Arc::new(Backend::default());
    let response = service(Arc::clone(&backend))
        .call_bytes(request(form_with_fields(fields)))
        .await;

    let observed = backend.observed.lock().expect("observation lock").clone();
    assert_eq!((response.status(), observed), (StatusCode::BAD_REQUEST, None));
}

#[tokio::test]
async fn an_unknown_success_action_status_is_refused_before_the_handler() {
    assert_success_action_is_refused(&[("success_action_status", "202")]).await;
}

#[tokio::test]
async fn an_empty_success_action_status_is_refused_before_the_handler() {
    assert_success_action_is_refused(&[("success_action_status", "")]).await;
}

#[tokio::test]
async fn duplicate_success_action_status_fields_are_refused_before_the_handler() {
    assert_success_action_is_refused(&[("success_action_status", "200"), ("success_action_status", "200")]).await;
}

#[tokio::test]
async fn conflicting_success_actions_are_refused_before_the_handler() {
    assert_success_action_is_refused(&[
        ("success_action_status", "201"),
        ("success_action_redirect", "https://client.example/finished"),
    ])
    .await;
}

#[tokio::test]
async fn duplicate_success_action_redirect_fields_are_refused_before_the_handler() {
    assert_success_action_is_refused(&[
        ("success_action_redirect", "https://client.example/first"),
        ("success_action_redirect", "https://client.example/second"),
    ])
    .await;
}

#[tokio::test]
async fn a_control_character_in_success_action_redirect_is_refused_before_the_handler() {
    assert_success_action_is_refused(&[("success_action_redirect", "https://client.example/finished\u{1}")]).await;
}

#[tokio::test]
async fn an_empty_success_action_redirect_is_refused_before_the_handler() {
    assert_success_action_is_refused(&[("success_action_redirect", "")]).await;
}

#[tokio::test]
async fn a_non_http_success_action_redirect_is_refused_before_the_handler() {
    assert_success_action_is_refused(&[("success_action_redirect", "ftp://client.example/finished")]).await;
}

#[tokio::test]
async fn an_unrenderable_success_action_redirect_is_refused_before_the_handler() {
    assert_success_action_is_refused(&[("success_action_redirect", "https:///missing-host")]).await;
}

#[tokio::test]
async fn a_form_without_a_key_is_refused_before_the_handler() {
    let backend = Arc::new(Backend::default());
    let response = service(Arc::clone(&backend)).call_bytes(request(file_only_form())).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(backend.observed.lock().expect("observation lock").is_none());
}

#[tokio::test]
async fn a_non_multipart_body_is_refused_before_the_handler() {
    let backend = Arc::new(Backend::default());
    let bad = Request::builder()
        .method("POST")
        .uri("http://host.invalid/example-bucket")
        .header("host", "host.invalid")
        .header("content-type", "text/plain")
        .body(Bytes::from_static(b"not multipart"))
        .expect("valid request");
    let response = service(Arc::clone(&backend)).call_bytes(bad).await;

    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert!(backend.observed.lock().expect("observation lock").is_none());
}
