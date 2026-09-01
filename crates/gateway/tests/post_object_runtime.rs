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
//! typed PostObject handler input, including its resolved key and file bytes.
//! NOT responsible for: signed-policy vectors or success actions beyond the default status.
//! Upstream: the facade public API. Downstream: the POST Object conformance family.

#![allow(clippy::expect_used)]

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use rustfs_gateway::dto::{PostObject, PostObjectOutput};
use rustfs_gateway::{
    Credentials, Handler, HandlerError, HandlerResult, Req, Resp, S3Service, ServiceBuilder, StaticCredentials,
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
        Ok(Resp::new(PostObjectOutput::default()))
    }
}

fn form() -> Bytes {
    Bytes::from(format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nuploads/${{filename}}\r\n\
         --{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"report.txt\"\r\n\
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

    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "{} observed={observed:?}",
        String::from_utf8_lossy(&refusal)
    );
    assert_eq!(
        observed.as_ref(),
        Some(&("uploads/report.txt".to_owned(), b"hello from a browser".to_vec()))
    );
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
