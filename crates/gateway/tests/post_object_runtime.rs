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
    refuse: bool,
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
        if self.refuse {
            return Err(HandlerError::new(rustfs_gateway::ErrorCode::SLOW_DOWN, "storage refused the upload"));
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
    service_with_form_profile(backend, false, true)
}

fn service_with_form_profile(backend: Arc<Backend>, legacy: bool, allow: bool) -> S3Service {
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

async fn success_status(legacy: bool, allow: bool, raw: &str) -> (StatusCode, String, Option<(String, Vec<u8>)>) {
    let (status, _, body, observed) = success_controls(legacy, allow, &[("success_action_status", raw)]).await;
    (status, body, observed)
}

async fn success_controls(
    legacy: bool,
    allow: bool,
    fields: &[(&str, &str)],
) -> (StatusCode, Option<String>, String, Option<(String, Vec<u8>)>) {
    success_controls_with_filename(legacy, allow, "report.txt", fields).await
}

async fn success_controls_with_filename(
    legacy: bool,
    allow: bool,
    filename: &str,
    fields: &[(&str, &str)],
) -> (StatusCode, Option<String>, String, Option<(String, Vec<u8>)>) {
    let backend = Arc::new(Backend::default());
    let response = service_with_form_profile(Arc::clone(&backend), legacy, allow)
        .call_bytes(request(form_with_filename_and_fields(filename, fields)))
        .await;
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .map(|value| value.to_str().expect("location").to_owned());
    let body = response.into_body().collect().await.expect("response body").to_bytes();
    let observed = backend.observed.lock().expect("observation lock").clone();
    (status, location, String::from_utf8(body.to_vec()).expect("XML response"), observed)
}

// Native RustFS HTTP comparisons, including authorization and stored bytes: gateway#1185.
#[tokio::test]
async fn legacy_success_status_accepts_numeric_spellings() {
    for (raw, expected) in [
        ("0200", StatusCode::OK),
        ("+201", StatusCode::CREATED),
        ("000204", StatusCode::NO_CONTENT),
    ] {
        let (status, body, observed) = success_status(true, true, raw).await;
        assert_eq!(status, expected, "{raw}: {body}");
        assert_eq!(observed, Some(("uploads/report.txt".to_owned(), b"hello from a browser".to_vec())));
    }
}

#[tokio::test]
async fn legacy_unreadable_success_status_precedes_authorization() {
    for raw in ["", "wrong", " 200", "200 ", "2147483648", "-2147483649"] {
        for allow in [true, false] {
            let (status, body, observed) = success_status(true, allow, raw).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{raw}: {body}");
            assert!(body.contains("<Code>InvalidArgument</Code>"), "{raw}: {body}");
            assert_eq!(observed, None);
        }
    }
}

#[tokio::test]
async fn legacy_unsupported_success_status_never_reaches_storage() {
    for raw in ["202", "0", "-1", "65536", "2147483647", "-2147483648"] {
        let (status, body, observed) = success_status(true, true, raw).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{raw}: {body}");
        assert!(body.contains("<Code>MalformedPOSTRequest</Code>"), "{raw}: {body}");
        assert_eq!(observed, None);
    }
}

#[tokio::test]
async fn legacy_denied_authorization_precedes_numeric_success_status() {
    for raw in ["202", "0", "-1", "65536", "2147483647", "-2147483648", "+200", "000204"] {
        let (status, body, observed) = success_status(true, false, raw).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{raw}: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "{raw}: {body}");
        assert_eq!(observed, None);
    }
}

#[tokio::test]
async fn generic_success_status_keeps_exact_spellings_and_early_refusal() {
    for raw in ["0200", "+201", "000204", "202", "", "2147483648"] {
        for allow in [true, false] {
            let (status, body, observed) = success_status(false, allow, raw).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{raw}: {body}");
            assert!(body.contains("<Code>MalformedPOSTRequest</Code>"), "{raw}: {body}");
            assert_eq!(observed, None);
        }
    }
}

#[tokio::test]
async fn legacy_created_response_keeps_its_relative_location_and_bare_etag() {
    let backend = Arc::new(Backend::default());
    let response = service_with_form_profile(Arc::clone(&backend), true, true)
        .call_bytes(request(form_with_filename_and_fields(
            "a b&résumé?.txt",
            &[("success_action_status", "201")],
        )))
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response.into_body().collect().await.expect("response body").to_bytes();
    assert_eq!(
        std::str::from_utf8(&body).expect("XML"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><PostResponse><Location>/example-bucket/uploads/a b&amp;résumé?.txt</Location><Bucket>example-bucket</Bucket><Key>uploads/a b&amp;résumé?.txt</Key><ETag>storage-etag</ETag></PostResponse>"
    );
    assert_eq!(
        backend.observed.lock().expect("observation lock").clone(),
        Some(("uploads/a b&résumé?.txt".to_owned(), b"hello from a browser".to_vec()))
    );
}

#[tokio::test]
async fn legacy_redirect_wins_over_a_supported_status() {
    let (status, location, body, observed) = success_controls(
        true,
        true,
        &[
            ("success_action_status", "201"),
            ("success_action_redirect", "https://client.example/finished?upload=1#receipt"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_eq!(
        location.as_deref(),
        Some("https://client.example/finished?upload=1&bucket=example-bucket&key=uploads%2Freport.txt&etag=storage-etag#receipt")
    );
    assert_eq!(body, "");
    assert_eq!(observed, Some(("uploads/report.txt".to_owned(), b"hello from a browser".to_vec())));
}

#[tokio::test]
async fn legacy_redirect_cannot_override_an_unsupported_numeric_status() {
    for allow in [true, false] {
        let (status, _, body, observed) = success_controls(
            true,
            allow,
            &[
                ("success_action_status", "202"),
                ("success_action_redirect", "https://client.example/finished"),
            ],
        )
        .await;
        let (expected, code) = if allow {
            (StatusCode::BAD_REQUEST, "MalformedPOSTRequest")
        } else {
            (StatusCode::FORBIDDEN, "AccessDenied")
        };
        assert_eq!(status, expected, "{body}");
        assert!(body.contains(&format!("<Code>{code}</Code>")), "{body}");
        assert_eq!(observed, None);
    }
}

#[tokio::test]
async fn legacy_invalid_redirect_does_not_preempt_authorization() {
    for raw in [
        "/complete",
        "https://",
        "//client.example/complete",
        "https://client.example:99999/complete",
        "https://[bad]/complete",
        "https://client.example:99999/a\tb",
        "https://[bad]/a\tb",
        "/a\tb",
    ] {
        for allow in [true, false] {
            let (status, _, body, observed) = success_controls(true, allow, &[("success_action_redirect", raw)]).await;
            let (expected, code) = if allow {
                (StatusCode::BAD_REQUEST, "MalformedPOSTRequest")
            } else {
                (StatusCode::FORBIDDEN, "AccessDenied")
            };
            assert_eq!(status, expected, "{raw}: {body}");
            assert!(body.contains(&format!("<Code>{code}</Code>")), "{raw}: {body}");
            assert_eq!(observed, None);
        }
    }
}

#[tokio::test]
async fn legacy_redirect_cannot_hide_an_unreadable_status() {
    for raw in ["", "wrong", "2147483648"] {
        for allow in [true, false] {
            let (status, _, body, observed) = success_controls(
                true,
                allow,
                &[
                    ("success_action_status", raw),
                    ("success_action_redirect", "https://client.example/finished"),
                ],
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{raw}: {body}");
            assert!(body.contains("<Code>InvalidArgument</Code>"), "{raw}: {body}");
            assert_eq!(observed, None);
        }
    }
}

#[tokio::test]
async fn generic_redirect_conflicts_still_preempt_authorization() {
    for allow in [true, false] {
        let (status, _, body, observed) = success_controls(
            false,
            allow,
            &[
                ("success_action_status", "201"),
                ("success_action_redirect", "https://client.example/finished"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("<Code>MalformedPOSTRequest</Code>"), "{body}");
        assert_eq!(observed, None);
    }
}

#[tokio::test]
async fn legacy_redirect_parameters_use_form_encoding_without_rewriting_the_url() {
    for (raw, prefix, fragment) in [
        (
            "https://client.example/a%20b?tag=a%20b#receipt",
            "https://client.example/a%20b?tag=a%20b&",
            "#receipt",
        ),
        ("https://client.example/finished?", "https://client.example/finished?", ""),
        ("https://client.example/finished?x=1&", "https://client.example/finished?x=1&&", ""),
        ("https://client.example/finished#receipt", "https://client.example/finished?", "#receipt"),
    ] {
        let (status, location, body, observed) =
            success_controls_with_filename(true, true, "a b~*+%&résumé.txt", &[("success_action_redirect", raw)]).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
        assert_eq!(
            location,
            Some(format!(
                "{prefix}bucket=example-bucket&key=uploads%2Fa+b%7E*%2B%25%26r%C3%A9sum%C3%A9.txt&etag=storage-etag{fragment}"
            ))
        );
        assert_eq!(
            observed,
            Some(("uploads/a b~*+%&résumé.txt".to_owned(), b"hello from a browser".to_vec()))
        );
    }
}

#[tokio::test]
async fn generic_redirect_parameters_do_not_inherit_legacy_form_encoding() {
    let (status, location, body, observed) = success_controls_with_filename(
        false,
        true,
        "a b~*+%&résumé.txt",
        &[("success_action_redirect", "https://client.example/finished#receipt")],
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_eq!(
        location.as_deref(),
        Some(
            "https://client.example/finished?bucket=example-bucket&key=uploads%2Fa%20b~%2A%2B%25%26r%C3%A9sum%C3%A9.txt&etag=%22storage-etag%22#receipt"
        )
    );
    assert_eq!(
        observed,
        Some(("uploads/a b~*+%&résumé.txt".to_owned(), b"hello from a browser".to_vec()))
    );
}

#[tokio::test]
async fn legacy_empty_redirect_is_refused_after_the_file_is_stored() {
    for status in [None, Some("200"), Some("201"), Some("204")] {
        let mut fields = vec![("success_action_redirect", "")];
        if let Some(status) = status {
            fields.push(("success_action_status", status));
        }
        let (status, _, body, observed) = success_controls(true, true, &fields).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("<Code>InvalidArgument</Code>"), "{body}");
        assert_eq!(observed, Some(("uploads/report.txt".to_owned(), b"hello from a browser".to_vec())));
    }
}

#[tokio::test]
async fn legacy_empty_redirect_cannot_bypass_authorization() {
    for status in [None, Some("200"), Some("201"), Some("204")] {
        let mut fields = vec![("success_action_redirect", "")];
        if let Some(status) = status {
            fields.push(("success_action_status", status));
        }
        let (status, _, body, observed) = success_controls(true, false, &fields).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");
        assert_eq!(observed, None);
    }
}

#[tokio::test]
async fn legacy_empty_redirect_cannot_override_an_unsupported_status() {
    for allow in [true, false] {
        let (status, _, body, observed) =
            success_controls(true, allow, &[("success_action_redirect", ""), ("success_action_status", "202")]).await;
        let (expected, code) = if allow {
            (StatusCode::BAD_REQUEST, "MalformedPOSTRequest")
        } else {
            (StatusCode::FORBIDDEN, "AccessDenied")
        };
        assert_eq!(status, expected, "{body}");
        assert!(body.contains(&format!("<Code>{code}</Code>")), "{body}");
        assert_eq!(observed, None);
    }
}

#[tokio::test]
async fn legacy_empty_redirect_cannot_hide_an_unreadable_status() {
    for allow in [true, false] {
        let (status, _, body, observed) =
            success_controls(true, allow, &[("success_action_redirect", ""), ("success_action_status", "")]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("<Code>InvalidArgument</Code>"), "{body}");
        assert_eq!(observed, None);
    }
}

#[tokio::test]
async fn generic_empty_redirect_keeps_its_early_refusal() {
    for allow in [true, false] {
        let (status, _, body, observed) = success_controls(false, allow, &[("success_action_redirect", "")]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("<Code>MalformedPOSTRequest</Code>"), "{body}");
        assert_eq!(observed, None);
    }
}

#[tokio::test]
async fn legacy_empty_redirect_cannot_hide_a_storage_failure() {
    let backend = Arc::new(Backend {
        refuse: true,
        ..Backend::default()
    });
    let response = service_with_form_profile(Arc::clone(&backend), true, true)
        .call_bytes(request(form_with_fields(&[("success_action_redirect", "")])))
        .await;
    let status = response.status();
    let body = response.into_body().collect().await.expect("response body").to_bytes();
    let body = std::str::from_utf8(&body).expect("XML response");
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body.contains("<Code>SlowDown</Code>"), "{body}");
    assert_eq!(backend.observed.lock().expect("observation lock").clone(), None);
}

#[tokio::test]
async fn legacy_redirects_use_absolute_url_parsing_and_normalization() {
    for (raw, prefix) in [
        ("https://CLIENT.example:443", "https://client.example/"),
        ("https://client.example/a/../done", "https://client.example/done"),
        ("https://client.example/résumé", "https://client.example/r%C3%A9sum%C3%A9"),
        ("https://client.example/a b", "https://client.example/a%20b"),
        ("  https://client.example/done  ", "https://client.example/done"),
        ("ftp://client.example/done", "ftp://client.example/done"),
        ("mailto:upload@client.example", "mailto:upload@client.example"),
    ] {
        let (status, location, body, observed) = success_controls(true, true, &[("success_action_redirect", raw)]).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{raw}: {body}");
        assert_eq!(
            location,
            Some(format!("{prefix}?bucket=example-bucket&key=uploads%2Freport.txt&etag=storage-etag"))
        );
        assert_eq!(observed, Some(("uploads/report.txt".to_owned(), b"hello from a browser".to_vec())));
    }
}

#[tokio::test]
async fn legacy_blank_and_tab_redirects_are_refused_after_storage() {
    for raw in [
        " ",
        "\t",
        "\u{a0}",
        "\u{2003}",
        "https://client.example/a\tb",
        "\thttps://client.example/done\t",
        "https://cli\tent.example/done",
        "mailto:up\tload@client.example",
    ] {
        let (status, _, body, observed) = success_controls(true, true, &[("success_action_redirect", raw)]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{raw:?}: {body}");
        assert!(body.contains("<Code>InvalidArgument</Code>"), "{raw:?}: {body}");
        assert_eq!(observed, Some(("uploads/report.txt".to_owned(), b"hello from a browser".to_vec())));
    }
}

#[tokio::test]
async fn legacy_normalized_and_control_redirects_cannot_bypass_authorization() {
    for raw in [
        "https://client.example/a b",
        "ftp://client.example/done",
        "mailto:upload@client.example",
        " ",
        "https://client.example/a\tb",
    ] {
        let (status, _, body, observed) = success_controls(true, false, &[("success_action_redirect", raw)]).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{raw:?}: {body}");
        assert!(body.contains("<Code>AccessDenied</Code>"), "{raw:?}: {body}");
        assert_eq!(observed, None);
    }
}

#[tokio::test]
async fn generic_redirects_do_not_inherit_legacy_url_grammar() {
    for raw in [
        "https://client.example/a b",
        "ftp://client.example/done",
        "mailto:upload@client.example",
        " ",
        "https://client.example/a\tb",
    ] {
        for allow in [true, false] {
            let (status, _, body, observed) = success_controls(false, allow, &[("success_action_redirect", raw)]).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{raw:?}: {body}");
            assert!(body.contains("<Code>MalformedPOSTRequest</Code>"), "{raw:?}: {body}");
            assert_eq!(observed, None);
        }
    }
}

// The shared multipart guard deliberately rejects these values under both form grammars.
#[tokio::test]
async fn legacy_prohibited_control_redirects_keep_the_wire_refusal() {
    for raw in [
        "\0",
        "\n",
        "https://client.example/a\nb",
        "https://client.example/a\rb",
        "https://client.example/a\u{1}b",
        "https://client.example/a\u{7f}b",
    ] {
        for allow in [true, false] {
            let (status, _, body, observed) = success_controls(true, allow, &[("success_action_redirect", raw)]).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{raw:?}: {body}");
            assert!(body.contains("<Code>MalformedPOSTRequest</Code>"), "{raw:?}: {body}");
            assert_eq!(observed, None);
        }
    }
}
