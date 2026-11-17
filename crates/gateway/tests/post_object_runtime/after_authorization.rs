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

//! Responsible for: exercising the PostObject authorization and success-control boundary.
//! NOT responsible for: multipart grammar or success response encoding.
//! Upstream: the facade public API. Downstream: the consolidated integration harness.

#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body::{Body, Frame, SizeHint};
use rustfs_gateway_sig::{SigFamily, SigLocation};

use crate::support::{self, wired as builder};
use rustfs_gateway::dto::{PostObject, PostObjectOutput};
use rustfs_gateway::{
    BoxFuture, Credentials, ErrorCode, Handler, HandlerError, HandlerResult, Next, OperationSetEnd, OperationSetNode,
    PostObjectHandler, RegionSet, Req, Resp, RuleRef, SecurityFloor, SessionBinding, SigV4Authenticator, StaticCredentials,
    allow_when, op_layer,
};

struct Backend {
    deny: bool,
    principal: Option<(SigFamily, bool)>,
    authorized: AtomicUsize,
    executed: AtomicUsize,
}

impl Backend {
    fn new(deny: bool) -> Arc<Self> {
        Arc::new(Self {
            deny,
            principal: None,
            authorized: AtomicUsize::new(0),
            executed: AtomicUsize::new(0),
        })
    }

    fn signed(family: SigFamily, temporary: bool) -> Arc<Self> {
        Arc::new(Self {
            deny: false,
            principal: Some((family, temporary)),
            authorized: AtomicUsize::new(0),
            executed: AtomicUsize::new(0),
        })
    }
}

impl PostObjectHandler for Backend {
    type Authorization = usize;

    fn authorize(&self, request: &Req<PostObject>) -> BoxFuture<'_, Result<usize, HandlerError>> {
        let key = request.input().key.as_str().to_owned();
        let context = request.context();
        if let Some((family, temporary)) = self.principal {
            let principal = context.principal().expect("signed request");
            assert_eq!(principal.scheme().family(), family);
            assert_eq!(principal.scheme().location(), SigLocation::FormField);
            assert_eq!(principal.scheme().is_temporary(), temporary);
            if temporary {
                assert!(
                    principal
                        .verified_form_session_token()
                        .is_some_and(|token| token.ct_verify(FORM_TOKEN.as_bytes()).is_ok())
                );
            } else {
                assert!(principal.verified_form_session_token().is_none());
            }
            let constraints = context
                .post_object_key_constraints()
                .expect("authenticated form key constraints");
            assert!(constraints.permits("upload"));
            assert!(!constraints.permits("upload/other"));
            assert!(!constraints.permits("other"));
            assert!(!format!("{context:?}").contains(FORM_TOKEN));
            let copy = context.clone_without_caller_secret();
            assert!(copy.principal().expect("signed copy").verified_form_session_token().is_none());
            assert_eq!(copy.post_object_success_check(), context.post_object_success_check());
            assert!(
                !copy
                    .post_object_key_constraints()
                    .expect("copied key constraints")
                    .permits("other")
            );
            let cleared = copy.with_post_object_key_constraints(None);
            assert!(
                cleared.post_object_key_constraints().is_none(),
                "an absent replacement must clear old constraints"
            );
        } else {
            assert!(context.principal().is_none());
            assert!(
                context.post_object_key_constraints().is_none(),
                "anonymous forms have no signed constraints"
            );
        }
        Box::pin(async move {
            tokio::task::yield_now().await;
            assert_eq!(key, "upload");
            self.authorized.fetch_add(1, Relaxed);
            if self.deny {
                return Err(HandlerError::new(ErrorCode::ACCESS_DENIED, "the host denied this upload"));
            }
            Ok(42)
        })
    }

    fn execute(&self, authorization: usize, request: Req<PostObject>) -> BoxFuture<'_, HandlerResult<PostObject>> {
        use http_body_util::BodyExt as _;
        Box::pin(async move {
            assert_eq!(authorization, 42);
            self.executed.fetch_add(1, Relaxed);
            let file = request.into_input().body.into_body().collect().await.expect("file body");
            assert_eq!(file.to_bytes(), Bytes::from_static(b"file"));
            Ok(Resp::new(PostObjectOutput {
                e_tag: None,
                version_id: None,
            }))
        })
    }
}

impl Handler<PostObject> for Backend {
    async fn call(&self, request: Req<PostObject>) -> HandlerResult<PostObject> {
        let authorization = self.authorize(&request).await?;
        self.execute(authorization, request).await
    }
}

struct FormBody {
    prelude: Option<Bytes>,
    file: Option<Bytes>,
    file_polls: Arc<AtomicUsize>,
}

impl Body for FormBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let bytes = self.prelude.take().or_else(|| {
            self.file_polls.fetch_add(1, Relaxed);
            self.file.take()
        });
        std::task::Poll::Ready(bytes.map(|bytes| Ok(Frame::data(bytes))))
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact((self.prelude.as_ref().map_or(0, Bytes::len) + self.file.as_ref().map_or(0, Bytes::len)) as u64)
    }
}

fn form(fields: &[(&str, &str)], file_polls: Arc<AtomicUsize>) -> Request<FormBody> {
    let mut prelude = "--post\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nupload\r\n".to_owned();
    for (name, value) in fields {
        prelude.push_str(&format!("--post\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"));
    }
    prelude.push_str("--post\r\nContent-Disposition: form-data; name=\"file\"; filename=\"upload\"\r\n\r\n");
    let body = FormBody {
        prelude: Some(Bytes::from(prelude)),
        file: Some(Bytes::from_static(b"file\r\n--post--\r\n")),
        file_polls,
    };
    Request::builder()
        .method("POST")
        .uri("http://host.invalid/example-bucket")
        .header("content-type", "multipart/form-data; boundary=post")
        .header("content-length", body.size_hint().exact().expect("exact size"))
        .body(body)
        .expect("valid POST")
}

async fn staged(
    deny: bool,
    fields: &[(&str, &str)],
    expected_status: StatusCode,
    expected_error: Option<(&str, &str)>,
    expected_execution: usize,
) {
    let backend = Backend::new(deny);
    let service = builder()
        .legacy_rustfs_post_forms()
        .register_post_object_after_authorization(Arc::clone(&backend))
        .build()
        .expect("complete service");
    let file_polls = Arc::new(AtomicUsize::new(0));
    let reply = rustfs_gateway::collect(service.call(form(fields, Arc::clone(&file_polls))).await)
        .await
        .expect("response");
    let xml = std::str::from_utf8(reply.body()).expect("UTF-8 response");
    assert_eq!(backend.executed.load(Relaxed), expected_execution, "execution count");
    assert_eq!(reply.status(), expected_status, "{xml}");
    if let Some((code, message)) = expected_error {
        assert!(xml.contains(&format!("<Code>{code}</Code>")), "{xml}");
        assert!(xml.contains(&format!("<Message>{message}</Message>")), "{xml}");
    }
    assert_eq!(backend.authorized.load(Relaxed), 1);
    assert_eq!(file_polls.load(Relaxed) > 0, expected_execution > 0);
}

#[tokio::test]
async fn host_denial_wins_over_invalid_success_controls() {
    for field in [("success_action_status", "202"), ("success_action_redirect", "/relative")] {
        staged(
            true,
            &[field],
            StatusCode::FORBIDDEN,
            Some(("AccessDenied", "the host denied this upload")),
            0,
        )
        .await;
    }
}

#[tokio::test]
async fn unsupported_status_wins_over_a_relative_redirect_after_authorization() {
    staged(
        false,
        &[("success_action_status", "202"), ("success_action_redirect", "/relative")],
        StatusCode::BAD_REQUEST,
        Some(("MalformedPOSTRequest", "success_action_status must be one of 200, 201, or 204")),
        0,
    )
    .await;
}

#[tokio::test]
async fn an_authorized_relative_redirect_refuses_without_execution() {
    staged(
        false,
        &[("success_action_redirect", "/relative")],
        StatusCode::BAD_REQUEST,
        Some(("MalformedPOSTRequest", "success_action_redirect must be a valid absolute URL")),
        0,
    )
    .await;
}

#[tokio::test]
async fn a_valid_status_and_the_post_storage_empty_redirect_execute_once() {
    staged(false, &[("success_action_status", "200")], StatusCode::OK, None, 1).await;
    staged(
        false,
        &[("success_action_redirect", "")],
        StatusCode::BAD_REQUEST,
        Some(("InvalidArgument", "Invalid redirect URL")),
        1,
    )
    .await;
}

fn short_circuit<O: rustfs_gateway::Operation>() -> impl rustfs_gateway::OpLayer<O> {
    op_layer(|_: Req<O>, _: Next<'_, O>| {
        Box::pin(std::future::ready(Err(HandlerError::internal_error("layer replaced the handler"))))
    })
}

fn assert_build_refused(result: Result<rustfs_gateway::S3Service, rustfs_gateway::AssemblyError>, reason: &str) {
    let Err(error) = result else {
        panic!("assembly should refuse {reason}");
    };
    assert_eq!(error.rule(), RuleRef::POST_OBJECT_AUTHORIZATION);
    assert!(error.to_string().contains(reason));
}

#[test]
fn the_staged_registration_requires_the_legacy_form_profile() {
    assert_build_refused(
        builder()
            .register_post_object_after_authorization(Backend::new(false))
            .build(),
        "legacy form profile",
    );
}

#[test]
fn a_short_circuiting_post_layer_is_refused() {
    let legacy = || builder().legacy_rustfs_post_forms();
    assert_build_refused(
        legacy()
            .register_post_object_after_authorization(Backend::new(false))
            .op_layer::<PostObject, _>(short_circuit())
            .build(),
        "PostObject operation layer",
    );
    assert!(
        legacy()
            .register::<PostObject, _>(Backend::new(false))
            .op_layer::<PostObject, _>(short_circuit())
            .build()
            .is_ok()
    );

    use rustfs_gateway::dto::{ListBuckets, ListBucketsOutput};
    struct Lists;
    impl Handler<ListBuckets> for Lists {
        async fn call(&self, _: Req<ListBuckets>) -> HandlerResult<ListBuckets> {
            Ok(Resp::new(ListBucketsOutput::default()))
        }
    }
    assert!(
        legacy()
            .register_post_object_after_authorization(Backend::new(false))
            .register::<ListBuckets, _>(Arc::new(Lists))
            .op_layer::<ListBuckets, _>(short_circuit())
            .build()
            .is_ok()
    );
}

#[test]
fn static_dispatch_cannot_bypass_the_post_adapter() {
    type Operations = OperationSetNode<PostObject, OperationSetEnd>;

    let legacy = || builder().legacy_rustfs_post_forms();
    let backend = Backend::new(false);
    let Err(error) = legacy()
        .register_post_object_after_authorization(Arc::clone(&backend))
        .build_monomorphic::<_, Operations>(Arc::clone(&backend))
    else {
        panic!("static dispatch must refuse the staged registration");
    };
    assert_eq!(error.rule(), RuleRef::POST_OBJECT_AUTHORIZATION);
    assert!(error.to_string().contains("dynamic dispatch"));
    assert!(
        legacy()
            .register::<PostObject, _>(Arc::clone(&backend))
            .build_monomorphic::<_, Operations>(backend)
            .is_ok()
    );
}

#[test]
fn staged_and_ordinary_registrations_cannot_replace_one_another() {
    let backend = Backend::new(false);
    let legacy = || builder().legacy_rustfs_post_forms();
    for builder in [
        legacy()
            .register_post_object_after_authorization(Arc::clone(&backend))
            .register::<PostObject, _>(Arc::clone(&backend)),
        legacy()
            .register::<PostObject, _>(Arc::clone(&backend))
            .register_post_object_after_authorization(Arc::clone(&backend)),
        legacy()
            .register_post_object_after_authorization(Arc::clone(&backend))
            .register_post_object_after_authorization(Arc::clone(&backend)),
    ] {
        let Err(error) = builder.build() else {
            panic!("PostObject registered twice");
        };
        assert_eq!(error.rule(), RuleRef::REGISTRATION);
    }
}

const FORM_TOKEN: &str = "fixture-form-token";

// Independent HMAC fixture over {"expiration":"2026-01-02T04:04:05Z","conditions":[{"bucket":"example-bucket"},{"key":"upload"},{"x-amz-algorithm":"AWS4-HMAC-SHA256"},{"x-amz-credential":"AKIDEXAMPLE/20260102/us-east-1/s3/aws4_request"},{"x-amz-date":"20260102T030405Z"}]}
const V4_LONG_TERM: (&str, &str) = (
    "eyJleHBpcmF0aW9uIjoiMjAyNi0wMS0wMlQwNDowNDowNVoiLCJjb25kaXRpb25zIjpbeyJidWNrZXQiOiJleGFtcGxlLWJ1Y2tldCJ9LHsia2V5IjoidXBsb2FkIn0seyJ4LWFtei1hbGdvcml0aG0iOiJBV1M0LUhNQUMtU0hBMjU2In0seyJ4LWFtei1jcmVkZW50aWFsIjoiQUtJREVYQU1QTEUvMjAyNjAxMDIvdXMtZWFzdC0xL3MzL2F3czRfcmVxdWVzdCJ9LHsieC1hbXotZGF0ZSI6IjIwMjYwMTAyVDAzMDQwNVoifV19",
    "22a54927bd0827dc861d68d29a50b8f4572b253db8a04ad6df7b98ec6c39d5bd",
);
// Independent HMAC fixture over {"expiration":"2026-01-02T04:04:05Z","conditions":[{"bucket":"example-bucket"},{"key":"upload"},{"x-amz-algorithm":"AWS4-HMAC-SHA256"},{"x-amz-credential":"AKIDEXAMPLE/20260102/us-east-1/s3/aws4_request"},{"x-amz-date":"20260102T030405Z"},["starts-with","$x-amz-security-token",""]]}
const V4_TEMP: (&str, &str) = (
    "eyJleHBpcmF0aW9uIjoiMjAyNi0wMS0wMlQwNDowNDowNVoiLCJjb25kaXRpb25zIjpbeyJidWNrZXQiOiJleGFtcGxlLWJ1Y2tldCJ9LHsia2V5IjoidXBsb2FkIn0seyJ4LWFtei1hbGdvcml0aG0iOiJBV1M0LUhNQUMtU0hBMjU2In0seyJ4LWFtei1jcmVkZW50aWFsIjoiQUtJREVYQU1QTEUvMjAyNjAxMDIvdXMtZWFzdC0xL3MzL2F3czRfcmVxdWVzdCJ9LHsieC1hbXotZGF0ZSI6IjIwMjYwMTAyVDAzMDQwNVoifSxbInN0YXJ0cy13aXRoIiwiJHgtYW16LXNlY3VyaXR5LXRva2VuIiwiIl1dfQ==",
    "bad4a2db09a331ca17fa07dbf5a25a68bdf6018fa7977def1ef030ace03b8c67",
);
// Independent HMAC fixture over {"expiration":"2026-01-02T04:04:05Z","conditions":[{"bucket":"example-bucket"},{"key":"upload"}]}
const V2_LONG_TERM: (&str, &str) = (
    "eyJleHBpcmF0aW9uIjoiMjAyNi0wMS0wMlQwNDowNDowNVoiLCJjb25kaXRpb25zIjpbeyJidWNrZXQiOiJleGFtcGxlLWJ1Y2tldCJ9LHsia2V5IjoidXBsb2FkIn1dfQ==",
    "J5KdgpBmUCwgNP9BkOpSegH74eQ=",
);
// Independent HMAC fixture over {"expiration":"2026-01-02T04:04:05Z","conditions":[{"bucket":"example-bucket"},{"key":"upload"},["starts-with","$x-amz-security-token",""]]}
const V2_TEMP: (&str, &str) = (
    "eyJleHBpcmF0aW9uIjoiMjAyNi0wMS0wMlQwNDowNDowNVoiLCJjb25kaXRpb25zIjpbeyJidWNrZXQiOiJleGFtcGxlLWJ1Y2tldCJ9LHsia2V5IjoidXBsb2FkIn0sWyJzdGFydHMtd2l0aCIsIiR4LWFtei1zZWN1cml0eS10b2tlbiIsIiJdXX0=",
    "Tt2f+UpLx0G/Poh2vnzJgq5nB38=",
);

async fn signed_form(
    family: SigFamily,
    temporary: bool,
    form_token: Option<&str>,
    wire_token: Option<&str>,
    query: bool,
) -> (StatusCode, usize, usize) {
    let backend = Backend::signed(family, temporary);
    let credentials = Credentials::new("AKIDEXAMPLE", b"secret").expect("credentials");
    let credentials = if temporary {
        credentials
            .with_session(
                FORM_TOKEN,
                SessionBinding::new("sts.example.com", support::SIGNED_AT_UNIX_SECONDS + 3600).expect("session binding"),
            )
            .expect("temporary credentials")
    } else {
        credentials
    };
    let service = support::wired_at_signed_time()
        .authenticator(SigV4Authenticator::new(
            Arc::new(StaticCredentials::new().with(credentials)),
            RegionSet::new(["us-east-1"]).expect("regions"),
        ))
        .security_floor(
            SecurityFloor::new()
                .enable_sigv2_presigned_compatibility()
                .recognize_signatures_as_legacy_rustfs(),
        )
        .authorizer(allow_when(|_| true))
        .legacy_rustfs_post_forms()
        .register_post_object_after_authorization(Arc::clone(&backend))
        .build()
        .expect("signed form service");
    let (policy, signature) = match (family, temporary) {
        (SigFamily::V4, true) => V4_TEMP,
        (SigFamily::V4, false) => V4_LONG_TERM,
        (SigFamily::V2, true) => V2_TEMP,
        (SigFamily::V2, false) => V2_LONG_TERM,
        _ => panic!("unsupported fixture family"),
    };
    let mut fields = vec![("policy", policy)];
    if family == SigFamily::V4 {
        fields.extend([
            ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
            ("x-amz-credential", "AKIDEXAMPLE/20260102/us-east-1/s3/aws4_request"),
            ("x-amz-date", support::SIGNED_AT_STAMP),
            ("x-amz-signature", signature),
        ]);
    } else {
        fields.extend([("AWSAccessKeyId", "AKIDEXAMPLE"), ("signature", signature)]);
    }
    if let Some(token) = form_token {
        fields.push(("x-amz-security-token", token));
    }
    let mut request = form(&fields, Arc::new(AtomicUsize::new(0)));
    if let Some(token) = wire_token {
        if query {
            *request.uri_mut() = format!("http://host.invalid/example-bucket?X-Amz-Security-Token={token}")
                .parse()
                .expect("fixture URI");
        } else {
            request
                .headers_mut()
                .insert("x-amz-security-token", token.parse().expect("fixture header"));
        }
    }
    let response = rustfs_gateway::collect(service.call(request).await)
        .await
        .expect("form response");
    (response.status(), backend.authorized.load(Relaxed), backend.executed.load(Relaxed))
}

#[tokio::test]
async fn a_verified_form_token_is_projected_without_substituting_the_wire_token() {
    for family in [SigFamily::V4, SigFamily::V2] {
        for (wire, query) in [
            (None, false),
            (Some("conflicting-wire-token"), false),
            (Some("conflicting-wire-token"), true),
        ] {
            assert_eq!(
                signed_form(family, true, Some(FORM_TOKEN), wire, query).await,
                (StatusCode::NO_CONTENT, 1, 1),
                "{family:?}, conflict: {}, query: {query}",
                wire.is_some()
            );
        }
    }
}

#[tokio::test]
async fn a_wire_token_cannot_rescue_a_missing_or_wrong_form_token() {
    for family in [SigFamily::V4, SigFamily::V2] {
        for query in [false, true] {
            for token in [None, Some("wrong-form-token")] {
                let outcome = signed_form(family, true, token, Some(FORM_TOKEN), query).await;
                assert_eq!(outcome, (StatusCode::FORBIDDEN, 0, 0), "{family:?}, query: {query}");
            }
        }
    }
}

#[tokio::test]
async fn a_long_term_form_principal_has_no_session_token() {
    for family in [SigFamily::V4, SigFamily::V2] {
        assert_eq!(signed_form(family, false, None, None, false).await, (StatusCode::NO_CONTENT, 1, 1));
    }
}

#[tokio::test]
async fn replacing_a_staged_registration_with_an_ordinary_one_restores_eager_validation() {
    let backend = Backend::new(true);
    let service = builder()
        .legacy_rustfs_post_forms()
        .register_post_object_after_authorization(Arc::clone(&backend))
        .build()
        .expect("initial assembly");
    service
        .replace_assembly(
            rustfs_gateway::AssemblyUpdate::new()
                .register::<PostObject, _>(Arc::clone(&backend))
                .authorizer(allow_when(|_| true)),
        )
        .expect("replacement assembly");
    let body_polls = Arc::new(AtomicUsize::new(0));
    let response = service
        .call(form(&[("success_action_status", "202")], Arc::clone(&body_polls)))
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(backend.authorized.load(Relaxed), 0);
    assert_eq!(body_polls.load(Relaxed), 0);
}
