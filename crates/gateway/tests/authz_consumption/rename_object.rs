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

//! End-to-end `RenameObject` security through an assembled `S3Service`.
//!
//! Responsible for: proving `x-amz-rename-source` validation, two-stage source authorization,
//! sealing of the raw source field, `SigService::S3Express` / `HostClass::S3Express` enforcement,
//! tolerant conditional date parsing, and strict conditional ETag validation through the full
//! service pipeline.
//! NOT responsible for: low-level naming unit matrices (`crates/core/src/ops/rename_object.rs`)
//! or trybuild compile-fail checks (`crates/core/tests/compile_fail/authz_rename_*.rs`).
//! Upstream: `rustfs-gateway` and `support`. Downstream: nothing.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway::sig::{AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, ClockSkewAck, Decision, ETag, Handler, HandlerResult, InputAuthzRequest, InputDecisions,
    NameRejection, NameValidator, RENAME_SOURCE_ACTION, Req, RequestContext, Resp, S3Service, Stricter, dto,
};

use super::rename_host::{EXPRESS_HOST, ExpressAwareHosts, STANDARD_HOST};
use crate::support::{SIGNED_AT_STAMP, exchange, fixed_clock, wired};

#[derive(Clone, Copy)]
enum RenameAuthPolicy {
    AllowAll,
    DenyRoute,
    DenySource,
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
struct AuthTrace {
    route_calls: usize,
    input_calls: usize,
    derived: Vec<(String, Option<String>, Option<String>)>,
}

struct RenameAuthorizer {
    policy: RenameAuthPolicy,
    trace: Arc<Mutex<AuthTrace>>,
}

impl Authorizer for RenameAuthorizer {
    fn authorize_route<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        _request: &'a AuthzRequest<'a>,
    ) -> BoxFuture<'a, Decision> {
        self.trace.lock().expect("trace lock").route_calls += 1;
        let decision = match self.policy {
            RenameAuthPolicy::DenyRoute => Decision::Deny,
            RenameAuthPolicy::AllowAll | RenameAuthPolicy::DenySource => Decision::Allow,
        };
        Box::pin(async move { decision })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let mut guard = self.trace.lock().expect("trace lock");
        guard.input_calls += 1;
        let decisions = request.decide_all(Decision::Allow, |resource| {
            guard.derived.push((
                resource.action.to_owned(),
                resource.bucket.map(|bucket| bucket.as_str().to_owned()),
                resource.key.map(|key| key.as_str().to_owned()),
            ));
            match self.policy {
                RenameAuthPolicy::DenySource => Decision::Deny,
                RenameAuthPolicy::AllowAll | RenameAuthPolicy::DenyRoute => Decision::Allow,
            }
        });
        drop(guard);
        Box::pin(async move { decisions })
    }
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
struct ObservedRename {
    raw_erased: bool,
    source_bucket: String,
    source_key: String,
    destination_if_match: Option<ETag>,
    destination_if_none_match: Option<ETag>,
    source_if_match: Option<ETag>,
    source_if_none_match: Option<ETag>,
    any_date_present: bool,
}

struct RenameBackend {
    calls: Arc<AtomicUsize>,
    observed: Arc<Mutex<Option<ObservedRename>>>,
}

impl Handler<dto::RenameObject> for RenameBackend {
    async fn call(&self, request: Req<dto::RenameObject>) -> HandlerResult<dto::RenameObject> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let input = request.input();
        let resolved = request
            .resources()
            .source()
            .resolve(request.read_proof())
            .expect("the request proof authorizes this rename source");
        let any_date_present = input.destination_if_modified_since.is_some()
            || input.destination_if_unmodified_since.is_some()
            || input.source_if_modified_since.is_some()
            || input.source_if_unmodified_since.is_some();
        *self.observed.lock().expect("observed lock") = Some(ObservedRename {
            raw_erased: input.rename_source.is_empty(),
            source_bucket: resolved.bucket().as_str().to_owned(),
            source_key: resolved.key().as_str().to_owned(),
            destination_if_match: input.destination_if_match.clone(),
            destination_if_none_match: input.destination_if_none_match.clone(),
            source_if_match: input.source_if_match.clone(),
            source_if_none_match: input.source_if_none_match.clone(),
            any_date_present,
        });
        Ok(Resp::new(dto::RenameObjectOutput::default()))
    }
}

struct CountingPut(Arc<AtomicUsize>);

impl Handler<dto::PutObject> for CountingPut {
    async fn call(&self, _request: Req<dto::PutObject>) -> HandlerResult<dto::PutObject> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(dto::PutObjectOutput::default()))
    }
}

struct CountingCopy(Arc<AtomicUsize>);

impl Handler<dto::CopyObject> for CountingCopy {
    async fn call(&self, _request: Req<dto::CopyObject>) -> HandlerResult<dto::CopyObject> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(dto::CopyObjectOutput::default()))
    }
}

struct ForbidPrefix(&'static str);

impl NameValidator for ForbidPrefix {
    fn check_bucket(&self, _name: &str) -> Stricter {
        Stricter::NoOpinion
    }

    fn check_key(&self, key: &str) -> Stricter {
        if key.starts_with(self.0) {
            Stricter::Reject(NameRejection::rejected_by_validator("prefix refused by deployment"))
        } else {
            Stricter::NoOpinion
        }
    }
}

struct Harness {
    service: S3Service,
    trace: Arc<Mutex<AuthTrace>>,
    rename_calls: Arc<AtomicUsize>,
    put_calls: Arc<AtomicUsize>,
    copy_calls: Arc<AtomicUsize>,
    observed: Arc<Mutex<Option<ObservedRename>>>,
}

fn assemble(policy: RenameAuthPolicy, validator: Option<ForbidPrefix>) -> Harness {
    let trace = Arc::new(Mutex::new(AuthTrace::default()));
    let rename_calls = Arc::new(AtomicUsize::new(0));
    let put_calls = Arc::new(AtomicUsize::new(0));
    let copy_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(None));

    let mut builder = wired()
        .host_resolver(ExpressAwareHosts)
        .authorizer(RenameAuthorizer {
            policy,
            trace: Arc::clone(&trace),
        })
        .clock_with_skew_ack(fixed_clock(), ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry())
        .register::<dto::RenameObject, _>(Arc::new(RenameBackend {
            calls: Arc::clone(&rename_calls),
            observed: Arc::clone(&observed),
        }))
        .register::<dto::PutObject, _>(Arc::new(CountingPut(Arc::clone(&put_calls))))
        .register::<dto::CopyObject, _>(Arc::new(CountingCopy(Arc::clone(&copy_calls))));
    if let Some(validator) = validator {
        builder = builder.name_validator(validator);
    }
    let service = builder.build().expect("complete rename assembly");
    Harness {
        service,
        trace,
        rename_calls,
        put_calls,
        copy_calls,
        observed,
    }
}

fn signed_rename(host: &str, service: SigService, target: &str, extra: &[(&str, &str)]) -> http::Request<Bytes> {
    let (path, query) = target.split_once('?').map_or((target, ""), |(path, query)| (path, query));
    let mut map = http::HeaderMap::new();
    map.insert(http::header::HOST, http::HeaderValue::from_str(host).expect("host header"));
    for (name, value) in extra {
        let name: http::HeaderName = name.parse().expect("header name");
        map.insert(name, http::HeaderValue::from_str(value).expect("header value"));
    }

    let probe = http::Request::builder()
        .method(http::Method::GET)
        .uri("/")
        .header(http::header::HOST, host)
        .body(Bytes::new())
        .expect("probe");
    let accepted = rustfs_gateway::WireRequest::accept(probe, &rustfs_gateway::Limits::default()).expect("accepted host");
    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials");
    let stamp = AmzDate::parse(SIGNED_AT_STAMP).expect("valid stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", service).expect("valid scope");
    let mut signer = SigV4Signer::new(credentials, scope);
    let signing = SigningRequest::new(
        &http::Method::PUT,
        path,
        query,
        &map,
        accepted.host().raw_for_signing(),
        PayloadMode::Empty,
        stamp,
    )
    .with_wire_content_length(0);
    let signed = signer.sign_headers(&signing).expect("signable request");

    let mut builder = http::Request::builder().method(http::Method::PUT).uri(target);
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    builder.body(Bytes::new()).expect("valid request")
}

/// Negative — denying the derived source object stops RenameObject before handler dispatch.
#[tokio::test]
async fn n_rename_source_denial_never_reaches_handler() {
    let h = assemble(RenameAuthPolicy::DenySource, None);
    let request = signed_rename(
        EXPRESS_HOST,
        SigService::S3Express,
        "/bucket/dst/new.txt?renameObject",
        &[("x-amz-rename-source", "dir/secret%20file.txt")],
    );
    let (status, body) = exchange(&h.service, request).await;

    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");
    assert_eq!(h.rename_calls.load(Ordering::SeqCst), 0);
    let trace = h.trace.lock().expect("trace lock");
    assert_eq!(trace.route_calls, 1);
    assert_eq!(trace.input_calls, 1);
    assert_eq!(
        trace.derived,
        vec![(
            RENAME_SOURCE_ACTION.to_owned(),
            Some("bucket".to_owned()),
            Some("dir/secret file.txt".to_owned()),
        )]
    );
}

/// Negative — route denial stops RenameObject before input authorization or handler dispatch.
#[tokio::test]
async fn n_rename_route_denial_never_reaches_input_authz_or_handler() {
    let h = assemble(RenameAuthPolicy::DenyRoute, None);
    let request = signed_rename(
        EXPRESS_HOST,
        SigService::S3Express,
        "/bucket/dst/new.txt?renameObject",
        &[("x-amz-rename-source", "dir/old.txt")],
    );
    let (status, body) = exchange(&h.service, request).await;

    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");
    assert_eq!(h.rename_calls.load(Ordering::SeqCst), 0);
    let trace = h.trace.lock().expect("trace lock");
    assert_eq!(trace.route_calls, 1);
    assert_eq!(trace.input_calls, 0);
}

/// Negative — unsafe `x-amz-rename-source` keys fail before input authorization and handler dispatch.
#[tokio::test]
async fn n_unsafe_rename_source_keys_refused_before_input_authz() {
    let over = "a".repeat(1025);
    for (source, expected_code) in [
        ("", "InvalidArgument"),
        ("..", "InvalidArgument"),
        ("../secret", "InvalidArgument"),
        ("a\\..\\secret", "InvalidArgument"),
        ("%2e%2e/secret", "InvalidArgument"),
        ("%252e%252e/secret", "InvalidArgument"),
        ("a%252Fb", "InvalidArgument"),
        ("a%255cb", "InvalidArgument"),
        ("a%00b", "InvalidArgument"),
        ("a%01b", "InvalidArgument"),
        ("a%7Fb", "InvalidArgument"),
        ("%FF%FE", "InvalidArgument"),
        ("//server/share", "InvalidArgument"),
        ("C:/Windows/win.ini", "InvalidArgument"),
        (over.as_str(), "KeyTooLongError"),
    ] {
        let h = assemble(RenameAuthPolicy::AllowAll, None);
        let request = signed_rename(
            EXPRESS_HOST,
            SigService::S3Express,
            "/bucket/dst/new.txt?renameObject",
            &[("x-amz-rename-source", source)],
        );
        let (status, body) = exchange(&h.service, request).await;

        assert_eq!(status, http::StatusCode::BAD_REQUEST, "source={source:?}: {body}");
        assert!(body.contains(&format!("<Code>{expected_code}</Code>")), "source={source:?}: {body}");
        assert_eq!(h.rename_calls.load(Ordering::SeqCst), 0, "source={source:?}");
        assert_eq!(h.trace.lock().expect("trace lock").input_calls, 0, "source={source:?}");
    }
}

/// Negative — a deployment `NameValidator` refusal rejects `x-amz-rename-source` before input authz.
#[tokio::test]
async fn n_custom_name_validator_refuses_rename_source_before_input_authz() {
    let h = assemble(RenameAuthPolicy::AllowAll, Some(ForbidPrefix("restricted/")));
    let request = signed_rename(
        EXPRESS_HOST,
        SigService::S3Express,
        "/bucket/dst/new.txt?renameObject",
        &[("x-amz-rename-source", "restricted/secret.txt")],
    );
    let (status, body) = exchange(&h.service, request).await;

    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("<Code>InvalidArgument</Code>"), "{body}");
    assert_eq!(h.rename_calls.load(Ordering::SeqCst), 0);
    assert_eq!(h.trace.lock().expect("trace lock").input_calls, 0);
}

/// Negative — malformed or comma-joined list ETags on any RenameObject conditional header are refused.
#[tokio::test]
async fn n_malformed_or_list_conditional_etags_refused_before_handler() {
    for header in [
        "if-match",
        "if-none-match",
        "x-amz-rename-source-if-match",
        "x-amz-rename-source-if-none-match",
    ] {
        for bad in ["\"unterminated", "a, b", "\"a\", \"b\"", "*, *"] {
            let h = assemble(RenameAuthPolicy::AllowAll, None);
            let request = signed_rename(
                EXPRESS_HOST,
                SigService::S3Express,
                "/bucket/dst/new.txt?renameObject",
                &[("x-amz-rename-source", "dir/old.txt"), (header, bad)],
            );
            let (status, body) = exchange(&h.service, request).await;

            assert_eq!(status, http::StatusCode::BAD_REQUEST, "{header}={bad:?}: {body}");
            assert!(body.contains("<Code>InvalidArgument</Code>"), "{header}={bad:?}: {body}");
            assert_eq!(h.rename_calls.load(Ordering::SeqCst), 0, "{header}={bad:?}");
            assert_eq!(h.trace.lock().expect("trace lock").input_calls, 0, "{header}={bad:?}");
        }
    }
}

/// Negative — a RenameObject request signed for `s3` instead of `s3express` is refused.
#[tokio::test]
async fn n_rename_signed_for_s3_instead_of_s3express_is_refused() {
    let h = assemble(RenameAuthPolicy::AllowAll, None);
    let request = signed_rename(
        EXPRESS_HOST,
        SigService::S3,
        "/bucket/dst/new.txt?renameObject",
        &[("x-amz-rename-source", "dir/old.txt")],
    );
    let (status, body) = exchange(&h.service, request).await;

    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("<Code>AuthorizationHeaderMalformed</Code>"), "{body}");
    assert_eq!(h.rename_calls.load(Ordering::SeqCst), 0);
}

/// Negative — `PUT /{Bucket}/{Key+}?renameObject` arriving on `HostClass::Standard` never falls
/// through to `PutObject` or `CopyObject`.
#[tokio::test]
async fn n_rename_on_standard_host_never_falls_through_to_put_or_copy() {
    for extra in [
        &[("x-amz-rename-source", "dir/old.txt")][..],
        &[("x-amz-rename-source", "dir/old.txt"), ("x-amz-copy-source", "/other/src")][..],
    ] {
        let h = assemble(RenameAuthPolicy::AllowAll, None);
        let request = signed_rename(STANDARD_HOST, SigService::S3, "/bucket/dst/new.txt?renameObject", extra);
        let (status, body) = exchange(&h.service, request).await;

        assert!(
            status.is_client_error() || status == http::StatusCode::NOT_IMPLEMENTED,
            "standard-host rename must be refused: status={status}, body={body}"
        );
        assert_eq!(h.put_calls.load(Ordering::SeqCst), 0, "must never overwrite via PutObject");
        assert_eq!(h.copy_calls.load(Ordering::SeqCst), 0, "must never fall through to CopyObject");
        assert_eq!(h.rename_calls.load(Ordering::SeqCst), 0, "must not run RenameObject on Standard");
    }
}

/// Negative — missing `x-amz-rename-source` on `HostClass::S3Express` fails as RenameObject, never PutObject.
#[tokio::test]
async fn n_missing_rename_source_header_is_refused_as_rename_object() {
    let h = assemble(RenameAuthPolicy::AllowAll, None);
    let request = signed_rename(EXPRESS_HOST, SigService::S3Express, "/bucket/dst/new.txt?renameObject", &[]);
    let (status, body) = exchange(&h.service, request).await;

    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("<Code>InvalidArgument</Code>"), "{body}");
    assert_eq!(h.put_calls.load(Ordering::SeqCst), 0);
    assert_eq!(h.rename_calls.load(Ordering::SeqCst), 0);
}

/// Positive — authorized S3Express RenameObject normalizes once, seals raw input, tolerates
/// unreadable date conditions, binds valid conditional ETags, and resolves the source with proof.
#[tokio::test]
async fn rename_object_authorizes_normalized_source_seals_raw_header_and_binds_conditionals() {
    let h = assemble(RenameAuthPolicy::AllowAll, None);
    let request = signed_rename(
        EXPRESS_HOST,
        SigService::S3Express,
        "/bucket/dst/new.txt?renameObject",
        &[
            ("x-amz-rename-source", "dir/old%20file.txt"),
            ("if-match", "\"dst-etag\""),
            ("if-none-match", "*"),
            ("x-amz-rename-source-if-match", "W/\"src-etag\""),
            ("x-amz-rename-source-if-none-match", "bare-src"),
            ("if-modified-since", "not-a-date"),
            ("if-unmodified-since", "not-a-date"),
            ("x-amz-rename-source-if-modified-since", "not-a-date"),
            ("x-amz-rename-source-if-unmodified-since", "not-a-date"),
        ],
    );
    let (status, body) = exchange(&h.service, request).await;

    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(h.rename_calls.load(Ordering::SeqCst), 1);
    let trace = h.trace.lock().expect("trace lock");
    assert_eq!(trace.route_calls, 1);
    assert_eq!(trace.input_calls, 1);
    assert_eq!(
        trace.derived,
        vec![(
            RENAME_SOURCE_ACTION.to_owned(),
            Some("bucket".to_owned()),
            Some("dir/old file.txt".to_owned()),
        )]
    );
    let observed = h.observed.lock().expect("observed lock").clone().expect("handler observed");
    assert_eq!(
        observed,
        ObservedRename {
            raw_erased: true,
            source_bucket: "bucket".to_owned(),
            source_key: "dir/old file.txt".to_owned(),
            destination_if_match: Some(ETag::new("dst-etag").expect("etag")),
            destination_if_none_match: Some(ETag::ANY),
            source_if_match: Some(ETag::new_weak("src-etag").expect("weak etag")),
            source_if_none_match: Some(ETag::new("bare-src").expect("bare etag")),
            any_date_present: false,
        }
    );
}
