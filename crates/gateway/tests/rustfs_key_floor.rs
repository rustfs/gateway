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

//! The legacy RustFS key floor through the facade (rustfs/gateway#1107): which keys reach the
//! handler under `accept_legacy_rustfs_object_keys_after_listing_in_the_posture_report`, as what
//! bytes, and which are still refused before anything is authorized.
//!
//! Responsible for: every key shape legacy RustFS's protocol front hands its storage reaching
//! `GetObject`, `PutObject`, `HeadObject`, `DeleteObject`, the `CopyObject` destination,
//! `PutObjectTagging`, `CreateMultipartUpload` and a `DeleteObjects` body as the same bytes, shown
//! to the authorizer as the same value; the default assembly still refusing each of them before the
//! authorizer runs; and NUL and an overlong key still refused under the RustFS floor.
//! NOT responsible for: the rule itself (`rustfs-gateway-types`' `rustfs_key_floor_tests`), the
//! stored bytes on a real backend (`compat/sut`), or the equality with what legacy RustFS hands
//! its storage (the difftest RustFS-profile rows).
//! Upstream: `rustfs-gateway`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway::dto::{
    CopyObject, CreateMultipartUpload, DeleteObject, DeleteObjects, GetObject, HeadObject, PostObject, PutObject,
    PutObjectTagging,
};
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, Credentials, Decision, ErrorCode, HandlerError, HandlerResult, InputAuthzRequest,
    InputDecisions, RegionSet, Req, RequestContext, S3Service, SecurityFloor, ServiceBuilder, SigV4Authenticator, SlashPolicy,
    StaticCredentials,
};

use crate::support::exchange;

/// What the handlers were handed and the authorizer was shown, in arrival order.
#[derive(Default)]
struct Seen {
    handed: Mutex<Vec<String>>,
    shown: Mutex<Vec<String>>,
    sources: Mutex<Vec<String>>,
    derived: Mutex<Vec<String>>,
}

impl Seen {
    fn derived(&self) -> Vec<String> {
        std::mem::take(&mut *self.derived.lock().expect("not poisoned"))
    }

    fn sources(&self) -> Vec<String> {
        std::mem::take(&mut *self.sources.lock().expect("not poisoned"))
    }

    fn handed(&self) -> Vec<String> {
        std::mem::take(&mut *self.handed.lock().expect("not poisoned"))
    }

    fn shown(&self) -> Vec<String> {
        std::mem::take(&mut *self.shown.lock().expect("not poisoned"))
    }

    fn hand(&self, key: &str) {
        self.handed.lock().expect("not poisoned").push(key.to_owned());
    }
}

/// Allows everything, recording the key the route stage was asked about.
struct ShowAndAllow(Arc<Seen>);

impl Authorizer for ShowAndAllow {
    fn authorize_route<'a>(&'a self, _context: &'a RequestContext<'a>, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        if let Some(key) = request.key {
            self.0.shown.lock().expect("not poisoned").push(key.as_str().to_owned());
        }
        Box::pin(async { Decision::Allow })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        for resource in request.resources() {
            if let Some(key) = resource.key {
                self.0.derived.lock().expect("not poisoned").push(key.as_str().to_owned());
            }
        }
        let decisions = request.decide_all(Decision::Allow, |_| Decision::Allow);
        Box::pin(async move { decisions })
    }
}

/// Records every key it is handed and refuses, so no output is ever encoded.
struct KeyRecorder(Arc<Seen>);

fn recorded<T>() -> Result<T, HandlerError> {
    Err(HandlerError::new(ErrorCode::NOT_IMPLEMENTED, "recorded"))
}

#[rustfs_gateway::handlers]
impl KeyRecorder {
    async fn get_object(&self, request: Req<GetObject>) -> HandlerResult<GetObject> {
        self.0.hand(request.input().key.as_str());
        recorded()
    }

    async fn head_object(&self, request: Req<HeadObject>) -> HandlerResult<HeadObject> {
        self.0.hand(request.input().key.as_str());
        recorded()
    }

    async fn put_object(&self, request: Req<PutObject>) -> HandlerResult<PutObject> {
        self.0.hand(request.input().key.as_str());
        recorded()
    }

    async fn delete_object(&self, request: Req<DeleteObject>) -> HandlerResult<DeleteObject> {
        self.0.hand(request.input().key.as_str());
        recorded()
    }

    async fn copy_object(&self, request: Req<CopyObject>) -> HandlerResult<CopyObject> {
        self.0.hand(request.input().key.as_str());
        if let Some(source) = request.resources().source().resolve(request.read_proof()) {
            self.0
                .sources
                .lock()
                .expect("not poisoned")
                .push(source.key().as_str().to_owned());
        }
        recorded()
    }

    async fn put_object_tagging(&self, request: Req<PutObjectTagging>) -> HandlerResult<PutObjectTagging> {
        self.0.hand(request.input().key.as_str());
        recorded()
    }

    async fn create_multipart_upload(&self, request: Req<CreateMultipartUpload>) -> HandlerResult<CreateMultipartUpload> {
        self.0.hand(request.input().key.as_str());
        recorded()
    }

    async fn post_object(&self, request: Req<PostObject>) -> HandlerResult<PostObject> {
        self.0.hand(request.input().key.as_str());
        recorded()
    }

    async fn delete_objects(&self, request: Req<DeleteObjects>) -> HandlerResult<DeleteObjects> {
        let keys = request
            .resources()
            .resolve(request.read_proof())
            .expect("every key was authorized")
            .map(|(key, _)| key.as_str().to_owned())
            .collect::<Vec<_>>();
        for key in keys {
            self.0.hand(&key);
        }
        recorded()
    }
}

/// Which naming rules an assembly under test runs.
#[derive(Clone, Copy)]
enum Naming {
    Default,
    SlashRuleOnly,
    Rustfs,
}

fn assembled(naming: Naming) -> (S3Service, Arc<Seen>) {
    let seen = Arc::new(Seen::default());
    let credentials = Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid key")));
    let recorder = Arc::new(KeyRecorder(Arc::clone(&seen)));
    let builder = ServiceBuilder::new()
        .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("non-empty")))
        .security_floor(SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report())
        .authorizer(ShowAndAllow(Arc::clone(&seen)))
        .register::<GetObject, _>(Arc::clone(&recorder))
        .register::<HeadObject, _>(Arc::clone(&recorder))
        .register::<PutObject, _>(Arc::clone(&recorder))
        .register::<DeleteObject, _>(Arc::clone(&recorder))
        .register::<CopyObject, _>(Arc::clone(&recorder))
        .register::<PutObjectTagging, _>(Arc::clone(&recorder))
        .register::<CreateMultipartUpload, _>(Arc::clone(&recorder))
        .register::<PostObject, _>(Arc::clone(&recorder))
        .register::<DeleteObjects, _>(recorder);
    let builder = match naming {
        Naming::Default => builder,
        Naming::SlashRuleOnly => builder.slash_policy(SlashPolicy::RustfsLegacy),
        Naming::Rustfs => builder
            .slash_policy(SlashPolicy::RustfsLegacy)
            .accept_legacy_rustfs_object_keys_after_listing_in_the_posture_report(),
    };
    (builder.build().expect("a complete assembly"), seen)
}

fn request(method: &str, target: &str, headers: &[(&str, &str)], body: &'static [u8]) -> http::Request<Bytes> {
    let mut builder = http::Request::builder()
        .method(method)
        .uri(target)
        .header("host", "s3.example.com")
        .header("content-length", body.len().to_string());
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(Bytes::from_static(body)).expect("a valid request")
}

/// One operation that names its key in the path, as `(method, suffix, headers, body)`.
type Operation = (&'static str, &'static str, &'static [(&'static str, &'static str)], &'static [u8]);

/// Every operation that names its key in the path.
const OPERATIONS: [Operation; 7] = [
    ("GET", "", &[], b""),
    ("HEAD", "", &[], b""),
    ("PUT", "", &[], b"body"),
    ("DELETE", "", &[], b""),
    ("PUT", "", &[("x-amz-copy-source", "src-bucket/src-key")], b""),
    (
        "PUT",
        "?tagging",
        &[("content-md5", "k6PBbu32RmFaV5nRULDSlw==")],
        b"<Tagging><TagSet></TagSet></Tagging>",
    ),
    ("POST", "?uploads", &[], b""),
];

/// Keys legacy RustFS stored and served (`PUT` 200, `GET` 200 on a legacy build), as the label
/// after `/bucket/` and the key its storage holds.
const STORED_BY_LEGACY: [(&str, &str); 12] = [
    ("a%01b", "a\u{1}b"),
    ("a%09b", "a\tb"),
    ("a%7Fb", "a\u{7f}b"),
    ("a%C2%85b", "a\u{85}b"),
    ("a%252Fb", "a%2Fb"),
    ("a%255Cb", "a%5Cb"),
    ("a%252e%252e", "a%2e%2e"),
    ("%5Cx", "\\x"),
    ("%5C%5Cserver%5Cshare", "\\\\server\\share"),
    ("C:%5Cx", "C:\\x"),
    ("c:/x", "c:/x"),
    ("//x", "x"),
];

/// Keys legacy RustFS's front hands to its storage, which refuses them (`400 InvalidArgument`)
/// after authorization: the gateway must hand them over for RustFS to refuse, not refuse them
/// itself at another stage.
const REFUSED_BY_LEGACY_STORAGE: [(&str, &str); 6] = [
    ("a/../b", "a/../b"),
    ("a/./b", "a/./b"),
    ("a%5C..%5Cb", "a\\..\\b"),
    ("a%0Ab", "a\nb"),
    ("a%0Db", "a\rb"),
    ("a//b", "a//b"),
];

/// Positive — under the RustFS floor every key legacy RustFS stored reaches every operation's
/// handler as the bytes its storage holds, and the authorizer is shown that same value.
#[tokio::test]
async fn every_key_legacy_rustfs_stored_reaches_every_handler_as_the_same_bytes() {
    let (service, seen) = assembled(Naming::Rustfs);
    for (label, stored) in STORED_BY_LEGACY.into_iter().chain(REFUSED_BY_LEGACY_STORAGE) {
        for (method, suffix, headers, body) in OPERATIONS {
            let target = format!("/bucket/{label}{suffix}");
            let (status, answer) = exchange(&service, request(method, &target, headers, body)).await;
            assert_eq!(seen.handed(), vec![stored.to_owned()], "{method} {target}: {status} {answer}");
            assert_eq!(seen.shown(), vec![stored.to_owned()], "{method} {target}: the authorizer saw another key");
        }
    }
}

/// Positive — a multi-object delete body is held to the same rule: legacy RustFS answers each of
/// these with a per-key error and deletes the rest, so none of them may refuse the whole request.
#[tokio::test]
async fn a_multi_object_delete_hands_every_key_over() {
    let (service, seen) = assembled(Naming::Rustfs);
    let body: &'static [u8] = b"<Delete><Object><Key>a/../b</Key></Object><Object><Key>//x</Key></Object><Object><Key>/</Key></Object><Object><Key>C:\\x</Key></Object></Delete>";
    let (status, answer) = exchange(
        &service,
        request("POST", "/bucket?delete", &[("content-md5", "KGBFdfEOSK0IZxCZboKz8g==")], body),
    )
    .await;
    assert_eq!(seen.handed(), ["a/../b", "//x", "/", "C:\\x"], "{status} {answer}");
}

/// Negative — without the RustFS floor every one of those keys is refused before the authorizer is
/// asked about it, as it always was.
#[tokio::test]
async fn n_the_default_floor_still_refuses_them_before_authorization() {
    let (service, seen) = assembled(Naming::Default);
    for (label, _) in STORED_BY_LEGACY.into_iter().chain(REFUSED_BY_LEGACY_STORAGE) {
        if matches!(label, "//x" | "a//b" | "a/./b") {
            // Legal under the default floor too: an empty or a `.` segment is not a traversal, and
            // the slash rule's own cases cover the first two.
            continue;
        }
        let (status, body) = exchange(&service, request("GET", &format!("/bucket/{label}"), &[], b"")).await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST, "{label}: {body}");
        assert!(body.contains("<Code>InvalidArgument</Code>"), "{label}: {body}");
        assert!(seen.shown().is_empty() && seen.handed().is_empty(), "{label} was not refused first");
    }
}

/// Negative — the slash rule alone lowers nothing: the floor is its own, named switch.
#[tokio::test]
async fn n_the_slash_rule_alone_does_not_lower_the_floor() {
    let (service, seen) = assembled(Naming::SlashRuleOnly);
    for label in ["a%01b", "a%252Fb", "%5Cx", "a/../b"] {
        let (status, body) = exchange(&service, request("GET", &format!("/bucket/{label}"), &[], b"")).await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST, "{label}: {body}");
        assert!(seen.handed().is_empty(), "{label} reached the handler");
    }
}

/// Negative — the RustFS floor still refuses what an `ObjectKey` cannot hold, before the authorizer
/// is asked: a NUL (legacy RustFS refuses it too, with the same code, after authorization) and a
/// key over 1024 bytes once folded (`KeyTooLongError`, as legacy RustFS answers it).
#[tokio::test]
async fn n_a_nul_or_an_overlong_key_is_still_refused_before_authorization() {
    let (service, seen) = assembled(Naming::Rustfs);
    let (status, body) = exchange(&service, request("GET", "/bucket/a%00b", &[], b"")).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("<Code>InvalidArgument</Code>"), "{body}");
    let overlong = format!("/bucket/{}", "k".repeat(1025));
    let (status, body) = exchange(&service, request("GET", &overlong, &[], b"")).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("<Code>KeyTooLongError</Code>"), "{body}");
    assert!(seen.shown().is_empty() && seen.handed().is_empty());
}

/// Positive — a copy source's key is held to the floor the destination's key is held to, through
/// the pipeline: every key legacy RustFS stored can be copied from, as the bytes its storage holds.
#[tokio::test]
async fn a_copy_source_key_is_held_to_the_same_floor() {
    let (service, seen) = assembled(Naming::Rustfs);
    for (label, stored) in STORED_BY_LEGACY.into_iter().chain(REFUSED_BY_LEGACY_STORAGE) {
        if label.starts_with("//") {
            // A copy source's key is never folded; the slash rule's own cases cover it.
            continue;
        }
        let source = format!("src-bucket/{label}");
        let (status, answer) = exchange(&service, request("PUT", "/bucket/dst", &[("x-amz-copy-source", &source)], b"")).await;
        assert_eq!(seen.sources(), vec![stored.to_owned()], "{source}: {status} {answer}");
        assert_eq!(seen.derived(), vec![stored.to_owned()], "{source}: the input stage judged another key");
        seen.handed();
        seen.shown();
    }
}

/// Negative — without the RustFS floor the same copy sources are refused before the handler.
#[tokio::test]
async fn n_the_default_floor_still_refuses_those_copy_sources() {
    let (service, seen) = assembled(Naming::Default);
    for label in ["a%01b", "%5Cx", "C:%5Cx", "a/../b", "a%0Ab"] {
        let source = format!("src-bucket/{label}");
        let (status, body) = exchange(&service, request("PUT", "/bucket/dst", &[("x-amz-copy-source", &source)], b"")).await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST, "{source}: {body}");
        assert!(seen.sources().is_empty() && seen.handed().is_empty(), "{source} reached the handler");
        seen.shown();
    }
}

const BOUNDARY: &str = "----RustfsKeyFloor";

/// An anonymous browser form whose `key` field is `key` and whose file carries a few bytes.
fn form(key: &str) -> http::Request<Bytes> {
    let body = format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\n{key}\r\n\
         --{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f.txt\"\r\n\
         Content-Type: text/plain\r\n\r\nform bytes\r\n--{BOUNDARY}--\r\n"
    );
    http::Request::builder()
        .method("POST")
        .uri("/bucket")
        .header("host", "s3.example.com")
        .header("content-type", format!("multipart/form-data; boundary={BOUNDARY}"))
        .header("content-length", body.len().to_string())
        .body(Bytes::from(body))
        .expect("a valid form request")
}

/// Positive — a browser form's key is held to the same floor: a key legacy RustFS's front hands
/// its storage reaches the POST Object handler as the same bytes.
#[tokio::test]
async fn a_form_key_is_held_to_the_same_floor() {
    let (service, seen) = assembled(Naming::Rustfs);
    for key in ["uploads/../x", "a\\x", "C:\\x", "a%2Fb"] {
        let (status, answer) = exchange(&service, form(key)).await;
        assert_eq!(seen.handed(), vec![key.to_owned()], "{key}: {status} {answer}");
        seen.shown();
        seen.derived();
    }
}

/// Negative — under the default floor the same form keys never reach the handler.
#[tokio::test]
async fn n_the_default_floor_still_refuses_those_form_keys() {
    let (service, seen) = assembled(Naming::Default);
    for key in ["uploads/../x", "\\x", "C:\\x"] {
        let (status, answer) = exchange(&service, form(key)).await;
        assert!(status.is_client_error(), "{key}: {status} {answer}");
        assert!(seen.handed().is_empty(), "{key} reached the handler");
        seen.shown();
    }
}
