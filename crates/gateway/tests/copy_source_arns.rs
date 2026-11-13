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

//! ADR-0045's copy-source ARN capability, selected through the facade
//! (`ServiceBuilder::refuse_copy_source_arns_as_not_implemented`, rustfs/gateway#1609).
//!
//! Responsible for: an access-point and an Outposts ARN source answering `501 NotImplemented` on
//! `CopyObject` and `UploadPartCopy` before the input stage of a counting authorizer and before the
//! handler, under the setting; a plain `bucket/key` source, an ARN the codec cannot read and an
//! anonymous request answered as before under it; the unchanged default; and the posture naming it.
//! NOT responsible for: the classifier itself (`rustfs-gateway-core`'s `copy_source/capability.rs`
//! and `tests/copy_source_input.rs`), or what a backend does with an ARN it is handed
//! (`rustfs-gateway-fs`'s `tests/crud/copy_source_arns.rs`).
//! Upstream: `rustfs-gateway`, `support`. Downstream: nothing.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, Decision, Handler, HandlerResult, InputAuthzRequest, InputDecisions, Req,
    RequestContext, Resp, S3Service, ServiceBuilder, dto,
};

use bytes::Bytes;

use crate::support::{element_text, exchange, plain, signed_target_with_body_and_headers, wired_at_signed_time};

const ACCESS_POINT: &str = "arn:aws:s3:us-east-1:123456789012:accesspoint/ap-1/object/key";
const OUTPOSTS_ACCESS_POINT: &str = "arn:aws:s3-outposts:us-east-1:123456789012:outpost/op-1/accesspoint/ap-1/object/key";
const OUTPOSTS: &str = "arn:aws:s3-outposts:us-east-1:123456789012:outpost/op-1/object/key";
const COPY: &str = "/destination/object";
const PART_COPY: &str = "/destination/object?partNumber=1&uploadId=upload-one";

/// What reached each stage, so "never asked" and "never handled" are counts.
#[derive(Default)]
struct Counts {
    route: AtomicUsize,
    copy_source: AtomicUsize,
    input: AtomicUsize,
    handled: AtomicUsize,
}

impl Counts {
    fn read(&self) -> [usize; 4] {
        [&self.route, &self.copy_source, &self.input, &self.handled].map(|count| count.load(Ordering::SeqCst))
    }
}

struct Counting(Arc<Counts>);

impl Authorizer for Counting {
    fn authorize_route<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        _request: &'a AuthzRequest<'a>,
    ) -> BoxFuture<'a, Decision> {
        self.0.route.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Decision::Allow })
    }

    fn authorize_copy_source<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        _route: &'a AuthzRequest<'a>,
        _source: &'a AuthzRequest<'a>,
    ) -> BoxFuture<'a, Decision> {
        self.0.copy_source.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Decision::Allow })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        self.0.input.fetch_add(1, Ordering::SeqCst);
        let decisions = request.decide_all(Decision::Allow, |_| Decision::Allow);
        Box::pin(async move { decisions })
    }
}

impl Handler<dto::CopyObject> for Counting {
    async fn call(&self, _request: Req<dto::CopyObject>) -> HandlerResult<dto::CopyObject> {
        self.0.handled.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(dto::CopyObjectOutput::default()))
    }
}

impl Handler<dto::UploadPartCopy> for Counting {
    async fn call(&self, _request: Req<dto::UploadPartCopy>) -> HandlerResult<dto::UploadPartCopy> {
        self.0.handled.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(dto::UploadPartCopyOutput::default()))
    }
}

fn assembled(select: fn(ServiceBuilder) -> ServiceBuilder) -> (S3Service, Arc<Counts>) {
    let counts = Arc::new(Counts::default());
    let service = select(wired_at_signed_time())
        .authorizer(Counting(Arc::clone(&counts)))
        .register::<dto::CopyObject, _>(Arc::new(Counting(Arc::clone(&counts))))
        .register::<dto::UploadPartCopy, _>(Arc::new(Counting(Arc::clone(&counts))))
        .build()
        .expect("a complete copy assembly");
    (service, counts)
}

fn unsupported(builder: ServiceBuilder) -> ServiceBuilder {
    builder.refuse_copy_source_arns_as_not_implemented()
}

fn default(builder: ServiceBuilder) -> ServiceBuilder {
    builder
}

/// One signed copy of `source` onto `target` on a fresh assembly, its empty payload digest
/// declared as an SDK declares it: status, body and stage counts.
async fn copy(select: fn(ServiceBuilder) -> ServiceBuilder, target: &str, source: &str) -> (u16, String, [usize; 4]) {
    let (service, counts) = assembled(select);
    let headers = [("x-amz-copy-source", source)];
    let request = signed_target_with_body_and_headers(http::Method::PUT, target, &headers, Bytes::new());
    let (status, body) = exchange(&service, request).await;
    (status.as_u16(), body, counts.read())
}

fn arn_sources() -> Vec<String> {
    let mut sources = Vec::new();
    for arn in [ACCESS_POINT, OUTPOSTS_ACCESS_POINT, OUTPOSTS] {
        for spelling in [arn.to_owned(), format!("/{arn}"), format!("{arn}?versionId=v1")] {
            sources.push(spelling);
        }
    }
    sources
}

/// Negative — under the setting every ARN source on both operations is `501 NotImplemented`, asked
/// of no copy-source or input stage and handed to no handler. The route stage, which runs before
/// the source is decoded, is asked once (ADR-0045 leaves its deferral to the adapter's authorizer).
#[tokio::test]
async fn n_an_arn_source_is_not_implemented_before_input_authorization_under_the_setting() {
    for target in [COPY, PART_COPY] {
        for source in arn_sources() {
            let (status, body, counts) = copy(unsupported, target, &source).await;
            assert_eq!(status, 501, "{target} {source}: {body}");
            assert_eq!(element_text(&body, "Code"), Some("NotImplemented"), "{target} {source}: {body}");
            assert_eq!(counts, [1, 0, 0, 0], "{target} {source}: route, copy source, input, handler");
        }
    }
}

/// Negative — the RustFS profile selects the setting: the one call a RustFS assembly makes answers
/// an ARN source `501` before the input stage, on both operations.
#[tokio::test]
async fn n_the_rustfs_profile_refuses_an_arn_source_before_input_authorization() {
    for target in [COPY, PART_COPY] {
        for source in [ACCESS_POINT, OUTPOSTS_ACCESS_POINT, OUTPOSTS] {
            let (status, body, counts) = copy(ServiceBuilder::rustfs_profile, target, source).await;
            assert_eq!(status, 501, "{target} {source}: {body}");
            assert_eq!(counts[1..], [0, 0, 0], "{target} {source}: copy source, input, handler");
        }
    }
}

/// Negative — an ARN the legacy parser rejects is still the codec's `400 InvalidArgument` under the
/// setting: the capability check classifies only what decoded (ADR-0045).
#[tokio::test]
async fn n_an_unreadable_arn_keeps_its_codec_refusal_under_the_setting() {
    for target in [COPY, PART_COPY] {
        for source in [
            "arn:aws:s3:us-east-1:123:accesspoint/ap-1/object/key",
            "arn:aws:s3-outposts:us-east-1:123456789012:outpost/op-1/accesspoint/ap-1/object/",
        ] {
            let (status, body, counts) = copy(unsupported, target, source).await;
            assert_eq!(status, 400, "{target} {source}: {body}");
            assert_eq!(element_text(&body, "Code"), Some("InvalidArgument"), "{target} {source}: {body}");
            assert_eq!(counts[2..], [0, 0], "{target} {source}: input, handler");
        }
    }
}

/// Negative — authentication stays ahead of the capability check: an anonymous ARN copy is refused
/// as anonymous, not answered `501`.
#[tokio::test]
async fn n_an_anonymous_arn_copy_is_refused_before_the_capability_check() {
    for target in [COPY, PART_COPY] {
        let (service, counts) = assembled(unsupported);
        let mut request = plain(http::Method::PUT, target);
        request
            .headers_mut()
            .insert("x-amz-copy-source", http::HeaderValue::from_static(ACCESS_POINT));
        let (status, body) = exchange(&service, request).await;
        assert_eq!(status.as_u16(), 403, "{target}: {body}");
        assert_eq!(counts.read(), [0, 0, 0, 0], "{target}");
    }
}

/// Positive — a plain `bucket/key` source is untouched by the setting: input authorization runs
/// and the handler answers, on both operations, exactly as on the default assembly.
#[tokio::test]
async fn a_plain_source_is_served_with_and_without_the_setting() {
    for target in [COPY, PART_COPY] {
        for select in [unsupported, default] {
            let (status, body, counts) = copy(select, target, "/source/key").await;
            assert_eq!(status, 200, "{target}: {body}");
            assert_eq!(counts, [1, 0, 1, 1], "{target}: route, copy source, input, handler");
        }
    }
}

/// Negative — without the setting nothing answers `501`, as before: an access-point source and the
/// bucket-less Outposts spelling reach the input stage and the handler, and the Outposts
/// access-point spelling keeps resource validation's `400 InvalidArgument` ahead of the input stage.
#[tokio::test]
async fn n_without_the_setting_an_arn_source_is_answered_as_before() {
    for target in [COPY, PART_COPY] {
        for source in arn_sources() {
            let (status, body, counts) = copy(default, target, &source).await;
            if source.contains(":outpost/op-1/accesspoint/") {
                assert_eq!(status, 400, "{target} {source}: {body}");
                assert_eq!(element_text(&body, "Code"), Some("InvalidArgument"), "{target} {source}: {body}");
                assert_eq!(counts, [1, 0, 0, 0], "{target} {source}: route, copy source, input, handler");
            } else {
                assert_eq!(status, 200, "{target} {source}: {body}");
                assert_eq!(counts, [1, 0, 1, 1], "{target} {source}: route, copy source, input, handler");
            }
        }
    }
}

/// Negative and positive — the start-up posture names the setting when, and only when, it is on.
#[test]
fn the_posture_names_the_setting_only_when_it_is_on() {
    let name = "refuse_copy_source_arns_as_not_implemented";
    let (on, _) = assembled(unsupported);
    let (off, _) = assembled(default);
    assert!(on.startup_posture().contains(name), "{}", on.startup_posture());
    assert!(!off.startup_posture().contains(name), "{}", off.startup_posture());
}
