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

//! The macro form and the hand-written form produce the same registry.
//!
//! Responsible for: the equivalence proof — same operations, same answers — and the multi-block
//! composition that "one operation per file" needs.
//! NOT responsible for: what the expansion looks like (`src/tests`), or what registration refuses
//! (`rustfs-gateway-core`'s own tests).
//! Upstream: `rustfs-gateway-macros`, `rustfs-gateway-core`. Downstream: nothing.
//!
//! # Why this is the test that matters
//!
//! Governance rule 4 says the macro is optional sugar. The only machine-checkable form of that
//! claim is this: build one backend with the macro and one without, register both, and show that
//! the registries agree — the same keys, and the same behaviour behind each key. A macro that
//! started doing something extra would fail here and nowhere else.

#![allow(clippy::expect_used, reason = "test code; a failed expectation is the test failing")]

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};

use bytes::Bytes;
use http::Request;
use rustfs_gateway_core::handler::{Handler, HandlerResult, Req, Resp};
use rustfs_gateway_core::registry::RouterBuilder;
use rustfs_gateway_core::{HandlerContext, MetaView, Router, SseConfig, SseEnforced, TargetKind, TransportSecurity, dispatch};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_macros::handlers;

// The proc-macro crate's own equivalence test stands in for the public facade without creating a
// dev-dependency cycle. Downstream users reach the same surface as `rustfs_gateway`.
extern crate rustfs_gateway_core as rustfs_gateway;
use rustfs_gateway_types::dto::{
    GetBucketLocation, GetBucketLocationInput, GetBucketLocationOutput, ListObjectsV2, ListObjectsV2Input, ListObjectsV2Output,
    LocationConstraint, PutObject, PutObjectInput, PutObjectOutput,
};

fn sse_proof() -> SseEnforced {
    let request = Request::builder()
        .method(http::Method::GET)
        .uri("/")
        .header("host", "s3.example.com")
        .body(Bytes::new())
        .expect("valid proof fixture");
    let wire = WireRequest::accept(request, &Limits::default()).expect("accepted proof fixture");
    let meta = MetaView::of(&wire, TargetKind::Service).expect("service proof fixture");
    rustfs_gateway_core::sse::enforce(&meta, TransportSecurity::Encrypted, &SseConfig::strict())
        .expect("an empty encrypted request passes SSE enforcement")
}

// ── the macro form ───────────────────────────────────────────────────────────────────────────

/// A backend whose handlers are generated.
#[derive(Debug, Default)]
pub struct MacroFs;

#[handlers(group = objects)]
impl MacroFs {
    async fn put_object(&self, request: Req<PutObject>) -> HandlerResult<PutObject> {
        let _ = request.input();
        Ok(Resp::new(PutObjectOutput {
            e_tag: self.etag(),
            ..PutObjectOutput::default()
        }))
    }

    async fn list_objects_v2(&self, request: Req<ListObjectsV2>) -> HandlerResult<ListObjectsV2> {
        let _ = request.input();
        Ok(Resp::new(ListObjectsV2Output {
            key_count: 0,
            ..ListObjectsV2Output::default()
        }))
    }

    /// Not an operation, and it says so. Without the marker this is a compile error, which is the
    /// intended behaviour: a method the macro cannot place must not be silently ignored.
    #[handlers(skip)]
    fn etag(&self) -> rustfs_gateway_types::ETag {
        rustfs_gateway_types::ETag::default()
    }
}

/// A second block for the same backend, as it would be in a second file.
#[handlers(group = buckets)]
impl MacroFs {
    async fn get_bucket_location(&self, request: Req<GetBucketLocation>) -> HandlerResult<GetBucketLocation> {
        let _ = request.input();
        Ok(Resp::new(GetBucketLocationOutput {
            location_constraint: Some(LocationConstraint::custom("us-east-1")),
        }))
    }
}

// ── the hand-written form ────────────────────────────────────────────────────────────────────

/// The same backend with no macro anywhere. This is what the macro emits, written out.
#[derive(Debug, Default)]
pub struct ManualFs;

impl ManualFs {
    async fn put_object(&self, request: Req<PutObject>) -> HandlerResult<PutObject> {
        let _ = request.input();
        Ok(Resp::new(PutObjectOutput {
            e_tag: self.etag(),
            ..PutObjectOutput::default()
        }))
    }

    async fn list_objects_v2(&self, request: Req<ListObjectsV2>) -> HandlerResult<ListObjectsV2> {
        let _ = request.input();
        Ok(Resp::new(ListObjectsV2Output {
            key_count: 0,
            ..ListObjectsV2Output::default()
        }))
    }

    async fn get_bucket_location(&self, request: Req<GetBucketLocation>) -> HandlerResult<GetBucketLocation> {
        let _ = request.input();
        Ok(Resp::new(GetBucketLocationOutput {
            location_constraint: Some(LocationConstraint::custom("us-east-1")),
        }))
    }

    fn etag(&self) -> rustfs_gateway_types::ETag {
        rustfs_gateway_types::ETag::default()
    }

    /// The hand-written equivalent of the generated `register_objects`.
    pub fn register_objects(this: &Arc<Self>, builder: RouterBuilder) -> RouterBuilder {
        builder
            .handle::<PutObject, Self>(Arc::clone(this))
            .handle::<ListObjectsV2, Self>(Arc::clone(this))
    }

    /// The hand-written equivalent of the generated `register_buckets`.
    pub fn register_buckets(this: &Arc<Self>, builder: RouterBuilder) -> RouterBuilder {
        builder.handle::<GetBucketLocation, Self>(Arc::clone(this))
    }
}

impl Handler<PutObject> for ManualFs {
    fn call(&self, request: Req<PutObject>) -> impl Future<Output = HandlerResult<PutObject>> + Send {
        self.put_object(request)
    }

    fn call_with_context(
        &self,
        request: Req<PutObject>,
        _context: HandlerContext,
    ) -> impl Future<Output = HandlerResult<PutObject>> + Send {
        self.put_object(request)
    }
}

impl Handler<ListObjectsV2> for ManualFs {
    fn call(&self, request: Req<ListObjectsV2>) -> impl Future<Output = HandlerResult<ListObjectsV2>> + Send {
        self.list_objects_v2(request)
    }

    fn call_with_context(
        &self,
        request: Req<ListObjectsV2>,
        _context: HandlerContext,
    ) -> impl Future<Output = HandlerResult<ListObjectsV2>> + Send {
        self.list_objects_v2(request)
    }
}

impl Handler<GetBucketLocation> for ManualFs {
    fn call(&self, request: Req<GetBucketLocation>) -> impl Future<Output = HandlerResult<GetBucketLocation>> + Send {
        self.get_bucket_location(request)
    }

    fn call_with_context(
        &self,
        request: Req<GetBucketLocation>,
        _context: HandlerContext,
    ) -> impl Future<Output = HandlerResult<GetBucketLocation>> + Send {
        self.get_bucket_location(request)
    }
}

// ── a four-line executor ─────────────────────────────────────────────────────────────────────

/// Wakes the thread that parked on a future.
struct ParkSignal {
    thread: Thread,
    woken: AtomicBool,
}

impl Wake for ParkSignal {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.woken.store(true, Ordering::Release);
        self.thread.unpark();
    }
}

/// Runs a future to completion on this thread; the workspace has no runtime dependency.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let signal = Arc::new(ParkSignal {
        thread: thread::current(),
        woken: AtomicBool::new(false),
    });
    let waker = Waker::from(Arc::clone(&signal));
    let mut context = Context::from_waker(&waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => {
                while !signal.woken.swap(false, Ordering::Acquire) {
                    thread::park();
                }
            }
        }
    }
}

// ── the routers ──────────────────────────────────────────────────────────────────────────────

fn macro_router() -> Router {
    let fs = Arc::new(MacroFs);
    let builder = MacroFs::register_objects(&fs, RouterBuilder::new());
    // No summary function is generated: the assembly point composes the groups, and that is a line
    // `grep` finds.
    MacroFs::register_buckets(&fs, builder)
        .build()
        .expect("the macro form builds")
}

fn manual_router() -> Router {
    let fs = Arc::new(ManualFs);
    let builder = ManualFs::register_objects(&fs, RouterBuilder::new());
    ManualFs::register_buckets(&fs, builder)
        .build()
        .expect("the hand-written form builds")
}

// ── positive ─────────────────────────────────────────────────────────────────────────────────

/// Positive — the two forms register exactly the same operations.
#[test]
fn macro_and_manual_registration_are_equivalent() {
    let generated: Vec<&str> = macro_router().registry().handler_names().collect();
    let written: Vec<&str> = manual_router().registry().handler_names().collect();
    assert_eq!(generated, written);
    assert_eq!(generated, vec!["GetBucketLocation", "ListObjectsV2", "PutObject"]);
}

/// Positive — and the behaviour behind each key is the same, which the key set alone does not say.
#[test]
fn the_two_forms_answer_identically() {
    let generated = macro_router();
    let written = manual_router();

    let one = block_on(
        generated
            .registry()
            .authorize_and_invoke_no_derived::<GetBucketLocation>(GetBucketLocationInput::default(), sse_proof())
            .expect("input authorization succeeds")
            .expect("registered"),
    )
    .expect("answered");
    let two = block_on(
        written
            .registry()
            .authorize_and_invoke_no_derived::<GetBucketLocation>(GetBucketLocationInput::default(), sse_proof())
            .expect("input authorization succeeds")
            .expect("registered"),
    )
    .expect("answered");
    assert_eq!(
        one.output()
            .expect("settled")
            .location_constraint
            .as_ref()
            .map(LocationConstraint::as_str),
        two.output()
            .expect("settled")
            .location_constraint
            .as_ref()
            .map(LocationConstraint::as_str),
    );

    let one = block_on(
        generated
            .registry()
            .authorize_and_invoke_no_derived::<ListObjectsV2>(ListObjectsV2Input::default(), sse_proof())
            .expect("input authorization succeeds")
            .expect("registered"),
    )
    .expect("answered");
    let two = block_on(
        written
            .registry()
            .authorize_and_invoke_no_derived::<ListObjectsV2>(ListObjectsV2Input::default(), sse_proof())
            .expect("input authorization succeeds")
            .expect("registered"),
    )
    .expect("answered");
    assert_eq!(one.output().expect("settled").key_count, two.output().expect("settled").key_count);
    assert_eq!(one.status(), two.status());

    let one = block_on(
        generated
            .registry()
            .authorize_and_invoke_no_derived::<PutObject>(PutObjectInput::default(), sse_proof())
            .expect("input authorization succeeds")
            .expect("registered"),
    )
    .expect("answered");
    let two = block_on(
        written
            .registry()
            .authorize_and_invoke_no_derived::<PutObject>(PutObjectInput::default(), sse_proof())
            .expect("input authorization succeeds")
            .expect("registered"),
    )
    .expect("answered");
    assert_eq!(one.output().expect("settled").e_tag, two.output().expect("settled").e_tag);
}

/// Positive — two groups compose, and each generated function registers only its own block.
#[test]
fn the_groups_compose_and_stay_separate() {
    let fs = Arc::new(MacroFs);
    let objects: Vec<&str> = MacroFs::register_objects(&fs, RouterBuilder::new()).registered().collect();
    assert_eq!(objects, vec!["ListObjectsV2", "PutObject"]);

    let buckets: Vec<&str> = MacroFs::register_buckets(&fs, RouterBuilder::new()).registered().collect();
    assert_eq!(buckets, vec!["GetBucketLocation"]);
}

// ── negative ─────────────────────────────────────────────────────────────────────────────────

/// Negative — the macro registers nothing extra: an operation nobody wrote a method for is a 501.
#[test]
fn the_macro_registers_nothing_it_was_not_given() {
    let fs = Arc::new(MacroFs);
    let router = MacroFs::register_buckets(&fs, RouterBuilder::new()).build().expect("built");

    assert!(
        router
            .registry()
            .authorize_and_invoke_no_derived::<PutObject>(PutObjectInput::default(), sse_proof())
            .expect("input authorization succeeds")
            .is_none()
    );
    assert_eq!(router.registry().handler_names().collect::<Vec<_>>(), vec!["GetBucketLocation"]);
}

/// Negative — the skipped helper did not become a handler, and did not become an operation name.
#[test]
fn a_skipped_method_is_not_registered() {
    let names: Vec<&str> = macro_router().registry().handler_names().collect();
    assert!(!names.iter().any(|name| name.contains("Etag")), "{names:?}");
    assert_eq!(names.len(), 3);
}

/// Negative — a request that routes to an operation neither form implements is the framework's
/// 501, not a panic and not a different backend's answer.
#[test]
fn an_operation_neither_form_implements_is_not_implemented() {
    for router in [macro_router(), manual_router()] {
        let registry = router.registry();
        assert!(registry.get("HeadObject").is_none());
        assert_eq!(dispatch::NOT_REGISTERED_MESSAGE.lines().count(), 1);
    }
}
