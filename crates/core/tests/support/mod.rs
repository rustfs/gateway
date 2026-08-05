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

//! Fixtures shared by the route, parameter and hot-path tests.
//!
//! Responsible for: [`Req`], which owns the buffers a borrowed [`RouteRequestParts`] points into,
//! the entry constructor, [`fixture_table`] — a route table shaped like the real one but small
//! enough to reason about — and [`block_on`], the small executor the handler tests run on.
//! NOT responsible for: any assertion. Helpers here never assert; a helper that decides what
//! passes moves the test out of the test file.
//! Upstream: `rustfs-gateway-core`, `rustfs-gateway-http`. Downstream: every integration test in
//! this crate.

// Each test binary compiles this module separately and uses a subset of it, so the unused-item and
// unreachable-pub lints fire on helpers another binary does use.
#![allow(dead_code, unreachable_pub)]

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};

use http::{HeaderMap, HeaderName, HeaderValue, Method};
use rustfs_gateway_core::route::{
    ArnForm, HostClass, Predicate, RouteEntry, RouteRequestParts, RouteSelector, RouteTable, ShadowingDecls, ShadowingPolicy,
    TargetKind,
};
use rustfs_gateway_http::{HeaderView, Limits, QueryIndex, QueryView};

/// An owned request the router can be pointed at.
pub struct Req {
    method: Method,
    path: String,
    target: TargetKind,
    host_class: HostClass,
    arn_form: Option<ArnForm>,
    raw_query: String,
    index: QueryIndex,
    headers: HeaderMap,
}

impl Req {
    /// Parses `"GET /bucket?acl&tagging"`.
    ///
    /// The target is inferred from the path the way a path-style resolver would, and can be
    /// overridden — the router never infers it itself, so a test that wants a literal path with a
    /// bucket target says so.
    ///
    /// # Panics
    ///
    /// On a malformed fixture. Test code, so a bad fixture should stop the run immediately.
    #[must_use]
    pub fn new(line: &str) -> Self {
        let (method, rest) = line.split_once(' ').expect("fixture is `METHOD /path[?query]`");
        let (path, query) = match rest.split_once('?') {
            Some((path, query)) => (path, query),
            None => (rest, ""),
        };
        let method = Method::from_bytes(method.as_bytes()).expect("fixture method");
        let target = infer_target(path);
        Self {
            method,
            path: path.to_owned(),
            target,
            host_class: HostClass::Standard,
            arn_form: None,
            raw_query: query.to_owned(),
            index: QueryIndex::parse(query, &Limits::default()).expect("fixture query is acceptable"),
            headers: HeaderMap::new(),
        }
    }

    /// Overrides the target the resolver would have computed.
    #[must_use]
    pub fn target(mut self, target: TargetKind) -> Self {
        self.target = target;
        self
    }

    /// Overrides the endpoint family.
    #[must_use]
    pub fn host_class(mut self, class: HostClass) -> Self {
        self.host_class = class;
        self
    }

    /// Declares an ARN in the bucket position.
    #[must_use]
    pub fn arn(mut self, form: ArnForm) -> Self {
        self.arn_form = Some(form);
        self
    }

    /// Appends a header.
    ///
    /// # Panics
    ///
    /// On a header name or value `http` refuses.
    #[must_use]
    pub fn header(mut self, name: &'static str, value: &str) -> Self {
        self.headers
            .append(HeaderName::from_static(name), HeaderValue::from_str(value).expect("fixture header value"));
        self
    }

    /// The borrowed view the router matches against.
    #[must_use]
    pub fn parts(&self) -> RouteRequestParts<'_> {
        RouteRequestParts {
            method: &self.method,
            path: &self.path,
            target: self.target,
            host_class: self.host_class,
            arn_form: self.arn_form,
            query: QueryView::new(&self.raw_query, &self.index),
            headers: HeaderView::new(&self.headers),
        }
    }

    /// Whether the query index stayed off the heap.
    #[must_use]
    pub fn query_is_inline(&self) -> bool {
        self.index.is_inline()
    }
}

/// What a path-style resolver would say a path addresses.
fn infer_target(path: &str) -> TargetKind {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return TargetKind::Service;
    }
    if trimmed.contains('/') {
        TargetKind::Object
    } else {
        TargetKind::Bucket
    }
}

/// One route entry.
///
/// Takes the predicates by value rather than as a `&'static [Predicate]`: `http::Method` carries
/// drop glue, so an inline predicate array is not promoted to `'static` and every fixture would
/// otherwise need a named `const` beside it.
#[must_use]
pub fn entry(op_name: &'static str, precedence: u16, predicates: Vec<Predicate>) -> RouteEntry {
    RouteEntry {
        precedence,
        selector: RouteSelector::owned(predicates),
        op_name,
        path_shape: "/{Bucket}",
    }
}

const COPY_SOURCE: &str = "x-amz-copy-source";

/// A table shaped like the real one: every band occupied, every predicate variant exercised.
///
/// Deliberately not the generated table. The generated table has three operations today; the
/// interesting routing questions — a subresource with and without its discriminator, a literal
/// path behind a host class, two operations separated only by a header — need entries that do not
/// exist yet, and inventing them here keeps the tests honest about what they cover.
#[must_use]
pub fn fixture_entries() -> Vec<RouteEntry> {
    vec![
        entry(
            "WriteGetObjectResponse",
            50,
            vec![
                Predicate::Method(Method::POST),
                Predicate::Target(TargetKind::Bucket),
                Predicate::HostClass(HostClass::ObjectLambda),
                Predicate::PathLiteral("/WriteGetObjectResponse"),
            ],
        ),
        entry(
            "GetObjectViaAccessPoint",
            150,
            vec![
                Predicate::Method(Method::GET),
                Predicate::Target(TargetKind::Object),
                Predicate::ArnForm(ArnForm::AccessPoint),
            ],
        ),
        entry(
            "GetBucketAnalyticsConfiguration",
            300,
            vec![
                Predicate::Method(Method::GET),
                Predicate::Target(TargetKind::Bucket),
                Predicate::QueryPresent("analytics"),
                Predicate::QueryPresent("id"),
            ],
        ),
        entry(
            "ListBucketAnalyticsConfigurations",
            310,
            vec![
                Predicate::Method(Method::GET),
                Predicate::Target(TargetKind::Bucket),
                Predicate::QueryPresent("analytics"),
            ],
        ),
        entry(
            "GetBucketAcl",
            320,
            vec![
                Predicate::Method(Method::GET),
                Predicate::Target(TargetKind::Bucket),
                Predicate::QueryPresent("acl"),
            ],
        ),
        entry(
            "GetBucketTagging",
            330,
            vec![
                Predicate::Method(Method::GET),
                Predicate::Target(TargetKind::Bucket),
                Predicate::QueryPresent("tagging"),
            ],
        ),
        entry(
            "ListMultipartUploads",
            340,
            vec![
                Predicate::Method(Method::GET),
                Predicate::Target(TargetKind::Bucket),
                Predicate::QueryPresent("uploads"),
            ],
        ),
        entry(
            "SelectObjectContent",
            350,
            vec![
                Predicate::Method(Method::POST),
                Predicate::Target(TargetKind::Object),
                Predicate::QueryEquals("select-type", "2"),
            ],
        ),
        entry(
            "ListObjectsV2",
            600,
            vec![
                Predicate::Method(Method::GET),
                Predicate::Target(TargetKind::Bucket),
                Predicate::QueryEquals("list-type", "2"),
            ],
        ),
        entry(
            "PostObject",
            700,
            vec![
                Predicate::Method(Method::POST),
                Predicate::Target(TargetKind::Bucket),
                Predicate::HeaderPrefix("content-type", "multipart/form-data"),
            ],
        ),
        entry(
            "CopyObject",
            805,
            vec![
                Predicate::Method(Method::PUT),
                Predicate::Target(TargetKind::Object),
                Predicate::HeaderPresent {
                    header: COPY_SOURCE,
                    negated: false,
                },
            ],
        ),
        entry(
            "PutObject",
            810,
            vec![
                Predicate::Method(Method::PUT),
                Predicate::Target(TargetKind::Object),
                Predicate::HeaderPresent {
                    header: COPY_SOURCE,
                    negated: true,
                },
            ],
        ),
        entry(
            "GetObject",
            820,
            vec![Predicate::Method(Method::GET), Predicate::Target(TargetKind::Object)],
        ),
    ]
}

/// The fixture table, built.
///
/// Uses [`ShadowingPolicy::TotalOnly`]: under the strict policy this thirteen-entry table needs
/// fourteen declarations that all say "a client would have to send two subresource keys at once",
/// which would make every test in this file about the declarations rather than about routing. The
/// strict policy is what the generated table is built under, and `route_table.rs` tests it
/// directly.
///
/// # Panics
///
/// When the fixture table does not build, which is the fixture's own bug.
#[must_use]
pub fn fixture_table() -> RouteTable {
    RouteTable::build(fixture_entries(), &ShadowingDecls::NONE.with_policy(ShadowingPolicy::TotalOnly))
        .expect("the fixture table is well formed")
}

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

/// Runs a future to completion on this thread.
///
/// The handler tests need an executor and this workspace has no runtime dependency — deliberately,
/// since the gateway is meant to be mounted on whichever one the host already runs. Park and
/// unpark is the whole executor: the futures under test are ready on the first poll, and a test
/// that hangs here is a test whose handler never completed, which is the failure it should show.
#[must_use]
pub fn block_on<F: Future>(future: F) -> F::Output {
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
