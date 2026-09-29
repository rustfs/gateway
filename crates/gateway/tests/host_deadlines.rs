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

//! A write that outlives a bounded framework deadline, under the deadline an embedding host
//! chooses when it wants none (rustfs/gateway#1070).
//!
//! Responsible for: the documented "no framework deadline" spelling, `Duration::MAX`, on the
//! handler deadline of both classes, on the committed continuation and on the request body —
//! each proved in both directions on the same staged write: a bounded deadline cancels it mid-write
//! and the backend's rollback leaves nothing behind, and `Duration::MAX` lets the very same write
//! finish and leaves it whole. The writes are the ones a server-side deadline can tear: `CopyObject`,
//! `UploadPartCopy`, `DeleteObjects`, `PutObject` and `CompleteMultipartUpload`.
//! NOT responsible for: the deadline race itself (`tests/connection_teardown.rs`, c-lim-0063) or
//! what ends a stalled committed response on a socket (`tests/committed_progress.rs`).
//! Upstream: `rustfs-gateway`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic)]

use crate::support;

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use futures_util::future::{Either, select};
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
use rustfs_gateway::{
    Handler, HandlerContext, HandlerDeadlineConfig, HandlerError, HandlerResult, HeadPart, Req, RequestBodyDeadlineConfig, Resp,
    S3Service, ServiceConfig, WireResponse, dto,
};

/// How long every staged write below takes once it has started.
const WRITE: Duration = Duration::from_millis(80);

/// The bounded control: well inside [`WRITE`], so it always lands mid-write.
const BOUNDED: Duration = Duration::from_millis(10);

/// What an embedding host that wants no framework deadline configures.
const NO_DEADLINE: Duration = Duration::MAX;

/// What the backend's storage holds: writes begun and not yet finished, and writes finished.
#[derive(Debug, Default, PartialEq, Eq)]
struct Stored {
    staged: BTreeSet<&'static str>,
    committed: BTreeSet<&'static str>,
}

/// A backend whose every write is staged, takes [`WRITE`], and is then committed — or rolled
/// back, when the framework cancels it first. A torn write would be a key left in `staged`.
#[derive(Clone, Default)]
struct StagedStore(Arc<Mutex<Stored>>);

impl StagedStore {
    fn snapshot(&self) -> (BTreeSet<&'static str>, BTreeSet<&'static str>) {
        let stored = self.0.lock().expect("the store is never poisoned");
        (stored.staged.clone(), stored.committed.clone())
    }

    fn stage(&self, key: &'static str) {
        self.0.lock().expect("the store is never poisoned").staged.insert(key);
    }

    fn roll_back(&self, key: &'static str) -> HandlerError {
        self.0.lock().expect("the store is never poisoned").staged.remove(key);
        HandlerError::internal_error("the write was cancelled and rolled back")
    }

    /// Finishes a staged write after [`WRITE`], or rolls it back if the framework cancels first.
    async fn finish(&self, key: &'static str, context: &HandlerContext) -> Result<(), HandlerError> {
        let finished = select(Box::pin(futures_timer::Delay::new(WRITE)), Box::pin(context.cancelled())).await;
        if let Either::Right(_) = finished {
            return Err(self.roll_back(key));
        }
        let mut stored = self.0.lock().expect("the store is never poisoned");
        stored.staged.remove(key);
        stored.committed.insert(key);
        Ok(())
    }

    async fn write(&self, key: &'static str, context: &HandlerContext) -> Result<(), HandlerError> {
        self.stage(key);
        self.finish(key, context).await
    }
}

fn bypassed<T>() -> Result<T, HandlerError> {
    Err(HandlerError::internal_error("the context-aware handler entry was bypassed"))
}

impl Handler<dto::CopyObject> for StagedStore {
    async fn call(&self, _request: Req<dto::CopyObject>) -> HandlerResult<dto::CopyObject> {
        bypassed()
    }

    async fn call_with_context(&self, _request: Req<dto::CopyObject>, context: HandlerContext) -> HandlerResult<dto::CopyObject> {
        self.write("copy", &context).await?;
        Ok(Resp::new(dto::CopyObjectOutput::default()))
    }
}

impl Handler<dto::UploadPartCopy> for StagedStore {
    async fn call(&self, _request: Req<dto::UploadPartCopy>) -> HandlerResult<dto::UploadPartCopy> {
        bypassed()
    }

    async fn call_with_context(
        &self,
        _request: Req<dto::UploadPartCopy>,
        context: HandlerContext,
    ) -> HandlerResult<dto::UploadPartCopy> {
        self.write("part-copy", &context).await?;
        Ok(Resp::new(dto::UploadPartCopyOutput::default()))
    }
}

impl Handler<dto::DeleteObjects> for StagedStore {
    async fn call(&self, _request: Req<dto::DeleteObjects>) -> HandlerResult<dto::DeleteObjects> {
        bypassed()
    }

    async fn call_with_context(
        &self,
        _request: Req<dto::DeleteObjects>,
        context: HandlerContext,
    ) -> HandlerResult<dto::DeleteObjects> {
        self.write("delete", &context).await?;
        Ok(Resp::new(dto::DeleteObjectsOutput::default()))
    }
}

impl Handler<dto::CompleteMultipartUpload> for StagedStore {
    async fn call(&self, _request: Req<dto::CompleteMultipartUpload>) -> HandlerResult<dto::CompleteMultipartUpload> {
        bypassed()
    }

    async fn call_with_context(
        &self,
        _request: Req<dto::CompleteMultipartUpload>,
        context: HandlerContext,
    ) -> HandlerResult<dto::CompleteMultipartUpload> {
        self.write("complete", &context).await?;
        Ok(Resp::new(dto::CompleteMultipartUploadOutput::default()))
    }
}

/// `PutObject` streams its body into the staged object, so a body deadline lands mid-write too.
impl Handler<dto::PutObject> for StagedStore {
    async fn call(&self, _request: Req<dto::PutObject>) -> HandlerResult<dto::PutObject> {
        bypassed()
    }

    async fn call_with_context(&self, request: Req<dto::PutObject>, context: HandlerContext) -> HandlerResult<dto::PutObject> {
        let mut body = request
            .into_input()
            .body
            .ok_or_else(|| HandlerError::internal_error("PutObject reached its handler without a body stream"))?
            .into_body();
        self.stage("put");
        let read = async {
            while let Some(frame) = body.frame().await {
                frame.map_err(|_| HandlerError::internal_error("the request body stream failed"))?;
            }
            Ok::<(), HandlerError>(())
        };
        match select(Box::pin(read), Box::pin(context.cancelled())).await {
            Either::Left((Ok(()), _)) => {}
            Either::Left((Err(_), _)) | Either::Right(_) => return Err(self.roll_back("put")),
        }
        self.finish("put", &context).await?;
        Ok(Resp::new(dto::PutObjectOutput::default()))
    }
}

fn deadlines(standard: Duration, extended: Duration) -> ServiceConfig {
    let deadlines = HandlerDeadlineConfig::new(standard, extended)
        .expect("non-zero handler deadlines")
        .try_with_cleanup_grace(Duration::from_millis(40))
        .expect("a non-zero cleanup grace");
    ServiceConfig::new(1 << 20).with_handler_deadlines(deadlines)
}

fn service(store: &StagedStore, config: ServiceConfig) -> S3Service {
    let backend = Arc::new(store.clone());
    let (builder, _handle) = support::wired_at_signed_time()
        .register::<dto::CopyObject, _>(Arc::clone(&backend))
        .register::<dto::UploadPartCopy, _>(Arc::clone(&backend))
        .register::<dto::DeleteObjects, _>(Arc::clone(&backend))
        .register::<dto::CompleteMultipartUpload, _>(Arc::clone(&backend))
        .register::<dto::PutObject, _>(backend)
        .config(config);
    builder.build().expect("a complete assembly")
}

const DELETE: &str = "<Delete><Object><Key>gone</Key></Object></Delete>";
const COMPLETE: &str =
    "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"etag\"</ETag></Part></CompleteMultipartUpload>";

/// One signed request per write, and the key its backend stages.
fn writes() -> Vec<(&'static str, http::Request<Bytes>)> {
    let copy_source = [("x-amz-copy-source", "/source/object")];
    vec![
        ("copy", support::signed_with(http::Method::PUT, "/bucket/copied", &copy_source)),
        (
            "part-copy",
            support::signed_with(http::Method::PUT, "/bucket/part?partNumber=1&uploadId=upload-one", &copy_source),
        ),
        (
            "delete",
            support::signed_target_with_body_and_headers(
                http::Method::POST,
                "/bucket?delete",
                &[("content-md5", &crate::tagging_reachability::content_md5(DELETE.as_bytes()))],
                Bytes::from_static(DELETE.as_bytes()),
            ),
        ),
        (
            "complete",
            support::signed_target_with_body(
                http::Method::POST,
                "/bucket/assembled?uploadId=upload-one",
                Bytes::from_static(COMPLETE.as_bytes()),
            ),
        ),
        ("put", put(OBJECT)),
    ]
}

const OBJECT: &[u8] = b"an object body in two halves";

/// A signed `PutObject` of `body`, with the `Content-Length` a `PutObject` must declare.
fn put(body: &'static [u8]) -> http::Request<Bytes> {
    let mut request = support::signed_target_with_body(http::Method::PUT, "/bucket/put", Bytes::from_static(body));
    request
        .headers_mut()
        .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(body.len()));
    request
}

async fn send(service: &S3Service, request: http::Request<Bytes>) -> WireResponse {
    rustfs_gateway::collect(service.call_bytes(request).await)
        .await
        .expect("an in-memory body")
}

/// Negative — the control that gives the next test its meaning: a bounded deadline on either
/// class lands mid-write, every write is refused, and the rollback leaves nothing staged and
/// nothing committed. Nothing is torn.
#[tokio::test]
async fn a_bounded_deadline_cancels_each_write_mid_flight_and_leaves_nothing_behind() {
    for (key, request) in writes() {
        let store = StagedStore::default();
        let response = send(&service(&store, deadlines(BOUNDED, BOUNDED)), request).await;
        assert_eq!(response.status().as_u16(), 500, "{key}: {:?}", response.body());
        assert_eq!(store.snapshot(), (BTreeSet::new(), BTreeSet::new()), "{key} left a write behind");
    }
}

/// Negative — with `Duration::MAX` on both classes, the same writes run past every bounded
/// deadline above and finish whole: answered `200`, committed, nothing left staged.
#[tokio::test]
async fn no_framework_deadline_lets_each_write_finish_whole() {
    for (key, request) in writes() {
        let store = StagedStore::default();
        let response = send(&service(&store, deadlines(NO_DEADLINE, NO_DEADLINE)), request).await;
        assert_eq!(response.status().as_u16(), 200, "{key}: {:?}", response.body());
        assert_eq!(store.snapshot(), (BTreeSet::new(), BTreeSet::from([key])), "{key} did not finish whole");
    }
}

/// Negative — the classes are independent: lifting only the standard class leaves the extended
/// one (`CompleteMultipartUpload`) bounded, and lifting only the extended one leaves the standard
/// ones bounded.
#[tokio::test]
async fn each_class_is_lifted_on_its_own() {
    for (standard, extended) in [(NO_DEADLINE, BOUNDED), (BOUNDED, NO_DEADLINE)] {
        for (key, request) in writes() {
            let store = StagedStore::default();
            let response = send(&service(&store, deadlines(standard, extended)), request).await;
            let lifted = if key == "complete" {
                extended == NO_DEADLINE
            } else {
                standard == NO_DEADLINE
            };
            let expected = if lifted { 200 } else { 500 };
            assert_eq!(response.status().as_u16(), expected, "{key}: {:?}", response.body());
            let committed = if lifted { BTreeSet::from([key]) } else { BTreeSet::new() };
            assert_eq!(store.snapshot(), (BTreeSet::new(), committed), "{key} under ({standard:?}, {extended:?})");
        }
    }
}

/// A `CopyObject` backend that commits its head at once and finishes the copy in its
/// continuation — the shape of a copy that must keep its connection alive while it works.
#[derive(Clone, Default)]
struct CommittedCopy(StagedStore);

impl Handler<dto::CopyObject> for CommittedCopy {
    async fn call(&self, _request: Req<dto::CopyObject>) -> HandlerResult<dto::CopyObject> {
        let store = self.0.clone();
        Ok(Resp::commit(
            HeadPart::new(http::HeaderMap::new()).expect("an empty generated operation head"),
            Box::pin(async move {
                store.0.lock().expect("the store is never poisoned").staged.insert("copy");
                futures_timer::Delay::new(WRITE).await;
                let mut stored = store.0.lock().expect("the store is never poisoned");
                stored.staged.remove("copy");
                stored.committed.insert("copy");
                Ok(dto::CopyObjectOutput::default())
            }),
        ))
    }
}

fn committed_copy_service(store: &StagedStore, commit_progress: Duration) -> S3Service {
    let deadlines = HandlerDeadlineConfig::default()
        .try_with_commit_progress(commit_progress)
        .expect("a non-zero commit progress bound");
    let (builder, _handle) = support::wired_at_signed_time()
        .register::<dto::CopyObject, _>(Arc::new(CommittedCopy(store.clone())))
        .config(ServiceConfig::new(1 << 20).with_handler_deadlines(deadlines));
    builder.build().expect("a complete assembly")
}

/// Negative — the committed continuation in both directions. A bounded progress deadline drops
/// the continuation mid-write — the framework has no cancellation channel into it, so the staged
/// key is exactly what a torn write looks like, and it is why a host that must not tear writes
/// lifts the bound — while `Duration::MAX` lets the same continuation finish whole.
#[tokio::test]
async fn no_commit_progress_deadline_lets_a_committed_write_finish_whole() {
    let copy = || support::signed_with(http::Method::PUT, "/bucket/copied", &[("x-amz-copy-source", "/source/object")]);

    let bounded = StagedStore::default();
    let response = send(&committed_copy_service(&bounded, BOUNDED), copy()).await;
    let body = String::from_utf8_lossy(response.body()).into_owned();
    assert!(body.contains(rustfs_gateway::commit::COMMIT_PROGRESS_EXPIRED), "{body}");
    assert_eq!(bounded.snapshot(), (BTreeSet::from(["copy"]), BTreeSet::new()));

    let lifted = StagedStore::default();
    let response = send(&committed_copy_service(&lifted, NO_DEADLINE), copy()).await;
    let body = String::from_utf8_lossy(response.body()).into_owned();
    assert_eq!(response.status().as_u16(), 200);
    assert!(body.contains("<CopyObjectResult"), "{body}");
    assert!(!body.contains("<Error>"), "{body}");
    assert_eq!(lifted.snapshot(), (BTreeSet::new(), BTreeSet::from(["copy"])));
}

/// The same signed `PutObject`, its body arriving in two halves, each after `pause`: the first
/// pause is what a first-byte deadline sees, the second what a between-read deadline sees.
fn paused_put(pause: Duration) -> http::Request<StreamBody<impl futures_util::Stream<Item = Result<Frame<Bytes>, Infallible>>>> {
    let (head, _) = put(OBJECT).into_parts();
    let (first, rest) = OBJECT.split_at(OBJECT.len() / 2);
    let halves = futures_util::stream::unfold(0_u8, move |step| async move {
        let half = match step {
            0 => first,
            1 => rest,
            _ => return None,
        };
        futures_timer::Delay::new(pause).await;
        Some((Ok(Frame::data(Bytes::from_static(half))), step + 1))
    });
    http::Request::from_parts(head, StreamBody::new(halves))
}

fn body_service(store: &StagedStore, body: RequestBodyDeadlineConfig) -> S3Service {
    let config = deadlines(NO_DEADLINE, NO_DEADLINE).with_request_body_deadlines(body);
    service(store, config)
}

async fn send_paused(service: &S3Service, pause: Duration) -> WireResponse {
    rustfs_gateway::collect(service.call(paused_put(pause)).await)
        .await
        .expect("an in-memory body")
}

/// Negative — the body's first-byte deadline, its between-read deadline and its throughput floor
/// each land on a body that pauses before each of its halves: the upload is refused and the
/// staged object is rolled back.
#[tokio::test]
async fn a_bounded_body_deadline_cancels_a_streaming_write_mid_flight_and_leaves_nothing_behind() {
    let long = Duration::from_secs(5);
    let first_byte = RequestBodyDeadlineConfig::new(BOUNDED, long).expect("non-zero body deadlines");
    let idle = RequestBodyDeadlineConfig::new(long, BOUNDED).expect("non-zero body deadlines");
    let floor = RequestBodyDeadlineConfig::new(long, long)
        .and_then(|deadlines| deadlines.try_with_throughput_floor(1024, BOUNDED))
        .expect("a non-zero throughput floor");
    for (name, body) in [("first byte", first_byte), ("idle", idle), ("floor", floor)] {
        let store = StagedStore::default();
        let response = send_paused(&body_service(&store, body), WRITE).await;
        assert_ne!(response.status().as_u16(), 200, "{name}: {:?}", response.body());
        assert_eq!(store.snapshot(), (BTreeSet::new(), BTreeSet::new()), "{name} left a write behind");
    }
}

/// Negative — with `Duration::MAX` as the first-byte and between-read deadlines and as the
/// throughput window, the same paused body is read to its end and the write finishes whole.
/// (Staging happens when the handler starts, so the first-byte pause lands mid-write too.)
#[tokio::test]
async fn no_body_deadline_lets_a_paused_streaming_write_finish_whole() {
    let lifted = RequestBodyDeadlineConfig::new(NO_DEADLINE, NO_DEADLINE)
        .and_then(|deadlines| deadlines.try_with_throughput_floor(1, NO_DEADLINE))
        .expect("the lifted body deadlines");
    let store = StagedStore::default();
    let response = send_paused(&body_service(&store, lifted), WRITE).await;
    assert_eq!(response.status().as_u16(), 200, "{:?}", response.body());
    assert_eq!(store.snapshot(), (BTreeSet::new(), BTreeSet::from(["put"])));
}
