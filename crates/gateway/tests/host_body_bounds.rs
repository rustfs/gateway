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

//! A request body read with every framework body deadline lifted, as the RustFS profile lifts
//! them, and bounded by the embedding host instead (rustfs/gateway#1173).
//!
//! Responsible for: proving that an inactivity bound the host wraps around the transport body,
//! the shape of RustFS's own `ObservedBody` once a handler arms it, ends a buffered read and a
//! POST form's text prelude that stop arriving, with a refusal before any handler runs, under
//! lifted framework body deadlines; that it is the host's bound that ends them (without it the
//! same reads are still unanswered long after the bound would have passed); and that a body that
//! keeps arriving inside the bound is read whole. Time is paused and advanced by the runtime, so
//! the bound is measured in the host's clock; that the lifted framework deadlines arm no timer of
//! their own is `tests/host_deadlines.rs`' census and `wire_read.rs`'s
//! `a_lifted_idle_deadline_arms_no_timer_while_a_frame_is_awaited`.
//! NOT responsible for: the gateway's own body deadlines (`c-lim-*` and `tests/host_deadlines.rs`),
//! or which reads RustFS's host bounds today: legacy RustFS arms its body idle bound
//! (`RUSTFS_HTTP_REQUEST_BODY_READ_TIMEOUT`) only in its `PutObject` and `UploadPart` handlers and
//! behind an early answer (rustfs/rustfs `3268c42e00`, `rustfs/src/app/object/request_body.rs`,
//! `rustfs/src/app/object/put.rs:127-160`, `rustfs/src/server/http.rs:910-953`), so it reads a
//! buffered body and a POST form's fields with no bound at all, and so does the RustFS profile.
//! Upstream: `S3Service`, with a host body wrapper written here. Downstream: nothing.

#![allow(clippy::expect_used)]

use std::convert::Infallible;
use std::future::Future as _;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::Frame;
use http_body_util::BodyExt as _;
use rustfs_gateway::dto::{PostObject, PostObjectOutput};
use rustfs_gateway::{
    ETag, Handler, HandlerError, HandlerResult, Req, RequestBodyDeadlineConfig, Resp, S3Service, ServiceConfig, WireResponse, dto,
};

use crate::support;

/// The host's idle bound, as RustFS's default `RUSTFS_HTTP_REQUEST_BODY_READ_TIMEOUT` sets it.
const HOST_IDLE: Duration = Duration::from_secs(300);

/// Twelve times the host's bound, in the paused clock.
const AN_HOUR: Duration = Duration::from_secs(3600);

const TAGGING: &[u8] = b"<Tagging><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>";
const BOUNDARY: &str = "----HostBodyBounds";

/// A transport body that hands over its pieces, one per poll after a `gap` of (paused) time
/// between them, and then either ends or goes silent for ever.
struct Transport {
    pieces: Vec<Bytes>,
    gap: Duration,
    wait: Option<Pin<Box<tokio::time::Sleep>>>,
    ends: bool,
}

impl Transport {
    fn stalling(prefix: &[u8]) -> Self {
        Self {
            pieces: vec![Bytes::copy_from_slice(prefix)],
            gap: Duration::ZERO,
            wait: None,
            ends: false,
        }
    }

    fn trickling(bytes: &[u8], gap: Duration) -> Self {
        Self {
            pieces: bytes.chunks(8).rev().map(Bytes::copy_from_slice).collect(),
            gap,
            wait: None,
            ends: true,
        }
    }
}

impl http_body::Body for Transport {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let this = self.get_mut();
        if this.pieces.is_empty() {
            return if this.ends { Poll::Ready(None) } else { Poll::Pending };
        }
        if !this.gap.is_zero() {
            let wait = this.wait.get_or_insert_with(|| Box::pin(tokio::time::sleep(this.gap)));
            if wait.as_mut().poll(context).is_pending() {
                return Poll::Pending;
            }
            this.wait = None;
        }
        let piece = this.pieces.pop().expect("a piece is left");
        Poll::Ready(Some(Ok(Frame::data(piece))))
    }
}

/// The host's inactivity bound around a transport body: the body fails once `idle` of (paused)
/// time passes with no frame, and every frame restarts the bound.
struct HostIdleBound<B> {
    inner: B,
    idle: Duration,
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<B> HostIdleBound<B> {
    fn around(inner: B) -> Self {
        Self {
            inner,
            idle: HOST_IDLE,
            deadline: None,
        }
    }
}

impl<B: http_body::Body<Data = Bytes, Error = Infallible> + Unpin> http_body::Body for HostIdleBound<B> {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(context) {
            Poll::Ready(frame) => {
                this.deadline = None;
                Poll::Ready(frame.map(|frame| frame.map_err(|never| match never {})))
            }
            Poll::Pending => {
                let deadline = this.deadline.get_or_insert_with(|| Box::pin(tokio::time::sleep(this.idle)));
                match deadline.as_mut().poll(context) {
                    Poll::Ready(()) => Poll::Ready(Some(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "the host's request body idle bound passed",
                    )))),
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }
}

#[derive(Default)]
struct Reached(AtomicUsize);

struct Backend(Arc<Reached>);

impl Handler<dto::PutObjectTagging> for Backend {
    async fn call(&self, _request: Req<dto::PutObjectTagging>) -> HandlerResult<dto::PutObjectTagging> {
        self.0.0.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(dto::PutObjectTaggingOutput::default()))
    }
}

impl Handler<PostObject> for Backend {
    async fn call(&self, request: Req<PostObject>) -> HandlerResult<PostObject> {
        self.0.0.fetch_add(1, Ordering::SeqCst);
        // Read to its end, as a storing handler does: the file is the body's last part.
        let mut file = request.into_input().body.into_body();
        while let Some(frame) = file.frame().await {
            frame.map_err(|_| HandlerError::internal_error("the POST file stream failed"))?;
        }
        Ok(Resp::new(PostObjectOutput {
            e_tag: Some(ETag::new("stored").expect("a valid entity tag")),
            version_id: None,
        }))
    }
}

/// The fixture service with every body deadline lifted, as the RustFS profile lifts them.
fn lifted() -> (S3Service, Arc<Reached>) {
    let reached = Arc::new(Reached::default());
    let backend = Arc::new(Backend(Arc::clone(&reached)));
    let body = RequestBodyDeadlineConfig::S3
        .without_idle_deadlines()
        .without_throughput_floor();
    let (builder, _config) = support::wired_at_signed_time()
        .accept_all_checksum_omissions()
        .register::<dto::PutObjectTagging, _>(Arc::clone(&backend))
        .register::<PostObject, _>(backend)
        .config(ServiceConfig::new(rustfs_gateway::DEFAULT_MAX_BUFFERED_BODY_BYTES).with_request_body_deadlines(body));
    (builder.build().expect("a complete assembly"), reached)
}

/// A signed tag-set write announcing all of [`TAGGING`], sent as `body`.
fn tagging_write<B>(body: B) -> http::Request<B> {
    let (mut parts, _) =
        support::signed_target_with_body(http::Method::PUT, "/bucket/object?tagging", Bytes::from_static(TAGGING)).into_parts();
    parts
        .headers
        .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(TAGGING.len()));
    http::Request::from_parts(parts, body)
}

/// An anonymous POST Object form of one field and a file.
fn form() -> Bytes {
    Bytes::from(format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nuploads/report.txt\r\n\
         --{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"report.txt\"\r\n\
         Content-Type: text/plain\r\n\r\nhello from a browser\r\n--{BOUNDARY}--\r\n"
    ))
}

fn form_post<B>(length: usize, body: B) -> http::Request<B> {
    http::Request::builder()
        .method(http::Method::POST)
        .uri("/bucket")
        .header(http::header::HOST, "s3.example.com")
        .header(http::header::CONTENT_TYPE, format!("multipart/form-data; boundary={BOUNDARY}"))
        .header(http::header::CONTENT_LENGTH, length)
        .body(body)
        .expect("a valid request")
}

async fn answer<B>(service: &S3Service, request: http::Request<B>) -> Option<WireResponse>
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let response = tokio::time::timeout(AN_HOUR, service.call(request)).await.ok()?;
    Some(rustfs_gateway::collect(response).await.expect("an in-memory body"))
}

/// Negative — without the host's bound the same stalled buffered body is still unanswered an hour
/// later, and no handler has run: the refusal below is the bound's.
#[tokio::test(start_paused = true)]
async fn n_without_the_host_bound_a_stalled_buffered_body_is_unanswered() {
    let (service, reached) = lifted();
    let request = tagging_write(Transport::stalling(TAGGING.get(..20).expect("a prefix")));
    assert!(answer(&service, request).await.is_none(), "something other than the host ended the body");
    assert_eq!(reached.0.load(Ordering::SeqCst), 0);
}

/// Positive — the host's idle bound ends the same read with a refusal, before any handler runs.
#[tokio::test(start_paused = true)]
async fn a_host_idle_bound_ends_a_stalled_buffered_body_before_the_handler() {
    let (service, reached) = lifted();
    let request = tagging_write(HostIdleBound::around(Transport::stalling(TAGGING.get(..20).expect("a prefix"))));
    let response = answer(&service, request).await.expect("the host's bound ended the read");
    assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    assert_eq!(reached.0.load(Ordering::SeqCst), 0, "a handler ran on a body the host abandoned");
}

/// Negative — a body that keeps arriving inside the host's bound, a piece every four minutes,
/// is read whole and applied: the bound is on silence, not on the length of the transfer.
#[tokio::test(start_paused = true)]
async fn n_a_body_that_keeps_arriving_inside_the_host_bound_is_read_whole() {
    let (service, reached) = lifted();
    let request = tagging_write(HostIdleBound::around(Transport::trickling(TAGGING, Duration::from_secs(240))));
    let response = answer(&service, request).await.expect("the write was answered");
    assert_eq!(response.status(), http::StatusCode::OK, "{:?}", response.body());
    assert_eq!(reached.0.load(Ordering::SeqCst), 1);
}

/// Negative — without the host's bound a POST form whose text prelude stops arriving before its
/// first field is complete is still unanswered an hour later.
#[tokio::test(start_paused = true)]
async fn n_without_the_host_bound_a_stalled_post_form_is_unanswered() {
    let (service, reached) = lifted();
    let form = form();
    let request = form_post(form.len(), Transport::stalling(form.get(..30).expect("a prefix")));
    assert!(answer(&service, request).await.is_none(), "something other than the host ended the form");
    assert_eq!(reached.0.load(Ordering::SeqCst), 0);
}

/// Positive — the host's idle bound ends the same form with a refusal, before any handler runs.
#[tokio::test(start_paused = true)]
async fn a_host_idle_bound_ends_a_stalled_post_form_prelude() {
    let (service, reached) = lifted();
    let form = form();
    let request = form_post(form.len(), HostIdleBound::around(Transport::stalling(form.get(..30).expect("a prefix"))));
    let response = answer(&service, request).await.expect("the host's bound ended the read");
    assert!(response.status().is_client_error(), "{:?}", response.status());
    assert_eq!(reached.0.load(Ordering::SeqCst), 0, "a handler ran on a form the host abandoned");
}

/// Negative — a complete form under the host's bound reaches its handler, as without the bound.
#[tokio::test(start_paused = true)]
async fn n_a_complete_form_under_the_host_bound_reaches_its_handler() {
    let (service, reached) = lifted();
    let form = form();
    let request = form_post(form.len(), HostIdleBound::around(Transport::trickling(&form, Duration::from_secs(1))));
    let response = answer(&service, request).await.expect("the form was answered");
    assert!(response.status().is_success(), "{:?} {:?}", response.status(), response.body());
    assert_eq!(reached.0.load(Ordering::SeqCst), 1);
}
