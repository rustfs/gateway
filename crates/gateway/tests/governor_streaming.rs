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

//! Live-socket evidence for a Governor lease that expires during a streaming request body.
//!
//! Responsible for: quota refusal after verified progress, handler cancellation and rollback,
//! unread socket bytes, connection close, the remaining-quota control, and permit reuse.
//! NOT responsible for: pre-body Governor rates or request-body idle policy.
//! Upstream: the verified streaming request fixture. Downstream: c-ing-0064.

#![allow(clippy::expect_used, clippy::panic)]

use super::streaming_request::{StreamingOutput, StreamingPut, live_server, stop, streaming_route};
use super::throughput_request::{signed_chunked_request, signed_chunked_request_with_chunk_bytes};
use crate::support;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::BodyExt;
use rustfs_gateway::{
    BodyQuota, BodyQuotaExceeded, BoxFuture, Governor, GovernorRequest, Handler, HandlerCancellation, HandlerError,
    HandlerResult, Lease, Req, Resp, ServiceConfig, VerifiedBodyProgress,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct ProgressQuota {
    active: Arc<AtomicUsize>,
    checks: Arc<AtomicUsize>,
    refuse_after: Option<usize>,
}

impl BodyQuota for ProgressQuota {
    fn check(&self, progress: VerifiedBodyProgress) -> Result<(), BodyQuotaExceeded> {
        assert!(progress.newly_verified_bytes() > 0);
        assert!(progress.verified_bytes() >= progress.newly_verified_bytes());
        let check = self.checks.fetch_add(1, Ordering::AcqRel) + 1;
        if self.refuse_after.is_some_and(|accepted| check > accepted) {
            Err(BodyQuotaExceeded::new())
        } else {
            Ok(())
        }
    }
}

impl Drop for ProgressQuota {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

struct SequencedGovernor {
    active: Arc<AtomicUsize>,
    admissions: AtomicUsize,
    checks: Arc<AtomicUsize>,
}

impl SequencedGovernor {
    fn new() -> Self {
        Self {
            active: Arc::new(AtomicUsize::new(0)),
            admissions: AtomicUsize::new(0),
            checks: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl Governor for SequencedGovernor {
    fn try_acquire<'a>(&'a self, _request: &'a GovernorRequest<'a>) -> BoxFuture<'a, Result<Lease, ()>> {
        let admitted = self
            .active
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        let ordinal = self.admissions.fetch_add(usize::from(admitted), Ordering::AcqRel);
        let active = Arc::clone(&self.active);
        let checks = Arc::clone(&self.checks);
        Box::pin(async move {
            if !admitted {
                return Err(());
            }
            let refuse_after = (ordinal == 0).then_some(1);
            Ok(Lease::admit().with_body_quota(ProgressQuota {
                active,
                checks,
                refuse_after,
            }))
        })
    }
}

struct PanickingQuota;

impl BodyQuota for PanickingQuota {
    fn check(&self, _progress: VerifiedBodyProgress) -> Result<(), BodyQuotaExceeded> {
        panic!("deployment quota panic")
    }
}

struct PanickingGovernor;

impl Governor for PanickingGovernor {
    fn try_acquire<'a>(&'a self, _request: &'a GovernorRequest<'a>) -> BoxFuture<'a, Result<Lease, ()>> {
        Box::pin(async { Ok(Lease::admit().with_body_quota(PanickingQuota)) })
    }
}

struct RollbackBackend {
    entered: AtomicUsize,
    cancellation: Mutex<Option<HandlerCancellation>>,
    rolled_back: AtomicBool,
    committed: AtomicBool,
    persisted_bytes: AtomicUsize,
}

impl RollbackBackend {
    fn new() -> Self {
        Self {
            entered: AtomicUsize::new(0),
            cancellation: Mutex::new(None),
            rolled_back: AtomicBool::new(false),
            committed: AtomicBool::new(false),
            persisted_bytes: AtomicUsize::new(0),
        }
    }

    fn rollback(&self, reason: HandlerCancellation) -> HandlerResult<StreamingPut> {
        *self.cancellation.lock().expect("not poisoned") = Some(reason);
        self.persisted_bytes.store(0, Ordering::Release);
        self.rolled_back.store(true, Ordering::Release);
        Err(HandlerError::internal_error("the quota-refused upload rolled back"))
    }
}

impl Handler<StreamingPut> for RollbackBackend {
    async fn call(&self, _request: Req<StreamingPut>) -> HandlerResult<StreamingPut> {
        Err(HandlerError::internal_error("the context-aware entry was bypassed"))
    }

    async fn call_with_context(
        &self,
        request: Req<StreamingPut>,
        context: rustfs_gateway::HandlerContext,
    ) -> HandlerResult<StreamingPut> {
        self.entered.fetch_add(1, Ordering::AcqRel);
        let mut staged = 0_usize;
        let mut body = request.into_input().body.into_body();
        loop {
            tokio::select! {
                biased;
                reason = context.cancelled() => return self.rollback(reason),
                frame = body.frame() => match frame {
                    Some(Ok(frame)) => {
                        if let Ok(bytes) = frame.into_data() {
                            staged = staged.saturating_add(bytes.len());
                        }
                    }
                    Some(Err(_)) => {
                        let reason = tokio::time::timeout(Duration::from_secs(1), context.cancelled())
                            .await
                            .expect("a quota stream error is paired with cancellation");
                        return self.rollback(reason);
                    }
                    None => {
                        self.persisted_bytes.store(staged, Ordering::Release);
                        self.committed.store(true, Ordering::Release);
                        return Ok(Resp::new(StreamingOutput));
                    }
                }
            }
        }
    }
}

fn service<G: Governor>(backend: Arc<RollbackBackend>, governor: Arc<G>) -> rustfs_gateway::S3Service {
    let (builder, _handle) = support::wired()
        .clock_with_skew_ack(
            support::fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<StreamingPut, _>(backend)
        .route(streaming_route())
        .governor(governor)
        .config(ServiceConfig::new(4 * 1024 * 1024));
    builder.build().expect("a complete streaming assembly")
}

/// Negative — a deployment quota panic is contained as the same closing refusal and cancellation.
#[tokio::test]
async fn a_body_quota_panic_fails_closed() {
    let backend = Arc::new(RollbackBackend::new());
    let running = live_server(service(Arc::clone(&backend), Arc::new(PanickingGovernor)));

    let response = control(running.local_addr).await;

    assert!(response.starts_with("HTTP/1.1 503"), "{response}");
    assert_eq!(*backend.cancellation.lock().expect("not poisoned"), Some(HandlerCancellation::BodyQuota));
    assert!(backend.rolled_back.load(Ordering::Acquire));
    stop(running).await;
}

async fn control(address: std::net::SocketAddr) -> String {
    let (head, wire) = signed_chunked_request(4 * 256);
    let mut stream = TcpStream::connect(address).await.expect("the control connects");
    stream.write_all(&head).await.expect("the control head writes");
    stream.write_all(&wire).await.expect("the control body writes");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .expect("the control completes")
        .expect("the control response reads");
    String::from_utf8(response).expect("an HTTP/1.1 response")
}

/// `c-ing-0064`. Negative — a lease that refuses after verified progress cancels bounded rollback,
/// commits no partial state, leaves the remaining live body unread, closes, and releases its permit
/// for a control upload whose quota remains available.
#[tokio::test]
async fn c_ing_0064_mid_body_governor_refusal_cancels_rolls_back_and_closes() {
    const DECODED_BYTES: usize = 2 * 1024 * 1024;

    let governor = Arc::new(SequencedGovernor::new());
    let backend = Arc::new(RollbackBackend::new());
    let running = live_server(service(Arc::clone(&backend), Arc::clone(&governor)));
    let (head, wire) = signed_chunked_request_with_chunk_bytes(DECODED_BYTES, 64 * 1024);
    let wire_len = wire.len();
    let standard = std::net::TcpStream::connect(running.local_addr).expect("the upload connects");
    socket2::SockRef::from(&standard)
        .set_send_buffer_size(8 * 1024)
        .expect("the client send buffer is bounded");
    standard.set_nonblocking(true).expect("the socket becomes asynchronous");
    let mut stream = TcpStream::from_std(standard).expect("tokio adopts the socket");
    stream.write_all(&head).await.expect("the signed head writes");
    let (mut reader, mut writer) = stream.into_split();
    let sent = Arc::new(AtomicUsize::new(0));
    let feeder_sent = Arc::clone(&sent);
    let feeder = tokio::spawn(async move {
        for chunk in wire.chunks(4096) {
            if writer.write_all(chunk).await.is_err() {
                break;
            }
            feeder_sent.fetch_add(chunk.len(), Ordering::AcqRel);
        }
    });

    let mut response = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(2), reader.read_to_end(&mut response))
        .await
        .expect("the quota refusal closes the connection");
    if let Err(error) = read {
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset, "the refusal read failed unexpectedly");
    }
    tokio::time::timeout(Duration::from_secs(1), feeder)
        .await
        .expect("closing the connection stops the live writer")
        .expect("the writer task joins");
    let text = String::from_utf8(response).expect("an HTTP/1.1 response");
    assert!(text.starts_with("HTTP/1.1 503"), "{text}");
    assert!(text.to_ascii_lowercase().contains("connection: close"), "{text}");
    assert!(governor.checks.load(Ordering::Acquire) >= 2, "the lease never advanced after admission");
    assert!(sent.load(Ordering::Acquire) < wire_len, "the gateway drained the remaining upload");
    assert_eq!(*backend.cancellation.lock().expect("not poisoned"), Some(HandlerCancellation::BodyQuota));
    assert!(backend.rolled_back.load(Ordering::Acquire));
    assert!(!backend.committed.load(Ordering::Acquire));
    assert_eq!(backend.persisted_bytes.load(Ordering::Acquire), 0);

    let control_response = control(running.local_addr).await;
    assert!(control_response.starts_with("HTTP/1.1 200"), "{control_response}");
    assert_eq!(backend.entered.load(Ordering::Acquire), 2);
    assert_eq!(governor.active.load(Ordering::Acquire), 0, "the completed control leaked its permit");
    stop(running).await;
}
