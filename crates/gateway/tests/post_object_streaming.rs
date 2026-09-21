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

//! Production POST Object streaming ownership, failure, and allocation regressions.
//!
//! Responsible for: observing the bytes and ownership the real handler receives under fragmented
//! input, and measuring adapter allocations in an isolated process. NOT responsible for MIME
//! grammar or policy signature vectors. Upstream: S3Service. Downstream: no runtime consumers.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body::{Body, Frame};
use http_body_util::BodyExt;
use rustfs_gateway::dto::{PostObject, PostObjectOutput};
use rustfs_gateway::{Handler, HandlerError, HandlerResult, Req, Resp, S3Service};

use crate::support;

const BOUNDARY: &str = "gateway-stream-probe";
const PROBE_ENV: &str = "RUSTFS_GATEWAY_POST_ALLOCATION_PROBE";
const PROBE_TEST: &str = "post_object_streaming::the_production_adapter_does_not_copy_each_file_frame";
const SENTINEL: &str = "post adapter allocation: ";

struct Probe {
    expected: Bytes,
    copied: AtomicUsize,
    received: AtomicUsize,
    failures: AtomicUsize,
    failed_after: AtomicUsize,
}

impl Probe {
    fn new(expected: Bytes) -> Self {
        Self {
            expected,
            copied: AtomicUsize::new(0),
            received: AtomicUsize::new(0),
            failures: AtomicUsize::new(0),
            failed_after: AtomicUsize::new(0),
        }
    }
}

impl Handler<PostObject> for Probe {
    async fn call(&self, request: Req<PostObject>) -> HandlerResult<PostObject> {
        let mut body = request.into_input().body.into_body();
        let mut count = 0usize;
        let mut copied = 0usize;
        while let Some(frame) = body.frame().await {
            let frame = match frame {
                Ok(frame) => frame,
                Err(_) => {
                    self.failures.fetch_add(1, Ordering::Relaxed);
                    self.failed_after.store(count, Ordering::Relaxed);
                    return Err(HandlerError::internal_error("the observed file stream failed"));
                }
            };
            if let Ok(bytes) = frame.into_data() {
                let expected = self.expected.get(count..count + bytes.len()).expect("no extra file bytes");
                assert_eq!(bytes.as_ref(), expected, "file bytes must survive every split");
                if bytes.as_ptr() != expected.as_ptr() {
                    copied += bytes.len();
                }
                count += bytes.len();
            }
        }
        assert_eq!(count, self.expected.len(), "a successful handler must consume the whole file");
        self.received.store(count, Ordering::Relaxed);
        self.copied.store(copied, Ordering::Relaxed);
        Ok(Resp::new(PostObjectOutput {
            e_tag: None,
            version_id: None,
        }))
    }
}

struct Fragments {
    wire: Bytes,
    chunk: usize,
    suspend: bool,
    pending: bool,
}

impl Body for Fragments {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if self.wire.is_empty() {
            return Poll::Ready(None);
        }
        if self.pending {
            self.pending = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.pending = self.suspend;
        let take = self.chunk.min(self.wire.len());
        Poll::Ready(Some(Ok(Frame::data(self.wire.split_to(take)))))
    }
}

fn fixture(len: usize, tail: &str) -> (Bytes, Arc<Probe>, S3Service) {
    let mut wire = format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nupload\r\n\
         --{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f\"\r\n\r\n"
    )
    .into_bytes();
    let start = wire.len();
    // Full-range deterministic payload includes CR/LF and NUL, unlike text-only fixtures.
    let mut state = 0x8197_4821_u32;
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        wire.push(state as u8);
    }
    wire.extend_from_slice(tail.as_bytes());
    let wire = Bytes::from(wire);
    let backend = Arc::new(Probe::new(wire.slice(start..start + len)));
    let service = support::wired()
        .register::<PostObject, _>(Arc::clone(&backend))
        .build()
        .expect("POST service");
    (wire, backend, service)
}

fn closing() -> String {
    format!("\r\n--{BOUNDARY}--\r\n")
}

async fn exchange(service: &S3Service, wire: Bytes, chunk: usize, suspend: bool) -> StatusCode {
    let request = Request::builder()
        .method("POST")
        .uri("http://host.invalid/example-bucket")
        .header("host", "host.invalid")
        .header("content-type", format!("multipart/form-data; boundary={BOUNDARY}"))
        .body(Fragments {
            wire,
            chunk,
            suspend,
            pending: suspend,
        })
        .expect("POST request");
    let response = service.call(request).await;
    let status = response.status();
    response.into_body().collect().await.expect("response body");
    status
}

#[tokio::test]
async fn fragmented_uploads_preserve_content_and_share_large_input_frames() {
    for chunk in [1, 7, 4096, 16384, usize::MAX] {
        let len = if chunk < 4096 { 1024 } else { 256 * 1024 };
        let (wire, backend, service) = fixture(len, &closing());
        let frames = wire.len().div_ceil(chunk);
        for suspend in [false, true] {
            assert_eq!(exchange(&service, wire.clone(), chunk, suspend).await, StatusCode::NO_CONTENT);
            assert_eq!(backend.received.load(Ordering::Relaxed), len);
            if chunk >= 4096 {
                // The bounded prelude and one delimiter residue per frame may be copied. The
                // remaining payload must retain the transport allocation all the way to storage.
                let limits = rustfs_gateway_http::FormLimits::default();
                // Reading the key value can also buffer bytes beyond its terminator.
                let prelude = limits
                    .max_part_header_bytes()
                    .max(limits.max_field_bytes() + BOUNDARY.len() + 4);
                let allowance = prelude + frames * (BOUNDARY.len() + 4);
                let copied = backend.copied.load(Ordering::Relaxed);
                assert!(
                    copied <= allowance,
                    "chunk={chunk} pending={suspend}: copied {copied}, allowance {allowance}"
                );
            }
        }
    }
}

async fn rejected_tail(tail: &str, rejects_during_push: bool) {
    for chunk in [1, 7, 4096, usize::MAX] {
        let (wire, backend, service) = fixture(1024, tail);
        assert_eq!(exchange(&service, wire, chunk, true).await, StatusCode::BAD_REQUEST);
        assert_eq!(backend.failures.load(Ordering::Relaxed), 1, "the handler must observe the stream refusal");
        assert_eq!(
            backend.received.load(Ordering::Relaxed),
            0,
            "the handler must never complete successfully"
        );
        if chunk == usize::MAX && rejects_during_push {
            assert_eq!(
                backend.failed_after.load(Ordering::Relaxed),
                0,
                "a rejected push must not expose its buffered output"
            );
        }
    }
}

#[tokio::test]
async fn a_truncated_boundary_never_completes_the_upload() {
    rejected_tail(&format!("\r\n--{BOUNDARY}-"), false).await;
}

#[tokio::test]
async fn a_part_after_the_file_never_completes_the_upload() {
    rejected_tail(&format!("\r\n--{BOUNDARY}\r\n"), true).await;
}

#[tokio::test]
async fn an_invalid_boundary_marker_never_completes_the_upload() {
    rejected_tail(&format!("\r\n--{BOUNDARY}??"), true).await;
}

fn allocation_cost(len: usize) -> (u64, u64) {
    let (wire, backend, service) = fixture(len, &closing());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    assert_eq!(runtime.block_on(exchange(&service, wire.clone(), 8192, false)), StatusCode::NO_CONTENT);
    let profiler = dhat::Profiler::builder().testing().build();
    let status = runtime.block_on(exchange(&service, wire, 8192, false));
    let stats = dhat::HeapStats::get();
    drop(profiler);
    assert_eq!((status, backend.received.load(Ordering::Relaxed)), (StatusCode::NO_CONTENT, len));
    (stats.total_blocks, stats.total_bytes)
}

#[test]
fn the_production_adapter_does_not_copy_each_file_frame() {
    if let Some(sizes) = support::allocations::requested_sizes(PROBE_ENV) {
        for size in sizes {
            let (blocks, bytes) = allocation_cost(size);
            println!("{SENTINEL}{blocks} {bytes}");
        }
        return;
    }
    let sizes = [64 * 1024, 1024 * 1024];
    let rows = support::allocations::measure(PROBE_TEST, PROBE_ENV, SENTINEL, &sizes, 2);
    println!("POST adapter: {rows:?}");
    for row in &rows {
        assert!(row[0] >= 16 && row[1] >= 1024, "the allocation instrument must observe the real service");
    }
    // Allow small carry ownership, frame metadata and runtime variance, but not a payload copy.
    let growth = rows[1][1].saturating_sub(rows[0][1]);
    assert!(
        growth <= (sizes[1] - sizes[0]) as u64 / 8 + 16 * 1024,
        "adapter allocated {growth} extra bytes"
    );
}
