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

//! Measures POST Object throughput through the production service and streaming adapter.
//!
//! Responsible for: identical binary uploads at several transport frame sizes and ready/Pending
//! schedules. NOT responsible for socket, disk, signed-policy performance or a timing CI gate.
//! Upstream: the S3Service public API. Downstream: manually compared benchmark output.
//!
//! Run with `cargo bench -p rustfs-gateway --bench post_object`. Payload creation, frame slicing,
//! service construction and exact-content validation happen before timing. Timed requests include
//! request construction, service dispatch, backend frame consumption and response draining.

use std::convert::Infallible;
use std::error::Error;
use std::hint::black_box;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body::{Body, Frame};
use http_body_util::BodyExt;
use rustfs_gateway::dto::{PostObject, PostObjectOutput};
use rustfs_gateway::{
    Handler, HandlerError, HandlerResult, RegionSet, Req, Resp, S3Service, ServiceBuilder, SigV4Authenticator, StaticCredentials,
    allow_when,
};

const BOUNDARY: &str = "gateway-post-benchmark";
const FILE_BYTES: usize = 4 * 1024 * 1024;
const REPETITIONS: usize = 16;

struct Backend {
    expected: Bytes,
    validate: AtomicBool,
    received: AtomicUsize,
}

impl Handler<PostObject> for Backend {
    async fn call(&self, request: Req<PostObject>) -> HandlerResult<PostObject> {
        let validate = self.validate.load(Ordering::Relaxed);
        let mut body = request.into_input().body.into_body();
        let mut count = 0;
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| HandlerError::internal_error("the benchmark file stream failed"))?;
            if let Ok(bytes) = frame.into_data() {
                if validate && self.expected.get(count..count + bytes.len()) != Some(bytes.as_ref()) {
                    return Err(HandlerError::internal_error("the benchmark file content changed"));
                }
                count += black_box(bytes.as_ref()).len();
            }
        }
        self.received.store(count, Ordering::Relaxed);
        if count != self.expected.len() {
            return Err(HandlerError::internal_error("the benchmark file length changed"));
        }
        Ok(Resp::new(PostObjectOutput {
            e_tag: None,
            version_id: None,
        }))
    }
}

struct Frames {
    chunks: Arc<[Bytes]>,
    position: usize,
    suspend: bool,
    pending: bool,
}

impl Body for Frames {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if self.position == self.chunks.len() {
            return Poll::Ready(None);
        }
        if self.pending {
            self.pending = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let chunk = self.chunks[self.position].clone();
        self.position += 1;
        self.pending = self.suspend;
        Poll::Ready(Some(Ok(Frame::data(chunk))))
    }
}

fn fixture() -> (Bytes, Bytes) {
    let mut wire = format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nupload\r\n\
         --{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"binary\"\r\n\r\n"
    )
    .into_bytes();
    let start = wire.len();
    // A fixed seed makes every frame schedule see the same full-range binary content.
    let mut state = 0x8197_4821_u32;
    for _ in 0..FILE_BYTES {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        wire.push(state as u8);
    }
    wire.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    let wire = Bytes::from(wire);
    let file = wire.slice(start..start + FILE_BYTES);
    (wire, file)
}

async fn exchange(service: &S3Service, backend: &Backend, chunks: Arc<[Bytes]>, suspend: bool) -> Result<(), Box<dyn Error>> {
    backend.received.store(0, Ordering::Relaxed);
    let request = Request::builder()
        .method("POST")
        .uri("http://host.invalid/example-bucket")
        .header("host", "host.invalid")
        .header("content-type", format!("multipart/form-data; boundary={BOUNDARY}"))
        .body(Frames {
            chunks,
            position: 0,
            suspend,
            pending: suspend,
        })?;
    let response = service.call(request).await;
    let status = response.status();
    let response_bytes = response.into_body().collect().await?.to_bytes();
    if status != StatusCode::NO_CONTENT || !response_bytes.is_empty() || backend.received.load(Ordering::Relaxed) != FILE_BYTES {
        return Err(io::Error::other(format!("benchmark upload failed: status={status}")).into());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let (wire, file) = fixture();
    println!("POST Object production service; file_bytes={FILE_BYTES}; repetitions={REPETITIONS}; no socket or storage IO");
    println!("frame_bytes,delivery,elapsed_ms,MiB_per_second");
    for frame_bytes in [1024, 8192, 65536, 1024 * 1024] {
        let chunks: Arc<[Bytes]> = (0..wire.len())
            .step_by(frame_bytes)
            .map(|start| wire.slice(start..(start + frame_bytes).min(wire.len())))
            .collect();
        for suspend in [false, true] {
            let backend = Arc::new(Backend {
                expected: file.clone(),
                validate: AtomicBool::new(true),
                received: AtomicUsize::new(0),
            });
            let service = ServiceBuilder::new()
                .register::<PostObject, _>(Arc::clone(&backend))
                .authenticator(SigV4Authenticator::new(
                    Arc::new(StaticCredentials::new()),
                    RegionSet::new(["us-east-1"])?,
                ))
                .authorizer(allow_when(|_| true))
                .build()?;
            runtime.block_on(exchange(&service, &backend, Arc::clone(&chunks), suspend))?;
            backend.validate.store(false, Ordering::Relaxed);
            let start = Instant::now();
            runtime.block_on(async {
                for _ in 0..REPETITIONS {
                    exchange(&service, &backend, Arc::clone(&chunks), suspend).await?;
                }
                Ok::<_, Box<dyn Error>>(())
            })?;
            let elapsed = start.elapsed().as_secs_f64();
            let throughput = (FILE_BYTES * REPETITIONS) as f64 / (1024.0 * 1024.0) / elapsed;
            println!(
                "{frame_bytes},{},{:.3},{throughput:.2}",
                if suspend { "pending" } else { "ready" },
                elapsed * 1000.0
            );
        }
    }
    Ok(())
}
