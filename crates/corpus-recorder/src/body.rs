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

//! Responsible for: the passive request-body tap, and the per-request capture that turns into a
//! record when its last holder — the tap or the response future — lets go.
//! Not responsible for: routing (`classify`), redaction or writing (`writer`).
//! Upstream: `layer::CorpusRecorderService::call`, which wraps every request body in a
//! [`TapBody`].
//! Downstream: the inner service, which reads the tap exactly as it would have read the body,
//! and `writer::Sink`.
//!
//! The tap never polls on its own, never buffers ahead, and never alters a frame: it copies the
//! bytes of each data frame the inner service pulls, and hands the frame on untouched. So pull
//! order, backpressure, frame boundaries and the terminal outcome the service sees are the ones
//! it would have seen without the recorder. Only the copy is bounded; the pass-through is not.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use pin_project_lite::pin_project;

use crate::writer::{RawRecord, ResponseHead, Sink};

/// The head of a request being recorded, captured before the inner service saw it.
pub(crate) struct Head {
    pub(crate) op: &'static str,
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) headers: Vec<(String, String)>,
}

/// What became of the request body.
enum BodyOutcome {
    /// The service stopped reading before the end, or the body failed.
    Unobserved,
    /// The whole body, as the service received it.
    Complete(Vec<u8>),
    /// A cap was reached; nothing of the body is kept.
    OverCap,
}

/// One request's recording, shared by its body tap and its response future.
pub(crate) struct Capture {
    head: Mutex<Option<Head>>,
    body: Mutex<BodyOutcome>,
    response: Mutex<Option<ResponseHead>>,
    sink: Arc<Sink>,
}

impl Capture {
    pub(crate) fn new(head: Head, sink: Arc<Sink>) -> Arc<Self> {
        Arc::new(Self {
            head: Mutex::new(Some(head)),
            body: Mutex::new(BodyOutcome::Unobserved),
            response: Mutex::new(None),
            sink,
        })
    }

    pub(crate) fn sink(&self) -> &Sink {
        &self.sink
    }

    pub(crate) fn set_response(&self, status: u16, headers: Vec<(String, String)>) {
        if let Ok(mut slot) = self.response.lock() {
            *slot = Some((status, headers));
        }
    }

    fn set_body(&self, outcome: BodyOutcome) {
        if let Ok(mut slot) = self.body.lock() {
            *slot = outcome;
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        let Some(head) = self.head.get_mut().ok().and_then(Option::take) else {
            return;
        };
        let body = match self
            .body
            .get_mut()
            .map(|slot| std::mem::replace(slot, BodyOutcome::Unobserved))
        {
            Ok(BodyOutcome::Complete(bytes)) => Some(bytes),
            Ok(BodyOutcome::Unobserved | BodyOutcome::OverCap) | Err(_) => {
                self.sink
                    .counters
                    .body_not_recorded
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                None
            }
        };
        // A head that declares a body, with no body recorded, would be written as an entry that
        // claims a request no client sent (its Content-Length over nothing) and replays as one.
        // It is counted above and not written; a head that declares no body is still worth its
        // route and response.
        if body.is_none() && declares_body(&head.headers) {
            return;
        }
        let reserved = body.as_ref().map_or(0, Vec::len);
        let response = self.response.get_mut().ok().and_then(Option::take);
        self.sink.submit(RawRecord {
            op: head.op,
            method: head.method,
            target: head.target,
            headers: head.headers,
            body,
            response,
        });
        self.sink.release(reserved);
    }
}

/// Whether a request head declares a body: a non-zero `Content-Length`, or any
/// `Transfer-Encoding`.
fn declares_body(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("transfer-encoding") || (name.eq_ignore_ascii_case("content-length") && value.trim() != "0")
    })
}

/// The copy the tap is accumulating.
struct Copy {
    capture: Arc<Capture>,
    bytes: Vec<u8>,
    over_cap: bool,
    finished: bool,
}

impl Copy {
    fn observe(&mut self, data: &[u8]) {
        if self.over_cap || self.finished {
            return;
        }
        let sink = self.capture.sink();
        if self.bytes.len() + data.len() > sink.max_body_bytes || !sink.reserve(data.len()) {
            sink.release(self.bytes.len());
            self.bytes = Vec::new();
            self.over_cap = true;
            return;
        }
        self.bytes.extend_from_slice(data);
    }

    fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        if self.over_cap {
            self.capture.set_body(BodyOutcome::OverCap);
        } else {
            // The reservation moves with the bytes and is returned when the record is submitted.
            self.capture.set_body(BodyOutcome::Complete(std::mem::take(&mut self.bytes)));
        }
    }
}

impl Drop for Copy {
    fn drop(&mut self) {
        if !self.finished {
            self.capture.sink().release(self.bytes.len());
        }
    }
}

pin_project! {
    /// A request body that the recorder observes on its way to the inner service.
    ///
    /// Every frame is handed on unchanged; a data frame's bytes are also copied, up to the
    /// recorder's caps. A request the recorder does not record carries no copy at all.
    pub struct TapBody<B> {
        #[pin]
        inner: B,
        copy: Option<Copy>,
    }
}

impl<B: Body> TapBody<B> {
    pub(crate) fn passthrough(inner: B) -> Self {
        Self { inner, copy: None }
    }

    pub(crate) fn recording(inner: B, capture: Arc<Capture>) -> Self {
        let mut copy = Copy {
            capture,
            bytes: Vec::new(),
            over_cap: false,
            finished: false,
        };
        if inner.is_end_stream() {
            copy.finish();
        }
        Self { inner, copy: Some(copy) }
    }
}

impl<B> Body for TapBody<B>
where
    B: Body<Data = Bytes>,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        let polled = this.inner.as_mut().poll_frame(context);
        if let Some(copy) = this.copy.as_mut() {
            match &polled {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        copy.observe(data);
                    }
                    // A consumer may stop at `is_end_stream` without polling for the `None`.
                    if this.inner.is_end_stream() {
                        copy.finish();
                    }
                }
                // A clean end of stream is the only thing that makes the copy a whole body.
                Poll::Ready(None) => copy.finish(),
                // A failed body was not observed whole; the copy is dropped with the tap.
                Poll::Ready(Some(Err(_))) | Poll::Pending => {}
            }
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
