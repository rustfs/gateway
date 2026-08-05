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

//! Scripted producers and drain helpers shared by the test modules.
//!
//! Responsible for: producers whose event sequence — including a truncation, a mid-body
//! failure, and a `Pending` — is written out in the test, and the two drivers that run a body
//! to its end without a runtime.
//! NOT responsible for: asserting anything. Every assertion lives in the module that owns the
//! behaviour under test.
//! Upstream: the crate's own traits. Downstream: the sibling test modules only.

use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use std::collections::VecDeque;

use bytes::Bytes;
use http::HeaderMap;
use http::header::{HeaderName, HeaderValue};

use crate::caps::PayloadCaps;
use crate::error::{StreamError, StreamErrorKind};
use crate::read::{AsyncPayloadRead, BoxPayloadReader, ReadProgress};
use crate::stream::{BoxPayloadStream, PayloadRead, PayloadStream};
use crate::trailers::TrailingHeaders;

/// One scripted event.
#[derive(Debug)]
pub(crate) enum Step {
    /// Hand out these bytes.
    Chunk(&'static str),
    /// Report "not ready" once, then continue with the next step.
    Pending,
    /// End the body with this trailer section.
    Eof(TrailingHeaders),
    /// Fail with this reason instead of ending the body.
    Fail(StreamErrorKind),
}

/// A push-model producer that replays a written-out script.
pub(crate) struct ScriptedStream {
    steps: VecDeque<Step>,
    caps: PayloadCaps,
    len_hint: Option<u64>,
    produced: u64,
}

impl ScriptedStream {
    pub(crate) fn new(steps: impl IntoIterator<Item = Step>) -> Self {
        Self {
            steps: steps.into_iter().collect(),
            caps: PayloadCaps::PUSH,
            len_hint: None,
            produced: 0,
        }
    }

    pub(crate) fn with_caps(mut self, caps: PayloadCaps) -> Self {
        self.caps = caps;
        self
    }

    pub(crate) fn with_len_hint(mut self, len_hint: Option<u64>) -> Self {
        self.len_hint = len_hint;
        self
    }

    pub(crate) fn boxed(self) -> BoxPayloadStream {
        Box::pin(self)
    }
}

impl PayloadStream for ScriptedStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        let this = self.get_mut();
        match this.steps.pop_front() {
            Some(Step::Chunk(text)) => {
                this.produced = this.produced.saturating_add(text.len() as u64);
                Poll::Ready(Ok(PayloadRead::Chunk(Bytes::from_static(text.as_bytes()))))
            }
            Some(Step::Pending) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Some(Step::Eof(trailers)) => Poll::Ready(Ok(PayloadRead::Eof { trailers })),
            Some(Step::Fail(kind)) => Poll::Ready(Err(StreamError::new(kind).with_bytes_before_error(this.produced))),
            None => Poll::Ready(Err(StreamError::polled_after_eof().with_bytes_before_error(this.produced))),
        }
    }

    fn caps(&self) -> PayloadCaps {
        self.caps
    }

    fn len_hint(&self) -> Option<u64> {
        self.len_hint
    }
}

/// A pull-model producer that replays the same script shape.
pub(crate) struct ScriptedReader {
    steps: VecDeque<Step>,
    leftover: Bytes,
    caps: PayloadCaps,
    len_hint: Option<u64>,
    produced: u64,
}

impl ScriptedReader {
    pub(crate) fn new(steps: impl IntoIterator<Item = Step>) -> Self {
        Self {
            steps: steps.into_iter().collect(),
            leftover: Bytes::new(),
            caps: PayloadCaps::PULL,
            len_hint: None,
            produced: 0,
        }
    }

    pub(crate) fn with_caps(mut self, caps: PayloadCaps) -> Self {
        self.caps = caps;
        self
    }

    pub(crate) fn with_len_hint(mut self, len_hint: Option<u64>) -> Self {
        self.len_hint = len_hint;
        self
    }

    pub(crate) fn boxed(self) -> BoxPayloadReader {
        Box::pin(self)
    }
}

impl AsyncPayloadRead for ScriptedReader {
    fn poll_fill(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<ReadProgress, StreamError>> {
        use bytes::Buf as _;

        let this = self.get_mut();
        loop {
            if !this.leftover.is_empty() {
                let n = buf.len().min(this.leftover.len());
                buf[..n].copy_from_slice(&this.leftover[..n]);
                this.leftover.advance(n);
                this.produced = this.produced.saturating_add(n as u64);
                return Poll::Ready(Ok(ReadProgress::Filled(n)));
            }
            match this.steps.pop_front() {
                Some(Step::Chunk(text)) => {
                    this.leftover = Bytes::from_static(text.as_bytes());
                }
                Some(Step::Pending) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Some(Step::Eof(trailers)) => {
                    return Poll::Ready(Ok(ReadProgress::Eof { trailers }));
                }
                Some(Step::Fail(kind)) => {
                    return Poll::Ready(Err(StreamError::new(kind).with_bytes_before_error(this.produced)));
                }
                None => {
                    return Poll::Ready(Err(StreamError::polled_after_eof().with_bytes_before_error(this.produced)));
                }
            }
        }
    }

    fn caps(&self) -> PayloadCaps {
        self.caps
    }

    fn len_hint(&self) -> Option<u64> {
        self.len_hint
    }
}

/// Builds a trailer section from name/value pairs.
pub(crate) fn trailers(pairs: &[(&str, &str)]) -> TrailingHeaders {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        let name = HeaderName::from_bytes(name.as_bytes()).expect("test trailer name is valid");
        let value = HeaderValue::from_str(value).expect("test trailer value is valid");
        map.insert(name, value);
    }
    TrailingHeaders::from_header_map(map)
}

/// Looks a trailer field up by name.
pub(crate) fn trailer_value(trailers: &TrailingHeaders, name: &str) -> Option<String> {
    let name = HeaderName::from_bytes(name.as_bytes()).expect("test trailer name is valid");
    trailers
        .get(&name)
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
}

fn noop_context() -> Context<'static> {
    Context::from_waker(Waker::noop())
}

/// Runs a push-model body to its end, collecting the chunks and the trailer section.
pub(crate) fn drain_stream(mut stream: BoxPayloadStream) -> Result<(Vec<Bytes>, TrailingHeaders), StreamError> {
    let mut cx = noop_context();
    let mut chunks = Vec::new();
    loop {
        match stream.as_mut().poll_read(&mut cx) {
            Poll::Pending => continue,
            Poll::Ready(Err(err)) => return Err(err),
            Poll::Ready(Ok(PayloadRead::Chunk(chunk))) => chunks.push(chunk),
            Poll::Ready(Ok(PayloadRead::Eof { trailers })) => return Ok((chunks, trailers)),
        }
    }
}

/// Runs a pull-model body to its end through a buffer of `buf_size` bytes.
pub(crate) fn drain_reader(mut reader: BoxPayloadReader, buf_size: usize) -> Result<(Vec<u8>, TrailingHeaders), StreamError> {
    let mut cx = noop_context();
    let mut out = Vec::new();
    let mut buf = vec![0u8; buf_size];
    loop {
        match reader.as_mut().poll_fill(&mut cx, &mut buf) {
            Poll::Pending => continue,
            Poll::Ready(Err(err)) => return Err(err),
            Poll::Ready(Ok(ReadProgress::Filled(n))) => out.extend_from_slice(&buf[..n]),
            Poll::Ready(Ok(ReadProgress::Eof { trailers })) => return Ok((out, trailers)),
        }
    }
}

/// Polls a push-model body exactly once.
pub(crate) fn poll_stream_once(stream: &mut BoxPayloadStream) -> Poll<Result<PayloadRead, StreamError>> {
    let mut cx = noop_context();
    stream.as_mut().poll_read(&mut cx)
}

/// Polls a pull-model body exactly once.
pub(crate) fn poll_reader_once(reader: &mut BoxPayloadReader, buf: &mut [u8]) -> Poll<Result<ReadProgress, StreamError>> {
    let mut cx = noop_context();
    reader.as_mut().poll_fill(&mut cx, buf)
}

/// Concatenates the chunks of a drained push-model body.
pub(crate) fn joined(chunks: &[Bytes]) -> Vec<u8> {
    chunks.iter().flat_map(|c| c.iter().copied()).collect()
}
