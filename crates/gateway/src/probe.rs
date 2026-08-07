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

//! A request body that reports how much of itself the service asked for.
//!
//! Responsible for: [`ObservedBody`] and [`BodyProgress`] — a request body assembled from frames
//! already in memory, which counts the bytes it handed over and records whether it was ever read
//! to its end.
//! NOT responsible for: producing bytes from anywhere but memory, pacing them, or judging
//! anything. It is an instrument, not a transport.
//! Upstream: nothing. Downstream: `crate::service` through `S3Service::call`, and the conformance
//! runner, which needs it to answer `expect.request_progress` honestly.
//!
//! # Why this is public API and not a test fixture
//!
//! `conformance/case.schema.json` has an assertion family — `request_progress` — whose whole
//! subject is *when* the server stopped needing the payload. Judging it needs a body the server
//! pulls from, and the only entry point a foreign implementation has to this framework is the
//! facade. A body that lives in this crate's `tests/` directory can prove the pipeline is right;
//! it cannot let the suite that ships to other implementations measure it. So the instrument is
//! published, with the narrow shape that keeps it an instrument: frames from memory, two counters,
//! no pacing, no failure injection.
//!
//! It is not a substitute for a socket. On a real connection, "bytes the client had written when
//! the response head arrived" and "bytes the server pulled" are two numbers, and a client can be
//! ahead of the server by a whole receive window. In process they are one number, and it is the
//! server-side one — the tighter of the two, and the one a case about early refusal is asking
//! about.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bytes::Bytes;

/// What an [`ObservedBody`] recorded, readable while the body is still being read.
///
/// Shared with the body behind an `Arc`, so a caller keeps its handle after handing the body to
/// the service — which is the only order in which the counters are worth anything.
#[derive(Debug, Default)]
pub struct BodyProgress {
    bytes_read: AtomicU64,
    exhausted: AtomicBool,
}

impl BodyProgress {
    /// How many payload bytes the consumer has taken so far.
    #[must_use]
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read.load(Ordering::SeqCst)
    }

    /// Whether the consumer read on until the body said there was nothing left.
    ///
    /// False while frames remain, and false forever if the consumer stopped early — which is what
    /// a refusal before the payload was needed looks like from here.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.exhausted.load(Ordering::SeqCst)
    }
}

/// A request body whose consumption is observable.
///
/// Frames are handed over in the order they were given, one per poll, so a consumer that stops
/// after the third frame is distinguishable from one that drained all ten.
#[derive(Debug)]
pub struct ObservedBody {
    frames: std::collections::VecDeque<Bytes>,
    progress: Arc<BodyProgress>,
}

impl ObservedBody {
    /// A body over the given frames, plus the handle that watches it.
    #[must_use]
    pub fn new(frames: impl IntoIterator<Item = Bytes>) -> (Self, Arc<BodyProgress>) {
        let progress = Arc::new(BodyProgress::default());
        (
            Self {
                frames: frames.into_iter().collect(),
                progress: Arc::clone(&progress),
            },
            progress,
        )
    }

    /// The total the frames add up to, which is what a `Content-Length` over them would say.
    #[must_use]
    pub fn declared_length(&self) -> u64 {
        self.frames.iter().map(|frame| frame.len() as u64).sum()
    }
}

impl http_body::Body for ObservedBody {
    type Data = Bytes;
    type Error = core::convert::Infallible;

    fn poll_frame(
        self: core::pin::Pin<&mut Self>,
        _context: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        match this.frames.pop_front() {
            Some(frame) => {
                // Counted as it is handed over, not as it is produced: the number has to mean "the
                // consumer has these bytes", or a case about early refusal reads the wrong way.
                this.progress.bytes_read.fetch_add(frame.len() as u64, Ordering::SeqCst);
                core::task::Poll::Ready(Some(Ok(http_body::Frame::data(frame))))
            }
            None => {
                this.progress.exhausted.store(true, Ordering::SeqCst);
                core::task::Poll::Ready(None)
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    /// Positive — a fully drained body reports every byte and says so.
    #[tokio::test]
    async fn a_drained_body_reports_its_whole_length() {
        let (body, progress) = ObservedBody::new([Bytes::from_static(b"ab"), Bytes::from_static(b"cde")]);
        assert_eq!(body.declared_length(), 5);
        let collected = body.collect().await.expect("infallible").to_bytes();
        assert_eq!(collected, Bytes::from_static(b"abcde"));
        assert_eq!(progress.bytes_read(), 5);
        assert!(progress.is_exhausted());
    }

    /// Negative — a body nobody polled reports nothing, and is not exhausted. This is the reading
    /// that makes "the server refused before it needed the payload" a measurement.
    #[test]
    fn an_unread_body_reports_nothing() {
        let (_body, progress) = ObservedBody::new([Bytes::from_static(b"ab")]);
        assert_eq!(progress.bytes_read(), 0);
        assert!(!progress.is_exhausted());
    }

    /// Negative — a consumer that stops after one frame is distinguishable from one that finished.
    #[tokio::test]
    async fn a_consumer_that_stops_early_leaves_the_body_unexhausted() {
        let (mut body, progress) = ObservedBody::new([Bytes::from_static(b"ab"), Bytes::from_static(b"cd")]);
        let _first = body.frame().await.expect("a frame").expect("infallible");
        drop(body);
        assert_eq!(progress.bytes_read(), 2);
        assert!(!progress.is_exhausted());
    }
}
