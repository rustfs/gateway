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

//! The two bounded reads permitted before signature verification.
//!
//! Responsible for: POST Object's text prelude and the RustFS profile's 8192-byte STS-scoped
//! body digest, retaining the latter's bytes for the ordinary proof-gated body handoff.
//! NOT responsible for: credential lookup, signature comparison or interpreting either body.
//! Upstream: `crate::service` and the built-in authenticator. Downstream: `super::SealedBody`
//! and `crate::wire_read`, which owns the frame ceilings and idle deadlines.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use http_body_util::Full;
use rustfs_gateway_core::BoxFuture;
use sha2::{Digest as _, Sha256};

use super::{BodyCeilings, BodyDigestObligation, BodyTimeouts, SealedBody};
use crate::render::S3Error;
use crate::wire_read::{WireFrames, WireProgress};

/// A private read offered only to the built-in authenticator, after credential lookup.
pub(crate) trait StsBodyReader: Send + Sync {
    /// Hashes at most 8192 body bytes and retains them for the authenticated handoff.
    fn digest(&self, timeouts: BodyTimeouts) -> BoxFuture<'_, Result<[u8; 32], S3Error>>;
}

impl<B> StsBodyReader for SealedBody<B>
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    fn digest(&self, timeouts: BodyTimeouts) -> BoxFuture<'_, Result<[u8; 32], S3Error>> {
        Box::pin(async move {
            let mut pending = self.body.lock().await;
            if let Some(result) = self.replay.get() {
                return result
                    .as_ref()
                    .as_ref()
                    .map(|bytes| Sha256::digest(bytes).into())
                    .map_err(Clone::clone);
            }
            if let Some(progress) = self.sts_progress.get() {
                return Err(progress.mark_refusal_if_unfinished(super::incomplete()));
            }
            let body = pending.take();
            let progress = WireProgress::for_body(BodyDigestObligation::None, body.as_ref());
            // Retained before polling: dropping this future must not turn a consumed body into EOF.
            let _ = self.sts_progress.set(progress.clone());
            let result = async {
                let mut bytes = BytesMut::new();
                if let Some(body) = body {
                    let ceilings = BodyCeilings {
                        buffered: 8192,
                        whole_body: true,
                        declared: None,
                    };
                    let mut frames = WireFrames::new(body, progress, ceilings, timeouts);
                    loop {
                        let frame = core::future::poll_fn(|context| frames.poll_next(context))
                            .await
                            .map_err(sts_body_refusal)?;
                        let Some(frame) = frame else { break };
                        bytes.put(frame);
                    }
                }
                Ok(bytes.freeze())
            }
            .await;
            let digest = result
                .as_ref()
                .map(|bytes| Sha256::digest(bytes).into())
                .map_err(Clone::clone);
            let _ = self.replay.set(Box::new(result));
            digest
        })
    }
}

/// Keep the reader's observed unfinished-body proof, replacing only its length-limit answer.
fn sts_body_refusal(refusal: S3Error) -> S3Error {
    if refusal.code() == Some(&rustfs_gateway_types::ErrorCode::ENTITY_TOO_LARGE) {
        let mut limit = crate::render::from_handler(
            rustfs_gateway_core::HandlerError::new(
                rustfs_gateway_types::ErrorCode::INVALID_REQUEST,
                "failed to read STS request body: length limit exceeded",
            ),
            rustfs_gateway_core::ResponseKind::Other,
            refusal.connection_intent(),
        );
        limit.body_unfinished = refusal.body_unfinished;
        return limit;
    }
    refusal
}

impl<B> SealedBody<B>
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    /// Reads only POST Object's bounded text prelude, leaving the file part unopened.
    pub(crate) async fn post_object_prelude(
        self,
        content_type: &str,
        form: crate::builder::view_policy::post_forms::PostFormRead,
        timeouts: BodyTimeouts,
    ) -> Result<crate::post_object::PostObjectPrelude<B>, S3Error> {
        crate::post_object::PostObjectPrelude::read_with_grammar(
            self.body.into_inner(),
            content_type,
            form.limits,
            form.grammar,
            timeouts,
        )
        .await
    }

    /// Consumed only by the ordinary body read, which still requires metadata admission.
    pub(super) fn into_body(self) -> Result<Option<ReplayBody<B>>, S3Error> {
        match self.replay.into_inner().map(|result| *result) {
            Some(Ok(bytes)) => Ok(Some(ReplayBody::Replay { body: Full::new(bytes) })),
            Some(Err(refusal)) => Err(refusal),
            None => match self.sts_progress.into_inner() {
                Some(progress) => Err(progress.mark_refusal_if_unfinished(super::incomplete())),
                None => Ok(self.body.into_inner().map(|body| ReplayBody::Original { body })),
            },
        }
    }
}

pin_project_lite::pin_project! {
    /// A body that was bounded and hashed for authentication is replayed without repolling the wire.
    #[project = ReplayBodyProjection]
    pub(super) enum ReplayBody<B> {
        Original { #[pin] body: B },
        Replay { #[pin] body: Full<Bytes> },
    }
}

impl<B> http_body::Body for ReplayBody<B>
where
    B: http_body::Body,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Data = ReplayData<B::Data>;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: core::pin::Pin<&mut Self>,
        context: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        match self.project() {
            ReplayBodyProjection::Original { body } => body
                .poll_frame(context)
                .map(|frame| frame.map(|frame| frame.map(|frame| frame.map_data(ReplayData::Original)).map_err(Into::into))),
            ReplayBodyProjection::Replay { body } => body
                .poll_frame(context)
                .map(|frame| frame.map(|frame| frame.map(|frame| frame.map_data(ReplayData::Replay)).map_err(Into::into))),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Original { body } => body.is_end_stream(),
            Self::Replay { body } => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            Self::Original { body } => body.size_hint(),
            Self::Replay { body } => body.size_hint(),
        }
    }
}

/// Preserves an original frame until `WireFrames` checks its length before any copying.
pub(super) enum ReplayData<D> {
    Original(D),
    Replay(Bytes),
}

impl<D: Buf> Buf for ReplayData<D> {
    fn remaining(&self) -> usize {
        match self {
            Self::Original(data) => data.remaining(),
            Self::Replay(data) => data.remaining(),
        }
    }

    fn chunk(&self) -> &[u8] {
        match self {
            Self::Original(data) => data.chunk(),
            Self::Replay(data) => data.chunk(),
        }
    }

    fn advance(&mut self, count: usize) {
        match self {
            Self::Original(data) => data.advance(count),
            Self::Replay(data) => data.advance(count),
        }
    }

    fn copy_to_bytes(&mut self, count: usize) -> Bytes {
        match self {
            Self::Original(data) => data.copy_to_bytes(count),
            Self::Replay(data) => data.copy_to_bytes(count),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)] // Test assertions deliberately panic on unexpected results.
mod tests {
    use std::convert::Infallible;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use futures_util::FutureExt;
    use rustfs_gateway_http::BodyIntegrity;
    use rustfs_gateway_types::ErrorCode;

    use super::*;
    use crate::gate::MetadataAdmission;

    struct OpenBody {
        frame: Option<Bytes>,
        polls: Arc<AtomicUsize>,
    }

    impl http_body::Body for OpenBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            self: core::pin::Pin<&mut Self>,
            _context: &mut core::task::Context<'_>,
        ) -> core::task::Poll<Option<Result<http_body::Frame<Bytes>, Infallible>>> {
            let this = self.get_mut();
            this.polls.fetch_add(1, Ordering::SeqCst);
            match this.frame.take() {
                Some(bytes) => core::task::Poll::Ready(Some(Ok(http_body::Frame::data(bytes)))),
                None => core::task::Poll::Pending,
            }
        }
    }

    fn body(bytes: Bytes) -> (SealedBody<OpenBody>, Arc<AtomicUsize>) {
        let polls = Arc::new(AtomicUsize::new(0));
        let sealed = SealedBody::seal(
            Some(OpenBody {
                frame: Some(bytes.clone()),
                polls: Arc::clone(&polls),
            }),
            Some(bytes.len() as u64),
        );
        (sealed, polls)
    }

    struct CopyingBuf {
        bytes: Bytes,
        copied: Arc<AtomicUsize>,
    }

    impl Buf for CopyingBuf {
        fn remaining(&self) -> usize {
            self.bytes.remaining()
        }

        fn chunk(&self) -> &[u8] {
            self.bytes.chunk()
        }

        fn advance(&mut self, count: usize) {
            self.bytes.advance(count);
        }

        fn copy_to_bytes(&mut self, count: usize) -> Bytes {
            let source = self.bytes.split_to(count);
            let copy = Bytes::copy_from_slice(&source);
            self.copied.fetch_add(copy.len(), Ordering::SeqCst);
            copy
        }
    }

    struct CopiedBody(Option<CopyingBuf>);

    impl http_body::Body for CopiedBody {
        type Data = CopyingBuf;
        type Error = Infallible;

        fn poll_frame(
            self: core::pin::Pin<&mut Self>,
            _context: &mut core::task::Context<'_>,
        ) -> core::task::Poll<Option<Result<http_body::Frame<CopyingBuf>, Infallible>>> {
            core::task::Poll::Ready(self.get_mut().0.take().map(|bytes| Ok(http_body::Frame::data(bytes))))
        }
    }

    /// Negative — a refused generic buffer is not copied; the accepted control observes a real copy.
    #[tokio::test]
    async fn n_an_oversized_sts_frame_is_refused_before_copying_its_buffer() {
        for size in [3, 8193] {
            let copied = Arc::new(AtomicUsize::new(0));
            let sealed = SealedBody::seal(
                Some(CopiedBody(Some(CopyingBuf {
                    bytes: Bytes::from(vec![b'a'; size]),
                    copied: Arc::clone(&copied),
                }))),
                Some(size as u64),
            );
            let result = sealed.digest(BodyTimeouts::S3).await;
            if size == 3 {
                assert_eq!(result.expect("the accepted control is hashed"), <[u8; 32]>::from(Sha256::digest(b"aaa")));
                assert_eq!(copied.load(Ordering::SeqCst), 3, "the control copied real source bytes");
            } else {
                assert_eq!(
                    result.expect_err("the oversized frame is refused").code(),
                    Some(&ErrorCode::INVALID_REQUEST)
                );
                assert_eq!(copied.load(Ordering::SeqCst), 0, "the rejected frame was allocated before the bound");
            }
        }
    }

    /// Negative — the ordinary handoff preserves the generic buffer's check before copying.
    #[tokio::test]
    async fn n_an_ordinary_frame_keeps_its_bound_before_copying() {
        for size in [3, 8193] {
            let copied = Arc::new(AtomicUsize::new(0));
            let sealed = SealedBody::seal(
                Some(CopiedBody(Some(CopyingBuf {
                    bytes: Bytes::from(vec![b'a'; size]),
                    copied: Arc::clone(&copied),
                }))),
                None,
            );
            let result = sealed
                .read(
                    &MetadataAdmission::granted_for_test(),
                    BodyCeilings {
                        buffered: 8192,
                        whole_body: true,
                        declared: None,
                    },
                    BodyTimeouts::S3,
                    None,
                    BodyDigestObligation::None,
                    BodyIntegrity::NONE,
                )
                .await;
            if size == 3 {
                assert_eq!(result.expect("the accepted control is read"), b"aaa".as_slice());
                assert_eq!(copied.load(Ordering::SeqCst), 3, "the control copied real source bytes");
            } else {
                assert_eq!(
                    result.expect_err("the oversized frame is refused").code(),
                    Some(&ErrorCode::ENTITY_TOO_LARGE)
                );
                assert_eq!(copied.load(Ordering::SeqCst), 0, "the ordinary frame was copied before its bound");
            }
        }
    }

    /// Positive — repeated delegation retains a completed read's digest and its exact replay.
    #[tokio::test]
    async fn a_completed_sts_read_survives_a_second_digest_request() {
        let bytes = Bytes::from_static(b"abc");
        let sealed = SealedBody::seal(Some(Full::new(bytes.clone())), Some(3));
        let first = sealed.digest(BodyTimeouts::S3).await.expect("a bounded completed body");
        assert_eq!(first, <[u8; 32]>::from(Sha256::digest(&bytes)));
        assert_eq!(sealed.digest(BodyTimeouts::S3).await.expect("the retained digest"), first);
        let replay = sealed
            .read(
                &MetadataAdmission::granted_for_test(),
                BodyCeilings {
                    buffered: 8192,
                    whole_body: true,
                    declared: None,
                },
                BodyTimeouts::S3,
                None,
                BodyDigestObligation::None,
                BodyIntegrity::NONE,
            )
            .await
            .expect("the completed read is handed off");
        assert_eq!(replay, bytes);
    }

    /// Negative — repeating authentication keeps the first refusal and its observed unread tail.
    #[tokio::test]
    async fn n_a_completed_sts_refusal_survives_a_second_digest_request() {
        let (sealed, polls) = body(Bytes::from(vec![b'a'; 8193]));
        let first = sealed.digest(BodyTimeouts::S3).await.expect_err("the body exceeds the bound");
        assert_eq!(first.code(), Some(&ErrorCode::INVALID_REQUEST));
        assert!(first.body_unfinished.is_some());
        let second = sealed
            .digest(BodyTimeouts::S3)
            .await
            .expect_err("a read refusal cannot become an empty digest");
        assert_eq!(second, first);
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }

    /// Negative — cancellation after a physical read is incomplete, distinct from a length refusal.
    #[tokio::test]
    async fn n_a_canceled_sts_read_is_refused_as_unfinished_on_retry() {
        let (sealed, polls) = body(Bytes::from_static(b"a"));
        assert!(sealed.digest(BodyTimeouts::S3).now_or_never().is_none(), "the body never reaches EOF");
        assert_eq!(polls.load(Ordering::SeqCst), 2, "one data frame and one pending poll were observed");
        let refusal = sealed
            .digest(BodyTimeouts::S3)
            .await
            .expect_err("a canceled read cannot become an empty digest");
        assert_eq!(refusal.code(), Some(&ErrorCode::INCOMPLETE_BODY));
        assert!(refusal.body_unfinished.is_some());
        assert!(refusal.must_close_connection());
        assert_eq!(polls.load(Ordering::SeqCst), 2);
    }

    /// Negative — neither ordinary body handoff can replace a failed hash read with empty bytes.
    #[tokio::test]
    async fn n_a_completed_sts_refusal_cannot_be_handed_to_an_operation() {
        for streaming in [false, true] {
            let (sealed, _) = body(Bytes::from(vec![b'a'; 8193]));
            let first = sealed.digest(BodyTimeouts::S3).await.expect_err("the body exceeds the bound");
            let proof = MetadataAdmission::granted_for_test();
            let ceilings = BodyCeilings {
                buffered: 20000,
                whole_body: true,
                declared: None,
            };
            let refusal = if streaming {
                sealed
                    .stream(
                        &proof,
                        (ceilings, BodyTimeouts::S3, None),
                        None,
                        BodyDigestObligation::None,
                        BodyIntegrity::NONE,
                    )
                    .err()
                    .expect("a failed hash read cannot produce an upload")
            } else {
                sealed
                    .read(&proof, ceilings, BodyTimeouts::S3, None, BodyDigestObligation::None, BodyIntegrity::NONE)
                    .await
                    .expect_err("a failed hash read cannot produce buffered bytes")
            };
            assert_eq!(refusal, first);
        }
    }
}
