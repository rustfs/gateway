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

//! The proof a stage must hold before it may read a request body, and the bounded read itself.
//!
//! Responsible for: [`MetadataAdmission`] — evidence that this request's metadata credential
//! surface was judged and not rejected, without claiming that a streaming payload is verified —
//! [`SealedBody`], which owns the body and publishes exactly one way to turn it into
//! bytes, [`BodyCeilings`], the two independent bounds that read is subject to, and
//! [`BodyTimeouts`], the first-byte and between-frame idle deadlines.
//! NOT responsible for: deciding who the caller is (`crate::ext::Authenticator` and
//! `rustfs_gateway_sig::SecurityFloor`), or what the body means once it is bytes
//! (`rustfs_gateway_core`'s codecs).
//! Upstream: `crate::service`, the only module that constructs either type. Downstream:
//! `crate::wire_read`, which pulls the frames and reads the ceilings, the deadlines and the four
//! refusals below back out of this file. Both types stay crate-private on purpose, so the set of
//! call sites is still the set this crate can see.
//!
//! # Why this is a type and not a comment
//!
//! "The object payload is exposed only after metadata admission" was, until this module existed, a
//! property of the order in which `crate::service::run` happened to call two functions. Nothing
//! stopped a later edit from moving the handoff back above the verifier, and nothing would have
//! gone red if it had. Axiom A3 says ordering contracts are fixed by types, and this is that fix —
//! [`SealedBody::read`] takes a [`&MetadataAdmission`], [`MetadataAdmission::of`] is the only
//! constructor of one and it is fallible on the verdict, so a pipeline that exposes ordinary body
//! bytes first does not compile. The bounded POST Object prelude and RustFS's STS-scoped body
//! hash are private pre-verification reads; both retain the proof-gated handoff to an operation.
//!
//! The cost of getting it wrong is not hypothetical. A request with a bad signature and a very
//! large body makes an implementation that reads first do the attacker's work: the transfer is
//! paid for, the memory is spent, and only then is the request refused. The refusal is free only
//! if it happens first.
//!
//! # The ceilings, and why they are not one number
//!
//! * **The assembly's buffered ceiling** is how much this deployment is willing to hold in memory
//!   at once. Exceeding it is `EntityTooLarge` / `413`: the caller sent something this server
//!   cannot hold, which is a statement about the server.
//! * **The operation's declared cap** is how large a well-formed body for *this* operation can be.
//!   `DeleteObjects` documents at most one thousand entries, so a body far past that is malformed
//!   however much memory is free. Exceeding it is `InvalidRequest` / `400`: a statement about the
//!   request.
//! * **The assembly's upload-object ceiling**, when one is set, is how large an object one
//!   `PutObject` or `UploadPart` may carry, measured as its decoded length. Exceeding it is
//!   `EntityTooLarge` / `400` before a byte is read: RustFS's single-request limit
//!   (`gate_ceilings.rs`, carried by [`SealedBody::with_object_ceiling`]).
//!
//! The first two are enforced while the body arrives rather than after it has been collected —
//! the check is inside `crate::wire_read::WireFrames`, which is the one place either path pulls a
//! frame from, so the refusal is emitted at the first frame that crosses the line and the frames
//! behind it are never buffered. A ceiling that is only consulted once the body is in hand is not
//! a ceiling; it is a report.

use bytes::{BufMut, Bytes, BytesMut};
use http::StatusCode;
use rustfs_gateway_core::{HandlerError, RequestBody, RequestBodyMode, ResponseKind};
#[cfg(test)]
use rustfs_gateway_http::BodyIntegrity;
use rustfs_gateway_http::ChecksumVerified;
use rustfs_gateway_sig::Verdict;
use rustfs_gateway_types::ErrorCode;

use crate::integrity::Integrity;
use crate::render::{S3Error, from_handler, from_transport_limit};
use crate::wire_read::{RequestBodyUnfinished, WireFrames, WireProgress, WireReader};

#[path = "gate_ceilings.rs"]
mod ceilings;
use ceilings::declared_body_cap;
#[path = "gate_pre_verification.rs"]
mod pre_verification;
pub use ceilings::max_framed_upload_bytes;
pub(crate) use ceilings::{object_ceiling_for, past_object_ceiling};
pub(crate) use pre_verification::StsBodyReader;

/// Evidence that a request's signature reached a verdict and the verdict was not a rejection.
///
/// Borrows the verdict rather than copying anything out of it, so one cannot be built beside a
/// verdict that says something else. It carries no data: its whole value is that holding one is
/// only possible after [`MetadataAdmission::of`] has looked at a real verdict.
pub(crate) struct MetadataAdmission<'a> {
    /// Held only to tie the proof's lifetime to the verdict it was read from.
    _verdict: core::marker::PhantomData<&'a Verdict>,
}

impl<'a> MetadataAdmission<'a> {
    /// The only constructor outside this file's own tests. `None` when the verdict rejects.
    ///
    /// There is deliberately no infallible form and no `Default`: "assume it authenticated" must
    /// not be spellable.
    pub(crate) fn of(verdict: &'a Verdict) -> Option<Self> {
        if verdict.rejection().is_some() {
            return None;
        }
        Some(Self {
            _verdict: core::marker::PhantomData,
        })
    }

    /// A proof for a test that is about the read and not about the verdict.
    ///
    /// `rustfs_gateway_sig::Verdict`'s two non-rejecting variants carry receipts that are
    /// unconstructible outside that crate — deliberately, so that "look up a credential and call it
    /// authentication" cannot be written. There is therefore no honest way to build an admitting
    /// verdict here, and a test about ceilings would otherwise have to become a test about
    /// signatures. `#[cfg(test)]`, so the release build still has exactly one constructor.
    #[cfg(test)]
    pub(crate) const fn granted_for_test() -> Self {
        Self {
            _verdict: core::marker::PhantomData,
        }
    }
}

/// The bounds one body read is subject to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BodyCeilings {
    /// How much one retained frame or a fully buffered body may hold.
    pub(crate) buffered: u64,
    /// Whether `buffered` limits the complete logical body rather than one live frame.
    pub(crate) whole_body: bool,
    /// How large a well-formed body for this operation can be, when the operation declares one.
    pub(crate) declared: Option<u64>,
}

/// Idle deadlines for one request body.
pub(crate) type BodyTimeouts = crate::config::RequestBodyDeadlineConfig;

/// The integrity work that remains after authentication and before decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BodyDigestObligation {
    /// No digest was promised for this body.
    None,
    /// The body must match this signed SHA-256 value before it may reach a handler.
    Sha256([u8; 32]),
}

impl BodyCeilings {
    /// The ceilings in force for one operation of this assembly.
    pub(crate) const fn of(operation: &str, buffered: u64) -> Self {
        Self {
            buffered,
            whole_body: true,
            declared: declared_body_cap(operation),
        }
    }

    /// The resident window for a streaming body, with no total logical-size ceiling.
    pub(crate) const fn streaming(declared: Option<u64>) -> Self {
        Self {
            buffered: 1024 * 1024,
            whole_body: false,
            declared,
        }
    }

    pub(crate) const fn for_mode(mode: RequestBodyMode, operation: &str, buffered: u64) -> Self {
        match mode {
            RequestBodyMode::Streaming | RequestBodyMode::PostObject => Self::streaming(declared_body_cap(operation)),
            RequestBodyMode::None | RequestBodyMode::Full | RequestBodyMode::Deferred => Self::of(operation, buffered),
        }
    }
}

/// A request body sealed from ordinary access until metadata admission.
///
/// The private STS digest read can retain a replay; the ordinary handoff still consumes `self`
/// and requires metadata admission, so neither the original body nor a replay reaches an operation twice.
pub(crate) struct SealedBody<B> {
    body: tokio::sync::Mutex<Option<B>>,
    replay: std::sync::OnceLock<Box<Result<Bytes, S3Error>>>, // Allocated only by the STS reader.
    sts_progress: std::sync::OnceLock<WireProgress>,
    declared_length: Option<u64>,
    /// The largest object a streamed upload may declare (`gate_ceilings.rs`), when one applies.
    object_ceiling: Option<u64>,
}

impl<B> SealedBody<B>
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    /// Seals a body that the transport handed over, with whatever length the head announced.
    pub(crate) fn seal(body: Option<B>, declared_length: Option<u64>) -> Self {
        Self {
            body: tokio::sync::Mutex::new(body),
            replay: std::sync::OnceLock::new(),
            sts_progress: std::sync::OnceLock::new(),
            declared_length,
            object_ceiling: None,
        }
    }

    /// This body, refused before its first byte when it streams an object past `ceiling`.
    pub(crate) const fn with_object_ceiling(mut self, ceiling: Option<u64>) -> Self {
        self.object_ceiling = ceiling;
        self
    }

    /// Reads the body, bounded twice, and only for a caller holding a [`MetadataAdmission`].
    ///
    /// The announced check runs first, so a body claiming more than a ceiling is refused without a
    /// single frame being polled. The delivered check runs inside the frame loop, so a body that
    /// announced nothing — or lied — is refused at the frame that crosses the line rather than
    /// after the last one.
    ///
    /// # Errors
    ///
    /// [`S3Error`] carrying `InvalidRequest` for the operation's cap, `EntityTooLarge` for the
    /// assembly's ceiling, and `IncompleteBody` for a body that did not arrive as it was framed.
    pub(crate) async fn read(
        self,
        _proof: &MetadataAdmission<'_>,
        ceilings: BodyCeilings,
        timeouts: BodyTimeouts,
        ingest: Option<crate::chunked::ChunkIngest>,
        digest: BodyDigestObligation,
        // Settled from the head by `crate::integrity::resolve`, above this call, because a
        // contradiction between two claims is not decidable from any number of body bytes.
        integrity: impl Into<Integrity>,
    ) -> Result<Bytes, S3Error> {
        let declared_length = self.declared_length;
        let body = self.into_body()?;
        let Integrity { claims, codes } = integrity.into();
        let refuse = move |reject| codes.refusal(reject);
        // Opened here, closed on every path that reaches a caller with bytes in hand.
        // `crate::payload_header::body_digest_obligation` mints `BodyDigestObligation::Sha256` for
        // every signed exact digest, header-signed and presigned alike (c-sig-0596, c-sig-0430).
        let progress = WireProgress::for_body(digest, body.as_ref());
        // Read only by the unframed arm below, and that is the whole of the rule: under framing
        // the bytes arriving here are chunk headers, signatures and CRLFs, and the object's own
        // octets exist only after the decoder has produced them, so the framed path's digests are
        // fed from inside `ChunkIngest::run` instead.
        let fuse_digests = !claims.is_empty();
        let mut digests = claims.begin();
        let Some(body) = body else {
            if !progress.digest_matches() {
                return Err(content_sha256_mismatch());
            }
            // An absent body is a zero-length body, and a zero-length body has a digest. A request
            // that claims the checksum of one byte and sends none must not pass because there was
            // nothing to compare.
            let _verified: ChecksumVerified = digests.verify().map_err(refuse)?;
            return Ok(Bytes::new());
        };
        if let Some(cap) = ceilings.declared
            && declared_length.is_some_and(|length| length > cap)
        {
            return Err(past_declared_cap(progress.request_body_unfinished()));
        }
        if ceilings.whole_body && declared_length.is_some_and(|length| length > ceilings.buffered) {
            return Err(past_buffered_ceiling(progress.request_body_unfinished()));
        }

        // Both ceilings are applied to the *wire* bytes — the ones the peer wrote and this process
        // is holding — frame by frame inside `WireFrames`, whichever branch below consumes them.
        // `crate::chunked` states why that is the right side of the decode to count on.
        let (body, verified) = match ingest {
            // Pulled, not collected. The decoder reads frames through `WireReader` as its window
            // has room for them, so the wire octets are never resident beside the decoded body:
            // the pipeline's bound is the only bound there is, which is what rustfs/gateway#229
            // is about. The decoder also feeds the digests as it produces the object's own
            // octets, so the checksum covers what the caller claimed a digest for and not the
            // framing around it.
            Some(ingest) => {
                let frames = WireFrames::new(body, progress.clone(), ceilings, timeouts);
                let decoded = ingest.run(WireReader::new(frames), &mut digests).await;
                // The reader's refusal outranks the pipeline's: a ceiling that answered `413` is
                // not an `IncompleteBody`, and the pull contract cannot carry the difference.
                let decoded = decoded.map_err(|error| {
                    progress
                        .take_refusal()
                        .unwrap_or_else(|| progress.mark_refusal_if_unfinished(error))
                })?;
                let verified = digests.verify_with_trailers(decoded.trailers()).map_err(refuse)?;
                if !decoded.commit_allowed(&verified) {
                    return Err(crate::chunked::trailers_not_verified());
                }
                (decoded.into_body(), verified)
            }
            // Not framed, so these bytes are the object's own and the collector keeps them whole.
            // Every digest this body owes is fed from the frame while it is still in cache, so the
            // body is walked once however many claims it carries.
            None => {
                let mut frames = WireFrames::new(body, progress.clone(), ceilings, timeouts);
                let mut collected = BytesMut::new();
                while let Some(frame) = core::future::poll_fn(|context| frames.poll_next(context)).await? {
                    if fuse_digests {
                        digests.update(&frame);
                    }
                    // `BytesMut::put` into a collector with no capacity yet takes the frame's own
                    // allocation instead of copying into a new one, so a body that arrives as one
                    // frame leaves this function as the memory it arrived in. A mebibyte request
                    // allocated 1,078,095 bytes before rustfs/gateway#225 and under thirty
                    // kibibytes since; `tests/request_allocations.rs` is what keeps it there, and
                    // it is a bound on the shape rather than on the number.
                    collected.put(frame);
                }
                let body = collected.freeze();
                let verified = digests.verify().map_err(refuse)?;
                (body, verified)
            }
        };
        // After the read rather than before it: under framing the payload hash is only complete
        // once the pipeline has pulled the last frame through. The comparison itself is unchanged,
        // and a framed body never carries one: a streaming payload declares no digest, and
        // `body_digest_obligation`, the only place a `Sha256` obligation is minted, mints none for it.
        if !progress.digest_matches() {
            return Err(content_sha256_mismatch());
        }
        // Bound and dropped on purpose: the witness's value is where it can be produced, not what
        // it carries. When the commit path takes an integrity proof by value (P5), it takes this.
        let _verified: ChecksumVerified = verified;
        Ok(body)
    }

    /// Opens a verified live producer without polling the transport.
    ///
    /// # Errors
    ///
    /// A head-level ceiling refusal or an ingest pipeline that cannot be constructed from the
    /// authenticated framing decision.
    pub(crate) fn stream(
        self,
        _proof: &MetadataAdmission<'_>,
        body_plan: (BodyCeilings, BodyTimeouts, Option<std::sync::Arc<dyn crate::BodyQuota>>),
        ingest: Option<crate::chunked::ChunkIngest>,
        digest: BodyDigestObligation,
        integrity: impl Into<Integrity>,
    ) -> Result<crate::request_body::StreamingRead, S3Error> {
        let (ceilings, timeouts, body_quota) = body_plan;
        let lengths = (self.declared_length, self.object_ceiling);
        crate::request_body::StreamingRead::new(
            self.into_body()?,
            lengths,
            (ceilings, timeouts, body_quota),
            ingest,
            digest,
            integrity,
        )
    }

    pub(crate) async fn handoff(
        self,
        proof: &MetadataAdmission<'_>,
        body_plan: (RequestBodyMode, BodyCeilings, BodyTimeouts, Option<std::sync::Arc<dyn crate::BodyQuota>>),
        ingest: Option<crate::chunked::ChunkIngest>,
        digest: BodyDigestObligation,
        integrity: impl Into<Integrity>,
    ) -> Result<(RequestBody, Option<crate::request_body::BodyMonitor>), S3Error> {
        let integrity = integrity.into();
        let (mode, ceilings, timeouts, body_quota) = body_plan;
        match mode {
            RequestBodyMode::Streaming => {
                let opened = self.stream(proof, (ceilings, timeouts, body_quota), ingest, digest, integrity)?;
                let (stream, monitor) = opened.into_parts();
                Ok((RequestBody::Stream(stream), Some(monitor)))
            }
            RequestBodyMode::PostObject => Err(from_handler(
                HandlerError::internal_error("PostObject must be prepared by the multipart form pipeline"),
                ResponseKind::Other,
                crate::close::ConnectionIntent::MayKeepAlive,
            )),
            RequestBodyMode::None => {
                self.read(proof, ceilings, timeouts, ingest, digest, integrity).await?;
                Ok((RequestBody::None, None))
            }
            RequestBodyMode::Full | RequestBodyMode::Deferred => {
                let bytes = self.read(proof, ceilings, timeouts, ingest, digest, integrity).await?;
                Ok((RequestBody::Buffered(bytes), None))
            }
        }
    }
}

pub(crate) fn content_sha256_mismatch() -> S3Error {
    from_handler(
        HandlerError::new(
            ErrorCode::X_AMZ_CONTENT_SHA256_MISMATCH,
            "the request body does not match x-amz-content-sha256",
        ),
        ResponseKind::Other,
        crate::close::ConnectionIntent::MayKeepAlive,
    )
}

/// The refusal for a body larger than the operation's own bound.
///
/// Closes the connection: the frames behind the one that crossed the line are never pulled, so the
/// peer's remaining octets are undrained, and RFC 9112 §9.3 gives a server that does not read the
/// whole body no second option. Draining them instead would be performing the transfer this
/// refusal exists to avoid — `crate::close::after_body_ceiling` is where that judgement is
/// written down. `c-object-0015` is the case.
pub(crate) fn past_declared_cap(proof: Option<RequestBodyUnfinished>) -> S3Error {
    let mut refusal = from_handler(
        HandlerError::new(ErrorCode::INVALID_REQUEST, "the request body is larger than this operation permits"),
        ResponseKind::Other,
        crate::close::after_body_ceiling(),
    );
    refusal.body_unfinished = proof;
    refusal
}

/// The refusal for a body larger than this assembly will hold.
pub(crate) fn past_buffered_ceiling(proof: Option<RequestBodyUnfinished>) -> S3Error {
    let mut refusal = from_transport_limit(
        HandlerError::new(
            ErrorCode::ENTITY_TOO_LARGE,
            "the declared request body is larger than this service will hold",
        ),
        StatusCode::PAYLOAD_TOO_LARGE,
        crate::close::after_body_ceiling(),
    );
    refusal.body_unfinished = proof;
    refusal
}

/// The refusal for a body that stopped early or ran on: both mean the body that arrived is not the
/// body that was announced, and saying which ceiling was hit tells a caller how to retry with a
/// body that is not refused.
pub(crate) fn incomplete() -> S3Error {
    // Closes, for the reason `ChunkReject::TruncatedStream` does: the transport reported the body
    // did not arrive as framed, so there is no well-defined remainder to drain and no
    // synchronisation point to resume from. RFC 9112 §6.3 and §9.3.
    from_handler(
        HandlerError::new(ErrorCode::INCOMPLETE_BODY, "the request body did not arrive as it was framed"),
        ResponseKind::Other,
        crate::close::ConnectionIntent::Close,
    )
}

/// The indistinguishable refusal for a body that is not delivering: first-byte expiry,
/// between-frame idle expiry, and a run of frames that carry no payload at all.
///
/// One refusal for three causes because a client has the same thing to do about each of them, and
/// because the third is the second measured a different way: a peer that keeps a connection alive
/// with payload-free frames is a peer whose body is idle, and the deadline cannot see it because
/// every one of those frames is an arrival. `crate::wire_read::MAX_PAYLOAD_FREE_FRAME_RUN` is
/// where that bound and its reason live. All three close the connection.
pub(crate) fn body_idle_timeout(proof: Option<RequestBodyUnfinished>) -> S3Error {
    let mut refusal = from_transport_limit(
        HandlerError::new(ErrorCode::REQUEST_TIMEOUT, "the request body stopped making progress"),
        StatusCode::BAD_REQUEST,
        crate::close::ConnectionIntent::Close,
    );
    refusal.body_unfinished = proof;
    refusal
}

/// The closing refusal for a body that keeps arriving below its configured throughput floor.
pub(crate) fn body_throughput_timeout(proof: Option<RequestBodyUnfinished>) -> S3Error {
    let mut refusal = from_transport_limit(
        HandlerError::new(ErrorCode::REQUEST_TIMEOUT, "the request body remained below the minimum throughput"),
        StatusCode::BAD_REQUEST,
        crate::close::ConnectionIntent::Close,
    );
    refusal.body_unfinished = proof;
    refusal
}

/// The closing refusal for a lease whose streaming body quota was exhausted.
pub(crate) fn body_quota_refusal(proof: Option<RequestBodyUnfinished>) -> S3Error {
    let mut refusal = from_handler(
        HandlerError::new(ErrorCode::SLOW_DOWN, "the service is not accepting this request right now"),
        ResponseKind::Other,
        crate::close::ConnectionIntent::Close,
    );
    refusal.body_unfinished = proof;
    refusal
}

#[cfg(test)]
#[path = "gate_tests.rs"]
mod tests;

#[cfg(all(test, feature = "server"))]
mod unfinished_body_tests {
    use core::convert::Infallible;
    use core::pin::Pin;
    use core::task::{Context, Poll};
    use std::time::Duration;

    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue};
    use rustfs_gateway_core::{HandlerError, ResponseKind};
    use rustfs_gateway_http::{BodyIntegrity, ChunkLimits, Framing};
    use rustfs_gateway_server::UnfinishedRequestBody;
    use rustfs_gateway_sig::{PayloadMode, TrailerSet};
    use rustfs_gateway_types::ErrorCode;

    use super::{
        BodyCeilings, BodyDigestObligation, BodyTimeouts, MetadataAdmission, SealedBody, body_idle_timeout, body_quota_refusal,
        body_throughput_timeout, incomplete, past_buffered_ceiling,
    };
    use crate::close::ConnectionIntent;
    use crate::render::{from_auth, from_handler, from_wire_reject, render};
    use crate::trace::RequestTrace;
    use crate::wire_read::WireProgress;

    fn unsigned_ingest(wire_length: u64) -> Option<crate::chunked::ChunkIngest> {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from(wire_length));
        headers.insert(
            http::HeaderName::from_static("x-amz-decoded-content-length"),
            HeaderValue::from_static("11"),
        );
        let wire = Framing::classify(http::Version::HTTP_11, &headers, &rustfs_gateway_http::Limits::default()).ok()?;
        crate::chunked::ChunkIngest::prepare(
            &PayloadMode::StreamingUnsigned {
                trailer: TrailerSet::None,
            },
            &headers,
            &wire,
            &crate::ext::ChunkSink::new(),
            None,
            ChunkLimits::default(),
        )
        .ok()?
    }

    struct FirstFrameThenPending(Option<Bytes>);

    impl http_body::Body for FirstFrameThenPending {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
            self.get_mut()
                .0
                .take()
                .map(http_body::Frame::data)
                .map(Ok)
                .map_or(Poll::Pending, |frame| Poll::Ready(Some(frame)))
        }
    }

    struct FinalFrameBody(Option<Bytes>);

    impl http_body::Body for FinalFrameBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(self.get_mut().0.take().map(http_body::Frame::data).map(Ok))
        }

        fn is_end_stream(&self) -> bool {
            self.0.is_none()
        }
    }

    fn unfinished_proof() -> Option<crate::wire_read::RequestBodyUnfinished> {
        let body = FirstFrameThenPending(Some(Bytes::new()));
        WireProgress::for_body(BodyDigestObligation::None, Some(&body)).request_body_unfinished()
    }

    async fn chunk_refusal<B>(body: B) -> Option<crate::render::S3Error>
    where
        B: http_body::Body<Data = Bytes, Error = Infallible> + Send + 'static,
    {
        let ingest = unsigned_ingest(4096)?;
        SealedBody::seal(Some(body), Some(4096))
            .read(
                &MetadataAdmission::granted_for_test(),
                BodyCeilings::of("PutObject", 1024 * 1024),
                BodyTimeouts::S3,
                Some(ingest),
                BodyDigestObligation::None,
                BodyIntegrity::NONE,
            )
            .await
            .err()
    }

    /// Positive — the early body ceiling is a proof that the service stopped before the body
    /// ended, independently of the connection-close verdict it also carries.
    #[test]
    fn an_early_body_ceiling_marks_the_rendered_response_as_unfinished() {
        let response = render(&past_buffered_ceiling(unfinished_proof()), &RequestTrace::from_bits(1, 2));
        assert!(
            response.extensions().get::<UnfinishedRequestBody>().is_some(),
            "the server cannot distinguish an arriving body from an ordinary close"
        );
    }

    /// Positive — `MissingContentLength` proves a different unfinished-body shape: HTTP frames an
    /// empty request, but the refusal exists only because this operation required the body the
    /// peer meant to send. The server must therefore wait briefly for those unframed trailing
    /// octets rather than dropping them with RST.
    #[test]
    fn an_undeclared_length_refusal_marks_the_rendered_response_for_lingering_close() {
        let error = from_handler(
            HandlerError::new(ErrorCode::MISSING_CONTENT_LENGTH, "length required"),
            ResponseKind::Other,
            ConnectionIntent::MayKeepAlive,
        );
        let response = render(&error, &RequestTrace::from_bits(1, 2));
        assert!(
            response.extensions().get::<UnfinishedRequestBody>().is_some(),
            "the 411 framing disagreement did not survive into the transport"
        );
    }

    /// Positive — every live-body policy refusal is emitted only while its monitor still owns a
    /// producer that has not reported EOF.
    #[test]
    fn live_body_policy_refusals_mark_the_rendered_response_as_unfinished() {
        let proof = unfinished_proof();
        assert!(proof.is_some(), "a fresh wire reader has not reached EOF");
        let Some(proof) = proof else {
            return;
        };
        for refusal in [
            body_idle_timeout(Some(proof)),
            body_throughput_timeout(Some(proof)),
            body_quota_refusal(Some(proof)),
        ] {
            let response = render(&refusal, &RequestTrace::from_bits(1, 2));
            assert!(
                response.extensions().get::<UnfinishedRequestBody>().is_some(),
                "a live-body refusal lost its independent unfinished-body proof"
            );
        }
    }

    /// Positive — malformed framing rejected before the reader asks for EOF leaves source bytes
    /// unconsumed and therefore carries the wire-owned proof.
    #[tokio::test]
    async fn a_pre_eof_chunk_parser_failure_marks_the_body_as_unfinished() {
        let error = tokio::time::timeout(
            Duration::from_millis(100),
            chunk_refusal(FirstFrameThenPending(Some(Bytes::from_static(b"z\r\n")))),
        )
        .await
        .ok()
        .flatten();
        assert!(error.is_some(), "plain text is not aws-chunked framing");
        let Some(error) = error else {
            return;
        };
        let response = render(&error, &RequestTrace::from_bits(1, 2));
        assert!(response.extensions().get::<UnfinishedRequestBody>().is_some());
    }

    /// Negative — a parser refusal on the source's final DATA frame happens after the transport
    /// has independently declared EOF, even though the reader never needs another poll.
    #[tokio::test]
    async fn a_final_frame_chunk_parser_failure_does_not_claim_bytes_remain() {
        let error = chunk_refusal(FinalFrameBody(Some(Bytes::from_static(b"z\r\n")))).await;
        assert!(error.is_some(), "plain text is not aws-chunked framing");
        let Some(error) = error else {
            return;
        };
        let response = render(&error, &RequestTrace::from_bits(1, 2));
        assert!(response.extensions().get::<UnfinishedRequestBody>().is_none());
    }

    /// Negative — a truncated but initially valid chunk stream is rejected only after its source
    /// reports EOF, so there is nothing left for lingering close to drain.
    #[tokio::test]
    async fn a_post_eof_chunk_parser_failure_does_not_claim_bytes_remain() {
        let (body, _) = crate::probe::ObservedBody::new([Bytes::from_static(b"b\r\nhello world\r\n")]);
        let error = chunk_refusal(body).await;
        assert!(error.is_some(), "the terminal zero chunk is required");
        let Some(error) = error else {
            return;
        };
        let response = render(&error, &RequestTrace::from_bits(1, 2));
        assert!(response.extensions().get::<UnfinishedRequestBody>().is_none());
    }

    /// Negative — signer material is a head-only prerequisite and says nothing about whether the
    /// transport has delivered or retained body bytes.
    #[test]
    fn unavailable_chunk_signatures_do_not_claim_body_progress() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from(4096));
        headers.insert(
            http::HeaderName::from_static("x-amz-decoded-content-length"),
            HeaderValue::from_static("11"),
        );
        let wire = Framing::classify(http::Version::HTTP_11, &headers, &rustfs_gateway_http::Limits::default()).ok();
        assert!(wire.is_some(), "a content length classifies");
        let Some(wire) = wire else {
            return;
        };
        let error = crate::chunked::ChunkIngest::prepare(
            &PayloadMode::StreamingSigned {
                trailer: TrailerSet::None,
            },
            &headers,
            &wire,
            &crate::ext::ChunkSink::new(),
            None,
            ChunkLimits::default(),
        )
        .err();
        assert!(error.is_some(), "signed chunks need verifier material");
        let Some(error) = error else {
            return;
        };
        let response = render(&error, &RequestTrace::from_bits(1, 2));
        assert!(response.extensions().get::<UnfinishedRequestBody>().is_none());
    }

    /// Negative — a close verdict alone says nothing about whether a body exists or reached its
    /// end, so it must never synthesize the server marker.
    #[test]
    fn a_generic_close_does_not_claim_that_the_request_body_is_unfinished() {
        for code in [ErrorCode::INTERNAL_ERROR, ErrorCode::ACCESS_DENIED] {
            let error = from_handler(HandlerError::new(code, "generic close"), ResponseKind::Other, ConnectionIntent::Close);
            let response = render(&error, &RequestTrace::from_bits(1, 2));
            assert!(
                response.extensions().get::<UnfinishedRequestBody>().is_none(),
                "ConnectionIntent::Close or an unrelated error code was treated as body-progress evidence"
            );
        }
    }

    /// Negative — a transport failure says framing did not complete, but it does not prove that
    /// readable request bytes remain for the server's lingering drain.
    #[test]
    fn an_incomplete_transport_does_not_claim_that_bytes_remain() {
        let response = render(&incomplete(), &RequestTrace::from_bits(1, 2));
        assert!(
            response.extensions().get::<UnfinishedRequestBody>().is_none(),
            "a transport error was treated as evidence that readable bytes remain"
        );
    }

    /// Negative — trailer verification is decided only after the chunk reader reports EOF, so a
    /// closing trailer refusal must not ask the server to drain a body it has already consumed.
    #[test]
    fn a_post_eof_trailer_refusal_does_not_claim_that_bytes_remain() {
        let response = render(&crate::chunked::trailers_not_verified(), &RequestTrace::from_bits(1, 2));
        assert!(
            response.extensions().get::<UnfinishedRequestBody>().is_none(),
            "a post-EOF refusal was treated as an unfinished body"
        );
    }

    /// Negative — a wire `Connection` header is only a close announcement and cannot manufacture
    /// the application proof consumed by the server's lingering drain.
    #[test]
    fn a_response_connection_close_header_does_not_claim_that_the_body_is_unfinished() {
        let error = from_handler(
            HandlerError::new(ErrorCode::INTERNAL_ERROR, "header-only close"),
            ResponseKind::Other,
            ConnectionIntent::MayKeepAlive,
        );
        let mut response = render(&error, &RequestTrace::from_bits(1, 2));
        response
            .headers_mut()
            .insert(http::header::CONNECTION, http::HeaderValue::from_static("close"));
        assert!(
            response.extensions().get::<UnfinishedRequestBody>().is_none(),
            "a response header was treated as body-progress evidence"
        );
    }

    /// Negative — authentication and head-only wire refusals close for their own reasons and
    /// carry no observation of body completion.
    #[test]
    fn closing_auth_and_wire_refusals_do_not_claim_body_progress() {
        let refusals = [
            from_auth(rustfs_gateway_sig::AuthError::SignatureDoesNotMatch, ResponseKind::Other, true),
            from_wire_reject(rustfs_gateway_http::WireReject::MalformedChunkFraming),
        ];
        for refusal in refusals {
            assert!(refusal.must_close_connection(), "the negative control must actually close");
            let response = render(&refusal, &RequestTrace::from_bits(1, 2));
            assert!(response.extensions().get::<UnfinishedRequestBody>().is_none());
        }
    }
}
