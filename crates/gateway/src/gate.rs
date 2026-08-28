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
//! Responsible for: [`Authenticated`] — evidence that this request's signature was judged and not
//! rejected — [`SealedBody`], which owns the body and publishes exactly one way to turn it into
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
//! "The signature is verified before any body byte is read" was, until this module existed, a
//! property of the order in which `crate::service::run` happened to call two functions. Nothing
//! stopped a later edit from moving the read back above the verifier, and nothing would have gone
//! red if it had: every conformance case that measures it asserts on a transport that reports the
//! whole body as sent regardless. Axiom A3 says ordering contracts are fixed by types, and this is
//! that fix — [`SealedBody::read`] takes an [`&Authenticated`], [`Authenticated::of`] is the only
//! constructor of one and it is fallible on the verdict, so a pipeline that reads the body first
//! does not compile.
//!
//! The cost of getting it wrong is not hypothetical. A request with a bad signature and a very
//! large body makes an implementation that reads first do the attacker's work: the transfer is
//! paid for, the memory is spent, and only then is the request refused. The refusal is free only
//! if it happens first.
//!
//! # The two ceilings, and why they are not one number
//!
//! * **The assembly's buffered ceiling** is how much this deployment is willing to hold in memory
//!   at once. Exceeding it is `EntityTooLarge` / `413`: the caller sent something this server
//!   cannot hold, which is a statement about the server.
//! * **The operation's declared cap** is how large a well-formed body for *this* operation can be.
//!   `DeleteObjects` documents at most one thousand entries, so a body far past that is malformed
//!   however much memory is free. Exceeding it is `InvalidRequest` / `400`: a statement about the
//!   request.
//!
//! Both are enforced while the body arrives rather than after it has been collected — the check is
//! inside `crate::wire_read::WireFrames`, which is the one place either path pulls a frame from, so
//! the refusal is emitted at the first frame that crosses the line and the frames behind it are
//! never buffered. A ceiling that is only consulted once the body is in hand is not a ceiling; it
//! is a report.

use bytes::{BufMut, Bytes, BytesMut};
use http::StatusCode;
use rustfs_gateway_core::{HandlerError, RequestBody, RequestBodyMode, ResponseKind};
use rustfs_gateway_http::{BodyIntegrity, ChecksumVerified};
use rustfs_gateway_sig::Verdict;
use rustfs_gateway_types::ErrorCode;

use crate::integrity::checksum_refusal;
use crate::render::{S3Error, from_handler, from_transport_limit};
use crate::wire_read::{WireFrames, WireProgress, WireReader};

/// Typed proof that a refusing stage stopped before request-body completion.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub(crate) struct RequestBodyUnfinished(bool);

impl RequestBodyUnfinished {
    pub(crate) const fn proven() -> Self {
        Self(true)
    }

    pub(crate) fn attach<B>(self, response: &mut http::Response<B>) {
        #[cfg(feature = "server")]
        if self.0 {
            response.extensions_mut().insert(rustfs_gateway_server::UnfinishedRequestBody);
        }
        #[cfg(not(feature = "server"))]
        let _ = (self, response);
    }
}

/// Evidence that a request's signature reached a verdict and the verdict was not a rejection.
///
/// Borrows the verdict rather than copying anything out of it, so one cannot be built beside a
/// verdict that says something else. It carries no data: its whole value is that holding one is
/// only possible after [`Authenticated::of`] has looked at a real verdict.
pub(crate) struct Authenticated<'a> {
    /// Held only to tie the proof's lifetime to the verdict it was read from.
    _verdict: core::marker::PhantomData<&'a Verdict>,
}

impl<'a> Authenticated<'a> {
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
            RequestBodyMode::Streaming => Self::streaming(declared_body_cap(operation)),
            RequestBodyMode::None | RequestBodyMode::Full | RequestBodyMode::Deferred => Self::of(operation, buffered),
        }
    }
}

/// A request body that has arrived and has not been read.
///
/// The `Option` is the "there was no body" case rather than a taken value: `read` consumes `self`,
/// so a body cannot be read twice and there is no state in which one has been half-taken.
pub(crate) struct SealedBody<B> {
    body: Option<B>,
    declared_length: Option<u64>,
}

impl<B> SealedBody<B>
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    /// Seals a body that the transport handed over, with whatever length the head announced.
    pub(crate) const fn seal(body: Option<B>, declared_length: Option<u64>) -> Self {
        Self { body, declared_length }
    }

    /// Reads the body, bounded twice, and only for a caller holding an [`Authenticated`].
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
        _proof: &Authenticated<'_>,
        ceilings: BodyCeilings,
        timeouts: BodyTimeouts,
        ingest: Option<crate::chunked::ChunkIngest>,
        digest: BodyDigestObligation,
        // Settled from the head by `crate::integrity::resolve`, above this call, because a
        // contradiction between two claims is not decidable from any number of body bytes.
        integrity: BodyIntegrity,
    ) -> Result<Bytes, S3Error> {
        // Opened here, closed on every path that reaches a caller with bytes in hand. Not two
        // halves of one guarantee: `BodyDigestObligation::Sha256` is minted only by
        // `presigned_body_obligation`, so a header-signed request's payload hash is still not
        // compared here — a P2 gap this predates and does not close.
        let progress = WireProgress::new(digest);
        // Read only by the unframed arm below, and that is the whole of the rule: under framing
        // the bytes arriving here are chunk headers, signatures and CRLFs, and the object's own
        // octets exist only after the decoder has produced them, so the framed path's digests are
        // fed from inside `ChunkIngest::run` instead.
        let fuse_digests = !integrity.is_empty();
        let mut digests = integrity.begin();
        let Some(body) = self.body else {
            if !progress.digest_matches() {
                return Err(content_sha256_mismatch());
            }
            // An absent body is a zero-length body, and a zero-length body has a digest. A request
            // that claims the checksum of one byte and sends none must not pass because there was
            // nothing to compare.
            let _verified: ChecksumVerified = digests.verify().map_err(checksum_refusal)?;
            return Ok(Bytes::new());
        };
        if let Some(cap) = ceilings.declared
            && self.declared_length.is_some_and(|length| length > cap)
        {
            return Err(past_declared_cap());
        }
        if ceilings.whole_body && self.declared_length.is_some_and(|length| length > ceilings.buffered) {
            return Err(past_buffered_ceiling());
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
                let decoded = decoded.map_err(|error| progress.take_refusal().unwrap_or(error))?;
                let verified = digests.verify_with_trailers(decoded.trailers()).map_err(checksum_refusal)?;
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
                let verified = digests.verify().map_err(checksum_refusal)?;
                (body, verified)
            }
        };
        // After the read rather than before it: under framing the payload hash is only complete
        // once the pipeline has pulled the last frame through. The comparison itself is unchanged,
        // and a framed body never carries one — `presigned_body_obligation` refuses a presigned
        // streaming request outright, and that is the only place a `Sha256` obligation is minted.
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
        _proof: &Authenticated<'_>,
        body_plan: (BodyCeilings, BodyTimeouts, Option<std::sync::Arc<dyn crate::BodyQuota>>),
        ingest: Option<crate::chunked::ChunkIngest>,
        digest: BodyDigestObligation,
        integrity: BodyIntegrity,
    ) -> Result<crate::request_body::StreamingRead, S3Error> {
        let (ceilings, timeouts, body_quota) = body_plan;
        if let Some(cap) = ceilings.declared
            && self.declared_length.is_some_and(|length| length > cap)
        {
            return Err(past_declared_cap());
        }
        if ceilings.whole_body && self.declared_length.is_some_and(|length| length > ceilings.buffered) {
            return Err(past_buffered_ceiling());
        }
        crate::request_body::StreamingRead::new(
            self.body,
            self.declared_length,
            (ceilings, timeouts, body_quota),
            ingest,
            digest,
            integrity,
        )
    }

    pub(crate) async fn handoff(
        self,
        proof: &Authenticated<'_>,
        body_plan: (RequestBodyMode, BodyCeilings, BodyTimeouts, Option<std::sync::Arc<dyn crate::BodyQuota>>),
        ingest: Option<crate::chunked::ChunkIngest>,
        digest: BodyDigestObligation,
        integrity: BodyIntegrity,
    ) -> Result<(RequestBody, Option<crate::request_body::BodyMonitor>), S3Error> {
        let (mode, ceilings, timeouts, body_quota) = body_plan;
        match mode {
            RequestBodyMode::Streaming => {
                let opened = self.stream(proof, (ceilings, timeouts, body_quota), ingest, digest, integrity)?;
                let (stream, monitor) = opened.into_parts();
                Ok((RequestBody::Stream(stream), Some(monitor)))
            }
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

/// How large a well-formed body for this operation can be, when the operation bounds one.
///
/// **This table is in the wrong crate and is here for a boundary reason, not a design one.** The
/// bound belongs beside the operation — `rustfs_gateway_core::Operation` is where a per-operation
/// constant should be declared, so that a new operation with a bounded body cannot be added
/// without stating its bound. Until that constant exists, an assembly that enforces nothing is
/// strictly worse than an assembly that enforces the documented number from one greppable place.
///
/// `DeleteObjects` is the only entry: AWS documents the request as carrying at most one thousand
/// key entries, and a thousand entries of the maximum key length plus their version ids fit inside
/// two mebibytes with room to spare. Everything else is `None` and falls back to the assembly's
/// buffered ceiling.
pub(crate) const fn declared_body_cap(operation: &str) -> Option<u64> {
    match operation.as_bytes() {
        b"DeleteObjects" => Some(MAX_DELETE_OBJECTS_BODY_BYTES),
        _ => None,
    }
}

/// The `DeleteObjects` request-body cap, in bytes.
pub(crate) const MAX_DELETE_OBJECTS_BODY_BYTES: u64 = 2 * 1024 * 1024;

/// The refusal for a body larger than the operation's own bound.
///
/// Closes the connection: the frames behind the one that crossed the line are never pulled, so the
/// peer's remaining octets are undrained, and RFC 9112 §9.3 gives a server that does not read the
/// whole body no second option. Draining them instead would be performing the transfer this
/// refusal exists to avoid — `crate::close::after_body_ceiling` is where that judgement is
/// written down. `c-object-0015` is the case.
pub(crate) fn past_declared_cap() -> S3Error {
    let mut refusal = from_handler(
        HandlerError::new(ErrorCode::INVALID_REQUEST, "the request body is larger than this operation permits"),
        ResponseKind::Other,
        crate::close::after_body_ceiling(),
    );
    refusal.body_unfinished = RequestBodyUnfinished::proven();
    refusal
}

/// The refusal for a body larger than this assembly will hold.
pub(crate) fn past_buffered_ceiling() -> S3Error {
    let mut refusal = from_transport_limit(
        HandlerError::new(
            ErrorCode::ENTITY_TOO_LARGE,
            "the declared request body is larger than this service will hold",
        ),
        StatusCode::PAYLOAD_TOO_LARGE,
        crate::close::after_body_ceiling(),
    );
    refusal.body_unfinished = RequestBodyUnfinished::proven();
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
pub(crate) fn body_idle_timeout() -> S3Error {
    from_transport_limit(
        HandlerError::new(ErrorCode::REQUEST_TIMEOUT, "the request body stopped making progress"),
        StatusCode::REQUEST_TIMEOUT,
        crate::close::ConnectionIntent::Close,
    )
}

/// The closing refusal for a body that keeps arriving below its configured throughput floor.
pub(crate) fn body_throughput_timeout() -> S3Error {
    from_transport_limit(
        HandlerError::new(ErrorCode::REQUEST_TIMEOUT, "the request body remained below the minimum throughput"),
        StatusCode::REQUEST_TIMEOUT,
        crate::close::ConnectionIntent::Close,
    )
}

/// The closing refusal for a lease whose streaming body quota was exhausted.
pub(crate) fn body_quota_refusal() -> S3Error {
    from_handler(
        HandlerError::new(ErrorCode::SLOW_DOWN, "the service is not accepting this request right now"),
        ResponseKind::Other,
        crate::close::ConnectionIntent::Close,
    )
}

#[cfg(test)]
#[path = "gate_tests.rs"]
mod tests;

#[cfg(all(test, feature = "server"))]
mod unfinished_body_tests {
    use rustfs_gateway_core::{HandlerError, ResponseKind};
    use rustfs_gateway_server::UnfinishedRequestBody;
    use rustfs_gateway_types::ErrorCode;

    use super::past_buffered_ceiling;
    use crate::close::ConnectionIntent;
    use crate::render::{from_handler, render};
    use crate::trace::RequestTrace;

    /// Positive — the early body ceiling is a proof that the service stopped before the body
    /// ended, independently of the connection-close verdict it also carries.
    #[test]
    fn an_early_body_ceiling_marks_the_rendered_response_as_unfinished() {
        let response = render(&past_buffered_ceiling(), &RequestTrace::from_bits(1, 2));
        assert!(
            response.extensions().get::<UnfinishedRequestBody>().is_some(),
            "the server cannot distinguish an arriving body from an ordinary close"
        );
    }

    /// Negative — a close verdict alone says nothing about whether a body exists or reached its
    /// end, so it must never synthesize the server marker.
    #[test]
    fn a_generic_close_does_not_claim_that_the_request_body_is_unfinished() {
        let error = from_handler(
            HandlerError::new(ErrorCode::INTERNAL_ERROR, "generic close"),
            ResponseKind::Other,
            ConnectionIntent::Close,
        );
        let response = render(&error, &RequestTrace::from_bits(1, 2));
        assert!(
            response.extensions().get::<UnfinishedRequestBody>().is_none(),
            "ConnectionIntent::Close was treated as body-progress evidence"
        );
    }
}
