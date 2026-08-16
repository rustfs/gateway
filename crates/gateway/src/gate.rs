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
//! Upstream: `crate::service`, the only module that constructs either type. Downstream: nothing —
//! both types are crate-private on purpose, so the set of call sites is the set this file can see.
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
//! inside the frame loop, so the refusal is emitted at the first frame that crosses the line and
//! the frames behind it are never buffered. A ceiling that is only consulted once the body is in
//! hand is not a ceiling; it is a report.

use core::task::Poll;
use std::pin::Pin;
use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_timer::Delay;
use http::StatusCode;
use http_body_util::BodyExt;
use rustfs_gateway_core::{HandlerError, ResponseKind};
use rustfs_gateway_sig::Verdict;
use rustfs_gateway_types::ErrorCode;
use sha2::{Digest, Sha256};

use crate::render::{S3Error, from_handler, from_transport_limit};

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
    /// How much this assembly will hold in memory, whatever the operation is.
    pub(crate) buffered: u64,
    /// How large a well-formed body for this operation can be, when the operation declares one.
    pub(crate) declared: Option<u64>,
}

/// Idle deadlines for one request body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BodyTimeouts {
    first_byte: Duration,
    read_idle: Duration,
}

impl BodyTimeouts {
    /// The framework defaults required by the limits contract.
    pub(crate) const S3: Self = Self {
        first_byte: Duration::from_secs(20),
        read_idle: Duration::from_secs(30),
    };

    /// Builds non-zero deadlines. Zero is not an alias for unlimited.
    #[cfg(test)]
    pub(crate) const fn new(first_byte: Duration, read_idle: Duration) -> Option<Self> {
        if first_byte.is_zero() || read_idle.is_zero() {
            return None;
        }
        Some(Self { first_byte, read_idle })
    }

    /// Maximum silence between the request head and the first body byte.
    #[must_use]
    #[cfg(test)]
    pub(crate) const fn first_byte(self) -> Duration {
        self.first_byte
    }

    /// Maximum silence between adjacent body reads.
    #[must_use]
    #[cfg(test)]
    pub(crate) const fn read_idle(self) -> Duration {
        self.read_idle
    }

    const fn waiting_for(self, body_byte_seen: bool) -> Duration {
        if body_byte_seen { self.read_idle } else { self.first_byte }
    }
}

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
            declared: declared_body_cap(operation),
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
    ) -> Result<Bytes, S3Error> {
        let mut sha256 = match digest {
            BodyDigestObligation::None => None,
            BodyDigestObligation::Sha256(_) => Some(Sha256::new()),
        };
        let Some(body) = self.body else {
            if !body_digest_matches(digest, sha256) {
                return Err(content_sha256_mismatch());
            }
            return Ok(Bytes::new());
        };
        if let Some(cap) = ceilings.declared
            && self.declared_length.is_some_and(|length| length > cap)
        {
            return Err(past_declared_cap());
        }
        if self.declared_length.is_some_and(|length| length > ceilings.buffered) {
            return Err(past_buffered_ceiling());
        }

        let mut body = core::pin::pin!(body);
        let mut collected = BytesMut::new();
        let mut seen: u64 = 0;
        while let Some(frame) = next_frame(&mut body, timeouts.waiting_for(seen != 0)).await? {
            let frame = frame.map_err(|_| incomplete())?;
            let Ok(mut data) = frame.into_data() else {
                // A trailer frame carries no payload. This assembly does not verify trailers, so
                // it neither counts nor keeps one; the framing layer is where a trailer is judged.
                continue;
            };
            seen = seen.saturating_add(data.remaining() as u64);
            // Inside the loop, before the bytes are kept: this is the whole difference between a
            // cap and a post-mortem. `data` itself is dropped with the error, so the frame that
            // crossed the line is not buffered either.
            if let Some(cap) = ceilings.declared
                && seen > cap
            {
                return Err(past_declared_cap());
            }
            if seen > ceilings.buffered {
                return Err(past_buffered_ceiling());
            }
            match sha256.as_mut() {
                Some(hasher) => {
                    while data.has_remaining() {
                        let chunk = data.chunk();
                        let length = chunk.len();
                        hasher.update(chunk);
                        collected.put_slice(chunk);
                        data.advance(length);
                    }
                }
                None => collected.put(data),
            }
        }
        if !body_digest_matches(digest, sha256) {
            return Err(content_sha256_mismatch());
        }
        let wire_bytes = collected.freeze();
        // The decode runs here and nowhere earlier. Both ceilings above have already been applied
        // to the *wire* bytes — the ones the peer wrote and this process is holding — and only what
        // survived them is handed to the chunk parser. `crate::chunked` states why that is the
        // right side of the decode to count on.
        match ingest {
            Some(ingest) => ingest.run(wire_bytes).await,
            None => Ok(wire_bytes),
        }
    }
}

async fn next_frame<B>(
    body: &mut Pin<&mut B>,
    timeout: Duration,
) -> Result<Option<Result<http_body::Frame<B::Data>, B::Error>>, S3Error>
where
    B: http_body::Body,
{
    let mut frame = core::pin::pin!(body.frame());
    let mut deadline = core::pin::pin!(Delay::new(timeout));
    let mut first_poll = true;
    core::future::poll_fn(move |context| {
        if first_poll {
            first_poll = false;
            if let Poll::Ready(frame) = frame.as_mut().poll(context) {
                return Poll::Ready(Ok(frame));
            }
            if deadline.as_mut().poll(context).is_ready() {
                return Poll::Ready(Err(body_idle_timeout()));
            }
            return Poll::Pending;
        }
        if deadline.as_mut().poll(context).is_ready() {
            return Poll::Ready(Err(body_idle_timeout()));
        }
        if let Poll::Ready(frame) = frame.as_mut().poll(context) {
            return Poll::Ready(Ok(frame));
        }
        Poll::Pending
    })
    .await
}

fn body_digest_matches(digest: BodyDigestObligation, sha256: Option<Sha256>) -> bool {
    if let (BodyDigestObligation::Sha256(expected), Some(hasher)) = (digest, sha256) {
        let actual: [u8; 32] = hasher.finalize().into();
        return actual == expected;
    }
    true
}

fn content_sha256_mismatch() -> S3Error {
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
const fn declared_body_cap(operation: &str) -> Option<u64> {
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
fn past_declared_cap() -> S3Error {
    from_handler(
        HandlerError::new(ErrorCode::INVALID_REQUEST, "the request body is larger than this operation permits"),
        ResponseKind::Other,
        crate::close::after_body_ceiling(),
    )
}

/// The refusal for a body larger than this assembly will hold.
fn past_buffered_ceiling() -> S3Error {
    from_transport_limit(
        HandlerError::new(
            ErrorCode::ENTITY_TOO_LARGE,
            "the declared request body is larger than this service will hold",
        ),
        StatusCode::PAYLOAD_TOO_LARGE,
        crate::close::after_body_ceiling(),
    )
}

/// The refusal for a body that stopped early or ran on: both mean the body that arrived is not the
/// body that was announced, and saying which ceiling was hit tells a caller how to retry with a
/// body that is not refused.
fn incomplete() -> S3Error {
    // Closes, for the reason `ChunkReject::TruncatedStream` does: the transport reported the body
    // did not arrive as framed, so there is no well-defined remainder to drain and no
    // synchronisation point to resume from. RFC 9112 §6.3 and §9.3.
    from_handler(
        HandlerError::new(ErrorCode::INCOMPLETE_BODY, "the request body did not arrive as it was framed"),
        ResponseKind::Other,
        crate::close::ConnectionIntent::Close,
    )
}

/// The indistinguishable refusal for first-byte and between-frame idle expiry.
fn body_idle_timeout() -> S3Error {
    from_transport_limit(
        HandlerError::new(ErrorCode::REQUEST_TIMEOUT, "the request body stopped making progress"),
        StatusCode::REQUEST_TIMEOUT,
        crate::close::ConnectionIntent::Close,
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use core::convert::Infallible;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use rustfs_gateway_server::{RunningServer, Server, ServerConfig, ShutdownReport};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::*;

    fn body_timeout_server(timeouts: BodyTimeouts) -> (RunningServer, Arc<AtomicUsize>) {
        let reached = Arc::new(AtomicUsize::new(0));
        let service_reached = Arc::clone(&reached);
        let service = tower::service_fn(move |request: http::Request<hyper::body::Incoming>| {
            let service_reached = Arc::clone(&service_reached);
            async move {
                let declared_length = request
                    .headers()
                    .get(http::header::CONTENT_LENGTH)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse().ok());
                let body = SealedBody::seal(Some(request.into_body()), declared_length);
                let proof = Authenticated::granted_for_test();
                let mut response = match body.read(&proof, roomy(), timeouts, None, BodyDigestObligation::None).await {
                    Ok(_) => {
                        service_reached.fetch_add(1, Ordering::SeqCst);
                        http::Response::new(rustfs_gateway_stream::Body::from_bytes(Bytes::from_static(b"ok")))
                    }
                    Err(error) => crate::render::render(&error, &crate::trace::RequestTrace::from_bits(1, 2)),
                };
                crate::adapt::announce_connection_verdict(&mut response);
                let wire = crate::wire::collect(response).await.expect("the fixture response is finite");
                let (status, headers, body, trailers) = wire.into_parts();
                assert!(trailers.is_empty(), "the fixture response has no trailers");
                let mut response = http::Response::builder().status(status);
                for (name, value) in headers {
                    response = response.header(name, value);
                }
                Ok::<_, Infallible>(response.body(http_body_util::Full::new(body)).expect("a valid response"))
            }
        });
        let config = ServerConfig {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            plaintext: true,
            header_read_timeout: Duration::from_secs(1),
            ..ServerConfig::default()
        };
        (Server::new(config, service).serve().expect("server starts"), reached)
    }

    fn raw_head(close: bool) -> Vec<u8> {
        let mut head = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n".to_vec();
        if close {
            head.extend_from_slice(b"Connection: close\r\n");
        }
        head.extend_from_slice(b"\r\n");
        head
    }

    async fn stop_server(running: RunningServer) {
        assert_eq!(
            running.shutdown.trigger(Duration::from_secs(1)).await,
            ShutdownReport { drained: 0, aborted: 0 }
        );
        assert!(running.task.await.expect("server task joins").is_ok());
    }

    async fn timeout_response(prefix: &[u8], timeouts: BodyTimeouts) -> (Vec<u8>, Arc<AtomicUsize>) {
        let (running, reached) = body_timeout_server(timeouts);
        let mut stream = TcpStream::connect(running.local_addr).await.expect("connection succeeds");
        stream.write_all(&raw_head(false)).await.expect("head writes");
        stream.write_all(prefix).await.expect("body prefix writes");
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_millis(250), stream.read_to_end(&mut response))
            .await
            .expect("the idle deadline closes the socket")
            .expect("response reads to EOF");
        stop_server(running).await;
        (response, reached)
    }

    /// Positive — the only operation with a declared cap has one, and it is the documented number.
    #[test]
    fn the_multi_object_delete_body_is_the_one_bounded_body() {
        assert_eq!(declared_body_cap("DeleteObjects"), Some(2 * 1024 * 1024));
        assert_eq!(declared_body_cap("PutObject"), None);
    }

    /// Negative — an operation name that only looks like the bounded one gets no cap. A prefix or
    /// case match here would silently bound `DeleteObject`, which has no body at all.
    #[test]
    fn a_neighbouring_operation_name_does_not_inherit_the_cap() {
        assert_eq!(declared_body_cap("DeleteObject"), None);
        assert_eq!(declared_body_cap("deleteobjects"), None);
        assert_eq!(declared_body_cap("DeleteObjectsExtra"), None);
    }

    /// The ceilings a test that is not about ceilings wants.
    const fn roomy() -> BodyCeilings {
        BodyCeilings {
            buffered: 1 << 20,
            declared: None,
        }
    }

    /// Negative — every rejecting verdict yields no proof, so nothing built from one can reach a
    /// body. This is the run-time half of what the type does at compile time.
    #[test]
    fn a_rejected_verdict_mints_no_proof() {
        for error in [
            rustfs_gateway_sig::AuthError::SignatureDoesNotMatch,
            rustfs_gateway_sig::AuthError::InvalidAccessKeyId,
            rustfs_gateway_sig::AuthError::RequestTimeTooSkewed,
            rustfs_gateway_sig::AuthError::AccessDenied,
        ] {
            assert!(Authenticated::of(&Verdict::reject(error)).is_none(), "{error:?}");
        }
    }

    /// Negative — a body that announces more than the assembly's ceiling is refused before a single
    /// frame is polled, so the refusal costs nothing.
    #[tokio::test]
    async fn an_oversized_declared_body_is_refused_without_being_read() {
        let proof = Authenticated::granted_for_test();
        let (body, read) = crate::probe::ObservedBody::new([Bytes::from_static(b"x")]);
        let ceilings = BodyCeilings {
            buffered: 1024,
            declared: None,
        };
        let error = SealedBody::seal(Some(body), Some(1 << 30))
            .read(&proof, ceilings, BodyTimeouts::S3, None, BodyDigestObligation::None)
            .await
            .expect_err("over the ceiling");
        assert_eq!(error.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(error.code(), Some(&ErrorCode::ENTITY_TOO_LARGE));
        assert_eq!(read.bytes_read(), 0, "not one frame was polled");
    }

    /// Negative — a body that announces nothing and then exceeds the ceiling is still refused; a
    /// limit that only fires on a declared length is one a client removes by not declaring it.
    #[tokio::test]
    async fn an_undeclared_oversized_body_is_still_refused() {
        let proof = Authenticated::granted_for_test();
        let (body, _) = crate::probe::ObservedBody::new([Bytes::from(vec![0_u8; 4096])]);
        let ceilings = BodyCeilings {
            buffered: 1024,
            declared: None,
        };
        let error = SealedBody::seal(Some(body), None)
            .read(&proof, ceilings, BodyTimeouts::S3, None, BodyDigestObligation::None)
            .await
            .expect_err("over the ceiling");
        assert_eq!(error.code(), Some(&ErrorCode::ENTITY_TOO_LARGE));
    }

    /// Negative — the operation's own cap is refused **while the body is still arriving**: the
    /// frames behind the one that crossed the line are never polled, which is the difference
    /// between a cap and a report. Without this assertion "refused at 2 MiB" and "collected 40 MiB
    /// and then complained" are the same test.
    #[tokio::test]
    async fn the_declared_cap_is_refused_at_the_frame_that_crosses_it() {
        let proof = Authenticated::granted_for_test();
        let frames = core::iter::repeat_n(Bytes::from(vec![b'k'; 64]), 100);
        let (body, read) = crate::probe::ObservedBody::new(frames);
        let ceilings = BodyCeilings {
            buffered: 1 << 20,
            declared: Some(128),
        };
        let error = SealedBody::seal(Some(body), None)
            .read(&proof, ceilings, BodyTimeouts::S3, None, BodyDigestObligation::None)
            .await
            .expect_err("past the operation's cap");
        assert_eq!(error.code(), Some(&ErrorCode::INVALID_REQUEST));
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
        // Three frames of 64 bytes is the first total past 128, and nothing after it was asked for.
        assert_eq!(read.bytes_read(), 192);
        assert!(!read.is_exhausted(), "the rest of the body was never pulled");
    }

    /// Negative — the operation's cap is decided on the announced length too, so a body that
    /// declares more than the cap never has a frame polled at all.
    #[tokio::test]
    async fn a_declared_length_past_the_operation_cap_is_refused_unread() {
        let proof = Authenticated::granted_for_test();
        let (body, read) = crate::probe::ObservedBody::new([Bytes::from_static(b"x")]);
        let ceilings = BodyCeilings {
            buffered: 1 << 20,
            declared: Some(128),
        };
        let error = SealedBody::seal(Some(body), Some(4096))
            .read(&proof, ceilings, BodyTimeouts::S3, None, BodyDigestObligation::None)
            .await
            .expect_err("past the operation's cap");
        assert_eq!(error.code(), Some(&ErrorCode::INVALID_REQUEST));
        assert_eq!(read.bytes_read(), 0);
    }

    /// Positive — an absent body reads as empty rather than as an error.
    #[tokio::test]
    async fn an_absent_body_reads_as_empty() {
        let proof = Authenticated::granted_for_test();
        let sealed: SealedBody<crate::probe::ObservedBody> = SealedBody::seal(None, None);
        assert!(
            sealed
                .read(&proof, roomy(), BodyTimeouts::S3, None, BodyDigestObligation::None)
                .await
                .expect("no body")
                .is_empty()
        );
    }

    /// Positive — a body inside both ceilings arrives whole, in frame order.
    #[tokio::test]
    async fn a_body_inside_every_ceiling_arrives_whole() {
        let proof = Authenticated::granted_for_test();
        let (body, read) = crate::probe::ObservedBody::new([Bytes::from_static(b"first-"), Bytes::from_static(b"second")]);
        let bytes = SealedBody::seal(Some(body), Some(12))
            .read(&proof, roomy(), BodyTimeouts::S3, None, BodyDigestObligation::None)
            .await
            .expect("inside every ceiling");
        assert_eq!(bytes, Bytes::from_static(b"first-second"));
        assert_eq!(read.bytes_read(), 12);
        assert!(read.is_exhausted());
    }

    /// c-lim-0033. Negative — a real h1 connection closes after the first-body-byte deadline.
    #[tokio::test]
    async fn c_lim_0033_closes_a_socket_when_the_first_body_byte_never_arrives() {
        let timeouts = BodyTimeouts::new(Duration::from_millis(20), Duration::from_millis(500)).expect("non-zero timeouts");
        let (response, reached) = timeout_response(b"", timeouts).await;
        let text = String::from_utf8(response).expect("HTTP response is text");
        assert!(text.starts_with("HTTP/1.1 408"), "{text}");
        assert!(text.contains("<Code>RequestTimeout</Code>"), "{text}");
        assert!(text.to_ascii_lowercase().contains("connection: close"), "{text}");
        assert_eq!(reached.fetch_add(0, Ordering::SeqCst), 0, "the timed-out request reached the handler");
    }

    /// c-lim-0034. Negative — progress once does not exempt the next body gap from its deadline.
    #[tokio::test]
    async fn c_lim_0034_closes_a_socket_when_the_body_stalls_between_bytes() {
        let timeouts = BodyTimeouts::new(Duration::from_millis(500), Duration::from_millis(20)).expect("non-zero timeouts");
        let (response, reached) = timeout_response(b"x", timeouts).await;
        let text = String::from_utf8(response).expect("HTTP response is text");
        assert!(text.starts_with("HTTP/1.1 408"), "{text}");
        assert!(text.to_ascii_lowercase().contains("connection: close"), "{text}");
        assert_eq!(reached.fetch_add(0, Ordering::SeqCst), 0, "the stalled request reached the handler");
    }

    /// c-lim-0001. Positive — total transfer time may exceed one idle interval while progress continues.
    #[tokio::test]
    async fn c_lim_0001_allows_a_long_socket_body_that_keeps_making_progress() {
        let timeouts = BodyTimeouts::new(Duration::from_millis(100), Duration::from_millis(100)).expect("non-zero timeouts");
        let (running, reached) = body_timeout_server(timeouts);
        let mut stream = TcpStream::connect(running.local_addr).await.expect("connection succeeds");
        stream.write_all(&raw_head(true)).await.expect("head writes");
        for byte in b"body" {
            tokio::time::sleep(Duration::from_millis(30)).await;
            stream.write_all(&[*byte]).await.expect("one progress byte writes");
        }
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut response))
            .await
            .expect("the response completes")
            .expect("response reads to EOF");
        let text = String::from_utf8(response).expect("HTTP response is text");
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert_eq!(reached.fetch_add(0, Ordering::SeqCst), 1, "the progressing request missed the handler");
        stop_server(running).await;
    }

    /// Negative — zero is never an implicit unlimited body deadline.
    #[test]
    fn zero_body_deadlines_are_refused() {
        assert!(BodyTimeouts::new(Duration::ZERO, Duration::from_secs(1)).is_none());
        assert!(BodyTimeouts::new(Duration::from_secs(1), Duration::ZERO).is_none());
    }

    /// Positive — the assembly defaults are the two independent limits contract values.
    #[test]
    fn body_deadline_defaults_match_the_limits_contract() {
        assert_eq!(BodyTimeouts::S3.first_byte(), Duration::from_secs(20));
        assert_eq!(BodyTimeouts::S3.read_idle(), Duration::from_secs(30));
    }
}
