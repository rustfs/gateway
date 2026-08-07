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
//! bytes, and [`BodyCeilings`], the two independent bounds that read is subject to.
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

use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::StatusCode;
use http_body_util::BodyExt;
use rustfs_gateway_sig::Verdict;
use rustfs_gateway_types::ErrorCode;

use crate::render::S3Error;

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
    pub(crate) async fn read(self, _proof: &Authenticated<'_>, ceilings: BodyCeilings) -> Result<Bytes, S3Error> {
        let Some(body) = self.body else {
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
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| incomplete())?;
            let Ok(data) = frame.into_data() else {
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
            collected.put(data);
        }
        Ok(collected.freeze())
    }
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
fn past_declared_cap() -> S3Error {
    S3Error::new(ErrorCode::INVALID_REQUEST, "the request body is larger than this operation permits")
}

/// The refusal for a body larger than this assembly will hold.
fn past_buffered_ceiling() -> S3Error {
    S3Error::new(
        ErrorCode::ENTITY_TOO_LARGE,
        "the declared request body is larger than this service will hold",
    )
    .with_status(StatusCode::PAYLOAD_TOO_LARGE)
}

/// The refusal for a body that stopped early or ran on: both mean the body that arrived is not the
/// body that was announced, and saying which ceiling was hit tells a caller how to retry with a
/// body that is not refused.
fn incomplete() -> S3Error {
    S3Error::new(ErrorCode::INCOMPLETE_BODY, "the request body did not arrive as it was framed")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

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
            .read(&proof, ceilings)
            .await
            .expect_err("over the ceiling");
        assert_eq!(error.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(error.code(), &ErrorCode::ENTITY_TOO_LARGE);
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
            .read(&proof, ceilings)
            .await
            .expect_err("over the ceiling");
        assert_eq!(error.code(), &ErrorCode::ENTITY_TOO_LARGE);
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
            .read(&proof, ceilings)
            .await
            .expect_err("past the operation's cap");
        assert_eq!(error.code(), &ErrorCode::INVALID_REQUEST);
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
            .read(&proof, ceilings)
            .await
            .expect_err("past the operation's cap");
        assert_eq!(error.code(), &ErrorCode::INVALID_REQUEST);
        assert_eq!(read.bytes_read(), 0);
    }

    /// Positive — an absent body reads as empty rather than as an error.
    #[tokio::test]
    async fn an_absent_body_reads_as_empty() {
        let proof = Authenticated::granted_for_test();
        let sealed: SealedBody<crate::probe::ObservedBody> = SealedBody::seal(None, None);
        assert!(sealed.read(&proof, roomy()).await.expect("no body").is_empty());
    }

    /// Positive — a body inside both ceilings arrives whole, in frame order.
    #[tokio::test]
    async fn a_body_inside_every_ceiling_arrives_whole() {
        let proof = Authenticated::granted_for_test();
        let (body, read) = crate::probe::ObservedBody::new([Bytes::from_static(b"first-"), Bytes::from_static(b"second")]);
        let bytes = SealedBody::seal(Some(body), Some(12))
            .read(&proof, roomy())
            .await
            .expect("inside every ceiling");
        assert_eq!(bytes, Bytes::from_static(b"first-second"));
        assert_eq!(read.bytes_read(), 12);
        assert!(read.is_exhausted());
    }
}
