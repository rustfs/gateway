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

//! The RustFS-profile switch that refuses a buffered request body legacy RustFS cannot size, as
//! legacy RustFS refuses it (rustfs/gateway#1173).
//!
//! Responsible for: [`ServiceBuilder::refuse_unsized_buffered_bodies_as_legacy_rustfs`],
//! [`SignedLength::of`] (whether a request's signature demands a known length) and
//! [`BufferedLengths`]' two checks, one before a buffered body is read and one after.
//! NOT responsible for: reading the body (`crate::gate`), a streamed, unread or POST body, or the
//! framing rules of an aws-chunked body (`crate::chunked`).
//! Upstream: `super::ServiceBuilder`. Downstream: `crate::service`, through
//! `super::view_policy::ViewPolicy`.
//!
//! # What legacy RustFS does
//!
//! Legacy RustFS reads an operation's buffered body (every configuration write, `DeleteObjects`,
//! `CompleteMultipartUpload`, ...) whole and only then decodes it, with two length rules around
//! the read (its stack configuration sets neither, `rustfs/src/server/http.rs:166-173` on
//! rustfs/rustfs `3268c42e00`):
//!
//! * Its signature check demands a body length it can know before reading: a header-signed
//!   request declaring a payload digest or `UNSIGNED-PAYLOAD`, and a presigned one declaring a
//!   digest, sent with no `Content-Length` and a transport that does not know the length (a
//!   chunked transfer), is `411 MissingContentLength` "missing header: content-length", whatever
//!   the body holds.
//! * After the read, a body that holds anything must have arrived under a `Content-Length` equal
//!   to its length. The length of an aws-chunked body is replaced by `0` once the chunk decoder
//!   takes it over, so a decoded buffered body that holds anything is `400 IncompleteBody` under a
//!   `Content-Length` and `411 MissingContentLength` "You must provide the Content-Length HTTP
//!   header." without one; so is a plain body a chunked transfer carried in an anonymous or SigV2
//!   request.
//!
//! Observed against a legacy RustFS build: `PutBucketTagging` over a chunked transfer is `411`
//! (`UNSIGNED-PAYLOAD`, empty and non-empty alike); as an aws-chunked `STREAMING-UNSIGNED-PAYLOAD-TRAILER`
//! body it is `400 IncompleteBody` under `Content-Length` and `411` under a chunked transfer; the
//! tag set is left as it was every time. The core reads all of them and stores the document.

use bytes::Bytes;
use rustfs_gateway_core::{HandlerError, RequestBodyMode, ResponseKind};
use rustfs_gateway_sig::{PayloadMode, SigLocation};
use rustfs_gateway_types::ErrorCode;

use super::ServiceBuilder;
use crate::close::ConnectionIntent;
use crate::gate::BodyDigestObligation;
use crate::render::{S3Error, from_handler};

/// Legacy RustFS's sentence for the length its signature check demands.
const SIGNED_LENGTH_MISSING: &str = "missing header: content-length";

/// Legacy RustFS's sentence for a buffered body that arrived without a length.
const BODY_LENGTH_MISSING: &str = "You must provide the Content-Length HTTP header.";

/// Legacy RustFS's sentence for a decoded buffered body under a `Content-Length`.
const BODY_LENGTH_MISMATCH: &str = "You did not provide the number of bytes specified by the Content-Length HTTP header";

/// Whether a request's signature demands a body length known before the body is read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum SignedLength {
    /// Anonymous, SigV2, a presigned request with no digest, or aws-chunked framing.
    #[default]
    NotDemanded,
    /// A header-signed payload digest or `UNSIGNED-PAYLOAD`, or a presigned digest.
    Demanded,
}

impl SignedLength {
    /// What a SigV4 signature at `location` declaring `payload`, and owing `digest`, demands.
    pub(crate) fn of(location: SigLocation, payload: &PayloadMode, digest: BodyDigestObligation) -> Self {
        let demanded = match (location, payload) {
            (_, PayloadMode::StreamingSigned { .. } | PayloadMode::StreamingUnsigned { .. }) => false,
            (SigLocation::Header, PayloadMode::ExactSha256(_) | PayloadMode::Base64Sha256(_) | PayloadMode::Unsigned) => true,
            (SigLocation::Query, _) => digest != BodyDigestObligation::None,
            _ => false,
        };
        if demanded { Self::Demanded } else { Self::NotDemanded }
    }
}

/// Whether a buffered body legacy RustFS cannot size is refused as legacy RustFS refuses it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum BufferedLengths {
    /// Read and decoded whatever its framing, as the core reads every body.
    #[default]
    Read,
    /// Refused where legacy RustFS refuses it.
    LegacyRustfs,
}

/// Whether the core reads a body of `mode` whole before decoding it.
const fn buffered(mode: RequestBodyMode) -> bool {
    matches!(mode, RequestBodyMode::Full | RequestBodyMode::Deferred)
}

impl BufferedLengths {
    /// The refusal owed before a buffered body is read: a length the signature demands and neither
    /// the head (`declared`) nor the transport (`transport`) knows. `framed` is an aws-chunked body.
    pub(crate) fn before_read(
        self,
        mode: RequestBodyMode,
        framed: bool,
        signed: SignedLength,
        declared: Option<u64>,
        transport: Option<u64>,
    ) -> Option<S3Error> {
        let lengthless = declared.is_none() && transport.is_none();
        (self == Self::LegacyRustfs && buffered(mode) && !framed && signed == SignedLength::Demanded && lengthless)
            .then(|| refusal(ErrorCode::MISSING_CONTENT_LENGTH, SIGNED_LENGTH_MISSING))
    }

    /// The refusal owed once a buffered body holding `body` has been read: one that holds anything
    /// and arrived decoded from aws-chunked framing, or with no `Content-Length`.
    pub(crate) fn after_read(self, mode: RequestBodyMode, framed: bool, declared: Option<u64>, body: &Bytes) -> Option<S3Error> {
        if self != Self::LegacyRustfs || !buffered(mode) || body.is_empty() {
            return None;
        }
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS measures a decoded aws-chunked body
        // against a `Content-Length` it has already replaced with `0`, so it refuses every
        // aws-chunked buffered write as `IncompleteBody` although the body arrived whole, and it
        // refuses a buffered body a chunked transfer carried although the transport framed it. Kept
        // so nothing is stored that legacy RustFS would not store; the intended future behaviour is
        // the core's, which reads either body and decodes it.
        match (framed, declared) {
            (true, Some(_)) => Some(refusal(ErrorCode::INCOMPLETE_BODY, BODY_LENGTH_MISMATCH)),
            (_, None) => Some(refusal(ErrorCode::MISSING_CONTENT_LENGTH, BODY_LENGTH_MISSING)),
            (false, Some(_)) => None,
        }
    }
}

/// A refusal of this code and sentence. The connection follows the code's own rule
/// (`crate::close::after_refusal_code`: a `411` lingers over the body it did not read).
fn refusal(code: ErrorCode, sentence: &'static str) -> S3Error {
    from_handler(HandlerError::new(code, sentence), ResponseKind::Other, ConnectionIntent::MayKeepAlive)
}

impl ServiceBuilder {
    /// Refuses a buffered request body legacy RustFS cannot size, as legacy RustFS refuses it
    /// (rustfs/gateway#1173): a signed request whose body has no length before it is read is
    /// `411 MissingContentLength`, and a buffered body that holds anything is refused after it is
    /// read when it arrived decoded from aws-chunked framing (`400 IncompleteBody` under a
    /// `Content-Length`) or with no `Content-Length` at all (`411`).
    ///
    /// Off by default: the core reads a buffered body whatever carried it — a chunked transfer,
    /// aws-chunked framing — and decodes it. Only operations whose body is buffered are reached;
    /// an upload, a POST form and a body-less operation are unchanged, and a body sent under a
    /// `Content-Length` is read exactly as before.
    #[must_use]
    pub fn refuse_unsized_buffered_bodies_as_legacy_rustfs(mut self) -> Self {
        self.view_policy.buffered_lengths = BufferedLengths::LegacyRustfs;
        self
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const DIGEST: BodyDigestObligation = BodyDigestObligation::Sha256([7; 32]);
    const BODY: Bytes = Bytes::from_static(b"<Tagging/>");

    fn code(refusal: Option<S3Error>) -> Option<String> {
        refusal.and_then(|refusal| refusal.code().map(|code| code.as_str().to_owned()))
    }

    fn streaming() -> PayloadMode {
        PayloadMode::parse("STREAMING-AWS4-HMAC-SHA256-PAYLOAD", rustfs_gateway_sig::TrailerSet::None)
            .expect("a signed streaming mode")
    }

    /// Positive — a header-signed digest or `UNSIGNED-PAYLOAD`, and a presigned digest, demand a
    /// length before the body is read.
    #[test]
    fn a_signed_payload_demands_a_length() {
        for payload in [
            PayloadMode::ExactSha256([1; 32]),
            PayloadMode::Base64Sha256([1; 32]),
            PayloadMode::Unsigned,
        ] {
            assert_eq!(
                SignedLength::of(SigLocation::Header, &payload, BodyDigestObligation::None),
                SignedLength::Demanded
            );
        }
        assert_eq!(
            SignedLength::of(SigLocation::Query, &PayloadMode::Unsigned, DIGEST),
            SignedLength::Demanded
        );
    }

    /// Negative — aws-chunked framing, a presigned request with no digest, and an unsigned header
    /// declaration of nothing demand no length.
    #[test]
    fn n_framing_and_a_digestless_presigned_request_demand_no_length() {
        for location in [SigLocation::Header, SigLocation::Query] {
            assert_eq!(
                SignedLength::of(location, &streaming(), DIGEST),
                SignedLength::NotDemanded,
                "{location:?}"
            );
        }
        let none = BodyDigestObligation::None;
        assert_eq!(
            SignedLength::of(SigLocation::Query, &PayloadMode::Unsigned, none),
            SignedLength::NotDemanded
        );
        assert_eq!(
            SignedLength::of(SigLocation::Header, &PayloadMode::Empty, none),
            SignedLength::NotDemanded
        );
        assert_eq!(SignedLength::default(), SignedLength::NotDemanded);
    }

    /// Positive — an unsized signed buffered body is `411` before it is read.
    #[test]
    fn an_unsized_signed_buffered_body_is_refused_before_it_is_read() {
        let refusal = BufferedLengths::LegacyRustfs.before_read(RequestBodyMode::Full, false, SignedLength::Demanded, None, None);
        assert_eq!(code(refusal).as_deref(), Some("MissingContentLength"));
    }

    /// Negative — a length the head or the transport knows, aws-chunked framing, a signature that
    /// demands none, a body that is not buffered, and the default each go on to the read.
    #[test]
    fn n_a_sized_framed_or_unbuffered_body_is_read() {
        let legacy = BufferedLengths::LegacyRustfs;
        let demanded = SignedLength::Demanded;
        assert!(
            legacy
                .before_read(RequestBodyMode::Full, false, demanded, Some(10), None)
                .is_none()
        );
        assert!(
            legacy
                .before_read(RequestBodyMode::Full, false, demanded, None, Some(0))
                .is_none()
        );
        assert!(
            legacy
                .before_read(RequestBodyMode::Full, true, demanded, None, None)
                .is_none()
        );
        assert!(
            legacy
                .before_read(RequestBodyMode::Full, false, SignedLength::NotDemanded, None, None)
                .is_none()
        );
        for mode in [RequestBodyMode::None, RequestBodyMode::Streaming, RequestBodyMode::PostObject] {
            assert!(legacy.before_read(mode, false, demanded, None, None).is_none(), "{mode:?}");
        }
        assert!(
            BufferedLengths::Read
                .before_read(RequestBodyMode::Full, false, demanded, None, None)
                .is_none()
        );
    }

    /// Positive — a decoded aws-chunked body is `IncompleteBody` under a `Content-Length` and
    /// `411` without one; a plain body without one is `411`.
    #[test]
    fn a_decoded_or_lengthless_buffered_body_is_refused_after_it_is_read() {
        let legacy = BufferedLengths::LegacyRustfs;
        assert_eq!(
            code(legacy.after_read(RequestBodyMode::Full, true, Some(99), &BODY)).as_deref(),
            Some("IncompleteBody")
        );
        assert_eq!(
            code(legacy.after_read(RequestBodyMode::Full, true, None, &BODY)).as_deref(),
            Some("MissingContentLength")
        );
        assert_eq!(
            code(legacy.after_read(RequestBodyMode::Deferred, false, None, &BODY)).as_deref(),
            Some("MissingContentLength")
        );
    }

    /// Negative — an empty body, a plain body under a `Content-Length`, a body that is not
    /// buffered, and the default are handed on.
    #[test]
    fn n_an_empty_sized_or_unbuffered_body_is_handed_on() {
        let legacy = BufferedLengths::LegacyRustfs;
        assert!(
            legacy
                .after_read(RequestBodyMode::Full, true, Some(99), &Bytes::new())
                .is_none()
        );
        assert!(legacy.after_read(RequestBodyMode::Full, false, None, &Bytes::new()).is_none());
        assert!(legacy.after_read(RequestBodyMode::Full, false, Some(10), &BODY).is_none());
        for mode in [RequestBodyMode::None, RequestBodyMode::Streaming, RequestBodyMode::PostObject] {
            assert!(legacy.after_read(mode, true, None, &BODY).is_none(), "{mode:?}");
        }
        assert!(
            BufferedLengths::Read
                .after_read(RequestBodyMode::Full, true, None, &BODY)
                .is_none()
        );
        assert_eq!(BufferedLengths::default(), BufferedLengths::Read);
    }
}
