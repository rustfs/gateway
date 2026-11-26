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

//! Signature-owned payload declarations read from the request head.
//!
//! Responsible for: deriving one complete [`PayloadMode`] from the signed payload and trailer
//! headers, turning a signed exact digest into body-reader work, and the RustFS profile's reading
//! of a presigned request's declaration ([`signed_payload`]). NOT responsible for:
//! authenticating the declaration or decoding `aws-chunked` framing. Upstream: `crate::service`.
//! Downstream: `rustfs-gateway-sig` payload parsing and `crate::gate` body validation.
//!
//! # How legacy RustFS reads a presigned upload's declaration
//!
//! Observed against a legacy RustFS build (rustfs/rustfs `e870a6d25b`; rustfs/rustfs#2379 took
//! the behaviour): a presigned request always signs `UNSIGNED-PAYLOAD`, whatever
//! `x-amz-content-sha256` says. A digest in that header (lowercase hex, or base64) is not part of
//! the signature; the body is verified against it and a mismatch is `400 BadDigest`. A value that
//! is none of a digest, `UNSIGNED-PAYLOAD` or a streaming mode is `403 SignatureDoesNotMatch`, and a
//! streaming mode is `501 NotImplemented`. AWS instead signs the declared digest itself, which is
//! the core's reading.

use http::HeaderMap;
use rustfs_gateway_core::{HandlerError, ResponseKind};
use rustfs_gateway_sig::{
    AuthError, PayloadMode, STREAMING_ECDSA, STREAMING_ECDSA_TRAILER, STREAMING_SIGNED, STREAMING_SIGNED_TRAILER,
    STREAMING_UNSIGNED_TRAILER, SigLocation, TrailerSet, UNSIGNED_PAYLOAD,
};
use rustfs_gateway_types::ErrorCode;

use crate::close::ConnectionIntent;
use crate::gate::BodyDigestObligation;
use crate::render::{S3Error, from_auth, from_handler};

/// A recognised presigned payload shape this assembly deliberately does not implement.
pub(crate) struct StreamingPresignedUnsupported;

/// Why a signed request's payload declaration was refused before its signature was checked.
pub(crate) enum PayloadRefusal {
    /// The head is unreadable as a declaration, answered as rendered.
    Head(S3Error),
    /// A presigned request declared a streaming payload: `501 NotImplemented`.
    StreamingPresigned,
    /// The RustFS profile's presigned reading refuses the declaration as an authentication failure.
    Unauthenticated(AuthError),
}

impl PayloadRefusal {
    /// The answer for a request of `response` kind, `body_owed` when its body is still unread.
    pub(crate) fn render(self, response: ResponseKind, body_owed: bool) -> S3Error {
        match self {
            Self::Head(error) => error,
            Self::StreamingPresigned => from_handler(
                HandlerError::new(
                    ErrorCode::NOT_IMPLEMENTED,
                    "streaming payloads are not implemented for presigned requests",
                ),
                response,
                ConnectionIntent::MayKeepAlive,
            ),
            Self::Unauthenticated(error) => from_auth(error, response, body_owed),
        }
    }
}

/// What a signed request's head declares: the payload mode its signature covers, and the digest
/// its body must match.
///
/// With `presigned_unsigned` on (the RustFS profile) a presigned request is read as legacy RustFS
/// reads it (see the module documentation); every other request, and every request with the switch
/// off, is [`payload_mode`] and [`body_digest_obligation`] exactly as before.
pub(crate) fn signed_payload(
    headers: &HeaderMap,
    location: SigLocation,
    presigned_unsigned: bool,
) -> Result<(PayloadMode, BodyDigestObligation), PayloadRefusal> {
    if presigned_unsigned && location.is_presigned() {
        return legacy_presigned_payload(headers);
    }
    let payload = payload_mode(headers, location).map_err(PayloadRefusal::Head)?;
    let obligation = body_digest_obligation(&payload, location).map_err(|_| PayloadRefusal::StreamingPresigned)?;
    Ok((payload, obligation))
}

/// Reads an unframed declaration for signature verification only. The route must still refuse it.
/// Only a well-formed header signature that covers the trailer declaration is eligible.
pub(crate) fn unframed_upload_with_signed_trailers(headers: &HeaderMap) -> Option<(PayloadMode, BodyDigestObligation)> {
    let single = |name: &'static str| {
        let mut values = headers.get_all(name).iter();
        let value = values.next()?.to_str().ok()?;
        values.next().is_none().then_some(value)
    };
    single("x-amz-trailer")?;
    if !declared_trailers(headers).ok()?.is_declared() {
        return None;
    }
    let mode = PayloadMode::parse(single("x-amz-content-sha256")?, TrailerSet::None).ok()?;
    if !matches!(mode, PayloadMode::ExactSha256(_) | PayloadMode::Unsigned) {
        return None;
    }
    let auth = rustfs_gateway_sig::SigV4Authorization::parse(single("authorization")?).ok()?;
    if !auth.signed_headers().split(';').any(|name| name == "x-amz-trailer") {
        return None;
    }
    let obligation = body_digest_obligation(&mode, SigLocation::Header).ok()?;
    Some((mode, obligation))
}

/// A presigned request's declaration as legacy RustFS reads it: always signed as
/// `UNSIGNED-PAYLOAD`, with a declared digest verified against the body.
fn legacy_presigned_payload(headers: &HeaderMap) -> Result<(PayloadMode, BodyDigestObligation), PayloadRefusal> {
    let unsigned = (PayloadMode::Unsigned, BodyDigestObligation::None);
    let Some(value) = headers.get("x-amz-content-sha256") else {
        return Ok(unsigned);
    };
    let declared = value
        .to_str()
        .map_err(|_| PayloadRefusal::Unauthenticated(AuthError::SignatureDoesNotMatch))?;
    if [
        STREAMING_SIGNED,
        STREAMING_SIGNED_TRAILER,
        STREAMING_UNSIGNED_TRAILER,
        STREAMING_ECDSA,
        STREAMING_ECDSA_TRAILER,
    ]
    .contains(&declared)
    {
        return Err(PayloadRefusal::StreamingPresigned);
    }
    if declared == UNSIGNED_PAYLOAD {
        return Ok(unsigned);
    }
    // Legacy-compat (rustfs/backlog#2684): legacy RustFS leaves a presigned upload's declared
    // digest out of the signature and verifies it against the body instead, where AWS signs it;
    // the declaration can then be swapped without invalidating the URL. Kept so the presigned
    // uploads RustFS accepts today (rustfs/rustfs#2379) keep working; the intended future
    // behaviour is the core's reading, which signs the declared digest.
    match PayloadMode::parse(declared, TrailerSet::None) {
        Ok(PayloadMode::ExactSha256(digest) | PayloadMode::Base64Sha256(digest)) => {
            Ok((PayloadMode::Unsigned, BodyDigestObligation::Sha256(digest)))
        }
        _ => Err(PayloadRefusal::Unauthenticated(AuthError::SignatureDoesNotMatch)),
    }
}

/// What `x-amz-content-sha256` said about the body.
///
/// An absent header is [`PayloadMode::Unsigned`] for a presigned query and
/// [`PayloadMode::Empty`] for a header signature. The trailer set is read atomically with the
/// digest because the two are valid only in specific combinations.
pub(crate) fn payload_mode(headers: &HeaderMap, location: SigLocation) -> Result<PayloadMode, S3Error> {
    let Some(value) = headers.get("x-amz-content-sha256") else {
        return Ok(if location.is_presigned() {
            PayloadMode::Unsigned
        } else {
            PayloadMode::Empty
        });
    };
    let Ok(text) = value.to_str() else {
        return Err(ordinary_refusal(
            ErrorCode::INVALID_REQUEST,
            "the x-amz-content-sha256 header is not a readable value",
        ));
    };
    PayloadMode::parse(text, declared_trailers(headers)?).map_err(|_| {
        ordinary_refusal(
            ErrorCode::INVALID_REQUEST,
            "the x-amz-content-sha256 header is not a value this service accepts",
        )
    })
}

/// The framing an anonymous request's own head declares (rustfs/gateway#1060).
///
/// `STREAMING-UNSIGNED-PAYLOAD-TRAILER` needs no signature to decode, so an anonymous request that
/// declares it is decoded exactly as a signed one is; handing it through would store the framing
/// as object data. A chunk-signed streaming mode cannot be verified without a signature and is
/// refused. Any other declaration leaves the body plain, as before: an anonymous request's digest
/// is not an obligation this assembly takes on.
///
/// With `decode` off (the RustFS profile) every anonymous body stays undecoded, as before
/// rustfs/gateway#1060.
pub(crate) fn anonymous_framing(headers: &HeaderMap, decode: bool) -> Result<Option<PayloadMode>, S3Error> {
    // Legacy-compat (rustfs/backlog#2684): legacy RustFS never decodes an anonymous aws-chunked
    // body; it sizes the object by x-amz-decoded-content-length and refuses the surplus framing
    // bytes (400 UnexpectedContent, 500 for a streamed body), so a valid anonymous
    // STREAMING-UNSIGNED-PAYLOAD-TRAILER upload that AWS accepts is refused. The RustFS profile
    // keeps that until the maintainer lifts it; the intended behaviour is the decode below.
    if !decode {
        return Ok(None);
    }
    let declares_streaming = headers
        .get("x-amz-content-sha256")
        .is_some_and(|value| value.as_bytes().starts_with(b"STREAMING-"));
    if !declares_streaming {
        return Ok(None);
    }
    match payload_mode(headers, SigLocation::Header)? {
        mode @ PayloadMode::StreamingUnsigned { .. } => Ok(Some(mode)),
        PayloadMode::StreamingSigned { .. } => Err(ordinary_refusal(
            ErrorCode::INVALID_REQUEST,
            "a chunk-signed streaming payload needs a signed request",
        )),
        _ => Ok(None),
    }
}

/// The SHA-256 digest of an empty payload (`e3b0c442...`), used when a header-signed request omits
/// `x-amz-content-sha256` so the body reader rejects any non-empty unsigned body.
const EMPTY_PAYLOAD_SHA256: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64,
    0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// The body-integrity work a signed payload declaration leaves for the body reader.
///
/// An exact digest is an obligation wherever the signature travels: the signature covers
/// `x-amz-content-sha256`, and only comparing that declaration with the body makes it cover the
/// body. A header-signed digest that went uncompared authenticated the head and not the payload, so
/// a replayed head carried any body (c-sig-0596, beside the presigned c-sig-0430). When a header
/// signature omits `x-amz-content-sha256`, SigV4 verifies against the empty-payload SHA-256, so the
/// body reader holds the body to that same empty digest unless STS/S3 Vectors body hashing verified
/// the actual body digest instead. A framed payload declares no digest — its chain of chunk
/// signatures covers it — and a presigned query cannot seed that chain, so the presigned streaming
/// form is refused.
pub(crate) fn body_digest_obligation(
    payload: &PayloadMode,
    location: SigLocation,
) -> Result<BodyDigestObligation, StreamingPresignedUnsupported> {
    if let Some(digest) = payload.digest() {
        return Ok(BodyDigestObligation::Sha256(*digest));
    }
    if *payload == PayloadMode::Empty && location == SigLocation::Header {
        return Ok(BodyDigestObligation::Sha256(EMPTY_PAYLOAD_SHA256));
    }
    if location.is_presigned() && payload.is_framed() {
        return Err(StreamingPresignedUnsupported);
    }
    Ok(BodyDigestObligation::None)
}

fn declared_trailers(headers: &HeaderMap) -> Result<TrailerSet, S3Error> {
    let Some(value) = headers.get("x-amz-trailer") else {
        return Ok(TrailerSet::None);
    };
    let malformed = || ordinary_refusal(ErrorCode::INVALID_REQUEST, "the x-amz-trailer header is not one this service can read");
    let text = value.to_str().map_err(|_| malformed())?;
    let mut names = Vec::new();
    for name in text.split(',').map(str::trim).filter(|name| !name.is_empty()) {
        names.push(rustfs_gateway_sig::TrailerName::new(name).map_err(|_| malformed())?);
    }
    rustfs_gateway_sig::DeclaredTrailers::new(names, false)
        .map(TrailerSet::Declared)
        .map_err(|_| malformed())
}

fn ordinary_refusal(code: ErrorCode, message: &'static str) -> S3Error {
    from_handler(HandlerError::new(code, message), ResponseKind::Other, ConnectionIntent::MayKeepAlive)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_content_sha256_uses_the_signature_location() {
        assert!(matches!(payload_mode(&HeaderMap::new(), SigLocation::Header), Ok(PayloadMode::Empty)));
        assert!(matches!(payload_mode(&HeaderMap::new(), SigLocation::Query), Ok(PayloadMode::Unsigned)));
    }

    fn declaring(value: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::HeaderName::from_static("x-amz-content-sha256"),
            http::HeaderValue::from_static(value),
        );
        headers
    }

    /// The SHA-256 of `abc`, in the two spellings a digest declaration takes.
    const HEX: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const BASE64: &str = "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=";

    fn digest() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&HEX[index * 2..index * 2 + 2], 16).unwrap_or_default();
        }
        bytes
    }

    #[test]
    fn the_legacy_presigned_reading_signs_unsigned_and_keeps_the_declared_digest() {
        for value in [HEX, BASE64] {
            let read = signed_payload(&declaring(value), SigLocation::Query, true);
            assert!(
                matches!(read, Ok((PayloadMode::Unsigned, BodyDigestObligation::Sha256(bytes))) if bytes == digest()),
                "{value}"
            );
        }
        for headers in [HeaderMap::new(), declaring("UNSIGNED-PAYLOAD")] {
            assert!(matches!(
                signed_payload(&headers, SigLocation::Query, true),
                Ok((PayloadMode::Unsigned, BodyDigestObligation::None))
            ));
        }
    }

    #[test]
    fn n_the_legacy_presigned_reading_refuses_what_is_not_a_digest() {
        for value in [
            "invalid-sha256",
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
            "unsigned-payload",
            "",
            " UNSIGNED-PAYLOAD",
        ] {
            assert!(
                matches!(
                    signed_payload(&declaring(value), SigLocation::Query, true),
                    Err(PayloadRefusal::Unauthenticated(AuthError::SignatureDoesNotMatch))
                ),
                "{value:?}"
            );
        }
        for value in [
            STREAMING_SIGNED,
            STREAMING_SIGNED_TRAILER,
            STREAMING_UNSIGNED_TRAILER,
            STREAMING_ECDSA,
            STREAMING_ECDSA_TRAILER,
        ] {
            assert!(
                matches!(
                    signed_payload(&declaring(value), SigLocation::Query, true),
                    Err(PayloadRefusal::StreamingPresigned)
                ),
                "{value}"
            );
        }
    }

    #[test]
    fn n_the_default_and_header_signed_requests_keep_the_signed_digest() {
        for (location, switch) in [
            (SigLocation::Query, false),
            (SigLocation::Header, true),
            (SigLocation::Header, false),
        ] {
            let read = signed_payload(&declaring(HEX), location, switch);
            assert!(
                matches!(read, Ok((PayloadMode::ExactSha256(bytes), BodyDigestObligation::Sha256(obligation))) if bytes == digest() && obligation == digest()),
                "{location:?} {switch}"
            );
        }
        assert!(matches!(
            signed_payload(&declaring("invalid-sha256"), SigLocation::Query, false),
            Err(PayloadRefusal::Head(_))
        ));
    }

    #[test]
    fn an_unframeable_payload_declaration_is_refused() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::HeaderName::from_static("x-amz-content-sha256"),
            http::HeaderValue::from_static("STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"),
        );
        assert!(payload_mode(&headers, SigLocation::Header).is_err());
    }

    #[test]
    fn n_absent_header_content_sha256_requires_empty_body_digest() {
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41,
            0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        ];
        assert!(matches!(
            signed_payload(&HeaderMap::new(), SigLocation::Header, false),
            Ok((PayloadMode::Empty, BodyDigestObligation::Sha256(digest))) if digest == expected
        ));
        assert!(matches!(
            signed_payload(&HeaderMap::new(), SigLocation::Query, false),
            Ok((PayloadMode::Unsigned, BodyDigestObligation::None))
        ));
    }
}
